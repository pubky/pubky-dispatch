//! Exclusive signer ownership, durable snapshots and canceled store calls.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;
#[path = "common/file_store.rs"]
mod file_store;

use std::io::Read;
use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, mpsc};
use std::time::{Duration, Instant};

use common::*;
use file_store::FileStore;
use pubky_switch_client::StoreError;
use pubky_switch_client::store::{
    AcquireOutcome, CommitOutcome, KeyValue, MemoryStore, StateStore, StoreHandle, StoreOwner,
    WriteBatch,
};
use pubky_switch_client::testing::SWITCH_ORIGIN;
use pubky_switch_signer::state::signer_namespace;
use pubky_switch_signer::{Refusal, Signer, SignerError, SignerStatus};

fn batch(ns: &str, value: &[u8]) -> WriteBatch {
    let mut batch = WriteBatch::new();
    batch.put(ns, b"a", value).unwrap();
    batch.put(ns, b"b", value).unwrap();
    batch
}

#[tokio::test]
async fn test_store_ownership_separate_handles_and_atomic_refusals() {
    let directory = tempfile::tempdir().unwrap();
    let raw = Arc::new(FileStore::new(directory.path()));
    let handle = StoreHandle::inline(raw.clone());
    let mut owner = handle.acquire("ns").await.unwrap();
    let other = StoreHandle::inline(Arc::new(FileStore::new(directory.path())));
    assert!(matches!(other.acquire("ns").await, Err(StoreError::InUse)));
    owner.commit(batch("ns", b"one")).await.unwrap();
    let mut mixed = batch("other", b"bad");
    mixed.delete_prefix("ns", b"").unwrap();
    assert_eq!(raw.commit(mixed), Err(StoreError::InUse));
    assert_eq!(raw.get("other", b"a").unwrap(), None);
    assert_eq!(owner.get(b"a").await.unwrap(), Some(b"one".to_vec()));
    assert!(owner.commit(batch("other", b"bad")).await.is_err());
    raw.fault.store(1, Ordering::SeqCst);
    assert_eq!(
        owner.commit(batch("ns", b"two")).await,
        Err(StoreError::Unavailable)
    );
    assert_eq!(owner.get(b"b").await.unwrap(), Some(b"one".to_vec()));
    raw.fault.store(2, Ordering::SeqCst);
    assert_eq!(
        owner.commit(batch("ns", b"two")).await,
        Err(StoreError::Unknown)
    );
    assert_eq!(
        owner.scan(b"", None, 10).await.unwrap(),
        vec![
            (b"a".to_vec(), b"two".to_vec()),
            (b"b".to_vec(), b"two".to_vec())
        ]
    );
    drop(owner);
    let reopened = other.acquire("ns").await.unwrap();
    assert_eq!(reopened.get(b"b").await.unwrap(), Some(b"two".to_vec()));
}

#[tokio::test]
async fn test_store_ownership_signer_constructors_preserve_current_records() {
    let world = World::new();
    let store = Arc::new(MemoryStore::new());
    let mut signer = Signer::create(world.env(store.clone()), world.keyring(), SWITCH_ORIGIN)
        .await
        .unwrap();
    let ns = signer_namespace(&world.key.public());
    let before = store.scan(&ns, b"", None, 10).unwrap();
    assert_eq!(
        Signer::open(world.env(store.clone()), world.keyring())
            .await
            .unwrap_err(),
        SignerError::Store(StoreError::InUse)
    );
    assert_eq!(
        Signer::create(world.env(store.clone()), world.keyring(), SWITCH_ORIGIN)
            .await
            .unwrap_err(),
        SignerError::Store(StoreError::InUse)
    );
    assert_eq!(
        Signer::restore_new(
            world.env(store.clone()),
            world.keyring(),
            pubky_switch_signer::UserConfirmed::shown_and_confirmed()
        )
        .await
        .unwrap_err(),
        SignerError::Store(StoreError::InUse)
    );
    assert_eq!(store.scan(&ns, b"", None, 10).unwrap(), before);
    // Ownership of an unrelated namespace does not hold this signer back.
    let unrelated = StoreHandle::inline(store.clone())
        .acquire("unrelated")
        .await
        .unwrap();
    signer.resume().await.unwrap();
    let install = signer.install_id();
    let high = signer.high_water().unwrap().unwrap();
    drop(signer);
    let reopened = Signer::open(world.env(store.clone()), world.keyring())
        .await
        .unwrap();
    assert_eq!(reopened.install_id(), install);
    assert_eq!(reopened.high_water().unwrap().unwrap(), high);
    drop(reopened);
    assert_eq!(
        Signer::create(world.env(store), world.keyring(), SWITCH_ORIGIN)
            .await
            .unwrap_err(),
        SignerError::Refused(Refusal::AlreadySetUp)
    );
    drop(unrelated);
}

struct ChildProcess(Child);
impl Drop for ChildProcess {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn child(directory: &Path, mode: &str) -> ChildProcess {
    let output = std::fs::File::create(directory.join(format!("{mode}.log"))).unwrap();
    ChildProcess(
        Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "test_store_ownership_child",
                "--nocapture",
                "--test-threads=1",
            ])
            .env("SWITCH_STORE_CHILD", mode)
            .env("SWITCH_STORE_DIRECTORY", directory)
            .stdin(Stdio::piped())
            .stdout(output.try_clone().unwrap())
            .stderr(output)
            .spawn()
            .unwrap(),
    )
}

fn wait_file(child: &mut ChildProcess, path: &Path) {
    let deadline = Instant::now() + Duration::from_secs(20);
    while !path.exists() {
        assert!(
            child.0.try_wait().unwrap().is_none(),
            "child exited before its acquisition assertion"
        );
        assert!(
            Instant::now() < deadline,
            "child did not reach its acquisition assertion"
        );
        std::thread::sleep(Duration::from_millis(10));
    }
}

#[tokio::test]
async fn test_store_ownership_process_death_releases_exact_durable_flow() {
    let directory = tempfile::tempdir().unwrap();
    let mut holder = child(directory.path(), "hold");
    wait_file(&mut holder, &directory.path().join("held"));
    let world = World::new();
    let store = Arc::new(FileStore::new(directory.path()));
    let ns = signer_namespace(&world.key.public());
    let before = store.scan(&ns, b"", None, 10).unwrap();
    assert_eq!(
        before.len(),
        2,
        "state and exact enrollment flow were committed"
    );
    assert_eq!(
        Signer::open(world.env(store.clone()), world.keyring())
            .await
            .unwrap_err(),
        SignerError::Store(StoreError::InUse)
    );
    assert_eq!(store.commit(batch(&ns, b"bad")), Err(StoreError::InUse));
    store.commit(batch("unrelated", b"allowed")).unwrap();
    holder.0.kill().unwrap();
    assert!(
        !holder.0.wait().unwrap().success(),
        "the holder died without destructors"
    );
    let mut next = child(directory.path(), "open");
    wait_file(&mut next, &directory.path().join("opened"));
    let deadline = Instant::now() + Duration::from_secs(20);
    let status = loop {
        if let Some(status) = next.0.try_wait().unwrap() {
            break status;
        }
        assert!(Instant::now() < deadline, "child did not exit");
        std::thread::sleep(Duration::from_millis(10));
    };
    assert!(status.success());
    assert!(
        std::fs::read_to_string(directory.path().join("open.log"))
            .unwrap()
            .contains("1 passed")
    );
    assert_eq!(store.scan(&ns, b"", None, 10).unwrap(), before);
    assert_eq!(
        std::fs::read(directory.path().join("held")).unwrap(),
        std::fs::read(directory.path().join("opened")).unwrap()
    );
}

#[tokio::test]
async fn test_store_ownership_child() {
    let Ok(mode) = std::env::var("SWITCH_STORE_CHILD") else {
        return;
    };
    let directory = std::path::PathBuf::from(std::env::var_os("SWITCH_STORE_DIRECTORY").unwrap());
    let world = World::new();
    let store = Arc::new(FileStore::new(&directory));
    if mode == "hold" {
        let signer = Signer::create(world.env(store), world.keyring(), SWITCH_ORIGIN)
            .await
            .unwrap();
        assert_eq!(signer.status(), SignerStatus::Enrolling);
        std::fs::write(directory.join("held"), signer.install_id()).unwrap();
        let _ = std::io::stdin().read_exact(&mut [0]);
        drop(signer);
    } else {
        assert_eq!(mode, "open");
        let signer = Signer::open(world.env(store), world.keyring())
            .await
            .unwrap();
        assert_eq!(signer.status(), SignerStatus::Enrolling);
        std::fs::write(directory.join("opened"), signer.install_id()).unwrap();
    }
}

struct DelayedStore {
    inner: MemoryStore,
    armed: AtomicBool,
    after: bool,
    unknown: bool,
    fail_reads: AtomicBool,
    entered: tokio::sync::Notify,
    released: Mutex<mpsc::Receiver<()>>,
}
impl StateStore for DelayedStore {
    fn get(&self, ns: &str, key: &[u8]) -> Result<Option<Vec<u8>>, StoreError> {
        if self.fail_reads.load(Ordering::SeqCst) {
            return Err(StoreError::Unavailable);
        }
        self.inner.get(ns, key)
    }
    fn scan(
        &self,
        ns: &str,
        prefix: &[u8],
        after: Option<&[u8]>,
        limit: u32,
    ) -> Result<Vec<KeyValue>, StoreError> {
        self.inner.scan(ns, prefix, after, limit)
    }
    fn acquire(&self, ns: &str, owner: StoreOwner) -> Result<AcquireOutcome, StoreError> {
        self.inner.acquire(ns, owner)
    }
    fn commit(&self, batch: WriteBatch) -> Result<(), StoreError> {
        self.inner.commit(batch)
    }
    fn commit_if(
        &self,
        ns: &str,
        owner: StoreOwner,
        batch: WriteBatch,
    ) -> Result<CommitOutcome, StoreError> {
        if !self.armed.swap(false, Ordering::SeqCst) {
            return self.inner.commit_if(ns, owner, batch);
        }
        if self.after {
            assert_eq!(
                self.inner.commit_if(ns, owner, batch.clone())?,
                CommitOutcome::Applied
            );
        }
        self.entered.notify_one();
        self.released
            .lock()
            .unwrap()
            .recv_timeout(Duration::from_secs(20))
            .unwrap();
        if !self.after {
            assert_eq!(
                self.inner.commit_if(ns, owner, batch)?,
                CommitOutcome::Applied
            );
        }
        if self.unknown {
            Err(StoreError::Unknown)
        } else {
            Ok(CommitOutcome::Applied)
        }
    }
}

// Poll exactly once with a real waker: the barrier, not an elapsed delay, determines progress.
fn poll_pending(future: std::pin::Pin<&mut impl std::future::Future>) {
    let waker = std::task::Waker::noop();
    assert!(
        future
            .poll(&mut std::task::Context::from_waker(waker))
            .is_pending()
    );
}

#[tokio::test]
async fn test_store_ownership_canceled_commit_drains_and_reloads_before_signing() {
    for after in [false, true] {
        for unknown in [false, true] {
            let world = World::new();
            let (release, released) = mpsc::channel();
            let store = Arc::new(DelayedStore {
                inner: MemoryStore::new(),
                armed: AtomicBool::new(false),
                after,
                unknown,
                fail_reads: AtomicBool::new(false),
                entered: tokio::sync::Notify::new(),
                released: Mutex::new(released),
            });
            let mut env = world.env(store.clone());
            env.store = StoreHandle::blocking(store.clone());
            let mut signer = Signer::create(env, world.keyring(), SWITCH_ORIGIN)
                .await
                .unwrap();
            signer.resume().await.unwrap();
            store.armed.store(true, Ordering::SeqCst);
            let mut saving = Box::pin(signer.set_connect_requests(
                pubky_switch_core::records::ConnectRequests {
                    enabled: true,
                    max_pending: 10,
                    push: false,
                },
            ));
            // Reach the blocked commit while servicing asynchronous reads that precede it.
            tokio::select! { () = store.entered.notified() => {}, result = &mut saving => panic!("commit did not wait: {result:?}") }
            drop(saving);
            assert!(matches!(
                signer.approved(&[0; 32]),
                Err(SignerError::Store(StoreError::Unknown))
            ));
            assert!(matches!(
                StoreHandle::inline(store.clone())
                    .acquire(&signer_namespace(&world.key.public()))
                    .await,
                Err(StoreError::InUse)
            ));
            let mut resumed = Box::pin(signer.resume());
            poll_pending(resumed.as_mut());
            release.send(()).unwrap();
            let result = resumed.await;
            if unknown {
                assert_eq!(result, Err(SignerError::Store(StoreError::Unknown)));
                store.fail_reads.store(true, Ordering::SeqCst);
                assert_eq!(
                    signer.resume().await,
                    Err(SignerError::Store(StoreError::Unavailable))
                );
                assert!(matches!(
                    signer.approved(&[0; 32]),
                    Err(SignerError::Store(StoreError::Unknown))
                ));
                assert_eq!(world.switch.identity_doc().unwrap().version(), 1);
                store.fail_reads.store(false, Ordering::SeqCst);
                signer.resume().await.unwrap();
            } else {
                result.unwrap();
            }
            assert_eq!(
                signer
                    .identity_doc()
                    .unwrap()
                    .unwrap()
                    .body()
                    .policy
                    .connect_requests,
                pubky_switch_core::records::ConnectRequests {
                    enabled: true,
                    max_pending: 10,
                    push: false
                }
            );
            assert_eq!(
                world.switch.identity_doc().unwrap().signed(),
                signer.identity_doc().unwrap().unwrap().signed()
            );
        }
    }
}

#[tokio::test]
async fn test_store_ownership_dropped_constructor_retains_running_commit() {
    let world = World::new();
    let (release, released) = mpsc::channel();
    let store = Arc::new(DelayedStore {
        inner: MemoryStore::new(),
        armed: AtomicBool::new(true),
        after: false,
        unknown: false,
        fail_reads: AtomicBool::new(false),
        entered: tokio::sync::Notify::new(),
        released: Mutex::new(released),
    });
    let mut env = world.env(store.clone());
    env.store = StoreHandle::blocking(store.clone());
    let mut creating = Box::pin(Signer::create(env, world.keyring(), SWITCH_ORIGIN));
    tokio::select! { () = store.entered.notified() => {}, result = &mut creating => panic!("constructor did not wait: {result:?}") }
    drop(creating);
    assert_eq!(
        Signer::open(world.env(store.clone()), world.keyring())
            .await
            .unwrap_err(),
        SignerError::Store(StoreError::InUse)
    );
    release.send(()).unwrap();
    // A store barrier observes the worker's actual finish, including its final lease drop.
    let deadline = Instant::now() + Duration::from_secs(20);
    loop {
        match Signer::open(world.env(store.clone()), world.keyring()).await {
            Ok(signer) => {
                assert_eq!(signer.status(), SignerStatus::Enrolling);
                break;
            }
            Err(SignerError::Store(StoreError::InUse)) => {
                assert!(Instant::now() < deadline);
                tokio::task::yield_now().await;
            }
            other => panic!("unexpected constructor result: {other:?}"),
        }
    }
}

#[tokio::test]
async fn test_store_ownership_canceled_write_remains_pending_until_completion() {
    let (release, released) = mpsc::channel();
    let store = Arc::new(DelayedStore {
        inner: MemoryStore::new(),
        armed: AtomicBool::new(true),
        after: false,
        unknown: false,
        fail_reads: AtomicBool::new(false),
        entered: tokio::sync::Notify::new(),
        released: Mutex::new(released),
    });
    let handle = StoreHandle::blocking(store.clone());
    let mut owner = handle.acquire("ns").await.unwrap();
    let mut saving = Box::pin(owner.commit(batch("ns", b"committed")));
    tokio::select! { () = store.entered.notified() => {}, result = &mut saving => panic!("write did not wait: {result:?}") }
    drop(saving);
    let mut draining = Box::pin(owner.drain());
    poll_pending(draining.as_mut());
    release.send(()).unwrap();
    draining.await.unwrap();
    assert_eq!(owner.get(b"a").await.unwrap(), Some(b"committed".to_vec()));
}

fn connect_requests() -> pubky_switch_core::records::ConnectRequests {
    pubky_switch_core::records::ConnectRequests {
        enabled: true,
        max_pending: 10,
        push: false,
    }
}

/// A signer on a store whose next owned commit waits for `release`, with a canceled call's
/// write waiting there.
async fn signer_with_a_waiting_write(
    world: &World,
    unknown: bool,
) -> (Signer, Arc<DelayedStore>, mpsc::Sender<()>) {
    let (release, released) = mpsc::channel();
    let store = Arc::new(DelayedStore {
        inner: MemoryStore::new(),
        armed: AtomicBool::new(false),
        after: false,
        unknown,
        fail_reads: AtomicBool::new(false),
        entered: tokio::sync::Notify::new(),
        released: Mutex::new(released),
    });
    let mut env = world.env(store.clone());
    env.store = StoreHandle::blocking(store.clone());
    let mut signer = Signer::create(env, world.keyring(), SWITCH_ORIGIN)
        .await
        .unwrap();
    signer.resume().await.unwrap();
    store.armed.store(true, Ordering::SeqCst);
    let mut saving = Box::pin(signer.set_connect_requests(connect_requests()));
    tokio::select! { () = store.entered.notified() => {}, result = &mut saving => panic!("commit did not wait: {result:?}") }
    drop(saving);
    (signer, store, release)
}

#[tokio::test]
async fn test_store_ownership_close_waits_for_a_canceled_write_then_releases() {
    let world = World::new();
    let (signer, store, release) = signer_with_a_waiting_write(&world, false).await;
    let mut closing = Box::pin(signer.close());
    poll_pending(closing.as_mut());
    // The left write owns the records until it ends.
    assert!(matches!(
        StoreHandle::inline(store.clone())
            .acquire(&signer_namespace(&world.key.public()))
            .await,
        Err(StoreError::InUse)
    ));
    release.send(()).unwrap();
    closing.await.unwrap();
    // Closed, the records are free at once, with the flow the canceled call left, which the
    // next signer finishes.
    let mut signer = Signer::open(world.env(store.clone()), world.keyring())
        .await
        .unwrap();
    signer.resume().await.unwrap();
    assert_eq!(
        signer
            .identity_doc()
            .unwrap()
            .unwrap()
            .body()
            .policy
            .connect_requests,
        connect_requests()
    );
}

#[tokio::test]
async fn test_store_ownership_close_reports_an_unknown_write_and_releases() {
    let world = World::new();
    let (signer, store, release) = signer_with_a_waiting_write(&world, true).await;
    let mut closing = Box::pin(signer.close());
    poll_pending(closing.as_mut());
    assert!(matches!(
        StoreHandle::inline(store.clone())
            .acquire(&signer_namespace(&world.key.public()))
            .await,
        Err(StoreError::InUse)
    ));
    release.send(()).unwrap();
    assert_eq!(closing.await, Err(SignerError::Store(StoreError::Unknown)));
    Signer::open(world.env(store.clone()), world.keyring())
        .await
        .unwrap();
}

#[tokio::test]
async fn test_store_ownership_close_with_nothing_pending_releases_at_once() {
    let world = World::new();
    let store = Arc::new(MemoryStore::new());
    let signer = Signer::create(world.env(store.clone()), world.keyring(), SWITCH_ORIGIN)
        .await
        .unwrap();
    assert_eq!(
        Signer::open(world.env(store.clone()), world.keyring())
            .await
            .unwrap_err(),
        SignerError::Store(StoreError::InUse)
    );
    signer.close().await.unwrap();
    Signer::open(world.env(store.clone()), world.keyring())
        .await
        .unwrap();
}
