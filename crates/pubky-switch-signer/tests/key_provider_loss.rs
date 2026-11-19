//! A provider loss declared with the identity key alone, against scripted switches (Switch
//! spec 12.6, 12.8): from every store state, with the account's service dead, refusing,
//! behind or hostile, each case ends with the recovering install named at the service the
//! user picked and signing on there. Then the rules that hold it back and its crash points.

// Test code: a failure is a test failure.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;
#[path = "key_provider_loss/recovery_enrollment.rs"]
mod recovery_enrollment;

use std::sync::{Arc, Mutex};

use common::*;
use pubky_switch_client::store::{MemoryStore, StateStore, WriteBatch};
use pubky_switch_client::testing::{Fault as SwitchFault, Router, SWITCH_ORIGIN, ScriptedSwitch};
use pubky_switch_core::http::ErrorCode;
use pubky_switch_core::keys::AppKeys;
use pubky_switch_core::records::{
    AppCert, AppRecord, AppRecordBody, IDENTITY_PATH, IdentityDoc, SIGNER_BACKUP_PATH,
    app_record_path,
};
use pubky_switch_signer::state::signer_namespace;
use pubky_switch_signer::{
    AppFate, BackupFound, KeyRecoveryConfirmed, KeyRecoveryKind, KeyRecoveryStop,
    KeyRecoverySurvey, ReceivingApp, Refusal, Signer, SignerEnv, SignerError, SignerStatus,
    UserConfirmed,
};

const NEW_ORIGIN: &str = "https://recovery.example";

fn confirmed() -> UserConfirmed {
    UserConfirmed::shown_and_confirmed()
}

fn refused(stop: KeyRecoveryStop) -> SignerError {
    SignerError::Refused(Refusal::KeyRecovery(stop))
}

/// The service the user picks, and a router that reaches only it: the account's service is
/// dead.
fn picked_service(world: &World) -> (Arc<ScriptedSwitch>, Arc<Router>) {
    let service =
        ScriptedSwitch::unenrolled_at(&world.key, [0x5e; 32], Arc::clone(&world.clock), NEW_ORIGIN);
    let router = Arc::new(Router::new());
    router.add_switch(NEW_ORIGIN, &service);
    (service, router)
}

fn env_on(world: &World, store: &Arc<MemoryStore>, router: &Arc<Router>) -> SignerEnv {
    let mut env = world.env(store.clone());
    env.transport = router.clone();
    env
}

async fn survey(
    world: &World,
    store: &Arc<MemoryStore>,
    router: &Arc<Router>,
) -> Result<KeyRecoverySurvey, SignerError> {
    Signer::survey_provider_loss_with_key(env_on(world, store, router), world.keyring(), NEW_ORIGIN)
        .await
}

/// The survey of a provider loss over `store`, then the declaration under its confirmation,
/// dropping `dropped`.
async fn lost_with_key(
    world: &World,
    store: &Arc<MemoryStore>,
    router: &Arc<Router>,
    dropped: &[[u8; 16]],
) -> Result<Signer, SignerError> {
    let shown = survey(world, store, router).await?;
    Signer::declare_provider_loss_with_key(
        env_on(world, store, router),
        world.keyring(),
        KeyRecoveryConfirmed::shown_and_confirmed(&shown, dropped),
    )
    .await
}

/// `app` publishes its record, carrying `cert`, on the Homeserver (Switch spec 4.2).
fn publish_record(world: &World, app: &App, cert: &AppCert) {
    let record =
        AppRecord::sign(&app.keys, AppRecordBody::new(cert, Vec::new(), START_MS)).unwrap();
    world.homeserver.set(
        &app_record_path(&app.keys.app_id_bytes()),
        serde_json::to_vec(record.signed()).unwrap(),
    );
}

/// An app holding `notes`, approved and joined, its record published, with its certificate.
async fn joined(world: &World, signer: &mut Signer, seed: u8) -> (App, AppCert) {
    let app = App::with_keys(
        AppKeys::from_secrets([seed; 32], [seed.wrapping_add(1); 32]),
        &["notes", "notes_sync"],
        None,
        [seed; 32],
    );
    let review = signer.review(&app.request, &app.auth).unwrap();
    let approved = signer.approve(review).await.unwrap();
    signer.claim_delivered(&approved.request).await.unwrap();
    let cert = world.join(&app, &approved);
    publish_record(world, &app, &cert);
    (app, cert)
}

/// The version `signer` delivered last names it, at the next generation after `lost`, at the
/// picked service, and it signs on there: a later ordinary version is delivered, published
/// and backed up.
async fn signs_at(world: &World, service: &ScriptedSwitch, signer: &mut Signer, lost: u64) {
    signs_at_origin(world, service, signer, lost, NEW_ORIGIN).await;
}

async fn signs_at_origin(
    world: &World,
    service: &ScriptedSwitch,
    signer: &mut Signer,
    lost: u64,
    origin: &str,
) {
    let doc = signer.identity_doc().unwrap().unwrap();
    assert_eq!(doc.body().signer, signer.install_id());
    assert_eq!(doc.inbox().url, origin);
    assert_eq!(doc.generation(), lost + 1);
    assert_eq!(doc.body().recovery_from, Some(lost));
    assert_eq!(service.identity_doc().unwrap().signed(), doc.signed());
    assert_eq!(signer.status(), SignerStatus::Signing);
    let later = signer.set_record_max_age(Some(3_600)).await.unwrap();
    assert_eq!(later.version(), doc.version() + 1);
    assert_eq!(service.identity_doc().unwrap().signed(), later.signed());
    assert_eq!(world.published().unwrap().signed(), later.signed());
    assert_eq!(world.backup().identity_doc().signed(), later.signed());
}

fn remove_file(world: &World, path: &str) {
    world.homeserver.files.lock().unwrap().remove(path);
}

#[tokio::test]
async fn test_key_provider_loss_new_device_at_a_dead_service() {
    // The account's service is gone and no install holds the records: a new device declares
    // the loss with the key alone, on the backup's version, and keeps the app.
    let world = World::new();
    let (mut old, _) = world.enrolled().await;
    let (app, _) = joined(&world, &mut old, 40).await;
    let held = old.identity_doc().unwrap().unwrap();
    drop(old);
    let (service, router) = picked_service(&world);
    let store = Arc::new(MemoryStore::new());
    let shown = survey(&world, &store, &router).await.unwrap();
    assert_eq!(shown.origin, NEW_ORIGIN);
    assert_eq!(shown.kind, KeyRecoveryKind::ProviderLoss { lost: Some(1) });
    assert_eq!(shown.version, held.version());
    assert_eq!(shown.apps, vec![(app.keys.app_id_bytes(), AppFate::Stays)]);
    assert!(matches!(shown.backup, BackupFound::Stale { .. }));
    let mut signer = Signer::declare_provider_loss_with_key(
        env_on(&world, &store, &router),
        world.keyring(),
        KeyRecoveryConfirmed::shown_and_confirmed(&shown, &[]),
    )
    .await
    .unwrap();
    let doc = signer.identity_doc().unwrap().unwrap();
    assert!(doc.version() > held.version());
    assert!(doc.listed_cert(&app.keys.app_id_bytes()).is_some());
    signs_at(&world, &service, &mut signer, 1).await;
}

#[tokio::test]
async fn test_key_provider_loss_with_nothing_but_the_key() {
    // Service, Homeserver and devices all lost: the first document takes the provider loss's
    // shape, at a generation and a version from the time, never version 1.
    let world = World::new();
    let (old, _) = world.enrolled().await;
    drop(old);
    remove_file(&world, IDENTITY_PATH);
    remove_file(&world, SIGNER_BACKUP_PATH);
    let (service, router) = picked_service(&world);
    let store = Arc::new(MemoryStore::new());
    let shown = survey(&world, &store, &router).await.unwrap();
    assert_eq!(shown.kind, KeyRecoveryKind::ProviderLoss { lost: None });
    assert_eq!((shown.version, shown.generation), (0, 0));
    assert_eq!(shown.backup, BackupFound::Missing);
    let mut signer = Signer::declare_provider_loss_with_key(
        env_on(&world, &store, &router),
        world.keyring(),
        KeyRecoveryConfirmed::shown_and_confirmed(&shown, &[]),
    )
    .await
    .unwrap();
    let doc = signer.identity_doc().unwrap().unwrap();
    let lost = START_MS / 1_000;
    assert!(doc.version() > START_MS);
    assert!(doc.body().apps.is_empty());
    signs_at(&world, &service, &mut signer, lost).await;
}

#[tokio::test]
async fn test_key_provider_loss_first_version_in_flight_to_a_dead_service() {
    // The first version was signed and sent, the service died before it answered, and the
    // backup is gone: the loss is declared on that version, never on a second version 1.
    let world = World::new();
    let store = Arc::new(MemoryStore::new());
    let mut signer = Signer::create(world.env(store.clone()), world.keyring(), SWITCH_ORIGIN)
        .await
        .unwrap();
    world.switch.fail_next(SwitchFault::Unreachable {
        path: "/identity".into(),
        after: 0,
    });
    signer.resume().await.unwrap_err();
    assert!(signer.identity_doc().unwrap().is_none());
    drop(signer);
    remove_file(&world, SIGNER_BACKUP_PATH);
    let (service, router) = picked_service(&world);
    let shown = survey(&world, &store, &router).await.unwrap();
    assert_eq!(shown.kind, KeyRecoveryKind::ProviderLoss { lost: Some(1) });
    assert_eq!((shown.version, shown.generation), (1, 1));
    let mut signer = lost_with_key(&world, &store, &router, &[]).await.unwrap();
    assert_eq!(signer.identity_doc().unwrap().unwrap().version(), 2);
    signs_at(&world, &service, &mut signer, 1).await;
}

#[tokio::test]
async fn test_key_provider_loss_old_signer_mid_hand_over_at_a_dead_service() {
    // A hand-over was stored, then the service died: the old signer can neither abort nor
    // take back. In place, the key-only declaration drops the hand-over and recovers.
    let world = World::new();
    let (mut old, store) = world.enrolled().await;
    let (app, _) = joined(&world, &mut old, 41).await;
    old.hand_over_to(app.keys.app_id_bytes(), confirmed())
        .await
        .unwrap();
    assert!(matches!(old.status(), SignerStatus::HandingOver { .. }));
    let install = old.install_id();
    let handed = old.identity_doc().unwrap().unwrap();
    drop(old);
    let (service, router) = picked_service(&world);
    let mut signer = lost_with_key(&world, &store, &router, &[]).await.unwrap();
    assert_eq!(signer.install_id(), install);
    // Above the version the hand-over's target may have signed first.
    assert_eq!(
        signer.identity_doc().unwrap().unwrap().version(),
        handed.version() + 2
    );
    assert!(
        signer
            .identity_doc()
            .unwrap()
            .unwrap()
            .listed_cert(&app.keys.app_id_bytes())
            .is_some()
    );
    signs_at(&world, &service, &mut signer, 1).await;
}

#[tokio::test]
async fn test_key_provider_loss_receiving_install_mid_take_over_at_a_dead_service() {
    // The receiving install stored the take-over and the service died before its first
    // delivery: its vault is empty. With the user's own copy of the key in the vault, the
    // key-only declaration drops the take-over and recovers on that store.
    let world = World::new();
    let (mut old, _) = world.enrolled().await;
    let (app, cert) = joined(&world, &mut old, 42).await;
    old.hand_over_to(app.keys.app_id_bytes(), confirmed())
        .await
        .unwrap();
    drop(old);
    let target = ReceivingApp {
        keys: app.keys.clone(),
        cert,
        origin: SWITCH_ORIGIN.to_owned(),
        service_key: world.switch.service_key(),
    };
    let store = Arc::new(MemoryStore::new());
    world.switch.fail_next(SwitchFault::Unreachable {
        path: "/apps".into(),
        after: 0,
    });
    let empty = Arc::new(Vault(Mutex::new(None)));
    Signer::receive_hand_over(world.env(store.clone()), &target, empty)
        .await
        .unwrap_err();
    let (service, router) = picked_service(&world);
    let mut signer = lost_with_key(&world, &store, &router, &[]).await.unwrap();
    signs_at(&world, &service, &mut signer, 1).await;
}

#[tokio::test]
async fn test_receiving_install_resumes_with_its_sealed_key_when_the_service_returns() {
    let world = World::new();
    let (mut old, _) = world.enrolled().await;
    let (app, cert) = joined(&world, &mut old, 42).await;
    old.hand_over_to(app.keys.app_id_bytes(), confirmed())
        .await
        .unwrap();
    drop(old);
    let target = ReceivingApp {
        keys: app.keys.clone(),
        cert,
        origin: SWITCH_ORIGIN.to_owned(),
        service_key: world.switch.service_key(),
    };
    let store = Arc::new(MemoryStore::new());
    world.switch.fail_next(SwitchFault::Unreachable {
        path: "/apps".into(),
        after: 0,
    });
    let empty = Arc::new(Vault(Mutex::new(None)));
    Signer::receive_hand_over(world.env(store.clone()), &target, empty.clone())
        .await
        .unwrap_err();
    let (_, router) = picked_service(&world);
    let identity = target.cert.identity();
    let remaining = || {
        store
            .scan(&signer_namespace(&identity), b"", None, 10)
            .unwrap()
    };
    let before = remaining();
    assert!(!before.is_empty());
    let error = Signer::resume_take_over(
        env_on(&world, &store, &router),
        identity,
        &target.keys,
        empty.clone(),
    )
    .await
    .unwrap_err();
    assert!(matches!(error, SignerError::Switch(_)), "{error:?}");
    assert_eq!(before, remaining());
    assert!(matches!(
        pubky_switch_signer::IdentityKeyring::open(empty.clone()),
        Err(pubky_switch_signer::KeyError::Missing)
    ));

    let mut signer =
        Signer::resume_take_over(world.env(store), identity, &target.keys, empty.clone())
            .await
            .unwrap();
    assert_eq!(
        pubky_switch_signer::IdentityKeyring::open(empty)
            .unwrap()
            .public_key(),
        identity
    );
    let later = signer.set_record_max_age(Some(3_600)).await.unwrap();
    assert_eq!(
        world.switch.identity_doc().unwrap().signed(),
        later.signed()
    );
}

#[tokio::test]
async fn test_key_provider_loss_service_behind_the_homeserver() {
    // The service was rolled back below the version the Homeserver publishes: the recovery at
    // the service is refused, and the provider loss builds on the Homeserver's copy, so the
    // app the later version removed stays removed.
    let world = World::new();
    let (mut old, store) = world.enrolled().await;
    let (kept, _) = joined(&world, &mut old, 43).await;
    let (removed, _) = joined(&world, &mut old, 45).await;
    let before = world.switch.identity_doc().unwrap();
    old.revoke(removed.keys.app_id_bytes(), None, confirmed())
        .await
        .unwrap();
    let newest = old.identity_doc().unwrap().unwrap();
    assert!(newest.listed_cert(&removed.keys.app_id_bytes()).is_none());
    drop(old);
    drop(store);
    remove_file(&world, SIGNER_BACKUP_PATH);
    world.switch.lose_identity();
    world.switch.deliver_identity(&before).unwrap_or_default();
    // The service shows the older copy: the recovery there is refused.
    let at_service = Arc::new(MemoryStore::new());
    let refusal = Signer::survey_key_recovery_new(world.env(at_service), world.keyring())
        .await
        .unwrap_err();
    assert!(matches!(
        refusal,
        SignerError::Refused(Refusal::KeyRecovery(
            KeyRecoveryStop::ServiceBehind { .. } | KeyRecoveryStop::SwitchCopy
        ))
    ));
    let (service, router) = picked_service(&world);
    router.add_switch(SWITCH_ORIGIN, &world.switch);
    let store = Arc::new(MemoryStore::new());
    let shown = survey(&world, &store, &router).await.unwrap();
    assert_eq!(shown.version, newest.version());
    let mut signer = lost_with_key(&world, &store, &router, &[]).await.unwrap();
    let doc = signer.identity_doc().unwrap().unwrap();
    assert!(doc.listed_cert(&removed.keys.app_id_bytes()).is_none());
    assert!(doc.listed_cert(&kept.keys.app_id_bytes()).is_some());
    signs_at(&world, &service, &mut signer, 1).await;
}

#[tokio::test]
async fn test_key_provider_loss_refusing_service() {
    // The account's service answers every signer read with an error it signs: no recovery at
    // the service, and the provider loss goes on elsewhere.
    let world = World::new();
    let (old, _) = world.enrolled().await;
    drop(old);
    for _ in 0..4 {
        world.switch.fail_next(SwitchFault::Error {
            path: "/apps".into(),
            code: ErrorCode::Staged,
            current: serde_json::Value::Null,
        });
    }
    let at_service = Arc::new(MemoryStore::new());
    assert_eq!(
        Signer::survey_key_recovery_new(world.env(at_service), world.keyring())
            .await
            .unwrap_err(),
        refused(KeyRecoveryStop::NotServing)
    );
    let (service, router) = picked_service(&world);
    router.add_switch(SWITCH_ORIGIN, &world.switch);
    let store = Arc::new(MemoryStore::new());
    let mut signer = lost_with_key(&world, &store, &router, &[]).await.unwrap();
    signs_at(&world, &service, &mut signer, 1).await;
}

/// The records and the flow `store` holds, as bytes.
fn stored(world: &World, store: &MemoryStore) -> (Option<Vec<u8>>, Option<Vec<u8>>) {
    let ns = signer_namespace(&world.key.public());
    (
        store.get(&ns, b"state").unwrap(),
        store.get(&ns, b"flow").unwrap(),
    )
}

fn edit_state(world: &World, store: &MemoryStore, edit: impl FnOnce(&mut serde_json::Value)) {
    let ns = signer_namespace(&world.key.public());
    let bytes = store.get(&ns, b"state").unwrap().unwrap();
    let mut state: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    edit(&mut state);
    let mut batch = WriteBatch::new();
    batch
        .put(&ns, b"state".to_vec(), serde_json::to_vec(&state).unwrap())
        .unwrap();
    store.commit(batch).unwrap();
}

/// A backup holding `doc`, which lists no app, of the account the backup on the Homeserver
/// names.
fn backup_holding(world: &World, doc: &IdentityDoc) -> Vec<u8> {
    let records = pubky_switch_core::records::SignerRecords::new(
        pubky_switch_core::keys::IdentityKey::from_secret(SECRET),
        doc.clone(),
        world.backup().account_created(),
        &[],
        &[],
        pubky_switch_core::records::Limits::default(),
        &[],
        None,
    )
    .unwrap();
    let backup = pubky_switch_core::records::SignerBackup::seal(&world.key, &records).unwrap();
    serde_json::to_vec(&backup).unwrap()
}

/// `doc` at `version` and `generation`, naming `install`, signed by the identity key.
fn signed_at(
    world: &World,
    doc: &IdentityDoc,
    version: u64,
    generation: u64,
    install: u8,
) -> IdentityDoc {
    let mut body = doc.body().clone();
    body.version = version;
    body.generation = generation;
    body.recovery_from = (generation > doc.generation()).then(|| generation - 1);
    body.signer = [install; 16];
    IdentityDoc::sign(&world.key, body).unwrap()
}

#[tokio::test]
async fn test_key_provider_loss_over_unusable_records_at_a_dead_service() {
    // The records don't read, the backup is gone and the service is dead: the declaration
    // takes what still reads, and the app, whose record is on the Homeserver, stays.
    let world = World::new();
    let (mut old, store) = world.enrolled().await;
    let (app, _) = joined(&world, &mut old, 46).await;
    drop(old);
    let ns = signer_namespace(&world.key.public());
    let mut batch = WriteBatch::new();
    batch.put(&ns, b"flow".to_vec(), b"{".to_vec()).unwrap();
    store.commit(batch).unwrap();
    remove_file(&world, SIGNER_BACKUP_PATH);
    let (service, router) = picked_service(&world);
    let mut signer = lost_with_key(&world, &store, &router, &[]).await.unwrap();
    assert!(
        signer
            .identity_doc()
            .unwrap()
            .unwrap()
            .listed_cert(&app.keys.app_id_bytes())
            .is_some()
    );
    signs_at(&world, &service, &mut signer, 1).await;
}

#[tokio::test]
async fn test_key_provider_loss_on_a_backup_above_the_services_copy() {
    // A live signer's losing sibling is the backup, at a version above the service's copy:
    // the recovery at the service refuses it, and the provider loss builds on it, above
    // every version it spent.
    let world = World::new();
    let (old, _) = world.enrolled().await;
    let doc = old.identity_doc().unwrap().unwrap();
    drop(old);
    let sibling = signed_at(&world, &doc, doc.version() + 3, doc.generation(), 7);
    world
        .homeserver
        .set(SIGNER_BACKUP_PATH, backup_holding(&world, &sibling));
    assert!(matches!(
        Signer::survey_key_recovery_new(world.env(Arc::new(MemoryStore::new())), world.keyring())
            .await
            .unwrap_err(),
        SignerError::Refused(Refusal::KeyRecovery(KeyRecoveryStop::ServiceBehind { .. }))
    ));
    let (service, router) = picked_service(&world);
    router.add_switch(SWITCH_ORIGIN, &world.switch);
    let store = Arc::new(MemoryStore::new());
    let shown = survey(&world, &store, &router).await.unwrap();
    assert_eq!((shown.version, shown.signer), (sibling.version(), [7; 16]));
    let mut signer = lost_with_key(&world, &store, &router, &[]).await.unwrap();
    assert_eq!(
        signer.identity_doc().unwrap().unwrap().version(),
        sibling.version() + 1
    );
    signs_at(&world, &service, &mut signer, 1).await;
}

#[tokio::test]
async fn test_key_provider_loss_signs_above_every_version_seen() {
    // A higher version at a lower generation than the copy it builds on, another install's:
    // the recovery's version is above it too, and that install's backup doesn't stop it.
    let world = World::new();
    let (old, _) = world.enrolled().await;
    let doc = old.identity_doc().unwrap().unwrap();
    drop(old);
    let older_generation = signed_at(&world, &doc, 9, 1, 7);
    let base = signed_at(&world, &doc, 5, 2, 8);
    world
        .homeserver
        .set(IDENTITY_PATH, serde_json::to_vec(base.signed()).unwrap());
    world.homeserver.set(
        SIGNER_BACKUP_PATH,
        backup_holding(&world, &older_generation),
    );
    let (service, router) = picked_service(&world);
    let store = Arc::new(MemoryStore::new());
    let shown = survey(&world, &store, &router).await.unwrap();
    assert_eq!((shown.version, shown.generation), (5, 2));
    assert_eq!(shown.kind, KeyRecoveryKind::ProviderLoss { lost: Some(2) });
    let mut signer = lost_with_key(&world, &store, &router, &[]).await.unwrap();
    assert_eq!(signer.identity_doc().unwrap().unwrap().version(), 10);
    signs_at(&world, &service, &mut signer, 2).await;
}

#[tokio::test]
async fn test_key_provider_loss_in_place_when_another_install_signs_and_the_service_dies() {
    // Another install took over, this one stopped as not named, and then the service died:
    // in place, the declaration builds on the other install's version.
    let world = World::new();
    let (mut old, store) = world.enrolled().await;
    let doc = old.identity_doc().unwrap().unwrap();
    let other = world.other_install_version(&doc, [9; 16]);
    world.switch.deliver_identity(&other).unwrap();
    old.set_record_max_age(Some(1)).await.unwrap_err();
    assert_eq!(old.status(), SignerStatus::ManagedBy { install: [9; 16] });
    drop(old);
    let (service, router) = picked_service(&world);
    router.add_switch(SWITCH_ORIGIN, &world.switch);
    world.switch.fail_next(SwitchFault::Unreachable {
        path: "/".into(),
        after: 0,
    });
    let shown = survey(&world, &store, &router).await.unwrap();
    assert_eq!(shown.version, other.version());
    let mut signer = lost_with_key(&world, &store, &router, &[]).await.unwrap();
    assert!(signer.identity_doc().unwrap().unwrap().version() > other.version());
    signs_at(&world, &service, &mut signer, 1).await;
}

#[tokio::test]
async fn test_key_provider_loss_after_the_account_was_erased() {
    // The account was erased and the service is gone: in place, the identity recovers at
    // another service.
    let world = World::new();
    let (mut old, store) = world.enrolled().await;
    old.close_account(confirmed()).await.unwrap();
    assert_eq!(old.status(), SignerStatus::Erased);
    drop(old);
    let (service, router) = picked_service(&world);
    let mut signer = lost_with_key(&world, &store, &router, &[]).await.unwrap();
    signs_at(&world, &service, &mut signer, 1).await;
}

#[tokio::test]
async fn test_key_provider_loss_after_a_refused_declaration() {
    // A provider loss declared from the records was refused at its service, and its backup
    // and the Homeserver's copy are gone: the key-only declaration starts above the
    // generation that declaration sent a start for.
    let world = World::new();
    let (old, store) = world.enrolled().await;
    drop(old);
    let (refusing, router) = picked_service(&world);
    let mut env = world.env(store.clone());
    env.transport = router.clone();
    let mut old = Signer::open(env, world.keyring()).await.unwrap();
    refusing.fail_next(SwitchFault::Error {
        path: "/identity".into(),
        code: ErrorCode::BadRequest,
        current: serde_json::Value::Null,
    });
    old.declare_provider_loss(NEW_ORIGIN, confirmed())
        .await
        .unwrap_err();
    assert_eq!(
        old.status(),
        SignerStatus::RecoveryRefused {
            origin: NEW_ORIGIN.into()
        }
    );
    drop(old);
    remove_file(&world, SIGNER_BACKUP_PATH);
    remove_file(&world, IDENTITY_PATH);
    const THIRD: &str = "https://third.example";
    let third =
        ScriptedSwitch::unenrolled_at(&world.key, [0x6e; 32], Arc::clone(&world.clock), THIRD);
    router.add_switch(THIRD, &third);
    let shown = Signer::survey_provider_loss_with_key(
        env_on(&world, &store, &router),
        world.keyring(),
        THIRD,
    )
    .await
    .unwrap();
    assert_eq!(shown.kind, KeyRecoveryKind::ProviderLoss { lost: Some(2) });
    let mut signer = Signer::declare_provider_loss_with_key(
        env_on(&world, &store, &router),
        world.keyring(),
        KeyRecoveryConfirmed::shown_and_confirmed(&shown, &[]),
    )
    .await
    .unwrap();
    signs_at_origin(&world, &third, &mut signer, 2, THIRD).await;
}

#[tokio::test]
async fn test_key_provider_loss_survey_changed_leaves_the_store_as_found() {
    // Between the survey and the declaration another install publishes a newer version: the
    // declaration is refused before anything is written, and the records are as found.
    let world = World::new();
    let (old, store) = world.enrolled().await;
    let doc = old.identity_doc().unwrap().unwrap();
    drop(old);
    let (_, router) = picked_service(&world);
    let shown = survey(&world, &store, &router).await.unwrap();
    let found = stored(&world, &store);
    let newer = world.other_install_version(&doc, [9; 16]);
    world
        .homeserver
        .set(IDENTITY_PATH, serde_json::to_vec(newer.signed()).unwrap());
    let refusal = Signer::declare_provider_loss_with_key(
        env_on(&world, &store, &router),
        world.keyring(),
        KeyRecoveryConfirmed::shown_and_confirmed(&shown, &[]),
    )
    .await
    .unwrap_err();
    assert_eq!(refusal, refused(KeyRecoveryStop::SurveyChanged));
    assert_eq!(stored(&world, &store), found);
}

#[tokio::test]
async fn test_key_provider_loss_needs_a_provider_loss_confirmation() {
    // A confirmation of a recovery at the service carries no service picked: refused, and
    // nothing is written.
    let world = World::new();
    let (old, _) = world.enrolled().await;
    drop(old);
    remove_file(&world, SIGNER_BACKUP_PATH);
    let store = Arc::new(MemoryStore::new());
    let at_service = Signer::survey_key_recovery_new(world.env(store.clone()), world.keyring())
        .await
        .unwrap();
    assert_eq!(at_service.kind, KeyRecoveryKind::AtService);
    let (_, router) = picked_service(&world);
    let refusal = Signer::declare_provider_loss_with_key(
        env_on(&world, &store, &router),
        world.keyring(),
        KeyRecoveryConfirmed::shown_and_confirmed(&at_service, &[]),
    )
    .await
    .unwrap_err();
    assert_eq!(refusal, refused(KeyRecoveryStop::SurveyChanged));
    assert_eq!(stored(&world, &store), (None, None));
}

#[tokio::test]
async fn test_key_provider_loss_reads_the_old_services_newer_copy() {
    // The Homeserver publishes an older version and the backup is gone, but the account's
    // service still answers: the declaration builds on that service's newer copy.
    let world = World::new();
    let (mut old, _) = world.enrolled().await;
    let first = old.identity_doc().unwrap().unwrap();
    let (app, _) = joined(&world, &mut old, 47).await;
    let newest = old.identity_doc().unwrap().unwrap();
    drop(old);
    world
        .homeserver
        .set(IDENTITY_PATH, serde_json::to_vec(first.signed()).unwrap());
    remove_file(&world, SIGNER_BACKUP_PATH);
    let (service, router) = picked_service(&world);
    router.add_switch(SWITCH_ORIGIN, &world.switch);
    let store = Arc::new(MemoryStore::new());
    let shown = survey(&world, &store, &router).await.unwrap();
    assert_eq!(shown.version, newest.version());
    let mut signer = lost_with_key(&world, &store, &router, &[]).await.unwrap();
    assert!(
        signer
            .identity_doc()
            .unwrap()
            .unwrap()
            .listed_cert(&app.keys.app_id_bytes())
            .is_some()
    );
    signs_at(&world, &service, &mut signer, 1).await;
}

#[tokio::test]
async fn test_key_provider_loss_at_the_same_service_with_no_copy_elsewhere() {
    // The Homeserver lost the copy and the backup, so nothing names the service: the user
    // picks the account's own service, whose copy the declaration builds on, there.
    let world = World::new();
    let (mut old, _) = world.enrolled().await;
    let (app, _) = joined(&world, &mut old, 48).await;
    drop(old);
    remove_file(&world, IDENTITY_PATH);
    remove_file(&world, SIGNER_BACKUP_PATH);
    let store = Arc::new(MemoryStore::new());
    assert_eq!(
        Signer::survey_key_recovery_new(world.env(store.clone()), world.keyring())
            .await
            .unwrap_err(),
        refused(KeyRecoveryStop::NoCopy)
    );
    let shown = Signer::survey_provider_loss_with_key(
        world.env(store.clone()),
        world.keyring(),
        SWITCH_ORIGIN,
    )
    .await
    .unwrap();
    assert_eq!(shown.kind, KeyRecoveryKind::ProviderLoss { lost: Some(1) });
    let mut signer = Signer::declare_provider_loss_with_key(
        world.env(store),
        world.keyring(),
        KeyRecoveryConfirmed::shown_and_confirmed(&shown, &[]),
    )
    .await
    .unwrap();
    assert!(
        signer
            .identity_doc()
            .unwrap()
            .unwrap()
            .listed_cert(&app.keys.app_id_bytes())
            .is_some()
    );
    let switch = Arc::clone(&world.switch);
    signs_at_origin(&world, &switch, &mut signer, 1, SWITCH_ORIGIN).await;
}

#[tokio::test]
async fn test_key_provider_loss_keeps_revocations_and_drops_apps() {
    // A revocation asked for in place that the dead service never took is carried out at
    // the new service, and an app the user drops in the survey is removed too.
    let world = World::new();
    let (mut old, store) = world.enrolled().await;
    let (pending, _) = joined(&world, &mut old, 50).await;
    let (dropped, _) = joined(&world, &mut old, 52).await;
    let (kept, _) = joined(&world, &mut old, 54).await;
    world.switch.fail_next(SwitchFault::Unreachable {
        path: "/revoke".into(),
        after: 0,
    });
    old.revoke(pending.keys.app_id_bytes(), None, confirmed())
        .await
        .unwrap_err();
    drop(old);
    let (service, router) = picked_service(&world);
    let shown = survey(&world, &store, &router).await.unwrap();
    let fate = |app: &App| {
        shown
            .apps
            .iter()
            .find(|(id, _)| *id == app.keys.app_id_bytes())
            .unwrap()
            .1
    };
    assert!(matches!(fate(&pending), AppFate::RevocationPending { .. }));
    assert_eq!(fate(&dropped), AppFate::Stays);
    let mut signer = Signer::declare_provider_loss_with_key(
        env_on(&world, &store, &router),
        world.keyring(),
        KeyRecoveryConfirmed::shown_and_confirmed(&shown, &[dropped.keys.app_id_bytes()]),
    )
    .await
    .unwrap();
    let doc = signer.identity_doc().unwrap().unwrap();
    assert!(doc.listed_cert(&pending.keys.app_id_bytes()).is_none());
    assert!(doc.listed_cert(&dropped.keys.app_id_bytes()).is_none());
    assert!(doc.listed_cert(&kept.keys.app_id_bytes()).is_some());
    assert_eq!(doc.body().signer, signer.install_id());
    let later = signer.set_record_max_age(Some(60)).await.unwrap();
    assert_eq!(service.identity_doc().unwrap().signed(), later.signed());
}

#[tokio::test]
async fn test_key_provider_loss_takes_removals_the_old_service_shows() {
    // The account's service shows an app revoked that no version removed: the survey says
    // so, and the version after the declaration's removes it.
    let world = World::new();
    let (mut old, _) = world.enrolled().await;
    let (revoked, _) = joined(&world, &mut old, 56).await;
    drop(old);
    world.switch.revoke(revoked.keys.app_id_bytes()).unwrap();
    remove_file(&world, SIGNER_BACKUP_PATH);
    let (service, router) = picked_service(&world);
    router.add_switch(SWITCH_ORIGIN, &world.switch);
    let store = Arc::new(MemoryStore::new());
    let shown = survey(&world, &store, &router).await.unwrap();
    assert!(matches!(
        shown.apps[0],
        (
            _,
            AppFate::RemovedAtSwitch {
                distrust_from: Some(_)
            }
        )
    ));
    let mut signer = lost_with_key(&world, &store, &router, &[]).await.unwrap();
    assert!(
        signer
            .identity_doc()
            .unwrap()
            .unwrap()
            .listed_cert(&revoked.keys.app_id_bytes())
            .is_none()
    );
    let later = signer.set_record_max_age(Some(60)).await.unwrap();
    assert_eq!(service.identity_doc().unwrap().signed(), later.signed());
}

#[tokio::test]
async fn test_key_provider_loss_refuses_a_copy_with_unknown_members() {
    // The copy it would build on carries a member this signer doesn't read: refused, since
    // its version would drop it; a signer that reads it declares the loss.
    let world = World::new();
    let (old, _) = world.enrolled().await;
    let doc = old.identity_doc().unwrap().unwrap();
    drop(old);
    let mut body = doc.body().clone();
    body.version += 1;
    let plain = IdentityDoc::sign(&world.key, body).unwrap();
    let mut value: serde_json::Value =
        serde_json::from_slice(&plain.signed().body_bytes().unwrap()).unwrap();
    value["later_member"] = 1.into();
    let signed = world.key.sign_doc(
        pubky_switch_core::labels::sig::IDENTITY,
        &[],
        serde_json::to_vec(&value).unwrap(),
    );
    world
        .homeserver
        .set(IDENTITY_PATH, serde_json::to_vec(&signed).unwrap());
    let (_, router) = picked_service(&world);
    let store = Arc::new(MemoryStore::new());
    assert_eq!(
        survey(&world, &store, &router).await.unwrap_err(),
        refused(KeyRecoveryStop::UnknownMembers)
    );
}

#[tokio::test]
async fn test_key_provider_loss_crash_after_its_commit_goes_on() {
    // The enrollment's answer is lost after the declaration was committed: the next run
    // sends the same enrollment and finishes.
    let world = World::new();
    let (old, store) = world.enrolled().await;
    drop(old);
    let (service, router) = picked_service(&world);
    service.fail_next(SwitchFault::LoseAnswer {
        path: "/enroll".into(),
    });
    lost_with_key(&world, &store, &router, &[])
        .await
        .unwrap_err();
    let mut signer = Signer::open(env_on(&world, &store, &router), world.keyring())
        .await
        .unwrap();
    assert!(matches!(signer.status(), SignerStatus::Recovering { .. }));
    signer.resume().await.unwrap();
    signs_at(&world, &service, &mut signer, 1).await;
}

#[tokio::test]
async fn test_key_provider_loss_twice_in_a_row() {
    // The service picked dies too, before any other install: the next declaration builds on
    // the first one's version, a generation further.
    let world = World::new();
    let (old, _) = world.enrolled().await;
    drop(old);
    let (_, router) = picked_service(&world);
    let first = lost_with_key(&world, &Arc::new(MemoryStore::new()), &router, &[])
        .await
        .unwrap();
    let recovered = first.identity_doc().unwrap().unwrap();
    drop(first);
    const THIRD: &str = "https://third.example";
    let third =
        ScriptedSwitch::unenrolled_at(&world.key, [0x6e; 32], Arc::clone(&world.clock), THIRD);
    let router = Arc::new(Router::new());
    router.add_switch(THIRD, &third);
    let store = Arc::new(MemoryStore::new());
    let shown = Signer::survey_provider_loss_with_key(
        env_on(&world, &store, &router),
        world.keyring(),
        THIRD,
    )
    .await
    .unwrap();
    assert_eq!(shown.version, recovered.version());
    let mut signer = Signer::declare_provider_loss_with_key(
        env_on(&world, &store, &router),
        world.keyring(),
        KeyRecoveryConfirmed::shown_and_confirmed(&shown, &[]),
    )
    .await
    .unwrap();
    signs_at_origin(&world, &third, &mut signer, 2, THIRD).await;
}

#[tokio::test]
async fn test_key_provider_loss_keeps_spent_epochs() {
    // The records spent epochs past every copy's: the declaration goes ahead and keeps them.
    let world = World::new();
    let (old, store) = world.enrolled().await;
    drop(old);
    edit_state(&world, &store, |state| state["epoch_through"] = 9.into());
    let (service, router) = picked_service(&world);
    let mut signer = lost_with_key(&world, &store, &router, &[]).await.unwrap();
    signs_at(&world, &service, &mut signer, 1).await;
}

#[tokio::test]
async fn test_key_provider_loss_signs_above_its_records_behind() {
    // The records saw a newer version of their own that no source still shows: the
    // declaration's version is above it.
    let world = World::new();
    let (old, store) = world.enrolled().await;
    let doc = old.identity_doc().unwrap().unwrap();
    drop(old);
    edit_state(&world, &store, |state| {
        state["records_behind"] = (doc.version() + 7).into();
    });
    let (service, router) = picked_service(&world);
    let mut signer = lost_with_key(&world, &store, &router, &[]).await.unwrap();
    assert_eq!(
        signer.identity_doc().unwrap().unwrap().version(),
        doc.version() + 8
    );
    signs_at(&world, &service, &mut signer, 1).await;
}

#[tokio::test]
async fn test_key_provider_loss_with_nothing_but_the_key_keeps_the_revocations() {
    // No copy reads anywhere, but the records still hold an App ID revoked for good: the
    // first document's enrollment names it, so the new service refuses it from the start.
    let world = World::new();
    let (mut old, store) = world.enrolled().await;
    let (app, _) = joined(&world, &mut old, 58).await;
    old.revoke(app.keys.app_id_bytes(), None, confirmed())
        .await
        .unwrap();
    drop(old);
    edit_state(&world, &store, |state| {
        state["newest"] = serde_json::Value::Null;
    });
    remove_file(&world, IDENTITY_PATH);
    remove_file(&world, SIGNER_BACKUP_PATH);
    let (service, router) = picked_service(&world);
    let shown = survey(&world, &store, &router).await.unwrap();
    assert_eq!(shown.kind, KeyRecoveryKind::ProviderLoss { lost: None });
    assert_eq!(shown.revoked, vec![app.keys.app_id_bytes()]);
    let mut signer = lost_with_key(&world, &store, &router, &[]).await.unwrap();
    assert!(service.kept_app_ids().contains(&app.keys.app_id_bytes()));
    signs_at(&world, &service, &mut signer, START_MS / 1_000).await;
}

#[tokio::test]
async fn test_key_provider_loss_takes_a_copy_in_another_writers_encoding() {
    // The copy it builds on was written by another conforming signer, pretty-printed:
    // nothing in it is unknown, and the declaration goes ahead.
    let world = World::new();
    let (old, _) = world.enrolled().await;
    let doc = old.identity_doc().unwrap().unwrap();
    drop(old);
    let mut body = doc.body().clone();
    body.version += 1;
    let plain = IdentityDoc::sign(&world.key, body).unwrap();
    let value: serde_json::Value =
        serde_json::from_slice(&plain.signed().body_bytes().unwrap()).unwrap();
    let signed = world.key.sign_doc(
        pubky_switch_core::labels::sig::IDENTITY,
        &[],
        serde_json::to_vec_pretty(&value).unwrap(),
    );
    world
        .homeserver
        .set(IDENTITY_PATH, serde_json::to_vec(&signed).unwrap());
    remove_file(&world, SIGNER_BACKUP_PATH);
    let (service, router) = picked_service(&world);
    let store = Arc::new(MemoryStore::new());
    let shown = survey(&world, &store, &router).await.unwrap();
    assert_eq!(shown.version, plain.version());
    let mut signer = lost_with_key(&world, &store, &router, &[]).await.unwrap();
    signs_at(&world, &service, &mut signer, 1).await;
}

#[tokio::test]
async fn test_key_provider_loss_reads_every_service_a_copy_names() {
    // The Homeserver shows, as its newest copy, an older version naming a former service,
    // while the backup names the service that serves the account and holds a newer version:
    // that service is read too, and the declaration builds on its copy.
    let world = World::new();
    let (mut old, _) = world.enrolled().await;
    let first = old.identity_doc().unwrap().unwrap();
    old.set_record_max_age(Some(60)).await.unwrap();
    let middle = old.identity_doc().unwrap().unwrap();
    old.set_record_max_age(Some(120)).await.unwrap();
    let newest = old.identity_doc().unwrap().unwrap();
    drop(old);
    world
        .homeserver
        .set(SIGNER_BACKUP_PATH, backup_holding(&world, &first));
    let mut body = middle.body().clone();
    body.inbox = pubky_switch_core::records::Inbox::new(
        "https://former.example",
        middle.inbox().service_key,
    );
    let former = IdentityDoc::sign(&world.key, body).unwrap();
    world
        .homeserver
        .set(IDENTITY_PATH, serde_json::to_vec(former.signed()).unwrap());
    let (service, router) = picked_service(&world);
    router.add_switch(SWITCH_ORIGIN, &world.switch);
    let store = Arc::new(MemoryStore::new());
    let shown = survey(&world, &store, &router).await.unwrap();
    assert_eq!(shown.version, newest.version());
    let mut signer = lost_with_key(&world, &store, &router, &[]).await.unwrap();
    assert_eq!(
        signer
            .identity_doc()
            .unwrap()
            .unwrap()
            .body()
            .record_max_age,
        Some(120)
    );
    signs_at(&world, &service, &mut signer, 1).await;
}

#[tokio::test]
async fn test_key_provider_loss_takes_revocations_every_service_shows() {
    // After a first declaration moved the identity, the former service, still answering,
    // shows an app revoked that the newer copy lists: the next declaration revokes it too.
    let world = World::new();
    let (mut old, _) = world.enrolled().await;
    let (app, _) = joined(&world, &mut old, 60).await;
    drop(old);
    let former_backup = world.homeserver.file(SIGNER_BACKUP_PATH).unwrap();
    let (moved_to, router) = picked_service(&world);
    let first = lost_with_key(&world, &Arc::new(MemoryStore::new()), &router, &[])
        .await
        .unwrap();
    assert!(
        first
            .identity_doc()
            .unwrap()
            .unwrap()
            .listed_cert(&app.keys.app_id_bytes())
            .is_some()
    );
    drop(first);
    world.switch.revoke(app.keys.app_id_bytes()).unwrap();
    world.homeserver.set(SIGNER_BACKUP_PATH, former_backup);
    const THIRD: &str = "https://third.example";
    let third =
        ScriptedSwitch::unenrolled_at(&world.key, [0x6e; 32], Arc::clone(&world.clock), THIRD);
    let router = Arc::new(Router::new());
    router.add_switch(SWITCH_ORIGIN, &world.switch);
    router.add_switch(NEW_ORIGIN, &moved_to);
    router.add_switch(THIRD, &third);
    let store = Arc::new(MemoryStore::new());
    let shown = Signer::survey_provider_loss_with_key(
        env_on(&world, &store, &router),
        world.keyring(),
        THIRD,
    )
    .await
    .unwrap();
    assert_eq!(shown.generation, 2);
    assert!(matches!(
        shown.apps[0],
        (
            _,
            AppFate::RemovedAtSwitch {
                distrust_from: Some(_)
            }
        )
    ));
    let mut signer = Signer::declare_provider_loss_with_key(
        env_on(&world, &store, &router),
        world.keyring(),
        KeyRecoveryConfirmed::shown_and_confirmed(&shown, &[]),
    )
    .await
    .unwrap();
    assert!(
        signer
            .identity_doc()
            .unwrap()
            .unwrap()
            .listed_cert(&app.keys.app_id_bytes())
            .is_none()
    );
    let later = signer.set_record_max_age(Some(60)).await.unwrap();
    assert_eq!(third.identity_doc().unwrap().signed(), later.signed());
}

#[tokio::test]
async fn test_key_provider_loss_binds_the_picked_services_key() {
    // The service picked answers its discovery under another key at the declaration than at
    // the survey: the declaration is refused before anything is written.
    let world = World::new();
    let (old, store) = world.enrolled().await;
    drop(old);
    let (first, router) = picked_service(&world);
    let shown = survey(&world, &store, &router).await.unwrap();
    assert_eq!(shown.service_key, first.service_key());
    let found = stored(&world, &store);
    let other =
        ScriptedSwitch::unenrolled_at(&world.key, [0x7e; 32], Arc::clone(&world.clock), NEW_ORIGIN);
    router.add_switch(NEW_ORIGIN, &other);
    let refusal = Signer::declare_provider_loss_with_key(
        env_on(&world, &store, &router),
        world.keyring(),
        KeyRecoveryConfirmed::shown_and_confirmed(&shown, &[]),
    )
    .await
    .unwrap_err();
    assert_eq!(refusal, refused(KeyRecoveryStop::SurveyChanged));
    assert_eq!(stored(&world, &store), found);
}

#[tokio::test]
async fn test_key_provider_loss_follows_no_key_but_the_discovered_one() {
    // The service's discovery is signed with one key and its enrollment answer names another:
    // that key is not followed, and no version naming it is delivered.
    let world = World::new();
    let (old, store) = world.enrolled().await;
    drop(old);
    let discovered =
        ScriptedSwitch::unenrolled_at(&world.key, [0x5e; 32], Arc::clone(&world.clock), NEW_ORIGIN);
    let answering =
        ScriptedSwitch::unenrolled_at(&world.key, [0x7e; 32], Arc::clone(&world.clock), NEW_ORIGIN);
    let (d, a) = (Arc::clone(&discovered), Arc::clone(&answering));
    let transport = Arc::new(pubky_switch_client::transport::MockTransport::with_handler(
        move |request| {
            if request.path_and_query.ends_with("/account") {
                d.handle(request)
            } else {
                a.handle(request)
            }
        },
    ));
    let env = || {
        let mut env = world.env(store.clone());
        env.transport = transport.clone();
        env
    };
    let shown = Signer::survey_provider_loss_with_key(env(), world.keyring(), NEW_ORIGIN)
        .await
        .unwrap();
    assert_eq!(shown.service_key, discovered.service_key());
    Signer::declare_provider_loss_with_key(
        env(),
        world.keyring(),
        KeyRecoveryConfirmed::shown_and_confirmed(&shown, &[]),
    )
    .await
    .unwrap_err();
    assert!(answering.identity_doc().is_none());
    assert!(discovered.identity_doc().is_none());
}

#[tokio::test]
async fn test_key_provider_loss_keeps_the_version_floor_it_showed() {
    // The Homeserver showed version 9 at the survey and an older version at the declaration,
    // the copy built on unchanged: the version signed is still above 9.
    let world = World::new();
    let (old, _) = world.enrolled().await;
    let doc = old.identity_doc().unwrap().unwrap();
    drop(old);
    let seen = signed_at(&world, &doc, 9, 1, 7);
    let base = signed_at(&world, &doc, 5, 2, 8);
    world
        .homeserver
        .set(SIGNER_BACKUP_PATH, backup_holding(&world, &base));
    world
        .homeserver
        .set(IDENTITY_PATH, serde_json::to_vec(seen.signed()).unwrap());
    let (service, router) = picked_service(&world);
    let store = Arc::new(MemoryStore::new());
    let shown = survey(&world, &store, &router).await.unwrap();
    assert_eq!((shown.version, shown.generation), (5, 2));
    let rolled_back = signed_at(&world, &doc, 4, 1, 7);
    world.homeserver.set(
        IDENTITY_PATH,
        serde_json::to_vec(rolled_back.signed()).unwrap(),
    );
    let mut signer = Signer::declare_provider_loss_with_key(
        env_on(&world, &store, &router),
        world.keyring(),
        KeyRecoveryConfirmed::shown_and_confirmed(&shown, &[]),
    )
    .await
    .unwrap();
    assert_eq!(signer.identity_doc().unwrap().unwrap().version(), 10);
    signs_at(&world, &service, &mut signer, 2).await;
}

#[tokio::test]
async fn test_key_provider_loss_confirmation_restores_nothing() {
    // A provider loss's confirmation given to a restore is refused, though a matching backup
    // is there: the restore would sign at the old service, which the user didn't confirm.
    let world = World::new();
    let (old, _) = world.enrolled().await;
    drop(old);
    let (_, router) = picked_service(&world);
    let store = Arc::new(MemoryStore::new());
    let shown = survey(&world, &store, &router).await.unwrap();
    let refusal = Signer::restore_new(
        world.env(store.clone()),
        world.keyring(),
        KeyRecoveryConfirmed::shown_and_confirmed(&shown, &[]),
    )
    .await
    .unwrap_err();
    assert_eq!(refusal, refused(KeyRecoveryStop::SurveyChanged));
    assert_eq!(stored(&world, &store), (None, None));
}

#[tokio::test]
async fn test_key_provider_loss_takes_an_earlier_time_for_a_removed_app() {
    // The copy built on removes an app from a later time than the one a backup shows the
    // user picked for its revocation: the version signed distrusts it from the earlier one.
    let world = World::new();
    let (mut old, _) = world.enrolled().await;
    let (app, _) = joined(&world, &mut old, 62).await;
    let id = app.keys.app_id_bytes();
    let picked = START_MS - 7_200_000;
    world.switch.fail_next(SwitchFault::Unreachable {
        path: "/revoke".into(),
        after: 0,
    });
    old.revoke(id, Some(picked), confirmed()).await.unwrap_err();
    old.set_record_max_age(Some(60)).await.unwrap();
    let doc = old.identity_doc().unwrap().unwrap();
    drop(old);
    let mut body = doc.body().clone();
    body.version += 1;
    body.apps.retain(|a| a.app_id != id);
    body.removed.push(pubky_switch_core::records::RemovedApp {
        app_id: id,
        distrust_from: START_MS,
    });
    let removing = IdentityDoc::sign(&world.key, body).unwrap();
    world.homeserver.set(
        IDENTITY_PATH,
        serde_json::to_vec(removing.signed()).unwrap(),
    );
    let (service, router) = picked_service(&world);
    let store = Arc::new(MemoryStore::new());
    let mut signer = lost_with_key(&world, &store, &router, &[]).await.unwrap();
    let removed = signer
        .identity_doc()
        .unwrap()
        .unwrap()
        .body()
        .removed
        .clone();
    assert_eq!(
        removed
            .iter()
            .find(|r| r.app_id == id)
            .unwrap()
            .distrust_from,
        picked
    );
    signs_at(&world, &service, &mut signer, 1).await;
    let later = world.published().unwrap();
    assert_eq!(
        later
            .body()
            .removed
            .iter()
            .find(|r| r.app_id == id)
            .unwrap()
            .distrust_from,
        picked
    );
}

#[tokio::test]
async fn test_key_provider_loss_takes_the_earlier_of_a_departure_and_a_revocation() {
    // The account's service shows an app departed, then revoked later: the earlier time is
    // the one it is distrusted from.
    let world = World::new();
    let (mut old, _) = world.enrolled().await;
    let (app, _) = joined(&world, &mut old, 64).await;
    let id = app.keys.app_id_bytes();
    drop(old);
    let departed = pubky_switch_client::clock::Clock::now_ms(world.clock.as_ref());
    world.switch.leave(id).unwrap();
    world.clock.advance_ms(3_600_000);
    world.switch.revoke(id).unwrap_or_default();
    remove_file(&world, SIGNER_BACKUP_PATH);
    let (_, router) = picked_service(&world);
    router.add_switch(SWITCH_ORIGIN, &world.switch);
    let store = Arc::new(MemoryStore::new());
    let shown = survey(&world, &store, &router).await.unwrap();
    assert_eq!(
        shown.apps,
        vec![(
            id,
            AppFate::RemovedAtSwitch {
                distrust_from: Some(departed)
            }
        )]
    );
}

#[tokio::test]
async fn test_key_provider_loss_follows_a_copy_to_the_service_it_names() {
    // The Homeserver names the first service only. That service holds a newer copy naming a
    // second one, which serves a newer version still: the survey follows the copies there
    // and builds on that version.
    let world = World::new();
    let (old, _) = world.enrolled().await;
    let first = old.identity_doc().unwrap().unwrap();
    drop(old);
    let (second, router) = picked_service(&world);
    let moved = lost_with_key(&world, &Arc::new(MemoryStore::new()), &router, &[])
        .await
        .unwrap()
        .identity_doc()
        .unwrap()
        .unwrap();
    let mut body = first.body().clone();
    body.version = moved.version() - 1;
    body.inbox = moved.inbox().clone();
    let pointing = IdentityDoc::sign(&world.key, body).unwrap();
    world.switch.lose_identity();
    world.switch.deliver_identity(&pointing).unwrap();
    world
        .homeserver
        .set(IDENTITY_PATH, serde_json::to_vec(first.signed()).unwrap());
    remove_file(&world, SIGNER_BACKUP_PATH);
    const THIRD: &str = "https://third.example";
    let third =
        ScriptedSwitch::unenrolled_at(&world.key, [0x6e; 32], Arc::clone(&world.clock), THIRD);
    let router = Arc::new(Router::new());
    router.add_switch(SWITCH_ORIGIN, &world.switch);
    router.add_switch(NEW_ORIGIN, &second);
    router.add_switch(THIRD, &third);
    let store = Arc::new(MemoryStore::new());
    let shown = Signer::survey_provider_loss_with_key(
        env_on(&world, &store, &router),
        world.keyring(),
        THIRD,
    )
    .await
    .unwrap();
    assert_eq!(
        world.switch.identity_doc().unwrap().signed(),
        pointing.signed()
    );
    assert_eq!((shown.version, shown.generation), (moved.version(), 2));
}

#[tokio::test]
async fn test_key_provider_loss_goes_on_past_a_service_that_flaps() {
    // The service being left shows an app revoked when it is surveyed and can't be reached
    // when the loss is declared, round after round: the declaration acts on what the user
    // confirmed, and the app is removed.
    let world = World::new();
    let (mut old, _) = world.enrolled().await;
    let (app, _) = joined(&world, &mut old, 66).await;
    let id = app.keys.app_id_bytes();
    drop(old);
    world.switch.revoke(id).unwrap();
    remove_file(&world, SIGNER_BACKUP_PATH);
    let (service, router) = picked_service(&world);
    router.add_switch(SWITCH_ORIGIN, &world.switch);
    let store = Arc::new(MemoryStore::new());
    let shown = survey(&world, &store, &router).await.unwrap();
    assert!(matches!(
        shown.apps[0],
        (_, AppFate::RemovedAtSwitch { .. })
    ));
    router.remove(SWITCH_ORIGIN);
    let mut signer = Signer::declare_provider_loss_with_key(
        env_on(&world, &store, &router),
        world.keyring(),
        KeyRecoveryConfirmed::shown_and_confirmed(&shown, &[]),
    )
    .await
    .unwrap();
    assert!(
        signer
            .identity_doc()
            .unwrap()
            .unwrap()
            .listed_cert(&id)
            .is_none()
    );
    signs_at(&world, &service, &mut signer, 1).await;
}

#[tokio::test]
async fn test_key_provider_loss_refuses_only_what_the_user_didnt_see() {
    // A revocation the service being left shows only at the declaration is new to the user:
    // refused. Surveyed again, it is shown, and the declaration goes ahead, whatever the
    // service shows then.
    let world = World::new();
    let (mut old, _) = world.enrolled().await;
    let (app, _) = joined(&world, &mut old, 68).await;
    let id = app.keys.app_id_bytes();
    drop(old);
    remove_file(&world, SIGNER_BACKUP_PATH);
    let (service, router) = picked_service(&world);
    router.add_switch(SWITCH_ORIGIN, &world.switch);
    let store = Arc::new(MemoryStore::new());
    let shown = survey(&world, &store, &router).await.unwrap();
    assert_eq!(shown.apps, vec![(id, AppFate::Stays)]);
    world.switch.revoke(id).unwrap();
    let refusal = Signer::declare_provider_loss_with_key(
        env_on(&world, &store, &router),
        world.keyring(),
        KeyRecoveryConfirmed::shown_and_confirmed(&shown, &[]),
    )
    .await
    .unwrap_err();
    assert_eq!(refusal, refused(KeyRecoveryStop::SurveyChanged));
    let shown = survey(&world, &store, &router).await.unwrap();
    router.remove(SWITCH_ORIGIN);
    let mut signer = Signer::declare_provider_loss_with_key(
        env_on(&world, &store, &router),
        world.keyring(),
        KeyRecoveryConfirmed::shown_and_confirmed(&shown, &[]),
    )
    .await
    .unwrap();
    assert!(
        signer
            .identity_doc()
            .unwrap()
            .unwrap()
            .listed_cert(&id)
            .is_none()
    );
    signs_at(&world, &service, &mut signer, 1).await;
}

#[tokio::test]
async fn test_key_provider_loss_takes_the_earlier_of_a_pick_and_a_services_time() {
    // The records picked a time to distrust an app from, and the service being left shows
    // it revoked at another: whichever is earlier is the one taken, in either order.
    for pick_first in [true, false] {
        let world = World::new();
        let (mut old, store) = world.enrolled().await;
        let (app, _) = joined(&world, &mut old, 70).await;
        let id = app.keys.app_id_bytes();
        let now = pubky_switch_client::clock::Clock::now_ms(world.clock.as_ref());
        world.switch.fail_next(SwitchFault::Unreachable {
            path: "/revoke".into(),
            after: 0,
        });
        old.revoke(id, Some(now - 7_200_000), confirmed())
            .await
            .unwrap_err();
        drop(old);
        world.switch.revoke(id).unwrap();
        // The records' pick, before or after the time the service shows.
        let picked = if pick_first {
            now - 7_200_000
        } else {
            now + 1_800_000
        };
        edit_state(&world, &store, |state| {
            state["revoking"][0]["distrust_from"] = picked.into();
        });
        let expected = picked.min(now);
        let (service, router) = picked_service(&world);
        router.add_switch(SWITCH_ORIGIN, &world.switch);
        let shown = survey(&world, &store, &router).await.unwrap();
        assert_eq!(
            shown.apps,
            vec![(
                id,
                AppFate::RemovedAtSwitch {
                    distrust_from: Some(expected)
                }
            )],
            "{pick_first}"
        );
        let mut signer = Signer::declare_provider_loss_with_key(
            env_on(&world, &store, &router),
            world.keyring(),
            KeyRecoveryConfirmed::shown_and_confirmed(&shown, &[]),
        )
        .await
        .unwrap();
        let doc = signer.identity_doc().unwrap().unwrap();
        assert_eq!(
            doc.body()
                .removed
                .iter()
                .find(|r| r.app_id == id)
                .unwrap()
                .distrust_from,
            expected,
            "{pick_first}"
        );
        signs_at(&world, &service, &mut signer, 1).await;
    }
}

#[tokio::test]
async fn test_key_provider_loss_takes_the_later_of_the_device_and_service_clocks() {
    // With nothing but the key, the first document's generation and version come from the
    // later of the device's clock and the picked service's: a service behind the device
    // can't set them lower, and one ahead raises them.
    for skew in [-240_000_i64, 240_000] {
        let world = World::new();
        let (old, _) = world.enrolled().await;
        drop(old);
        remove_file(&world, IDENTITY_PATH);
        remove_file(&world, SIGNER_BACKUP_PATH);
        let service_time = START_MS.checked_add_signed(skew).unwrap();
        let service = ScriptedSwitch::unenrolled_at(
            &world.key,
            [0x5e; 32],
            Arc::new(pubky_switch_client::clock::TestClock::new(service_time)),
            NEW_ORIGIN,
        );
        let router = Arc::new(Router::new());
        router.add_switch(NEW_ORIGIN, &service);
        let store = Arc::new(MemoryStore::new());
        let signer = lost_with_key(&world, &store, &router, &[]).await.unwrap();
        let doc = signer.identity_doc().unwrap().unwrap();
        let time = START_MS.max(service_time);
        assert_eq!(doc.body().recovery_from, Some(time / 1_000), "{skew}");
        assert!(doc.version() > time * 1_000, "{skew}");
    }
}

#[tokio::test]
async fn test_key_provider_loss_starts_above_a_generation_its_records_saw() {
    // The records saw a version of their own at a later generation that no source shows any
    // more: the declaration starts above that generation.
    let world = World::new();
    let (old, store) = world.enrolled().await;
    drop(old);
    edit_state(&world, &store, |state| state["generation_seen"] = 4.into());
    let (service, router) = picked_service(&world);
    let shown = survey(&world, &store, &router).await.unwrap();
    assert_eq!(shown.kind, KeyRecoveryKind::ProviderLoss { lost: Some(4) });
    let mut signer = lost_with_key(&world, &store, &router, &[]).await.unwrap();
    signs_at(&world, &service, &mut signer, 4).await;
}

#[tokio::test]
async fn test_key_provider_loss_reads_the_backup_a_delivery_sealed() {
    // The records don't read, the Homeserver lost the backup, but the delivery in flight kept
    // the backup it sealed, which holds a revocation the switch never took: the app is
    // revoked, not signed back in.
    let world = World::new();
    let (mut old, store) = world.enrolled().await;
    let (app, _) = joined(&world, &mut old, 72).await;
    let id = app.keys.app_id_bytes();
    world.switch.fail_next(SwitchFault::Unreachable {
        path: "/revoke".into(),
        after: 0,
    });
    old.revoke(id, None, confirmed()).await.unwrap_err();
    world.switch.fail_next(SwitchFault::Unreachable {
        path: "/identity".into(),
        after: 0,
    });
    old.set_record_max_age(Some(60)).await.unwrap_err();
    drop(old);
    remove_file(&world, SIGNER_BACKUP_PATH);
    let ns = signer_namespace(&world.key.public());
    let mut batch = WriteBatch::new();
    batch.put(&ns, b"state".to_vec(), b"{".to_vec()).unwrap();
    store.commit(batch).unwrap();
    let (service, router) = picked_service(&world);
    let shown = survey(&world, &store, &router).await.unwrap();
    assert!(matches!(
        shown.apps.iter().find(|(a, _)| *a == id).unwrap().1,
        AppFate::RevocationPending { .. }
    ));
    let mut signer = lost_with_key(&world, &store, &router, &[]).await.unwrap();
    assert!(
        signer
            .identity_doc()
            .unwrap()
            .unwrap()
            .listed_cert(&id)
            .is_none()
    );
    signs_at(&world, &service, &mut signer, 1).await;
}

#[tokio::test]
async fn test_key_provider_loss_with_more_revoked_ids_than_an_enrollment_carries() {
    // The records hold more App IDs revoked for good than one enrollment can name, none of
    // them listed or removed by any version: the declaration names as many as fit and goes
    // ahead, and the identity signs on.
    let world = World::new();
    let (old, store) = world.enrolled().await;
    drop(old);
    edit_state(&world, &store, |state| {
        let ids: Vec<serde_json::Value> = (0..20_000u64)
            .map(|i| {
                let mut id = [0u8; 16];
                id[..8].copy_from_slice(&(i + 1).to_be_bytes());
                serde_json::json!(id.to_vec())
            })
            .collect();
        state["tombstones"] = serde_json::Value::Array(ids);
    });
    let (service, router) = picked_service(&world);
    let shown = survey(&world, &store, &router).await.unwrap();
    assert!(!shown.revoked.is_empty() && shown.revoked.len() < 20_000);
    let mut signer = lost_with_key(&world, &store, &router, &[]).await.unwrap();
    assert_eq!(service.kept_app_ids().len(), shown.revoked.len());
    signs_at(&world, &service, &mut signer, 1).await;
}

#[tokio::test]
async fn test_key_provider_loss_refuses_a_copy_that_appears_after_a_survey_of_none() {
    // The survey found no copy anywhere; at the declaration the Homeserver shows one: it is
    // new to the user, refused, and nothing is written.
    let world = World::new();
    let (old, _) = world.enrolled().await;
    let doc = old.identity_doc().unwrap().unwrap();
    drop(old);
    remove_file(&world, IDENTITY_PATH);
    remove_file(&world, SIGNER_BACKUP_PATH);
    let (_, router) = picked_service(&world);
    let store = Arc::new(MemoryStore::new());
    let shown = survey(&world, &store, &router).await.unwrap();
    assert_eq!(shown.kind, KeyRecoveryKind::ProviderLoss { lost: None });
    world
        .homeserver
        .set(IDENTITY_PATH, serde_json::to_vec(doc.signed()).unwrap());
    let refusal = Signer::declare_provider_loss_with_key(
        env_on(&world, &store, &router),
        world.keyring(),
        KeyRecoveryConfirmed::shown_and_confirmed(&shown, &[]),
    )
    .await
    .unwrap_err();
    assert_eq!(refusal, refused(KeyRecoveryStop::SurveyChanged));
    assert_eq!(stored(&world, &store), (None, None));
}

#[tokio::test]
async fn test_key_provider_loss_signs_above_a_version_seen_only_at_the_declaration() {
    // A higher version at a lower generation than the copy built on shows only at the
    // declaration: the base stands, and the version signed is above it.
    let world = World::new();
    let (old, _) = world.enrolled().await;
    let doc = old.identity_doc().unwrap().unwrap();
    drop(old);
    let base = signed_at(&world, &doc, 5, 2, 8);
    world
        .homeserver
        .set(SIGNER_BACKUP_PATH, backup_holding(&world, &base));
    remove_file(&world, IDENTITY_PATH);
    let (service, router) = picked_service(&world);
    let store = Arc::new(MemoryStore::new());
    let shown = survey(&world, &store, &router).await.unwrap();
    let seen = signed_at(&world, &doc, 9, 1, 7);
    world
        .homeserver
        .set(IDENTITY_PATH, serde_json::to_vec(seen.signed()).unwrap());
    let mut signer = Signer::declare_provider_loss_with_key(
        env_on(&world, &store, &router),
        world.keyring(),
        KeyRecoveryConfirmed::shown_and_confirmed(&shown, &[]),
    )
    .await
    .unwrap();
    assert_eq!(signer.identity_doc().unwrap().unwrap().version(), 10);
    signs_at(&world, &service, &mut signer, 2).await;
}

#[tokio::test]
async fn test_key_provider_loss_keeps_a_declared_enrollments_revocations() {
    // An App ID revoked and purged lives only in the records; they stop reading while a
    // declaration's enrollment, naming it, is still in flight: the next declaration names
    // it too.
    let world = World::new();
    let (mut old, store) = world.enrolled().await;
    let (app, _) = joined(&world, &mut old, 74).await;
    let id = app.keys.app_id_bytes();
    old.revoke(id, None, confirmed()).await.unwrap();
    old.purge_removed(id).await.unwrap();
    drop(old);
    let (service, router) = picked_service(&world);
    let mut env = world.env(store.clone());
    env.transport = router.clone();
    let mut declaring = Signer::open(env, world.keyring()).await.unwrap();
    declaring
        .declare_provider_loss("https://unreached.example", confirmed())
        .await
        .unwrap_err();
    drop(declaring);
    let ns = signer_namespace(&world.key.public());
    let mut batch = WriteBatch::new();
    batch.put(&ns, b"state".to_vec(), b"{".to_vec()).unwrap();
    store.commit(batch).unwrap();
    remove_file(&world, SIGNER_BACKUP_PATH);
    let shown = survey(&world, &store, &router).await.unwrap();
    assert!(shown.revoked.contains(&id));
    let mut signer = lost_with_key(&world, &store, &router, &[]).await.unwrap();
    assert!(service.kept_app_ids().contains(&id));
    signs_at(&world, &service, &mut signer, 1).await;
}
