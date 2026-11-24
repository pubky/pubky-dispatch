//! Fixtures shared by the signer's flow tests: an identity with its scripted switch, its
//! Homeserver, a vault and a store, and a protocol with one neutral scope.

// Fixtures, where a failure is a test failure: the workspace's no-panic lints don't apply.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, dead_code)]

use std::collections::{BTreeSet, HashMap};
use std::sync::{Arc, Mutex};

use pubky_switch_client::StoreError;
use pubky_switch_client::TransportError;
use pubky_switch_client::clock::TestClock;
use pubky_switch_client::store::{KeyValue, MemoryStore, StateStore, StoreHandle, WriteBatch};
use pubky_switch_client::testing::{SWITCH_ORIGIN, ScriptedSwitch};
use pubky_switch_client::transport::{BoxFuture, MockTransport};
use pubky_switch_core::keys::{AppKeys, IdentityKey};
use pubky_switch_core::records::{
    AppRequest, AppRequestBody, AuthRequest, IDENTITY_PATH, IdentityDoc, SIGNER_BACKUP_PATH,
    SignerBackup, SignerRecords, app_record_path,
};
use pubky_switch_core::scopes::Permission;
use pubky_switch_core::sig::SignedDoc;
use pubky_switch_signer::{
    AddOutcome, GrantPath, Homeserver, IdentityKeyring, IdentitySecret, Protocol, Protocols,
    ScopeDef, SecretVault, Signer, SignerEnv, VaultError,
};

pub const SECRET: [u8; 32] = [11; 32];
pub const SERVICE_SECRET: [u8; 32] = [22; 32];
pub const START_MS: u64 = 1_767_225_600_000;

/// A vault holding one secret.
pub struct Vault(pub Mutex<Option<[u8; 32]>>);

impl SecretVault for Vault {
    fn load(&self) -> Result<Option<IdentitySecret>, VaultError> {
        Ok(self.0.lock().unwrap().map(IdentitySecret::from_bytes))
    }
    fn add(&self, secret: &IdentitySecret) -> Result<AddOutcome, VaultError> {
        let mut held = self.0.lock().unwrap();
        if held.is_some() {
            return Ok(AddOutcome::Occupied);
        }
        *held = Some(*secret.as_bytes());
        Ok(AddOutcome::Stored)
    }
    fn delete(&self, expected: &IdentitySecret) -> Result<(), VaultError> {
        let mut held = self.0.lock().unwrap();
        if held.as_ref() == Some(expected.as_bytes()) {
            *held = None;
        }
        Ok(())
    }
}

/// The identity's Homeserver: its files, every write in order, and a switch to take it down.
#[derive(Default)]
pub struct TestHomeserver {
    pub files: Mutex<HashMap<String, Vec<u8>>>,
    pub writes: Mutex<Vec<(String, Vec<u8>)>>,
    pub down: Mutex<bool>,
    /// Writes fail while reads still answer.
    pub failing_puts: Mutex<bool>,
    /// Writes to this path fail while reads and other writes go through.
    pub failing_path: Mutex<Option<String>>,
    /// Writes to this path apply, and their answer is lost: the writer sees a failure.
    pub losing_path: Mutex<Option<String>>,
    /// Reads of this path fail while other reads and every write go through.
    pub failing_read_path: Mutex<Option<String>>,
    /// Deletions of these paths fail.
    pub failing_deletes: Mutex<BTreeSet<String>>,
    /// Every path a deletion was asked for, in order, failed or not.
    pub deletes: Mutex<Vec<String>>,
    /// Every path a read was asked for, in order, failed or not.
    pub gets: Mutex<Vec<String>>,
    /// Run once, right after this path is deleted: something that happens between two
    /// deletions, such as another install delivering.
    #[allow(clippy::type_complexity)]
    pub after_delete: Mutex<Option<(String, Box<dyn FnOnce() + Send>)>>,
    /// Run once, right after the given read of this path, counted from 1: something that
    /// happens between a check and the step after it.
    #[allow(clippy::type_complexity)]
    pub after_get: Mutex<Option<(String, usize, Box<dyn FnOnce() + Send>)>>,
}

impl TestHomeserver {
    pub fn file(&self, path: &str) -> Option<Vec<u8>> {
        self.files.lock().unwrap().get(path).cloned()
    }

    pub fn set(&self, path: &str, bytes: Vec<u8>) {
        self.files.lock().unwrap().insert(path.to_owned(), bytes);
    }

    /// The distinct bodies written at `path`.
    pub fn distinct_writes(&self, path: &str) -> usize {
        let writes = self.writes.lock().unwrap();
        let bodies: BTreeSet<&Vec<u8>> = writes
            .iter()
            .filter(|(p, _)| p == path)
            .map(|(_, b)| b)
            .collect();
        bodies.len()
    }
}

impl Homeserver for TestHomeserver {
    fn get(&self, path: &str) -> BoxFuture<'_, Result<Option<Vec<u8>>, TransportError>> {
        self.gets.lock().unwrap().push(path.to_owned());
        let failing = self.failing_read_path.lock().unwrap().as_deref() == Some(path);
        let answer = if *self.down.lock().unwrap() || failing {
            Err(TransportError::Connect("down".into()))
        } else {
            Ok(self.file(path))
        };
        let hook = {
            let mut hook = self.after_get.lock().unwrap();
            match hook.as_mut() {
                Some((at, left, _)) if at == path => {
                    *left = left.saturating_sub(1);
                    if *left == 0 { hook.take() } else { None }
                }
                _ => None,
            }
        };
        if let Some((_, _, run)) = hook {
            run();
        }
        Box::pin(async move { answer })
    }
    fn put(&self, path: &str, bytes: Vec<u8>) -> BoxFuture<'_, Result<(), TransportError>> {
        let failing_path = self.failing_path.lock().unwrap().as_deref() == Some(path);
        let answer =
            if *self.down.lock().unwrap() || *self.failing_puts.lock().unwrap() || failing_path {
                Err(TransportError::Connect("down".into()))
            } else {
                self.writes
                    .lock()
                    .unwrap()
                    .push((path.to_owned(), bytes.clone()));
                self.set(path, bytes);
                if self.losing_path.lock().unwrap().as_deref() == Some(path) {
                    Err(TransportError::Connect("answer lost".into()))
                } else {
                    Ok(())
                }
            };
        Box::pin(async move { answer })
    }
    fn delete(&self, path: &str) -> BoxFuture<'_, Result<(), TransportError>> {
        self.deletes.lock().unwrap().push(path.to_owned());
        let failing_path = self.failing_path.lock().unwrap().as_deref() == Some(path)
            || self.failing_deletes.lock().unwrap().contains(path);
        let answer =
            if *self.down.lock().unwrap() || *self.failing_puts.lock().unwrap() || failing_path {
                Err(TransportError::Connect("down".into()))
            } else {
                self.files.lock().unwrap().remove(path);
                let hook = {
                    let mut hook = self.after_delete.lock().unwrap();
                    if hook.as_ref().is_some_and(|(at, _)| at == path) {
                        hook.take()
                    } else {
                        None
                    }
                };
                if let Some((_, run)) = hook {
                    run();
                }
                Ok(())
            };
        Box::pin(async move { answer })
    }
}

/// A store whose commits fail with `Unavailable`, applying nothing, while `failing` is set.
pub struct FlakyStore {
    pub inner: Arc<MemoryStore>,
    pub failing: Mutex<bool>,
}

impl FlakyStore {
    pub fn new(inner: Arc<MemoryStore>) -> Arc<Self> {
        Arc::new(Self {
            inner,
            failing: Mutex::new(false),
        })
    }

    pub fn fail(&self, failing: bool) {
        *self.failing.lock().unwrap() = failing;
    }
}

impl StateStore for FlakyStore {
    fn get(&self, ns: &str, key: &[u8]) -> Result<Option<Vec<u8>>, StoreError> {
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
    fn commit(&self, batch: WriteBatch) -> Result<(), StoreError> {
        if *self.failing.lock().unwrap() {
            return Err(StoreError::Unavailable);
        }
        self.inner.commit(batch)
    }

    fn acquire(
        &self,
        ns: &str,
        owner: pubky_switch_client::store::StoreOwner,
    ) -> Result<pubky_switch_client::store::AcquireOutcome, pubky_switch_client::store::StoreError>
    {
        self.inner.acquire(ns, owner)
    }

    fn commit_if(
        &self,
        ns: &str,
        owner: pubky_switch_client::store::StoreOwner,
        batch: pubky_switch_client::store::WriteBatch,
    ) -> Result<pubky_switch_client::store::CommitOutcome, pubky_switch_client::store::StoreError>
    {
        if *self.failing.lock().unwrap() {
            return Err(StoreError::Unavailable);
        }
        self.inner.commit_if(ns, owner, batch)
    }
}

/// The path the test protocol adds to the grant of an app holding `notes_tags`.
pub const TAGS_PATH: &str = "/pub/notes/tags.json";

/// A protocol with neutral scopes: `notes`, with keys, needing `claims.read`, and `notes_tags`,
/// without keys, needing `lists.read` and adding [`TAGS_PATH`] to the app's grant.
pub struct Notes;

impl Protocol for Notes {
    fn name(&self) -> &str {
        "notes"
    }
    fn scopes(&self) -> Vec<ScopeDef> {
        vec![
            ScopeDef::keyed("notes"),
            ScopeDef::keyed("notes_sync"),
            ScopeDef::unkeyed("notes_tags"),
        ]
    }
    fn check_scopes(&self, _: &[&str]) -> Result<(), String> {
        Ok(())
    }
    fn permissions(&self, scopes: &[&str]) -> Vec<Permission> {
        let mut out = Vec::new();
        if scopes.contains(&"notes") {
            out.push(Permission::ClaimsRead);
        }
        if scopes.contains(&"notes_tags") {
            out.push(Permission::ListsRead);
        }
        out
    }
    fn grant_paths(&self, _: &[u8; 16], scopes: &[&str]) -> Vec<GrantPath> {
        if scopes.contains(&"notes_tags") {
            vec![GrantPath {
                path: TAGS_PATH.into(),
                purpose: "the public tag list".into(),
            }]
        } else {
            Vec::new()
        }
    }
}

/// The test protocol, whose `notes` scope gives `permissions`.
pub struct NotesGiving(pub Vec<Permission>);

impl Protocol for NotesGiving {
    fn name(&self) -> &str {
        Notes.name()
    }
    fn scopes(&self) -> Vec<ScopeDef> {
        Notes.scopes()
    }
    fn check_scopes(&self, scopes: &[&str]) -> Result<(), String> {
        Notes.check_scopes(scopes)
    }
    fn permissions(&self, scopes: &[&str]) -> Vec<Permission> {
        if scopes.contains(&"notes") {
            self.0.clone()
        } else {
            Vec::new()
        }
    }
}

/// One identity, its switch, its Homeserver and an install's store.
pub struct World {
    pub key: IdentityKey,
    pub switch: Arc<ScriptedSwitch>,
    pub transport: Arc<MockTransport>,
    pub homeserver: Arc<TestHomeserver>,
    pub clock: Arc<TestClock>,
    pub vault: Arc<Vault>,
    /// The scope keys each app got with its approval, by App ID: what it holds before it
    /// fetches any bundle part (Switch wire 3.10).
    pub approval_keys: Mutex<HashMap<[u8; 16], pubky_switch_core::keys::ScopeKeys>>,
}

impl World {
    pub fn new() -> Self {
        let key = IdentityKey::from_secret(SECRET);
        let clock = Arc::new(TestClock::new(START_MS));
        let switch = ScriptedSwitch::unenrolled(&key, SERVICE_SECRET, Arc::clone(&clock));
        Self {
            transport: switch.transport(),
            switch,
            homeserver: Arc::new(TestHomeserver::default()),
            clock,
            vault: Arc::new(Vault(Mutex::new(Some(SECRET)))),
            approval_keys: Mutex::new(HashMap::new()),
            key,
        }
    }

    pub fn env(&self, store: Arc<dyn StateStore>) -> SignerEnv {
        self.env_with(store, Protocols::new(vec![Arc::new(Notes)]).unwrap())
    }

    /// The env, behind a transport that strips the signature from the switch's `404` answers
    /// once it erased the account, as an intermediary answering for it would: a `404` the
    /// signer can't check (Switch wire 7.4.16 "The signer's `404`"). Returns that transport
    /// too, which sees every request.
    pub fn env_with_unsigned_404s(
        &self,
        store: Arc<dyn StateStore>,
    ) -> (SignerEnv, Arc<MockTransport>) {
        let switch = Arc::clone(&self.switch);
        let transport = Arc::new(MockTransport::with_handler(move |request| {
            let response = switch.handle(request)?;
            if response.status == 404 && switch.erased() {
                return Ok(pubky_switch_client::transport::Response {
                    status: 404,
                    headers: Vec::new(),
                    body: b"{}".to_vec(),
                });
            }
            Ok(response)
        }));
        let mut env = self.env(store);
        env.transport = transport.clone();
        (env, transport)
    }

    /// The env with `protocols` registered in place of the test protocol.
    pub fn env_with(&self, store: Arc<dyn StateStore>, protocols: Protocols) -> SignerEnv {
        SignerEnv {
            store: StoreHandle::inline(store),
            clock: self.clock.clone(),
            transport: self.transport.clone(),
            homeserver: self.homeserver.clone(),
            protocols,
        }
    }

    pub fn keyring(&self) -> IdentityKeyring {
        IdentityKeyring::open(self.vault.clone()).unwrap()
    }

    /// A signer of this identity, enrolled and serving, with its store.
    pub async fn enrolled(&self) -> (Signer, Arc<MemoryStore>) {
        let store = Arc::new(MemoryStore::new());
        let mut signer = Signer::create(self.env(store.clone()), self.keyring(), SWITCH_ORIGIN)
            .await
            .unwrap();
        signer.resume().await.unwrap();
        (signer, store)
    }

    /// Edit a persisted record while the signer is closed.
    pub fn edit_signer_record(
        &self,
        store: &MemoryStore,
        name: &[u8],
        edit: impl FnOnce(&mut serde_json::Value),
    ) {
        let ns = pubky_switch_signer::state::signer_namespace(&self.key.public());
        let bytes = store.get(&ns, name).unwrap().unwrap();
        let mut record = serde_json::from_slice(&bytes).unwrap();
        edit(&mut record);
        let mut batch = WriteBatch::new();
        batch
            .put(&ns, name.to_vec(), serde_json::to_vec(&record).unwrap())
            .unwrap();
        store.commit(batch).unwrap();
    }

    /// The real signer transport, optionally bound to an established account.
    pub fn signer_client(&self, created: Option<u64>) -> pubky_switch_client::SwitchClient {
        let client = pubky_switch_client::SwitchClient::new(
            SWITCH_ORIGIN,
            self.key.public(),
            pubky_switch_client::Credentials::Signer {
                identity: self.key.public(),
                key: Arc::new(self.key.clone()),
            },
            Some(self.switch.service_key()),
            self.transport.clone(),
            self.clock.clone(),
        )
        .unwrap();
        match created {
            Some(created) => client.with_account_created(created).unwrap(),
            None => client,
        }
    }

    /// Erase through the authenticated endpoint, then create a distinct staged account.
    pub async fn create_after_erasure(&self) -> u64 {
        let created = self.switch.created();
        let following = self.switch.identity_doc().as_ref().map(IdentityDoc::hash);
        self.signer_client(Some(created))
            .erase(Some(created), following)
            .await
            .unwrap();
        self.clock.advance_ms(1000);
        let next = self.create_staged_account().await;
        assert!(next > created);
        next
    }

    /// Enroll an absent account without delivering its first identity document.
    pub async fn create_staged_account(&self) -> u64 {
        use pubky_switch_core::records::{
            Enrollment, EnrollmentBody, EnrollmentIntent, IdentityPolicy,
        };
        let client = self.signer_client(None);
        let observation = client.observe_account().await.unwrap();
        assert_eq!(observation.body().created, None);
        let enrollment = Enrollment::sign(
            &self.key,
            EnrollmentBody {
                identity: self.key.public(),
                origin: SWITCH_ORIGIN.into(),
                nonce: [80; 16],
                intent: EnrollmentIntent::Create {
                    observation: observation.carried().clone(),
                },
                policy: IdentityPolicy::default(),
                identity_doc: None,
                revoked_apps: None,
            },
        )
        .unwrap();
        let answer = client.enroll(&enrollment).await.unwrap();
        assert!(self.switch.identity_doc().is_none());
        answer.created
    }

    /// The backup on the Homeserver, opened.
    pub fn backup(&self) -> SignerRecords {
        let bytes = self.homeserver.file(SIGNER_BACKUP_PATH).expect("a backup");
        let backup: SignerBackup = serde_json::from_slice(&bytes).unwrap();
        backup.open(&self.key).unwrap()
    }

    /// The `identity.json` the Homeserver publishes.
    pub fn published(&self) -> Option<IdentityDoc> {
        let bytes = self.homeserver.file(IDENTITY_PATH)?;
        let signed: SignedDoc = serde_json::from_slice(&bytes).unwrap();
        Some(IdentityDoc::verify(&signed, &self.key.public()).unwrap())
    }

    /// Bodies sent to this endpoint after the first `since` requests, in send order.
    fn request_bodies_since(&self, since: usize, method: &str, suffix: &str) -> Vec<Vec<u8>> {
        self.transport
            .requests()
            .into_iter()
            .skip(since)
            .filter(|r| r.method == method && r.path_and_query.ends_with(suffix))
            .map(|r| r.body)
            .collect()
    }

    /// Check how many attempts reached the endpoint and that retries kept the same bytes.
    #[track_caller]
    pub fn assert_request_attempts(&self, since: usize, method: &str, suffix: &str, count: usize) {
        let bodies = self.request_bodies_since(since, method, suffix);
        assert_eq!(bodies.len(), count, "{method} {suffix} attempts");
        for pair in bodies.windows(2) {
            assert_eq!(pair[0], pair[1], "{method} {suffix} retry body");
        }
    }

    /// The service and the Homeserver both hold this signed identity document.
    pub fn assert_published_at(&self, service: &ScriptedSwitch, doc: &IdentityDoc) {
        assert_eq!(service.identity_doc().unwrap().signed(), doc.signed());
        assert_eq!(self.published().unwrap().signed(), doc.signed());
    }

    /// The number of distinct request bodies, however often each was sent.
    pub fn distinct_requests(&self, method: &str, suffix: &str) -> usize {
        self.request_bodies_since(0, method, suffix)
            .into_iter()
            .collect::<BTreeSet<_>>()
            .len()
    }

    /// Every `identity.json` sent to the switch, in order.
    pub fn sent_docs(&self) -> Vec<IdentityDoc> {
        self.transport
            .requests()
            .into_iter()
            .filter(|r| r.method == "PUT" && r.path_and_query.ends_with("/identity"))
            .map(|r| {
                let delivery = pubky_switch_core::http::IdentityDelivery::parse(&r.body).unwrap();
                IdentityDoc::verify(&delivery.identity, &self.key.public()).unwrap()
            })
            .collect()
    }

    /// Fails when two different documents were sent at one version: the identity key never
    /// signs equivocation (Switch spec 4.3, 13.2).
    pub fn assert_no_version_sent_twice(&self) {
        let mut seen: HashMap<u64, [u8; 32]> = HashMap::new();
        for doc in self.sent_docs() {
            let body = doc.body_hash();
            let first = *seen.entry(doc.version()).or_insert(body);
            assert_eq!(first, body, "two bodies sent at version {}", doc.version());
        }
    }

    /// A version after `doc` signed by another install, delivered to the switch behind the
    /// signer's back.
    pub fn other_install_version(&self, doc: &IdentityDoc, install: [u8; 16]) -> IdentityDoc {
        let mut body = doc.body().clone();
        body.version += 1;
        body.signer = install;
        IdentityDoc::sign(&self.key, body).unwrap()
    }
}

/// An app asking for `scopes`, with the auth request its request binds.
pub struct App {
    pub keys: AppKeys,
    pub auth: AuthRequest,
    pub request: SignedDoc,
}

impl App {
    pub fn new(scopes: &[&str], caps: Option<String>, secret: [u8; 32]) -> Self {
        Self::with_keys(
            AppKeys::from_secrets([3; 32], [4; 32]),
            scopes,
            caps,
            secret,
        )
    }

    /// An app with `keys` asking for `scopes`.
    pub fn with_keys(
        keys: AppKeys,
        scopes: &[&str],
        caps: Option<String>,
        secret: [u8; 32],
    ) -> Self {
        let record = format!("{}:rw", app_record_path(&keys.app_id_bytes()));
        let caps = caps.unwrap_or_else(|| {
            if scopes.contains(&"notes_tags") {
                format!("{record},{TAGS_PATH}:rw")
            } else {
                record
            }
        });
        let auth = AuthRequest {
            client_id: "app.example".into(),
            client_key: [8; 32],
            caps,
            secret,
        };
        let scopes = scopes.iter().map(|s| (*s).to_owned()).collect();
        let request = AppRequest::sign(&keys, AppRequestBody::new(&keys, scopes, &auth))
            .unwrap()
            .signed()
            .clone();
        Self {
            keys,
            auth,
            request,
        }
    }
}

impl World {
    /// Approve `app` with `signer`: review, approve and report the claim delivered. The app
    /// then joins ([`World::join`]).
    pub async fn approve(&self, signer: &mut Signer, app: &App) -> IdentityDoc {
        let review = signer.review(&app.request, &app.auth).unwrap();
        let approved = signer.approve(review).await.unwrap();
        signer.claim_delivered(&approved.request).await.unwrap();
        self.join(app, &approved);
        signer.identity_doc().unwrap().unwrap()
    }

    /// `app` joins as Switch spec 12.1 step 2 says: it reads its approval's claim and delivers
    /// its record with the certificate the approval names.
    pub fn join(
        &self,
        app: &App,
        approved: &pubky_switch_signer::ApprovedRequest,
    ) -> pubky_switch_core::records::AppCert {
        use pubky_switch_core::ops::OpKind;
        use pubky_switch_core::records::{AppRecord, AppRecordBody, Approval, ApprovalClaim};
        let identity = self.key.public();
        let claim = ApprovalClaim::from_plaintext(&approved.claim).unwrap();
        let json = claim.verify(&identity, &app.auth).unwrap();
        let request = AppRequest::verify(&app.request).unwrap();
        let read = Approval::read(
            json,
            &request,
            &identity,
            &app.keys.bundle_secret(),
            // Every test scope has keys but `notes_tags`.
            &|scope: &str| scope != "notes_tags",
        )
        .unwrap();
        self.approval_keys
            .lock()
            .unwrap()
            .insert(app.keys.app_id_bytes(), read.keys.clone());
        let record = AppRecord::sign(
            &app.keys,
            AppRecordBody::new(&read.cert, Vec::new(), START_MS),
        )
        .unwrap();
        self.switch
            .app_op(
                &app.keys,
                OpKind::AppPut {
                    record: record.signed().clone(),
                },
            )
            .unwrap();
        read.cert
    }
}
