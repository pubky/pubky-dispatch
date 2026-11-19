//! The signer's records in the host's store, and the flow in progress.
//!
//! Everything lives in one namespace, `signer/<identity>`, under two keys: the records
//! (`SignerState`) and the flow in progress (`Flow`), always committed together. A flow
//! holds every artifact it signed before sending it, so a crash resends the same bytes and
//! nothing is signed twice (Switch wire 2.1). Nothing in the Switch spec fixes this layout;
//! it is the crate's own, versioned by [`SCHEMA_VERSION`].
//!
//! The records hold no secret: the identity key stays in the host's vault. A take-over's flow
//! holds the hand-over as the switch served it, sealed to the new signer's bundle key, until
//! the secret it carries is in the vault (Switch wire 3.12).

use pubky_switch_client::client::Batch;
use pubky_switch_client::store::{OwnedStoreHandle, WriteBatch};
use pubky_switch_core::enc::zbase32_encode;
use pubky_switch_core::ops::SignedOp;
use pubky_switch_core::records::{
    AccountAssociation, AccountObservation, AppCert, CarriedAccountObservation,
    DEFAULT_CERT_LIFETIME_MS, Enrollment, EnrollmentAnswer, EnrollmentIntent, IdentityDoc,
    IdentityPolicy, Limits, SignerBackup, SignerHandover, StoredPart,
};
use pubky_switch_core::scopes;
use pubky_switch_core::sig::SignedDoc;
use serde::{Deserialize, Serialize};

use crate::alert::Alert;
use crate::error::{RecordsFault, Result, SignerError, SignerRecord};

mod recovery_delivery;
pub(crate) use recovery_delivery::{RecoveryDelivery, RecoveryStep};

/// The version of the records' layout.
pub const SCHEMA_VERSION: u32 = 1;

/// The prefix of the signer's namespace, which the identity's Pubky ID in z-base-32 follows.
pub const SIGNER_NAMESPACE_PREFIX: &str = "signer/";

const STATE_KEY: &[u8] = b"state";
const FLOW_KEY: &[u8] = b"flow";

/// The signer's namespace for an identity: `signer/<identity>`.
pub fn signer_namespace(identity: &[u8; 32]) -> String {
    format!("{SIGNER_NAMESPACE_PREFIX}{}", zbase32_encode(identity))
}

/// What the user asked of an app's renewal that didn't happen (Switch spec 3.2): the scopes
/// and switch permissions to remove and an earlier expiry, which make it a reduction, and
/// the scopes to add and a later expiry. A second one the user asks for the same app adds to
/// it, its parts standing where the two contradict.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct AskedRenewal {
    /// The app.
    pub(crate) app_id: [u8; 16],
    /// The scopes the user asked to remove.
    pub(crate) remove: Vec<String>,
    /// The switch permissions the user's renewal would have removed, by name.
    pub(crate) remove_permissions: Vec<String>,
    /// The earliest expiry the user asked for, when earlier than the certificate's.
    pub(crate) expires_by: Option<u64>,
    /// The scopes the user asked to add.
    pub(crate) add: Vec<String>,
    /// The switch permissions the user's renewal would have added, by name.
    pub(crate) add_permissions: Vec<String>,
    /// The latest expiry the user asked for, when later than the certificate's.
    pub(crate) expires_from: Option<u64>,
}

impl AskedRenewal {
    /// What renewing `old` into `new` asks of the app `app_id`.
    pub(crate) fn between(app_id: [u8; 16], old: &AppCert, new: &AppCert) -> Self {
        let missing = |held: &AppCert, from: &AppCert| -> Vec<String> {
            from.scopes()
                .iter()
                .filter(|scope| !scopes::holds(held.scopes(), scope))
                .cloned()
                .collect()
        };
        Self {
            app_id,
            remove: missing(new, old),
            remove_permissions: old
                .permissions()
                .iter()
                .filter(|permission| !new.has_permission(**permission))
                .map(|permission| permission.as_str().to_owned())
                .collect(),
            expires_by: (new.expires_at() < old.expires_at()).then(|| new.expires_at()),
            add: missing(old, new),
            add_permissions: new
                .permissions()
                .iter()
                .filter(|permission| !old.has_permission(**permission))
                .map(|permission| permission.as_str().to_owned())
                .collect(),
            expires_from: (new.expires_at() > old.expires_at()).then(|| new.expires_at()),
        }
    }

    /// Add what `later`, the user's newer request, asks. Where the two contradict, the newer
    /// stands: a scope or permission it asks to add leaves those to remove, and one it asks
    /// to remove those to add; a later expiry it asks ends the earlier one asked, and an
    /// earlier one the later. Parts that don't contradict add up: every scope and permission
    /// either asks to remove or to add, the earlier of two earlier expiries and the later of
    /// two later ones.
    pub(crate) fn merge(&mut self, later: &AskedRenewal) {
        self.remove.retain(|scope| !later.add.contains(scope));
        self.add.retain(|scope| !later.remove.contains(scope));
        self.remove_permissions
            .retain(|permission| !later.add_permissions.contains(permission));
        self.add_permissions
            .retain(|permission| !later.remove_permissions.contains(permission));
        for scope in &later.remove {
            if !self.remove.contains(scope) {
                self.remove.push(scope.clone());
            }
        }
        for permission in &later.remove_permissions {
            if !self.remove_permissions.contains(permission) {
                self.remove_permissions.push(permission.clone());
            }
        }
        for scope in &later.add {
            if !self.add.contains(scope) {
                self.add.push(scope.clone());
            }
        }
        for permission in &later.add_permissions {
            if !self.add_permissions.contains(permission) {
                self.add_permissions.push(permission.clone());
            }
        }
        if later.expires_from.is_some() {
            self.expires_by = None;
        }
        if later.expires_by.is_some() {
            self.expires_from = None;
        }
        self.expires_by = match (self.expires_by, later.expires_by) {
            (Some(a), Some(b)) => Some(a.min(b)),
            (a, b) => a.or(b),
        };
        self.expires_from = match (self.expires_from, later.expires_from) {
            (Some(a), Some(b)) => Some(a.max(b)),
            (a, b) => a.or(b),
        };
    }

    /// Whether the user asked to reduce the app: to remove a scope or a switch permission, or
    /// to expire it earlier (Switch wire 3.8 "Reductions").
    pub(crate) fn reduction(&self) -> bool {
        !self.remove.is_empty() || !self.remove_permissions.is_empty() || self.expires_by.is_some()
    }

    /// Whether `cert` holds what the user asked: for a reduction, none of the scopes to
    /// remove, by the scope hierarchy, none of the switch permissions to remove, and an expiry
    /// no later than asked; otherwise every scope to add and an expiry no earlier than asked,
    /// when something was asked.
    pub(crate) fn met_by(&self, cert: &AppCert) -> bool {
        if self.reduction() {
            self.remove
                .iter()
                .all(|scope| !scopes::holds(cert.scopes(), scope))
                && self.remove_permissions.iter().all(|name| {
                    scopes::Permission::from_name(name)
                        .is_none_or(|permission| !cert.has_permission(permission))
                })
                && self.expires_by.is_none_or(|by| cert.expires_at() <= by)
        } else {
            (!self.add.is_empty() || self.expires_from.is_some())
                && self
                    .add
                    .iter()
                    .all(|scope| scopes::holds(cert.scopes(), scope))
                && self
                    .expires_from
                    .is_none_or(|from| cert.expires_at() >= from)
        }
    }
}

/// The switch the identity is enrolled at (Switch wire 3.7).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct Service {
    /// The switch origin, exactly as `identity.json` names it.
    pub(crate) origin: String,
    /// The account's service key, from the enrollment answer.
    pub(crate) service_key: [u8; 32],
    /// The limits the enrollment answer announced, which the switch gives only then.
    pub(crate) limits: Limits,
    /// The account's original creation, retained from enrollment or the authenticated
    /// backup/hand-over with its document (Switch account-binding Sections 1 and 4).
    pub(crate) created: u64,
}

impl Service {
    fn check(&self) -> Result<()> {
        if !pubky_switch_core::records::is_origin(&self.origin)
            || self.created > pubky_switch_core::time::MAX_TIME_MS
        {
            return Err(RecordsFault::Invariant("invalid original account target").into());
        }
        Ok(())
    }

    /// Check the retained target against the identity-signed document it accompanies.
    pub(crate) fn check_document(&self, doc: &IdentityDoc) -> Result<()> {
        self.check()?;
        if self.origin != doc.inbox().url || self.service_key != doc.inbox().service_key {
            return Err(RecordsFault::Invariant("the document names another account").into());
        }
        Ok(())
    }
}

/// The `identity.json` an account that answers the notice holds, as a signed `409` to an
/// erasure showed it in `current.identity`, judged as every copy (Switch wire 7.4.16, spec
/// 4.3).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct ShownCopy {
    /// Its document hash; `None` where the account holds none.
    pub(crate) hash: Option<[u8; 32]>,
}

/// The newest `identity.json` a service accepted from this signer, or that it adopted: its
/// high-water mark (Switch spec 4.3).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct Newest {
    /// The document, as signed.
    pub(crate) doc: SignedDoc,
    /// Its original account, retained with this exact document. A copy learned only from
    /// another install may establish who signs without establishing an account binding.
    pub(crate) account: Option<Service>,
    /// The document hash of the version it builds on; `None` for a first version and an
    /// adopted copy.
    pub(crate) prev: Option<[u8; 32]>,
    /// Whether it is published on the Homeserver.
    pub(crate) published: bool,
    /// The service time at which the switch took it, from its delivery's transition proof;
    /// `None` for an adopted copy. A reduction's cutoff is this time plus the clock tolerance
    /// (Switch wire 3.8).
    pub(crate) delivered_at: Option<u64>,
}

/// The signer's records.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct SignerState {
    /// The layout version.
    pub(crate) v: u32,
    /// The identity.
    pub(crate) identity: [u8; 32],
    /// This install's signer ID, picked at random when it first signs (Switch spec 4.3).
    pub(crate) install: [u8; 16],
    /// The switch, once the enrollment is answered.
    pub(crate) service: Option<Service>,
    /// The newest version accepted or adopted.
    pub(crate) newest: Option<Newest>,
    /// The highest version this install committed a signed `identity.json` at, sent or not.
    /// Every new version is signed above it, so no version is signed twice with two bodies
    /// (Switch spec 4.3, 13.2).
    pub(crate) signed_through: u64,
    /// Every App ID revoked or seen departing, kept for good (Switch spec 12.2).
    pub(crate) tombstones: Vec<[u8; 16]>,
    /// The certificates the newest document references, as signed.
    pub(crate) certs: Vec<SignedDoc>,
    /// The key bundle parts stored for each listed app (Switch wire 3.5).
    pub(crate) bundle_parts: Vec<StoredPart>,
    /// Another install that the newest document or the backup names as the signer.
    pub(crate) managed_by: Option<[u8; 16]>,
    /// The version of a newer `identity.json` this install signed itself that the switch or
    /// the Homeserver holds: the records are behind, and nothing is signed until a restore
    /// from the signer backup replaces them ([`crate::Signer::restore`]).
    pub(crate) records_behind: Option<u64>,
    /// The document hash of another body at the mark's version that the Homeserver
    /// published, which raised [`Alert::Equivocation`].
    pub(crate) homeserver_other: Option<[u8; 32]>,
    /// That copy, once the user has seen its alert: publication writes the switch's copy over
    /// it (Switch wire 3.3 "Deliver, then publish").
    pub(crate) republish_over: Option<[u8; 32]>,
    /// The revocations asked for whose removal isn't delivered yet, with the earlier
    /// `distrust_from` the user picked, if any (Switch spec 12.2).
    pub(crate) revoking: Vec<Revoking>,
    /// The removed apps whose Homeserver record is still to be deleted (Switch spec 12.2
    /// step 4).
    pub(crate) cleanup: Vec<[u8; 16]>,
    /// The apps of `cleanup` whose [`Alert::GrantRevocationOwed`] was raised: once for each
    /// owed deletion, so the user can clear it while a deletion keeps failing.
    pub(crate) grant_reminded: Vec<[u8; 16]>,
    /// The removed apps a restore found whose record may still be on the Homeserver: the
    /// routine run checks them, a few at a time, and owes the deletion of those it finds.
    pub(crate) deletion_checks: Vec<[u8; 16]>,
    /// A restore's backup write is owed: it raced another signer, so it is written once its
    /// delivery has won (Switch wire 3.13).
    pub(crate) backup_owed: bool,
    /// The hand-over this install is making, until it takes effect or is aborted (Switch wire
    /// 3.12): it signs nothing for the identity but the abort meanwhile.
    pub(crate) handing_over: Option<HandingOver>,
    /// This install is taking the identity over from a hand-over, until its first delivery
    /// has won and the received secret is in the vault (Switch wire 3.12).
    pub(crate) taking_over: bool,
    /// A take-over's first version won, and its publication waits for its backup (Switch wire
    /// 3.12): the old signer's deletion relies on that order.
    pub(crate) publish_after_backup: bool,
    /// The hand-over took effect, naming this install as the signer: committed before the key
    /// is deleted, so records a crash leaves behind are deleted on the next open and count as
    /// none for a new set-up (Switch spec 12.8).
    pub(crate) handed_over_to: Option<[u8; 16]>,
    /// The full-bundle requests whose answer the switch refused, not tried again until the
    /// app asks anew.
    pub(crate) refused_requests: Vec<RefusedRequest>,
    /// The service time at which the switch took the first version this signer delivered
    /// that lists each app: no app left or was revoked before it (Switch spec 12.3).
    pub(crate) listed_at: Vec<([u8; 16], u64)>,
    /// The alerts the user hasn't cleared.
    pub(crate) alerts: Vec<Alert>,
    /// The certificate lifetime new certificates get, in milliseconds (Switch spec 3.2).
    pub(crate) cert_lifetime_ms: u64,
    /// The automatic renewals in a row no record of their app has taken up, each by the app
    /// and the hash of the certificate it issued: at two for an app, the signer stops renewing
    /// it by itself (Switch spec 3.1). A renewal the user asks for, or a record carrying the
    /// newest certificate, takes the app out, as the app's removal does. Added in the commit
    /// of the renewing version, so a renewal counts once however its delivery goes, and
    /// dropped with its certificate when that version is never delivered
    /// ([`SignerState::prune_unreferenced`]). This install's own: a new install starts with
    /// none.
    pub(crate) untaken_renewals: Vec<([u8; 16], [u8; 32])>,
    /// The companion claims of approvals, signed once, until the host has delivered them
    /// (Switch wire 3.10).
    pub(crate) claims: Vec<PendingClaim>,
    /// The switch showed a rollback or an equivocation, and no delivery has succeeded since:
    /// the signer doesn't know that the switch holds its high-water version, so it releases
    /// no claim.
    pub(crate) switch_unconfirmed: bool,
    /// The highest data epoch whose keys this signer ever sent in a bundle, by a rotation it
    /// gave up too. While it is above the newest version's `data_epoch`, some apps may hold
    /// keys of an epoch no version raised: before its next rotation the signer completes that
    /// epoch, giving every current app holding each keyed scope its keys through it and
    /// delivering a version that raises `data_epoch` to it, then rotates by one (Switch spec
    /// 3.2, 3.5). A restore or a hand-over takes it as the highest `last_epoch` of the parts
    /// it receives and of `keys_through` and `bundle_ranges` in `GET /apps` (Switch wire 3.5,
    /// 3.12, 7.4.12), never below the newest `data_epoch`.
    pub(crate) epoch_through: u64,
    /// The version that was delivered again for its service time, because a closing delivery
    /// is owed and the delivery's answer was lost: its retry's answer must carry that time
    /// (Switch wire 7.4.2). It concerns only that version.
    pub(crate) time_asked: Option<u64>,
    /// The version whose retry gave no service time either: the closing stays owed, with
    /// [`Alert::ReductionNotClosed`] shown, until a later version's delivery carries a service
    /// time to close at.
    pub(crate) closing_unavailable: Option<u64>,
    /// The identity's account at its switch is erased (Switch spec 12.7): the records stay,
    /// and nothing more is signed for that account.
    pub(crate) erased: bool,
    /// A provider loss is declared and its version not delivered yet (Switch spec 12.6 step
    /// 1): its own steps pass the recovery's gate ([`crate::signer::gate::recovery_key`])
    /// while an alarm about the lost service is held, and every other signing step is
    /// refused ([`crate::error::Refusal::Recovering`]).
    pub(crate) recovering: bool,
    /// The document a declared recovery builds on (Switch spec 12.6 step 1): the newest this
    /// install signed when it was first declared, a version in flight to the lost service
    /// included, since that service may have taken it and apps seen it. Kept while the
    /// recovery is declared again elsewhere, and dropped once its version is delivered.
    pub(crate) recovery_base: Option<SignedDoc>,
    /// The original commit digest while a joint enrollment and delivery is uncertain.
    /// The recovery base then retains the frozen signed version for a separately confirmed
    /// provider loss, even if the flow can no longer be read.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) recovery_commit: Option<[u8; 32]>,
    /// The generation a declared recovery declares lost (Switch spec 12.6 step 1): its
    /// version is the next one, with `recovery_from` this. Kept while the recovery is
    /// declared again, since its base may be a recovery's own version not delivered yet, as
    /// one restored from a backup written mid-recovery.
    pub(crate) lost_generation: Option<u64>,
    /// The Homeserver's `identity.json` was missing or didn't verify when the recovery was
    /// declared, and the records explained it, or the user confirmed them anyway (Switch spec
    /// 12.6 step 1): a backup missing or unreadable is then written over without that copy.
    pub(crate) homeserver_copy_waived: bool,
    /// The recovery's version is delivered and lists apps whose revocation is pending: they
    /// are revoked at the new service before the version is published, which is how apps
    /// find the service (Switch spec 12.6 step 1).
    pub(crate) revoke_at_service: bool,
    /// For apps the newest version removes, earlier times to distrust them from than its
    /// `removed` entries, which a recovery with the key alone found picked: every version
    /// built from then on takes them (Switch spec 12.8).
    pub(crate) earlier_distrust: Vec<pubky_switch_core::records::RemovedApp>,
    /// The highest generation of a version of this install's own it saw ahead of its
    /// records, with `records_behind`: a recovery with the key alone starts above it, whatever
    /// copies it finds then (Switch spec 12.8).
    pub(crate) generation_seen: u64,
    /// The renewals the user asked for, each as its app and the new certificate's hash, whose
    /// flow is in progress: one delivered ends that app's [`Alert::RenewalRefused`] for a
    /// renewal that reduced nothing, as the user's newest choice, and one refused is the
    /// user's, with what it asked (Switch spec 3.2). Emptied once the flow ends.
    pub(crate) user_renewals: Vec<([u8; 16], [u8; 32])>,
    /// What the user asked of each renewal that didn't happen, beside its
    /// [`Alert::RenewalRefused`]: whether the alert holds is judged from the certificate
    /// `identity.json` lists against it (Switch spec 3.2). One per app; it goes with the alert.
    pub(crate) asked_renewals: Vec<AskedRenewal>,
    /// Some version of the identity was published on the Homeserver, by this install or,
    /// for records restored or received, by the install they came from (Switch spec 4.3). A
    /// missing `identity.json` is explained without it only by an erasure (Switch spec 12.6
    /// step 1).
    pub(crate) ever_published: bool,
    /// The service the recovery in progress last went to, for its status (Switch spec 12.6
    /// step 1).
    pub(crate) recovery_origin: Option<String>,
    /// Each service an earlier declaration of the recovery in progress enrolled at, with
    /// the key its enrollment answered: declared again there, the signer reads under that
    /// key whether the earlier version was taken, since a service that took it may have
    /// changed its key since (Switch wire 3.7, 7.4.2, spec 12.5).
    pub(crate) recovery_services: Vec<Service>,
    /// A recovery declared in place, at the service that served the lost generation, after
    /// that service changed its key (Switch spec 12.5): that service, under the key it served
    /// the lost generation with. None where it kept its one key, which the version names
    /// (Switch wire 3.7). Until it takes the recovery's version it signs every answer with
    /// that key, but the `200` of the delivery that starts the new generation, which the new
    /// key the version names signs (Switch wire 3.13, 7.4.1, 7.4.2). So the signer pins this
    /// key while the recovery goes there, and the delivery's `200` alone is checked with the
    /// new key. Kept through
    /// declarations at other origins, since only the service at its own origin is read under
    /// it; when none is kept, taken from a signed copy of the lost generation naming the
    /// declared origin: the version the recovery builds on, or the Homeserver's copy when that
    /// version is a restored recovery's own (Switch wire 3.13). Dropped with the
    /// recovery's other records once its version is delivered, and as soon as an answer under
    /// the key the version names shows the lost generation served there no more: that version
    /// taken, by this install or another, or the account one the enrollment made.
    pub(crate) recovery_serving: Option<Service>,
    /// The later step of [`crate::Signer::run_due`] the next run starts from: the one a run
    /// whose time passed didn't start, so each comes in turn whatever the device clock does
    /// (design note, section 4.5). Zero, the first, otherwise.
    pub(crate) due_from: u8,
    /// The recovery's version that a service took names another install: a restore's, from
    /// a backup written mid-recovery. This install signs the next version naming itself, as
    /// a restore does (Switch wire 3.13).
    pub(crate) owes_own_version: bool,
    /// The staged admission a recovery started is the signer's to end (Switch spec 12.6 step
    /// 2): none of the listed apps holds `lists.manage`, or the user asked. `POST
    /// /recovery/admission` is owed, sent again at every run, after publication, until `GET
    /// /apps` shows the wait ended or no wait.
    pub(crate) admission_owed: bool,
}

/// A hand-over this install is making (Switch wire 3.12).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct HandingOver {
    /// The new signer's App ID.
    pub(crate) to_app: [u8; 16],
    /// The original account of the handed-over version and its pending requests.
    pub(crate) account: Service,
    /// The version handed over, as signed: the newest the switch accepted from this install.
    pub(crate) doc: SignedDoc,
    /// The hand-over, sealed to the new signer's bundle key and signed once, and sent again
    /// with the same bytes. It is ciphertext only that app opens.
    pub(crate) handover: SignerHandover,
    /// Where its `PUT /handover` is.
    pub(crate) sent: HandOverSent,
    /// The document hash of the abort, once it is signed: never taken for the new signer's
    /// version.
    pub(crate) abort: Option<[u8; 32]>,
    /// The take-back, once it is signed: kept to be sent again, the same bytes.
    pub(crate) take_back: Option<TakeBack>,
}

/// A take-back of the identity from a new signer that is lost (Switch wire 3.12).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct TakeBack {
    /// The version, as signed: the switch's copy's content, naming this install.
    pub(crate) doc: SignedDoc,
    /// The document hash of the switch's copy it builds on.
    pub(crate) prev: [u8; 32],
    /// The install the switch's copy named.
    pub(crate) from: [u8; 16],
}

/// Where a hand-over's `PUT /handover` is (Switch wire 7.4.17).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) enum HandOverSent {
    /// Not answered yet: it is sent again, the same bytes.
    Pending,
    /// The switch stores it for the new signer.
    Stored,
    /// The switch refused it for good. An earlier send may still be stored, so the hand-over
    /// stays in progress until it takes effect or the user aborts it.
    Refused,
}

/// A take-over's first delivery (Switch wire 3.12), signed once with the received key.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct TakeOverDelivery {
    /// The version, as signed: the handed-over one plus 1, naming this install.
    pub(crate) doc: SignedDoc,
    /// The document hash of the handed-over version it builds on.
    pub(crate) prev: [u8; 32],
    /// Whether it won: the secret is put in the vault next, and nothing is sent again.
    pub(crate) won: bool,
}

/// A revocation asked for, until the version that removes the app is delivered.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct Revoking {
    /// The App ID.
    pub(crate) app_id: [u8; 16],
    /// An earlier `distrust_from` than the revocation time, which the user picked after a
    /// compromise.
    pub(crate) distrust_from: Option<u64>,
    /// The revocation's time, from the proof of the switch's answer (Switch wire 7.4.12).
    pub(crate) revoked_at: Option<u64>,
    /// Whether the switch answered the revocation, so it serves the app no more.
    pub(crate) taken: bool,
}

/// A full-bundle request the switch refused an answer to, by the time the app asked.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct RefusedRequest {
    /// The app.
    pub(crate) app_id: [u8; 16],
    /// When it asked (`full_bundle_requested`, Switch wire 7.4.12).
    pub(crate) requested: u64,
}

/// An approval's companion claim, signed with the version that lists its certificate and
/// released to the host once the switch took that version (Switch wire 3.10).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct PendingClaim {
    /// The document hash of the app request it answers.
    pub(crate) request: [u8; 32],
    /// The approved app.
    pub(crate) app_id: [u8; 16],
    /// The document hash of its certificate.
    pub(crate) cert: [u8; 32],
    /// The capabilities to approve the Pubky grant for: those the auth request asks for, in
    /// its order, less the paths the user declined (Switch spec 3.4).
    pub(crate) caps: String,
    /// The claim's plaintext: the approval's JSON bytes, then the identity key's signature.
    #[serde(with = "pubky_switch_core::enc::serde_b64_vec")]
    pub(crate) plaintext: Vec<u8>,
}

impl SignerState {
    /// Keep only the certificates the newest version references, of its apps and its
    /// `renewed` entries, the claims of certificates it lists, and the untaken renewals of
    /// certificates it references: a version that wasn't delivered leaves none of its own
    /// behind, nor counts as a renewal the app left untaken. A declared recovery's base
    /// counts as the newest version too, since the recovery's version is built on it.
    pub(crate) fn prune_unreferenced(&mut self) -> Result<()> {
        let identity = self.identity;
        let docs: Vec<IdentityDoc> = self
            .newest_doc()?
            .into_iter()
            .chain(
                self.recovery_base
                    .as_ref()
                    .map(|base| stored_identity(base, &identity))
                    .transpose()?,
            )
            .collect();
        let referenced = |hash: &[u8; 32]| {
            docs.iter().any(|doc| {
                doc.body().apps.iter().any(|a| &a.cert == hash)
                    || doc.body().renewed.iter().any(|r| &r.cert == hash)
            })
        };
        self.certs = self
            .certificates()?
            .into_iter()
            .filter(|cert| referenced(&cert.hash()))
            .map(|cert| cert.signed().clone())
            .collect();
        self.untaken_renewals.retain(|(_, cert)| referenced(cert));
        self.claims.retain(|claim| {
            docs.iter()
                .any(|doc| doc.listed_cert(&claim.app_id) == Some(claim.cert))
        });
        Ok(())
    }

    /// The `distrust_from` the user picked for each revocation asked for, which the records
    /// carry for those no version carried out yet (Switch wire 3.12, 3.13).
    pub(crate) fn picked_distrust(&self) -> Vec<pubky_switch_core::records::RemovedApp> {
        self.revoking
            .iter()
            .filter_map(|r| {
                r.distrust_from
                    .map(|distrust_from| pubky_switch_core::records::RemovedApp {
                        app_id: r.app_id,
                        distrust_from,
                    })
            })
            .collect()
    }

    /// The records of a new identity, for this install.
    pub(crate) fn new(identity: [u8; 32], install: [u8; 16]) -> Self {
        Self {
            v: SCHEMA_VERSION,
            identity,
            install,
            service: None,
            newest: None,
            signed_through: 0,
            tombstones: Vec::new(),
            certs: Vec::new(),
            bundle_parts: Vec::new(),
            managed_by: None,
            records_behind: None,
            homeserver_other: None,
            republish_over: None,
            revoking: Vec::new(),
            cleanup: Vec::new(),
            grant_reminded: Vec::new(),
            deletion_checks: Vec::new(),
            backup_owed: false,
            handing_over: None,
            taking_over: false,
            handed_over_to: None,
            publish_after_backup: false,
            refused_requests: Vec::new(),
            listed_at: Vec::new(),
            alerts: Vec::new(),
            cert_lifetime_ms: DEFAULT_CERT_LIFETIME_MS,
            untaken_renewals: Vec::new(),
            claims: Vec::new(),
            switch_unconfirmed: false,
            epoch_through: 0,
            time_asked: None,
            closing_unavailable: None,
            erased: false,
            recovering: false,
            recovery_base: None,
            recovery_commit: None,
            lost_generation: None,
            homeserver_copy_waived: false,
            revoke_at_service: false,
            earlier_distrust: Vec::new(),
            generation_seen: 0,
            user_renewals: Vec::new(),
            asked_renewals: Vec::new(),
            ever_published: false,
            recovery_origin: None,
            recovery_services: Vec::new(),
            recovery_serving: None,
            due_from: 0,
            owes_own_version: false,
            admission_owed: false,
        }
    }

    /// This installation has neither selected an account nor spent a document version.
    pub(crate) fn before_first_version(&self) -> bool {
        self.service.is_none() && self.newest.is_none() && self.signed_through == 0
    }

    /// The newest document, verified.
    pub(crate) fn newest_doc(&self) -> Result<Option<IdentityDoc>> {
        self.newest
            .as_ref()
            .map(|n| stored_identity(&n.doc, &self.identity))
            .transpose()
    }

    pub(crate) fn certificates(&self) -> Result<Vec<AppCert>> {
        self.certs
            .iter()
            .map(|cert| AppCert::verify(cert, &self.identity).map_err(SignerError::StoredData))
            .collect()
    }

    /// Check state read from the store. A failed binding here describes the stored value.
    pub(crate) fn check_stored_copies(&self) -> Result<()> {
        self.check_copies().map_err(|error| match error {
            SignerError::Records(RecordsFault::Invariant(binding)) => {
                RecordsFault::Damaged(binding).into()
            }
            other => other,
        })
    }

    /// Check the signed copies independently of the service and of caller-supplied keys.
    fn check_copies(&self) -> Result<()> {
        for service in self
            .service
            .iter()
            .chain(self.recovery_serving.iter())
            .chain(&self.recovery_services)
        {
            service.check()?;
        }
        if let Some(newest) = &self.newest {
            let doc = stored_identity(&newest.doc, &self.identity)?;
            if let Some(account) = &newest.account {
                account.check_document(&doc)?;
            } else if self.managed_by != Some(doc.body().signer)
                || doc.body().signer == self.install
            {
                return Err(
                    RecordsFault::Invariant("an owned version has no original account").into(),
                );
            }
        }
        self.certificates()?;
        if let Some(base) = &self.recovery_base {
            stored_identity(base, &self.identity)?;
        }
        if let Some(handing) = &self.handing_over {
            handing
                .account
                .check_document(&stored_identity(&handing.doc, &self.identity)?)?;
            handing
                .handover
                .verify(&self.identity, &handing.to_app)
                .map_err(SignerError::StoredData)?;
            if let Some(take_back) = &handing.take_back {
                stored_identity(&take_back.doc, &self.identity)?;
            }
        }
        Ok(())
    }

    /// Add `alert` unless it is held already.
    pub(crate) fn alert(&mut self, alert: Alert) {
        if !self.alerts.contains(&alert) {
            self.alerts.push(alert);
        }
    }

    /// Note the size of the newest version, `bytes` in the body it comes nearest to filling,
    /// its delivery or a move's enrollment carrying it, whose cap is `limit` (Switch wire
    /// 3.7, 7.1): [`Alert::IdentityNearLimit`] past three quarters of it, replacing an
    /// earlier one, or none.
    pub(crate) fn note_size(&mut self, bytes: usize, limit: usize) {
        self.alerts
            .retain(|alert| !matches!(alert, Alert::IdentityNearLimit { .. }));
        if bytes.saturating_mul(4) > limit.saturating_mul(3) {
            self.alerts.push(Alert::IdentityNearLimit {
                bytes: u64::try_from(bytes).unwrap_or(u64::MAX),
                limit: u64::try_from(limit).unwrap_or(u64::MAX),
            });
        }
    }
}

/// Where a delivery of a new version is (Switch spec 4.3, 12.8; Switch wire 3.13).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) enum DeliverStep {
    /// Signed and committed; the backup holding it is next.
    Signed,
    /// The backup holding it is on the Homeserver; the delivery is next.
    BackupWritten,
}

/// Local progress of the exact existing enrollment for a key-only recovery (Switch spec 12.8).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) enum KeyEnrollmentStep {
    /// No send can start until this step has been durably replaced.
    Unsent,
    /// The original request may have reached the service.
    Sending,
    /// An authenticated success from the selected service key and creation.
    Applied(Box<EnrollmentAnswer>),
}

/// A distinct recovery's enrollment, before discovery or retained for exact retries
/// (Switch account binding 2-3).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) enum RecoveryEnrollment {
    /// The authorized destination has not supplied its authenticated association yet.
    Preparing {
        nonce: [u8; 16],
        policy: IdentityPolicy,
        revoked_apps: Vec<[u8; 16]>,
    },
    /// The original observation and the complete signed action selected from it.
    Ready {
        observation: CarriedAccountObservation,
        enrollment: SignedDoc,
    },
}

impl RecoveryEnrollment {
    /// Verify the ordinary recovery's selected serving account and its signed existing intent.
    pub(crate) fn existing(
        &self,
        identity: &[u8; 32],
        origin: &str,
    ) -> Result<(AccountObservation, Enrollment)> {
        let Self::Ready {
            observation,
            enrollment,
        } = self
        else {
            return Err(RecordsFault::Invariant("a key recovery without its enrollment").into());
        };
        let observed = observation
            .verify(identity, origin)
            .map_err(SignerError::StoredData)?;
        let signed =
            Enrollment::verify(enrollment, identity, origin).map_err(SignerError::StoredData)?;
        if observed.body().association != AccountAssociation::Account
            || signed.body().intent != observed.enrollment_intent()?
            || signed.body().identity_doc.is_some()
            || !signed.revoked_apps().is_empty()
        {
            return Err(RecordsFault::Invariant("another key recovery enrollment").into());
        }
        Ok((observed, signed))
    }

    /// Permanent exclusions are the retained tombstones outside the verified recovery base
    /// (Switch spec 12.6 step 1), every one where a recovery with the key alone found no
    /// copy to build on (spec 12.8). Later revocations of listed apps remain deferred work.
    pub(crate) fn check_exclusions(&self, state: &SignerState, origin: &str) -> Result<()> {
        let base = match &state.recovery_base {
            Some(base) => Some(stored_identity(base, &state.identity)?),
            None if state.newest.is_none() => None,
            None => {
                return Err(RecordsFault::Invariant("a recovery enrollment has no base").into());
            }
        };
        let mut expected: Vec<_> = state
            .tombstones
            .iter()
            .copied()
            .filter(|app| {
                base.as_ref()
                    .is_none_or(|base| base.listed_cert(app).is_none())
            })
            .collect();
        expected.sort_unstable();
        expected.dedup();
        let mut excluded = match self {
            Self::Preparing { revoked_apps, .. } => revoked_apps.clone(),
            Self::Ready { enrollment, .. } => {
                Enrollment::verify(enrollment, &state.identity, origin)
                    .map_err(SignerError::StoredData)?
                    .revoked_apps()
                    .to_vec()
            }
        };
        excluded.sort_unstable();
        if excluded != expected {
            return Err(
                RecordsFault::Invariant("recovery exclusions disagree with records").into(),
            );
        }
        Ok(())
    }
}

/// The flow in progress, with every artifact it signed.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) enum Flow {
    /// Enrolling a new identity at a switch (Switch spec 4.3, Switch wire 3.7).
    Enroll {
        /// The switch origin.
        origin: String,
        /// The nonce retained before discovery.
        nonce: [u8; 16],
        /// The signed enrollment once discovery supplies its original observation.
        enrollment: Option<SignedDoc>,
        /// The policy the first `identity.json` carries.
        policy: IdentityPolicy,
    },
    /// First setup found an account or surviving mark before signing a creation.
    FirstAccountPresent {
        /// The origin the user selected for setup.
        origin: String,
        /// The original authenticated discovery (Switch account binding 2.1).
        observation: CarriedAccountObservation,
    },
    /// Recovering from a provider loss (Switch spec 12.6 step 1): enrolling at the service
    /// at `origin`, then signing the next generation's `identity.json` with `recovery_from`,
    /// which a delivery then takes there.
    Recover {
        /// The service's origin.
        origin: String,
        /// Preparation or the exact signed enrollment and its original target.
        enrollment: RecoveryEnrollment,
    },
    /// The exact recovery enrollment and signed document awaiting their joint receipt.
    RecoveryDelivery(Box<RecoveryDelivery>),
    /// Renewing an app's certificate (Switch spec 3.2, Switch wire 3.8), or completing a data
    /// epoch before a rotation: storing the new certificate and the key bundles at the switch,
    /// batch by batch, then delivering the version.
    Renew {
        /// The original target of the signed batches and version.
        account: Service,
        /// The signed batches, each sent again with the same bytes until it is answered.
        batches: Vec<RenewBatch>,
        /// How many batches the switch took.
        sent: usize,
        /// The renewing version, as signed.
        doc: SignedDoc,
        /// The document hash of the version it builds on.
        prev: Option<[u8; 32]>,
    },
    /// Taking the identity over from a hand-over (Switch wire 3.12), until the first
    /// delivery has won and the secret is in the vault.
    TakingOver {
        /// The hand-over as the switch served it, sealed to this app's bundle key: the secret
        /// is opened from it in memory, to sign and to send, and goes to the vault only once
        /// the delivery has won.
        handover: SignerHandover,
        /// This app's App ID, the hand-over's target.
        app_id: [u8; 16],
        /// The first delivery, once check 3 has passed and it is signed.
        delivery: Option<TakeOverDelivery>,
    },
    /// Erasing the identity's account at its switch (Switch spec 12.7, Switch wire 7.4.16):
    /// first `identity.json` and the app records leave the Homeserver, then the erasure is
    /// sent until it is answered.
    Erase {
        /// The original authorized account, retained through unknown outcomes.
        account: Service,
        /// The Homeserver's files are deleted.
        unpublished: bool,
        /// The App IDs whose grant reminder this erasure raised: withdrawn if it ends without
        /// erasing the account.
        reminded: Vec<[u8; 16]>,
        /// An erasure request went out with no definitive application result: it may have
        /// landed (including after signed unavailable), so the
        /// signed `404` of an identity the service doesn't host now means it did, and an
        /// unsigned `404` does once it has held for 24 hours (Switch wire 7.4.16).
        unanswered: bool,
        /// The device time a check first met an unsigned `404` after the request in
        /// doubt, kept until an answer the pinned key signs: erased but unconfirmed, the
        /// erasure done at the first run 24 hours on (Switch wire 7.4.16, spec 12.7 step 5).
        first_404_ms: Option<u64>,
        /// The copy a signed `409` at an account that answers the notice showed it to hold,
        /// which the erasure names in place of the mark's, its retries included; `None`
        /// until one did (Switch wire 7.4.16).
        shown: Option<ShownCopy>,
    },
    /// Recovering with the identity key alone (Switch spec 12.8): the `existing` enrollment
    /// at the service the newest copy names, sent again with the same bytes until answered,
    /// then the records rebuilt and the version naming this install signed, in one commit,
    /// once the survey the user confirmed still reads the same.
    KeyRecover {
        /// The service's origin.
        origin: String,
        /// The observation and the signed `existing` enrollment selected from it.
        enrollment: RecoveryEnrollment,
        /// Whether the selected enrollment can already be stopped before signing its version.
        step: KeyEnrollmentStep,
        /// The digest of the survey the user confirmed.
        digest: [u8; 32],
        /// The listed apps the user chose to drop.
        dropped: Vec<[u8; 16]>,
        /// Whether the records were made for it, on a store that held none or unusable ones:
        /// a refusal before the version is signed deletes them.
        fresh: bool,
    },
    /// Delivering a new `identity.json` version, then publishing it.
    Deliver {
        /// The original target of this signed version, kept through every retry.
        account: Service,
        /// The new version, as signed.
        doc: SignedDoc,
        /// The document hash of the version it builds on.
        prev: Option<[u8; 32]>,
        /// The backup holding it, sealed and signed once.
        backup: Option<SignerBackup>,
        /// Where it is.
        step: DeliverStep,
    },
}

impl Flow {
    /// The chosen service where first setup stopped before signing any enrollment.
    pub(crate) fn first_account_origin(&self) -> Option<&str> {
        match self {
            Self::FirstAccountPresent { origin, .. } => Some(origin),
            _ => None,
        }
    }

    /// A first setup stopped before signing has no pending action for a restore to displace.
    pub(crate) fn blocks_restore(&self) -> bool {
        self.first_account_origin().is_none()
    }

    pub(crate) fn check_state(&self, state: &SignerState) -> Result<()> {
        self.check_copies(&state.identity)?;
        if matches!(self, Self::FirstAccountPresent { .. }) && !state.before_first_version() {
            return Err(RecordsFault::Invariant("first setup already selected an account").into());
        }
        if let Self::Recover { origin, enrollment } = self {
            enrollment.check_exclusions(state, origin)?;
        }
        if let Self::RecoveryDelivery(action) = self {
            action.check_state(state)?;
        }
        Ok(())
    }

    pub(crate) fn check_copies(&self, identity: &[u8; 32]) -> Result<()> {
        match self {
            Self::RecoveryDelivery(action) => action.check(identity)?,
            Self::Enroll {
                origin,
                nonce,
                enrollment,
                policy,
            } => {
                if !pubky_switch_core::records::is_origin(origin) {
                    return Err(RecordsFault::Invariant("invalid enrollment origin").into());
                }
                if let Some(signed) = enrollment {
                    let enrollment = Enrollment::verify(signed, identity, origin)
                        .map_err(SignerError::StoredData)?;
                    if enrollment.body().nonce != *nonce
                        || enrollment.body().policy != *policy
                        || !matches!(enrollment.body().intent, EnrollmentIntent::Create { .. })
                    {
                        return Err(RecordsFault::Invariant("another initial enrollment").into());
                    }
                }
            }
            Self::FirstAccountPresent {
                origin,
                observation,
            } => {
                let observed = observation
                    .verify(identity, origin)
                    .map_err(SignerError::StoredData)?;
                if observed.body().association == AccountAssociation::Absent {
                    return Err(
                        RecordsFault::Invariant("first setup recorded an absent account").into(),
                    );
                }
            }
            Self::KeyRecover {
                origin,
                enrollment,
                step,
                ..
            } => {
                let (observed, signed) = enrollment.existing(identity, origin)?;
                if let KeyEnrollmentStep::Applied(answer) = step {
                    answer.check(&signed).map_err(SignerError::StoredData)?;
                    if answer.service_key != observed.body().service_key
                        || Some(answer.created) != signed.body().intent.created()
                    {
                        return Err(RecordsFault::Invariant(
                            "another key recovery enrollment result",
                        )
                        .into());
                    }
                }
            }
            Self::Recover { origin, enrollment } => {
                if !pubky_switch_core::records::is_origin(origin) {
                    return Err(RecordsFault::Invariant("invalid recovery origin").into());
                }
                match enrollment {
                    RecoveryEnrollment::Preparing { revoked_apps, .. } => {
                        if revoked_apps
                            .windows(2)
                            .any(|ids| matches!(ids, [a, b] if a >= b))
                        {
                            return Err(
                                RecordsFault::Invariant("unordered recovery exclusions").into()
                            );
                        }
                    }
                    RecoveryEnrollment::Ready {
                        observation,
                        enrollment,
                    } => {
                        let observed = observation
                            .verify(identity, origin)
                            .map_err(SignerError::StoredData)?;
                        let signed = Enrollment::verify(enrollment, identity, origin)
                            .map_err(SignerError::StoredData)?;
                        if signed.body().intent != observed.enrollment_intent()?
                            || signed.body().identity_doc.is_some()
                        {
                            return Err(
                                RecordsFault::Invariant("another recovery enrollment").into()
                            );
                        }
                    }
                }
            }
            Self::Renew {
                account,
                batches,
                doc,
                ..
            } => {
                account.check_document(&stored_identity(doc, identity)?)?;
                for batch in batches {
                    batch.read(identity)?;
                }
            }
            Self::TakingOver {
                handover,
                app_id,
                delivery,
            } => {
                handover
                    .verify(identity, app_id)
                    .map_err(SignerError::StoredData)?;
                if let Some(delivery) = delivery {
                    stored_identity(&delivery.doc, identity)?;
                }
            }
            Self::Deliver {
                account,
                doc,
                backup,
                ..
            } => {
                account.check_document(&stored_identity(doc, identity)?)?;
                if let Some(backup) = backup {
                    backup.verify(identity).map_err(SignerError::StoredData)?;
                }
            }
            Self::Erase { account, .. } => account.check()?,
        }
        Ok(())
    }
}

/// One signed batch of a renewal or an epoch's completion, and the key bundle parts it stores.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct RenewBatch {
    /// The batch, as signed.
    pub(crate) bytes: Bytes,
    /// The key bundle parts it stores (Switch wire 3.5).
    pub(crate) parts: Vec<StoredPart>,
}

impl RenewBatch {
    /// Read and authenticate the exact operations this signer kept before sending them.
    pub(crate) fn read(&self, identity: &[u8; 32]) -> Result<Batch> {
        let batch = Batch::from_body(self.bytes.0.clone()).map_err(|_| {
            SignerError::StoredData(pubky_switch_core::Error::Invalid(
                "stored renewal batch does not parse".into(),
            ))
        })?;
        for op in batch.ops() {
            SignedOp::verify(op.signed(), identity, identity, None).map_err(|_| {
                SignerError::StoredData(pubky_switch_core::Error::Invalid(
                    "stored renewal operation does not verify for the signer".into(),
                ))
            })?;
        }
        Ok(batch)
    }
}

/// Verify an identity document read from the signer's own state or flow.
pub(crate) fn stored_identity(signed: &SignedDoc, identity: &[u8; 32]) -> Result<IdentityDoc> {
    IdentityDoc::verify(signed, identity).map_err(SignerError::StoredData)
}

/// Bytes kept as they were signed, stored in base64url.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub(crate) struct Bytes(
    #[serde(with = "pubky_switch_core::enc::serde_b64_vec")] pub(crate) Vec<u8>,
);

/// Delete the records and the flow of `identity`, in one atomic write: once the identity was
/// handed over, or a take-over was cancelled (Switch spec 12.8).
pub(crate) async fn delete(store: &mut OwnedStoreHandle, identity: &[u8; 32]) -> Result<()> {
    let ns = signer_namespace(identity);
    let mut batch = WriteBatch::new();
    for key in [STATE_KEY, FLOW_KEY] {
        batch.delete(&ns, key).map_err(RecordsFault::WriteRefused)?;
    }
    store.commit(batch).await?;
    Ok(())
}

/// Whether the store holds records for `identity` that a new set-up would replace: any but
/// those of a hand-over that took effect, which are only waiting to be deleted.
pub(crate) async fn set_up(store: &OwnedStoreHandle, identity: &[u8; 32]) -> Result<bool> {
    Ok(load(store, identity)
        .await?
        .is_some_and(|(state, _)| state.handed_over_to.is_none()))
}

/// Read the records and the flow of `identity`; `None` when the store holds none.
pub(crate) async fn load(
    store: &OwnedStoreHandle,
    identity: &[u8; 32],
) -> Result<Option<(SignerState, Option<Flow>)>> {
    let records = read(store, identity).await?;
    let Some(state) = records.state? else {
        if !matches!(records.flow, Ok(None)) {
            return Err(RecordsFault::Incomplete.into());
        }
        return Ok(None);
    };
    let flow = records.flow?;
    state.check_stored_copies()?;
    check_flow(&state, flow.as_ref())?;
    Ok(Some((state, flow)))
}

fn check_flow(state: &SignerState, flow: Option<&Flow>) -> Result<()> {
    if state.recovery_commit.is_some() && !matches!(flow, Some(Flow::RecoveryDelivery(_))) {
        return Err(RecordsFault::Incomplete.into());
    }
    if let Some(flow) = flow {
        flow.check_state(state)?;
    }
    Ok(())
}

/// Independently decoded current records, read together while the namespace is owned.
/// A decoded state has the current header and requested identity; its copies are not yet
/// authenticated. Only the explicit confirmed restore may retain it after a copy fails.
pub(crate) struct ReadRecords {
    pub(crate) state: Result<Option<SignerState>>,
    pub(crate) flow: Result<Option<Flow>>,
}

pub(crate) async fn read(store: &OwnedStoreHandle, identity: &[u8; 32]) -> Result<ReadRecords> {
    if store.namespace() != signer_namespace(identity) {
        return Err(RecordsFault::Invariant("another store namespace").into());
    }
    let bytes = store.get(STATE_KEY).await?;
    let flow = store.get(FLOW_KEY).await?;
    let state = bytes
        .map(|bytes| {
            let state: SignerState = decode(&bytes, SignerRecord::State)?;
            if state.v != SCHEMA_VERSION {
                return Err(RecordsFault::InvalidHeader.into());
            }
            if &state.identity != identity {
                return Err(RecordsFault::OtherIdentity.into());
            }
            Ok(state)
        })
        .transpose();
    let flow = flow
        .map(|bytes| decode(&bytes, SignerRecord::Flow))
        .transpose();
    Ok(ReadRecords { state, flow })
}

/// Commit the records and the flow together, in one atomic write.
pub(crate) async fn save(
    store: &mut OwnedStoreHandle,
    state: &SignerState,
    flow: Option<&Flow>,
) -> Result<()> {
    state.check_copies().map_err(|_| {
        RecordsFault::Invariant("the state to write contains an invalid signed copy")
    })?;
    check_flow(state, flow).map_err(|_| {
        RecordsFault::Invariant("the flow to write disagrees with the signer records")
    })?;
    let ns = signer_namespace(&state.identity);
    let mut batch = WriteBatch::new();
    batch
        .put(&ns, STATE_KEY, encode(state)?)
        .map_err(RecordsFault::WriteRefused)?;
    match flow {
        Some(flow) => batch
            .put(&ns, FLOW_KEY, encode(flow)?)
            .map_err(RecordsFault::WriteRefused)?,
        None => batch
            .delete(&ns, FLOW_KEY)
            .map_err(RecordsFault::WriteRefused)?,
    };
    store.commit(batch).await?;
    Ok(())
}

fn encode<T: Serialize>(value: &T) -> Result<Vec<u8>> {
    serde_json::to_vec(value).map_err(|_| RecordsFault::Encode.into())
}

fn decode<T: for<'de> Deserialize<'de>>(bytes: &[u8], record: SignerRecord) -> Result<T> {
    // The decoder's message can quote the stored value, which may hold signed records:
    // only the position is kept.
    serde_json::from_slice(bytes).map_err(|e| {
        RecordsFault::Undecodable {
            record,
            line: e.line(),
            column: e.column(),
        }
        .into()
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_state_round_trips_every_member() {
        let state = SignerState::new([1; 32], [2; 16]);
        assert!(
            !state.ever_published,
            "a new identity's records start unpublished"
        );
        assert_eq!(state.cert_lifetime_ms, DEFAULT_CERT_LIFETIME_MS);
        let read: SignerState = decode(&encode(&state).unwrap(), SignerRecord::State).unwrap();
        assert_eq!(read, state);
    }

    #[test]
    fn test_identity_near_limit_raised_replaced_and_cleared() {
        // The cap a delivery and a move's enrollment share is 256 KiB (Switch wire 3.7, 7.1):
        // past three quarters of it the user is told, one alert at a time, with the newest
        // size, and none once the version is smaller again.
        let limit = 256 << 10;
        let near = |bytes: usize| Alert::IdentityNearLimit {
            bytes: bytes as u64,
            limit: limit as u64,
        };
        let mut state = SignerState::new([1; 32], [2; 16]);
        state.note_size(limit * 3 / 4, limit);
        assert!(state.alerts.is_empty());
        state.note_size(limit * 3 / 4 + 1, limit);
        assert_eq!(state.alerts, [near(limit * 3 / 4 + 1)]);
        state.note_size(limit + 10, limit);
        assert_eq!(state.alerts, [near(limit + 10)]);
        state.note_size(1_000, limit);
        assert!(state.alerts.is_empty());
    }
}
