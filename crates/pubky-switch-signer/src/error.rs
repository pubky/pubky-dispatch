//! The signer's error type.
//!
//! Every failure has a typed variant, so a host can tell a refusal it shows the user from a
//! key or storage failure it reports. Messages name the rule that failed and never carry a
//! secret, and they don't repeat the text of a document or request that failed a check.

use pubky_switch_client::{ClientError, StoreError, TransportError};

use crate::alert::Alert;
use crate::key::KeyError;
use crate::protocol::ProtocolError;

/// A failure of the signer.
#[derive(Debug, thiserror::Error, Clone, PartialEq)]
#[non_exhaustive]
pub enum SignerError {
    /// The identity key couldn't be loaded, stored or used.
    #[error(transparent)]
    Key(#[from] KeyError),
    /// A rule refused what was asked: the signer shows the user why.
    #[error(transparent)]
    Refused(#[from] Refusal),
    /// A protocol the host registered is malformed, or gave the signer something the Switch's
    /// rules don't allow. This is a fault of the host's set-up, not of the request.
    #[error(transparent)]
    Protocol(#[from] ProtocolError),
    /// Data that didn't verify or parse, such as a document from the network.
    #[error("invalid data: {0}")]
    InvalidData(#[from] pubky_switch_core::Error),
    /// A call to the switch failed. A call that may not have arrived is resent with the same
    /// bytes by [`crate::Signer::resume`].
    #[error(transparent)]
    Switch(#[from] ClientError),
    /// The identity's Homeserver couldn't be read or written.
    #[error("homeserver: {0}")]
    Homeserver(TransportError),
    /// The host's store failed.
    #[error(transparent)]
    Store(#[from] StoreError),
    /// Reading or constructing the signer's local records failed.
    #[error("signer records: {0}")]
    Records(#[from] RecordsFault),
    /// A signed artifact kept in the signer's records no longer verifies or parses.
    /// This is distinct from invalid caller input or an invalid network answer.
    #[error("stored signer data: {0}")]
    StoredData(#[source] pubky_switch_core::Error),
    /// Another install is the identity's signer, as the newest `identity.json` or the backup
    /// names it, so this one signs nothing until the user has it take over (Switch spec 4.3,
    /// 12.8): [`crate::Signer::restore`], from the backup, or with the key alone when the
    /// backup is missing, unreadable or stale ([`crate::Signer::survey_key_recovery`]).
    #[error("another install is the identity's signer")]
    NotNamed {
        /// That install's signer ID.
        install: [u8; 16],
    },
    /// A rollback or an equivocation: the signer shows it to the user instead of building on
    /// it (Switch spec 4.3, Switch wire 3.3 "Never back").
    #[error("alarm: {0:?}")]
    Alarm(Alert),
    /// The hand-over took effect: the switch holds the version after the one handed over,
    /// naming `install`, so this install deleted the identity key and its records (Switch
    /// wire 3.12, Switch spec 12.8). That install is the hand-over's target, or one that
    /// restored the target's backup in the meantime: the switch's copy can't tell them apart.
    #[error("the identity was handed over, and this install deleted its key and records")]
    HandedOver {
        /// The signer ID the switch's copy names.
        install: [u8; 16],
    },
}

/// Which of the signer's two atomic local records could not be decoded.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SignerRecord {
    /// The signer's state.
    State,
    /// The exact flow kept for retry.
    Flow,
}

/// A failure of the signer's local record format or of constructing its next write.
///
/// A failed host read or commit is instead [`SignerError::Store`]. A refused write or
/// internal invariant does not mean the existing records can be discarded.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum RecordsFault {
    /// A current local record could not be decoded. No stored value appears in the error.
    #[error("{record:?} cannot be decoded at line {line} column {column}")]
    Undecodable {
        /// The record being read.
        record: SignerRecord,
        /// The decoder's one-based line.
        line: usize,
        /// The decoder's column.
        column: usize,
    },
    /// The current state header is invalid.
    #[error("invalid state header")]
    InvalidHeader,
    /// The state belongs to a different identity than its namespace.
    #[error("state belongs to another identity")]
    OtherIdentity,
    /// A flow is present without the state committed together with it.
    #[error("flow without state")]
    Incomplete,
    /// A stored signer record breaks a binding checked before every write.
    #[error("stored signer state is damaged: {0}")]
    Damaged(&'static str),
    /// The bounded write batch refused a write before calling the host store.
    #[error("{0}")]
    WriteRefused(pubky_switch_client::store::BatchError),
    /// Serializing a local record or signed artifact failed.
    #[error("records cannot be encoded")]
    Encode,
    /// An internal requirement failed; this is not evidence of unreadable stored data.
    #[error("{0}")]
    Invariant(&'static str),
}

/// A body a version of `identity.json` must fit in (Switch wire 3.7, 7.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum SizedBody {
    /// Its delivery, `PUT /identity`.
    Delivery,
    /// A move's enrollment carrying it, `POST /enroll`.
    Enrollment,
}

impl std::fmt::Display for SizedBody {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Delivery => "delivery",
            Self::Enrollment => "move's enrollment",
        })
    }
}

/// A rule of the Switch or of a protocol said no.
///
/// The `Display` text names the rule only. The fields carry what a host shows the user, such as
/// the scopes no registered protocol owns.
#[derive(Debug, thiserror::Error, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum Refusal {
    /// A clock-derived floor for recovery without a copy is too high (Switch spec 12.8).
    /// Correct the device clock and repeat the provider-loss survey.
    #[error("refused: correct the device clock before choosing the {counter:?} floor")]
    CounterClock {
        /// The counter derived from the clock.
        counter: crate::Counter,
    },
    /// A pending counter needs independent evidence. Keep the original bytes and retry
    /// when a verified copy is reachable (Switch spec 4.3, 12.8).
    #[error("retry when a verified copy of the {counter:?} counter is available")]
    CounterCopyNeeded {
        /// The counter for which a copy is needed.
        counter: crate::Counter,
    },
    /// The counter has no wire-representable successor for this operation
    /// (Switch wire 1.1). Advancing past that limit requires a protocol change.
    #[error("refused: advancing the {counter:?} counter requires a wider wire range")]
    CounterExhausted {
        /// The counter that would exceed the wire range.
        counter: crate::Counter,
    },
    /// The scopes break the Switch's scope rule: at most 32, each a name or `name:<sub>`, each
    /// once, and never a name beside one of its own sub-scopes (Switch spec 3.3, Switch wire
    /// 3.1). The reason is the core's, naming the part of the rule that failed.
    #[error("refused: {0}")]
    Scopes(String),
    /// Scopes whose names no registered protocol owns (Switch wire 3.9 step 1). The host tells
    /// the user which protocol support is missing.
    #[error("refused: {} scope(s) that no registered protocol owns", scopes.len())]
    UnknownScopes {
        /// The scopes, in the order they were asked for.
        scopes: Vec<String>,
    },
    /// A protocol's own rule on its scopes, or on its grant paths, refused them (Switch spec 1,
    /// 3.4).
    #[error("refused by the rules of protocol {protocol}: {reason}")]
    ProtocolRule {
        /// The protocol's name.
        protocol: String,
        /// The protocol's reason.
        reason: String,
    },
    /// A decline of a path that isn't one the user may decline: only a path a protocol added
    /// to the app's grant, and the app asks for, is (Switch spec 3.4, Switch wire 3.9). The
    /// app's record and backup paths never are.
    #[error("refused: a path the user can't decline")]
    NotDeclinable {
        /// The path.
        path: String,
    },
    /// The app request fails a check of Switch wire 3.9: the reason names the step.
    #[error("refused: {0}")]
    AppRequest(String),
    /// The effective authority of a previously confirmed app request has changed
    /// (Switch spec 12.1). Show the current terms and obtain a new confirmation.
    #[error("refused: the app approval terms changed")]
    ApprovalChanged,
    /// The app isn't listed in the newest `identity.json`, so it has no certificate to renew.
    #[error("refused: the app isn't listed")]
    NotListed,
    /// The approval's version is delivered, but its claim is held: the switch isn't confirmed
    /// to hold the signer's newest version since a rollback or an equivocation, named here
    /// when its alert is still held ([`crate::Signer::clear_alert`]).
    #[error("refused: the claim is held until the switch is confirmed")]
    ClaimHeld {
        /// The rollback or equivocation alert behind it, if still held.
        alert: Option<crate::alert::Alert>,
    },
    /// The app hasn't joined: the switch holds no record of it, so it takes no certificate or
    /// bundle for it yet (Switch wire 6.2, spec 12.1 step 2).
    #[error("refused: the app hasn't joined the switch")]
    NotJoined,
    /// The store already holds this identity's signer records, so it isn't set up again.
    #[error("refused: the signer is already set up for this identity")]
    AlreadySetUp,
    /// This install's records are behind a newer `identity.json` it signed itself, so it
    /// signs nothing until they are restored (Switch wire 3.13): [`crate::Signer::restore`],
    /// from the signer backup, or with the key alone when the backup is missing, unreadable
    /// or stale ([`crate::Signer::survey_key_recovery`]).
    #[error("refused: this install's records are behind its own version {version}")]
    RecordsBehind {
        /// The newer version.
        version: u64,
    },
    /// That App ID is revoked, being revoked, or seen departing: it gets no new certificate
    /// or key (Switch spec 12.2).
    #[error("refused: the App ID is revoked or being revoked")]
    CutOff,
    /// This install is handing the identity over to the app `to_app`: it signs nothing but
    /// the abort until the hand-over takes effect or is aborted (Switch wire 3.12).
    #[error("refused: the identity is being handed over")]
    HandingOver {
        /// The new signer's App ID.
        to_app: [u8; 16],
    },
    /// The device clock and the switch's signed time differ by more than the clock tolerance
    /// (Switch spec 10.1): a certificate would be stamped with a time the switch doesn't
    /// share, so none is issued or renewed until they agree.
    #[error("refused: the device clock is off the switch's time")]
    ClockOff {
        /// The device clock, in Unix milliseconds.
        device_ms: u64,
        /// The switch's signed time, in Unix milliseconds.
        switch_ms: u64,
    },
    /// The version would be larger than `body` may carry: a delivery (`PUT /identity`'s body
    /// cap), or a move's enrollment carrying it with the App IDs revoked (`POST /enroll`'s)
    /// (Switch wire 3.7, 7.1). It is measured with its open `renewed` entries closed, as later
    /// versions close them: the switch could never take it or its closings, or the identity
    /// could never move. Nothing is signed. A revocation, which drops the app's `renewed`
    /// entries, never makes either body larger: the enrollment is measured with every listed
    /// app's App ID as revoked already.
    #[error("refused: identity.json would be over the size a {body} may carry")]
    IdentityTooLarge {
        /// The body that wouldn't fit.
        body: SizedBody,
        /// Its size, in bytes.
        bytes: u64,
        /// Its cap, in bytes.
        limit: u64,
    },
    /// No hand-over is in progress to abort.
    #[error("refused: no hand-over is in progress")]
    NotHandingOver,
    /// The identity's account at its switch is erased (Switch spec 12.7): nothing more is
    /// signed for it.
    #[error("refused: the account is erased")]
    Erased,
    /// The switch refused the erasure (`409 conflict`) while it still holds this install's
    /// mark, as during a move (Switch wire 7.4.16). Nothing was erased: `identity.json` is
    /// published again, and the grant reminders the erasure raised are withdrawn.
    #[error("refused: the switch refused the erasure")]
    ErasureRefused,
    /// No erasure is in progress to abort.
    #[error("refused: no erasure is in progress")]
    NotErasing,
    /// An erasure request went unanswered, so it may have erased the account: the erasure
    /// can't be aborted, and [`crate::Signer::resume`] sends it again, after a check, to learn
    /// the outcome. Once an unsigned `404` has been met, `resume` only reads, until the `404`
    /// has held for 24 hours or an answer the pinned key signs ends the wait
    /// ([`Refusal::ErasureUnconfirmed`]).
    #[error("refused: the erasure may have reached the switch")]
    ErasureUnanswered,
    /// The account looks erased: after a request in doubt, a check or a retry met an unsigned
    /// `404` at `since_ms`, by the device clock, which may be an intermediary's and which
    /// nobody can authenticate, and no answer the pinned key signs has come since. The erasure is
    /// done at the first run 24 hours on that meets the `404` again; an answer the pinned key
    /// signs before that, an error included, ends the wait, and the next `404` starts it
    /// again (Switch wire 7.4.16, spec 12.7 step 5). No answer, and an unsigned answer other
    /// than a `404`, leave it as it is. Nothing else is signed meanwhile, and revocations are
    /// refused.
    #[error("refused: the account looks erased, unconfirmed until 24 hours have passed")]
    ErasureUnconfirmed {
        /// When a check first met the `404`, in Unix milliseconds, by the device clock.
        since_ms: u64,
    },
    /// This install is taking the identity over: it signs nothing but its first delivery
    /// until that has won (Switch wire 3.12).
    #[error("refused: the identity is being taken over")]
    TakingOver,
    /// The target of a hand-over isn't current at the switch with the certificate the newest
    /// `identity.json` lists for it (Switch wire 3.12, 7.4.17).
    #[error("refused: the hand-over's target isn't current")]
    TargetNotCurrent,
    /// A revocation is asked for whose version isn't delivered yet: no hand-over until it is.
    /// The hand-over carries the records, not a revocation in progress, so one the switch
    /// hadn't taken would never be sent (Switch spec 12.2, Switch wire 3.12).
    #[error("refused: a revocation is owed")]
    RevocationOwed,
    /// A reduction's closing delivery is owed: no hand-over until it is made (Switch wire
    /// 3.12).
    #[error("refused: a closing delivery is owed")]
    ClosingOwed,
    /// The take-over's check 3 failed (Switch wire 3.12): the switch's copy of `identity.json`
    /// isn't the version handed over, or the Homeserver's is newer or another at its version.
    /// An abort that won, a newer version, or a switch that went back. Nothing was sent, and
    /// nothing received is kept.
    #[error("refused: the switch's or the Homeserver's copy isn't the version handed over")]
    StaleHandOver,
    /// The switch holds a newer version naming `install`, but the proof that it holds the
    /// identity isn't there yet: its signer backup on the Homeserver, holding a newer version
    /// naming it (Switch wire 3.12). This install signs nothing, as one that isn't named,
    /// keeps the key and the hand-over, and looks for the proof again at each run; if that
    /// install is lost, the user takes the identity back ([`crate::Signer::take_back`]).
    #[error("refused: another install's version holds no proof yet")]
    SuccessorUnproven {
        /// The signer ID the switch's copy names.
        install: [u8; 16],
    },
    /// Nothing to take back: the switch doesn't show another install's version after the one
    /// handed over, or that install's proof is there, or no hand-over is in progress (Switch
    /// wire 3.12).
    #[error("refused: nothing to take back")]
    NothingToTakeBack,
    /// The store holds no take-over in progress for this identity.
    #[error("refused: no take-over is in progress")]
    NotTakingOver,
    /// The take-over was cancelled: the switch holds a newer version that isn't this
    /// install's first delivery, as after an abort (Switch wire 3.12). What was received, the
    /// records and the take-over, are deleted.
    #[error("refused: the take-over was cancelled")]
    TakeOverCancelled,
    /// The Homeserver holds no signer backup to restore from (Switch wire 3.13). The way on
    /// is a recovery with the key alone: [`crate::Signer::survey_key_recovery_new`] (or
    /// [`crate::Signer::survey_key_recovery`] in place), then the restore again with the
    /// user's [`crate::KeyRecoveryConfirmed`].
    #[error("refused: there is no signer backup; recover with the identity key")]
    NoBackup,
    /// The signer backup is stale: the switch holds another version than the backup's or
    /// the one it builds on, or the Homeserver a newer one or another at its version (Switch
    /// wire 3.13 "Restoring"). The way on is a recovery with the key alone, as for
    /// [`Refusal::NoBackup`].
    #[error("refused: the signer backup is stale; recover with the identity key")]
    StaleBackup,
    /// A recovery with the identity key alone doesn't go ahead, for the reason given (Switch
    /// spec 12.8); nothing was signed.
    #[error("refused: the recovery with the identity key doesn't go ahead: {0:?}")]
    KeyRecovery(KeyRecoveryStop),
    /// The newest `identity.json` doesn't list that App ID in `removed`.
    #[error("refused: the App ID isn't in removed")]
    NotRemoved,
    /// An alarm's alert was cleared, and the re-delivery that confirms the switch holds this
    /// signer's newest version hasn't succeeded yet: nothing new is signed until it has
    /// ([`crate::Signer::resume`] sends it).
    #[error("refused: the switch isn't confirmed since an alarm")]
    SwitchUnconfirmed,
    /// There is no ordinary recovery that the holder can stop before its version is signed
    /// (Switch spec 12.8). A signed delivery or other pending work resumes normally.
    #[error("refused: no ordinary key recovery is pending before its signed version")]
    NoPendingKeyRecovery,
    /// The original first creation cannot be restarted under the same absent account
    /// binding (Switch account binding 3). Resume the pending action or use recovery.
    #[error("refused: first enrollment cannot be restarted at this service")]
    FirstEnrollmentUnavailable,
    /// Setup waits at the saved first step until the user addresses its alert.
    #[error("refused: first enrollment is waiting for the user")]
    FirstEnrollmentHeld,
    /// First discovery found an account or its mark before this install signed a creation.
    /// The user can restore the signer (Switch account binding 3 and spec 12.8).
    #[error("refused: the service already has this identity's account or its mark")]
    FirstAccountPresent,
    /// The store holds no signer records for this identity.
    #[error("refused: the signer isn't set up for this identity")]
    NotSetUp,
    /// The Homeserver holds a signer backup this install can't open: found by a restore, the
    /// way on is a recovery with the key alone, as for [`Refusal::NoBackup`]; found before an
    /// enrollment's first version was delivered, nothing is written or delivered until the
    /// user deals with it ([`crate::Alert::UnreadableBackupBeforeEnrollment`]).
    #[error("refused: the Homeserver holds a signer backup this install can't open")]
    UnreadableBackup,
    /// A flow is in progress: [`crate::Signer::resume`] finishes it first.
    #[error("refused: a flow is in progress")]
    FlowInProgress,
    /// A provider loss is declared and the new service hasn't taken its version yet (Switch
    /// spec 12.6 step 1): nothing else is signed meanwhile. [`crate::Signer::resume`] goes on
    /// with it, and [`crate::Signer::declare_provider_loss`] declares it again, at the same
    /// service or another.
    #[error("refused: a recovery is in progress")]
    Recovering,
    /// The Homeserver holds no `identity.json`, which the records don't explain: another
    /// install may have signed and published newer versions there, deleted since, so a
    /// provider loss isn't declared on this install's records alone (Switch spec 12.6 step
    /// 1). [`crate::Signer::declare_provider_loss_confirming_records`] declares it once the
    /// user confirms no other install signs.
    #[error("refused: the Homeserver holds no identity.json")]
    HomeserverCopyMissing,
    /// The Homeserver's `identity.json` doesn't verify, which the signer's own steps never
    /// leave: it is refused as [`Refusal::HomeserverCopyMissing`] is, with the same way past
    /// it.
    #[error("refused: the Homeserver's identity.json doesn't verify")]
    HomeserverCopyUnreadable,
    /// The switch holds a newer `identity.json` that this install didn't sign, which it
    /// adopted; the change asked for wasn't made, and may be asked for again on top of it
    /// (Switch spec 4.3).
    #[error("refused: the switch holds a newer version, {version}, which the signer adopted")]
    Superseded {
        /// The adopted version.
        version: u64,
    },
}

/// Why a recovery with the identity key alone doesn't go ahead (Switch spec 12.8). It builds
/// on the copy of `identity.json` the account's service holds, so it needs a service that
/// serves the account and holds the newest version anyone saw. Where it doesn't, the way on
/// is a provider loss declared with the key alone, at a service the user picks
/// ([`crate::Signer::survey_provider_loss_with_key`],
/// [`crate::Signer::declare_provider_loss_with_key`]), which works from whatever the store
/// holds.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum KeyRecoveryStop {
    /// No copy of `identity.json` the identity key signed was found, on the Homeserver, in a
    /// backup that opens or in this install's records, so no service is known to recover
    /// at: the user gives the one that serves the account
    /// ([`crate::Signer::survey_key_recovery_new_at`]).
    NoCopy,
    /// The service the newest copy names, or the one the user gave, doesn't serve the
    /// account: it holds none, only its mark, or a staged or recovering one, or answers with
    /// an error it signs. Where the account moved since that copy, the user gives the service
    /// that serves it ([`crate::Signer::survey_key_recovery_new_at`]).
    NotServing,
    /// The service's copy is missing, doesn't verify, or names another origin or service key
    /// than the one that answered.
    SwitchCopy,
    /// A copy newer than the service's was seen, at `seen_version`: on the Homeserver, in the
    /// signer backup or in this install's records, or this install's own epochs show one.
    /// The service holds an older version, `switch_version`, and building on it would undo
    /// what came after.
    ServiceBehind {
        /// The version of the service's copy.
        switch_version: u64,
        /// The version seen above it.
        seen_version: u64,
    },
    /// What the survey shows changed since the user confirmed it: survey again and confirm.
    SurveyChanged,
    /// The service's copy carries members this signer doesn't read, which a later version of
    /// the signer signed: recovering here would drop them. A signer version that reads them
    /// recovers.
    UnknownMembers,
}

/// The signer's result type.
pub type Result<T> = std::result::Result<T, SignerError>;
