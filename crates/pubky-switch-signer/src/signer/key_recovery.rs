//! Recovering with the identity key alone (Switch spec 12.8 "Recovering with the key alone";
//! Switch wire 3.13 "Restoring").
//!
//! When the signer backup is missing, doesn't open, or is stale, a holder of the identity key
//! still takes the identity back: the install rebuilds the records from what the key verifies
//! and signs the next version on the copy of `identity.json` the account's service holds,
//! naming itself, with the same content. The service's compare-and-swap decides between it
//! and any other install, as for every racing delivery.
//!
//! First a read-only survey ([`Signer::survey_key_recovery`], [`Signer::survey_key_recovery_new`])
//! shows the user what the recovery does: the service, the version it builds on and the install
//! that version names, each listed app's fate, and what the backup held. The user confirms
//! that survey, as a whole: a recovery whose survey reads otherwise when it signs is refused
//! ([`KeyRecoveryStop::SurveyChanged`]).
//!
//! It goes ahead only when:
//!
//! 1. the service the newest copy the key signed names (on the Homeserver, in a backup that
//!    opens, in this install's records) serves the account: an authenticated account read
//!    shows it, and `GET /apps` answers `200`;
//! 2. the service's copy verifies, and names that origin and the key that signed its answers,
//!    which the recovery keeps as the account's key;
//! 3. nothing shows a newer copy than the service's: not the Homeserver's copy, not this
//!    install's own records, nor a backup above it.
//!
//! What it takes:
//!
//! - the App IDs revoked for good, from the copies' `removed`, every backup that opens, this
//!   install's records, and what `GET /apps` shows revoked, departed, or kept with no record,
//!   the last as far as a move's enrollment can still carry them;
//! - the certificates from every backup that opens, whatever its age, this install's records,
//!   and each app's own record on the Homeserver. An app whose certificate isn't found is
//!   revoked, and approved again under a new key; an earlier certificate in `renewed` that
//!   isn't found is dropped, and the messages carrying it are refused;
//! - for a revocation in progress, the earliest time to distrust the app from that any backup
//!   or copy shows;
//! - the limits, from an `existing` enrollment at the account, which changes nothing there
//!   (Switch wire 3.7), committed before it is sent and sent again with the same bytes.
//!
//! The records and the version are committed together. Its backup is written once that
//! delivery has won, as for every racing delivery; while the version names a certificate
//! this install doesn't hold, none can be sealed, and the version after it, which removes
//! those apps and drops those entries, comes before every other one.
//!
//! Where that recovery can't go ahead, or the user prefers, the key alone also declares a
//! provider loss at a service the user picks, from whatever the store holds
//! ([`Signer::survey_provider_loss_with_key`], [`Signer::declare_provider_loss_with_key`]):
//! it builds on the highest copy the key signed that any source shows, and starts the next
//! generation there (Switch spec 12.6, 12.8).

mod cancellation;
mod first_enrollment;
pub use first_enrollment::FirstEnrollmentRestore;

use std::collections::BTreeSet;

use pubky_switch_client::ClientError;
use pubky_switch_client::client::answers::AppsAnswer;
use pubky_switch_client::store::OwnedStoreHandle;
use pubky_switch_core::enc::{hash, lp, random_bytes, u64be};
use pubky_switch_core::records::{
    AccountAssociation, AccountObservation, AppCert, AppRecord, CLOCK_TOLERANCE_MS, Enrollment,
    EnrollmentAnswer, EnrollmentBody, IDENTITY_PATH, IdentityBody, IdentityDoc, IdentityPolicy,
    Limits, RemovedApp, SIGNER_BACKUP_PATH, app_record_path,
};
use pubky_switch_core::sig::SignedDoc;

use super::clients::{RequestClient, Target};
use super::restore::{KeptCopy, RestoreLocal, check_local_restore, no_copy, restored_alerts};
use super::revocation::UserConfirmed;
use super::{CAP_HEADROOM, Room, Signer, SignerEnv, enrollment_limit, gate};
use crate::alert::Alert;
use crate::error::{KeyRecoveryStop, RecordsFault, Refusal, Result, SignerError};
use crate::key::{BackupView, IdentityKeyring};
use crate::state::{
    self, DeliverStep, Flow, KeyEnrollmentStep, Newest, RecoveryEnrollment, Service, SignerState,
};

/// What a recovery with the identity key alone would do, read before the user confirms it
/// (Switch spec 12.8). Reading it writes nothing.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct KeyRecoverySurvey {
    /// The service the recovery goes to: the one the newest copy of `identity.json` names.
    pub origin: String,
    /// The version of the service's copy, which the recovery builds on.
    pub version: u64,
    /// Its generation, which the recovery keeps.
    pub generation: u64,
    /// The install that copy names: once the recovery's version is delivered, it and every
    /// other install stop signing.
    pub signer: [u8; 16],
    /// Each app that copy lists, and what becomes of it.
    pub apps: Vec<([u8; 16], AppFate)>,
    /// The apps whose earlier certificate in `renewed` isn't found: that entry goes, with the
    /// app or alone, and the messages still carrying that certificate are refused.
    pub renewals_dropped: Vec<[u8; 16]>,
    /// The App IDs kept revoked for good, ascending.
    pub revoked: Vec<[u8; 16]>,
    /// What the signer backup on the Homeserver holds.
    pub backup: BackupFound,
    /// What the recovery does: at the service, or a provider loss.
    pub kind: KeyRecoveryKind,
    /// Whether the user supplied the origin for this survey or for first setup when
    /// discovery found an account and no other copy named a service (Switch spec 12.8).
    pub origin_supplied: bool,
    /// The key the service at `origin` signs with: for a provider loss, the one its account
    /// discovery showed, which every answer there must be signed with; at the service, the
    /// one its copy names.
    pub service_key: [u8; 32],
    identity: [u8; 32],
    copy: [u8; 32],
    /// What the account discovery at `origin` showed: its association and creation.
    discovery: Vec<u8>,
    /// The earlier certificates in `renewed` that go, by document hash.
    certs_dropped: Vec<[u8; 32]>,
    /// For apps the copy removes, the earlier times picked to distrust them from, which the
    /// version signed takes.
    earlier: Vec<RemovedApp>,
    /// The highest version any source showed, which the version signed is above.
    versions: u64,
    /// For a provider loss, what it read, which the declaration acts on.
    carried: Option<Carried>,
    digest: [u8; 32],
}

/// What a provider loss's survey read ([`LossPlan`]), carried to the declaration with the
/// user's confirmation of it. Surveys compare by everything they show, not by this.
#[derive(Clone)]
struct Carried(std::sync::Arc<LossPlan>);

impl PartialEq for Carried {
    fn eq(&self, _: &Self) -> bool {
        true
    }
}

impl Eq for Carried {}

impl std::fmt::Debug for Carried {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Carried")
    }
}

/// What a recovery with the identity key alone does (Switch spec 12.8).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum KeyRecoveryKind {
    /// At the service that serves the account, on its copy: the generation stays
    /// ([`Signer::survey_key_recovery`], [`Signer::survey_key_recovery_new`]).
    AtService,
    /// A provider loss at the service the user picked, built on the highest copy any source
    /// shows (Switch spec 12.6): the generation `lost` is declared lost and the next one
    /// starts there ([`Signer::survey_provider_loss_with_key`]).
    ProviderLoss {
        /// The generation declared lost. `None` when no copy was found anywhere: the first
        /// document then takes its generation and version from the time.
        lost: Option<u64>,
    },
}

/// What becomes of a listed app in a recovery with the key alone (Switch spec 12.8).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum AppFate {
    /// Its certificate was found: it stays listed, unless the user drops it.
    Stays,
    /// The service shows it revoked or departed: the version after the recovery's removes it,
    /// distrusted from `distrust_from` when a backup or a copy shows a time picked earlier.
    RemovedAtSwitch {
        /// The earliest time picked to distrust it from, in Unix milliseconds.
        distrust_from: Option<u64>,
    },
    /// A revocation asked for and not carried out, which a backup, a copy or this install's
    /// records show: it is removed, distrusted from `distrust_from` when one was picked.
    RevocationPending {
        /// The earliest time picked to distrust it from, in Unix milliseconds.
        distrust_from: Option<u64>,
    },
    /// No copy of its certificate was found: it is revoked, and approved again under a new
    /// key.
    CertificateNotFound,
}

/// What the signer backup on the Homeserver holds, for a recovery with the key alone.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum BackupFound {
    /// None.
    Missing,
    /// One that doesn't open or verify.
    Unreadable,
    /// One that opens and holds `version`, which the service's copy doesn't match, or, for a
    /// provider loss, any that opens: its certificates, revoked App IDs and picked times
    /// count.
    Stale {
        /// The version it holds.
        version: u64,
    },
    /// One the service's copy matches: the restore takes it, and loses nothing.
    Matches,
}

/// The user's confirmation of a recovery with the identity key alone, bound to the whole
/// survey they were shown, with the listed apps they chose to drop (Switch spec 12.8). This
/// is the host's attestation, not verification that a user interface was shown.
#[derive(Clone, Debug)]
pub struct KeyRecoveryConfirmed {
    digest: [u8; 32],
    dropped: Vec<[u8; 16]>,
    /// The service a provider loss goes to, which the user picked.
    to: Option<String>,
    /// What the provider loss's survey read.
    shown: Option<Carried>,
    /// The origin the user gave for the survey, if they gave one.
    asked: Option<String>,
}

impl KeyRecoveryConfirmed {
    /// Whether it confirms a provider loss, which only
    /// [`Signer::declare_provider_loss_with_key`] carries out.
    pub(super) fn is_provider_loss(&self) -> bool {
        self.to.is_some()
    }

    /// Made by the host only after showing `survey` and what it loses, with `dropped` the
    /// apps of the survey the user chose to revoke too.
    #[must_use]
    pub fn shown_and_confirmed(survey: &KeyRecoverySurvey, dropped: &[[u8; 16]]) -> Self {
        Self {
            digest: survey.digest,
            shown: survey.carried.clone(),
            dropped: dropped.to_vec(),
            to: match survey.kind {
                KeyRecoveryKind::AtService => None,
                KeyRecoveryKind::ProviderLoss { .. } => Some(survey.origin.clone()),
            },
            asked: survey.origin_supplied.then(|| survey.origin.clone()),
        }
    }
}

/// What the user confirmed for a restore: the restore from the backup ([`UserConfirmed`]),
/// or, should the backup be missing, unreadable or stale, a recovery with the key alone
/// ([`KeyRecoveryConfirmed`]).
#[derive(Clone, Debug)]
pub struct RestoreConfirmed(pub(super) Option<KeyRecoveryConfirmed>);

impl From<UserConfirmed> for RestoreConfirmed {
    fn from(_: UserConfirmed) -> Self {
        Self(None)
    }
}

impl From<KeyRecoveryConfirmed> for RestoreConfirmed {
    fn from(confirmed: KeyRecoveryConfirmed) -> Self {
        Self(Some(confirmed))
    }
}

/// Where a recovery with the key alone starts: on this install's own records, or on a store
/// that holds none or unusable ones, whose readable floors and revocations it keeps.
pub(super) enum Found {
    InPlace,
    Fresh(Option<Box<RestoreLocal>>),
}

/// Where the records a recovery with the key alone starts from are until its version is
/// signed: committed for it on a store that held none, this install's own, or, over unusable
/// records, only in memory.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Held {
    Fresh,
    InPlace,
    Unusable,
}

/// The identity's two published files. A valid backup's exact bytes can bind a user's choice.
struct PublishedCopies {
    opened: Option<Option<BackupView>>,
    backup_hash: Option<[u8; 32]>,
    published: Option<IdentityDoc>,
}

/// A survey, with what the recovery signs on.
struct KeyPlan {
    survey: KeyRecoverySurvey,
    observation: AccountObservation,
    created: u64,
    copy: IdentityDoc,
    answer: AppsAnswer,
    view: BackupView,
}

/// What becomes of each listed app, and what a recovery takes (the module's doc).
struct Fates {
    apps: Vec<([u8; 16], AppFate)>,
    renewals_dropped: Vec<[u8; 16]>,
    certs_dropped: Vec<[u8; 32]>,
    revoked: Vec<[u8; 16]>,
    picked: Vec<RemovedApp>,
    /// For apps the copy removes, the earlier times picked than its `removed` entries'.
    earlier: Vec<RemovedApp>,
    certs: Vec<AppCert>,
    not_found: Vec<[u8; 16]>,
}

impl Fates {
    /// For a provider loss: the apps a service read shows revoked or departed are revoked
    /// at the new service, which doesn't know, distrusted from the earliest of a picked time
    /// and the time `answer` shows.
    fn removed_elsewhere(&mut self, answer: &AppsAnswer) {
        for (app_id, fate) in &mut self.apps {
            let AppFate::RemovedAtSwitch { distrust_from } = fate else {
                continue;
            };
            let at_switch = answer
                .apps
                .iter()
                .filter(|status| status.app_id == *app_id)
                .flat_map(|status| status.revoked_at.into_iter().chain(status.departed_at))
                .min();
            let earliest = match (*distrust_from, at_switch) {
                (Some(picked), Some(shown)) => Some(picked.min(shown)),
                (picked, shown) => picked.or(shown),
            };
            *distrust_from = earliest;
            self.revoked.push(*app_id);
            if let Some(time) = earliest {
                self.picked.retain(|p| p.app_id != *app_id);
                self.picked.push(RemovedApp {
                    app_id: *app_id,
                    distrust_from: time,
                });
            }
        }
        self.revoked.sort_unstable();
        self.revoked.dedup();
    }

    /// The records a recovery takes on `copy`, as a backup would hold them, with `created`
    /// the account creation and `limits` its limits: every App ID revoked for good, a listed
    /// app whose certificate wasn't found among them.
    fn view(&self, copy: &IdentityDoc, created: u64, limits: Limits) -> BackupView {
        let mut revoked_apps = self.revoked.clone();
        revoked_apps.extend(&self.not_found);
        BackupView {
            identity_doc: copy.clone(),
            account_created: created,
            revoked_apps,
            certs: self.certs.clone(),
            limits,
            bundle_parts: Vec::new(),
            prev: None,
            pending_distrust: self.picked.clone(),
        }
    }
}

impl KeyRecoverySurvey {
    /// The survey of a recovery `kind` at `origin` on `copy`, with its digest, with
    /// `observation` the account discovery there and `versions` the highest version seen.
    fn of(
        origin: String,
        copy: &IdentityDoc,
        fates: &Fates,
        backup: BackupFound,
        kind: KeyRecoveryKind,
        observation: &AccountObservation,
        versions: u64,
    ) -> Self {
        let mut survey = Self {
            origin,
            version: copy.version(),
            generation: copy.generation(),
            signer: copy.body().signer,
            apps: fates.apps.clone(),
            renewals_dropped: fates.renewals_dropped.clone(),
            revoked: fates.revoked.clone(),
            backup,
            kind,
            origin_supplied: false,
            service_key: observation.body().service_key,
            identity: copy.body().identity,
            copy: copy.hash(),
            discovery: discovery_of(observation),
            certs_dropped: fates.certs_dropped.clone(),
            earlier: fates.earlier.clone(),
            versions,
            carried: None,
            digest: [0; 32],
        };
        survey.digest = digest_of(&survey);
        survey
    }
}

fn stop(stop: KeyRecoveryStop) -> SignerError {
    Refusal::KeyRecovery(stop).into()
}

impl Signer {
    /// Survey a recovery with the identity key alone, in place (Switch spec 12.8): when the
    /// restore from the backup refuses ([`Refusal::NoBackup`], [`Refusal::UnreadableBackup`],
    /// [`Refusal::StaleBackup`]). It reads, and writes nothing. The user confirms it
    /// ([`KeyRecoveryConfirmed`]) and [`Signer::restore`] carries it out. Beside it, and
    /// wherever it is refused, a provider loss with the key alone is offered
    /// ([`Signer::survey_provider_loss_with_key`]).
    ///
    /// # Errors
    ///
    /// [`Refusal::KeyRecovery`] with the reason it can't go ahead; what [`Signer::restore`]
    /// refuses first (an erased account, a flow in progress, a hand-over or a take-over);
    /// [`SignerError::Alarm`] while an alarm is held; the switch's or the Homeserver's error.
    pub async fn survey_key_recovery(&mut self) -> Result<KeyRecoverySurvey> {
        self.refresh().await?;
        let pending = self
            .flow
            .as_ref()
            .filter(|flow| !matches!(flow, Flow::KeyRecover { .. }));
        check_local_restore(&self.state, pending.is_some_and(Flow::blocks_restore))?;
        let marks = marks_of(&self.state)?;
        let first = self.flow.as_ref().and_then(Flow::first_account_origin);
        let selected = self.first_key_selection()?;
        let origin = selected
            .as_ref()
            .map(|observation| observation.body().origin.as_str());
        Ok(self
            .key_plan(&self.state, &marks, origin, first, selected.as_ref())
            .await?
            .survey)
    }

    /// Until an in-place first restore holds a document, its selected existing enrollment
    /// supplies the original account for a fresh survey (Switch account binding 3).
    fn first_key_selection(&self) -> Result<Option<AccountObservation>> {
        if self.state.before_first_version()
            && let Some(Flow::KeyRecover {
                origin,
                enrollment: RecoveryEnrollment::Ready { observation, .. },
                fresh: false,
                ..
            }) = &self.flow
        {
            return observation
                .verify(&self.state.identity, origin)
                .map(Some)
                .map_err(SignerError::StoredData);
        }
        Ok(None)
    }

    /// Survey a recovery with the identity key alone for a store that holds no records for
    /// the identity, or unusable ones, or such a recovery a crash left (Switch spec 12.8), as
    /// on a new device. It reads, and writes nothing; [`Signer::restore_new`] or
    /// [`Signer::restore_over_unusable`] carries it out.
    ///
    /// # Errors
    ///
    /// [`Refusal::AlreadySetUp`] for usable records, which [`Signer::survey_key_recovery`]
    /// surveys in place; otherwise as [`Signer::survey_key_recovery`].
    pub async fn survey_key_recovery_new(
        env: SignerEnv,
        keyring: IdentityKeyring,
    ) -> Result<KeyRecoverySurvey> {
        Self::survey_new(env, keyring, None).await
    }

    /// [`Signer::survey_key_recovery_new`] at the service at `origin`, which the user gave:
    /// when no copy the identity key signed names the service that serves the account
    /// ([`KeyRecoveryStop::NoCopy`]), or the newest one names a former service
    /// ([`KeyRecoveryStop::NotServing`]), as after the user changed Homeserver or moved. Every
    /// other rule holds: that service's copy verifies and names `origin` and the key that
    /// signed its answers, and nothing the install reads shows a newer one. The survey shows
    /// the origin as the user's ([`KeyRecoverySurvey::origin_supplied`]).
    ///
    /// # Errors
    ///
    /// As [`Signer::survey_key_recovery_new`].
    pub async fn survey_key_recovery_new_at(
        env: SignerEnv,
        keyring: IdentityKeyring,
        origin: &str,
    ) -> Result<KeyRecoverySurvey> {
        let mut survey = Self::survey_new(env, keyring, Some(origin)).await?;
        survey.origin_supplied = true;
        Ok(survey)
    }

    /// [`Signer::survey_key_recovery_new`], at `asked` when the user gave an origin.
    async fn survey_new(
        env: SignerEnv,
        keyring: IdentityKeyring,
        asked: Option<&str>,
    ) -> Result<KeyRecoverySurvey> {
        let identity = keyring.public_key();
        let store = env
            .store
            .acquire(&state::signer_namespace(&identity))
            .await?;
        let mut first = None;
        let (kept, marks, origin) = match state::load(&store, &identity).await {
            Ok(None) => (None, Vec::new(), None),
            Ok(Some((
                state,
                Some(Flow::KeyRecover {
                    fresh: true,
                    origin,
                    ..
                }),
            ))) => (Some(state), Vec::new(), Some(origin)),
            Ok(Some(_)) => return Err(Refusal::AlreadySetUp.into()),
            Err(_) => {
                let mut local =
                    RestoreLocal::unusable(state::read(&store, &identity).await?, &identity)?;
                first = local.first_account_origin.take();
                (
                    Some(fresh_records(identity, [0; 16], Some(&local))),
                    copies_of(&local),
                    None,
                )
            }
        };
        let signer = Self::restore_target(env, keyring, store)?;
        let kept = kept.unwrap_or_else(|| signer.state.clone());
        Ok(signer
            .key_plan(
                &kept,
                &marks,
                asked.or(origin.as_deref()),
                first.as_deref(),
                None,
            )
            .await?
            .survey)
    }

    /// Go on with the recovery with the key alone a crash left on a store that held no
    /// records, under the user's confirmation `confirmed`.
    pub(super) async fn continue_fresh(
        env: SignerEnv,
        keyring: IdentityKeyring,
        store: OwnedStoreHandle,
        confirmed: KeyRecoveryConfirmed,
    ) -> Result<Self> {
        let identity = keyring.public_key();
        let fresh = matches!(
            state::load(&store, &identity).await?,
            Some((_, Some(Flow::KeyRecover { fresh: true, .. })))
        );
        if !fresh {
            return Err(Refusal::AlreadySetUp.into());
        }
        let mut signer = Self::open_owned(env, keyring, store).await?;
        Box::pin(signer.continue_key_recovery(confirmed)).await?;
        Ok(signer)
    }

    /// Go on with the recovery with the key alone in progress, now under `confirmed`.
    pub(super) async fn continue_key_recovery(
        &mut self,
        confirmed: KeyRecoveryConfirmed,
    ) -> Result<IdentityDoc> {
        let Some(Flow::KeyRecover {
            origin,
            enrollment,
            fresh,
            step,
            ..
        }) = self.flow.clone()
        else {
            return Err(Refusal::FlowInProgress.into());
        };
        let flow = Flow::KeyRecover {
            origin,
            enrollment,
            step,
            digest: confirmed.digest,
            dropped: confirmed.dropped,
            fresh,
        };
        self.commit(self.state.clone(), Some(flow)).await?;
        self.finish_key_recovery().await
    }

    /// Start a recovery with the key alone from `found`, under `confirmed`: the survey read
    /// again must be the one confirmed; then the `existing` enrollment is signed. On this
    /// install's records, or a store that held none, it is committed with the records it
    /// starts from before anything is sent. Over unusable records nothing is written before
    /// the recovery's own commit: a refusal or a crash leaves them as found.
    pub(super) async fn recover_with_key(
        &mut self,
        found: Found,
        confirmed: KeyRecoveryConfirmed,
    ) -> Result<IdentityDoc> {
        let (kept, marks, held) = match found {
            Found::InPlace => (self.state.clone(), marks_of(&self.state)?, Held::InPlace),
            Found::Fresh(None) => (self.state.clone(), Vec::new(), Held::Fresh),
            Found::Fresh(Some(local)) => (
                fresh_records(self.state.identity, self.state.install, Some(&local)),
                copies_of(&local),
                Held::Unusable,
            ),
        };
        let plan = self
            .key_plan(&kept, &marks, confirmed.asked.as_deref(), None, None)
            .await?;
        self.start_key_recovery(kept, &marks, held, plan, confirmed)
            .await
    }

    async fn start_key_recovery(
        &mut self,
        kept: SignerState,
        marks: &[IdentityDoc],
        held: Held,
        plan: KeyPlan,
        confirmed: KeyRecoveryConfirmed,
    ) -> Result<IdentityDoc> {
        if plan.survey.digest != confirmed.digest {
            return Err(stop(KeyRecoveryStop::SurveyChanged));
        }
        let identity = self.state.identity;
        let origin = plan.survey.origin;
        let signed = {
            let key = gate::key_recovery_key(&self.keyring, &self.store)?;
            Enrollment::sign(
                &key,
                EnrollmentBody {
                    identity,
                    origin: origin.clone(),
                    nonce: random_bytes()?,
                    intent: plan.observation.enrollment_intent()?,
                    policy: plan.copy.body().policy,
                    identity_doc: None,
                    revoked_apps: None,
                },
            )?
        };
        let enrollment = RecoveryEnrollment::Ready {
            observation: plan.observation.carried().clone(),
            enrollment: signed.signed().clone(),
        };
        if held == Held::Unusable {
            self.state = kept;
            Box::pin(self.key_recover(
                &origin,
                &enrollment,
                confirmed.digest,
                &confirmed.dropped,
                held,
                marks,
            ))
            .await?;
        } else {
            let flow = Flow::KeyRecover {
                origin,
                enrollment,
                step: KeyEnrollmentStep::Unsent,
                digest: confirmed.digest,
                dropped: confirmed.dropped,
                fresh: held == Held::Fresh,
            };
            self.commit(kept, Some(flow)).await?;
        }
        self.finish_key_recovery().await
    }

    /// Run the recovery to its version's delivery, its owed backup and publication, and the
    /// version that removes the apps it revokes, those whose certificate wasn't found among
    /// them. Returns the newest version.
    async fn finish_key_recovery(&mut self) -> Result<IdentityDoc> {
        Box::pin(self.resume()).await?;
        Box::pin(self.complete_removals()).await?;
        self.state
            .newest_doc()?
            .ok_or_else(|| RecordsFault::Invariant("the recovery's version is gone").into())
    }

    /// Send the same signed `existing` enrollment and read the survey again using the
    /// verified local copies in `marks` (Switch spec 12.8). If the survey still matches
    /// the confirmation, commit the version naming this install, built on the service's
    /// copy. A definite refusal before that commit ends the recovery as
    /// [`Signer::end_key_recovery`] says.
    pub(super) async fn key_recover(
        &mut self,
        origin: &str,
        enrollment: &RecoveryEnrollment,
        digest: [u8; 32],
        dropped: &[[u8; 16]],
        held: Held,
        marks: &[IdentityDoc],
    ) -> Result<()> {
        let (observed, signed) = enrollment.existing(&self.state.identity, origin)?;
        let answer = match self.key_enrollment_answer(&observed, &signed, held).await {
            Ok(answer) => answer,
            Err(SignerError::Switch(error))
                if held == Held::Unusable && !matches!(error, ClientError::Transport(_)) =>
            {
                return Err(stop(KeyRecoveryStop::NotServing));
            }
            Err(SignerError::Switch(error)) if error.is_not_hosted() => {
                let target = Target {
                    origin,
                    pinned: Some(observed.body().service_key),
                    created: None,
                    identity: self.state.identity,
                };
                let current = RequestClient::new(&self.env, &target, &self.keyring, &self.store)?
                    .observe_account()
                    .await?;
                // A zero mark can also answer not hosted. Only a later completed erasure
                // of the selected lifetime ends its pending retry (Switch account binding 2–3).
                let ended = current.body().store_id == observed.body().store_id
                    && current.body().erased_at > observed.body().erased_at
                    && current.body().erased_at >= observed.body().created;
                let refused = stop(KeyRecoveryStop::NotServing);
                return Err(if ended {
                    self.end_key_recovery(held, refused).await
                } else {
                    refused
                });
            }
            Err(error) => return Err(error),
        };
        // A newer user survey may change the app selection. The existing enrollment
        // and its saved answer still belong to the original service, store and creation.
        let planned = self
            .key_plan(&self.state, marks, Some(origin), None, Some(&observed))
            .await;
        let first = held == Held::InPlace && self.state.before_first_version();
        let built = match planned {
            Ok(plan) if plan.survey.digest == digest => {
                self.recovered_records(origin, plan, &answer, dropped)
            }
            Ok(_) => Err(stop(KeyRecoveryStop::SurveyChanged)),
            Err(SignerError::Refused(Refusal::FirstEnrollmentUnavailable)) if !first => {
                Err(stop(KeyRecoveryStop::SurveyChanged))
            }
            Err(error) => Err(error),
        };
        match built {
            Ok((state, flow)) => self.commit(state, Some(flow)).await,
            // A rotated enrollment key can announce its result while the old key still
            // serves the account. Until the survey succeeds it cannot release this retry.
            Err(error @ (SignerError::Refused(_) | SignerError::Alarm(_)))
                if answer.service_key == observed.body().service_key =>
            {
                Err(self.end_key_recovery(held, error).await)
            }
            Err(error) => Err(error),
        }
    }

    /// The records a recovery with the key alone rebuilt from `plan`, with the limits
    /// `answer` gave and the apps the user `dropped` revoked, and the delivery of its
    /// version: the service's copy's content, naming this install, above every version it
    /// signed, built on the copy's hash.
    fn recovered_records(
        &self,
        origin: &str,
        plan: KeyPlan,
        answer: &EnrollmentAnswer,
        dropped: &[[u8; 16]],
    ) -> Result<(SignerState, Flow)> {
        let (service_key, changed) =
            account_key(origin, plan.copy.inbox().service_key, answer.service_key);
        let service = Service {
            origin: origin.to_owned(),
            service_key,
            limits: answer.limits,
            created: plan.created,
        };
        let mut view = plan.view;
        view.limits = answer.limits;
        for app in dropped {
            if plan.copy.listed_cert(app).is_some() && !view.revoked_apps.contains(app) {
                view.revoked_apps.push(*app);
            }
        }
        let local = RestoreLocal::intact(self.state.clone())?;
        let mut state =
            self.rebuilt_records(&view, &plan.answer, service.clone(), Some(&local), true)?;
        if let Some(alert) = changed {
            state.alert(alert);
        }
        state.owes_own_version = false;
        state.newest = Some(Newest {
            account: Some(service.clone()),
            doc: plan.copy.signed().clone(),
            prev: None,
            published: false,
            delivered_at: None,
        });
        // No content is added, so the plain cap: the copy was measured with the headroom.
        state.earlier_distrust.clone_from(&plan.survey.earlier);
        let body = Self::body_on(&state, &plan.copy, |_| {}, Room::Cap)?;
        let doc = {
            let key = gate::signing_key(&self.keyring, &state, &self.store)?;
            IdentityDoc::sign(&key, body)?
        };
        state.signed_through = doc.version();
        // It races any other install, so its backup is written once it has won (Switch wire
        // 3.13 "When it is written").
        state.backup_owed = true;
        let flow = Flow::Deliver {
            account: service,
            doc: doc.signed().clone(),
            prev: Some(plan.copy.hash()),
            backup: None,
            step: DeliverStep::BackupWritten,
        };
        Ok((state, flow))
    }

    /// End a recovery with the key alone refused before its version was signed, with
    /// `refused`: records made for it on a store that held none are deleted, and this signer
    /// reads as not set up from then on. In place the records stay as they were. Until this
    /// install has its first version, it retains the selected enrollment for another survey.
    /// Over unusable records, nothing was written.
    async fn end_key_recovery(&mut self, held: Held, refused: SignerError) -> SignerError {
        // Until the first version, retain the original selection for another survey.
        if held == Held::InPlace && self.state.before_first_version() {
            return refused;
        }
        let ended = self.clear_key_recovery(held).await;
        ended.err().unwrap_or(refused)
    }

    /// Read the survey of a recovery with the key alone (the module's doc), with `kept` the
    /// records it starts from, `marks` the copies they hold, and `asked` the service a
    /// recovery in progress chose already. A verified first setup origin is a fallback only
    /// when no signed copy names a service.
    async fn key_plan(
        &self,
        kept: &SignerState,
        marks: &[IdentityDoc],
        asked: Option<&str>,
        first_account_origin: Option<&str>,
        selected: Option<&AccountObservation>,
    ) -> Result<KeyPlan> {
        if let Some(alarm) = gate::held_alarm(kept) {
            return Err(SignerError::Alarm(alarm.clone()));
        }
        let sources = self.read_published().await?;
        self.key_plan_from(kept, marks, asked, first_account_origin, &sources, selected)
            .await
    }

    async fn key_plan_from(
        &self,
        kept: &SignerState,
        marks: &[IdentityDoc],
        asked: Option<&str>,
        first_account_origin: Option<&str>,
        sources: &PublishedCopies,
        original: Option<&AccountObservation>,
    ) -> Result<KeyPlan> {
        let identity = self.state.identity;
        let PublishedCopies {
            opened, published, ..
        } = sources;
        let backed_up = opened.as_ref().and_then(Option::as_ref);
        // Rule 1: the service the newest copy names, which must serve the account.
        let seen: Vec<&IdentityDoc> = published
            .iter()
            .chain(backed_up.map(|view| &view.identity_doc))
            .chain(marks)
            .collect();
        let newest = seen
            .iter()
            .max_by_key(|doc| (doc.generation(), doc.version()));
        let (origin, from_setup) = match (asked, newest, first_account_origin) {
            (Some(origin), _, _) => (origin.to_owned(), false),
            (None, Some(doc), _) => (doc.inbox().url.clone(), false),
            // The user gave this origin for setup. As for any supplied origin, the
            // service must show the identity's signed history before confirmation.
            (None, None, Some(origin)) => (origin.to_owned(), true),
            _ => return Err(stop(KeyRecoveryStop::NoCopy)),
        };
        let target = Target {
            origin: &origin,
            pinned: original.map(|old| old.body().service_key),
            created: None,
            identity,
        };
        let observation = match RequestClient::new(&self.env, &target, &self.keyring, &self.store)?
            .observe_account()
            .await
        {
            Ok(observation) => observation,
            Err(error @ ClientError::Transport(_)) => return Err(error.into()),
            Err(_) => return Err(stop(KeyRecoveryStop::NotServing)),
        };
        let body = observation.body();
        let (AccountAssociation::Account, Some(created)) = (body.association, body.created) else {
            return Err(stop(KeyRecoveryStop::NotServing));
        };
        if let Some(original) = original {
            let old = original.body();
            let matches = match old.association {
                AccountAssociation::Absent => old.erased_at.is_none(),
                AccountAssociation::Account => old.created == body.created,
                AccountAssociation::Mark => false,
            };
            if !matches || body.store_id != old.store_id || body.erased_at != old.erased_at {
                return Err(Refusal::FirstEnrollmentUnavailable.into());
            }
        }
        let key = body.service_key;
        let target = Target {
            origin: &origin,
            pinned: Some(key),
            created: Some(created),
            identity,
        };
        let answer = match RequestClient::new(&self.env, &target, &self.keyring, &self.store)?
            .apps()
            .await
        {
            Ok(answer) => answer,
            Err(error @ ClientError::Transport(_)) => return Err(error.into()),
            Err(ClientError::Switch { .. }) => return Err(stop(KeyRecoveryStop::NotServing)),
            Err(_) => return Err(stop(KeyRecoveryStop::SwitchCopy)),
        };
        // Rule 2: the copy verifies, at that origin, under the key that signed the answers.
        let copy = answer
            .identity
            .as_ref()
            .and_then(|signed| IdentityDoc::verify(signed, &identity).ok())
            .filter(|copy| copy.inbox().url == origin && copy.inbox().service_key == key)
            .ok_or_else(|| stop(KeyRecoveryStop::SwitchCopy))?;
        // The recovery signs the copy's content from the members this signer reads: a copy
        // that carries others, signed by a later signer, would lose them.
        if carries_unknown_members(&copy)? {
            return Err(stop(KeyRecoveryStop::UnknownMembers));
        }
        let backup = match opened {
            None => BackupFound::Missing,
            Some(None) => BackupFound::Unreadable,
            Some(Some(view))
                if view.identity_doc.hash() == copy.hash() || view.prev == Some(copy.hash()) =>
            {
                BackupFound::Matches
            }
            Some(Some(view)) => BackupFound::Stale {
                version: view.identity_doc.version(),
            },
        };
        // Rule 3: nothing newer than the copy was seen; a backup one version ahead of it is
        // the restore's to deliver, and loses nothing.
        let behind = |seen_version: u64| {
            stop(KeyRecoveryStop::ServiceBehind {
                switch_version: copy.version(),
                seen_version,
            })
        };
        for seen in published.iter().chain(marks) {
            let above = seen.generation() > copy.generation()
                || seen.version() > copy.version()
                || (seen.version() == copy.version() && seen.body_hash() != copy.body_hash());
            if above {
                return Err(behind(seen.version()));
            }
        }
        if let Some(view) = backed_up.filter(|_| backup != BackupFound::Matches)
            && (view.identity_doc.version() > copy.version()
                || view.identity_doc.generation() > copy.generation())
        {
            return Err(behind(view.identity_doc.version()));
        }
        if let Some(seen) = kept.records_behind.filter(|seen| *seen > copy.version()) {
            return Err(behind(seen));
        }
        if kept.epoch_through > copy.data_epoch().saturating_add(1) {
            return Err(behind(kept.signed_through));
        }
        let docs: Vec<&IdentityDoc> = std::iter::once(&copy).chain(seen.iter().copied()).collect();
        let kind = KeyRecoveryKind::AtService;
        let fates = self
            .fates(&copy, &docs, backed_up, kept, &answer, kind)
            .await?;
        let mut survey = KeyRecoverySurvey::of(
            origin,
            &copy,
            &fates,
            backup,
            kind,
            &observation,
            copy.version(),
        );
        survey.origin_supplied = from_setup;
        let view = fates.view(&copy, created, Limits::default());
        Ok(KeyPlan {
            survey,
            observation,
            created,
            copy,
            answer,
            view,
        })
    }

    /// The signer backup on the Homeserver, `Some(None)` for one that doesn't open, and the
    /// Homeserver's `identity.json` where the identity key signed it.
    async fn read_published(&self) -> Result<PublishedCopies> {
        let identity = self.state.identity;
        let homeserver = &self.env.homeserver;
        let (opened, backup_hash) = match homeserver
            .get(SIGNER_BACKUP_PATH)
            .await
            .map_err(SignerError::Homeserver)?
        {
            None => (None, None),
            Some(bytes) => {
                let view = self.open_backup(&bytes)?;
                let digest = view.as_ref().map(|_| hash(&bytes));
                (Some(view), digest)
            }
        };
        let published = homeserver
            .get(IDENTITY_PATH)
            .await
            .map_err(SignerError::Homeserver)?
            .and_then(|bytes| serde_json::from_slice::<SignedDoc>(&bytes).ok())
            .and_then(|signed| IdentityDoc::verify(&signed, &identity).ok());
        Ok(PublishedCopies {
            opened,
            backup_hash,
            published,
        })
    }

    /// What becomes of each app `copy` lists, and what the recovery takes, with `docs` every
    /// copy seen, `backed_up` the backup that opened, `kept` the records it starts from and
    /// `answer` the switch's `GET /apps` (the module's doc).
    async fn fates(
        &self,
        copy: &IdentityDoc,
        docs: &[&IdentityDoc],
        backed_up: Option<&BackupView>,
        kept: &SignerState,
        answer: &AppsAnswer,
        kind: KeyRecoveryKind,
    ) -> Result<Fates> {
        let certs = self.found_certs(copy, backed_up, kept).await?;
        let held = |cert: &[u8; 32]| certs.iter().any(|found| &found.hash() == cert);
        let (revoked, picked) = revoked_for_good(copy, docs, backed_up, kept, answer, kind)?;
        let mut apps = Vec::new();
        let mut not_found = Vec::new();
        for listed in &copy.body().apps {
            let at_switch = answer.apps.iter().any(|status| {
                status.app_id == listed.app_id
                    && (status.revoked_at.is_some() || status.departed_at.is_some())
            });
            let distrust_from = picked
                .iter()
                .find(|p| p.app_id == listed.app_id)
                .map(|p| p.distrust_from);
            let fate = if at_switch {
                AppFate::RemovedAtSwitch { distrust_from }
            } else if revoked.contains(&listed.app_id) {
                AppFate::RevocationPending { distrust_from }
            } else if !held(&listed.cert) {
                not_found.push(listed.app_id);
                AppFate::CertificateNotFound
            } else {
                AppFate::Stays
            };
            apps.push((listed.app_id, fate));
        }
        let mut certs_dropped: Vec<[u8; 32]> = copy
            .body()
            .renewed
            .iter()
            .filter(|entry| !held(&entry.cert))
            .map(|entry| entry.cert)
            .collect();
        certs_dropped.sort_unstable();
        let mut renewals_dropped: Vec<[u8; 16]> = copy
            .body()
            .renewed
            .iter()
            .filter(|entry| !held(&entry.cert))
            .map(|entry| entry.app_id)
            .collect();
        renewals_dropped.dedup();
        Ok(Fates {
            apps,
            renewals_dropped,
            certs_dropped,
            revoked,
            earlier: picked
                .iter()
                .filter(|p| {
                    copy.body()
                        .removed
                        .iter()
                        .any(|r| r.app_id == p.app_id && p.distrust_from < r.distrust_from)
                })
                .copied()
                .collect(),
            picked,
            certs,
            not_found,
        })
    }

    /// The certificates the key verifies, from the backup `backed_up` of any age, the records
    /// `kept`, and the own record on the Homeserver of each app `copy` lists whose certificate
    /// isn't among them.
    async fn found_certs(
        &self,
        copy: &IdentityDoc,
        backed_up: Option<&BackupView>,
        kept: &SignerState,
    ) -> Result<Vec<AppCert>> {
        let identity = self.state.identity;
        let mut certs: Vec<AppCert> = backed_up.map(|view| view.certs.clone()).unwrap_or_default();
        certs.extend(
            kept.certs
                .iter()
                .filter_map(|cert| AppCert::verify(cert, &identity).ok()),
        );
        for listed in &copy.body().apps {
            if certs.iter().any(|cert| cert.hash() == listed.cert) {
                continue;
            }
            let record = self
                .env
                .homeserver
                .get(&app_record_path(&listed.app_id))
                .await
                .map_err(SignerError::Homeserver)?
                .and_then(|bytes| serde_json::from_slice::<SignedDoc>(&bytes).ok())
                .and_then(|signed| AppRecord::verify(&signed, &identity).ok());
            // A record carrying another certificate counts for nothing: the copy names this one.
            if let Some(record) = record {
                certs.push(record.cert().clone());
            }
        }
        // Each once: the backup and the records hold most of the same.
        let mut held: Vec<AppCert> = Vec::new();
        for cert in certs {
            if !held.iter().any(|kept| kept.hash() == cert.hash()) {
                held.push(cert);
            }
        }
        Ok(held)
    }
}

/// What a store holds for the identity, whatever its state, for a provider loss with the key
/// alone (Switch spec 12.8): the records it starts from, what binds them, the copies they
/// hold, and the generation a recovery they declared sent a start for.
pub(super) struct LossFound {
    kept: SignerState,
    uncertain_origin: Option<String>,
    required_exclusions: BTreeSet<[u8; 16]>,
    /// A backup a delivery in flight sealed, as the store's flow holds it.
    sealed: Option<Vec<u8>>,
    local: RestoreLocal,
    marks: Vec<IdentityDoc>,
    generations: u64,
}

/// [`LossFound`] from what the store read, `records`: a state that decodes counts whatever it
/// says, and so does a version a flow that decodes signed; nothing else is kept. A new
/// install's records, `install`, when no state decodes.
fn loss_found(records: state::ReadRecords, identity: [u8; 32], install: [u8; 16]) -> LossFound {
    let state = records.state.ok().flatten();
    let flow = records.flow.ok().flatten();
    let mut local = RestoreLocal::from_state(state.clone(), &identity);
    let mut marks = copies_of(&local);
    // A version a flow signed may have reached a service, and spent its version and epoch.
    let signed = match &flow {
        Some(Flow::RecoveryDelivery(action)) => Some(&action.doc),
        Some(Flow::Renew { doc, .. } | Flow::Deliver { doc, .. }) => Some(doc),
        Some(Flow::TakingOver { delivery, .. }) => delivery.as_ref().map(|d| &d.doc),
        _ => None,
    };
    // The backup a delivery sealed, and the App IDs a declared recovery's enrollment names
    // revoked, count as the records' own, whether the state decodes or not.
    let sealed = match &flow {
        Some(Flow::Deliver {
            backup: Some(backup),
            ..
        }) => serde_json::to_vec(backup).ok(),
        _ => None,
    };
    let mut required_exclusions = BTreeSet::new();
    let mut uncertain_origin = state.as_ref().and_then(|kept| {
        kept.recovery_commit?;
        required_exclusions.extend(kept.tombstones.iter().copied());
        kept.recovery_origin.clone()
    });
    let enrolled_revoked: Vec<[u8; 16]> = match &flow {
        Some(Flow::RecoveryDelivery(action)) => {
            uncertain_origin = Some(action.origin.clone());
            let revoked = Enrollment::verify(&action.enrollment, &identity, &action.origin)
                .map(|signed| signed.revoked_apps().to_vec())
                .unwrap_or_default();
            required_exclusions.extend(revoked.iter().copied());
            revoked
        }
        Some(Flow::Recover {
            origin,
            enrollment: RecoveryEnrollment::Ready { enrollment, .. },
        }) => Enrollment::verify(enrollment, &identity, origin)
            .map(|signed| signed.revoked_apps().to_vec())
            .unwrap_or_default(),
        Some(Flow::Recover {
            enrollment: RecoveryEnrollment::Preparing { revoked_apps, .. },
            ..
        }) => revoked_apps.clone(),
        _ => Vec::new(),
    };
    if let Some(doc) = signed.and_then(|signed| state::stored_identity(signed, &identity).ok()) {
        local.signed_through = Some(local.signed_through.unwrap_or(0).max(doc.version()));
        local.epoch_through = Some(local.epoch_through.unwrap_or(0).max(doc.data_epoch()));
        marks.push(doc);
    }
    let mut kept = state.unwrap_or_else(|| SignerState::new(identity, install));
    for app in enrolled_revoked {
        if !kept.tombstones.contains(&app) {
            kept.tombstones.push(app);
        }
    }
    kept.signed_through = local
        .signed_through
        .unwrap_or(0)
        .max(kept.records_behind.unwrap_or(0));
    kept.epoch_through = local.epoch_through.unwrap_or(0);
    // A hand-over in progress lets its target sign the next version, which nothing may show.
    if let Some(handed) = kept
        .handing_over
        .as_ref()
        .and_then(|h| state::stored_identity(&h.doc, &identity).ok())
    {
        kept.signed_through = kept.signed_through.max(handed.version().saturating_add(1));
    }
    // A recovery declared already may have sent a start for the generation after the lost
    // one, and the records may have seen a version of their own at a higher one.
    let generations = kept
        .lost_generation
        .filter(|_| kept.recovering)
        .map_or(0, |lost| lost.saturating_add(1))
        .max(kept.generation_seen);
    LossFound {
        kept,
        uncertain_origin,
        required_exclusions,
        sealed,
        local,
        marks,
        generations,
    }
}

/// Of the App IDs `revoked` (ascending), those a move's enrollment carrying `base` could
/// carry within seven eighths of its cap, with the headroom every version keeps (Switch wire
/// 3.7, 7.1). Revoked apps `base` lists or removes and the exclusions of an uncertain
/// signed recovery enrollment always stay. When
/// more were found than fit, as when disjoint sources each hold many, the others, revoked
/// apps no version lists or removes any more, go: the same loss as when no source holds
/// them, and no recovery is ever refused for their number (Switch spec 12.8).
fn enrollable(
    base: Option<&IdentityDoc>,
    revoked: Vec<[u8; 16]>,
    required: &BTreeSet<[u8; 16]>,
) -> Result<Vec<[u8; 16]>> {
    let Some(limit) = enrollment_limit() else {
        return Ok(revoked);
    };
    let named = |app: &[u8; 16]| {
        required.contains(app)
            || base.is_some_and(|base| {
                base.listed_cert(app).is_some()
                    || base.body().removed.iter().any(|r| &r.app_id == app)
            })
    };
    let (kept, rest): (Vec<[u8; 16]>, Vec<[u8; 16]>) = revoked.into_iter().partition(named);
    let policy = base.map_or_else(IdentityPolicy::default, |base| base.body().policy);
    let fits = |taken: usize| -> Result<bool> {
        let ids: Vec<[u8; 16]> = kept.iter().chain(&rest[..taken]).copied().collect();
        let bytes = Enrollment::max_request_len(&policy, base.map(IdentityDoc::signed), &ids)?;
        // An eighth of the cap stays free for the content the identity adds later.
        Ok(bytes.saturating_add(CAP_HEADROOM) <= limit - limit / 8)
    };
    let (mut fitting, mut over) = (0, rest.len());
    if !fits(over)? {
        while over - fitting > 1 {
            let middle = fitting + (over - fitting) / 2;
            if fits(middle)? {
                fitting = middle;
            } else {
                over = middle;
            }
        }
    } else {
        fitting = over;
    }
    let mut taken: Vec<[u8; 16]> = kept
        .into_iter()
        .chain(rest.into_iter().take(fitting))
        .collect();
    taken.sort_unstable();
    Ok(taken)
}

/// The backup on the Homeserver, `found`, and one the store's flow sealed, `sealed`, as one:
/// the revoked App IDs, the certificates and the picked times of both. The Homeserver's
/// document stands, else the sealed one's.
fn merged_views(found: Option<BackupView>, sealed: Option<BackupView>) -> Option<BackupView> {
    match (found, sealed) {
        (Some(mut view), Some(other)) => {
            for app in other.revoked_apps {
                if !view.revoked_apps.contains(&app) {
                    view.revoked_apps.push(app);
                }
            }
            for cert in other.certs {
                if !view.certs.iter().any(|held| held.hash() == cert.hash()) {
                    view.certs.push(cert);
                }
            }
            view.pending_distrust.extend(other.pending_distrust);
            Some(view)
        }
        (view, other) => view.or(other),
    }
}

/// A provider loss's survey, with what it builds on.
#[derive(Clone, Debug)]
struct LossPlan {
    survey: KeyRecoverySurvey,
    observation: AccountObservation,
    base: Option<IdentityDoc>,
    lost: u64,
    versions: u64,
    answer: AppsAnswer,
    view: Option<BackupView>,
}

impl LossPlan {
    /// This plan, its survey carrying it.
    fn carried(mut self) -> Self {
        self.survey.carried = Some(Carried(std::sync::Arc::new(self.clone())));
        self
    }

    /// The plan the declaration acts on: `shown`, the one the user confirmed, with what this
    /// one, read again at the declaration, adds that doesn't change what the user saw. A
    /// source that shows less now, or none, changes nothing. A copy above the one confirmed,
    /// a revocation or an earlier time not shown, or another key or account at the service
    /// picked is new to the user, and refused (Switch spec 12.8).
    fn settle(self, shown: &Self) -> Result<Self> {
        let changed = || stop(KeyRecoveryStop::SurveyChanged);
        let (now, then) = (&self.survey, &shown.survey);
        if now.identity != then.identity
            || now.origin != then.origin
            || now.service_key != then.service_key
            || now.discovery != then.discovery
        {
            return Err(changed());
        }
        match (&shown.base, &self.base) {
            (_, None) => {}
            (None, Some(_)) => return Err(changed()),
            (Some(confirmed), Some(read)) => {
                if read.hash() != confirmed.hash()
                    && (read.generation(), read.version())
                        >= (confirmed.generation(), confirmed.version())
                {
                    return Err(changed());
                }
            }
        }
        if now.revoked.iter().any(|app| !then.revoked.contains(app)) {
            return Err(changed());
        }
        let revoked_from = |fate: &AppFate| match fate {
            AppFate::RemovedAtSwitch { distrust_from }
            | AppFate::RevocationPending { distrust_from } => Some(*distrust_from),
            _ => None,
        };
        for (app, fate) in &now.apps {
            let Some(from_now) = revoked_from(fate) else {
                continue;
            };
            let Some((_, confirmed)) = then.apps.iter().find(|(id, _)| id == app) else {
                continue;
            };
            match revoked_from(confirmed) {
                None => return Err(changed()),
                Some(from_then) => {
                    if from_now.is_some_and(|t| from_then.is_none_or(|c| t < c)) {
                        return Err(changed());
                    }
                }
            }
        }
        for earlier in &now.earlier {
            let known = then
                .earlier
                .iter()
                .any(|e| e.app_id == earlier.app_id && e.distrust_from <= earlier.distrust_from);
            if !known {
                return Err(changed());
            }
        }
        let mut settled = shown.clone();
        settled.survey.carried = None;
        settled.observation = self.observation;
        settled.lost = settled.lost.max(self.lost);
        settled.versions = settled.versions.max(self.versions);
        if let (Some(view), Some(read)) = (&mut settled.view, &self.view) {
            for cert in &read.certs {
                if !view.certs.iter().any(|held| held.hash() == cert.hash()) {
                    view.certs.push(cert.clone());
                }
            }
        }
        settled.answer.apps.extend(self.answer.apps);
        Ok(settled)
    }
}

/// The copy of the highest generation, then version, of `docs`, the first of equals: the
/// ones a service took come first.
fn highest(docs: &[IdentityDoc]) -> Option<&IdentityDoc> {
    docs.iter()
        .fold(None, |best: Option<&IdentityDoc>, doc| match best {
            Some(best)
                if (best.generation(), best.version()) >= (doc.generation(), doc.version()) =>
            {
                Some(best)
            }
            _ => Some(doc),
        })
}

impl Signer {
    /// Survey a provider loss with the identity key alone, at the service at `origin` the
    /// user picked (Switch spec 12.6, 12.8): from whatever the store holds for the identity,
    /// no records, usable ones in any state, or unusable ones, with no [`Signer`] open for it.
    /// It reads, and writes nothing; [`Signer::declare_provider_loss_with_key`] carries it out.
    ///
    /// It builds on the highest copy of `identity.json` the identity key signed that any
    /// source shows: the Homeserver's, one in a backup that opens, the store's records and
    /// the versions its flows signed, and the copy of every service those name, and of the
    /// one picked, where they serve the account. It declares that copy's
    /// generation lost, or a higher one a recovery the records declared sent a start for.
    ///
    /// # Errors
    ///
    /// [`Refusal::KeyRecovery`] with [`KeyRecoveryStop::NotServing`] when the service at
    /// `origin` doesn't answer the account discovery (another service is the way on), or
    /// [`KeyRecoveryStop::UnknownMembers`]; an `origin` that isn't a switch origin; the
    /// switch's, the Homeserver's or the store's error.
    pub async fn survey_provider_loss_with_key(
        env: SignerEnv,
        keyring: IdentityKeyring,
        origin: &str,
    ) -> Result<KeyRecoverySurvey> {
        let (signer, found) = Self::loss_target(env, keyring).await?;
        Ok(signer.loss_plan(&found, origin).await?.survey)
    }

    /// Declare a provider loss with the identity key alone, once the user confirmed its
    /// survey ([`Signer::survey_provider_loss_with_key`]), and recover at the service they
    /// picked (Switch spec 12.6, 12.8). Like the survey, it takes whatever the store holds,
    /// with no [`Signer`] open for the identity: a hand-over, a take-over, an erasure or a
    /// flow in progress, another install named, records behind, an alarm or a recovery
    /// already declared, and records that don't read. Returns the signer, once the
    /// recovery's version is delivered and published.
    ///
    /// Before anything is written, everything is read again. A source that shows less now,
    /// or nothing, changes nothing: the declaration acts on the survey confirmed. A copy above
    /// the one confirmed, a revocation or an earlier time it didn't show, or another key or
    /// account at the service picked is refused. The enrollment at that service is signed.
    /// Then the records it rebuilt and the declaration are committed in one write, and the
    /// provider loss goes on as one declared with [`Signer::declare_provider_loss`]: the
    /// enrollment, whose answer must name the key the discovery showed, the version naming
    /// this install at the next generation, built on the copy the survey showed, above every
    /// version any source or the survey showed or the records spent, and its delivery. Its
    /// backup is written once that delivery has won where the copy names another install,
    /// names a certificate this install doesn't hold, or there is none; before it otherwise.
    ///
    /// # Errors
    ///
    /// [`KeyRecoveryStop::SurveyChanged`] for something the survey didn't show, or when
    /// `confirmed` isn't a provider loss's: survey again; [`Refusal::IdentityTooLarge`] for
    /// a version the cap can't take; otherwise as [`Signer::survey_provider_loss_with_key`].
    /// With nothing written, the store is as found. Once the declaration is committed, as
    /// [`Signer::resume`]: the recovery in progress is resumed, or declared again with this
    /// entry, at that service or another, or with [`Signer::declare_provider_loss`] where it
    /// built on a copy (with no copy anywhere, this entry only).
    pub async fn declare_provider_loss_with_key(
        env: SignerEnv,
        keyring: IdentityKeyring,
        confirmed: KeyRecoveryConfirmed,
    ) -> Result<Self> {
        let Some(to) = confirmed.to.clone() else {
            return Err(stop(KeyRecoveryStop::SurveyChanged));
        };
        let Some(Carried(shown)) = confirmed.shown.clone() else {
            return Err(stop(KeyRecoveryStop::SurveyChanged));
        };
        let (mut signer, found) = Self::loss_target(env, keyring).await?;
        if found.uncertain_origin.as_deref() == Some(&to) {
            let mut signer = Self::open_owned(signer.env, signer.keyring, signer.store).await?;
            let Some(Flow::RecoveryDelivery(action)) = &signer.flow else {
                return Err(Refusal::FlowInProgress.into());
            };
            let original = action.observation.verify(&signer.state.identity, &to)?;
            let selected = shown.observation.body();
            if discovery_of(&original) != discovery_of(&shown.observation)
                || original.body().store_id != selected.store_id
                || original.body().erased_at != selected.erased_at
                || original.body().identity != selected.identity
                || confirmed
                    .dropped
                    .iter()
                    .any(|app| !signer.state.tombstones.contains(app))
            {
                return Err(stop(KeyRecoveryStop::SurveyChanged));
            }
            signer.resume().await?;
            Box::pin(signer.complete_listed_revocations()).await?;
            return Ok(signer);
        }
        let plan = Box::pin(signer.loss_plan(&found, &to))
            .await?
            .settle(&shown)?;
        let identity = signer.state.identity;
        let state = signer.loss_records(&plan, &found, &to, &confirmed.dropped)?;
        // In memory until the commit below: a refusal before it leaves the store as found.
        signer.state = state;
        let until = signer.env.clock.now_ms().saturating_add(CLOCK_TOLERANCE_MS);
        let base = plan.base.as_ref();
        signer.recovery_body(base, plan.lost, &to, [0; 32], until)?;
        let mut revoked: Vec<[u8; 16]> = signer
            .state
            .tombstones
            .iter()
            .copied()
            .filter(|app| base.is_none_or(|base| base.listed_cert(app).is_none()))
            .collect();
        revoked.sort_unstable();
        revoked.dedup();
        let signed = {
            let key = gate::recovery_key(&signer.keyring, &signer.state, &signer.store)?;
            Enrollment::sign(
                &key,
                EnrollmentBody {
                    identity,
                    origin: to.clone(),
                    nonce: random_bytes()?,
                    intent: plan.observation.enrollment_intent()?,
                    policy: base.map_or_else(IdentityPolicy::default, |base| base.body().policy),
                    identity_doc: None,
                    revoked_apps: Some(revoked),
                },
            )?
        };
        let flow = Flow::Recover {
            origin: to,
            enrollment: RecoveryEnrollment::Ready {
                observation: plan.observation.carried().clone(),
                enrollment: signed.signed().clone(),
            },
        };
        signer.commit(signer.state.clone(), Some(flow)).await?;
        Box::pin(signer.resume()).await?;
        Box::pin(signer.complete_listed_revocations()).await?;
        Ok(signer)
    }

    /// The signer of a provider loss with the key alone, on the store it takes over, and
    /// what that store holds ([`loss_found`]).
    async fn loss_target(env: SignerEnv, keyring: IdentityKeyring) -> Result<(Self, LossFound)> {
        let identity = keyring.public_key();
        let store = env
            .store
            .acquire(&state::signer_namespace(&identity))
            .await?;
        let records = state::read(&store, &identity).await?;
        let mut signer = Self::restore_target(env, keyring, store)?;
        let found = loss_found(records, identity, signer.state.install);
        signer.state = found.kept.clone();
        Ok((signer, found))
    }

    /// The account the service at `origin` serves for the identity, its creation and its
    /// `GET /apps` answer; `None` where it serves none or can't be read.
    async fn serving(&self, origin: &str) -> Result<Option<(u64, AppsAnswer)>> {
        if !pubky_switch_core::records::is_origin(origin) {
            return Ok(None);
        }
        let identity = self.state.identity;
        let target = Target {
            origin,
            pinned: None,
            created: None,
            identity,
        };
        let Ok(observation) = RequestClient::new(&self.env, &target, &self.keyring, &self.store)?
            .observe_account()
            .await
        else {
            return Ok(None);
        };
        Ok(self.apps_of(origin, &observation).await?.ok())
    }

    /// The `GET /apps` answer of the account `observation` shows at `origin`, under the key
    /// that signed it, with its creation; `Err` with the switch's error, `Ok(Err(()))` for an
    /// observation of no account.
    async fn apps_of(
        &self,
        origin: &str,
        observation: &AccountObservation,
    ) -> Result<std::result::Result<(u64, AppsAnswer), ClientError>> {
        let body = observation.body();
        let (AccountAssociation::Account, Some(created)) = (body.association, body.created) else {
            return Ok(Err(ClientError::Usage("no account is served".into())));
        };
        let target = Target {
            origin,
            pinned: Some(body.service_key),
            created: Some(created),
            identity: self.state.identity,
        };
        Ok(
            RequestClient::new(&self.env, &target, &self.keyring, &self.store)?
                .apps()
                .await
                .map(|answer| (created, answer)),
        )
    }

    /// Read each service `pending` names that isn't `visited` yet ([`Signer::serving`]),
    /// into `reads`, and the service each copy read names in turn, up to [`MAX_SERVICES`] in
    /// all.
    async fn follow(
        &self,
        pending: &mut std::collections::BTreeSet<String>,
        visited: &mut std::collections::BTreeSet<String>,
        reads: &mut Vec<(u64, AppsAnswer)>,
    ) -> Result<()> {
        let identity = self.state.identity;
        while let Some(origin) = pending.pop_first() {
            if visited.len() > MAX_SERVICES || !visited.insert(origin.clone()) {
                continue;
            }
            if let Some(read) = Box::pin(self.serving(&origin)).await? {
                if let Some(copy) = read
                    .1
                    .identity
                    .as_ref()
                    .and_then(|signed| IdentityDoc::verify(signed, &identity).ok())
                {
                    pending.insert(copy.inbox().url.clone());
                }
                reads.push(read);
            }
        }
        Ok(())
    }

    /// Read a provider loss's survey at `to` (the doc of
    /// [`Signer::survey_provider_loss_with_key`]) over what the store holds, `found`.
    async fn loss_plan(&self, found: &LossFound, to: &str) -> Result<LossPlan> {
        let identity = self.state.identity;
        if !pubky_switch_core::records::is_origin(to) {
            return Err(SignerError::InvalidData(pubky_switch_core::Error::Invalid(
                "Switch wire 3.7: invalid recovery origin".into(),
            )));
        }
        let PublishedCopies {
            opened, published, ..
        } = self.read_published().await?;
        let sealed = match &found.sealed {
            Some(bytes) => self.open_backup(bytes)?,
            None => None,
        };
        let merged = merged_views(opened.clone().flatten(), sealed.clone());
        let backed_up = merged.as_ref();
        let mut held: Vec<IdentityDoc> = published
            .iter()
            .cloned()
            .chain(
                opened
                    .iter()
                    .flatten()
                    .map(|view| view.identity_doc.clone()),
            )
            .chain(sealed.iter().map(|view| view.identity_doc.clone()))
            .chain(found.marks.iter().cloned())
            .collect();
        let copy_of = |answer: &AppsAnswer| {
            answer
                .identity
                .as_ref()
                .and_then(|signed| IdentityDoc::verify(signed, &identity).ok())
        };
        // Every service a copy names, read where it serves the account, and every service
        // the copies those hold name in turn: the Homeserver can't choose which copy counts
        // as the newest by showing an older one naming another service, and a service's
        // newer copy naming the next one is followed there.
        let mut visited = std::collections::BTreeSet::from([to.to_owned()]);
        let mut pending: std::collections::BTreeSet<String> =
            held.iter().map(|doc| doc.inbox().url.clone()).collect();
        let mut reads = Vec::new();
        Box::pin(self.follow(&mut pending, &mut visited, &mut reads)).await?;
        // The service picked, which the enrollment goes to.
        let target = Target {
            origin: to,
            pinned: None,
            created: None,
            identity,
        };
        let observation = match RequestClient::new(&self.env, &target, &self.keyring, &self.store)?
            .observe_account()
            .await
        {
            Ok(observation) => observation,
            Err(error @ ClientError::Transport(_)) => return Err(error.into()),
            Err(_) => return Err(stop(KeyRecoveryStop::NotServing)),
        };
        observation.enrollment_intent()?;
        let picked = match self.apps_of(to, &observation).await? {
            Ok(answer) => Some(answer),
            Err(error @ ClientError::Transport(_)) => return Err(error.into()),
            Err(_) => None,
        };
        if let Some(copy) = picked.as_ref().and_then(|(_, answer)| copy_of(answer)) {
            pending.insert(copy.inbox().url.clone());
            Box::pin(self.follow(&mut pending, &mut visited, &mut reads)).await?;
        }
        reads.extend(picked);
        // Copies a service took come first among equals.
        let mut seen: Vec<IdentityDoc> = reads
            .iter()
            .filter_map(|(_, answer)| copy_of(answer))
            .collect();
        seen.append(&mut held);
        let base = highest(&seen).cloned();
        let versions = seen
            .iter()
            .map(IdentityDoc::version)
            .fold(found.kept.signed_through, u64::max);
        // The answer of the service holding the base, else of the first that answered, with
        // the revocations and departures every service shows: none of them is dropped.
        let holding = reads
            .iter()
            .position(|(_, answer)| {
                copy_of(answer)
                    .is_some_and(|copy| base.as_ref().is_some_and(|b| b.hash() == copy.hash()))
            })
            .unwrap_or(0);
        let (created, mut answer) = if reads.is_empty() {
            (0, no_copy())
        } else {
            reads.swap_remove(holding)
        };
        for (_, other) in reads {
            answer.apps.extend(
                other
                    .apps
                    .into_iter()
                    .filter(|status| status.revoked_at.is_some() || status.departed_at.is_some()),
            );
        }
        let backup = match &opened {
            None => BackupFound::Missing,
            Some(None) => BackupFound::Unreadable,
            Some(Some(view)) => BackupFound::Stale {
                version: view.identity_doc.version(),
            },
        };
        let Some(base) = base else {
            // No copy anywhere: a first document in a provider loss's shape, at a generation
            // (the seconds) and a version (the milliseconds, times a thousand, plus a random
            // part, so two such recoveries in one millisecond don't sign one version twice)
            // from the time, above any a lost install could have reached (Switch spec 12.8).
            let time = no_copy_time(self.env.clock.now_ms(), observation.body().observed_at);
            let spread = u64::from(u16::from_be_bytes(random_bytes()?) % 1_000);
            let floor = time.saturating_mul(1_000).saturating_add(spread);
            let mut revoked = found.kept.tombstones.clone();
            revoked.sort_unstable();
            revoked.dedup();
            let revoked = enrollable(None, revoked, &found.required_exclusions)?;
            let mut survey = KeyRecoverySurvey {
                origin: to.to_owned(),
                version: 0,
                generation: 0,
                signer: [0; 16],
                apps: Vec::new(),
                renewals_dropped: Vec::new(),
                revoked,
                backup,
                kind: KeyRecoveryKind::ProviderLoss { lost: None },
                origin_supplied: false,
                service_key: observation.body().service_key,
                identity,
                copy: [0; 32],
                discovery: discovery_of(&observation),
                certs_dropped: Vec::new(),
                earlier: Vec::new(),
                versions: versions.max(floor),
                carried: None,
                digest: [0; 32],
            };
            survey.digest = digest_of(&survey);
            return Ok(LossPlan {
                survey,
                observation,
                base: None,
                lost: (time / 1_000).max(found.generations),
                versions: versions.max(floor),
                answer,
                view: None,
            }
            .carried());
        };
        // The version signs the members this signer reads, as at the service.
        if carries_unknown_members(&base)? {
            return Err(stop(KeyRecoveryStop::UnknownMembers));
        }
        let lost = base.generation().max(found.generations);
        let kind = KeyRecoveryKind::ProviderLoss { lost: Some(lost) };
        let docs: Vec<&IdentityDoc> = seen.iter().collect();
        let mut fates = self
            .fates(&base, &docs, backed_up, &found.kept, &answer, kind)
            .await?;
        fates.removed_elsewhere(&answer);
        fates.revoked = enrollable(Some(&base), fates.revoked, &found.required_exclusions)?;
        let survey = KeyRecoverySurvey::of(
            to.to_owned(),
            &base,
            &fates,
            backup,
            kind,
            &observation,
            versions,
        );
        let (created, limits) = backed_up.map_or((created, Limits::default()), |view| {
            (view.account_created, view.limits)
        });
        let view = fates.view(&base, created, limits);
        Ok(LossPlan {
            survey,
            observation,
            base: Some(base),
            lost,
            versions,
            answer,
            view: Some(view),
        }
        .carried())
    }

    /// The records a provider loss with the key alone commits from `plan` over what the store
    /// held, `found`, declared to the service at `to`, with the listed apps the user
    /// `dropped` revoked: a recovery in progress, as [`Signer::declare_provider_loss`] leaves
    /// it, built on the plan's copy, which the Homeserver's copy needn't name.
    fn loss_records(
        &self,
        plan: &LossPlan,
        found: &LossFound,
        to: &str,
        dropped: &[[u8; 16]],
    ) -> Result<SignerState> {
        let mut state = match (&plan.base, &plan.view) {
            (Some(base), Some(view)) => {
                let mut view = view.clone();
                for app in dropped {
                    if base.listed_cert(app).is_some() && !view.revoked_apps.contains(app) {
                        view.revoked_apps.push(*app);
                    }
                }
                let service = Service {
                    origin: base.inbox().url.clone(),
                    service_key: base.inbox().service_key,
                    limits: view.limits,
                    created: view.account_created,
                };
                let mut state = self.rebuilt_records(
                    &view,
                    &plan.answer,
                    service.clone(),
                    Some(&found.local),
                    false,
                )?;
                state.newest = Some(Newest {
                    account: Some(service),
                    doc: base.signed().clone(),
                    prev: None,
                    published: false,
                    delivered_at: None,
                });
                state.recovery_base = Some(base.signed().clone());
                state
            }
            _ => {
                let kept = &found.kept;
                let mut state = SignerState::new(kept.identity, kept.install);
                state.alerts = restored_alerts(kept);
                state.tombstones.clone_from(&plan.survey.revoked);
                state.cleanup.clone_from(&kept.cleanup);
                state.deletion_checks = state
                    .tombstones
                    .iter()
                    .copied()
                    .filter(|app| !state.cleanup.contains(app))
                    .collect();
                state
            }
        };
        state.signed_through = state.signed_through.max(plan.versions);
        state.epoch_through = state
            .epoch_through
            .max(found.local.epoch_through.unwrap_or(0));
        state.earlier_distrust.clone_from(&plan.survey.earlier);
        // Only the App IDs the survey kept: the enrollment names them all (Switch wire 3.7).
        let listed = |app: &[u8; 16]| {
            plan.base
                .as_ref()
                .is_some_and(|base| base.listed_cert(app).is_some())
        };
        state
            .tombstones
            .retain(|app| listed(app) || plan.survey.revoked.contains(app));
        state.recovering = true;
        state.lost_generation = Some(plan.lost);
        state.recovery_origin = Some(to.to_owned());
        // The survey the user confirmed read the Homeserver's copy, and took it as one of the
        // copies to build on: a missing or unreadable one is no reason to stop.
        state.homeserver_copy_waived = true;
        Ok(state)
    }
}

/// Whether the body `copy` was signed with carries a member this signer doesn't read, at
/// any depth. Its bytes are never compared with this signer's own encoding: writers may use
/// any member order and whitespace (Switch wire 1.1). A member this signer leaves out when
/// it is absent or empty may be written as `null` or empty; any other name it doesn't
/// read counts, whatever its value.
fn carries_unknown_members(copy: &IdentityDoc) -> Result<bool> {
    let invalid = |error: serde_json::Error| {
        SignerError::InvalidData(pubky_switch_core::Error::Invalid(error.to_string()))
    };
    let signed: serde_json::Value =
        serde_json::from_slice(&copy.signed().body_bytes()?).map_err(invalid)?;
    let read: serde_json::Value =
        serde_json::from_slice(&copy.body().to_json()?).map_err(invalid)?;
    let (serde_json::Value::Object(signed), serde_json::Value::Object(read)) = (&signed, &read)
    else {
        return Ok(true);
    };
    Ok(signed.iter().any(|(name, value)| match read.get(name) {
        Some(known) => unknown_in(value, known),
        // A name it leaves out can only be `null` or empty here: else it would read it.
        None => !left_out_when_empty(read, name, copy.body()),
    }))
}

/// Whether this signer reads the top-level member `name` of `identity.json` and left it out
/// of `read`, its own encoding of `body`, as it leaves out a member that is absent or
/// empty: the reader is asked, not a list kept beside it. A name it reads, given a value of
/// no type it takes, fails to read or reads otherwise; an unknown one is passed over.
fn left_out_when_empty(
    read: &serde_json::Map<String, serde_json::Value>,
    name: &str,
    body: &IdentityBody,
) -> bool {
    let mut probe = read.clone();
    probe.insert(
        name.to_owned(),
        serde_json::Value::String("\u{0}".to_owned()),
    );
    serde_json::from_value::<IdentityBody>(serde_json::Value::Object(probe))
        .map_or(true, |probed| &probed != body)
}

/// Whether `signed` holds a member `read`, the same value as this signer reads it, lacks,
/// below the top level, where this signer leaves no member out. Both come from the same
/// bytes, so each list holds as many entries in both, and a member read as an object or a
/// list was one: only names can differ.
fn unknown_in(signed: &serde_json::Value, read: &serde_json::Value) -> bool {
    use serde_json::Value;
    match (signed, read) {
        (Value::Object(signed), Value::Object(read)) => {
            signed.iter().any(|(name, value)| match read.get(name) {
                Some(known) => unknown_in(value, known),
                None => true,
            })
        }
        (Value::Array(signed), Value::Array(read)) => signed
            .iter()
            .zip(read)
            .any(|(value, known)| unknown_in(value, known)),
        _ => false,
    }
}

/// The App IDs revoked for good, ascending, and the earliest time picked to distrust each
/// listed one from (Switch spec 12.2, 12.8): every copy's `removed`, the backup's revoked
/// App IDs and picked times, the records `kept`, and the IDs the switch shows revoked,
/// departed, or kept with no record of an app, that `copy` neither lists nor removes, as many
/// as a move's enrollment carrying `copy` can still hold.
fn revoked_for_good(
    copy: &IdentityDoc,
    docs: &[&IdentityDoc],
    backed_up: Option<&BackupView>,
    kept: &SignerState,
    answer: &AppsAnswer,
    kind: KeyRecoveryKind,
) -> Result<(Vec<[u8; 16]>, Vec<RemovedApp>)> {
    let listed = |app: &[u8; 16]| copy.listed_cert(app).is_some();
    let mut revoked: Vec<[u8; 16]> = kept.tombstones.clone();
    let mut times: Vec<RemovedApp> = kept
        .revoking
        .iter()
        .filter_map(|r| {
            r.distrust_from.map(|distrust_from| RemovedApp {
                app_id: r.app_id,
                distrust_from,
            })
        })
        .collect();
    if let Some(view) = backed_up {
        revoked.extend(view.revoked_apps.iter().copied());
        times.extend(view.pending_distrust.iter().copied());
    }
    for doc in docs {
        revoked.extend(doc.body().removed.iter().map(|r| r.app_id));
        times.extend(doc.body().removed.iter().copied());
    }
    let mut picked: Vec<RemovedApp> = Vec::new();
    // For an app the copy lists, and one it removes: an earlier time than its `removed`
    // entry's is a time the user picked, and the version signed takes it.
    let removes = |app: &[u8; 16]| copy.body().removed.iter().any(|r| &r.app_id == app);
    for time in times
        .into_iter()
        .filter(|t| listed(&t.app_id) || removes(&t.app_id))
    {
        match picked.iter_mut().find(|p| p.app_id == time.app_id) {
            Some(earlier) => earlier.distrust_from = earlier.distrust_from.min(time.distrust_from),
            None => picked.push(time),
        }
    }
    let mut extras: Vec<[u8; 16]> = answer
        .apps
        .iter()
        .filter(|s| !listed(&s.app_id) && !revoked.contains(&s.app_id))
        .filter(|s| {
            s.revoked_at.is_some()
                || s.departed_at.is_some()
                || (!s.current && s.record_cert.is_none() && s.last_seen.is_none())
        })
        .map(|s| s.app_id)
        .collect();
    extras.sort_unstable();
    extras.dedup();
    let mut carried: Vec<[u8; 16]> = revoked
        .iter()
        .copied()
        .chain(copy.body().apps.iter().map(|a| a.app_id))
        .collect();
    carried.sort_unstable();
    carried.dedup();
    extras.truncate(enrollment_room(copy, &carried, &extras, kind)?);
    revoked.extend(extras);
    revoked.sort_unstable();
    revoked.dedup();
    Ok((revoked, picked))
}

/// How many of `extras`, the first ones, a move's enrollment carrying `copy` and the App IDs
/// `carried` can still hold, with the headroom every version keeps (Switch wire 3.7, 7.1),
/// and within an eighth of that enrollment's cap: App IDs taken on a switch's word alone never
/// take the room the identity's own later versions need.
fn enrollment_room(
    copy: &IdentityDoc,
    carried: &[[u8; 16]],
    extras: &[[u8; 16]],
    kind: KeyRecoveryKind,
) -> Result<usize> {
    let Some(limit) = enrollment_limit() else {
        return Ok(extras.len());
    };
    let policy = copy.body().policy;
    let size = |taken: usize| -> Result<usize> {
        let ids: Vec<[u8; 16]> = carried.iter().chain(&extras[..taken]).copied().collect();
        Ok(Enrollment::max_request_len(
            &policy,
            Some(copy.signed()),
            &ids,
        )?)
    };
    let without = size(0)?;
    // At a serving account all previously held IDs stay, so each addition must leave room
    // for later versions. A provider loss applies its reserve to the combined sources in
    // `enrollable` (Switch spec 12.8).
    let available = match kind {
        KeyRecoveryKind::AtService => limit - limit / 8,
        KeyRecoveryKind::ProviderLoss { .. } => limit,
    };
    let fits = |taken: usize| -> Result<bool> {
        let bytes = size(taken)?;
        Ok(bytes.saturating_add(CAP_HEADROOM) <= available
            && bytes.saturating_sub(without) <= limit / 8)
    };
    if fits(extras.len())? {
        return Ok(extras.len());
    }
    // The size grows with every App ID taken: the most that fit, found by halving.
    let (mut fitting, mut over) = (0, extras.len());
    if !fits(0)? {
        return Ok(0);
    }
    while over - fitting > 1 {
        let middle = fitting + (over - fitting) / 2;
        if fits(middle)? {
            fitting = middle;
        } else {
            over = middle;
        }
    }
    Ok(fitting)
}

/// The account's service key, and the alert for an `existing` enrollment's answer naming
/// another (Switch spec 12.5, 12.8): the account is served under the key its copy names, so
/// that one is kept and the other is shown, never followed.
fn account_key(origin: &str, copy: [u8; 32], answered: [u8; 32]) -> ([u8; 32], Option<Alert>) {
    let changed = (answered != copy).then(|| Alert::ServiceKeyNotFollowed {
        origin: origin.to_owned(),
        kept: copy,
        answered,
    });
    (copy, changed)
}

/// The copies the records `state` hold: the newest version and a declared recovery's base.
pub(super) fn marks_of(state: &SignerState) -> Result<Vec<IdentityDoc>> {
    let mut marks: Vec<IdentityDoc> = state.newest_doc()?.into_iter().collect();
    if let Some(base) = &state.recovery_base {
        marks.push(state::stored_identity(base, &state.identity)?);
    }
    Ok(marks)
}

/// The copies unusable records still verify.
fn copies_of(local: &RestoreLocal) -> Vec<IdentityDoc> {
    local
        .copies
        .iter()
        .filter_map(|copy| match copy {
            KeptCopy::Verified(doc) => Some(doc.as_ref().clone()),
            _ => None,
        })
        .collect()
}

/// The records a recovery with the key alone starts from on a store that held none, or over
/// the unusable ones `local`: a new install's, with the versions and epochs they spent and,
/// from a state that still reads, its revocations, owed deletions and the certificates that
/// verify, which bind it as this install's own records would.
fn fresh_records(
    identity: [u8; 32],
    install: [u8; 16],
    local: Option<&RestoreLocal>,
) -> SignerState {
    let mut state = SignerState::new(identity, install);
    let Some(local) = local else {
        return state;
    };
    state.signed_through = local.signed_through.unwrap_or(0);
    state.epoch_through = local.epoch_through.unwrap_or(0);
    if let Some(kept) = &local.state {
        state.records_behind = kept.records_behind;
        state.alerts = restored_alerts(kept);
        state.tombstones.clone_from(&kept.tombstones);
        state.revoking.clone_from(&kept.revoking);
        state.cleanup.clone_from(&kept.cleanup);
        state.certs = kept
            .certs
            .iter()
            .filter(|cert| AppCert::verify(cert, &identity).is_ok())
            .cloned()
            .collect();
    }
    state
}

/// The time a first document with no copy anywhere takes its generation and version from:
/// the later of the device's clock `now` and the picked service's trusted time `observed`,
/// which counts at most a day ahead of the device's, so neither a service's clock nor the
/// device's alone sets it below the other.
fn no_copy_time(now: u64, observed: u64) -> u64 {
    now.max(observed.min(now.saturating_add(DAY_MS)))
}

/// How many services a provider loss's survey reads at most, following the copies.
const MAX_SERVICES: usize = 32;

/// A day, in milliseconds.
const DAY_MS: u64 = 86_400_000;

/// What an account discovery showed, as the digest takes it: the association, the creation
/// and the key that signed it.
fn discovery_of(observation: &AccountObservation) -> Vec<u8> {
    let body = observation.body();
    let association = match body.association {
        AccountAssociation::Account => 0,
        AccountAssociation::Mark => 1,
        AccountAssociation::Absent => 2,
    };
    [
        &[association][..],
        &picked_time(body.created),
        &body.service_key,
    ]
    .concat()
}

/// A picked time or a generation as the digest takes it: none, or its eight bytes.
fn picked_time(time: Option<u64>) -> Vec<u8> {
    time.map(|time| u64be(time).to_vec()).unwrap_or_default()
}

/// The digest of the whole survey, which the user's confirmation binds (Switch spec 12.8).
fn digest_of(survey: &KeyRecoverySurvey) -> [u8; 32] {
    // The copy's hash stands for its version, generation and signer.
    let kind = match survey.kind {
        KeyRecoveryKind::AtService => vec![0],
        KeyRecoveryKind::ProviderLoss { lost } => [&[1][..], &picked_time(lost)].concat(),
    };
    let mut parts: Vec<Vec<u8>> = vec![
        kind,
        survey.identity.to_vec(),
        survey.origin.as_bytes().to_vec(),
        survey.service_key.to_vec(),
        survey.discovery.clone(),
        survey.copy.to_vec(),
        survey.certs_dropped.concat(),
    ];
    for earlier in &survey.earlier {
        parts.push([&earlier.app_id[..], &u64be(earlier.distrust_from)].concat());
    }
    for (app, fate) in &survey.apps {
        let fate = match fate {
            AppFate::Stays => vec![0],
            AppFate::RemovedAtSwitch { distrust_from } => {
                [&[1][..], &picked_time(*distrust_from)].concat()
            }
            AppFate::RevocationPending { distrust_from } => {
                [&[2][..], &picked_time(*distrust_from)].concat()
            }
            AppFate::CertificateNotFound => vec![3],
        };
        parts.push([app.as_slice(), &fate].concat());
    }
    parts.push(survey.renewals_dropped.concat());
    parts.push(survey.revoked.concat());
    parts.push(match survey.backup {
        BackupFound::Missing => vec![0],
        BackupFound::Unreadable => vec![1],
        BackupFound::Stale { version } => [&[2][..], &u64be(version)].concat(),
        BackupFound::Matches => vec![3],
    });
    let parts: Vec<&[u8]> = parts.iter().map(Vec::as_slice).collect();
    hash(&lp(&parts))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_key_recovery_caps_the_switchs_revoked_ids_at_a_moves_enrollment() {
        // However many App IDs a switch shows, the recovery takes no more than an eighth of a
        // move's enrollment carrying the copy, nor more than it can still hold.
        use pubky_switch_core::keys::IdentityKey;
        use pubky_switch_core::records::{IdentityBody, IdentityPolicy, Inbox};
        let key = IdentityKey::from_secret([11; 32]);
        let body = IdentityBody::first(
            key.public(),
            [1; 16],
            Inbox::new("https://switch.example", [2; 32]),
            IdentityPolicy::default(),
        );
        let copy = IdentityDoc::sign(&key, body).unwrap();
        let carried = [[3; 16]];
        let extras: Vec<[u8; 16]> = (0..20_000u64)
            .map(|i| {
                let mut id = [0; 16];
                id[..8].copy_from_slice(&(i + 10).to_be_bytes());
                id
            })
            .collect();
        let at_service = KeyRecoveryKind::AtService;
        let room = enrollment_room(&copy, &carried, &extras, at_service).unwrap();
        assert!(room > 0 && room < extras.len());
        let policy = copy.body().policy;
        let measure = |n: usize| {
            let ids: Vec<[u8; 16]> = carried.iter().chain(&extras[..n]).copied().collect();
            Enrollment::max_request_len(&policy, Some(copy.signed()), &ids).unwrap()
        };
        let limit = enrollment_limit().unwrap();
        // Within an eighth of the cap, and the most that fit there.
        assert!(measure(room) - measure(0) <= limit / 8);
        assert!(measure(room + 1) - measure(0) > limit / 8);
        assert!(measure(room) + CAP_HEADROOM <= limit);
        assert_eq!(
            enrollment_room(&copy, &carried, &extras[..5], at_service).unwrap(),
            5
        );
        // A serving account reserves the last eighth immediately. A provider loss still
        // gathers IDs up to the cap before choosing which fit across all its sources.
        let loss = KeyRecoveryKind::ProviderLoss { lost: Some(1) };
        for (kind, held, budget) in [
            (at_service, room * 6, limit - limit / 8),
            (loss, room * 7, limit),
        ] {
            let (carried, remaining) = extras.split_at(held);
            let near = enrollment_room(&copy, carried, remaining, kind).unwrap();
            assert!(near > 0 && near < room);
            let total = |n| {
                Enrollment::max_request_len(&policy, Some(copy.signed()), &extras[..held + n])
                    .unwrap()
                    + CAP_HEADROOM
            };
            assert!(total(near) <= budget);
            assert!(total(near + 1) > budget);
        }
    }

    #[test]
    fn test_key_recovery_digest_binds_every_member_shown() {
        // Each member the survey shows changes the digest the confirmation binds.
        let survey = KeyRecoverySurvey {
            origin: "https://switch.example".into(),
            version: 4,
            generation: 1,
            signer: [1; 16],
            apps: vec![
                ([2; 16], AppFate::Stays),
                (
                    [3; 16],
                    AppFate::RemovedAtSwitch {
                        distrust_from: Some(10),
                    },
                ),
                (
                    [4; 16],
                    AppFate::RevocationPending {
                        distrust_from: Some(20),
                    },
                ),
                ([5; 16], AppFate::CertificateNotFound),
            ],
            renewals_dropped: vec![[2; 16]],
            revoked: vec![[6; 16]],
            backup: BackupFound::Stale { version: 3 },
            kind: KeyRecoveryKind::AtService,
            origin_supplied: false,
            service_key: [10; 32],
            identity: [11; 32],
            copy: [7; 32],
            discovery: vec![0],
            certs_dropped: vec![[12; 32]],
            earlier: vec![RemovedApp {
                app_id: [16; 16],
                distrust_from: 7,
            }],
            versions: 4,
            carried: None,
            digest: [0; 32],
        };
        let changes: Vec<fn(&mut KeyRecoverySurvey)> = vec![
            |s| s.copy = [8; 32],
            |s| s.apps[0].1 = AppFate::CertificateNotFound,
            |s| {
                s.apps[1].1 = AppFate::RemovedAtSwitch {
                    distrust_from: Some(11),
                };
            },
            |s| {
                s.apps[2].1 = AppFate::RevocationPending {
                    distrust_from: None,
                };
            },
            |s| s.renewals_dropped.clear(),
            |s| s.revoked.push([9; 16]),
            |s| s.backup = BackupFound::Stale { version: 2 },
            |s| s.backup = BackupFound::Missing,
            |s| s.origin = "https://other.example".into(),
            |s| s.kind = KeyRecoveryKind::ProviderLoss { lost: Some(1) },
            |s| s.kind = KeyRecoveryKind::ProviderLoss { lost: None },
            |s| s.service_key = [13; 32],
            |s| s.identity = [14; 32],
            |s| s.discovery = vec![1],
            |s| s.certs_dropped = vec![[15; 32]],
            |s| s.earlier[0].distrust_from = 6,
        ];
        let mut digests = vec![digest_of(&survey)];
        for change in changes {
            let mut changed = survey.clone();
            change(&mut changed);
            digests.push(digest_of(&changed));
        }
        let mut distinct = digests.clone();
        distinct.sort_unstable();
        distinct.dedup();
        assert_eq!(distinct.len(), digests.len());
    }

    #[test]
    fn test_key_recovery_no_copy_time_is_bound_by_the_device_clock() {
        // A service's time below the device's counts for nothing; one ahead counts at most a
        // day ahead.
        assert_eq!(no_copy_time(5_000_000, 1_000), 5_000_000);
        assert_eq!(no_copy_time(5_000_000, 6_000_000), 6_000_000);
        assert_eq!(no_copy_time(5_000_000, u64::MAX), 5_000_000 + DAY_MS);
    }

    #[test]
    fn test_key_recovery_keeps_the_copys_service_key() {
        let (kept, changed) = account_key("https://switch.example", [1; 32], [1; 32]);
        assert_eq!((kept, changed), ([1; 32], None));
        let (kept, changed) = account_key("https://switch.example", [1; 32], [2; 32]);
        assert_eq!(kept, [1; 32]);
        assert_eq!(
            changed,
            Some(Alert::ServiceKeyNotFollowed {
                origin: "https://switch.example".into(),
                kept: [1; 32],
                answered: [2; 32],
            })
        );
    }
}
