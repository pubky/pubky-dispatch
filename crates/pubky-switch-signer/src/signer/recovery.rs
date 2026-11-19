//! A provider loss (Switch spec 12.6 steps 1 and 2; Switch wire 3.3, 3.7, 7.4.2, 7.4.14): the
//! signer enrolls at a service, the lost one's operator or another, and delivers there the
//! next generation's `identity.json`, which declares the generation it served lost.
//!
//! [`Signer::declare_provider_loss`] checks the copies, commits the declaration as a flow,
//! then:
//!
//! 1. enrolls at the service, naming every App ID it revoked or saw depart that the version
//!    it delivers doesn't list, so the service refuses them from the start although no
//!    export reaches it;
//! 2. signs the version, built on the newest this install signed, one in flight to the lost
//!    service included: the next generation, `recovery_from` the lost one, naming the
//!    service and the key its enrollment answered, at a higher version, with the same
//!    `data_epoch`, every `service_keys` entry of a lost generation left out, and every
//!    reduction whose closing is owed closed at the time it signs, plus the clock tolerance,
//!    since the lost service can't take the closing; cooperative renewals stay open;
//! 3. delivers it with `prev` `null`, as a new account's first document, which a recovery in
//!    place takes too, whatever version the service holds; writes its backup before, and
//!    publishes it after, as every version;
//! 4. completes there every revocation that version still lists the app of, a removal with
//!    its own rotation, as at any service;
//! 5. when none of the apps it lists holds `lists.manage`, ends the staged admission the
//!    recovery started (`POST /recovery/admission`), since no upload could, and reads
//!    `GET /apps` back to see it ended. An app whose certificate this install doesn't hold
//!    may hold it, so then the wait stays, for the user to end
//!    ([`Signer::end_staged_admission`]).
//!
//! Each step is resumed after a failure or a crash, the enrollment and the version sent again
//! with their bytes. Until the service takes the version, the user may declare the loss
//! again, at that service or another: the new declaration replaces the one in progress, and
//! its version is higher. The declaration is allowed while an alarm is held, at an erased
//! account, and during an erasure, which it ends, the lost account counting as erased: a
//! provider loss is the way out of each. It is refused while the records are behind, while
//! another install signs, and during a hand-over or a take-over.

use pubky_switch_core::records::{
    CLOCK_TOLERANCE_MS, Enrollment, EnrollmentBody, IDENTITY_PATH, IdentityBody, IdentityDoc,
    IdentityPolicy, Inbox,
};
use pubky_switch_core::scopes::Permission;
use pubky_switch_core::sig::SignedDoc;

use pubky_switch_client::ClientError;

use super::clients::{RequestClient, Target};
use super::erasure::withdraw_reminders;
use super::revocation::UserConfirmed;
use super::{Room, Signer, gate};
use crate::alert::{Alert, Source};
use crate::error::{RecordsFault, Refusal, Result, SignerError};
use crate::state::{self, DeliverStep, Flow, RecoveryEnrollment, Service, SignerState};

/// How many times in all a run sends a recovery's enrollment, the same bytes each time,
/// before its failure is shown (Switch wire 7.4.1).
const ENROLL_TRIES: u32 = 3;

impl Signer {
    /// Declare the service the identity is enrolled at lost, and recover at the service at
    /// `origin`: the same operator's or another's (Switch spec 12.6 step 1). Shown and
    /// confirmed by the user, since apps then rebuild their state there. Returns the version
    /// that starts the new generation, once delivered and published.
    ///
    /// Declaring it again before the service takes that version, at the same service or
    /// another, replaces the recovery in progress: for an origin that never answers, or a
    /// service that refused the version ([`crate::SignerStatus::RecoveryRefused`]).
    ///
    /// # Errors
    ///
    /// [`Refusal::NotSetUp`] before the first version; [`SignerError::NotNamed`],
    /// [`Refusal::RecordsBehind`], [`Refusal::HandingOver`] and [`Refusal::TakingOver`], as
    /// the spec's "who may declare it" asks, also when the signer backup or the Homeserver's
    /// `identity.json` shows one of them; [`Refusal::FlowInProgress`] during a first
    /// enrollment or a take-over; [`Refusal::IdentityTooLarge`] for a version naming
    /// `origin` that the cap can't take; an origin that isn't a switch origin; otherwise as
    /// [`Signer::resume`], with the recovery kept and resumed there. Declared again at the
    /// service its version is in flight to, the recovery goes on there, as
    /// [`Signer::resume`] would. [`Refusal::HomeserverCopyMissing`] or
    /// [`Refusal::HomeserverCopyUnreadable`] when the Homeserver's `identity.json` is
    /// missing, where the records don't explain it, or doesn't verify:
    /// [`Signer::declare_provider_loss_confirming_records`] is the way past either.
    pub async fn declare_provider_loss(
        &mut self,
        origin: &str,
        _confirmed: UserConfirmed,
    ) -> Result<IdentityDoc> {
        self.declare_loss(origin, false).await
    }

    /// [`Signer::declare_provider_loss`], once the user has also confirmed that no other
    /// install signs for the identity, when the Homeserver's `identity.json` is missing or
    /// doesn't verify ([`Refusal::HomeserverCopyMissing`],
    /// [`Refusal::HomeserverCopyUnreadable`]): that copy is what names the signer while the
    /// lost service can't be asked (Switch spec 12.6 step 1, 4.3), so without it the user's
    /// word stands in. A copy that verifies is judged as for every declaration.
    ///
    /// # Errors
    ///
    /// As [`Signer::declare_provider_loss`], but for those two refusals.
    pub async fn declare_provider_loss_confirming_records(
        &mut self,
        origin: &str,
        _confirmed: UserConfirmed,
    ) -> Result<IdentityDoc> {
        self.declare_loss(origin, true).await
    }

    /// The declaration (the module's doc), `records_confirmed` when the user confirmed this
    /// install's records stand without the Homeserver's copy.
    async fn declare_loss(&mut self, origin: &str, records_confirmed: bool) -> Result<IdentityDoc> {
        self.refresh().await?;
        let newest = self.state.newest_doc()?.ok_or(Refusal::NotSetUp)?;
        // Who may declare it: the recovery's gate, before anything is read or signed.
        if let Some(refused) = gate::recovery_refusal(&self.state) {
            return Err(refused);
        }
        if matches!(
            self.flow,
            Some(Flow::Enroll { .. } | Flow::TakingOver { .. })
        ) {
            return Err(Refusal::FlowInProgress.into());
        }
        // A recovery version already in flight to this origin continues unchanged. Only an
        // enrollment-only continuation may be ended by this explicit authorization while
        // its remote outcome remains unknown (Switch account binding 3).
        // Declared again at a service an earlier declaration enrolled at: one that took that
        // version serves it, so it is read first under the key it was answered with.
        // The backup is judged first: an install that took over shows there, and its version
        // must never be superseded by an earlier one the pre-read would take.
        let goes_to = self.recovery_goes_to(origin);
        if matches!(self.flow, Some(Flow::RecoveryDelivery(_))) && !goes_to {
            // Replacing an uncertain joint action requires a separate key-holder survey.
            return Err(Refusal::FlowInProgress.into());
        }
        if !goes_to {
            self.check_backup_copy().await?;
        }
        if goes_to || self.taken_under_an_earlier_key(origin, false).await? {
            self.resume().await?;
            self.complete_listed_revocations().await?;
            return self
                .state
                .newest_doc()?
                .ok_or(SignerError::Records(RecordsFault::Invariant(
                    "the recovery's version is gone",
                )));
        }
        // Taken before the checks below, which may end a flow in progress.
        let base = self.recovery_base()?.ok_or(Refusal::NotSetUp)?;
        // The copies the lost service can't be asked about: the backup and the Homeserver's
        // `identity.json` show another install that took over, or records behind (Switch
        // spec 4.3). Another body there at the mark is an alarm, which the recovery passes,
        // and its version waits for the user to clear it before it is published.
        self.check_backup_copy().await?;
        let waived = self
            .check_homeserver_copy(&newest, records_confirmed)
            .await?;
        // The App IDs to refuse from the start, but those the version still lists: a
        // revocation not signed into a version yet is completed at the service once it
        // took the recovery's version, which can't also rotate (Switch spec 12.6 step 1).
        let mut revoked: Vec<[u8; 16]> = self
            .state
            .tombstones
            .iter()
            .copied()
            .filter(|app| base.listed_cert(app).is_none())
            .collect();
        revoked.sort_unstable();
        revoked.dedup();
        // A version the cap can't take is refused before anything is sent: the origin is in
        // it, and the service's key is as long whatever it is.
        let lost = self.lost_generation(Some(&base))?;
        let until = self.env.clock.now_ms().saturating_add(CLOCK_TOLERANCE_MS);
        self.recovery_body(Some(&base), lost, origin, [0; 32], until)?;
        if !pubky_switch_core::records::is_origin(origin) {
            return Err(SignerError::InvalidData(pubky_switch_core::Error::Invalid(
                "Switch wire 3.7: invalid recovery origin".into(),
            )));
        }
        let enrollment = RecoveryEnrollment::Preparing {
            nonce: pubky_switch_core::enc::random_bytes()?,
            policy: newest.body().policy,
            revoked_apps: revoked,
        };
        let mut state = self.state.clone();
        // An erasure ends: the account at the lost service counts as gone, and its reminders
        // for apps still listed are withdrawn (Switch spec 12.7). So are those of an erased
        // account's, enrolled again with those apps (Switch spec 12.7 step 4).
        self.end_erasure_in(&mut state)?;
        if state.erased {
            let reminded = state.grant_reminded.clone();
            withdraw_reminders(&mut state, &reminded)?;
        }
        state.erased = false;
        state.recovering = true;
        state.recovery_base = Some(base.signed().clone());
        state.lost_generation = Some(lost);
        state.homeserver_copy_waived = waived;
        state.recovery_origin = Some(origin.to_owned());
        let flow = Flow::Recover {
            origin: origin.to_owned(),
            enrollment,
        };
        self.commit(state, Some(flow)).await?;
        self.resume().await?;
        self.complete_listed_revocations().await?;
        self.state
            .newest_doc()?
            .ok_or(SignerError::Records(RecordsFault::Invariant(
                "the recovery's version is gone",
            )))
    }

    /// End the staged admission a recovery started at the service (Switch spec 12.6 step 2;
    /// wire 7.4.14), on the user's word: for example once the app that manages contacts is
    /// gone for good. Owed until `GET /apps` shows the wait ended, and sent again at every
    /// run; `GET /apps` is read first, so a wait that isn't staged, or no recovery, changes
    /// nothing and sends nothing.
    ///
    /// # Errors
    ///
    /// [`Refusal::FlowInProgress`] while a flow is in progress; [`Refusal::Recovering`]
    /// before the recovery's version is delivered; a switch error, the call kept owed for the
    /// next run.
    pub async fn end_staged_admission(&mut self) -> Result<()> {
        self.refresh().await?;
        self.check_named()?;
        if self.flow.is_some() {
            return Err(Refusal::FlowInProgress.into());
        }
        if self.state.recovering {
            return Err(Refusal::Recovering.into());
        }
        let mut state = self.state.clone();
        state.admission_owed = true;
        self.commit(state, None).await?;
        self.end_owed_admission().await
    }

    /// Whether the recovery's already signed version is in flight to `origin`.
    fn recovery_goes_to(&self, origin: &str) -> bool {
        if !self.state.recovering {
            return false;
        }
        match &self.flow {
            Some(Flow::RecoveryDelivery(action)) => action.origin == origin,
            Some(Flow::Deliver { .. }) => self
                .state
                .service
                .as_ref()
                .is_some_and(|service| service.origin == origin),
            _ => false,
        }
    }

    /// Whether a service at `origin` an earlier declaration of this recovery enrolled at holds
    /// a version of it, read under each key it answered, but the one pinned now when
    /// `skip_pinned` (Switch wire 3.7, 7.4.12): then that is the recovery delivered, under
    /// that key, and the run goes on from there. A read that fails shows nothing, and the
    /// caller goes on as if none was taken.
    pub(super) async fn taken_under_an_earlier_key(
        &mut self,
        origin: &str,
        skip_pinned: bool,
    ) -> Result<bool> {
        if !self.state.recovering {
            return Ok(false);
        }
        let pinned = self
            .state
            .service
            .as_ref()
            .map(|s| s.service_key)
            .filter(|_| skip_pinned);
        let earlier: Vec<Service> = self
            .state
            .recovery_services
            .iter()
            .filter(|s| s.origin == origin && Some(s.service_key) != pinned)
            .cloned()
            .collect();
        let identity = self.state.identity;
        for service in earlier {
            let target = Target {
                origin,
                pinned: Some(service.service_key),
                created: Some(service.created),
                identity,
            };
            let Ok(answer) = RequestClient::new(&self.env, &target, &self.keyring, &self.store)?
                .apps()
                .await
            else {
                continue;
            };
            let copy = answer
                .identity
                .as_ref()
                .and_then(|signed| IdentityDoc::verify(signed, &identity).ok());
            if let Some(copy) = copy.filter(|copy| self.own_recovery_version(copy)) {
                let mut state = self.state.clone();
                state.service = Some(service);
                state.recovery_origin = Some(origin.to_owned());
                self.commit(state, self.flow.clone()).await?;
                self.own_recovery_held(copy).await?;
                return Ok(true);
            }
        }
        Ok(false)
    }

    /// Judge the Homeserver's `identity.json` before a recovery is signed (Switch spec 12.6
    /// step 1, 4.3): a copy that verifies, as [`Signer::judge_homeserver`] does, an alarm
    /// passing. One that is missing passes when the records explain it: an erasure, done or
    /// in progress, deleted it, or no version was ever published. An unpublished newest
    /// version explains nothing, since an earlier one was. Otherwise, and for one that
    /// doesn't verify, only with the user's confirmation `records_confirmed`. Returns whether
    /// the copy was waived so.
    async fn check_homeserver_copy(
        &mut self,
        newest: &IdentityDoc,
        records_confirmed: bool,
    ) -> Result<bool> {
        let held = self
            .env
            .homeserver
            .get(IDENTITY_PATH)
            .await
            .map_err(SignerError::Homeserver)?;
        let Some(bytes) = held else {
            let explained = self.state.erased
                || matches!(self.flow, Some(Flow::Erase { .. }))
                || !self.state.ever_published;
            if explained || records_confirmed {
                return Ok(true);
            }
            return Err(Refusal::HomeserverCopyMissing.into());
        };
        let verifies = serde_json::from_slice::<SignedDoc>(&bytes)
            .ok()
            .is_some_and(|signed| IdentityDoc::verify(&signed, &self.state.identity).is_ok());
        if !verifies {
            if records_confirmed {
                return Ok(true);
            }
            return Err(Refusal::HomeserverCopyUnreadable.into());
        }
        match self.judge_homeserver(newest).await {
            Ok(_) | Err(SignerError::Alarm(_)) => Ok(false),
            Err(error) => Err(error),
        }
    }

    /// The document the recovery builds on: the one kept for a recovery declared already,
    /// else the newest this install signed, the version of a delivery or a renewal in flight
    /// to the lost service included, since that service may have taken it and apps seen it.
    /// `None` for a recovery with the key alone that found no copy anywhere (Switch spec
    /// 12.8), and before the first version.
    pub(super) fn recovery_base(&self) -> Result<Option<IdentityDoc>> {
        let identity = self.state.identity;
        if self.state.recovering
            && let Some(base) = &self.state.recovery_base
        {
            return state::stored_identity(base, &identity).map(Some);
        }
        let Some(newest) = self.state.newest_doc()? else {
            return Ok(None);
        };
        let in_flight = match &self.flow {
            Some(Flow::Deliver { doc, .. } | Flow::Renew { doc, .. }) => {
                Some(state::stored_identity(doc, &identity)?)
            }
            _ => None,
        };
        Ok(Some(
            in_flight
                .filter(|doc| {
                    doc.generation() == newest.generation() && doc.version() > newest.version()
                })
                .unwrap_or(newest),
        ))
    }

    /// The generation the recovery declares lost: the one kept for a recovery declared
    /// already, else `base`'s.
    fn lost_generation(&self, base: Option<&IdentityDoc>) -> Result<u64> {
        self.state
            .lost_generation
            .filter(|_| self.state.recovering)
            .or_else(|| base.map(IdentityDoc::generation))
            .ok_or_else(|| RecordsFault::Invariant("a recovery declares no generation lost").into())
    }

    /// The body of the recovery's version on `base`, declaring generation `lost` lost and
    /// naming the service at `origin` and its key `service_key`, with owed reductions closed
    /// at `until` (the module's doc, step 2), measured against the cap. Nothing is signed.
    /// With no `base`, after a recovery with the key alone that found no copy anywhere, it is
    /// a first document in a provider loss's shape (Switch spec 12.8, wire 3.3): no app, at
    /// the generation after `lost` and above every version the records spent.
    pub(super) fn recovery_body(
        &self,
        base: Option<&IdentityDoc>,
        lost: u64,
        origin: &str,
        service_key: [u8; 32],
        until: u64,
    ) -> Result<IdentityBody> {
        let generation =
            lost.checked_add(1)
                .ok_or(SignerError::Records(RecordsFault::Invariant(
                    "the generation can't go higher",
                )))?;
        let Some(base) = base else {
            let mut body = IdentityBody::first(
                self.state.identity,
                self.state.install,
                Inbox::new(origin, service_key),
                IdentityPolicy::default(),
            );
            body.version = self
                .state
                .signed_through
                .checked_add(1)
                .ok_or(SignerError::Records(RecordsFault::Invariant(
                    "the version can't go higher",
                )))?;
            body.generation = generation;
            body.recovery_from = Some(lost);
            return Self::measured(&self.state, body, None, Room::Cap);
        };
        let owed = self.owed_in(base)?;
        self.next_body_on(
            base,
            |body| {
                body.generation = generation;
                body.recovery_from = Some(lost);
                body.inbox = Inbox::new(origin, service_key);
                // Every lost generation's key is left out (wire 3.3): nothing resolves it.
                body.service_keys.retain(|entry| entry.generation > lost);
                for app in &owed {
                    body.close_renewals(app, until);
                }
            },
            Room::Cap,
        )
    }

    /// Continue only this recovery's preparation or original signed enrollment.
    pub(super) async fn recover(
        &mut self,
        origin: &str,
        enrollment: &RecoveryEnrollment,
    ) -> Result<()> {
        let RecoveryEnrollment::Ready {
            observation,
            enrollment,
        } = enrollment
        else {
            return self.observe_recovery_account(origin, enrollment).await;
        };
        let observed = observation
            .verify(&self.state.identity, origin)
            .map_err(SignerError::StoredData)?;
        let answer = match self
            .enroll_for_recovery(origin, enrollment, observed.body().service_key)
            .await
        {
            Ok(answer) => answer,
            Err(error @ SignerError::Switch(_)) => {
                return self
                    .prepare_recovery_delivery(&observed, enrollment, error)
                    .await;
            }
            Err(error) => return Err(error),
        };
        // The enrollment's answer names the key the service signs with from then on: only the
        // one its account discovery showed, which the user confirmed, is followed. Another
        // fails the step, and the recovery is declared again (Switch spec 12.6, 12.8).
        if answer.service_key != observed.body().service_key {
            return Err(SignerError::InvalidData(pubky_switch_core::Error::Invalid(
                "Switch wire 7.4.1: the enrollment's answer names another key than the account discovery".into(),
            )));
        }
        let base = self.recovery_base()?;
        let lost = self.lost_generation(base.as_ref())?;
        let until = self.env.clock.now_ms().saturating_add(CLOCK_TOLERANCE_MS);
        // The enrollment names no App ID this version lists: both come from `base`.
        let body = self.recovery_body(base.as_ref(), lost, origin, answer.service_key, until)?;
        let key = gate::recovery_key(&self.keyring, &self.state, &self.store)?;
        let doc = IdentityDoc::sign(&key, body)?;
        drop(key);
        let mut state = self.state.clone();
        // An answer naming another key than the one pinned for this service is taken only
        // within a step the user started, this declaration among them, and the new key is
        // shown, never followed silently: the key an enrollment answer names is trusted on
        // first use (Switch wire 7.4.1 "Which key signs", spec 12.5).
        if let Some(pinned) = self
            .pinned_for(origin)
            .filter(|pinned| *pinned != answer.service_key)
        {
            state.alert(Alert::ServiceKeyTaken {
                origin: origin.to_owned(),
                pinned,
                service_key: answer.service_key,
            });
        }
        let service = Service {
            origin: origin.to_owned(),
            service_key: answer.service_key,
            limits: answer.limits,
            created: answer.created,
        };
        if !state.recovery_services.contains(&service) {
            state.recovery_services.push(service.clone());
        }
        // In place, the service keeps the one key it served the lost generation with, which
        // its enrollment answers name again (Switch wire 3.7, 7.4.1), and the signer checks
        // every answer with that key, the delivery's and its refusal's alike (Switch wire
        // 7.4.2 "Which key signs the answer", spec 12.6 step 1). Only where the service
        // changed its key since (Switch spec 12.5) does it still serve the lost generation
        // under the key it had, until it takes the version: that key is then kept, read as
        // below. A key kept from an earlier declaration or a restore stays, for whichever
        // origin it was kept for, since only the service at that origin is read under it.
        // Otherwise it is taken from a signed copy of the lost generation naming this origin:
        // the version the recovery builds on, or, when that is a restored recovery's own
        // version, the Homeserver's copy, as the restore takes it (Switch wire 3.13). A
        // delivery whose answer shows that key no longer serves drops it.
        state.recovery_serving = match self.state.recovery_serving.clone() {
            Some(kept) => Some(kept),
            None => {
                let earlier = match &base {
                    None => None,
                    Some(base) if base.generation() == lost => {
                        (base.inbox().url == origin).then(|| base.inbox().service_key)
                    }
                    Some(base) => {
                        self.lost_generations_key_on_homeserver(origin, lost, base.version())
                            .await?
                    }
                };
                earlier
                    .filter(|earlier| *earlier != answer.service_key)
                    .map(|service_key| Service {
                        origin: origin.to_owned(),
                        service_key,
                        limits: answer.limits,
                        created: answer.created,
                    })
            }
        };
        state.service = Some(service.clone());
        state.signed_through = state.signed_through.max(doc.version());
        // After a recovery with the key alone the version may name a certificate this install
        // doesn't hold, and no backup of it can be sealed: it is written once the delivery
        // has won, as a racing delivery's is, by the version that drops those certificates
        // (Switch spec 12.8). So is one built on a copy another install signed, or on none:
        // it races whatever install signed that copy, and a backup that install wrote is
        // below its version only once it has won.
        let unheld = self.names_unheld(&doc)?
            || base
                .as_ref()
                .is_none_or(|base| base.body().signer != self.state.install);
        state.backup_owed |= unheld;
        let flow = Flow::Deliver {
            account: service,
            doc: doc.signed().clone(),
            prev: None,
            backup: None,
            step: if unheld {
                DeliverStep::BackupWritten
            } else {
                DeliverStep::Signed
            },
        };
        self.commit(state, Some(flow)).await
    }

    /// Select once under the user's recovery authorization, then commit before sending.
    async fn observe_recovery_account(
        &mut self,
        origin: &str,
        enrollment: &RecoveryEnrollment,
    ) -> Result<()> {
        let RecoveryEnrollment::Preparing {
            nonce,
            policy,
            revoked_apps,
        } = enrollment
        else {
            return Err(RecordsFault::Invariant("the recovery was already signed").into());
        };
        enrollment.check_exclusions(&self.state, origin)?;
        let target = Target {
            origin,
            // The explicit recovery permits the selected HTTPS origin's current key
            // (Switch spec 12.5-12.6); it never repins an older pending action.
            pinned: None,
            created: None,
            identity: self.state.identity,
        };
        let observation = RequestClient::new(&self.env, &target, &self.keyring, &self.store)?
            .observe_account()
            .await?;
        let key = gate::recovery_key(&self.keyring, &self.state, &self.store)?;
        let signed = Enrollment::sign(
            &key,
            EnrollmentBody {
                identity: self.state.identity,
                origin: origin.to_owned(),
                nonce: *nonce,
                intent: observation.enrollment_intent()?,
                policy: *policy,
                identity_doc: None,
                revoked_apps: Some(revoked_apps.clone()),
            },
        )?;
        drop(key);
        let flow = Flow::Recover {
            origin: origin.to_owned(),
            enrollment: RecoveryEnrollment::Ready {
                observation: observation.carried().clone(),
                enrollment: signed.signed().clone(),
            },
        };
        self.commit(self.state.clone(), Some(flow)).await
    }

    /// The key the service at `origin` served generation `lost` with, as the Homeserver's
    /// copy of `identity.json` names it: a copy the identity key signed, at that generation,
    /// naming that origin, below version `below` (Switch wire 3.13). No other copy gives one.
    pub(super) async fn lost_generations_key_on_homeserver(
        &self,
        origin: &str,
        lost: u64,
        below: u64,
    ) -> Result<Option<[u8; 32]>> {
        let identity = self.state.identity;
        Ok(self
            .env
            .homeserver
            .get(IDENTITY_PATH)
            .await
            .map_err(SignerError::Homeserver)?
            .and_then(|bytes| serde_json::from_slice::<SignedDoc>(&bytes).ok())
            .and_then(|signed| IdentityDoc::verify(&signed, &identity).ok())
            .filter(|copy| {
                copy.generation() == lost && copy.version() < below && copy.inbox().url == origin
            })
            .map(|copy| copy.inbox().service_key))
    }

    /// The key this install pinned for the service at `origin`: the enrolled service's, else
    /// the one an earlier declaration's enrollment there answered, the newest first; `None`
    /// for a service it never enrolled at (Switch wire 7.4.1).
    pub(super) fn pinned_for(&self, origin: &str) -> Option<[u8; 32]> {
        self.state
            .service
            .iter()
            .chain(self.state.recovery_services.iter().rev())
            .find(|service| service.origin == origin)
            .map(|service| service.service_key)
    }

    /// Retry with the original observed key and signed body. A bounded run stops on its
    /// error without retiring the continuation (Switch account binding 3).
    async fn enroll_for_recovery(
        &mut self,
        origin: &str,
        signed: &SignedDoc,
        service_key: [u8; 32],
    ) -> Result<pubky_switch_core::records::EnrollmentAnswer> {
        let identity = self.state.identity;
        let enrollment =
            Enrollment::verify(signed, &identity, origin).map_err(SignerError::StoredData)?;
        let target = Target {
            origin,
            pinned: Some(service_key),
            created: enrollment.body().intent.created(),
            identity,
        };
        let mut sends = 0;
        loop {
            sends += 1;
            let error = match RequestClient::new(&self.env, &target, &self.keyring, &self.store)?
                .enroll(&enrollment)
                .await
            {
                Ok(answer) => return Ok(answer),
                Err(error) => error,
            };
            let refused = matches!(
                error,
                ClientError::BadServiceSignature { status: 400 }
                    | ClientError::Switch { status: 400, .. }
            );
            if !refused {
                return Err(error.into());
            }
            if sends >= ENROLL_TRIES {
                return Err(error.into());
            }
        }
    }

    /// Complete at the new service every revocation the recovery's version still lists the
    /// app of (the module's doc, step 4). One that fails stays pending with its alert, and is
    /// completed as any pending revocation is: the recovery itself is done.
    pub(super) async fn complete_listed_revocations(&mut self) -> Result<()> {
        let newest = self.state.newest_doc()?.ok_or(Refusal::NotSetUp)?;
        let pending: Vec<[u8; 16]> = self
            .state
            .revoking
            .iter()
            .map(|r| r.app_id)
            .filter(|app| newest.listed_cert(app).is_some())
            .collect();
        if pending.is_empty() || self.complete_removals().await.is_ok() {
            return Ok(());
        }
        let newest = self.state.newest_doc()?.ok_or(Refusal::NotSetUp)?;
        let mut state = self.state.clone();
        for app_id in pending {
            if newest.listed_cert(&app_id).is_some() {
                let at_switch = state.revoking.iter().any(|r| r.app_id == app_id && r.taken);
                state.alert(Alert::RevocationPending { app_id, at_switch });
            }
        }
        self.commit(state, self.flow.clone()).await
    }

    /// Whether an app `doc` lists may hold `lists.manage`: its certificate grants it, or
    /// this install doesn't hold its certificate, so it can't tell.
    pub(super) fn listed_may_manage_lists(&self, doc: &IdentityDoc) -> Result<bool> {
        let certs = self.held_certs()?;
        Ok(doc.body().apps.iter().any(|listed| {
            certs
                .iter()
                .find(|cert| cert.hash() == listed.cert)
                .is_none_or(|cert| cert.has_permission(Permission::ListsManage))
        }))
    }

    /// The recovery's version `doc` is delivered (Switch spec 12.6 step 1): the account
    /// served from here is the new service's, and what the lost one held against this install
    /// goes, its alarms, an unconfirmed switch and the revocations it took among them, which
    /// are sent to the new service again. An alert for a revocation `doc` completed goes.
    pub(super) fn recovered_in(state: &mut SignerState, doc: &IdentityDoc) {
        state.recovering = false;
        state.recovery_base = None;
        state.recovery_commit = None;
        state.lost_generation = None;
        state.homeserver_copy_waived = false;
        state.recovery_origin = None;
        state.recovery_services.clear();
        state.recovery_serving = None;
        state.owes_own_version = doc.body().signer != state.install;
        state.revoke_at_service = state
            .revoking
            .iter()
            .any(|r| doc.listed_cert(&r.app_id).is_some());
        state.switch_unconfirmed = false;
        for revoking in &mut state.revoking {
            revoking.taken = false;
        }
        state.alerts.retain(|alert| match alert {
            Alert::Rollback {
                source: Source::Switch,
                ..
            }
            | Alert::Equivocation {
                source: Source::Switch,
                ..
            }
            | Alert::AccountNotHosted
            | Alert::ServiceHoldsNoAccount => false,
            Alert::RevocationPending { app_id, .. } | Alert::RevocationUnconfirmed { app_id } => {
                doc.listed_cert(app_id).is_some()
            }
            _ => true,
        });
    }

    /// End staged admission, owed after a recovery or asked for by the user, and read it back
    /// (the module's doc, step 5). `GET /apps` is read first, so a wait that ended or a
    /// service with no recovery sends nothing and owes nothing more.
    pub(super) async fn end_owed_admission(&mut self) -> Result<()> {
        let staged = |read: &super::SwitchRead| {
            read.answer
                .recovery
                .as_ref()
                .is_some_and(|r| r.admission_staged)
        };
        if !staged(&self.read_apps().await?) {
            return Ok(());
        }
        self.service_client()?.recovery_admission().await?;
        if staged(&self.read_apps().await?) {
            return Err(SignerError::InvalidData(pubky_switch_core::Error::Invalid(
                "Switch wire 7.4.14: admission is still staged after its end".into(),
            )));
        }
        Ok(())
    }
}
