//! Restoring the signer from its backup (Switch spec 12.8; Switch wire 3.13).
//!
//! On the user's confirmation, an install reads the backup on the Homeserver, opens it with the
//! identity key, and checks it as wire 3.13 "Restoring" says:
//!
//! - the switch's copy of `identity.json` is the backup's version, or the version it builds on
//!   (`prev`), as when the signer stopped between writing the backup and delivering: that
//!   version is then delivered first. A switch with no copy counts only under a backup of the
//!   account's first version, or of a recovery's version. A recovery declared in place, at
//!   the service that served the lost generation, names that service's one key again, and
//!   every answer there is checked with it; after a service key change, an answer the key
//!   the version names didn't sign is read again under the key the Homeserver's copy of the
//!   lost generation names, at that origin and below the backup's version, and under no
//!   other key. Either way its copy of the lost generation below the backup's version, or a
//!   signed `503 recovery_required` naming the lost generation or the backup's, counts as no
//!   copy. Any other copy makes the backup stale, and the restore is refused;
//! - the Homeserver's copy is neither newer than the backup's version nor another document at
//!   it.
//!
//! In place, the install's own records are checked too: no alarm stands, since a restore never
//! clears one, and the backup isn't below the mark (wire 3.3 "Never back").
//!
//! The install then takes the backup's records as its own, with these additions:
//! - the App IDs `GET /apps` shows revoked or departed join the tombstones, and, in place, so
//!   do this install's own, with the revocations it asked for and the deletions it owes;
//! - the epoch floor is the highest epoch whose keys the records or the switch show were
//!   sent, at most one past `data_epoch`;
//! - the removed apps are left for the routine run to check, whose record still on the
//!   Homeserver owes its deletion again, with its grant reminder raised once more.
//!
//! It delivers the next version naming this install as the signer, publishes it, and owes its
//! own backup, which `resume` writes once that delivery has won (wire 3.13 "When it is
//! written"). Records behind their own newer version, or an install another took over from,
//! are restored in place this way.

use pubky_switch_client::ClientError;
use pubky_switch_client::client::answers::AppsAnswer;
use pubky_switch_client::store::OwnedStoreHandle;
use pubky_switch_core::http::ErrorCode;
use pubky_switch_core::ops::OpKind;
use pubky_switch_core::records::{
    IDENTITY_PATH, IdentityDoc, SIGNER_BACKUP_PATH, SignerBackup, app_record_path,
};
use pubky_switch_core::sig::SignedDoc;

use super::SignerEnv;
use super::clients::{RequestClient, Target};
use super::key_recovery::{Found, KeyRecoveryConfirmed, RestoreConfirmed};
use super::{Signer, gate};
use crate::Counter;
use crate::alert::Alert;
use crate::error::{KeyRecoveryStop, RecordsFault, Refusal, Result, SignerError};
use crate::key::{BackupView, IdentityKeyring};
use crate::state::{self, DeliverStep, Flow, Newest, RenewBatch, Revoking, Service, SignerState};

impl BackupView {
    pub(super) fn holds_delivery(
        &self,
        doc: &SignedDoc,
        prev: Option<[u8; 32]>,
        account: &Service,
    ) -> bool {
        self.identity_doc.signed() == doc && self.prev == prev && self.service() == *account
    }

    fn service(&self) -> Service {
        Service {
            origin: self.identity_doc.inbox().url.clone(),
            service_key: self.identity_doc.inbox().service_key,
            limits: self.limits,
            created: self.account_created,
        }
    }
}

/// Confirmation that the user chose restoration after seeing what unusable local records
/// may lose: claims, undelivered changes, pending effects and local history (Switch spec 12.8).
/// This is the host's attestation, not verification that a user interface was shown.
#[derive(Clone, Debug)]
pub struct RecordsDiscarded(Option<KeyRecoveryConfirmed>);

impl RecordsDiscarded {
    /// Made by the host only after showing the losses and obtaining confirmation to restore.
    #[must_use]
    pub fn shown_and_confirmed() -> Self {
        Self(None)
    }

    /// The same, with the user's confirmation of a recovery with the key alone, for a backup
    /// that is missing, unreadable or stale ([`Signer::survey_key_recovery_new`]).
    #[must_use]
    pub fn and_key_recovery(self, confirmed: KeyRecoveryConfirmed) -> Self {
        Self(Some(confirmed))
    }
}

/// Whether `error` is a refusal of the backup itself, which a recovery with the key alone
/// is the way past (Switch spec 12.8): none, one that doesn't open, or a stale one.
pub(super) fn backup_refused(error: &SignerError) -> bool {
    matches!(
        error,
        SignerError::Refused(Refusal::NoBackup | Refusal::UnreadableBackup | Refusal::StaleBackup)
    )
}

// A missing copy in readable current state is different from a copy whose evidence was lost.
pub(super) enum KeptCopy {
    Absent,
    Verified(Box<IdentityDoc>),
    Unusable,
}

impl KeptCopy {
    fn read(signed: Option<&SignedDoc>, identity: &[u8; 32]) -> Self {
        match signed {
            None => Self::Absent,
            Some(signed) => match state::stored_identity(signed, identity) {
                Ok(doc) => Self::Verified(Box::new(doc)),
                Err(_) => Self::Unusable,
            },
        }
    }
}

/// A signed successor whose backup was saved before its delivery (Switch wire 3.13).
struct PendingDelivery {
    account: Service,
    doc: SignedDoc,
    prev: [u8; 32],
    backup: SignerBackup,
}

impl PendingDelivery {
    fn from_flow(flow: Flow) -> Option<Box<Self>> {
        match flow {
            Flow::Deliver {
                account,
                doc,
                prev: Some(prev),
                backup: Some(backup),
                ..
            } => Some(Box::new(Self {
                account,
                doc,
                prev,
                backup,
            })),
            _ => None,
        }
    }

    /// Open the backup at the Homeserver only when it covers the entire saved delivery.
    fn open(&self, keyring: &IdentityKeyring, bytes: Option<&[u8]>) -> Result<BackupView> {
        let found = bytes.and_then(|bytes| serde_json::from_slice::<SignerBackup>(bytes).ok());
        if found.as_ref() != Some(&self.backup) {
            return Err(Refusal::FlowInProgress.into());
        }
        let view = keyring
            .open_backup(&self.backup)?
            .ok_or(Refusal::FlowInProgress)?;
        if !view.holds_delivery(&self.doc, Some(self.prev), &self.account) {
            return Err(Refusal::FlowInProgress.into());
        }
        Ok(view)
    }
}

// Retained restrictions, never a ready signer or permission to sign. Only a whole decoded
// current state for the requested identity contributes its scalar and collection members.
pub(super) struct RestoreLocal {
    pending_delivery: Option<Box<PendingDelivery>>,
    repair_on_install: Option<Box<Flow>>,
    pub(super) state: Option<SignerState>,
    pub(super) copies: [KeptCopy; 2],
    /// A verified first discovery can locate a service when no signed copy names one.
    pub(super) first_account_origin: Option<String>,
    /// The verified version spent by an undelivered flow (Switch spec 4.3).
    pub(super) spent_doc: Option<Box<IdentityDoc>>,
    pub(super) signed_through: Option<u64>,
    pub(super) epoch_through: Option<u64>,
}

impl RestoreLocal {
    pub(super) fn from_state(state: Option<SignerState>, identity: &[u8; 32]) -> Self {
        let copies = match &state {
            Some(state) => [
                KeptCopy::read(state.newest.as_ref().map(|newest| &newest.doc), identity),
                KeptCopy::read(state.recovery_base.as_ref(), identity),
            ],
            None => [KeptCopy::Unusable, KeptCopy::Unusable],
        };
        let mut local = Self {
            spent_doc: state
                .as_ref()
                .and_then(|s| s.spent_doc.as_ref())
                .and_then(|doc| state::stored_identity(doc, identity).ok())
                .map(Box::new),
            signed_through: state.as_ref().map(|state| state.signed_through),
            epoch_through: state.as_ref().map(|state| state.epoch_through),
            state,
            copies,
            pending_delivery: None,
            repair_on_install: None,
            first_account_origin: None,
        };
        for copy in &local.copies {
            if let KeptCopy::Verified(doc) = copy {
                local.signed_through = Some(local.signed_through.unwrap_or(0).max(doc.version()));
                local.epoch_through = Some(local.epoch_through.unwrap_or(0).max(doc.data_epoch()));
            }
        }
        local
    }

    pub(super) fn intact(state: SignerState) -> Result<Self> {
        state.check_stored_copies()?;
        let identity = state.identity;
        Ok(Self::from_state(Some(state), &identity))
    }

    pub(super) fn unusable(records: state::ReadRecords, identity: &[u8; 32]) -> Result<Self> {
        let local = Self::unusable_for_backup(records, identity)?;
        if local.pending_delivery.is_some() || local.repair_on_install.is_some() {
            return Err(Refusal::FlowInProgress.into());
        }
        Ok(local)
    }

    fn unusable_for_backup(records: state::ReadRecords, identity: &[u8; 32]) -> Result<Self> {
        let mut damaged = false;
        let flow = match records.flow {
            Ok(flow) => flow,
            Err(error) => {
                local_damage(error)?;
                damaged = true;
                None
            }
        };
        let intact_flow = match flow.as_ref().map(|flow| flow.check_copies(identity)) {
            // An unreadable origin can still be a valid URL. An independent backup must
            // bind the original signed creation before this installation can use it again.
            Some(Err(_)) if matches!(flow, Some(Flow::Enroll { .. })) => {
                let state = records.state?.ok_or(RecordsFault::Incomplete)?;
                check_local_restore(&state, false)?;
                // Repairing the original route signs nothing and leaves a retained alarm
                // for the holder. The ordinary recovery and signing gates still check it.
                if let Some(error) = gate::refusal(&state)
                    && !matches!(error, SignerError::Alarm(_))
                {
                    return Err(error);
                }
                if !state.before_first_version() {
                    return Err(Refusal::FlowInProgress.into());
                }
                let mut local = Self::intact(state)?;
                local.repair_on_install = flow.map(Box::new);
                return Ok(local);
            }
            Some(Err(error)) => {
                local_damage(error)?;
                damaged = true;
                false
            }
            Some(Ok(())) => true,
            None => false,
        };
        let state = match records.state {
            Ok(state) => state,
            Err(error) => {
                local_damage(error)?;
                damaged = true;
                None
            }
        };
        if let Some(state) = &state {
            if let Err(error) = state.check_stored_copies() {
                local_damage(error)?;
                damaged = true;
            }
        } else if flow.is_some() {
            damaged = true;
        }
        if intact_flow
            && let (Some(state), Some(flow)) = (&state, &flow)
            && let Err(error) = flow.check_state(state)
        {
            local_damage(error)?;
            damaged = true;
        }
        if !damaged {
            return Err(if state.is_some() {
                Refusal::AlreadySetUp
            } else {
                Refusal::NotSetUp
            }
            .into());
        }
        let verified_flow = flow.as_ref().filter(|_| intact_flow);
        let pending = verified_flow.is_some_and(Flow::blocks_restore);
        let mut local = Self::from_state(state, identity);
        local.first_account_origin = verified_flow
            .and_then(Flow::first_account_origin)
            .map(str::to_owned);
        // A valid signed version in an otherwise unusable flow still spent that version
        // and may have sent its epoch's keys. It is not proof that a service accepted it.
        if let Some(signed) = flow.as_ref().and_then(Flow::signed_version)
            && let Ok(doc) = state::stored_identity(signed, identity)
        {
            local.epoch_through = Some(Counter::Epoch.floor(doc.data_epoch(), local.epoch_through));
            local.signed_through =
                Some(Counter::Version.floor(doc.version(), local.signed_through));
            if local
                .spent_doc
                .as_ref()
                .is_none_or(|held| held.version() < doc.version())
            {
                local.spent_doc = Some(Box::new(doc));
            }
        }
        if pending
            && local.state.as_ref().is_none_or(|state| {
                !state.recovering
                    && !state.switch_unconfirmed
                    && state.managed_by.is_none()
                    && gate::held_alarm(state).is_none()
            })
        {
            match flow {
                Some(renewal @ Flow::Renew { .. })
                    if local.state.as_ref().is_some_and(|state| {
                        state.handed_over_to.is_none()
                            && gate::refusal(state).is_none()
                            && state.newest.as_ref().is_some_and(|n| n.account.is_none())
                    }) =>
                {
                    local.repair_on_install = Some(Box::new(renewal));
                }
                other => local.pending_delivery = other.and_then(PendingDelivery::from_flow),
            }
        }
        let blocked =
            pending && local.pending_delivery.is_none() && local.repair_on_install.is_none();
        if let Some(state) = &local.state {
            check_local_restore(state, blocked)?;
        } else if blocked {
            return Err(Refusal::FlowInProgress.into());
        }
        Ok(local)
    }
}

fn local_damage(error: SignerError) -> Result<()> {
    match error {
        SignerError::StoredData(_)
        | SignerError::Records(
            RecordsFault::Undecodable { .. }
            | RecordsFault::InvalidHeader
            | RecordsFault::OtherIdentity
            | RecordsFault::Incomplete
            | RecordsFault::Damaged(_),
        ) => Ok(()),
        other => Err(other),
    }
}

pub(super) fn restored_alerts(state: &SignerState) -> Vec<Alert> {
    state
        .alerts
        .iter()
        .filter(|alert| {
            !matches!(
                alert,
                Alert::FirstEnrollmentHeld { .. }
                    | Alert::RecordsBehind { .. }
                    | Alert::ManagedByOtherInstall { .. }
                    | Alert::RenewalsStopped { .. }
                    | Alert::LapsingWithOpenAttempts { .. }
                    | Alert::RenewalRefused { .. }
            )
        })
        .cloned()
        .collect()
}

pub(super) fn check_local_restore(state: &SignerState, has_flow: bool) -> Result<()> {
    if state.erased {
        return Err(Refusal::Erased.into());
    }
    if has_flow {
        return Err(Refusal::FlowInProgress.into());
    }
    if let Some(handing) = &state.handing_over {
        return Err(Refusal::HandingOver {
            to_app: handing.to_app,
        }
        .into());
    }
    if state.taking_over {
        return Err(Refusal::TakingOver.into());
    }
    if let Some(install) = state.handed_over_to {
        return Err(SignerError::NotNamed { install });
    }
    Ok(())
}

/// Verify a rotation before repairing its predecessor. An epoch completion requires all
/// batches stored. A removal can still owe the original signed batches to surviving apps
/// (Switch spec 3.2, 3.5, 12.2, 12.3, wire 7.4.12).
fn confirm_rotation(
    state: &SignerState,
    backup: &BackupView,
    successor: &IdentityDoc,
    batches: &[RenewBatch],
    sent: usize,
    answer: &AppsAnswer,
) -> Result<()> {
    let predecessor = &backup.identity_doc;
    let epoch = successor.data_epoch();
    let mut expected = predecessor.body().clone();
    expected.version = successor.version();
    expected.data_epoch = epoch;
    let removal = successor.body().removed != predecessor.body().removed;
    if removal {
        let found = Signer::removals(state, predecessor, &answer.apps, answer.server_time);
        if found.apps.is_empty() {
            return Err(Refusal::FlowInProgress.into());
        }
        for removed in &found.apps {
            let id = &removed.app_id;
            let status = answer.apps.iter().find(|status| &status.app_id == id);
            if !state.tombstones.contains(id)
                || !state.cleanup.contains(id)
                || status.is_none_or(|s| {
                    (s.revoked_at.is_none() && s.departed_at.is_none())
                        || s.keys_through.is_some_and(|through| through >= epoch)
                        || s.bundle_ranges.iter().any(|range| range.last >= epoch)
                })
                || state
                    .bundle_parts
                    .iter()
                    .chain(&backup.bundle_parts)
                    .any(|part| &part.app_id == id && part.last_epoch >= epoch)
            {
                return Err(Refusal::FlowInProgress.into());
            }
        }
        super::revocation::remove_from_document(&mut expected, &found.apps);
        Signer::apply_earlier_distrust(state, &mut expected);
    } else if batches.is_empty() || sent != batches.len() {
        return Err(Refusal::FlowInProgress.into());
    }
    if predecessor.data_epoch().checked_add(1) != Some(epoch)
        || epoch != state.epoch_through
        || successor.body() != &expected
        || backup
            .revoked_apps
            .iter()
            .any(|id| !state.tombstones.contains(id))
        || backup
            .certs
            .iter()
            .any(|cert| !state.certs.contains(cert.signed()))
        || state
            .bundle_parts
            .iter()
            .chain(&backup.bundle_parts)
            .any(|p| p.last_epoch > epoch)
    {
        return Err(Refusal::FlowInProgress.into());
    }
    for (index, batch) in batches.iter().enumerate() {
        let signed = batch.read(&state.identity)?;
        if signed.ops().len() != batch.parts.len() {
            return Err(Refusal::FlowInProgress.into());
        }
        for (op, part) in signed.ops().iter().zip(&batch.parts) {
            let OpKind::KeyBundlePut(put) = &op.body().kind else {
                return Err(Refusal::FlowInProgress.into());
            };
            if op.body().generation != predecessor.generation()
                || put.target_app_id != part.app_id
                || put.first_epoch != part.first_epoch
                || put.last_epoch != part.last_epoch
                || put.last_epoch > epoch
                || successor.listed_cert(&part.app_id) != Some(part.cert)
                || (index < sent && !state.bundle_parts.contains(part))
            {
                return Err(Refusal::FlowInProgress.into());
            }
        }
    }
    for listed in &successor.body().apps {
        let status = answer
            .apps
            .iter()
            .find(|s| s.app_id == listed.app_id)
            .ok_or(Refusal::FlowInProgress)?;
        if !status.current
            || status.revoked_at.is_some()
            || status.departed_at.is_some()
            || state.tombstones.contains(&listed.app_id)
            || state.revoking.iter().any(|r| r.app_id == listed.app_id)
        {
            return Err(Refusal::FlowInProgress.into());
        }
        if status.keys_through.is_some_and(|held| held > epoch)
            || status.bundle_ranges.iter().any(|range| range.last > epoch)
        {
            return Err(Refusal::FlowInProgress.into());
        }
        // Approval lists the app before it joins. The removal sends no rotation bundle
        // to an app for which the service has never taken a record (wire 3.5, 7.4.12).
        if removal && status.record_cert.is_none() {
            if status.record_at.is_some()
                || status.last_seen.is_some()
                || status.full_bundle_requested.is_some()
                || !status.bundle_ranges.is_empty()
                || status.keys_through.is_some_and(|held| held >= epoch)
                || batches
                    .iter()
                    .flat_map(|b| &b.parts)
                    .chain(&state.bundle_parts)
                    .chain(&backup.bundle_parts)
                    .any(|part| part.app_id == listed.app_id)
            {
                return Err(Refusal::FlowInProgress.into());
            }
            continue;
        }
        if status.record_cert != Some(listed.cert) {
            return Err(Refusal::FlowInProgress.into());
        }
        let (held, mut parts) =
            super::renewal::listed_bundle_ranges(&state.bundle_parts, listed, status);
        // On acknowledgement a new range replaces overlapping parts for this app (wire 6.2).
        // Count only keys that will remain when the signed suffix has been accepted.
        for pending in batches
            .iter()
            .skip(sent)
            .flat_map(|batch| &batch.parts)
            .filter(|part| part.app_id == listed.app_id)
        {
            parts
                .retain(|(first, last)| *last < pending.first_epoch || pending.last_epoch < *first);
            parts.push((pending.first_epoch, pending.last_epoch));
        }
        let held = held
            .filter(|_| status.full_bundle_requested.is_none())
            .unwrap_or(0);
        if held < epoch
            && !pubky_switch_core::records::missing_ranges(&parts, held + 1, epoch).is_empty()
        {
            return Err(Refusal::FlowInProgress.into());
        }
    }
    Ok(())
}

impl Signer {
    /// Set up this install from the signer backup on the Homeserver, for an identity whose
    /// key `keyring` holds and whose records this store doesn't hold, as on a new device
    /// (Switch spec 12.8, Switch wire 3.13). This install gets a signer ID of its own.
    ///
    /// With the user's [`KeyRecoveryConfirmed`] in `confirmed`, a backup that is missing,
    /// unreadable or stale is recovered from with the key alone instead
    /// ([`Signer::survey_key_recovery_new`]), and a recovery a crash left on this store goes
    /// on; a backup the switch's copy matches is restored from as without it.
    ///
    /// Close an open signer for this identity first ([`Signer::close`]): while one owns its
    /// records, this call is refused with `StoreError::InUse`.
    ///
    /// # Errors
    ///
    /// [`Refusal::AlreadySetUp`] when the store holds records for this identity, but those of
    /// a recovery with the key alone in progress under a key confirmation; otherwise as
    /// [`Signer::restore`].
    pub async fn restore_new(
        env: SignerEnv,
        keyring: IdentityKeyring,
        confirmed: impl Into<RestoreConfirmed>,
    ) -> Result<Self> {
        let identity = keyring.public_key();
        let store = env
            .store
            .acquire(&state::signer_namespace(&identity))
            .await?;
        let key = confirmed.into().0;
        // A provider loss's confirmation is no confirmation of a restore (Switch spec 12.8).
        if key
            .as_ref()
            .is_some_and(KeyRecoveryConfirmed::is_provider_loss)
        {
            return Err(Refusal::KeyRecovery(KeyRecoveryStop::SurveyChanged).into());
        }
        if state::set_up(&store, &identity).await? {
            return match key {
                Some(key) => Box::pin(Self::continue_fresh(env, keyring, store, key)).await,
                None => Err(Refusal::AlreadySetUp.into()),
            };
        }
        let mut signer = Self::restore_target(env, keyring, store)?;
        match (signer.restore_records(None, key.is_some()).await, key) {
            (Err(error), Some(key)) if backup_refused(&error) => {
                Box::pin(signer.recover_with_key(Found::Fresh(None), key)).await?;
            }
            (result, _) => drop(result?),
        }
        Ok(signer)
    }

    /// Restore over records this call itself proves unusable, after the user accepts the
    /// losses (Switch spec 12.8, Switch wire 3.13). Readable local restrictions remain binding.
    /// A renewal whose predecessor lost only its account binding resumes on the original
    /// install when its backup and serving account verify the predecessor.
    /// A spent epoch can finish its signed delivery on that install once every key batch was
    /// stored and the original account confirms the listed apps' coverage.
    /// An interrupted app removal can resume its original bundles for the remaining apps
    /// when the signed removal matches the service's cutoffs and the saved cleanup.
    /// A damaged origin in a signed first creation can be repaired from a current backup at
    /// that original account. The same installation keeps its pending creation for the user.
    /// On an idle signing installation with a held alarm, the backup and original account
    /// may confirm the missing binding of its high-water document. The alarm stays held.
    /// The same namespace owner is retained through the first atomic replacement and retry.
    /// No record is deleted before the verified replacement is committed.
    ///
    /// Close an open signer for this identity first ([`Signer::close`]): while one owns its
    /// records, this call is refused with `StoreError::InUse`.
    ///
    /// # Errors
    ///
    /// [`Refusal::AlreadySetUp`] for usable records, [`Refusal::NotSetUp`] for an empty store;
    /// a host read failure never permits replacement. Intact flows, erasure, hand-over,
    /// take-over, security alarms and known version or epoch floors still constrain it.
    /// A completed hand-over refuses with [`SignerError::NotNamed`]. Otherwise as
    /// [`Signer::restore`]. An unknown write requires reopening the actual stored result;
    /// repeating this entry cannot replace a successfully committed usable candidate. With
    /// a key recovery confirmed too ([`RecordsDiscarded::and_key_recovery`]), as
    /// [`Signer::restore_new`] with one: the versions and epochs the readable records spent bind it.
    pub async fn restore_over_unusable(
        env: SignerEnv,
        keyring: IdentityKeyring,
        confirmed: RecordsDiscarded,
    ) -> Result<Self> {
        let identity = keyring.public_key();
        let store = env
            .store
            .acquire(&state::signer_namespace(&identity))
            .await?;
        if confirmed
            .0
            .as_ref()
            .is_some_and(KeyRecoveryConfirmed::is_provider_loss)
        {
            return Err(Refusal::KeyRecovery(KeyRecoveryStop::SurveyChanged).into());
        }
        let records = state::read(&store, &identity).await?;
        let idle = matches!(records.flow, Ok(None));
        let mut local = match (
            RestoreLocal::unusable_for_backup(records, &identity),
            confirmed.0.clone(),
        ) {
            (Err(SignerError::Refused(Refusal::AlreadySetUp)), Some(key)) => {
                return Box::pin(Self::continue_fresh(env, keyring, store, key)).await;
            }
            (local, _) => local?,
        };
        let mut signer = Self::restore_target(env, keyring, store)?;
        if let Some(flow) = local.repair_on_install.take() {
            let state = local.state.take().ok_or(Refusal::FlowInProgress)?;
            if matches!(*flow, Flow::Enroll { .. }) {
                return Box::pin(signer.repair_first_origin(state, *flow)).await;
            }
            return Box::pin(signer.restore_renewal(state, *flow)).await;
        }
        let restored = if idle
            && let Some(state) = local.state.take_if(|state| {
                state
                    .newest
                    .as_ref()
                    .is_some_and(|newest| newest.account.is_none())
                    && matches!(gate::refusal(state), Some(SignerError::Alarm(_)))
            }) {
            Box::pin(signer.repair_alarmed_account(state)).await
        } else {
            Box::pin(signer.restore_records(Some(local), confirmed.0.is_some()))
                .await
                .map(drop)
        };
        match (restored, confirmed.0) {
            (Err(error), Some(key)) if backup_refused(&error) => {
                let local = RestoreLocal::unusable(
                    state::read(&signer.store, &identity).await?,
                    &identity,
                )?;
                let local = Some(Box::new(local));
                Box::pin(signer.recover_with_key(Found::Fresh(local), key)).await?;
            }
            (result, _) => result?,
        }
        Ok(signer)
    }

    /// Restore only the missing original account of this install's own signed document.
    /// The holder must still acknowledge the alarm (Switch spec 4.3, account binding 2).
    async fn repair_alarmed_account(&mut self, mut state: SignerState) -> Result<()> {
        let held = gate::held_alarm(&state)
            .cloned()
            .ok_or(RecordsFault::Incomplete)?;
        let newest = state.newest.as_mut().ok_or(RecordsFault::Incomplete)?;
        let bytes = self
            .env
            .homeserver
            .get(SIGNER_BACKUP_PATH)
            .await
            .map_err(SignerError::Homeserver)?
            .ok_or(Refusal::NoBackup)?;
        let view = self.open_backup(&bytes)?.ok_or(Refusal::UnreadableBackup)?;
        let account = view.service();
        let doc = &view.identity_doc;
        Counter::Version.repair(doc.version(), &mut state.signed_through);
        if doc.signed() != &newest.doc
            || doc.body().signer != state.install
            || doc.version() != state.signed_through
            || state.service.as_ref() != Some(&account)
            || view.prev != newest.prev
        {
            return Err(SignerError::Alarm(held));
        }
        let client = self.account_client(&account)?;
        newest.account = Some(account);
        state.check_stored_copies()?;
        let current = client.apps().await?;
        if current.identity.as_ref() != Some(doc.signed()) {
            return Err(SignerError::Alarm(held));
        }
        self.check_published_restore_doc(doc).await?;
        // No flow completed. Keep the saved approvals and certificates with their alarm.
        state::save(&mut self.store, &state, None).await?;
        self.state = state;
        Ok(())
    }

    async fn restore_renewal(mut self, mut state: SignerState, flow: Flow) -> Result<Self> {
        Box::pin(self.bind_renewal_predecessor(&mut state, &flow)).await?;
        self.commit(state, Some(flow)).await?;
        Box::pin(self.resume()).await?;
        Ok(self)
    }

    /// Recover the binding of the exact predecessor from its sealed backup. The original
    /// install still owns the renewal and retries the batches it signed (Switch spec 3.2,
    /// 12.8, Switch account-binding 2).
    async fn bind_renewal_predecessor(&self, state: &mut SignerState, flow: &Flow) -> Result<()> {
        let Flow::Renew {
            account,
            prev: Some(prev),
            doc,
            batches,
            sent,
        } = flow
        else {
            return Err(Refusal::FlowInProgress.into());
        };
        // A certificate renewal starts with cert.put. A rotation has only key bundles and
        // may need none if no app remains to receive keys (Switch spec 3.2, 12.2).
        let first = batches
            .first()
            .map(|batch| batch.read(&state.identity))
            .transpose()?;
        let certificate = match first
            .as_ref()
            .and_then(|batch| batch.ops().first())
            .map(|op| &op.body().kind)
        {
            Some(OpKind::CertPut {
                target_app_id,
                cert,
            }) => Some((
                *target_app_id,
                cert.doc_hash().map_err(|_| Refusal::FlowInProgress)?,
            )),
            Some(OpKind::KeyBundlePut(_)) | None => None,
            _ => return Err(Refusal::FlowInProgress.into()),
        };
        let successor = state::stored_identity(doc, &state.identity)?;
        if certificate.is_some_and(|(target, replacement)| {
            successor.listed_cert(&target) != Some(replacement)
        }) {
            return Err(Refusal::FlowInProgress.into());
        }
        let newest = state.newest.as_ref().ok_or(Refusal::FlowInProgress)?;
        let bytes = self
            .env
            .homeserver
            .get(SIGNER_BACKUP_PATH)
            .await
            .map_err(SignerError::Homeserver)?
            .ok_or(Refusal::FlowInProgress)?;
        let view = self.open_backup(&bytes)?.ok_or(Refusal::FlowInProgress)?;
        let predecessor = &view.identity_doc;
        crate::counters::check_copy(&successor, Some(predecessor), 1)?;
        Counter::Version.repair(successor.version(), &mut state.signed_through);
        Counter::Epoch.repair(successor.data_epoch(), &mut state.epoch_through);
        let local = RestoreLocal::from_state(Some(state.clone()), &state.identity);
        if let Some((target, replacement)) = certificate {
            let original = predecessor
                .listed_cert(&target)
                .ok_or(Refusal::FlowInProgress)?;
            if original == replacement
                || !successor.body().renewed.iter().any(|renewed| {
                    renewed.app_id == target && renewed.cert == original && renewed.until.is_none()
                })
            {
                return Err(Refusal::FlowInProgress.into());
            }
        }
        if predecessor.signed() != &newest.doc
            || predecessor.hash() != *prev
            || predecessor.body().signer != state.install
            || view.service() != *account
            || state.service.as_ref() != Some(account)
            || successor.body().signer != state.install
            || successor.generation() != predecessor.generation()
            || successor.version() <= predecessor.version()
            || successor.version() != state.signed_through
            || *sent > batches.len()
        {
            return Err(Refusal::FlowInProgress.into());
        }
        let answer = self.account_client(account)?.apps().await?;
        if answer.identity.as_ref() != Some(&newest.doc) {
            return Err(Refusal::FlowInProgress.into());
        }
        if certificate.is_none() {
            if newest.prev != view.prev || local.epoch_through != Some(successor.data_epoch()) {
                return Err(Refusal::FlowInProgress.into());
            }
            confirm_rotation(state, &view, &successor, batches, *sent, &answer)?;
        }
        self.check_restore(&view, answer.identity.as_ref(), Some(&local))
            .await?;
        state
            .newest
            .as_mut()
            .ok_or(Refusal::FlowInProgress)?
            .account = Some(view.service());
        state.check_stored_copies()
    }

    pub(super) fn restore_target(
        env: SignerEnv,
        keyring: IdentityKeyring,
        store: OwnedStoreHandle,
    ) -> Result<Self> {
        let identity = keyring.public_key();
        let install = pubky_switch_core::enc::random_bytes::<16>()?;
        Ok(Self {
            store,
            env,
            keyring,
            state: SignerState::new(identity, install),
            flow: None,
            unsure: false,
            left: super::RunDue::default(),
            run: std::sync::Arc::default(),
        })
    }

    /// Restore this install's records from the signer backup on the Homeserver, in place:
    /// when they are behind a newer version of its own ([`Alert::RecordsBehind`]), or when
    /// another install signs and the user has this one take over (Switch spec 12.8, Switch
    /// wire 3.13). Returns the version this install delivers as the signer. A backup written
    /// mid-recovery, holding the recovery's version, restores as that recovery in progress
    /// (Switch spec 12.6 step 1): its version is delivered first, and when the service it
    /// names doesn't take it, the restore returns it, the recovery to be resumed or declared
    /// again ([`crate::SignerStatus::Recovering`], [`crate::SignerStatus::RecoveryRefused`]).
    ///
    /// # Errors
    ///
    /// [`Refusal::Erased`] once the account is erased; [`Refusal::FlowInProgress`] while a
    /// flow is in progress; [`Refusal::HandingOver`] or
    /// [`Refusal::TakingOver`] while a hand-over is in progress, which the abort or the
    /// take-over ends; [`Refusal::NoBackup`] when the
    /// Homeserver holds none; [`Refusal::UnreadableBackup`] for one that doesn't open or
    /// verify; [`Refusal::StaleBackup`] when the switch's or the Homeserver's copy is past it;
    /// otherwise as [`Signer::resume`].
    ///
    /// With the user's [`KeyRecoveryConfirmed`] in `confirmed`, a backup that is missing,
    /// unreadable or stale is recovered from with the key alone instead
    /// ([`Signer::survey_key_recovery`]), and such a recovery in progress goes on with it; a
    /// backup the switch's copy matches is restored from as without it.
    pub async fn restore(&mut self, confirmed: impl Into<RestoreConfirmed>) -> Result<IdentityDoc> {
        self.refresh().await?;
        let key = confirmed.into().0;
        // A provider loss's confirmation is no confirmation of a restore (Switch spec 12.8).
        if key
            .as_ref()
            .is_some_and(KeyRecoveryConfirmed::is_provider_loss)
        {
            return Err(Refusal::KeyRecovery(KeyRecoveryStop::SurveyChanged).into());
        }
        if let (Some(key), Some(Flow::KeyRecover { .. })) = (&key, &self.flow) {
            return Box::pin(self.continue_key_recovery(key.clone())).await;
        }
        check_local_restore(
            &self.state,
            self.flow.as_ref().is_some_and(Flow::blocks_restore),
        )?;
        let local = RestoreLocal::intact(self.state.clone())?;
        match (self.restore_records(Some(local), key.is_some()).await, key) {
            (Err(error), Some(key)) if backup_refused(&error) => {
                Box::pin(self.recover_with_key(Found::InPlace, key)).await
            }
            (result, _) => result,
        }
    }

    /// The restore from the backup, the doc of [`Signer::restore`]. Under the user's
    /// confirmation of a recovery with the key alone, `key_confirmed`, a backup its own
    /// service can't check is refused as stale, and the recovery goes on without it: one
    /// that service refuses for good, or, unreachable or failing for now, one naming another
    /// service or key than the newest copy the install reads, as a backup from before a move
    /// does. The service that copy names failing for now fails the recovery too: that error
    /// is returned, and the restore tried again.
    async fn restore_records(
        &mut self,
        local: Option<RestoreLocal>,
        key_confirmed: bool,
    ) -> Result<IdentityDoc> {
        let identity = self.state.identity;
        let bytes = self
            .env
            .homeserver
            .get(SIGNER_BACKUP_PATH)
            .await
            .map_err(SignerError::Homeserver)?;
        let view = match local
            .as_ref()
            .and_then(|local| local.pending_delivery.as_deref())
        {
            Some(delivery) => delivery.open(&self.keyring, bytes.as_deref())?,
            None => self
                .open_backup(&bytes.ok_or(Refusal::NoBackup)?)?
                .ok_or(Refusal::UnreadableBackup)?,
        };
        let service = view.service();
        let target = Target {
            origin: &service.origin,
            pinned: Some(service.service_key),
            created: Some(service.created),
            identity,
        };
        let mut serving = None;
        let answer = match RequestClient::new(&self.env, &target, &self.keyring, &self.store)?
            .apps()
            .await
        {
            Ok(answer) => answer,
            // A backup written mid-recovery names the service the recovery went to, which
            // holds a staged account and no document until it takes that version, or which
            // can't be reached: it shows no copy, so the version is delivered first, and the
            // recovery is in progress again (Switch spec 12.6 step 1, wire 3.13, 7.3).
            Err(
                ClientError::Switch {
                    code: ErrorCode::Staged,
                    ..
                }
                | ClientError::Transport(_),
            ) if is_recovery(&view) => no_copy(),
            // In place, before the service takes the version, its notice for the lost
            // generation or the version's counts as no copy (Switch wire 3.13).
            Err(ClientError::Switch {
                code: ErrorCode::RecoveryRequired,
                current,
                ..
            }) if notice_before_the_recovery(&view, &current) => no_copy(),
            // A recovery declared at the service that served the lost generation, after that
            // service changed its key (Switch spec 12.5): the version names the new key, and
            // the service answers under the key it served with until it takes the version
            // (Switch wire 3.13, 7.4.1, 7.4.2).
            Err(error @ ClientError::BadServiceSignature { .. }) if is_recovery(&view) => {
                match self.serving_key_in_place(&view).await? {
                    Some(key) => {
                        serving = Some(key);
                        self.apps_under_serving_key(&view, key).await?
                    }
                    None => return Err(error.into()),
                }
            }
            Err(error) => {
                if key_confirmed && self.unchecked_backup(&view, &error, local.as_ref()).await? {
                    return Err(Refusal::StaleBackup.into());
                }
                return Err(error.into());
            }
        };
        Box::pin(self.restore_from_copy(view, answer, local, serving)).await
    }

    /// Restore the opened backup against the answer authenticated for its original account.
    pub(super) async fn restore_from_copy(
        &mut self,
        view: BackupView,
        answer: AppsAnswer,
        mut local: Option<RestoreLocal>,
        serving: Option<[u8; 32]>,
    ) -> Result<IdentityDoc> {
        let identity = self.state.identity;
        let doc = view.identity_doc.clone();
        let service = view.service();
        // In place, the service still serves the lost generation until it takes the version:
        // its copy of that generation counts as no copy (Switch wire 3.13).
        let answer = without_the_lost_copy(&view, answer, &identity);
        let first = self
            .check_restore(&view, answer.identity.as_ref(), local.as_ref())
            .await?;
        let mut state =
            self.rebuilt_records(&view, &answer, service.clone(), local.as_ref(), true)?;
        let kept = local.as_ref().and_then(|local| local.state.as_ref());
        // A backup written mid-recovery holds the recovery's version, which the service it
        // names doesn't hold yet: the recovery is in progress again, delivered first, and
        // declared again elsewhere if that service refuses it (Switch spec 12.6 step 1).
        if first == Some(None)
            && is_recovery(&view)
            && let Some(lost) = doc.body().recovery_from
        {
            state.recovering = true;
            state.recovery_base = Some(doc.signed().clone());
            state.lost_generation = Some(lost);
            // The services this recovery enrolled at, kept in place for the same lost
            // generation, and the one the backup's version names, under its key: declared
            // again at one, it is read under that key first.
            if let Some(kept) = kept
                && kept.recovering
                && kept.lost_generation == Some(lost)
            {
                state.recovery_services.clone_from(&kept.recovery_services);
            }
            if let Some(service) = state.service.clone()
                && !state.recovery_services.contains(&service)
            {
                state.recovery_services.push(service);
            }
            // In place after a service key change, the service answers under the key it
            // served the lost generation with until it takes the version: that key is pinned
            // for it meanwhile (Switch wire 3.13, 7.4.2).
            state.recovery_serving = serving.and_then(|key| {
                state.service.clone().map(|service| Service {
                    service_key: key,
                    ..service
                })
            });
        }
        state.newest = Some(Newest {
            account: Some(service.clone()),
            doc: doc.signed().clone(),
            prev: view.prev,
            published: false,
            delivered_at: None,
        });
        state.next_version(doc.version())?;
        // The opened backup independently authenticates this exact delivery (Switch wire 3.13).
        if first.is_some() {
            crate::counters::check_copy(&doc, Some(&view.identity_doc), 1)?;
        }
        // The version the backup holds goes first when the switch is at the one before.
        let deliver_first = first.map(|prev| Flow::Deliver {
            account: service,
            doc: doc.signed().clone(),
            prev,
            backup: local
                .as_mut()
                .and_then(|local| local.pending_delivery.take())
                .map(|delivery| delivery.backup),
            step: DeliverStep::BackupWritten,
        });
        let recovering = state.recovering;
        self.commit(state, deliver_first).await?;
        match Box::pin(self.finish_flow()).await {
            Ok(()) => {}
            // The recovery's version wasn't taken: the restore is done, the recovery in
            // progress, resumed or declared again at another service from here.
            Err(error @ SignerError::Refused(Refusal::CounterCopyNeeded { .. })) => {
                return Err(error);
            }
            Err(_) if recovering => return Ok(doc),
            Err(error) => return Err(error),
        }

        let next = self.sign_own_version().await?;
        Box::pin(self.resume()).await?;
        Ok(next)
    }

    /// Whether the backup `view` can't be checked at the service it names, which answered
    /// `error` (the doc of [`Signer::restore_records`]), with `local` what in-place or
    /// unusable records keep.
    async fn unchecked_backup(
        &self,
        view: &BackupView,
        error: &ClientError,
        local: Option<&RestoreLocal>,
    ) -> Result<bool> {
        let transient = matches!(
            error,
            ClientError::Transport(_) | ClientError::Switch { status: 500.., .. }
        );
        if !transient {
            return Ok(true);
        }
        let identity = self.state.identity;
        let published = self
            .env
            .homeserver
            .get(IDENTITY_PATH)
            .await
            .map_err(SignerError::Homeserver)?
            .and_then(|bytes| serde_json::from_slice::<SignedDoc>(&bytes).ok())
            .and_then(|signed| IdentityDoc::verify(&signed, &identity).ok());
        let kept = local
            .into_iter()
            .flat_map(|local| &local.copies)
            .filter_map(|copy| match copy {
                KeptCopy::Verified(doc) => Some(doc.as_ref()),
                _ => None,
            });
        let newest = published
            .iter()
            .chain(std::iter::once(&view.identity_doc))
            .chain(kept)
            .max_by_key(|doc| (doc.generation(), doc.version()));
        Ok(newest.is_some_and(|doc| doc.inbox() != view.identity_doc.inbox()))
    }

    /// The records a restore takes from `view`, the backup's or those a recovery with the
    /// key alone found, the switch's `GET /apps` answer `answer`, and, in place or over
    /// unusable records, what `local` keeps binding (Switch wire 3.13 "Restoring"). The
    /// caller sets `newest`; the version naming this install is owed. With `epochs_bound`,
    /// local epochs past the one after `view`'s refuse it as stale; a provider loss, which
    /// builds on the highest copy there is, keeps them as its floor instead.
    pub(super) fn rebuilt_records(
        &self,
        view: &BackupView,
        answer: &AppsAnswer,
        service: Service,
        local: Option<&RestoreLocal>,
        epochs_bound: bool,
    ) -> Result<SignerState> {
        let doc = &view.identity_doc;
        // Revoked for good: the backup's, `identity_doc`'s `removed`, what the switch shows,
        // and, in place, this install's own, with the revocations it asked for and the
        // deletions it owes: one whose record is gone already still owes its grant reminder,
        // which `deletion_checks`, finding no record, wouldn't raise.
        let mut tombstones = view.revoked_apps.clone();
        tombstones.extend(doc.body().removed.iter().map(|r| r.app_id));
        tombstones.extend(removed_at_switch(answer, doc));
        let kept = local.and_then(|local| local.state.as_ref());
        let cleanup = if let Some(kept) = kept {
            tombstones.extend(kept.tombstones.iter().copied());
            kept.cleanup.clone()
        } else {
            Vec::new()
        };
        let mut state = self.taken_records(view, answer, service, tombstones, cleanup)?;
        if let Some(local) = local {
            state.spent_doc = local.spent_doc.as_ref().map(|doc| doc.signed().clone());
            if let Some(epoch) = local.epoch_through {
                let epoch = Counter::Epoch.floor(doc.data_epoch(), Some(epoch));
                if epochs_bound && epoch > doc.data_epoch().saturating_add(1) {
                    return Err(Refusal::StaleBackup.into());
                }
                state.epoch_through = state.epoch_through.max(epoch);
            }
            if let Some(version) = local.signed_through {
                state.signed_through = state.signed_through.max(
                    Counter::Version.floor(state.verified_version(doc.version())?, Some(version)),
                );
            }
        }
        if let Some(kept) = kept {
            for alert in restored_alerts(kept) {
                state.alert(alert);
            }
        }
        // The first commit must also tell a restart to finish taking over (Switch wire 3.13).
        state.owes_own_version = true;
        // In place, the revocations this install asked for stay as they were, with their
        // alerts; those only the backup names are added. Where both picked a time to distrust
        // an app from, the earlier wins: after a compromise it trusts less, and two installs
        // that disagree never trust more than either asked (Switch wire 3.12).
        if let Some(kept) = kept {
            for carried in &kept.revoking {
                if let Some(rebuilt) = state
                    .revoking
                    .iter_mut()
                    .find(|r| r.app_id == carried.app_id)
                {
                    let backed_up = rebuilt.distrust_from;
                    rebuilt.clone_from(carried);
                    rebuilt.distrust_from = match (carried.distrust_from, backed_up) {
                        (Some(own), Some(theirs)) => Some(own.min(theirs)),
                        (own, theirs) => own.or(theirs),
                    };
                    state.alerts.retain(|alert| {
                        !matches!(alert, Alert::RevocationPending { app_id, at_switch: false }
                            if *app_id == carried.app_id)
                            || kept.alerts.contains(alert)
                    });
                } else {
                    state.revoking.push(carried.clone());
                }
            }
        }
        Ok(state)
    }

    /// The next version, naming this install as the signer, committed for delivery: a
    /// restore's, or a restore's recovery taken later (Switch wire 3.13). It races any other
    /// signer, so its backup is owed, and written by `resume` once the delivery has won.
    pub(super) async fn sign_own_version(&mut self) -> Result<IdentityDoc> {
        let key = self.signing_key()?;
        let (next, flow) = self.next_version_closing(&key, |_| {})?;
        drop(key);
        let Flow::Deliver {
            account,
            doc: signed,
            prev,
            ..
        } = flow
        else {
            return Err(SignerError::Records(RecordsFault::Invariant(
                "a version without its delivery",
            )));
        };
        let mut state = self.state.clone();
        state.signed_through = next.version();
        state.backup_owed = true;
        state.owes_own_version = false;
        let flow = Flow::Deliver {
            account,
            doc: signed,
            prev,
            backup: None,
            step: DeliverStep::BackupWritten,
        };
        self.commit(state, Some(flow)).await?;
        Ok(next)
    }

    /// The records an install takes from records it received or restored, `view`, and the
    /// switch's `GET /apps` answer `apps` (Switch wire 3.12, 3.13), with `tombstones` the App
    /// IDs revoked for good and `cleanup` the deletions owed already. The versions this
    /// install spent stay spent; of its alerts, those about the records taken over go. The
    /// caller sets `newest`.
    ///
    /// - The apps the document lists get no listing floor for their removal time: the time
    ///   they were first listed is unknown here, and a reported time before it changes
    ///   nothing anyway (Switch spec 12.3).
    /// - The epoch floor is the highest epoch whose keys were sent, by the records or as the
    ///   switch shows, and never more than one past `data_epoch`, since epochs never skip
    ///   (Switch spec 3.2, 3.5).
    /// - A removed app's record may still be on the Homeserver: the routine run checks, a few
    ///   at a time, and owes its deletion with its grant reminder raised once more, since
    ///   this install can't tell the user saw it. Taking over doesn't wait for that.
    pub(super) fn taken_records(
        &self,
        view: &BackupView,
        apps: &AppsAnswer,
        service: Service,
        mut tombstones: Vec<[u8; 16]>,
        cleanup: Vec<[u8; 16]>,
    ) -> Result<SignerState> {
        let doc = &view.identity_doc;
        let mut state = SignerState::new(self.state.identity, self.state.install);
        state.signed_through =
            Counter::Version.floor(doc.version(), Some(self.state.signed_through));
        state.alerts = restored_alerts(&self.state);
        state.service = Some(service);
        state.certs = view.certs.iter().map(|c| c.signed().clone()).collect();
        // The install the records came from published its versions (Switch wire 3.12, 3.13).
        state.ever_published = true;
        state.bundle_parts = view.bundle_parts.clone();
        state.cleanup = cleanup;
        tombstones.sort_unstable();
        tombstones.dedup();
        state.listed_at = doc.body().apps.iter().map(|a| (a.app_id, 0)).collect();
        let claimed = view
            .bundle_parts
            .iter()
            .map(|p| p.last_epoch)
            .chain(apps.apps.iter().filter_map(|s| s.keys_through))
            .chain(
                apps.apps
                    .iter()
                    .flat_map(|s| s.bundle_ranges.iter().map(|r| r.last)),
            )
            .fold(doc.data_epoch(), u64::max);
        let epoch = doc.data_epoch();
        let step = u64::from(claimed > epoch && epoch < pubky_switch_core::json::MAX_INT);
        let most = Counter::Epoch.next(epoch, None, step)?;
        if claimed > most {
            state.alert(Alert::EpochFloorBounded {
                claimed,
                kept: most,
            });
        }
        state.epoch_through = claimed.min(most);
        // A damaged range cannot establish which keys its ciphertext actually carries.
        state.bundle_parts.retain(|part| part.last_epoch <= most);
        state.deletion_checks = tombstones
            .iter()
            .copied()
            .filter(|app| doc.listed_cert(app).is_none() && !state.cleanup.contains(app))
            .collect();
        // A revocation the records named but no version carried out yet: its App ID is a
        // tombstone the document still lists. It is pending again, sent to the switch and
        // completed by the version removing the app, its alert shown meanwhile (Switch spec
        // 12.2). The time the user picked to distrust it from comes with it; records written
        // without one give it the switch's revocation time.
        for app_id in view
            .revoked_apps
            .iter()
            .copied()
            .filter(|app| doc.listed_cert(app).is_some())
        {
            if !state.revoking.iter().any(|r| r.app_id == app_id) {
                let picked = view
                    .pending_distrust
                    .iter()
                    .find(|p| p.app_id == app_id)
                    .map(|p| p.distrust_from);
                state.revoking.push(Revoking {
                    app_id,
                    distrust_from: picked,
                    revoked_at: None,
                    taken: false,
                });
                state.alert(Alert::RevocationPending {
                    app_id,
                    at_switch: false,
                });
            }
        }
        state.tombstones = tombstones;
        Ok(state)
    }

    /// The key the service a backup's recovery went to served the lost generation with,
    /// when that recovery is in place, at the service that served it (Switch wire 3.13): the
    /// key a copy of `identity.json` names that the identity key signed at the lost
    /// generation, at the origin the backup's version names and below its version: the
    /// Homeserver's copy. Any other key is never taken.
    async fn serving_key_in_place(&self, view: &BackupView) -> Result<Option<[u8; 32]>> {
        let doc = &view.identity_doc;
        let Some(lost) = doc.body().recovery_from else {
            return Ok(None);
        };
        self.lost_generations_key_on_homeserver(&doc.inbox().url, lost, doc.version())
            .await
    }

    /// `GET /apps` read again under `serving`, the key the recovery's service served the
    /// lost generation with before it changed its key (Switch wire 3.13): its copy of the
    /// lost generation, below the backup's version, and a signed `503 recovery_required`
    /// naming the lost generation or the backup's show no copy, and the restore is that
    /// recovery in progress again. Another copy is judged as every switch's copy is, and
    /// refuses the restore.
    async fn apps_under_serving_key(
        &self,
        view: &BackupView,
        serving: [u8; 32],
    ) -> Result<AppsAnswer> {
        let identity = self.state.identity;
        let doc = &view.identity_doc;
        let origin = doc.inbox().url.clone();
        let target = Target {
            origin: &origin,
            pinned: Some(serving),
            created: Some(view.account_created),
            identity,
        };
        match RequestClient::new(&self.env, &target, &self.keyring, &self.store)?
            .apps()
            .await
        {
            Ok(answer) => Ok(without_the_lost_copy(view, answer, &identity)),
            Err(ClientError::Switch {
                code: ErrorCode::RecoveryRequired,
                current,
                ..
            }) if notice_before_the_recovery(view, &current) => Ok(no_copy()),
            Err(error) => Err(error.into()),
        }
    }

    /// The checks a restore passes before it takes the backup's records (Switch wire 3.13
    /// "Restoring"). They are its only guard: once the records are replaced, the signing gate
    /// passes by construction. Returns, when the backup's own version is to be delivered
    /// first, the `prev` it builds on.
    ///
    /// - In place, the records' own state: no alarm's alert stands, since a restore never
    ///   clears one, and the backup isn't below the mark, by version or generation, nor
    ///   another body at its version, nor below a newer version of this install's own the
    ///   switch showed (`RecordsBehind`) (Switch wire 3.3 "Never back").
    /// - The switch's copy, `held`, is the backup's version, or the one it builds on, or
    ///   none under a backup of the account's first version.
    /// - The Homeserver's copy is neither newer than the backup's version nor another
    ///   document at it.
    async fn check_restore(
        &self,
        view: &BackupView,
        held: Option<&SignedDoc>,
        local: Option<&RestoreLocal>,
    ) -> Result<Option<Option<[u8; 32]>>> {
        let identity = self.state.identity;
        let doc = &view.identity_doc;
        if let Some(local) = local {
            if let Some(state) = &local.state {
                if let Some(alarm) = gate::held_alarm(state) {
                    return Err(SignerError::Alarm(alarm.clone()));
                }
                if let Some(seen) = state.records_behind
                    && doc.version() < Counter::Version.floor(doc.version(), Some(seen))
                {
                    return Err(Refusal::StaleBackup.into());
                }
            }
            for copy in &local.copies {
                if let KeptCopy::Verified(mark) = copy {
                    let below = doc.version() < mark.version()
                        || doc.generation() < mark.generation()
                        || (doc.version() == mark.version() && doc.body_hash() != mark.body_hash());
                    if below {
                        return Err(Refusal::StaleBackup.into());
                    }
                }
            }
        }
        let held = held
            .map(|signed| IdentityDoc::verify(signed, &identity))
            .transpose()?;
        let first = match (&held, view.prev) {
            (Some(copy), _) if copy.hash() == doc.hash() => None,
            (Some(copy), Some(prev)) if copy.hash() == prev => Some(view.prev),
            (None, None) => Some(None),
            _ => return Err(Refusal::StaleBackup.into()),
        };
        self.check_published_restore_doc(doc).await?;
        Ok(first)
    }

    async fn check_published_restore_doc(&self, doc: &IdentityDoc) -> Result<()> {
        if let Some(copy) = self
            .env
            .homeserver
            .get(IDENTITY_PATH)
            .await
            .map_err(SignerError::Homeserver)?
            .and_then(|bytes| serde_json::from_slice::<SignedDoc>(&bytes).ok())
            .and_then(|signed| IdentityDoc::verify(&signed, &self.state.identity).ok())
        {
            let past = copy.version() > doc.version()
                || copy.generation() > doc.generation()
                || (copy.version() == doc.version() && copy.hash() != doc.hash());
            if past {
                return Err(Refusal::StaleBackup.into());
            }
        }
        Ok(())
    }

    /// Write the backup a restore owes, holding the newest version, once its delivery has won
    /// (Switch wire 3.13 "When it is written"). It passes the checks of every backup write
    /// first ([`Signer::check_backup_write`]): a backup there that another install wrote at or
    /// past the mark, or a newer one of this install's own, is never written over, and the
    /// install stops as those checks say. A write, or a check, that fails on the Homeserver or
    /// the switch raises [`Alert::BackupNotWritten`] and stays owed; nothing is held back by
    /// it.
    pub(super) async fn write_owed_backup(&mut self) -> Result<()> {
        if !self.state.backup_owed || self.flow.is_some() || gate::refusal(&self.state).is_some() {
            return Ok(());
        }
        let Some(newest) = self.state.newest.clone() else {
            return Ok(());
        };
        // A recovery with the key alone's version may list a certificate this install doesn't
        // hold, and no backup holding it can be sealed: it stays owed, told, until the
        // version that drops those certificates writes its own (Switch spec 12.8).
        if self.unheld_references()? {
            let mut state = self.state.clone();
            state.alert(Alert::BackupNotWritten);
            if state != self.state {
                self.commit(state, None).await?;
            }
            return Ok(());
        }
        // Sealed before the check, so only the check's read comes before the write.
        let backup = self.seal_backup(&newest.doc, newest.prev, &self.newest_account()?)?;
        let bytes = serde_json::to_vec(&backup).map_err(|_| RecordsFault::Encode)?;
        let raised = match self.check_backup_write().await {
            Ok(raised) => raised,
            Err(SignerError::Homeserver(_) | SignerError::Switch(_)) => {
                let mut state = self.state.clone();
                state.alert(Alert::BackupNotWritten);
                if state != self.state {
                    self.commit(state, None).await?;
                }
                return Ok(());
            }
            Err(error) => return Err(error),
        };
        let written = self
            .env
            .homeserver
            .put(SIGNER_BACKUP_PATH, bytes)
            .await
            .is_ok();
        let mut state = self.state.clone();
        if let Some(alert) = raised {
            state.alert(alert);
        }
        if written {
            state.backup_owed = false;
            state.publish_after_backup = false;
            state.alerts.retain(|a| *a != Alert::BackupNotWritten);
        } else {
            state.alert(Alert::BackupNotWritten);
        }
        if state != self.state {
            self.commit(state, None).await?;
        }
        Ok(())
    }

    /// Check, a few at a time, whether the record of a removed app a restore found is still
    /// on the Homeserver, and owe its deletion if it is (Switch spec 12.2 step 4). A read that
    /// fails postpones the rest to the next run.
    pub(super) async fn check_owed_deletions(&mut self) -> Result<()> {
        if self.state.deletion_checks.is_empty() {
            return Ok(());
        }
        // The run's budget, shared with every other check this run makes.
        let allowed = self.allowance().checks;
        if self.state.deletion_checks.len() > allowed {
            self.left.deletions_left = true;
        }
        let mut state = self.state.clone();
        let batch: Vec<[u8; 16]> = state
            .deletion_checks
            .iter()
            .take(allowed)
            .copied()
            .collect();
        let mut tried = 0;
        for app_id in batch {
            tried += 1;
            match self.env.homeserver.get(&app_record_path(&app_id)).await {
                Ok(found) => {
                    state.deletion_checks.retain(|a| *a != app_id);
                    if found.is_some() && !state.cleanup.contains(&app_id) {
                        state.cleanup.push(app_id);
                    }
                }
                // The Homeserver failed: the rest wait for the next run, and this one goes
                // behind them, so a path that keeps failing holds none of them back.
                Err(_) => {
                    state.deletion_checks.retain(|a| *a != app_id);
                    state.deletion_checks.push(app_id);
                    break;
                }
            }
        }
        self.spend(|run| run.checks = run.checks.saturating_sub(tried));
        if state != self.state {
            self.commit(state, self.flow.clone()).await?;
        }
        Ok(())
    }
}

/// The App IDs `GET /apps` shows revoked or departed, of the apps `version` lists: a removal
/// is taken from the switch only for an app the identity's own version lists, as a routine
/// run takes one. An ID the switch shows for any other app counts for nothing: one the
/// version removed comes from its `removed` and the records, and one no version listed would
/// only grow the records, and a move's enrollment with them, on a switch's word (Switch wire
/// 3.7, 7.4.12).
pub(super) fn removed_at_switch<'a>(
    apps: &'a AppsAnswer,
    version: &'a IdentityDoc,
) -> impl Iterator<Item = [u8; 16]> + 'a {
    apps.apps
        .iter()
        .filter(|s| s.revoked_at.is_some() || s.departed_at.is_some())
        .map(|s| s.app_id)
        .filter(|id| version.listed_cert(id).is_some())
}

/// A `GET /apps` answer that shows no copy, nothing revoked and no epoch: a recovery's
/// service before it takes the version (Switch wire 3.13).
pub(super) fn no_copy() -> AppsAnswer {
    AppsAnswer {
        apps: Vec::new(),
        recovery: None,
        proof_generations: Vec::new(),
        identity: None,
        server_time: 0,
    }
}

/// `answer` with its copy left out when, under a backup of a recovery's version, that copy is
/// the lost generation's, at the origin the version names and below its version: the service
/// still serving there until it takes the version, a recovery in place (Switch wire 3.13).
fn without_the_lost_copy(
    view: &BackupView,
    mut answer: AppsAnswer,
    identity: &[u8; 32],
) -> AppsAnswer {
    let doc = &view.identity_doc;
    let lost_copy = is_recovery(view)
        && answer
            .identity
            .as_ref()
            .and_then(|signed| IdentityDoc::verify(signed, identity).ok())
            .is_some_and(|copy| {
                Some(copy.generation()) == doc.body().recovery_from
                    && copy.version() < doc.version()
                    && copy.inbox().url == doc.inbox().url
            });
    if lost_copy {
        answer.identity = None;
    }
    answer
}

/// Whether a signed `503 recovery_required`'s `current` names the lost generation or the
/// version's, under a backup of a recovery's version: the service before it takes the version
/// (Switch wire 3.13, 7.6).
fn notice_before_the_recovery(view: &BackupView, current: &serde_json::Value) -> bool {
    let doc = &view.identity_doc;
    is_recovery(view)
        && pubky_switch_core::http::RecoveryNotice::from_current(current).is_ok_and(|notice| {
            Some(notice.generation) == doc.body().recovery_from
                || notice.generation == doc.generation()
        })
}

/// Whether the backup `view` holds the version that starts a recovery: `recovery_from` the
/// generation before its own, built on none, since later versions of that generation keep
/// `recovery_from` (Switch spec 12.6 step 1, wire 3.13).
fn is_recovery(view: &BackupView) -> bool {
    let doc = &view.identity_doc;
    view.prev.is_none() && is_recovery_doc(doc)
}

/// Whether `doc` carries `recovery_from` the generation before its own.
fn is_recovery_doc(doc: &IdentityDoc) -> bool {
    doc.body().recovery_from.is_some()
        && doc.body().recovery_from == doc.generation().checked_sub(1)
}
