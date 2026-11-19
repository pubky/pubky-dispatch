//! Same-account recovery when a key-only declaration writes its backup after winning.

use pubky_switch_client::{ClientError, client::RecoveryEnrollmentAnswer};
use pubky_switch_core::enc::hash;
use pubky_switch_core::http::{ErrorCode, RecoveryNotice};
use pubky_switch_core::records::recovery_enrollment::{
    RecoveryDisposition, RecoveryEnrollmentRequest, recovery_commit_digest,
};
use pubky_switch_core::records::{AccountAssociation, AccountObservation, CLOCK_TOLERANCE_MS};

use super::*;
use crate::state::{RecoveryDelivery, RecoveryStep};

impl Signer {
    pub(super) async fn prepare_recovery_delivery(
        &mut self,
        observed: &AccountObservation,
        enrollment: &SignedDoc,
        error: SignerError,
    ) -> Result<()> {
        let SignerError::Switch(ClientError::Switch {
            code: ErrorCode::RecoveryRequired,
            current,
            ..
        }) = &error
        else {
            return Err(error);
        };
        let Ok(notice) = RecoveryNotice::from_current(current) else {
            return Err(error);
        };
        let account = observed.body();
        let base = self.recovery_base()?;
        // A copy from another install, or no copy anywhere, owes the backup after winning.
        if account.association != AccountAssociation::Account
            || base
                .as_ref()
                .is_some_and(|base| base.body().signer == self.state.install)
        {
            return Err(error);
        }
        let target = Target {
            origin: &account.origin,
            identity: account.identity,
            pinned: Some(account.service_key),
            created: account.created,
        };
        let client = RequestClient::new(&self.env, &target, &self.keyring, &self.store)?;
        let request = RecoveryEnrollmentRequest::Prepare {
            enrollment: enrollment.clone(),
        }
        .to_json()?;
        let RecoveryEnrollmentAnswer::Preparation(prepared) =
            client.recovery_enrollment(observed, &request).await?
        else {
            return Err(RecordsFault::Invariant("unexpected recovery preparation answer").into());
        };
        let binding = &prepared.body().binding;
        let lost = self
            .state
            .lost_generation
            .ok_or(RecordsFault::Invariant("missing lost generation"))?
            .max(notice.generation)
            .max(binding.generation_floor)
            .max(self.state.generation_seen);
        let until = self.env.clock.now_ms().saturating_add(CLOCK_TOLERANCE_MS);
        let mut body = self.recovery_body(
            base.as_ref(),
            lost,
            &account.origin,
            account.service_key,
            until,
        )?;
        if body.version <= binding.version_floor {
            body.version = binding
                .version_floor
                .checked_add(1)
                .ok_or(RecordsFault::Invariant("recovery version exhausted"))?;
            body = Self::measured(&self.state, body, None, Room::Cap)?;
        }
        let prior = base
            .as_ref()
            .filter(|base| Some(base.hash()) == prepared.body().prior)
            .map(|base| base.signed().clone());
        let doc = {
            let key = gate::recovery_key(&self.keyring, &self.state, &self.store)?;
            IdentityDoc::sign(&key, body)?
        };
        let mut action = RecoveryDelivery {
            origin: account.origin.clone(),
            observation: observed.carried().clone(),
            enrollment: enrollment.clone(),
            preparation: prepared.signed().clone(),
            doc: doc.signed().clone(),
            prior,
            commit_digest: [0; 32],
            step: RecoveryStep::Commit,
        };
        action.commit_digest = recovery_commit_digest(&action.commit_packet(&action.preparation)?);
        let mut state = self.state.clone();
        state.recovery_commit = Some(action.commit_digest);
        state.recovery_base = Some(doc.signed().clone());
        state.signed_through = doc.version();
        state.epoch_through = state.epoch_through.max(doc.data_epoch());
        state.lost_generation = Some(lost);
        state.backup_owed = true;
        self.commit(state, Some(Flow::RecoveryDelivery(Box::new(action))))
            .await
    }

    pub(super) async fn resume_recovery_delivery(
        &mut self,
        mut action: RecoveryDelivery,
    ) -> Result<()> {
        if let Some(refused) = gate::recovery_refusal(&self.state) {
            return Err(refused);
        }
        if self.keyring.is_received() {
            return Err(Refusal::TakingOver.into());
        }
        let observed = action
            .observation
            .verify(&self.state.identity, &action.origin)?;
        let account = observed.body();
        let packet = action.packet()?;
        let target = Target {
            origin: &account.origin,
            identity: account.identity,
            pinned: Some(account.service_key),
            created: account.created,
        };
        let client = RequestClient::new(&self.env, &target, &self.keyring, &self.store)?;
        let reply = client.recovery_enrollment(&observed, &packet).await?;
        match reply {
            RecoveryEnrollmentAnswer::Committed(receipt) => {
                let result = Service {
                    origin: action.origin,
                    service_key: receipt.enrollment.service_key,
                    created: receipt.enrollment.created,
                    limits: receipt.enrollment.limits,
                };
                return self
                    .delivered(
                        result,
                        action.doc,
                        None,
                        Some(receipt.proof.envelope().server_time),
                    )
                    .await;
            }
            RecoveryEnrollmentAnswer::Disposition(RecoveryDisposition::Expired(ticket))
                if matches!(action.step, RecoveryStep::Commit) =>
            {
                // The ticket cannot settle the commit. Save this exact renewal before it can reserve.
                let ticket = ticket.signed().clone();
                let renew_hash = hash(&action.renew_packet(&ticket)?);
                action.step = RecoveryStep::Renew { ticket, renew_hash };
            }
            RecoveryEnrollmentAnswer::Preparation(preparation) => {
                let RecoveryStep::Renew {
                    ref ticket,
                    renew_hash,
                } = action.step
                else {
                    return Err(RecordsFault::Invariant("recovery renewal was not pending").into());
                };
                let preparation = preparation.signed().clone();
                let digest = recovery_commit_digest(&action.commit_packet(&preparation)?);
                action.step = RecoveryStep::Replacement {
                    ticket: ticket.clone(),
                    renew_hash,
                    preparation,
                    digest,
                };
            }
            RecoveryEnrollmentAnswer::Disposition(RecoveryDisposition::Renewed(preparation))
                if matches!(action.step, RecoveryStep::Commit) =>
            {
                action.step = RecoveryStep::Hold {
                    replacement: preparation.signed().clone(),
                };
            }
            _ => return Err(Refusal::FlowInProgress.into()),
        }
        self.commit(
            self.state.clone(),
            Some(Flow::RecoveryDelivery(Box::new(action))),
        )
        .await
    }
}
