//! The signed operands of an existing-account recovery awaiting its receipt.

use pubky_switch_core::enc::hash;
use pubky_switch_core::records::recovery_enrollment::{
    RecoveryEnrollmentRequest, RecoveryExpiryTicket, RecoveryPreparation, recovery_commit_digest,
};

use super::*;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct RecoveryDelivery {
    pub(crate) origin: String,
    pub(crate) observation: CarriedAccountObservation,
    pub(crate) enrollment: SignedDoc,
    pub(crate) preparation: SignedDoc,
    pub(crate) doc: SignedDoc,
    pub(crate) prior: Option<SignedDoc>,
    pub(crate) commit_digest: [u8; 32],
    pub(crate) step: RecoveryStep,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) enum RecoveryStep {
    Commit,
    Hold {
        replacement: SignedDoc,
    },
    Renew {
        ticket: SignedDoc,
        renew_hash: [u8; 32],
    },
    Replacement {
        ticket: SignedDoc,
        renew_hash: [u8; 32],
        preparation: SignedDoc,
        digest: [u8; 32],
    },
}

impl RecoveryDelivery {
    pub(crate) fn commit_packet(&self, preparation: &SignedDoc) -> Result<Vec<u8>> {
        Ok(RecoveryEnrollmentRequest::Commit {
            enrollment: self.enrollment.clone(),
            preparation: preparation.clone(),
            identity: self.doc.clone(),
            prior: self.prior.clone(),
        }
        .to_json()?)
    }

    pub(crate) fn renew_packet(&self, ticket: &SignedDoc) -> Result<Vec<u8>> {
        Ok(RecoveryEnrollmentRequest::Renew {
            ticket: ticket.clone(),
            enrollment: self.enrollment.clone(),
            identity: self.doc.clone(),
            prior: self.prior.clone(),
        }
        .to_json()?)
    }

    pub(crate) fn packet(&self) -> Result<Vec<u8>> {
        match &self.step {
            RecoveryStep::Commit => self.commit_packet(&self.preparation),
            RecoveryStep::Hold { .. } => Err(crate::error::Refusal::FlowInProgress.into()),
            RecoveryStep::Renew { ticket, .. } => self.renew_packet(ticket),
            RecoveryStep::Replacement { preparation, .. } => self.commit_packet(preparation),
        }
    }

    pub(super) fn check(&self, identity: &[u8; 32]) -> Result<()> {
        let fault =
            || RecordsFault::Invariant("recovery delivery differs from the selected action");
        let observed = self.observation.verify(identity, &self.origin)?;
        let account = observed.body();
        let signed = Enrollment::verify(&self.enrollment, identity, &self.origin)?;
        let prepared =
            RecoveryPreparation::verify(&self.preparation, &account.service_key, identity)?;
        let binding = &prepared.body().binding;
        let doc = stored_identity(&self.doc, identity)?;
        let prior = self
            .prior
            .as_ref()
            .map(|prior| stored_identity(prior, identity))
            .transpose()?;
        if !matches!(signed.body().intent, EnrollmentIntent::Existing { .. })
            || signed.body().intent != observed.enrollment_intent()?
            || signed.body().identity_doc.is_some()
            || !prepared.covers_existing(&observed, &signed)
            || prepared.body().replaces.is_some()
            || !binding.permits_document(&doc)
            || prior
                .as_ref()
                .is_some_and(|prior| Some(prior.hash()) != prepared.body().prior)
            || recovery_commit_digest(&self.commit_packet(&self.preparation)?) != self.commit_digest
        {
            return Err(fault().into());
        }
        let (ticket, renew_hash) = match &self.step {
            RecoveryStep::Commit => return Ok(()),
            RecoveryStep::Hold { replacement } => {
                let replacement =
                    RecoveryPreparation::verify(replacement, &account.service_key, identity)?;
                return if replacement.body().binding == *binding
                    && replacement.body().prior == prepared.body().prior
                    && replacement.body().replaces == Some(self.commit_digest)
                {
                    Ok(())
                } else {
                    Err(fault().into())
                };
            }
            RecoveryStep::Renew { ticket, renew_hash }
            | RecoveryStep::Replacement {
                ticket, renew_hash, ..
            } => (ticket, renew_hash),
        };
        let expiry = RecoveryExpiryTicket::verify(ticket, &account.service_key, identity)?;
        let body = expiry.body();
        if body.binding != *binding
            || body.document != doc.hash()
            || body.commit != self.commit_digest
            || body.preparation != self.preparation.doc_hash()?
            || body.enrollment_terms != signed.hash()
            || body.prior != prior.as_ref().map(IdentityDoc::hash)
            || hash(&self.renew_packet(ticket)?) != *renew_hash
        {
            return Err(fault().into());
        }
        if let RecoveryStep::Replacement {
            preparation,
            digest,
            ..
        } = &self.step
        {
            let replacement =
                RecoveryPreparation::verify(preparation, &account.service_key, identity)?;
            if replacement.body().replaces != Some(self.commit_digest)
                || replacement.body().binding != *binding
                || replacement.body().prior != prepared.body().prior
                || recovery_commit_digest(&self.commit_packet(preparation)?) != *digest
            {
                return Err(fault().into());
            }
        }
        Ok(())
    }

    pub(super) fn check_state(&self, state: &SignerState) -> Result<()> {
        let doc = stored_identity(&self.doc, &state.identity)?;
        if !state.recovering
            || !state.backup_owed
            || state.recovery_commit != Some(self.commit_digest)
            || state.recovery_base.as_ref() != Some(&self.doc)
            || state.recovery_origin.as_deref() != Some(&self.origin)
            || state.signed_through < doc.version()
            || state.epoch_through < doc.data_epoch()
            || state.lost_generation != doc.body().recovery_from
            || state.install != doc.body().signer
        {
            return Err(
                RecordsFault::Invariant("recovery delivery disagrees with signer records").into(),
            );
        }
        RecoveryEnrollment::Ready {
            observation: self.observation.clone(),
            enrollment: self.enrollment.clone(),
        }
        .check_exclusions(state, &self.origin)
    }
}
