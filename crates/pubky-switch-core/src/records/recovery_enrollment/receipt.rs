//! Verify the results of an atomic recovery enrollment and delivery (account binding 3.3).

use super::{MAX_RESPONSE_BYTES, RecoveryPreparation};
use crate::Result;
use crate::chain::{ItemType, SignedHead, TransitionProof, item_hash};
use crate::error::invalid;
use crate::json::{parse_json, reject_unknown_members};
use crate::records::{
    AccountAssociation, Enrollment, EnrollmentAnswer, EnrollmentIntent, IdentityDoc,
};
use crate::sig::SignedDoc;
use serde_json::Value;

/// Both authenticated results of the selected action, checked against the pending inputs.
#[derive(Clone, Debug, PartialEq)]
pub struct RecoveryEnrollmentReceipt {
    /// The checked account creation and limits.
    pub enrollment: EnrollmentAnswer,
    /// The proof accepting the signed identity document.
    pub proof: TransitionProof,
    /// The signed head that covers the accepted document.
    pub head: SignedHead,
}

impl RecoveryEnrollmentReceipt {
    /// Check the service's successful HTTP body against the verified response head and
    /// the exact enrollment, preparation and signed identity held by the signer.
    ///
    /// # Errors
    ///
    /// The size, service signature, selection, limits, proof or signed head do not match.
    pub fn verify(
        bytes: &[u8],
        enrollment: &Enrollment,
        preparation: &RecoveryPreparation,
        document: &IdentityDoc,
        response_head: &SignedHead,
    ) -> Result<Self> {
        if bytes.len() > MAX_RESPONSE_BYTES {
            return invalid("Switch account binding 3.3: oversized recovery receipt");
        }
        let v: Value = parse_json(bytes)?;
        reject_unknown_members(
            &v,
            &["enrollment", "proof", "head"],
            "recovery enrollment receipt",
        )?;
        let answer: EnrollmentAnswer = serde_json::from_value(v["enrollment"].clone())?;
        answer.check(enrollment)?;
        let prep = &preparation.body().binding;
        let intent = &enrollment.body().intent;
        let association = match intent {
            EnrollmentIntent::Existing { .. } => AccountAssociation::Account,
            EnrollmentIntent::Takeover { .. } => AccountAssociation::Mark,
            EnrollmentIntent::Create { .. } => {
                return invalid("Switch account binding 3.3: recovery needs a selected creation");
            }
        };
        if prep.enrollment != enrollment.hash()
            || prep.origin != answer.origin
            || prep.identity != answer.identity
            || prep.association != association
            || intent.created() != Some(prep.created)
            || answer.service_key != prep.service_key
            || answer.created != prep.result_created
            || answer.limits != prep.limits
            || !prep.permits_document(document)
        {
            return invalid("Switch account binding 3.3: recovery receipt bindings");
        }
        let head = SignedHead::from_value(&v["head"])?;
        head.verify(&prep.service_key, &prep.identity)?;
        let proof = TransitionProof::verify(
            &SignedDoc::from_strict_value(&v["proof"])?,
            &prep.service_key,
            &prep.identity,
        )?;
        let state = &proof.body().state;
        let env = proof.envelope();
        if &head != response_head
            || head.seq == 0
            || head.generation != document.generation()
            || env.item_type != ItemType::Identity
            || env.item_hash != item_hash(ItemType::Identity, &document.signed().doc_bytes()?)
            || env.generation != head.generation
            || env.seq != head.seq
            || proof.body().chain.chain_hash != head.chain_hash
            || proof.body().object != "identity"
            || proof.body().step.is_some()
            || proof.body().version != Some(document.version())
            || state.get("version").and_then(Value::as_u64) != Some(document.version())
            || state.get("generation").and_then(Value::as_u64) != Some(document.generation())
            || state.get("data_epoch").and_then(Value::as_u64) != Some(document.data_epoch())
        {
            return invalid("Switch account binding 3.3: identity proof and accepted head");
        }
        Ok(Self {
            enrollment: answer,
            proof,
            head,
        })
    }
}
