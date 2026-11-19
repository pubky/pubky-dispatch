//! Recovery service documents for wire vectors and scripted signer tests.

use super::evidence::{EXPIRY_KIND, PREPARATION_KIND};
use super::{
    MAX_RESPONSE_BYTES, RecoveryEnrollmentReceipt, RecoveryExpiryTicket, RecoveryExpiryTicketBody,
    RecoveryPreparation, RecoveryPreparationBody,
};
use crate::{Result, error::invalid, labels::sig, records::encode, sig::SignedDoc, signing::Signs};
use serde::Serialize;

impl RecoveryPreparation {
    /// Sign a preparation for the service's locked selection.
    ///
    /// # Errors
    ///
    /// Invalid bindings, lifetime, limits or carrying size.
    pub fn sign(key: &impl Signs, body: RecoveryPreparationBody) -> Result<Self> {
        let signed = sign(
            key,
            &body.binding.identity,
            PREPARATION_KIND,
            sig::RECOVERY_PREPARATION,
            &body,
        )?;
        Self::verify(&signed, &key.public_key(), &body.binding.identity)
    }
}

impl RecoveryExpiryTicket {
    /// Sign the terms of an authenticated expired commit.
    ///
    /// # Errors
    ///
    /// Invalid selection, encoding or carrying size.
    pub fn sign(key: &impl Signs, body: RecoveryExpiryTicketBody) -> Result<Self> {
        let signed = sign(
            key,
            &body.binding.identity,
            EXPIRY_KIND,
            sig::RECOVERY_EXPIRY,
            &body,
        )?;
        Self::verify(&signed, &key.public_key(), &body.binding.identity)
    }
}

impl RecoveryEnrollmentReceipt {
    /// Encode both results and the exact signed head for the service response.
    ///
    /// # Errors
    ///
    /// Invalid JSON or a response that exceeds the route's byte limit.
    pub fn to_json(&self) -> Result<Vec<u8>> {
        let bytes = serde_json::to_vec(&serde_json::json!({
            "enrollment": self.enrollment,
            "proof": self.proof.signed(),
            "head": self.head.to_value(),
        }))?;
        if bytes.len() > MAX_RESPONSE_BYTES {
            return invalid("Switch account binding 3.3: oversized recovery receipt");
        }
        Ok(bytes)
    }
}

fn sign(
    key: &impl Signs,
    identity: &[u8; 32],
    kind: &str,
    label: &str,
    body: &impl Serialize,
) -> Result<SignedDoc> {
    let bytes = encode(kind, body)?;
    let signature = key.sign_fields(label, &[identity, &bytes]);
    Ok(SignedDoc::from_parts(&bytes, &signature))
}
