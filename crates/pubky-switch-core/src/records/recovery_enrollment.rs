//! Enrollment at a recovering provider (Switch account binding 3.3).
//!
//! Signed documents retain their original body and signature. A renewed commit has one
//! exact outer representation that the service and signer can construct independently.

mod evidence;
#[cfg(feature = "test-vectors")]
mod fixtures;
mod receipt;
pub use evidence::{
    RecoveryBinding, RecoveryDisposition, RecoveryExpiryTicket, RecoveryExpiryTicketBody,
    RecoveryPreparation, RecoveryPreparationBody,
};
pub use receipt::RecoveryEnrollmentReceipt;

use serde::Serialize;
use serde_json::Value;

use crate::enc::{hash, lp};
use crate::json::{check_json, member_span, reject_unknown_members};
use crate::sig::SignedDoc;
use crate::{Result, SizeRefusal};

/// Maximum complete prepare request, including JSON syntax.
pub const MAX_PREPARE_BYTES: usize = 264 << 10;
/// Maximum complete commit or renew request and the route's transport ceiling.
pub const MAX_REQUEST_BYTES: usize = 1 << 20;
/// All response bodies for the route, including errors, fit this many bytes.
pub const MAX_RESPONSE_BYTES: usize = 16 << 10;
/// A signed preparation or expiry ticket fits this many bytes including its wrapper.
pub const MAX_EVIDENCE_BYTES: usize = 4096;

/// The identity-authenticated action carried by the HTTP request.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "op", rename_all = "snake_case")]
pub enum RecoveryEnrollmentRequest {
    /// Obtain a read-only judgment on this signed enrollment.
    Prepare {
        /// The exact pending enrollment.
        enrollment: SignedDoc,
    },
    /// Apply or resume the exact prepared enrollment and identity delivery together.
    Commit {
        /// The exact enrollment named by the preparation.
        enrollment: SignedDoc,
        /// The signed preparation.
        preparation: SignedDoc,
        /// The frozen higher-generation identity document.
        identity: SignedDoc,
        /// Supplied prior evidence, or explicit null.
        prior: Option<SignedDoc>,
    },
    /// Recheck the predecessor and reserve a replacement for an expired action.
    Renew {
        /// The service's signed expiry ticket.
        ticket: SignedDoc,
        /// The enrollment authorized for this renewal.
        enrollment: SignedDoc,
        /// The original signed identity document.
        identity: SignedDoc,
        /// The original supplied prior proof, or explicit null.
        prior: Option<SignedDoc>,
    },
}

impl RecoveryEnrollmentRequest {
    /// Read the complete bounded packet, retaining the exact signed document contents.
    /// The HTTP caller retains the original request bytes for its commit digest.
    ///
    /// # Errors
    ///
    /// An oversized packet or carrying form is a size refusal. Invalid JSON, missing
    /// members, additional members and invalid binary encodings are malformed.
    pub fn from_json(bytes: &[u8]) -> std::result::Result<Self, SizeRefusal> {
        let too_large =
            || SizeRefusal::TooLarge("Switch account binding 3.3: recovery enrollment".into());
        let malformed =
            || SizeRefusal::BadRequest("Switch account binding 3.3: recovery enrollment".into());
        if bytes.len() > MAX_REQUEST_BYTES {
            return Err(too_large());
        }
        check_json(bytes).map_err(|_| malformed())?;
        let value: Value = serde_json::from_slice(bytes).map_err(|_| malformed())?;
        let op = value
            .get("op")
            .and_then(Value::as_str)
            .ok_or_else(malformed)?;
        let names: &[&str] = match op {
            "prepare" if bytes.len() > MAX_PREPARE_BYTES => return Err(too_large()),
            "prepare" => &["op", "enrollment"],
            "commit" => &["op", "enrollment", "preparation", "identity", "prior"],
            "renew" => &["op", "ticket", "enrollment", "identity", "prior"],
            _ => return Err(malformed()),
        };
        reject_unknown_members(&value, names, "recovery enrollment").map_err(|_| malformed())?;
        let doc = |name: &str, cap: usize| {
            let span = member_span(bytes, name).ok_or_else(malformed)?;
            if span.len() > cap {
                return Err(too_large());
            }
            let signed = SignedDoc::from_strict_value(&value[name]).map_err(|_| malformed())?;
            signed.body_bytes().map_err(|_| malformed())?;
            signed.sig_bytes().map_err(|_| malformed())?;
            Ok(signed)
        };
        let cap = super::MAX_ENROLLMENT_BYTES;
        let enrollment = doc("enrollment", cap)?;
        if op == "prepare" {
            return Ok(Self::Prepare { enrollment });
        }
        let identity = doc("identity", cap)?;
        let prior = match value.get("prior") {
            Some(Value::Null) => None,
            Some(_) => Some(doc("prior", cap)?),
            None => return Err(malformed()),
        };
        if op == "commit" {
            Ok(Self::Commit {
                enrollment,
                preparation: doc("preparation", MAX_EVIDENCE_BYTES)?,
                identity,
                prior,
            })
        } else {
            Ok(Self::Renew {
                ticket: doc("ticket", MAX_EVIDENCE_BYTES)?,
                enrollment,
                identity,
                prior,
            })
        }
    }

    /// Write the complete packet. For commit this emits the prescribed literal ASCII
    /// member names, punctuation, unescaped canonical base64url and explicit prior value.
    ///
    /// # Errors
    ///
    /// A signed object's encoding is invalid or a packet or component exceeds its limit.
    pub fn to_json(&self) -> Result<Vec<u8>> {
        let check = |document: &SignedDoc, limit: usize| -> Result<()> {
            // Valid base64url has no escaped characters in the canonical wrapper.
            let len = br#"{"body":"","sig":""}"#
                .len()
                .saturating_add(document.body.len())
                .saturating_add(document.sig.len());
            if len > limit {
                return crate::error::invalid(
                    "Switch account binding 3.3: oversized signed object",
                );
            }
            document.body_bytes()?;
            document.sig_bytes()?;
            Ok(())
        };
        let doc_limit = super::MAX_ENROLLMENT_BYTES;
        match self {
            Self::Prepare { enrollment } => check(enrollment, doc_limit)?,
            Self::Commit {
                enrollment,
                preparation: evidence,
                identity,
                prior,
            }
            | Self::Renew {
                enrollment,
                ticket: evidence,
                identity,
                prior,
            } => {
                check(enrollment, doc_limit)?;
                check(evidence, MAX_EVIDENCE_BYTES)?;
                check(identity, doc_limit)?;
                if let Some(prior) = prior {
                    check(prior, doc_limit)?;
                }
            }
        }
        // Three 256 KiB documents, one 4 KiB wrapper and the fixed outer punctuation
        // fit the commit/renew limit. One enrollment and its punctuation fit prepare.
        Ok(serde_json::to_vec(self)?)
    }
}

/// The commitment to the exact HTTP commit body (Switch account binding 3.3).
pub fn recovery_commit_digest(body: &[u8]) -> [u8; 32] {
    hash(&lp(&[b"pubky-switch/v1/recovery-commit", body]))
}
