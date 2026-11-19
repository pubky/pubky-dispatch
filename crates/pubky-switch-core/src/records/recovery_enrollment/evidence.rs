//! The two service-signed recovery enrollment documents (Switch account binding 3.3).

use serde::{Deserialize, Serialize, de::DeserializeOwned};
use serde_json::Value;

use super::MAX_EVIDENCE_BYTES;
use crate::enc::serde_b64;
use crate::error::invalid;
use crate::json::{parse_json, reject_unknown_members};
use crate::labels::sig;
use crate::records::account::{millis, nullable_millis};
use crate::records::{
    ACCOUNT_OBSERVATION_VALIDITY_MS, AccountAssociation, AccountObservation, Enrollment,
    EnrollmentIntent, IdentityDoc, Limits, check_tag, fmt, is_origin,
};
use crate::sig::SignedDoc;
use crate::time::MAX_TIME_MS;
use crate::{Error, Result};

pub(super) const PREPARATION_KIND: &str = "pubky-switch.recovery-preparation";
pub(super) const EXPIRY_KIND: &str = "pubky-switch.recovery-expiry";

/// Service, lifetime, predecessor and result shared by a preparation and its expiry ticket.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RecoveryBinding {
    /// The service's signed request origin.
    pub origin: String,
    /// The selected account identity.
    #[serde(with = "fmt::pubky")]
    pub identity: [u8; 32],
    /// The service key for the result.
    #[serde(with = "serde_b64")]
    pub service_key: [u8; 32],
    /// The independently confirmed store identity.
    #[serde(with = "serde_b64")]
    pub store_id: [u8; 16],
    /// The selected account or surviving mark.
    pub association: AccountAssociation,
    /// The creation named by the original request.
    #[serde(with = "millis")]
    pub created: u64,
    /// The last completed erasure, or its established absence.
    #[serde(with = "nullable_millis")]
    pub erased_at: Option<u64>,
    /// Document hash of the selected enrollment.
    #[serde(with = "serde_b64")]
    pub enrollment: [u8; 32],
    /// Service commitment to the complete selected predecessor.
    #[serde(with = "serde_b64")]
    pub predecessor: [u8; 32],
    /// Highest established generation floor.
    pub generation_floor: u64,
    /// Highest established document version floor.
    pub version_floor: u64,
    /// The selected result lifetime.
    #[serde(with = "millis")]
    pub result_created: u64,
    /// All seven limits of the result.
    pub limits: Limits,
}

impl RecoveryBinding {
    /// Whether this predecessor belongs to the exact service and lifetime the signer observed.
    pub fn matches_observation(&self, observation: &AccountObservation) -> bool {
        let at = observation.body();
        self.origin == at.origin
            && self.identity == at.identity
            && self.service_key == at.service_key
            && self.store_id == at.store_id
            && self.association == at.association
            && Some(self.created) == at.created
            && self.erased_at == at.erased_at
    }

    /// Whether the identity document selects this service and starts above all known floors.
    pub fn permits_document(&self, doc: &IdentityDoc) -> bool {
        doc.identity() == self.identity
            && doc.inbox().url == self.origin
            && doc.inbox().service_key == self.service_key
            && doc.generation() > self.generation_floor
            && doc.version() > self.version_floor
            && doc.body().recovery_from == doc.generation().checked_sub(1)
    }

    fn check(&self, key: &[u8; 32], identity: &[u8; 32]) -> Result<()> {
        let valid_creation = match self.association {
            AccountAssociation::Account => self.result_created == self.created,
            AccountAssociation::Mark => self.result_created > self.created,
            AccountAssociation::Absent => false,
        };
        if &self.service_key != key
            || &self.identity != identity
            || !is_origin(&self.origin)
            || !valid_creation
            || self.result_created > MAX_TIME_MS
            || self.erased_at.is_some_and(|at| at >= self.created)
            || self.limits.app_limit > crate::records::MAX_APP_LIMIT
        {
            return invalid("Switch account binding 3.3: recovery lifetime or service binding");
        }
        Ok(())
    }
}

/// Contents authenticated in a preparation.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RecoveryPreparationBody {
    /// Locked selection and result.
    #[serde(flatten)]
    pub binding: RecoveryBinding,
    /// Hash of the verified previous document, when known.
    #[serde(with = "nullable_hash")]
    pub prior: Option<[u8; 32]>,
    /// Trusted issue time.
    #[serde(with = "millis")]
    pub issued_at: u64,
    /// Last valid boundary of an unreserved preparation.
    #[serde(with = "millis")]
    pub expires_at: u64,
    /// Exact old commit replaced by this preparation, or null on first issue.
    #[serde(with = "nullable_hash")]
    pub replaces: Option<[u8; 32]>,
}

/// The evidence retained by the service in an expiry ticket.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RecoveryExpiryTicketBody {
    /// Original selection and result.
    #[serde(flatten)]
    pub binding: RecoveryBinding,
    /// Digest of the old HTTP commit bytes.
    #[serde(with = "serde_b64")]
    pub commit: [u8; 32],
    /// Hash of the frozen signed identity document.
    #[serde(with = "serde_b64")]
    pub document: [u8; 32],
    /// Hash of the supplied signed prior document, or null.
    #[serde(with = "nullable_hash")]
    pub prior: Option<[u8; 32]>,
    /// Hash of the original signed preparation.
    #[serde(with = "serde_b64")]
    pub preparation: [u8; 32],
    /// Original enrollment hash, or commitment to the byte-exact takeover terms.
    #[serde(with = "serde_b64")]
    pub enrollment_terms: [u8; 32],
}

/// A preparation whose service signature, identity and field rules have been verified.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RecoveryPreparation {
    body: RecoveryPreparationBody,
    signed: SignedDoc,
}

impl RecoveryPreparation {
    /// Whether this preparation covers the signer's existing-account enrollment and observation.
    pub fn covers_existing(
        &self,
        observation: &AccountObservation,
        enrollment: &Enrollment,
    ) -> bool {
        let body = self.body();
        matches!(enrollment.body().intent, EnrollmentIntent::Existing { created } if created == body.binding.created)
            && body.binding.association == AccountAssociation::Account
            && body.binding.matches_observation(observation)
            && body.binding.enrollment == enrollment.hash()
            && body.issued_at.checked_add(ACCOUNT_OBSERVATION_VALIDITY_MS) == Some(body.expires_at)
    }

    /// Verify with the independently selected identity and service key.
    ///
    /// # Errors
    ///
    /// An invalid signature, malformed document, wrong binding or invalid validity period.
    pub fn verify(signed: &SignedDoc, service_key: &[u8; 32], identity: &[u8; 32]) -> Result<Self> {
        let body: RecoveryPreparationBody = open(
            signed,
            service_key,
            identity,
            PREPARATION_KIND,
            sig::RECOVERY_PREPARATION,
            &["prior", "issued_at", "expires_at", "replaces"],
        )?;
        body.binding.check(service_key, identity)?;
        let duration = body.expires_at.checked_sub(body.issued_at);
        if !duration.is_some_and(|ms| ms <= crate::records::ACCOUNT_OBSERVATION_VALIDITY_MS)
            || (body.binding.association == AccountAssociation::Mark
                && body.binding.result_created > body.issued_at)
        {
            return invalid("Switch account binding 3.3: preparation validity");
        }
        Ok(Self {
            body,
            signed: signed.clone(),
        })
    }

    /// The verified selection and lifetime.
    pub fn body(&self) -> &RecoveryPreparationBody {
        &self.body
    }

    /// The original signed document.
    pub fn signed(&self) -> &SignedDoc {
        &self.signed
    }
}

/// A verified ticket about an expired action. It does not establish non-application.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RecoveryExpiryTicket {
    body: RecoveryExpiryTicketBody,
    signed: SignedDoc,
}

impl RecoveryExpiryTicket {
    /// Verify the ticket with the selected service key and identity.
    ///
    /// # Errors
    ///
    /// An invalid signature, malformed document or wrong selection.
    pub fn verify(signed: &SignedDoc, service_key: &[u8; 32], identity: &[u8; 32]) -> Result<Self> {
        let body: RecoveryExpiryTicketBody = open(
            signed,
            service_key,
            identity,
            EXPIRY_KIND,
            sig::RECOVERY_EXPIRY,
            &[
                "commit",
                "document",
                "prior",
                "preparation",
                "enrollment_terms",
            ],
        )?;
        body.binding.check(service_key, identity)?;
        Ok(Self {
            body,
            signed: signed.clone(),
        })
    }

    /// The verified old action and renewal terms.
    pub fn body(&self) -> &RecoveryExpiryTicketBody {
        &self.body
    }

    /// The original signed document.
    pub fn signed(&self) -> &SignedDoc {
        &self.signed
    }
}

fn open<T: DeserializeOwned>(
    signed: &SignedDoc,
    key: &[u8; 32],
    identity: &[u8; 32],
    kind: &str,
    label: &str,
    additional: &[&str],
) -> Result<T> {
    // Only the two literal base64url strings and the fixed carrying syntax are accepted.
    if signed
        .body
        .len()
        .saturating_add(signed.sig.len())
        .saturating_add(br#"{"body":"","sig":""}"#.len())
        > MAX_EVIDENCE_BYTES
    {
        return invalid("Switch account binding 3.3: oversized signed recovery evidence");
    }
    let bytes = signed.verify(key, label, &[identity])?;
    let v: Value = parse_json(&bytes)?;
    check_tag(&v, kind, "Switch account binding 3.3")?;
    let mut fields = vec![
        "v",
        "kind",
        "origin",
        "identity",
        "service_key",
        "store_id",
        "association",
        "created",
        "erased_at",
        "enrollment",
        "predecessor",
        "generation_floor",
        "version_floor",
        "result_created",
        "limits",
    ];
    fields.extend_from_slice(additional);
    reject_unknown_members(&v, &fields, "signed recovery evidence")?;
    reject_unknown_members(
        &v["limits"],
        &[
            "app_limit",
            "max_envelope",
            "max_sealed_value",
            "quota_bytes",
            "max_batch",
            "record_quota_bytes",
            "max_import_bytes",
        ],
        "recovery limits",
    )?;
    serde_json::from_value(v).map_err(Error::from)
}

mod nullable_hash {
    use crate::enc::{b64, unb64_array};
    use serde::{Deserialize, Deserializer, Serialize, Serializer, de::Error as _};
    pub fn serialize<S: Serializer>(v: &Option<[u8; 32]>, s: S) -> Result<S::Ok, S::Error> {
        v.as_ref().map(|bytes| b64(bytes)).serialize(s)
    }
    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Option<[u8; 32]>, D::Error> {
        Option::<String>::deserialize(d)?
            .map(|v| unb64_array(&v).map_err(D::Error::custom))
            .transpose()
    }
}

/// The authenticated disposition of a previous commit in a signed 409 response.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RecoveryDisposition {
    /// The old packet expired; no outcome is established by this ticket alone.
    Expired(RecoveryExpiryTicket),
    /// The service durably selected the replacement preparation.
    Renewed(RecoveryPreparation),
}

impl RecoveryDisposition {
    /// Read a recovery-specific 409 conflict after the HTTP signature was checked.
    /// Other conflict shapes have no recovery disposition.
    ///
    /// # Errors
    ///
    /// A recognized disposition lacks its bounded signed evidence or fails verification.
    pub fn from_error_body(
        bytes: &[u8],
        service_key: &[u8; 32],
        identity: &[u8; 32],
    ) -> Result<Option<Self>> {
        check_response_size(bytes)?;
        let error: Value = parse_json(bytes)?;
        let Some(kind) = error
            .get("current")
            .and_then(|v| v.get("recovery"))
            .and_then(Value::as_str)
        else {
            return Ok(None);
        };
        let (member, expired) = match kind {
            "expired" => ("ticket", true),
            "renewed" => ("preparation", false),
            _ => return Ok(None),
        };
        if error.get("code").and_then(Value::as_str) != Some("conflict") {
            return invalid("Switch account binding 3.3: recovery disposition code");
        }
        let current = &error["current"];
        reject_unknown_members(current, &["recovery", member], "recovery disposition")?;
        let current_bytes = crate::json::member_span(bytes, "current")
            .and_then(|r| bytes.get(r))
            .ok_or_else(|| Error::Invalid("missing recovery disposition".into()))?;
        let doc = carried(current_bytes, current, member)?;
        if expired {
            Ok(Some(Self::Expired(RecoveryExpiryTicket::verify(
                &doc,
                service_key,
                identity,
            )?)))
        } else {
            let prep = RecoveryPreparation::verify(&doc, service_key, identity)?;
            if prep.body().replaces.is_none() {
                return invalid("Switch account binding 3.3: replacement names no old commit");
            }
            Ok(Some(Self::Renewed(prep)))
        }
    }
}

impl RecoveryPreparation {
    /// Read the complete successful preparation or renewal response. The reader checks
    /// the raw wrapper's size, including whitespace and escapes.
    ///
    /// # Errors
    ///
    /// The response is oversized, has extra members, or the preparation fails verification.
    pub fn from_response(
        bytes: &[u8],
        service_key: &[u8; 32],
        identity: &[u8; 32],
    ) -> Result<Self> {
        check_response_size(bytes)?;
        let value: Value = parse_json(bytes)?;
        reject_unknown_members(&value, &["preparation"], "recovery preparation response")?;
        Self::verify(
            &carried(bytes, &value, "preparation")?,
            service_key,
            identity,
        )
    }
}

fn check_response_size(bytes: &[u8]) -> Result<()> {
    if bytes.len() > super::MAX_RESPONSE_BYTES {
        return invalid("Switch account binding 3.3: oversized recovery response");
    }
    Ok(())
}

fn carried(bytes: &[u8], value: &Value, member: &str) -> Result<SignedDoc> {
    if !crate::json::member_span(bytes, member).is_some_and(|r| r.len() <= MAX_EVIDENCE_BYTES) {
        return invalid(
            "Switch account binding 3.3: missing or oversized signed recovery evidence",
        );
    }
    SignedDoc::from_strict_value(&value[member])
}
