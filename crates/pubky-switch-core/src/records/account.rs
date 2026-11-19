//! Authenticated account observations and enrollment intents (Switch account binding 2-3).

use serde::{Deserialize, Serialize};

use super::{check_tag, decode, encode, fmt, is_origin};
use crate::enc::{b64, pubky_id, serde_b64};
use crate::error::{Result, invalid};
use crate::http::{
    self, BodyField, ReceivedHeaders, ReceivedRequest, RequestHeaders, RequestTarget, ResponseParts,
};
use crate::json::{parse_json, reject_unknown_members};
use crate::time::{MAX_TIME_MS, rfc3339, rfc3339_seconds};

/// The account discovery body's kind (Switch account binding 2).
pub const ACCOUNT_OBSERVATION_KIND: &str = "pubky-switch.account";
/// The exact observation lifetime; no HTTP clock tolerance extends it.
pub const ACCOUNT_OBSERVATION_VALIDITY_MS: u64 = 300_000;
/// The maximum exact successful discovery body, including whitespace and escapes
/// (Switch account binding 2).
pub const MAX_ACCOUNT_OBSERVATION_BYTES: usize = 1024;
/// The largest compact carried observation. This bounds locally written JSON, not the
/// raw spelling of an unsigned carrier (Switch account binding 2.1).
pub const MAX_CARRIED_ACCOUNT_OBSERVATION_BYTES: usize =
    br#"{"body":"","sig":"","request_timestamp":"","request_signature":""}"#.len()
        + (MAX_ACCOUNT_OBSERVATION_BYTES * 4).div_ceil(3)
        + 2 * 86
        + 20;
/// The largest compact enrollment intent: a takeover with its exact bounded observation
/// (Switch account binding 2.1). It reserves no ability to alter pending signed bytes.
pub const MAX_ENROLLMENT_INTENT_BYTES: usize = br#"{"kind":"takeover","created":"","observation":}"#
    .len()
    + 24 + MAX_CARRIED_ACCOUNT_OBSERVATION_BYTES;

/// The current account's durable activation requirement (Switch account binding 3.1).
/// A retained safety baseline is not an accepted document in its new lifetime.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AccountActivation {
    /// Ordinary enrollment and import activation rules apply.
    Ordinary,
    /// Only a durable authorized higher recovery may activate this account.
    Recovery,
}

impl AccountActivation {
    /// The required persisted value.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Ordinary => "ordinary",
            Self::Recovery => "recovery",
        }
    }

    /// Read the required current-account value.
    ///
    /// # Errors
    ///
    /// [`crate::Error::Invalid`] for any other value.
    pub fn parse(value: &str) -> Result<Self> {
        match value {
            "ordinary" => Ok(Self::Ordinary),
            "recovery" => Ok(Self::Recovery),
            _ => invalid("account activation requirement"),
        }
    }
}

/// The current lifetime established by the locked account and mark inputs
/// (Switch account binding 1.1).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AccountAssociation {
    /// The selected SQL account, including when its mark is lost or older.
    Account,
    /// The selected surviving mark, with no associated SQL account.
    Mark,
    /// Established absence of both the SQL account and its mark.
    Absent,
}

impl<'de> Deserialize<'de> for AccountAssociation {
    fn deserialize<D: serde::Deserializer<'de>>(
        deserializer: D,
    ) -> std::result::Result<Self, D::Error> {
        match String::deserialize(deserializer)?.as_str() {
            "account" => Ok(Self::Account),
            "mark" => Ok(Self::Mark),
            "absent" => Ok(Self::Absent),
            _ => Err(serde::de::Error::custom("invalid account association")),
        }
    }
}

/// The established mark input for selecting an account lifetime. This does not replace
/// the physical mark or any of its recovery bounds (Switch account binding 1.1).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AccountMarkInput {
    /// The store could not be read reliably.
    Unreadable,
    /// The confirmed store has no mark for this identity.
    Missing,
    /// A record exists but is not a readable mark.
    Malformed,
    /// The creation in a readable mark, including a zero mark.
    Created(u64),
}

/// A consistent selected association and creation (Switch account binding 1.1).
/// Selection never consumes the physical inputs or discards their recovery bounds.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AccountBinding {
    association: AccountAssociation,
    created: Option<u64>,
}

impl AccountBinding {
    /// Select from readable SQL (or established SQL absence) and the distinct mark input.
    /// Callers first enforce SQL/store identity, erasure outcome and cleanup checks.
    ///
    /// # Errors
    ///
    /// [`crate::Error::Invalid`] when an input is unestablished or a creation is invalid.
    pub fn select(account_created: Option<u64>, mark: AccountMarkInput) -> Result<Self> {
        if account_created.is_some_and(|created| created > MAX_TIME_MS)
            || matches!(mark, AccountMarkInput::Created(created) if created > MAX_TIME_MS)
        {
            return invalid("account creation is outside the time range");
        }
        let (association, created) = match (account_created, mark) {
            (_, AccountMarkInput::Unreadable) | (None, AccountMarkInput::Malformed) => {
                return invalid("account association is unavailable");
            }
            (Some(account), AccountMarkInput::Created(mark)) if account < mark => {
                (AccountAssociation::Mark, Some(mark))
            }
            (Some(account), _) => (AccountAssociation::Account, Some(account)),
            (None, AccountMarkInput::Created(mark)) => (AccountAssociation::Mark, Some(mark)),
            (None, AccountMarkInput::Missing) => (AccountAssociation::Absent, None),
        };
        Ok(Self {
            association,
            created,
        })
    }

    /// The durable input establishing this lifetime, or established absence.
    pub fn association(self) -> AccountAssociation {
        self.association
    }

    /// The selected creation; absent exactly when the association is absent.
    pub fn created(self) -> Option<u64> {
        self.created
    }
}

/// The strict body of the authenticated account discovery response.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AccountObservationBody {
    /// The requested identity.
    #[serde(with = "fmt::pubky")]
    pub identity: [u8; 32],
    /// The exact request-signature origin.
    pub origin: String,
    /// The key signing the response.
    #[serde(with = "serde_b64")]
    pub service_key: [u8; 32],
    /// The existing mark-store identity.
    #[serde(with = "serde_b64")]
    pub store_id: [u8; 16],
    /// Which durable input establishes the selected lifetime, or established absence.
    pub association: AccountAssociation,
    /// The established creation, or explicit current absence.
    #[serde(with = "nullable_millis")]
    pub created: Option<u64>,
    /// The latest completed erasure, or its established absence.
    #[serde(with = "nullable_millis")]
    pub erased_at: Option<u64>,
    /// The trusted observation time, independent of account-stamped time.
    #[serde(with = "millis")]
    pub observed_at: u64,
    /// Exactly five minutes after `observed_at`.
    #[serde(with = "millis")]
    pub expires_at: u64,
}

impl AccountObservationBody {
    /// Read the exact strict discovery body (Switch account binding 2).
    ///
    /// # Errors
    ///
    /// [`crate::Error::Invalid`] for malformed fields, unknown members or invalid times.
    pub fn from_json(bytes: &[u8]) -> Result<Self> {
        check_observation_size(bytes.len())?;
        let value = parse_json(bytes)?;
        check_tag(&value, ACCOUNT_OBSERVATION_KIND, "Switch account binding 2")?;
        reject_unknown_members(
            &value,
            &[
                "v",
                "kind",
                "identity",
                "origin",
                "service_key",
                "store_id",
                "association",
                "created",
                "erased_at",
                "observed_at",
                "expires_at",
            ],
            "account observation",
        )?;
        let body: Self = decode(value)?;
        body.check()?;
        Ok(body)
    }

    /// Write the checked body, with `v` and `kind` first.
    ///
    /// # Errors
    ///
    /// [`crate::Error::Invalid`] if the fields cannot form an observation.
    pub fn to_json(&self) -> Result<Vec<u8>> {
        self.check()?;
        let bytes = encode(ACCOUNT_OBSERVATION_KIND, self)?;
        check_observation_size(bytes.len())?;
        Ok(bytes)
    }

    fn check(&self) -> Result<()> {
        if !is_origin(&self.origin) {
            return invalid("Switch account binding 2: invalid origin");
        }
        if (self.association == AccountAssociation::Absent) != self.created.is_none() {
            return invalid("Switch account binding 2: association and creation disagree");
        }
        if self.expires_at > MAX_TIME_MS
            || self
                .observed_at
                .checked_add(ACCOUNT_OBSERVATION_VALIDITY_MS)
                != Some(self.expires_at)
        {
            return invalid("Switch account binding 2.2: invalid expiry");
        }
        if self
            .created
            .into_iter()
            .chain(self.erased_at)
            .any(|at| at > self.observed_at)
        {
            return invalid("Switch account binding 2.2: observation precedes account history");
        }
        Ok(())
    }
}

fn check_observation_size(bytes: usize) -> Result<()> {
    if bytes > MAX_ACCOUNT_OBSERVATION_BYTES {
        return invalid("Switch account binding 2: discovery body exceeds its byte limit");
    }
    Ok(())
}

/// The exact original discovery response and request authentication carried by an intent.
/// Verification does not reserialize `body` or replace the original request timestamp.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CarriedAccountObservation {
    /// The exact successful response body bytes.
    #[serde(with = "observation_bytes")]
    pub body: Vec<u8>,
    /// The response's service signature.
    #[serde(with = "serde_b64")]
    pub sig: [u8; 64],
    /// The exact original request time, without fractional digits.
    pub request_timestamp: String,
    /// The identity's signature on that discovery request.
    #[serde(with = "serde_b64")]
    pub request_signature: [u8; 64],
}

impl CarriedAccountObservation {
    /// Verify both signatures and the expected identity/origin (Switch account binding 2.1).
    /// The caller separately applies its service-key pin and current locked binding rules.
    /// Expiry is not checked here: a retained same-account receipt can outlive it.
    ///
    /// # Errors
    ///
    /// [`crate::Error::Invalid`] for malformed or mismatched context;
    /// [`crate::Error::Signature`] if either signature does not verify.
    pub fn verify(&self, identity: &[u8; 32], origin: &str) -> Result<AccountObservation> {
        let body = AccountObservationBody::from_json(&self.body)?;
        if body.identity != *identity || body.origin != origin {
            return invalid("Switch account binding 2.1: another identity or origin");
        }
        let timestamp = crate::time::parse_rfc3339(&self.request_timestamp)?;
        if rfc3339_seconds(timestamp) != self.request_timestamp {
            return invalid("Switch account binding 2.1: request time needs whole seconds");
        }
        let path = format!("/v1/{}/account", pubky_id(identity));
        let headers = RequestHeaders {
            timestamp: self.request_timestamp.clone(),
            identity: pubky_id(identity),
            app: None,
            cert: None,
            invite_code: None,
            created: None,
        };
        let target = RequestTarget {
            method: "GET",
            path_and_query: &path,
            body: &[],
            origin,
        };
        http::verify_request(identity, &target, &headers, &self.request_signature)?;
        let signature = b64(&self.request_signature);
        let received = ReceivedHeaders::of([
            (http::header::IDENTITY, headers.identity.as_bytes()),
            (http::header::TIMESTAMP, self.request_timestamp.as_bytes()),
            (http::header::SIGNATURE, signature.as_bytes()),
        ]);
        let server_time = rfc3339(body.observed_at);
        let response = ResponseParts {
            status: 200,
            request: ReceivedRequest {
                method: "GET",
                path_and_query: &path,
                body: BodyField::read(&[]),
                origin,
                headers: &received,
            },
            server_time: &server_time,
            head: None,
            body: &self.body,
        };
        http::verify_response(&body.service_key, &response, &self.sig)?;
        Ok(AccountObservation {
            body,
            carried: self.clone(),
        })
    }
}

/// An observation with its exact original request and response signatures verified.
/// This proves what its service key said, not trust in that key or the current durable tuple.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AccountObservation {
    body: AccountObservationBody,
    carried: CarriedAccountObservation,
}

impl AccountObservation {
    /// The authenticated fields.
    pub fn body(&self) -> &AccountObservationBody {
        &self.body
    }

    /// The original bytes and signatures, suitable for the exact pending intent.
    pub fn carried(&self) -> &CarriedAccountObservation {
        &self.carried
    }

    /// Select the initial intent for a distinct authorized enrollment from this verified
    /// observation (Switch account binding 1.1). Never use this to refresh a pending intent.
    /// Service-key trust and authorization remain the caller's responsibilities.
    ///
    /// # Errors
    ///
    /// [`crate::Error::Invalid`] if the association and creation are inconsistent.
    pub fn enrollment_intent(&self) -> Result<EnrollmentIntent> {
        match (self.body.association, self.body.created) {
            (AccountAssociation::Account, Some(created)) => {
                Ok(EnrollmentIntent::Existing { created })
            }
            (AccountAssociation::Mark, Some(created)) => Ok(EnrollmentIntent::Takeover {
                created,
                observation: self.carried.clone(),
            }),
            (AccountAssociation::Absent, None) => Ok(EnrollmentIntent::Create {
                observation: self.carried.clone(),
            }),
            _ => invalid("Switch account binding 2: association and creation disagree"),
        }
    }

    /// Compare against usable trusted time without grace (Switch account binding 2.2).
    /// The caller must refuse when it has no usable trusted time; account-stamped time and
    /// wall time are not substitutes for this argument.
    pub fn validity(&self, trusted_now: u64) -> ObservationValidity {
        if trusted_now < self.body.observed_at {
            ObservationValidity::Future
        } else if trusted_now >= self.body.expires_at {
            ObservationValidity::Expired
        } else {
            ObservationValidity::Current
        }
    }
}

/// The distinct trusted-time outcomes, before a fresh creation can be authorized.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ObservationValidity {
    /// The observation is not from the future and has not expired.
    Current,
    /// Trusted time is behind the observation; no authority is available.
    Future,
    /// The exact expiry has been reached; a new intent is a separate authorized action.
    Expired,
}

/// The complete, strict enrollment intent (Switch account binding 3).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum EnrollmentIntent {
    /// Create from an authenticated absence, without an account creation header.
    Create {
        /// The original service observation, retained byte for byte.
        observation: CarriedAccountObservation,
    },
    /// Enroll at the same account; this cannot create an account.
    Existing {
        /// The account creation also carried by the request header.
        #[serde(with = "millis")]
        created: u64,
    },
    /// Explicitly take over the exact surviving mark after database loss.
    Takeover {
        /// The old mark creation also carried by the request header.
        #[serde(with = "millis")]
        created: u64,
        /// The original service observation naming that mark.
        observation: CarriedAccountObservation,
    },
}

impl EnrollmentIntent {
    /// The required creation header's value, or absence for a fresh creation.
    pub fn created(&self) -> Option<u64> {
        match self {
            Self::Create { .. } => None,
            Self::Existing { created } | Self::Takeover { created, .. } => Some(*created),
        }
    }

    /// Verify the carried observation and intent association, without checking expiry.
    /// Service-key trust, current store/erasure state and exact receipt handling remain the
    /// caller's locked decisions (Switch account binding 3).
    ///
    /// # Errors
    ///
    /// [`crate::Error::Invalid`] for an invalid intent or mismatched observation, and
    /// [`crate::Error::Signature`] for an invalid carried signature.
    pub fn check(&self, identity: &[u8; 32], origin: &str) -> Result<Option<AccountObservation>> {
        if self.created().is_some_and(|created| created > MAX_TIME_MS) {
            return invalid("Switch account binding 3: creation is unrepresentable");
        }
        let carried = match self {
            Self::Existing { .. } => return Ok(None),
            Self::Create { observation } | Self::Takeover { observation, .. } => observation,
        };
        let observation = carried.verify(identity, origin)?;
        let association = match self {
            Self::Create { .. } => AccountAssociation::Absent,
            Self::Takeover { .. } => AccountAssociation::Mark,
            Self::Existing { .. } => AccountAssociation::Account,
        };
        if observation.body.created != self.created() || observation.body.association != association
        {
            return invalid("Switch account binding 3: intent names another creation");
        }
        Ok(Some(observation))
    }
}

mod observation_bytes {
    use serde::{Deserializer, Serializer, de::Visitor};

    use super::{MAX_ACCOUNT_OBSERVATION_BYTES, check_observation_size};

    pub fn serialize<S: Serializer>(bytes: &[u8], serializer: S) -> Result<S::Ok, S::Error> {
        check_observation_size(bytes.len()).map_err(serde::ser::Error::custom)?;
        serializer.serialize_str(&crate::enc::b64(bytes))
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(deserializer: D) -> Result<Vec<u8>, D::Error> {
        struct Body;
        impl Visitor<'_> for Body {
            type Value = Vec<u8>;

            fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_str("a bounded account observation body in base64url")
            }

            fn visit_str<E: serde::de::Error>(self, text: &str) -> Result<Vec<u8>, E> {
                // Check the encoded length before allocating the decoded body. Base64url
                // is unpadded; the shared decoder also checks its canonical spelling.
                if text.len() > (MAX_ACCOUNT_OBSERVATION_BYTES * 4).div_ceil(3) {
                    return Err(E::custom(
                        "Switch account binding 2: discovery body exceeds its byte limit",
                    ));
                }
                let bytes = crate::enc::unb64(text).map_err(E::custom)?;
                check_observation_size(bytes.len()).map_err(E::custom)?;
                Ok(bytes)
            }
        }
        deserializer.deserialize_str(Body)
    }
}

pub(super) mod millis {
    use serde::{Deserialize, Deserializer, Serializer, de::Error as _};

    pub fn serialize<S: Serializer>(value: &u64, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&crate::time::rfc3339(*value))
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(deserializer: D) -> Result<u64, D::Error> {
        let text = String::deserialize(deserializer)?;
        crate::http::parse_created(&text).map_err(D::Error::custom)
    }
}

pub(super) mod nullable_millis {
    use serde::{Deserialize, Deserializer, Serialize, Serializer, de::Error as _};

    pub fn serialize<S: Serializer>(value: &Option<u64>, serializer: S) -> Result<S::Ok, S::Error> {
        value.map(crate::time::rfc3339).serialize(serializer)
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(
        deserializer: D,
    ) -> Result<Option<u64>, D::Error> {
        Option::<String>::deserialize(deserializer)?
            .map(|text| crate::http::parse_created(&text).map_err(D::Error::custom))
            .transpose()
    }
}
