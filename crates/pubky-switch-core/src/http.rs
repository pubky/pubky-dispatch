//! Requests to and responses from the switch (Switch wire 7.1, 7.2, 7.6), and the push
//! webhook (Switch wire 8.2): what each signature covers, signing and checking, body caps and
//! the error codes.
//!
//! The transport is the caller's: these functions build and check the signed fields of a
//! request or response whose method, path, headers and body the caller holds.

use serde::{Deserialize, Serialize};

use crate::enc::{hash, lp, u64be, unb64_array};
use crate::error::{Error, Result, invalid};
use crate::labels;
use crate::sig;
use crate::signing::Signs;

/// Header names, as the switch sends them, in lower case; names are case-insensitive
/// (Switch wire 7.1).
pub mod header {
    /// The caller's identity, a Pubky ID.
    pub const IDENTITY: &str = "switch-identity";
    /// The calling App ID; absent for the signer.
    pub const APP: &str = "switch-app";
    /// The app's certificate in compact form, for calls to another identity's account.
    pub const CERT: &str = "switch-cert";
    /// An invite code.
    pub const INVITE_CODE: &str = "switch-invite-code";
    /// The creation of the account a signer request concerns, with three fraction digits.
    pub const CREATED: &str = "switch-created";
    /// The signer's export transfer in compact form, for the next service's chunk fetches.
    pub const TRANSFER: &str = "switch-transfer";
    /// The signing time, `YYYY-MM-DDTHH:MM:SSZ`.
    pub const TIMESTAMP: &str = "switch-timestamp";
    /// The request signature, `b64(64)`.
    pub const SIGNATURE: &str = "switch-signature";
    /// The response signature, `b64(64)`.
    pub const SERVICE_SIGNATURE: &str = "switch-service-signature";
    /// The identity's service time, three fraction digits.
    pub const SERVER_TIME: &str = "switch-server-time";
    /// The newest signed head, base64url of its JSON.
    pub const HEAD: &str = "switch-head";
    /// Seconds to wait, on `429`.
    pub const RETRY_AFTER: &str = "retry-after";
}

/// How far a `Switch-Timestamp` may be from the service's time base: 5 minutes (Switch wire
/// 7.1).
pub const TIMESTAMP_TOLERANCE_MS: u64 = 5 * 60 * 1000;

/// Maximum cache age of a public identity response (Switch wire 7.4.15).
pub const PUBLIC_READ_CACHE_MS: u64 = 60_000;

/// Cache-Control for a successful public identity read (Switch wire 7.4.15).
pub fn public_read_cache_control() -> String {
    format!(
        "public, max-age={}, must-revalidate",
        PUBLIC_READ_CACHE_MS / 1000
    )
}

/// The headers a request to the switch signs, as their exact text; `None` when absent
/// (Switch wire 7.1).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct RequestHeaders {
    /// `Switch-Timestamp`.
    pub timestamp: String,
    /// `Switch-Identity`.
    pub identity: String,
    /// `Switch-App`; absent for the signer.
    pub app: Option<String>,
    /// `Switch-Cert`.
    pub cert: Option<String>,
    /// `Switch-Invite-Code`.
    pub invite_code: Option<String>,
    /// `Switch-Created`; absent for app calls and fresh account discovery/creation.
    pub created: Option<String>,
}

/// The parts of a request its signature covers besides the headers.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RequestTarget<'a> {
    /// The method, exactly as sent; the routes name theirs in upper case.
    pub method: &'a str,
    /// The path and query, exactly as sent.
    pub path_and_query: &'a str,
    /// The raw body bytes; empty for a request without a body.
    pub body: &'a [u8],
    /// The switch origin, exactly as `identity.json` names it in `inbox.url`, for example
    /// `https://inbox.example`. It isn't sent; both sides know it.
    pub origin: &'a str,
}

/// The fields after the label of a request signature: method, as sent, path and query,
/// `hash(body)`, `Switch-Timestamp`, switch origin, `Switch-Identity`, `Switch-App`,
/// `Switch-Cert`, `Switch-Invite-Code` and `Switch-Created`, an absent header as an empty
/// field (Switch wire 7.1; Switch account binding 1).
pub fn request_fields(target: &RequestTarget<'_>, headers: &RequestHeaders) -> Vec<Vec<u8>> {
    vec![
        target.method.as_bytes().to_vec(),
        target.path_and_query.as_bytes().to_vec(),
        hash(target.body).to_vec(),
        headers.timestamp.as_bytes().to_vec(),
        target.origin.as_bytes().to_vec(),
        headers.identity.as_bytes().to_vec(),
        headers
            .app
            .as_deref()
            .unwrap_or_default()
            .as_bytes()
            .to_vec(),
        headers
            .cert
            .as_deref()
            .unwrap_or_default()
            .as_bytes()
            .to_vec(),
        headers
            .invite_code
            .as_deref()
            .unwrap_or_default()
            .as_bytes()
            .to_vec(),
        headers
            .created
            .as_deref()
            .unwrap_or_default()
            .as_bytes()
            .to_vec(),
    ]
}

/// Read an account creation header with exactly three fractional digits
/// (Switch account binding 1).
///
/// # Errors
///
/// [`Error::Invalid`] if the text is not the exact required UTC representation.
pub fn parse_created(text: &str) -> Result<u64> {
    let created = crate::time::parse_rfc3339(text)?;
    if crate::time::rfc3339(created) != text {
        return invalid("Switch account binding 1: creation needs three fraction digits");
    }
    Ok(created)
}

fn refs(fields: &[Vec<u8>]) -> Vec<&[u8]> {
    fields.iter().map(Vec::as_slice).collect()
}

/// Sign a request to the switch with the identity key or an app's signing key (Switch wire
/// 7.1): the value of `Switch-Signature`.
pub fn sign_request(
    key: &impl Signs,
    target: &RequestTarget<'_>,
    headers: &RequestHeaders,
) -> [u8; 64] {
    key.sign_fields(labels::sig::HTTP, &refs(&request_fields(target, headers)))
}

/// Check a request signature (Switch wire 7.1).
///
/// # Errors
///
/// [`Error::Signature`] if it doesn't verify with `public`.
pub fn verify_request(
    public: &[u8; 32],
    target: &RequestTarget<'_>,
    headers: &RequestHeaders,
    signature: &[u8; 64],
) -> Result<()> {
    sig::verify(
        public,
        labels::sig::HTTP,
        &refs(&request_fields(target, headers)),
        signature,
    )
}

/// The headers of the next service's export request (Switch wire 7.1, 7.2): it carries
/// `Switch-Transfer` and no `Switch-App`, `Switch-Cert` or `Switch-Invite-Code`.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct TransferHeaders {
    /// `Switch-Timestamp`.
    pub timestamp: String,
    /// `Switch-Identity`: the account's identity.
    pub identity: String,
    /// `Switch-Transfer`: the signer's export transfer in compact form.
    pub transfer: String,
}

/// The fields after the label of the next service's request signature: method, path and
/// query, `hash(body)`, `Switch-Timestamp`, switch origin (the old service's),
/// `Switch-Identity` and `Switch-Transfer` (Switch wire 7.1).
pub fn transfer_request_fields(
    target: &RequestTarget<'_>,
    headers: &TransferHeaders,
) -> Vec<Vec<u8>> {
    vec![
        target.method.as_bytes().to_vec(),
        target.path_and_query.as_bytes().to_vec(),
        hash(target.body).to_vec(),
        headers.timestamp.as_bytes().to_vec(),
        target.origin.as_bytes().to_vec(),
        headers.identity.as_bytes().to_vec(),
        headers.transfer.as_bytes().to_vec(),
    ]
}

/// Sign the next service's export request with its key for the account (Switch wire 7.1).
pub fn sign_transfer_request(
    key: &impl Signs,
    target: &RequestTarget<'_>,
    headers: &TransferHeaders,
) -> [u8; 64] {
    key.sign_fields(
        labels::sig::TRANSFER_REQUEST,
        &refs(&transfer_request_fields(target, headers)),
    )
}

/// Check the next service's request signature with the key the export transfer names
/// (Switch wire 7.2).
///
/// # Errors
///
/// [`Error::Signature`] if it doesn't verify with `public`.
pub fn verify_transfer_request(
    public: &[u8; 32],
    target: &RequestTarget<'_>,
    headers: &TransferHeaders,
    signature: &[u8; 64],
) -> Result<()> {
    sig::verify(
        public,
        labels::sig::TRANSFER_REQUEST,
        &refs(&transfer_request_fields(target, headers)),
        signature,
    )
}

/// The request headers a received request covers, in its order (Switch wire 7.1).
pub const RECEIVED_HEADERS: [&str; 8] = [
    header::IDENTITY,
    header::APP,
    header::CERT,
    header::INVITE_CODE,
    header::TRANSFER,
    header::TIMESTAMP,
    header::SIGNATURE,
    header::CREATED,
];

/// The body field of a received request (Switch wire 7.1).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BodyField {
    /// The answer came before the service read the body: an empty field. Only a `413
    /// too_large`, a `429 rate_limited` before authentication and the `404` of an unknown
    /// route may come so.
    NotRead,
    /// `hash(body)`, once the service has read the body whole.
    Read([u8; 32]),
}

impl BodyField {
    /// The field of a body read whole.
    pub fn read(body: &[u8]) -> Self {
        BodyField::Read(hash(body))
    }

    /// The field's bytes: empty, or the 32 bytes of the hash.
    pub fn as_bytes(&self) -> &[u8] {
        match self {
            BodyField::NotRead => &[],
            BodyField::Read(hash) => hash,
        }
    }
}

/// The values of the request headers a received request covers ([`RECEIVED_HEADERS`]), each
/// with its presence: every value of a header in the order received, none for a header
/// absent (Switch wire 7.1).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ReceivedHeaders {
    values: [Vec<Vec<u8>>; 8],
}

impl ReceivedHeaders {
    /// The headers of `pairs`, a request's headers as (name, value) in the order received;
    /// names are compared case-insensitively, and headers a received request doesn't cover
    /// are left out.
    pub fn of<'a>(pairs: impl IntoIterator<Item = (&'a str, &'a [u8])>) -> Self {
        let mut headers = ReceivedHeaders::default();
        for (name, value) in pairs {
            if let Some(at) = RECEIVED_HEADERS
                .iter()
                .position(|covered| covered.eq_ignore_ascii_case(name))
                && let Some(values) = headers.values.get_mut(at)
            {
                values.push(value.to_vec());
            }
        }
        headers
    }

    /// The values of the header `name` in the order received; empty when it is absent or
    /// isn't one a received request covers.
    pub fn values(&self, name: &str) -> &[Vec<u8>] {
        RECEIVED_HEADERS
            .iter()
            .position(|covered| covered.eq_ignore_ascii_case(name))
            .and_then(|at| self.values.get(at))
            .map_or(&[], Vec::as_slice)
    }

    /// The header rule these headers break, as the reason of its `400 bad_request`, or
    /// `None` (Switch wire 7.1 "Each header once, as text"): a signed request header sent more
    /// than once, or present with a value that is empty or isn't printable ASCII (bytes 0x20
    /// to 0x7E). The service never acts on signed values it would have to choose between, or
    /// on one it would read otherwise than its answer binds it. The public read, which uses
    /// none of these headers, is exempt; the caller decides that by the call.
    pub fn broken_rule(&self) -> Option<&'static str> {
        if self.values.iter().any(|values| values.len() > 1) {
            return Some("7.1: a signed request header sent more than once");
        }
        let mut values = self.values.iter().flatten();
        if values.clone().any(Vec::is_empty) {
            return Some("7.1: a signed request header with an empty value");
        }
        if values.any(|value| !value.iter().all(|byte| (0x20..=0x7e).contains(byte))) {
            return Some("7.1: a signed request header whose value isn't printable ASCII");
        }
        None
    }
}

/// The request a response answers, exactly as the service received it (Switch wire 7.1).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ReceivedRequest<'a> {
    /// The method, exactly as received, never case-folded.
    pub method: &'a str,
    /// The path and query, exactly as received: not percent-decoded, the query included.
    pub path_and_query: &'a str,
    /// `hash(body)` once the body is read whole; [`BodyField::NotRead`] for an answer given
    /// before.
    pub body: BodyField,
    /// The switch origin, as the request signature takes it.
    pub origin: &'a str,
    /// The request headers it covers, each with its presence.
    pub headers: &'a ReceivedHeaders,
}

/// Whether `method` and `path_and_query` are the public read, `GET /v1/{id}/identity`
/// (Switch wire 7.4.15), as the service routes it: the method exactly `GET`, the path, before
/// any query, `/v1/`, a non-empty `{id}` and `/identity`.
pub fn is_public_read(method: &str, path_and_query: &str) -> bool {
    let path = path_and_query.split('?').next().unwrap_or_default();
    let Some(rest) = path.strip_prefix("/v1/") else {
        return false;
    };
    method == "GET"
        && matches!(rest.split('/').collect::<Vec<_>>().as_slice(), [id, "identity"] if !id.is_empty())
}

/// The bytes of a received request (Switch wire 7.1): `lp(method, path and query, body
/// field, switch origin, H(Switch-Identity), H(Switch-App), H(Switch-Cert),
/// H(Switch-Invite-Code), H(Switch-Transfer), H(Switch-Timestamp), H(Switch-Signature),
/// H(Switch-Created))`.
/// `H` of a header is empty when it is absent and `lp()` of its values in the order received
/// when present. The public read binds every header field as absent, whatever the request
/// carries ([`is_public_read`]). Every signer and verifier of a response takes the received
/// request from here.
pub fn received_request(request: &ReceivedRequest<'_>) -> Vec<u8> {
    let public_read = is_public_read(request.method, request.path_and_query);
    let header_fields: Vec<Vec<u8>> = request
        .headers
        .values
        .iter()
        .map(|values| {
            if public_read || values.is_empty() {
                Vec::new()
            } else {
                lp(&refs(values))
            }
        })
        .collect();
    let mut fields: Vec<&[u8]> = vec![
        request.method.as_bytes(),
        request.path_and_query.as_bytes(),
        request.body.as_bytes(),
        request.origin.as_bytes(),
    ];
    fields.extend(header_fields.iter().map(Vec::as_slice));
    lp(&fields)
}

/// What a response signature covers besides its label (Switch wire 7.1, 2.3).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ResponseParts<'a> {
    /// The HTTP status.
    pub status: u16,
    /// The request the response answers, as the service received it.
    pub request: ReceivedRequest<'a>,
    /// The `Switch-Server-Time` text.
    pub server_time: &'a str,
    /// The `Switch-Head` text, exactly as sent; `None` when the response carries none.
    pub head: Option<&'a str>,
    /// The raw body bytes.
    pub body: &'a [u8],
}

/// The fields after the label of a response signature: `u64(status)`, `hash(received
/// request)` ([`received_request`]), the `Switch-Server-Time` text, the head field and
/// `hash(body)` (Switch wire 7.1). The head field is empty when the response carries no
/// `Switch-Head` and `hash` of its text when it carries one, so an absent head and an empty
/// one differ.
pub fn response_fields(parts: &ResponseParts<'_>) -> Vec<Vec<u8>> {
    vec![
        u64be(u64::from(parts.status)).to_vec(),
        hash(&received_request(&parts.request)).to_vec(),
        parts.server_time.as_bytes().to_vec(),
        parts
            .head
            .map_or_else(Vec::new, |head| hash(head.as_bytes()).to_vec()),
        hash(parts.body).to_vec(),
    ]
}

/// Sign a response with the service key (Switch wire 7.1).
pub fn sign_response(key: &impl Signs, parts: &ResponseParts<'_>) -> [u8; 64] {
    key.sign_fields(labels::sig::HTTP_RESPONSE, &refs(&response_fields(parts)))
}

/// Check a response signature with the service key the client pinned (Switch wire 7.1).
///
/// A client checks this before it uses anything in the response, with the received request
/// built from what it sent.
///
/// # Errors
///
/// [`Error::Signature`] if it doesn't verify with `service_key`.
pub fn verify_response(
    service_key: &[u8; 32],
    parts: &ResponseParts<'_>,
    signature: &[u8; 64],
) -> Result<()> {
    sig::verify(
        service_key,
        labels::sig::HTTP_RESPONSE,
        &refs(&response_fields(parts)),
        signature,
    )
}

/// The relay origin a webhook signature covers: `https://` and the relay URL's host,
/// without port or path (Switch wire 8.2).
///
/// # Errors
///
/// [`Error::Invalid`] if the URL isn't `https` or has no host.
pub fn relay_origin(relay_url: &str) -> Result<String> {
    let Some(rest) = relay_url.strip_prefix("https://") else {
        return invalid("Switch wire 8.2: a relay URL is https");
    };
    let authority = rest.split(['/', '?', '#']).next().unwrap_or_default();
    let host = authority
        .rsplit_once('@')
        .map_or(authority, |(_, host)| host);
    let host = if let Some(bracketed) = host.strip_prefix('[') {
        bracketed.split_once(']').map_or("", |(inner, _)| inner)
    } else {
        host.split(':').next().unwrap_or_default()
    };
    if host.is_empty() {
        return invalid("Switch wire 8.2: a relay URL has a host");
    }
    if relay_url.contains("://[") {
        return Ok(format!("https://[{host}]"));
    }
    Ok(format!("https://{host}"))
}

/// A webhook body: `{"v":1,"handle":...,"ts":...,"nonce":...}`, with the service time when
/// sent and a fresh random nonce (Switch wire 8.2). It names nothing about the message.
pub fn webhook_body(handle: &str, sent_at_ms: u64, nonce: &[u8; 16]) -> Vec<u8> {
    // The members in the order Switch wire 8.2 shows them; the handle is escaped as a JSON
    // string.
    let handle = serde_json::Value::String(handle.to_owned());
    format!(
        "{{\"v\":1,\"handle\":{handle},\"ts\":\"{}\",\"nonce\":\"{}\"}}",
        crate::time::rfc3339(sent_at_ms),
        crate::enc::b64(nonce)
    )
    .into_bytes()
}

/// Sign a webhook with the registration's push key, never the service key, over
/// `lp("pubky-switch/v1/push", relay origin, body bytes)` (Switch wire 8.2).
///
/// # Errors
///
/// [`Error::Invalid`] if the relay URL has no origin.
pub fn sign_webhook(push_key: &impl Signs, relay_url: &str, body: &[u8]) -> Result<[u8; 64]> {
    let origin = relay_origin(relay_url)?;
    Ok(push_key.sign_fields(labels::sig::PUSH, &[origin.as_bytes(), body]))
}

/// Check a webhook signature, as the push relay does (Switch wire 8.2, 8.3).
///
/// # Errors
///
/// [`Error::Invalid`] if the relay URL has no origin, [`Error::Signature`] if the signature
/// doesn't verify with `push_key`.
pub fn verify_webhook(
    push_key: &[u8; 32],
    relay_url: &str,
    body: &[u8],
    signature: &[u8; 64],
) -> Result<()> {
    let origin = relay_origin(relay_url)?;
    sig::verify(
        push_key,
        labels::sig::PUSH,
        &[origin.as_bytes(), body],
        signature,
    )
}

/// The body of `PUT /v1/{id}/identity`: `{ "identity": signed<IdentityDoc>, "prev": b64(32)
/// | null }` (Switch wire 7.4.2).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IdentityDelivery {
    /// The delivered `identity.json`, as signed.
    pub identity: sig::SignedDoc,
    /// The document hash of the version this one builds on; `None` for the first delivery
    /// to an account that holds none.
    pub prev: Option<[u8; 32]>,
}

impl IdentityDelivery {
    /// Read a delivery body. `prev` is always written, `null` for none; other members are
    /// ignored (Switch wire 1.1).
    ///
    /// # Errors
    ///
    /// [`Error::Invalid`] if the body isn't strict JSON of that shape.
    pub fn parse(body: &[u8]) -> Result<Self> {
        let value: serde_json::Value = crate::json::parse_json(body)?;
        let Some(identity) = value.get("identity") else {
            return invalid("Switch wire 7.4.2: a delivery carries `identity`");
        };
        let identity: sig::SignedDoc = serde_json::from_value(identity.clone())?;
        let prev = match value.get("prev") {
            Some(serde_json::Value::Null) => None,
            Some(serde_json::Value::String(text)) => Some(unb64_array::<32>(text)?),
            _ => return invalid("Switch wire 7.4.2: `prev` is a hash or null"),
        };
        Ok(Self { identity, prev })
    }

    /// Write a delivery body.
    pub fn to_json(&self) -> Vec<u8> {
        serde_json::json!({
            "identity": self.identity,
            "prev": self.prev.map(|hash| crate::enc::b64(&hash)),
        })
        .to_string()
        .into_bytes()
    }
}

/// The answer body of a committed erasure, `{"erased":true}` (Switch wire 7.4.16).
pub const ERASED_BODY: &[u8] = br#"{"erased":true}"#;

/// The body of `POST /v1/{id}/erase` (Switch wire 7.4.16).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct EraseBody {
    /// The account's creation time, in Unix milliseconds, as its enrollment answer named it:
    /// the erasure is refused when the account was created at another time. Absent where the
    /// signer holds none; the refusal names it.
    pub created: Option<u64>,
    /// The document hash of the newest `identity.json` the account holds: the erasure is
    /// refused when the account holds another, or none. Absent only for an account that
    /// holds no `identity.json`.
    pub identity_hash: Option<[u8; 32]>,
}

/// Read the body of `POST /v1/{id}/erase`: `{ "created": time, "identity_hash": b64(32) }`,
/// both optional in shape (Switch wire 7.4.16). A member that is `null` reads as missing
/// (Switch wire 1.1 "Absent and null"), so the erasure's binding refuses it as it refuses a
/// missing one.
///
/// # Errors
///
/// [`Error::Invalid`] (`400 bad_request`) for any other member, a `created` that isn't a
/// time (Switch wire 1.6), or a hash that isn't `b64(32)`.
pub fn parse_erase_body(body: &[u8]) -> Result<EraseBody> {
    let value: serde_json::Value = crate::json::parse_json(body)?;
    crate::json::reject_unknown_members(&value, &["created", "identity_hash"], "the erasure body")?;
    let created = match value.get("created") {
        None | Some(serde_json::Value::Null) => None,
        Some(serde_json::Value::String(text)) => Some(crate::time::parse_rfc3339(text)?),
        Some(_) => return invalid("Switch wire 7.4.16: `created` is a time"),
    };
    let identity_hash = match value.get("identity_hash") {
        None | Some(serde_json::Value::Null) => None,
        Some(serde_json::Value::String(text)) => Some(unb64_array::<32>(text)?),
        Some(_) => return invalid("Switch wire 7.4.16: `identity_hash` is b64(32)"),
    };
    Ok(EraseBody {
        created,
        identity_hash,
    })
}

/// The body of `POST /v1/{id}/erase` naming `created`, the account's creation time from its
/// enrollment answer, and `identity_hash`, the document hash of the newest `identity.json`
/// the account holds, each left out when `None` (Switch wire 7.4.16).
pub fn erase_body(created: Option<u64>, identity_hash: Option<&[u8; 32]>) -> Vec<u8> {
    let mut members = Vec::new();
    if let Some(created) = created {
        members.push(format!("\"created\":\"{}\"", crate::time::rfc3339(created)));
    }
    if let Some(hash) = identity_hash {
        members.push(format!("\"identity_hash\":\"{}\"", crate::enc::b64(hash)));
    }
    format!("{{{}}}", members.join(",")).into_bytes()
}

/// The most handles one push registration holds, one per device (Switch wire 8.1).
pub const MAX_PUSH_HANDLES: usize = 8;

/// The body of `PUT /v1/{id}/push` (Switch wire 8.1), read by [`parse_push_body`]. Its
/// `Debug` shows neither the relay URL nor a handle, which stay out of logs.
#[derive(Clone, PartialEq, Eq)]
pub struct PushBody {
    /// The relay URL, which passed [`crate::net::check_url`] for a relay; its host's
    /// addresses are still the caller's to check, once resolved.
    pub relay_url: String,
    /// The handles: empty on a start, at most [`MAX_PUSH_HANDLES`].
    pub handles: Vec<String>,
    /// The push key of the registration whose handles this sets; `None` on a start.
    pub push_key: Option<[u8; 32]>,
    /// On a start only: the push key of the registration it replaces.
    pub replaces: Option<[u8; 32]>,
}

impl PushBody {
    /// Whether the body starts a registration: it names no `push_key`.
    pub fn is_start(&self) -> bool {
        self.push_key.is_none()
    }
}

impl std::fmt::Debug for PushBody {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PushBody")
            .field("handles", &self.handles.len())
            .field("push_key", &self.push_key.is_some())
            .field("replaces", &self.replaces.is_some())
            .finish_non_exhaustive()
    }
}

/// Read the body of `PUT /v1/{id}/push` (Switch wire 8.1): `relay_url` and `handles`
/// required, `push_key` and `replaces` optional (`null` as absent), other members ignored
/// (1.1). The relay URL passes the syntax, scheme, port and address literal checks of
/// [`crate::net::check_url`]; resolving its host and checking the addresses is the
/// caller's.
///
/// # Errors
///
/// [`Error::Invalid`] (`400 bad_request`) for a body that isn't that, more than
/// [`MAX_PUSH_HANDLES`] handles, handles on a start, `replaces` with `push_key`, or a relay
/// URL that fails the checks. No message names the URL or a handle.
pub fn parse_push_body(body: &[u8]) -> Result<PushBody> {
    let value: serde_json::Value = crate::json::parse_json(body)?;
    let Some(relay_url) = value.get("relay_url").and_then(serde_json::Value::as_str) else {
        return invalid("Switch wire 8.1: `relay_url` is a string");
    };
    let handles = match value.get("handles") {
        Some(serde_json::Value::Array(items)) => items
            .iter()
            .map(|item| item.as_str().map(str::to_owned))
            .collect::<Option<Vec<String>>>(),
        _ => None,
    };
    let Some(handles) = handles else {
        return invalid("Switch wire 8.1: `handles` is an array of strings");
    };
    let key = |name: &str| match value.get(name) {
        None | Some(serde_json::Value::Null) => Ok(None),
        Some(serde_json::Value::String(text)) => unb64_array::<32>(text).map(Some),
        Some(_) => invalid(format!("Switch wire 8.1: `{name}` is b64(32)")),
    };
    let push_key = key("push_key")?;
    let replaces = key("replaces")?;
    if handles.len() > MAX_PUSH_HANDLES {
        return invalid("Switch wire 8.1: at most 8 handles");
    }
    if push_key.is_none() && !handles.is_empty() {
        return invalid("Switch wire 8.1: a start carries no handles");
    }
    if push_key.is_some() && replaces.is_some() {
        return invalid("Switch wire 8.1: `replaces` is only on a start");
    }
    if crate::net::check_url(relay_url, &crate::net::UrlUse::Relay).is_err() {
        return invalid(
            "Switch wire 8.1: the relay URL isn't https on port 443 without user info, or its \
             host isn't public",
        );
    }
    Ok(PushBody {
        relay_url: relay_url.to_owned(),
        handles,
        push_key,
        replaces,
    })
}

/// The calls after `/v1/{id}/` of a path, without its query.
fn call_of(path: &str) -> Option<Vec<&str>> {
    let path = path.split('?').next().unwrap_or_default();
    let parts: Vec<&str> = path.trim_start_matches('/').split('/').collect();
    match parts.as_slice() {
        ["v1", "enroll"] => Some(vec!["enroll"]),
        ["v1", _id, rest @ ..] => Some(rest.to_vec()),
        _ => None,
    }
}

/// The body cap of a call, in bytes; a larger body is `413 too_large` before it is read
/// (Switch wire 7.1). `None` for a call the table doesn't name.
pub fn body_cap(method: &str, path: &str) -> Option<usize> {
    let call = call_of(path)?;
    Some(match (method, call.as_slice()) {
        ("POST", ["enroll"]) => crate::records::MAX_ENROLLMENT_BYTES,
        ("GET", _) => 0,
        ("POST", ["inbox"]) => 65_536,
        ("POST", ["ops"] | ["import"]) => 4 << 20,
        ("PUT", ["identity"] | ["peers"]) => 256 << 10,
        ("PUT", ["import", "chunks", _]) => 1 << 20,
        ("POST", ["recovery", "upload"]) => 16 << 20,
        ("POST", ["recovery", "enrollment"]) => {
            crate::records::recovery_enrollment::MAX_REQUEST_BYTES
        }
        ("PUT", ["handover"]) => 12 << 20,
        ("POST", ["freeze"])
        | ("POST", ["unfreeze"])
        | ("POST", ["import", "activate"])
        | ("POST", ["recovery", "admission"])
        | ("POST", ["apps", _, "revoke" | "leave" | "keys"])
        | ("PUT", ["push"])
        | ("POST", ["erase"]) => 16 << 10,
        ("POST", ["connect"]) | ("DELETE", ["connect", _]) => 0,
        _ => return None,
    })
}

/// A response-body limit imposed by the call and status, before accumulation or parsing.
/// `None` leaves the caller's configured limit unchanged; a configured smaller limit still
/// applies (Switch account binding 2, 3.3).
pub fn response_body_cap(method: &str, path_and_query: &str, status: u16) -> Option<usize> {
    if method == "POST" && call_of(path_and_query).as_deref() == Some(&["recovery", "enrollment"]) {
        return Some(crate::records::recovery_enrollment::MAX_RESPONSE_BYTES);
    }
    (status == 200 && is_account_discovery(method, path_and_query))
        .then_some(crate::records::MAX_ACCOUNT_OBSERVATION_BYTES)
}

fn is_account_discovery(method: &str, path_and_query: &str) -> bool {
    let path = path_and_query.split('?').next().unwrap_or_default();
    let Some(rest) = path.strip_prefix("/v1/") else {
        return false;
    };
    matches!(rest.split_once('/'), Some((id, "account")) if method == "GET" && !id.is_empty())
}

/// Whether a frozen account answers a call with `410 moved` (Switch wire 7.3): the writes
/// other than the export, the unfreeze and the erasure. Reads go on.
pub fn frozen_refuses(method: &str, path: &str) -> bool {
    let Some(call) = call_of(path) else {
        return false;
    };
    matches!(
        (method, call.as_slice()),
        ("POST", ["inbox"])
            | ("PUT", ["peers"])
            | ("POST", ["connect"])
            | ("DELETE", ["connect", _])
            | ("POST", ["ops"])
            | ("POST", ["apps", _, "leave" | "revoke"])
            | ("POST", ["recovery", "upload"])
            | ("PUT", ["push"])
            | ("PUT", ["handover"])
    )
}

/// The error codes of the switch, with their HTTP status (Switch wire 7.6, Switch spec 6.4).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum ErrorCode {
    /// `400`: a malformed request, document or operation.
    BadRequest,
    /// `401`: a signature that doesn't verify.
    BadSignature,
    /// `401`: `Switch-Timestamp` more than 5 minutes from the service's clock.
    StaleTimestamp,
    /// `403`: a sender not admitted or denied.
    NotAdmitted,
    /// `403`: the caller's certificate lacks the switch permission or scope.
    PermissionMissing,
    /// `403`: the calling app isn't current.
    NotCurrent,
    /// `403`: the caller's certificate has expired.
    CertExpired,
    /// `404`: no such object.
    NotFound,
    /// `409`: a condition, an expected step or version, or a registration failed.
    Conflict,
    /// `409`: a sealed value at another data epoch.
    StaleEpoch,
    /// `409`: an operation naming another generation.
    StaleGeneration,
    /// `409`: an envelope wrapped to a receive key that isn't current.
    StaleKey,
    /// `409`: a delivered `identity.json` that isn't newer, or doesn't build on the one held.
    StaleIdentity,
    /// `409`: the service's copy of the sender identity's `identity.json` doesn't list the app.
    IdentityNeeded,
    /// `410`: the account is frozen.
    Moved,
    /// `413`: a size cap exceeded.
    TooLarge,
    /// `429`: too many requests.
    RateLimited,
    /// `429`: a quota or a per-kind limit is full.
    QuotaExceeded,
    /// `503`: the account isn't named by its `identity.json` yet, or restores its allowlist.
    Staged,
    /// `503`: a temporary failure.
    Unavailable,
    /// `503`: the account awaits a recovery; its `current` is a [`RecoveryNotice`] (Switch
    /// wire 7.3, 7.6).
    RecoveryRequired,
}

/// Whether the same request may succeed later (the Retry column of Switch spec 6.4).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Retry {
    /// Never unchanged.
    No,
    /// With a new timestamp.
    WithNewTimestamp,
    /// After re-reading and recomputing.
    AfterReread,
    /// After fetching the key bundle.
    AfterKeyBundle,
    /// After signing again for the current generation.
    AfterResigning,
    /// After sealing again to the current keys.
    AfterResealing,
    /// After delivering the sender's `identity.json`.
    AfterDeliveringIdentity,
    /// At the next service.
    AtNextService,
    /// After `Retry-After`.
    AfterRetryAfter,
    /// Once the full limit frees.
    WhenLimitFrees,
    /// Yes, unchanged.
    Yes,
    /// Held for the next generation: neither sent again to this generation nor final
    /// (Switch wire 7.6, Switch spec 6.4).
    HeldForNextGeneration,
}

impl ErrorCode {
    /// Every code, in the order of the table.
    pub const ALL: [ErrorCode; 21] = [
        ErrorCode::BadRequest,
        ErrorCode::BadSignature,
        ErrorCode::StaleTimestamp,
        ErrorCode::NotAdmitted,
        ErrorCode::PermissionMissing,
        ErrorCode::NotCurrent,
        ErrorCode::CertExpired,
        ErrorCode::NotFound,
        ErrorCode::Conflict,
        ErrorCode::StaleEpoch,
        ErrorCode::StaleGeneration,
        ErrorCode::StaleKey,
        ErrorCode::StaleIdentity,
        ErrorCode::IdentityNeeded,
        ErrorCode::Moved,
        ErrorCode::TooLarge,
        ErrorCode::RateLimited,
        ErrorCode::QuotaExceeded,
        ErrorCode::Staged,
        ErrorCode::Unavailable,
        ErrorCode::RecoveryRequired,
    ];

    /// The `code` text.
    pub fn as_str(self) -> &'static str {
        match self {
            ErrorCode::BadRequest => "bad_request",
            ErrorCode::BadSignature => "bad_signature",
            ErrorCode::StaleTimestamp => "stale_timestamp",
            ErrorCode::NotAdmitted => "not_admitted",
            ErrorCode::PermissionMissing => "permission_missing",
            ErrorCode::NotCurrent => "not_current",
            ErrorCode::CertExpired => "cert_expired",
            ErrorCode::NotFound => "not_found",
            ErrorCode::Conflict => "conflict",
            ErrorCode::StaleEpoch => "stale_epoch",
            ErrorCode::StaleGeneration => "stale_generation",
            ErrorCode::StaleKey => "stale_key",
            ErrorCode::StaleIdentity => "stale_identity",
            ErrorCode::IdentityNeeded => "identity_needed",
            ErrorCode::Moved => "moved",
            ErrorCode::TooLarge => "too_large",
            ErrorCode::RateLimited => "rate_limited",
            ErrorCode::QuotaExceeded => "quota_exceeded",
            ErrorCode::Staged => "staged",
            ErrorCode::Unavailable => "unavailable",
            ErrorCode::RecoveryRequired => "recovery_required",
        }
    }

    /// The code of a `code` text, if the switch defines it.
    pub fn parse(text: &str) -> Option<ErrorCode> {
        ErrorCode::ALL
            .into_iter()
            .find(|code| code.as_str() == text)
    }

    /// The HTTP status the code is answered with.
    pub fn status(self) -> u16 {
        match self {
            ErrorCode::BadRequest => 400,
            ErrorCode::BadSignature | ErrorCode::StaleTimestamp => 401,
            ErrorCode::NotAdmitted
            | ErrorCode::PermissionMissing
            | ErrorCode::NotCurrent
            | ErrorCode::CertExpired => 403,
            ErrorCode::NotFound => 404,
            ErrorCode::Conflict
            | ErrorCode::StaleEpoch
            | ErrorCode::StaleGeneration
            | ErrorCode::StaleKey
            | ErrorCode::StaleIdentity
            | ErrorCode::IdentityNeeded => 409,
            ErrorCode::Moved => 410,
            ErrorCode::TooLarge => 413,
            ErrorCode::RateLimited | ErrorCode::QuotaExceeded => 429,
            ErrorCode::Staged | ErrorCode::Unavailable | ErrorCode::RecoveryRequired => 503,
        }
    }

    /// Whether the same request may succeed later (Switch spec 6.4).
    pub fn retry(self) -> Retry {
        match self {
            ErrorCode::BadRequest
            | ErrorCode::BadSignature
            | ErrorCode::NotAdmitted
            | ErrorCode::PermissionMissing
            | ErrorCode::NotCurrent
            | ErrorCode::CertExpired
            | ErrorCode::NotFound
            | ErrorCode::StaleIdentity
            | ErrorCode::TooLarge => Retry::No,
            ErrorCode::StaleTimestamp => Retry::WithNewTimestamp,
            ErrorCode::Conflict => Retry::AfterReread,
            ErrorCode::StaleEpoch => Retry::AfterKeyBundle,
            ErrorCode::StaleGeneration => Retry::AfterResigning,
            ErrorCode::StaleKey => Retry::AfterResealing,
            ErrorCode::IdentityNeeded => Retry::AfterDeliveringIdentity,
            ErrorCode::Moved => Retry::AtNextService,
            ErrorCode::RateLimited => Retry::AfterRetryAfter,
            ErrorCode::QuotaExceeded => Retry::WhenLimitFrees,
            ErrorCode::Staged | ErrorCode::Unavailable => Retry::Yes,
            ErrorCode::RecoveryRequired => Retry::HeldForNextGeneration,
        }
    }

    /// Whether the answer carries `known_version` for an app of another identity: a `2xx`
    /// answer and `409 identity_needed` do, other errors don't (Switch wire 7.1).
    pub fn carries_known_version(self) -> bool {
        self == ErrorCode::IdentityNeeded
    }
}

/// The classes of answer that count in no comparison of service times, the only answers
/// to a request a client sends that the service signs at its time base (Switch wire 7.1
/// Timestamp, spec 10.1). A client tells each from the answer and the call it made alone
/// ([`uncompared`]).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Uncompared {
    /// Every answer to the enrollment, `POST /v1/enroll`, outside the comparison of the
    /// account's committed times.
    Enrollment,
    /// Every authenticated account discovery answer, independent of committed account time.
    AccountDiscovery,
    /// Every answer to the erasure, `POST /v1/{id}/erase`, outside the comparison of the
    /// account's committed times.
    Erasure,
    /// Every answer to the public read, `GET /v1/{id}/identity`, which binds no request, so
    /// an earlier one may be sent again (Switch wire 7.4.15).
    PublicRead,
    /// An answer given before the body was read, which verifies only with the empty body
    /// field.
    BodyUnread,
    /// An authenticated conflict names only the current account creation, with no head
    /// (Switch account binding 1, Switch wire 7.1).
    CreationConflict,
    /// The notice, `503 recovery_required` (Switch wire 7.6).
    Notice,
    /// Every `503 unavailable`: a temporary failure, which tells nothing of the account's
    /// state.
    Unavailable,
    /// The `404` with `current: { "hosted": false }` of an identity the service doesn't host
    /// (Switch wire 7.3 step 2).
    NotHosted,
}

/// The class of an answer that counts in no comparison of service times, `None` for one
/// that counts (Switch wire 7.1 Timestamp): by the request it answers, `method` and
/// `path_and_query` as sent and the body field the answer verifies with, and by the answer's
/// `status` and, for an error, its `code` and `current`. `head_present` reports the actual
/// received head field, not whether parsing that field succeeded.
pub fn uncompared(
    method: &str,
    path_and_query: &str,
    body: BodyField,
    status: u16,
    code: Option<ErrorCode>,
    current: Option<&serde_json::Value>,
    head_present: bool,
) -> Option<Uncompared> {
    let path = path_and_query.split('?').next().unwrap_or_default();
    let segments: Vec<&str> = path
        .strip_prefix("/v1/")
        .map(|rest| rest.split('/').collect())
        .unwrap_or_default();
    match (method, segments.as_slice()) {
        ("POST", ["enroll"]) => return Some(Uncompared::Enrollment),
        _ if is_account_discovery(method, path_and_query) => {
            return Some(Uncompared::AccountDiscovery);
        }
        ("POST", [id, "erase"]) if !id.is_empty() => return Some(Uncompared::Erasure),
        _ if is_public_read(method, path_and_query) => return Some(Uncompared::PublicRead),
        _ => {}
    }
    if body == BodyField::NotRead {
        return Some(Uncompared::BodyUnread);
    }
    match code {
        Some(ErrorCode::Conflict)
            if status == 409
                && !head_present
                && current
                    .and_then(serde_json::Value::as_object)
                    .is_some_and(|fields| {
                        fields.len() == 1
                            && fields
                                .get("created")
                                .and_then(serde_json::Value::as_str)
                                .is_some_and(|created| parse_created(created).is_ok())
                    }) =>
        {
            Some(Uncompared::CreationConflict)
        }
        Some(ErrorCode::RecoveryRequired) if status == 503 => Some(Uncompared::Notice),
        Some(ErrorCode::Unavailable) if status == 503 => Some(Uncompared::Unavailable),
        Some(ErrorCode::NotFound) if status == 404 && current == Some(&not_hosted_current()) => {
            Some(Uncompared::NotHosted)
        }
        _ => None,
    }
}

impl std::fmt::Display for ErrorCode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{} {}", self.status(), self.as_str())
    }
}

/// Decode a header's base64url signature.
///
/// # Errors
///
/// [`Error::Signature`] if it isn't base64url of 64 bytes, as a request with such a
/// signature is answered `401` (Switch wire 7.2).
pub fn decode_signature(text: &str) -> Result<[u8; 64]> {
    unb64_array::<64>(text)
        .map_err(|_| Error::Signature("Switch wire 7.1: a signature header isn't b64(64)".into()))
}

/// Why an account awaits a recovery, the `reason` of a [`RecoveryNotice`] (Switch wire 7.6).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NoticeReason {
    /// `behind`: the account's state is behind the newest head the service signed for it,
    /// or of an earlier generation than its mark, or the account is gone while its mark is
    /// there, or is staged and bounded by its mark.
    Behind,
    /// `fork`: the account is at that head's `seq` with another chain hash.
    Fork,
    /// `mark_lost`: the account's mark is missing or doesn't read as a mark.
    MarkLost,
}

/// The `current` of a `503 recovery_required`, the recovery notice (Switch wire 7.6, Switch
/// spec 6.5). All three members are required; unknown members are ignored, since an error
/// body isn't among the places that refuse them (Switch wire 1.1).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RecoveryNotice {
    /// The higher of the account's chain generation (its document's without a chain,
    /// zero with neither) and its mark's generation.
    pub generation: u64,
    /// Why the account awaits a recovery.
    pub reason: NoticeReason,
    /// `true` once the operator retired this generation for the account.
    pub permanent: bool,
}

impl RecoveryNotice {
    /// Read a notice from an error body's `current` (Switch wire 7.6). Unknown members are
    /// ignored (Switch wire 1.1).
    /// The error body has already passed [`crate::json::parse_json`].
    ///
    /// # Errors
    ///
    /// [`Error::Invalid`] if a member is missing or of another type, or `reason` isn't one
    /// of the three: a malformed notice, which a client still holds as a notice for the
    /// generation it follows, with `permanent` `false` (Switch wire 7.6).
    pub fn from_current(current: &serde_json::Value) -> Result<Self> {
        Ok(serde_json::from_value(current.clone())?)
    }

    /// The notice as an error body's `current`.
    pub fn to_current(&self) -> serde_json::Value {
        serde_json::json!({
            "generation": self.generation,
            "reason": self.reason,
            "permanent": self.permanent,
        })
    }
}

/// The `current` of the `404 not_found` to an identity the service doesn't host,
/// `{ "hosted": false }`, and of nothing else (Switch wire 7.3 step 2, 7.6).
pub fn not_hosted_current() -> serde_json::Value {
    serde_json::json!({ "hosted": false })
}

#[cfg(test)]
mod tests {
    #[test]
    fn test_recovery_notice_round_trips_each_reason() {
        for (reason, text) in [
            (NoticeReason::Behind, "behind"),
            (NoticeReason::Fork, "fork"),
            (NoticeReason::MarkLost, "mark_lost"),
        ] {
            for (generation, permanent) in [(0, false), (3, true), (crate::json::MAX_INT, false)] {
                let notice = RecoveryNotice {
                    generation,
                    reason,
                    permanent,
                };
                let expected = serde_json::json!({
                    "generation": generation, "reason": text, "permanent": permanent
                });
                assert_eq!(notice.to_current(), expected);
                assert_eq!(RecoveryNotice::from_current(&expected).unwrap(), notice);
            }
        }
    }

    #[test]
    fn test_recovery_notice_requires_each_member() {
        let full = serde_json::json!({"generation": 3, "reason": "behind", "permanent": false});
        for field in ["generation", "reason", "permanent"] {
            let mut missing = full.clone();
            missing.as_object_mut().unwrap().remove(field);
            assert!(RecoveryNotice::from_current(&missing).is_err(), "{field}");
        }
        assert!(RecoveryNotice::from_current(&full).is_ok());
    }

    #[test]
    fn test_recovery_notice_rejects_invalid_member_types() {
        for value in [
            serde_json::json!({"generation": -1, "reason": "fork", "permanent": false}),
            serde_json::json!({"generation": "3", "reason": "fork", "permanent": false}),
            serde_json::json!({"generation": 3, "reason": "unknown", "permanent": false}),
            serde_json::json!({"generation": 3, "reason": null, "permanent": false}),
            serde_json::json!({"generation": 3, "reason": "fork", "permanent": "false"}),
            serde_json::json!({"generation": 3, "reason": "fork", "permanent": null}),
        ] {
            assert!(RecoveryNotice::from_current(&value).is_err(), "{value}");
        }
    }

    #[test]
    fn test_recovery_notice_ignores_unknown_members() {
        let with_extra = serde_json::json!({
            "generation": 2, "reason": "behind", "permanent": true, "extra": {"value": 1}
        });
        assert_eq!(
            RecoveryNotice::from_current(&with_extra).unwrap(),
            RecoveryNotice {
                generation: 2,
                reason: NoticeReason::Behind,
                permanent: true
            }
        );
    }

    #[test]
    fn test_not_hosted_current_has_no_account_fields() {
        assert_eq!(not_hosted_current(), serde_json::json!({ "hosted": false }));
    }

    use super::*;
    use crate::keys::AppKeys;

    fn target(body: &[u8]) -> RequestTarget<'_> {
        RequestTarget {
            method: "POST",
            path_and_query: "/v1/x/ops",
            body,
            origin: "https://switch.example",
        }
    }

    #[test]
    fn test_recovery_notice_reads_its_members() {
        let notice = RecoveryNotice::from_current(&serde_json::json!({
            "generation": 3, "reason": "mark_lost", "permanent": false
        }))
        .unwrap();
        assert_eq!(
            notice,
            RecoveryNotice {
                generation: 3,
                reason: NoticeReason::MarkLost,
                permanent: false
            }
        );
        assert_eq!(
            RecoveryNotice::from_current(&notice.to_current()).unwrap(),
            notice
        );
        // An unknown member is ignored (Switch wire 1.1).
        assert_eq!(
            RecoveryNotice::from_current(&serde_json::json!({
                "generation": 3, "reason": "mark_lost", "permanent": false, "x": 1
            }))
            .unwrap(),
            notice
        );
        // A malformed notice: a member missing, an unknown `reason`, a wrong type.
        for bad in [
            serde_json::json!({ "generation": 3, "reason": "behind" }),
            serde_json::json!({ "generation": 3, "reason": "lost", "permanent": false }),
            serde_json::json!({ "generation": "3", "reason": "fork", "permanent": false }),
            serde_json::json!({ "generation": 3, "reason": "fork", "permanent": "no" }),
        ] {
            assert!(RecoveryNotice::from_current(&bad).is_err(), "{bad}");
        }
        assert_eq!(ErrorCode::RecoveryRequired.status(), 503);
        assert_eq!(
            ErrorCode::parse("recovery_required"),
            Some(ErrorCode::RecoveryRequired)
        );
        assert_eq!(
            ErrorCode::RecoveryRequired.retry(),
            Retry::HeldForNextGeneration
        );
        assert_eq!(not_hosted_current(), serde_json::json!({ "hosted": false }));
    }

    #[test]
    fn test_request_signature_covers_body_and_headers() {
        let app = AppKeys::from_secrets([1; 32], [2; 32]);
        let headers = RequestHeaders {
            timestamp: "2026-01-01T00:00:00Z".into(),
            identity: "id".into(),
            app: Some(app.app_id()),
            ..RequestHeaders::default()
        };
        let signature = sign_request(&app, &target(b"{}"), &headers);
        let public = app.signing_public();
        assert!(verify_request(&public, &target(b"{}"), &headers, &signature).is_ok());
        assert!(verify_request(&public, &target(b"{ }"), &headers, &signature).is_err());
        let mut other = headers.clone();
        other.invite_code = Some("code".into());
        assert!(verify_request(&public, &target(b"{}"), &other, &signature).is_err());
    }

    #[test]
    fn test_request_signature_takes_the_method_as_sent() {
        let app = AppKeys::from_secrets([1; 32], [2; 32]);
        let headers = RequestHeaders {
            timestamp: "2026-01-01T00:00:00Z".into(),
            identity: "id".into(),
            ..RequestHeaders::default()
        };
        let signature = sign_request(&app, &target(b"{}"), &headers);
        let lower = RequestTarget {
            method: "post",
            ..target(b"{}")
        };
        assert_eq!(request_fields(&lower, &headers)[0], b"post".to_vec());
        assert!(verify_request(&app.signing_public(), &lower, &headers, &signature).is_err());
    }

    fn honest_headers() -> ReceivedHeaders {
        ReceivedHeaders::of([
            (header::IDENTITY, b"id".as_slice()),
            (header::APP, b"app".as_slice()),
            (header::TIMESTAMP, b"2026-01-01T00:00:00Z".as_slice()),
            (header::SIGNATURE, b"c2ln".as_slice()),
        ])
    }

    fn received<'a>(headers: &'a ReceivedHeaders) -> ReceivedRequest<'a> {
        ReceivedRequest {
            method: "GET",
            path_and_query: "/v1/x/feed?after=3",
            body: BodyField::read(b""),
            origin: "https://switch.example",
            headers,
        }
    }

    #[test]
    fn test_response_signature_binds_the_received_request() {
        let key = AppKeys::from_secrets([3; 32], [4; 32]);
        let public = key.signing_public();
        let headers = honest_headers();
        let parts = ResponseParts {
            status: 200,
            request: received(&headers),
            server_time: "2026-01-01T00:00:00.000Z",
            head: Some("aGVhZA"),
            body: b"{}",
        };
        let signature = sign_response(&key, &parts);
        assert!(verify_response(&public, &parts, &signature).is_ok());
        let forged_signature = ReceivedHeaders::of([
            (header::IDENTITY, b"id".as_slice()),
            (header::APP, b"app".as_slice()),
            (header::TIMESTAMP, b"2026-01-01T00:00:00Z".as_slice()),
            (header::SIGNATURE, b"c2lo".as_slice()),
        ]);
        let other_time = ReceivedHeaders::of([
            (header::IDENTITY, b"id".as_slice()),
            (header::APP, b"app".as_slice()),
            (header::TIMESTAMP, b"2026-01-01T00:00:01Z".as_slice()),
            (header::SIGNATURE, b"c2ln".as_slice()),
        ]);
        let request = received(&headers);
        let changed = [
            ResponseParts {
                status: 201,
                ..parts
            },
            ResponseParts {
                head: None,
                ..parts
            },
            ResponseParts {
                head: Some("aGVhZB"),
                ..parts
            },
            ResponseParts {
                server_time: "2026-01-01T00:00:00.001Z",
                ..parts
            },
            ResponseParts {
                body: b"{ }",
                ..parts
            },
        ];
        for other in changed {
            assert!(verify_response(&public, &other, &signature).is_err());
        }
        // Every part of the received request: the method as received, the query, the body
        // field, the origin and each header.
        let requests = [
            ReceivedRequest {
                method: "get",
                ..request
            },
            ReceivedRequest {
                path_and_query: "/v1/x/feed?after=4",
                ..request
            },
            ReceivedRequest {
                path_and_query: "/v1/x/feed",
                ..request
            },
            ReceivedRequest {
                body: BodyField::NotRead,
                ..request
            },
            ReceivedRequest {
                body: BodyField::read(b"x"),
                ..request
            },
            ReceivedRequest {
                origin: "https://other.example",
                ..request
            },
            ReceivedRequest {
                headers: &forged_signature,
                ..request
            },
            ReceivedRequest {
                headers: &other_time,
                ..request
            },
        ];
        for other in requests {
            let other = ResponseParts {
                request: other,
                ..parts
            };
            assert!(verify_response(&public, &other, &signature).is_err());
        }
    }

    #[test]
    fn test_response_head_field_tells_absent_from_empty() {
        let headers = honest_headers();
        let parts = ResponseParts {
            status: 403,
            request: received(&headers),
            server_time: "2026-01-01T00:00:00.000Z",
            head: None,
            body: b"{}",
        };
        let absent = response_fields(&parts);
        assert!(absent[3].is_empty());
        let empty = response_fields(&ResponseParts {
            head: Some(""),
            ..parts
        });
        assert_eq!(empty[3], hash(b"").to_vec());
        let key = AppKeys::from_secrets([3; 32], [4; 32]);
        let signature = sign_response(&key, &parts);
        assert!(
            verify_response(
                &key.signing_public(),
                &ResponseParts {
                    head: Some(""),
                    ..parts
                },
                &signature
            )
            .is_err()
        );
    }

    #[test]
    fn test_received_request_header_presence_and_repeats() {
        let none = ReceivedHeaders::default();
        let empty = ReceivedHeaders::of([(header::INVITE_CODE, b"".as_slice())]);
        let once = ReceivedHeaders::of([(header::APP, b"a".as_slice())]);
        let twice = ReceivedHeaders::of([
            (header::APP, b"a".as_slice()),
            (header::APP, b"a".as_slice()),
        ]);
        let joined = ReceivedHeaders::of([(header::APP, b"a, a".as_slice())]);
        let created_empty = ReceivedHeaders::of([(header::CREATED, b"".as_slice())]);
        let created_once = ReceivedHeaders::of([(header::CREATED, b"a".as_slice())]);
        let created_twice = ReceivedHeaders::of([
            (header::CREATED, b"a".as_slice()),
            (header::CREATED, b"a".as_slice()),
        ]);
        let created_joined = ReceivedHeaders::of([(header::CREATED, b"a, a".as_slice())]);
        let encodings: Vec<Vec<u8>> = [
            &none,
            &empty,
            &once,
            &twice,
            &joined,
            &created_empty,
            &created_once,
            &created_twice,
            &created_joined,
        ]
        .into_iter()
        .map(|headers| received_request(&received(headers)))
        .collect();
        for (i, a) in encodings.iter().enumerate() {
            for b in &encodings[i + 1..] {
                assert_ne!(a, b);
            }
        }
        // An absent header is an empty field; one present once with an empty value is
        // `u32_be(0)`.
        let fields = crate::enc::split_lp(&encodings[1]).unwrap();
        assert_eq!(fields.len(), 12);
        assert_eq!(fields[7], vec![0, 0, 0, 0]);
        assert!(
            fields[4..12]
                .iter()
                .enumerate()
                .all(|(i, f)| i == 3 || f.is_empty())
        );
        let fields = crate::enc::split_lp(&encodings[5]).unwrap();
        assert_eq!(fields.len(), 12);
        assert_eq!(fields[11], vec![0, 0, 0, 0]);
        assert!(fields[4..11].iter().all(Vec::is_empty));
        // Names are compared case-insensitively, and headers it doesn't cover are left out.
        let mixed = ReceivedHeaders::of([
            ("Switch-App", b"a".as_slice()),
            ("content-type", b"x".as_slice()),
        ]);
        assert_eq!(mixed, once);
        assert_eq!(mixed.values(header::APP), [b"a".to_vec()]);
        // The body field: empty before the body is read, 32 bytes after.
        let fields = crate::enc::split_lp(&received_request(&ReceivedRequest {
            body: BodyField::NotRead,
            ..received(&none)
        }))
        .unwrap();
        assert!(fields[2].is_empty());
        assert_eq!(BodyField::read(b"").as_bytes(), hash(b""));
    }

    #[test]
    fn test_received_headers_broken_rule() {
        let of = |pairs: &[(&str, &[u8])]| ReceivedHeaders::of(pairs.iter().copied());
        // Absent, once, and headers a received request doesn't cover break nothing.
        assert_eq!(ReceivedHeaders::default().broken_rule(), None);
        assert_eq!(honest_headers().broken_rule(), None);
        assert_eq!(
            of(&[
                (header::APP, b"a b~"),
                ("content-type", b""),
                ("x-other", b"\xff")
            ])
            .broken_rule(),
            None
        );
        // Repeated, empty, or not printable ASCII: refused, each with its own reason.
        for (pairs, reason) in [
            (
                &[
                    (header::TIMESTAMP, b"t".as_slice()),
                    (header::TIMESTAMP, b"t"),
                ][..],
                "7.1: a signed request header sent more than once",
            ),
            (
                &[(header::APP, b"a".as_slice()), ("Switch-App", b"b")][..],
                "7.1: a signed request header sent more than once",
            ),
            (
                &[(header::INVITE_CODE, b"".as_slice())][..],
                "7.1: a signed request header with an empty value",
            ),
            (
                &[(header::TRANSFER, b"".as_slice())][..],
                "7.1: a signed request header with an empty value",
            ),
            (
                &[(header::APP, b"\xff\xfe".as_slice())][..],
                "7.1: a signed request header whose value isn't printable ASCII",
            ),
            (
                &[(header::CERT, b"a\tb".as_slice())][..],
                "7.1: a signed request header whose value isn't printable ASCII",
            ),
            (
                &[(header::SIGNATURE, b"a\x7f".as_slice())][..],
                "7.1: a signed request header whose value isn't printable ASCII",
            ),
        ] {
            assert_eq!(of(pairs).broken_rule(), Some(reason), "{pairs:?}");
        }
    }

    #[test]
    fn test_creation_conflict_is_outside_account_time() {
        let current = serde_json::json!({"created": "2026-01-01T00:00:00.000Z"});
        assert_eq!(
            super::uncompared(
                "GET",
                "/v1/x/apps",
                BodyField::read(b""),
                409,
                Some(ErrorCode::Conflict),
                Some(&current),
                false
            ),
            Some(Uncompared::CreationConflict)
        );
    }

    #[test]
    fn test_creation_conflict_requires_exact_shape_and_absent_head() {
        let current = serde_json::json!({"created": "2026-01-01T00:00:00.000Z"});
        for (status, code, head) in [
            (409, Some(ErrorCode::Conflict), true),
            (400, Some(ErrorCode::Conflict), false),
            (409, None, false),
            (409, Some(ErrorCode::BadRequest), false),
        ] {
            assert_eq!(
                super::uncompared(
                    "GET",
                    "/v1/x/apps",
                    BodyField::read(b""),
                    status,
                    code,
                    Some(&current),
                    head
                ),
                None
            );
        }
        for current in [
            None,
            Some(serde_json::Value::Null),
            Some(serde_json::json!({})),
            Some(serde_json::json!({"created": null})),
            Some(serde_json::json!({"created": 0})),
            Some(serde_json::json!({"created": "2026-01-01T00:00:00Z"})),
            Some(serde_json::json!({"created": "2026-01-01T00:00:00.000+00:00"})),
            Some(serde_json::json!({"created": "2026-13-01T00:00:00.000Z"})),
            Some(serde_json::json!({"created": "2026-01-01T00:00:00.000Z", "binding": "changed"})),
            Some(serde_json::json!({"binding": "expired"})),
        ] {
            assert_eq!(
                super::uncompared(
                    "GET",
                    "/v1/x/apps",
                    BodyField::read(b""),
                    409,
                    Some(ErrorCode::Conflict),
                    current.as_ref(),
                    false
                ),
                None,
                "{current:?}"
            );
        }
    }

    #[test]
    fn test_creation_conflict_preserves_endpoint_and_unread_precedence() {
        let current = serde_json::json!({"created": "2026-01-01T00:00:00.000Z"});
        for (method, path, body, class) in [
            (
                "POST",
                "/v1/enroll",
                BodyField::read(b""),
                Uncompared::Enrollment,
            ),
            (
                "GET",
                "/v1/x/account",
                BodyField::read(b""),
                Uncompared::AccountDiscovery,
            ),
            (
                "POST",
                "/v1/x/erase",
                BodyField::read(b""),
                Uncompared::Erasure,
            ),
            (
                "GET",
                "/v1/x/identity",
                BodyField::read(b""),
                Uncompared::PublicRead,
            ),
            (
                "PUT",
                "/v1/x/identity",
                BodyField::NotRead,
                Uncompared::BodyUnread,
            ),
        ] {
            assert_eq!(
                super::uncompared(
                    method,
                    path,
                    body,
                    409,
                    Some(ErrorCode::Conflict),
                    Some(&current),
                    false
                ),
                Some(class)
            );
        }
    }

    #[test]
    fn test_uncompared_classes_are_told_from_the_answer_and_the_call() {
        // Switch wire 7.1 Timestamp: exactly these count in no comparison of service times.
        let read = BodyField::read(b"");
        let not_hosted = not_hosted_current();
        let hosted = serde_json::json!({ "hosted": true });
        let notice = serde_json::json!({ "generation": 1, "reason": "behind", "permanent": false });
        let uncompared = [
            (
                "POST",
                "/v1/enroll",
                read,
                200,
                None,
                None,
                Uncompared::Enrollment,
            ),
            (
                "POST",
                "/v1/enroll",
                read,
                409,
                Some(ErrorCode::Conflict),
                None,
                Uncompared::Enrollment,
            ),
            (
                "POST",
                "/v1/x/erase",
                read,
                200,
                None,
                None,
                Uncompared::Erasure,
            ),
            (
                "POST",
                "/v1/x/erase",
                read,
                429,
                Some(ErrorCode::RateLimited),
                None,
                Uncompared::Erasure,
            ),
            (
                "GET",
                "/v1/x/identity",
                read,
                200,
                None,
                None,
                Uncompared::PublicRead,
            ),
            (
                "GET",
                "/v1/x/identity?a=1",
                read,
                429,
                Some(ErrorCode::RateLimited),
                None,
                Uncompared::PublicRead,
            ),
            (
                "POST",
                "/v1/x/ops",
                BodyField::NotRead,
                413,
                Some(ErrorCode::TooLarge),
                None,
                Uncompared::BodyUnread,
            ),
            (
                "GET",
                "/v1/x/feed",
                read,
                503,
                Some(ErrorCode::RecoveryRequired),
                Some(&notice),
                Uncompared::Notice,
            ),
            (
                "GET",
                "/v1/x/feed",
                read,
                503,
                Some(ErrorCode::Unavailable),
                None,
                Uncompared::Unavailable,
            ),
            (
                "GET",
                "/v1/x/feed",
                read,
                404,
                Some(ErrorCode::NotFound),
                Some(&not_hosted),
                Uncompared::NotHosted,
            ),
        ];
        for (method, path, body, status, code, current, class) in uncompared {
            assert_eq!(
                super::uncompared(method, path, body, status, code, current, false),
                Some(class),
                "{method} {path} {status} {code:?}"
            );
        }
        // Every other answer counts: a success, a refusal of the same status, a `404` with
        // another `current`, and the calls next to those left out.
        let compared = [
            ("GET", "/v1/x/feed", 200, None, None),
            ("POST", "/v1/x/ops", 429, Some(ErrorCode::RateLimited), None),
            ("GET", "/v1/x/feed", 503, Some(ErrorCode::Staged), None),
            ("GET", "/v1/x/feed", 404, Some(ErrorCode::NotFound), None),
            (
                "GET",
                "/v1/x/feed",
                404,
                Some(ErrorCode::NotFound),
                Some(&hosted),
            ),
            (
                "GET",
                "/v1/x/feed",
                401,
                Some(ErrorCode::BadSignature),
                None,
            ),
            ("PUT", "/v1/x/identity", 200, None, None),
            ("GET", "/v1/x/erase", 404, Some(ErrorCode::NotFound), None),
            ("POST", "/v1/x/enroll", 404, Some(ErrorCode::NotFound), None),
        ];
        for (method, path, status, code, current) in compared {
            assert_eq!(
                super::uncompared(method, path, read, status, code, current, false),
                None,
                "{method} {path} {status} {code:?}"
            );
        }
    }

    #[test]
    fn test_public_read_binds_no_header() {
        let headers = honest_headers();
        let read = ReceivedRequest {
            path_and_query: "/v1/x/identity",
            ..received(&headers)
        };
        let bare = ReceivedHeaders::default();
        assert_eq!(
            received_request(&read),
            received_request(&ReceivedRequest {
                headers: &bare,
                ..read
            })
        );
        // Only the call decides: another method's or another path's headers count.
        for (method, path) in [
            ("get", "/v1/x/identity"),
            ("PUT", "/v1/x/identity"),
            ("GET", "/v1/x/identity/"),
            ("GET", "/v1//identity"),
            ("GET", "/v1/x/feed"),
        ] {
            assert!(!is_public_read(method, path), "{method} {path}");
            let other = ReceivedRequest {
                method,
                path_and_query: path,
                ..read
            };
            assert_ne!(
                received_request(&other),
                received_request(&ReceivedRequest {
                    headers: &bare,
                    ..other
                })
            );
        }
        assert!(is_public_read("GET", "/v1/x/identity?x=1"));
    }

    #[test]
    fn test_relay_origin_drops_port_path_and_user() {
        assert_eq!(
            relay_origin("https://push.example/v1/hook").unwrap(),
            "https://push.example"
        );
        assert_eq!(
            relay_origin("https://u@push.example:443/x").unwrap(),
            "https://push.example"
        );
        assert!(relay_origin("http://push.example").is_err());
        assert!(relay_origin("https:///x").is_err());
    }

    #[test]
    fn test_webhook_signature_round_trips() {
        let key = AppKeys::from_secrets([5; 32], [6; 32]);
        let body = webhook_body("handle", 1_767_225_960_000, &[9; 16]);
        let url = "https://push.example/v1/hook";
        let signature = sign_webhook(&key, url, &body).unwrap();
        assert!(verify_webhook(&key.signing_public(), url, &body, &signature).is_ok());
        assert!(
            verify_webhook(
                &key.signing_public(),
                "https://other.example",
                &body,
                &signature
            )
            .is_err()
        );
    }

    #[test]
    fn test_body_caps_and_frozen_calls() {
        assert_eq!(body_cap("POST", "/v1/enroll"), Some(256 << 10));
        assert_eq!(
            body_cap("POST", "/v1/id/inbox?apps_version=4"),
            Some(65_536)
        );
        assert_eq!(body_cap("GET", "/v1/id/feed"), Some(0));
        // 128 envelopes in base64url (Switch wire 3.12).
        assert_eq!(body_cap("PUT", "/v1/id/handover"), Some(12 << 20));
        assert_eq!(body_cap("POST", "/v1/id/apps/a/keys"), Some(16 << 10));
        assert_eq!(body_cap("PATCH", "/v1/id/ops"), None);
        assert!(frozen_refuses("POST", "/v1/id/ops"));
        assert!(!frozen_refuses("POST", "/v1/id/unfreeze"));
        assert!(!frozen_refuses("GET", "/v1/id/feed"));
    }

    #[test]
    fn test_identity_delivery_requires_prev() {
        let doc = sig::SignedDoc::from_parts(b"{}", &[1; 64]);
        let delivery = IdentityDelivery {
            identity: doc.clone(),
            prev: Some([2; 32]),
        };
        assert_eq!(
            IdentityDelivery::parse(&delivery.to_json()).unwrap(),
            delivery
        );
        let first = IdentityDelivery {
            identity: doc,
            prev: None,
        };
        assert_eq!(IdentityDelivery::parse(&first.to_json()).unwrap(), first);
        assert!(IdentityDelivery::parse(br#"{"identity":{"body":"","sig":""}}"#).is_err());
        assert!(IdentityDelivery::parse(br#"{"prev":null}"#).is_err());
    }

    #[test]
    fn test_push_body_cases() {
        let key = crate::enc::b64(&[7u8; 32]);
        let start =
            parse_push_body(br#"{"relay_url":"https://push.example/v1/hook","handles":[]}"#)
                .expect("start");
        assert!(start.is_start() && start.replaces.is_none());
        let set = format!(
            r#"{{"relay_url":"https://push.example/h","handles":["a","b"],"push_key":"{key}","x":1}}"#
        );
        let set = parse_push_body(set.as_bytes()).expect("set");
        assert_eq!(set.push_key, Some([7; 32]));
        assert_eq!(set.handles, ["a", "b"]);
        let nulls =
            br#"{"relay_url":"https://push.example","handles":[],"push_key":null,"replaces":null}"#;
        assert!(parse_push_body(nulls).expect("nulls").is_start());
        let nine = format!(
            r#"{{"relay_url":"https://push.example","handles":[{}],"push_key":"{key}"}}"#,
            ["\"h\""; 9].join(",")
        );
        for bad in [
            r#"{"handles":[]}"#.to_owned(),
            r#"{"relay_url":"https://push.example"}"#.to_owned(),
            r#"{"relay_url":"https://push.example","handles":[1]}"#.to_owned(),
            r#"{"relay_url":"https://push.example","handles":["h"]}"#.to_owned(),
            r#"{"relay_url":"https://push.example","handles":[],"push_key":"short"}"#.to_owned(),
            format!(
                r#"{{"relay_url":"https://push.example","handles":[],"push_key":"{key}","replaces":"{key}"}}"#
            ),
            nine,
            r#"{"relay_url":"http://push.example","handles":[]}"#.to_owned(),
            r#"{"relay_url":"https://push.example:8443","handles":[]}"#.to_owned(),
            r#"{"relay_url":"https://u@push.example","handles":[]}"#.to_owned(),
            r#"{"relay_url":"https://10.0.0.1/hook","handles":[]}"#.to_owned(),
            r#"{"relay_url":"https://push.example","handles":[],"relay_url":"x"}"#.to_owned(),
        ] {
            assert!(parse_push_body(bad.as_bytes()).is_err(), "{bad}");
        }
    }

    #[test]
    fn test_push_body_debug_shows_no_relay_or_handle() {
        let key = crate::enc::b64(&[7u8; 32]);
        let body = format!(
            r#"{{"relay_url":"https://push.example/v1/hook","handles":["handle-Kt8fSp"],"push_key":"{key}"}}"#
        );
        let shown = format!("{:?}", parse_push_body(body.as_bytes()).expect("set"));
        for hidden in ["push.example", "/v1/hook", "handle-Kt8fSp", key.as_str()] {
            assert!(!shown.contains(hidden), "{shown}");
        }
    }

    #[test]
    fn test_erase_body_refuses_other_members() {
        assert_eq!(
            parse_erase_body(&erase_body(None, None)).unwrap(),
            EraseBody {
                created: None,
                identity_hash: None
            }
        );
        assert_eq!(erase_body(None, None), b"{}");
        assert!(parse_erase_body(br#"{"x":1}"#).is_err());
        assert!(parse_erase_body(b"[]").is_err());
    }

    #[test]
    fn test_erase_body_null_member_reads_as_missing() {
        // `null` is a missing member (Switch wire 1.1 "Absent and null"): the binding then
        // answers the `409` a missing member gets, never a `400`.
        assert_eq!(
            parse_erase_body(br#"{"created":null,"identity_hash":null}"#).unwrap(),
            EraseBody {
                created: None,
                identity_hash: None
            }
        );
        let hash = crate::enc::b64(&[4; 32]);
        let body = format!(r#"{{"created":null,"identity_hash":"{hash}"}}"#);
        assert_eq!(
            parse_erase_body(body.as_bytes()).unwrap(),
            EraseBody {
                created: None,
                identity_hash: Some([4; 32])
            }
        );
    }

    #[test]
    fn test_erase_body_carries_the_creation_time_and_the_identity_hash() {
        let (created, hash) = (1_767_225_600_123, [4; 32]);
        let body = erase_body(Some(created), Some(&hash));
        assert_eq!(
            body,
            format!(
                r#"{{"created":"2026-01-01T00:00:00.123Z","identity_hash":"{}"}}"#,
                crate::enc::b64(&hash)
            )
            .into_bytes()
        );
        assert_eq!(
            parse_erase_body(&body).unwrap(),
            EraseBody {
                created: Some(created),
                identity_hash: Some(hash)
            }
        );
        assert!(parse_erase_body(br#"{"identity_hash":7}"#).is_err());
        assert!(parse_erase_body(br#"{"identity_hash":"AA"}"#).is_err());
        assert!(parse_erase_body(br#"{"created":"yesterday"}"#).is_err());
        assert!(parse_erase_body(br#"{"created":1767225600123}"#).is_err());
    }

    #[test]
    fn test_error_codes_round_trip() {
        for code in ErrorCode::ALL {
            assert_eq!(ErrorCode::parse(code.as_str()), Some(code));
        }
        assert_eq!(ErrorCode::parse("teapot"), None);
        assert_eq!(ErrorCode::StaleKey.status(), 409);
        assert_eq!(ErrorCode::Unavailable.retry(), Retry::Yes);
        assert_eq!(ErrorCode::StaleIdentity.retry(), Retry::No);
    }
}
