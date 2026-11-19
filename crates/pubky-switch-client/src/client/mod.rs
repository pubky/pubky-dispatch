//! The Switch client: signed requests, checked answers and a typed call for every endpoint
//! (Switch wire 7, 8.1, 10).
//!
//! A [`SwitchClient`] acts with one set of [`Credentials`] on one account at one switch
//! origin. It signs every request (Switch wire 7.1, 7.2) and checks every answer with the
//! service key it pinned before it uses anything in it. Without a pinned key it sends only
//! an enrollment and authenticated account discovery. Their first-use
//! rules establish which key checks the answer; every other call fails closed before it
//! is sent (Switch wire 7.1, Switch spec 6.1, account-binding Section 2).
//!
//! - [`answers`]: the answer and body types of the calls.
//! - [`Batch`]: signed operations kept with their exact request body, so a retry resends the
//!   same bytes (Switch wire 2.1, 6.4).

pub mod answers;
mod batch;
mod calls;
pub(crate) mod read;
mod recovery_enrollment;

pub use batch::{Batch, Submitted};
pub use recovery_enrollment::RecoveryEnrollmentAnswer;

use std::sync::{Arc, Mutex, PoisonError};

use pubky_switch_core::chain::{ChainError, SignedHead};
use pubky_switch_core::enc::{b64, hash, pubky_id, zbase32_encode};
use pubky_switch_core::http::{
    self, ErrorCode, RequestHeaders, RequestTarget, TransferHeaders, header,
};
use pubky_switch_core::keys::AppKeys;
use pubky_switch_core::labels;
use pubky_switch_core::records::{AppCert, Enrollment, ExportTransfer};
use pubky_switch_core::signing::{Signs, SignsRequests};
use pubky_switch_core::time::{MAX_TIME_MS, parse_rfc3339, rfc3339, rfc3339_seconds};
use serde_json::Value;

use crate::clock::Clock;
use crate::error::{ClientError, TransportError};
use crate::transport::{Header, Request, Response, TimeoutClass, Transport};

/// Who signs the requests (Switch wire 7.2).
#[derive(Clone)]
pub enum Credentials {
    /// An app: its identity, its static keys and its certificate, which goes in
    /// `Switch-Cert` when it calls another identity's account.
    App {
        /// The app's identity.
        identity: [u8; 32],
        /// The app's signing and bundle keys.
        keys: AppKeys,
        /// The app's certificate.
        cert: AppCert,
    },
    /// The signer, with the identity key.
    Signer {
        /// The identity.
        identity: [u8; 32],
        /// The identity key, behind the signing interface.
        key: Arc<dyn Signs + Send + Sync>,
    },
    /// The signer, with a credential for requests only: it signs the `Switch-Signature` of a
    /// request (Switch wire 7.1) and no operation or document, so a client made with it
    /// reads and delivers what was signed already. It calls as the signer does.
    SignerRequests {
        /// The identity.
        identity: [u8; 32],
        /// The identity key, behind the request-only signing interface.
        key: Arc<dyn SignsRequests + Send + Sync>,
    },
    /// The next service of a cooperative move, fetching export chunks from the old service
    /// under the signer's export transfer (Switch wire 3.11, 7.2).
    NextService {
        /// The account's identity.
        identity: [u8; 32],
        /// The next service's key for the account, the one the transfer names in `to`.
        key: Arc<dyn Signs + Send + Sync>,
        /// The signer's export transfer.
        transfer: ExportTransfer,
    },
}

impl std::fmt::Debug for Credentials {
    // Names the caller only: keys never appear.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Credentials::App { identity, keys, .. } => f
                .debug_struct("App")
                .field("identity", &pubky_id(identity))
                .field("app_id", &keys.app_id())
                .finish(),
            Credentials::Signer { identity, .. } => f
                .debug_struct("Signer")
                .field("identity", &pubky_id(identity))
                .finish(),
            Credentials::SignerRequests { identity, .. } => f
                .debug_struct("SignerRequests")
                .field("identity", &pubky_id(identity))
                .finish(),
            Credentials::NextService { identity, .. } => f
                .debug_struct("NextService")
                .field("identity", &pubky_id(identity))
                .finish(),
        }
    }
}

impl Credentials {
    /// The caller's identity.
    pub fn identity(&self) -> [u8; 32] {
        match self {
            Credentials::App { identity, .. }
            | Credentials::Signer { identity, .. }
            | Credentials::SignerRequests { identity, .. }
            | Credentials::NextService { identity, .. } => *identity,
        }
    }

    /// The calling app's App ID; `None` for the signer and the next service.
    pub fn app_id(&self) -> Option<[u8; 16]> {
        match self {
            Credentials::App { keys, .. } => Some(keys.app_id_bytes()),
            Credentials::Signer { .. }
            | Credentials::SignerRequests { .. }
            | Credentials::NextService { .. } => None,
        }
    }

    /// Check that the keys are the ones the identity, the certificate or the transfer name.
    fn check(&self) -> Result<(), ClientError> {
        let ok = match self {
            Credentials::App {
                identity,
                keys,
                cert,
            } => cert.identity() == *identity && cert.signing_key() == keys.signing_public(),
            Credentials::Signer { identity, key } => key.public_key() == *identity,
            Credentials::SignerRequests { identity, key } => key.public_key() == *identity,
            Credentials::NextService {
                identity,
                key,
                transfer,
            } => {
                transfer.body().identity == *identity
                    && transfer.body().to.service_key == key.public_key()
            }
        };
        if ok {
            Ok(())
        } else {
            Err(ClientError::Usage(
                "the credentials' keys aren't the ones their identity, certificate or transfer \
                 names"
                    .into(),
            ))
        }
    }

    /// Sign `lp(label, fields...)` with the credential's key.
    ///
    /// # Errors
    ///
    /// [`ClientError::Usage`] for a label other than the request label with
    /// [`Credentials::SignerRequests`], which signs requests only.
    fn sign(&self, label: &str, fields: &[Vec<u8>]) -> Result<[u8; 64], ClientError> {
        let refs: Vec<&[u8]> = fields.iter().map(Vec::as_slice).collect();
        match self {
            Credentials::App { keys, .. } => Ok(keys.sign_fields(label, &refs)),
            Credentials::Signer { key, .. } | Credentials::NextService { key, .. } => {
                Ok(key.sign_fields(label, &refs))
            }
            Credentials::SignerRequests { key, .. } if label == labels::sig::HTTP => {
                Ok(key.sign_request_fields(&refs))
            }
            Credentials::SignerRequests { .. } => Err(request_only()),
        }
    }
}

/// The refusal of a signature other than a request's with [`Credentials::SignerRequests`].
pub(crate) fn request_only() -> ClientError {
    ClientError::Usage("the request-only credential signs requests only".into())
}

/// A key behind `dyn Signs`, as a `Sized` signer for the core's generic signing functions.
pub(crate) struct DynSigner<'a>(pub(crate) &'a (dyn Signs + Send + Sync));

impl Signs for DynSigner<'_> {
    fn public_key(&self) -> [u8; 32] {
        self.0.public_key()
    }

    fn sign_fields(&self, label: &str, fields: &[&[u8]]) -> [u8; 64] {
        self.0.sign_fields(label, fields)
    }
}

/// How a request is authenticated, beyond the caller's credentials.
#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct Auth<'a> {
    /// The first transport handoff of a kept operation (Switch spec 10.1).
    first_send: Option<&'a crate::transport::FirstSend>,
    /// `Switch-Invite-Code`.
    pub(crate) invite_code: Option<&'a str>,
    /// Send `Switch-Cert` even at the caller's own account: the staged head upload (Switch
    /// wire 7.2).
    pub(crate) with_cert: bool,
    /// The unauthenticated public read: no `Switch-*` header at all (Switch wire 7.4.15).
    pub(crate) public: bool,
    /// The signing time to send instead of the clock's: the `current.server_time` of a
    /// `401 stale_timestamp`, for its one retry (Switch wire 7.1).
    pub(crate) timestamp_ms: Option<u64>,
    /// The key that signs a `2xx` answer instead of the pinned one: the new key a delivery
    /// names that starts a generation after a service key change (Switch wire 7.4.2, spec
    /// 12.5). Other statuses are still checked with the pinned key.
    pub(crate) success_key: Option<[u8; 32]>,
    /// How long the call may take ([`TimeoutClass`]), which goes to the transport with
    /// the request.
    pub(crate) timeout: TimeoutClass,
}

/// The `Content-Type` of a request body (Switch wire 7.1).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Body {
    /// No body.
    Empty,
    /// A JSON body.
    Json,
    /// An envelope.
    Octets,
}

/// A request this client built, signed in its `Switch-Signature` header but for the
/// unauthenticated public read, to send with [`SwitchClient::send`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SignedRequest {
    /// The request.
    pub request: Request,
}

/// The request the client sent, as the service receives it, which a response signature
/// covers (Switch wire 7.1): its method, path and query, body, origin and each request header
/// it sent, a header it didn't send absent. A client checks an answer against what it sent.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SentRequest {
    method: String,
    path_and_query: String,
    body_hash: [u8; 32],
    origin: String,
    headers: http::ReceivedHeaders,
}

impl SentRequest {
    /// What the client sends with `request`.
    pub fn of(request: &Request) -> Self {
        SentRequest {
            method: request.method.clone(),
            path_and_query: request.path_and_query.clone(),
            body_hash: hash(&request.body),
            origin: request.origin.clone(),
            headers: http::ReceivedHeaders::of(
                request
                    .headers
                    .iter()
                    .map(|header| (header.name.as_str(), header.value.as_bytes())),
            ),
        }
    }

    /// The received request: its body field the body's hash where `body_read`, as for an
    /// answer the service gave once it read the body, else empty (Switch wire 7.1).
    pub fn received(&self, body_read: bool) -> http::ReceivedRequest<'_> {
        http::ReceivedRequest {
            method: &self.method,
            path_and_query: &self.path_and_query,
            body: if body_read {
                http::BodyField::Read(self.body_hash)
            } else {
                http::BodyField::NotRead
            },
            origin: &self.origin,
            headers: &self.headers,
        }
    }
}

/// An answer whose response signature verified with the pinned service key (Switch wire
/// 7.1), with a `2xx` status.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CheckedResponse {
    /// The HTTP status.
    pub status: u16,
    /// The body bytes.
    pub body: Vec<u8>,
    /// `Switch-Server-Time`, the identity's service time, in Unix milliseconds.
    pub server_time_ms: u64,
    /// `Switch-Head`, where present and verified with the service key; `None` only when
    /// absent. A present head that doesn't read or verify for the account fails the
    /// response (Switch wire 6.7, 7.1).
    pub head: Option<SignedHead>,
}

/// A call failure and the account head verified on that same error answer, if any.
pub(crate) struct CallError {
    pub(crate) error: ClientError,
    pub(crate) head: Option<Box<SignedHead>>,
}

impl From<ClientError> for CallError {
    fn from(error: ClientError) -> Self {
        Self { error, head: None }
    }
}

impl From<CallError> for ClientError {
    fn from(failure: CallError) -> Self {
        failure.error
    }
}

pub(crate) enum CallStep {
    Answer(CheckedResponse),
    Retry(Box<TimestampRetry>),
}

pub(crate) struct TimestampRetry {
    signed: SignedRequest,
    key: [u8; 32],
    success_key: Option<[u8; 32]>,
}

/// Check a response with the pinned service key before anything in it is used (Switch wire
/// 7.1): its signature over the status, the request `sent` as the service received it,
/// `Switch-Server-Time`, the head field of the `Switch-Head` text as received and the body;
/// then `Switch-Server-Time`; then `Switch-Head`, where present, as a head the service key
/// signed for `account` (Switch wire 6.7). An error status is read into
/// [`ClientError::Switch`].
///
/// A response that carries `Switch-Service-Signature`, `Switch-Server-Time` or `Switch-Head`
/// more than once, or a `Switch-Head` that doesn't read or verify as a head for `account`,
/// fails as a signature that doesn't verify. An answer that verifies only with the empty
/// body field, one the service gave before it read the body, is
/// [`ClientError::BodyUnread`], final for nothing, when it is a `413 too_large`, a `429
/// rate_limited` or a `404 not_found` without a head; any other fails as a signature that
/// doesn't verify. The heads the chain view checks come from the signed bodies.
///
/// # Errors
///
/// [`ClientError::BadServiceSignature`] for a signature that is missing or doesn't verify,
/// [`ClientError::InvalidResponse`] for a server time that doesn't read,
/// [`ClientError::BodyUnread`] for an answer given before the body was read, and
/// [`ClientError::Switch`] for an error answer.
pub fn check_response(
    service_key: &[u8; 32],
    account: &[u8; 32],
    sent: &SentRequest,
    response: &Response,
) -> Result<CheckedResponse, ClientError> {
    check_response_with_head(service_key, account, sent, response).map_err(ClientError::from)
}

fn check_response_with_head(
    service_key: &[u8; 32],
    account: &[u8; 32],
    sent: &SentRequest,
    response: &Response,
) -> Result<CheckedResponse, CallError> {
    let status = response.status;
    let unauthenticated = ClientError::BadServiceSignature { status };
    // Each header the signature decides on comes once at most (Switch wire 7.1).
    let repeated = [header::SERVICE_SIGNATURE, header::SERVER_TIME, header::HEAD]
        .iter()
        .any(|name| {
            response
                .headers
                .iter()
                .filter(|header| header.name.eq_ignore_ascii_case(name))
                .count()
                > 1
        });
    if repeated {
        return Err(unauthenticated.into());
    }
    let signature = response
        .header(header::SERVICE_SIGNATURE)
        .and_then(|text| http::decode_signature(text).ok())
        .ok_or_else(|| unauthenticated.clone())?;
    let server_time = response
        .header(header::SERVER_TIME)
        .ok_or_else(|| unauthenticated.clone())?;
    let head_text = response.header(header::HEAD);
    let verifies = |read: bool| {
        http::verify_response(
            service_key,
            &http::ResponseParts {
                status,
                request: sent.received(read),
                server_time,
                head: head_text,
                body: &response.body,
            },
            &signature,
        )
        .is_ok()
    };
    let body_read = if verifies(true) {
        true
    } else if verifies(false) {
        false
    } else {
        return Err(unauthenticated.into());
    };
    // A head that is there must be the account's (Switch wire 7.1).
    let head = match head_text {
        None => None,
        Some(text) => Some(
            SignedHead::from_header(text)
                .ok()
                .filter(|head| verify_head(head, service_key, account).is_ok())
                .ok_or_else(|| unauthenticated.clone())?,
        ),
    };
    if !body_read {
        // Only the answers a service may give before it reads the body (Switch wire 7.1).
        return match parse_error(status, &response.body) {
            ClientError::Switch {
                code: code @ (ErrorCode::TooLarge | ErrorCode::RateLimited | ErrorCode::NotFound),
                retry_after,
                ..
            } if head.is_none() => Err(ClientError::BodyUnread {
                status,
                code,
                retry_after,
            }
            .into()),
            _ => Err(unauthenticated.into()),
        };
    }
    // Only a full binding and an accepted head can establish an authenticated malformed
    // answer. An unread answer remains final for nothing (Switch wire 7.1).
    let server_time_ms = parse_rfc3339(server_time).map_err(|_| {
        ClientError::InvalidResponse("Switch wire 7.1: Switch-Server-Time doesn't parse".into())
    })?;
    if !(200..300).contains(&status) {
        return Err(CallError {
            error: parse_error(status, &response.body),
            head: head.map(Box::new),
        });
    }
    Ok(CheckedResponse {
        status,
        body: response.body.clone(),
        server_time_ms,
        head,
    })
}

/// Verify a head with the service key (Switch wire 6.7).
pub(crate) fn verify_head(
    head: &SignedHead,
    service_key: &[u8; 32],
    account: &[u8; 32],
) -> Result<(), ClientError> {
    head.verify(service_key, account)
        .map_err(|error| ClientError::Chain(ChainError::Signature(error.to_string())))
}

/// Read a checked error body: `{ "code", "message", "current", "known_version",
/// "retry_after" }` (Switch wire 7.1, 7.6). The code must be one the wire format defines,
/// with the status it fixes.
pub(crate) fn parse_error(status: u16, body: &[u8]) -> ClientError {
    let invalid =
        |why: &str| ClientError::InvalidResponse(format!("Switch wire 7.6: an error body {why}"));
    let Ok(value) = pubky_switch_core::json::parse_json::<Value>(body) else {
        return invalid("isn't strict JSON");
    };
    let Some(code) = value.get("code").and_then(Value::as_str) else {
        return invalid("has no code");
    };
    let Some(code) = ErrorCode::parse(code) else {
        return invalid("names a code the wire format doesn't define");
    };
    if code.status() != status {
        return invalid("has a code of another status");
    }
    let Some(message) = value.get("message").and_then(Value::as_str) else {
        return invalid("has no message");
    };
    ClientError::Switch {
        status,
        code,
        message: message.to_owned(),
        current: value.get("current").cloned().unwrap_or(Value::Null),
        known_version: value.get("known_version").and_then(Value::as_u64),
        retry_after: value.get("retry_after").and_then(Value::as_u64),
    }
}

/// The `current.server_time` of a verified `401 stale_timestamp`: the service's time base,
/// for the one retry's timestamp (Switch wire 7.1, 7.6). It isn't the identity's service
/// time, and counts as no verified service time (Switch spec 10.1).
fn stale_timestamp_hint(error: Option<&ClientError>) -> Option<u64> {
    match error {
        Some(ClientError::Switch {
            code: ErrorCode::StaleTimestamp,
            current,
            ..
        }) => current
            .get("server_time")
            .and_then(Value::as_str)
            .and_then(|text| parse_rfc3339(text).ok()),
        _ => None,
    }
}

/// Comparable answers from one call, including its automatic timestamp retry.
#[derive(Clone, Copy, Debug)]
pub(crate) struct ComparedTimes {
    pub(crate) first: u64,
    pub(crate) highest: u64,
    pub(crate) backwards: Option<(u64, u64)>,
}

#[derive(Default)]
struct CallTimes {
    latest: Option<u64>,
    compared: Option<ComparedTimes>,
}

impl CallTimes {
    fn observe(&mut self, time: Option<u64>) {
        self.latest = time;
        let Some(time) = time else { return };
        match &mut self.compared {
            Some(held) => {
                if time < held.highest && held.backwards.is_none() {
                    held.backwards = Some((held.highest, time));
                }
                held.highest = held.highest.max(time);
            }
            None => {
                self.compared = Some(ComparedTimes {
                    first: time,
                    highest: time,
                    backwards: None,
                })
            }
        }
    }
}

/// Whether a text is safe as a header value and a path segment: visible ASCII without the
/// characters a path or query gives meaning to.
fn is_token(text: &str) -> bool {
    !text.is_empty()
        && text
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.' | b'~'))
}

/// A client for one account at one switch, acting with one set of credentials.
pub struct SwitchClient {
    origin: String,
    account: [u8; 32],
    created: Option<u64>,
    credentials: Credentials,
    pinned: Mutex<Option<[u8; 32]>>,
    last_server_time: Mutex<Option<u64>>,
    latest_server_time: Mutex<Option<u64>>,
    call_times: Mutex<CallTimes>,
    transport: Arc<dyn Transport>,
    clock: Arc<dyn Clock>,
}

impl std::fmt::Debug for SwitchClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SwitchClient")
            .field("origin", &self.origin)
            .field("account", &pubky_id(&self.account))
            .field("created", &self.created)
            .field("credentials", &self.credentials)
            .field("pinned", &self.pinned_key().map(|key| b64(&key)))
            .finish()
    }
}

impl SwitchClient {
    /// A client acting with `credentials` on the account of `account` at the switch
    /// `origin`, exactly as `identity.json` names it in `inbox.url` (Switch wire 7.1).
    ///
    /// `pinned_key` is the account's service key the caller pinned: from the `identity.json`
    /// naming the service or, for the signer, from its enrollment answer or the freeze naming
    /// the next service (Switch wire 7.1). Without one, the client sends only an enrollment
    /// and authenticated account discovery. Existing-account signer
    /// calls also need [`Self::with_account_created`].
    ///
    /// # Errors
    ///
    /// [`ClientError::Usage`] if the credentials' keys aren't the ones their identity,
    /// certificate or transfer names, or the next service's credentials name another account
    /// or an origin other than the transfer's old service.
    pub fn new(
        origin: &str,
        account: [u8; 32],
        credentials: Credentials,
        pinned_key: Option<[u8; 32]>,
        transport: Arc<dyn Transport>,
        clock: Arc<dyn Clock>,
    ) -> Result<Self, ClientError> {
        credentials.check()?;
        if let Credentials::NextService { transfer, .. } = &credentials
            && (credentials.identity() != account || transfer.body().from.url != origin)
        {
            return Err(ClientError::Usage(
                "Switch wire 3.11: the next service fetches from the old service the transfer \
                 names, for its own account"
                    .into(),
            ));
        }
        Ok(Self {
            origin: origin.to_owned(),
            account,
            created: None,
            credentials,
            pinned: Mutex::new(pinned_key),
            last_server_time: Mutex::new(None),
            latest_server_time: Mutex::new(None),
            call_times: Mutex::new(CallTimes::default()),
            transport,
            clock,
        })
    }

    /// Bind this signer's calls to the creation retained with its account or pending
    /// operation (Switch account-binding Section 1). Answers never replace this binding.
    /// Enrollment uses its own signed intent; discovery always omits the binding.
    ///
    /// # Errors
    ///
    /// [`ClientError::Usage`] for non-signer credentials, a client already bound, or a time
    /// outside the wire grammar. Selecting another account requires another client.
    pub fn with_account_created(mut self, created: u64) -> Result<Self, ClientError> {
        self.signer_only()?;
        if self.created.is_some() || created > MAX_TIME_MS {
            return Err(ClientError::Usage(
                "Switch account-binding 1: the account creation is fixed and representable".into(),
            ));
        }
        self.created = Some(created);
        Ok(self)
    }

    /// The switch origin.
    pub fn origin(&self) -> &str {
        &self.origin
    }

    /// The account's identity.
    pub fn account(&self) -> [u8; 32] {
        self.account
    }

    /// The credentials.
    pub fn credentials(&self) -> &Credentials {
        &self.credentials
    }

    /// The pinned service key, if any.
    pub fn pinned_key(&self) -> Option<[u8; 32]> {
        *self.pinned.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Pin the account's service key, replacing any pinned before: after a key change, the
    /// signer pins the key the delivered `identity.json` names (Switch wire 3.3, 3.7).
    pub fn pin(&self, service_key: [u8; 32]) {
        *self.pinned.lock().unwrap_or_else(PoisonError::into_inner) = Some(service_key);
    }

    /// The `Switch-Server-Time` of the latest answer this client checked with the pinned key
    /// that carries the identity's stamped service time, in Unix milliseconds: a success, or
    /// an error answered once the request verified; `None` before any. An app keeps the
    /// highest service time it verified and measures it against its own clock (Switch spec
    /// 10.1).
    ///
    /// A refusal answered before the request verified carries no stamped time: the service
    /// answers it before the account's lock, with the last time it committed, which may be
    /// days old on an idle account (Switch wire 7.1, 7.2 Order). Such refusals are those
    /// without a verified `Switch-Head` (Switch wire 7.1 "`Switch-Head` on refusals"): every
    /// `401`, among them `stale_timestamp`, a `429` before authentication, a first call
    /// nothing verified, and the `503` of an account behind its key's mark; to an app of
    /// another identity, which is shown no head, every refusal. They count for nothing
    /// here, and so does a `stale_timestamp`'s `current.server_time`. Nor does any answer to
    /// the public read, which may be an earlier one sent again (Switch wire 7.1 "Identical
    /// requests").
    pub fn last_server_time(&self) -> Option<u64> {
        *self
            .last_server_time
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
    }

    /// The stamped service time of this client's latest call, as
    /// [`SwitchClient::last_server_time`] counts it: `None` when that call got no answer
    /// checked with the pinned key, or one that carries no stamped time. The clock bound is
    /// measured from it (Switch spec 10.1).
    pub(crate) fn latest_server_time(&self) -> Option<u64> {
        *self
            .latest_server_time
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
    }

    /// The `Switch-Server-Time` of this client's latest call, where it counts in the
    /// comparison of service times that never go back (Switch spec 10.1, wire 7.1
    /// Timestamp): every answer checked with the pinned key, refusals included, but those
    /// that count in no comparison, `None` for them and for a call without a checked answer.
    /// Those are told from the answer and the call alone ([`http::uncompared`]): every answer
    /// to enrollment, account discovery, erasure and the public read; a headless canonical
    /// creation conflict; an answer that verifies only with
    /// the empty body field, given before the body was read (7.1); the notice, `503
    /// recovery_required` (7.6); every `503 unavailable`; and the `404` with `current: {
    /// "hosted": false }` of an identity the service doesn't host (7.3 step 2). Only these
    /// may carry the time base; every other answer carries a time the service stamped, or the
    /// last time it committed for the identity, which no later answer goes behind.
    pub(crate) fn latest_compared_time(&self) -> Option<u64> {
        self.call_times
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .latest
    }

    /// All comparable answers of the call, even if its retry answered an excluded class
    /// or failed to return a verified answer.
    pub(crate) fn compared_times(&self) -> Option<ComparedTimes> {
        self.call_times
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .compared
    }

    /// Forget the latest call's times, before a call.
    fn forget_latest(&self) {
        self.set_latest(None);
        *self
            .call_times
            .lock()
            .unwrap_or_else(PoisonError::into_inner) = CallTimes::default();
    }

    fn set_latest(&self, time: Option<u64>) {
        *self
            .latest_server_time
            .lock()
            .unwrap_or_else(PoisonError::into_inner) = time;
    }

    fn note_server_time(
        &self,
        sent: &SentRequest,
        checked: Result<&CheckedResponse, &ClientError>,
        response: &Response,
    ) {
        let shown = || {
            response
                .header(header::SERVER_TIME)
                .and_then(|text| parse_rfc3339(text).ok())
        };
        // Every checked answer but those that count in no comparison, told from the answer
        // and the call alone (Switch wire 7.1 Timestamp).
        let uncompared = |body, code, current| {
            http::uncompared(
                &sent.method,
                &sent.path_and_query,
                body,
                response.status,
                code,
                current,
                response.header(header::HEAD).is_some(),
            )
        };
        let read = http::BodyField::Read(sent.body_hash);
        let class = match checked {
            Ok(_) => uncompared(read, None, None),
            Err(ClientError::Switch { code, current, .. }) => {
                uncompared(read, Some(*code), Some(current))
            }
            Err(ClientError::BodyUnread { code, .. }) => {
                uncompared(http::BodyField::NotRead, Some(*code), None)
            }
            Err(_) => None,
        };
        let time = match checked {
            // The public read binds no request, so its answer may be an earlier one sent again
            // (Switch wire 7.1 "Identical requests"): its time is no latest time.
            _ if matches!(
                class,
                Some(
                    http::Uncompared::AccountDiscovery
                        | http::Uncompared::CreationConflict
                        | http::Uncompared::PublicRead
                )
            ) =>
            {
                None
            }
            Ok(answer) => Some(answer.server_time_ms),
            // A verified error's present head proves its time is stamped for this account
            // (Switch wire 7.1). Discovery and creation conflicts above carry the time base.
            Err(ClientError::Switch { .. }) if response.header(header::HEAD).is_some() => shown(),
            Err(_) => None,
        };
        let compared = match checked {
            Ok(answer) => class.is_none().then_some(answer.server_time_ms),
            Err(ClientError::Switch { .. } | ClientError::BodyUnread { .. }) => {
                class.is_none().then(shown).flatten()
            }
            Err(_) => None,
        };
        self.call_times
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .observe(compared);
        self.set_latest(time);
        if let Some(time) = time {
            *self
                .last_server_time
                .lock()
                .unwrap_or_else(PoisonError::into_inner) = Some(time);
        }
    }

    /// Whether the account is another identity's than the caller's, so an app sends
    /// `Switch-Cert` (Switch wire 7.1, 7.2).
    pub fn is_foreign(&self) -> bool {
        self.credentials.identity() != self.account
    }

    /// The path `/v1/{id}/{rest}` of this account.
    pub(crate) fn path(&self, rest: &str) -> String {
        format!("/v1/{}/{rest}", pubky_id(&self.account))
    }

    /// The calling app's App ID, for the calls only an app makes.
    pub(crate) fn own_app_id(&self) -> Result<[u8; 16], ClientError> {
        self.credentials
            .app_id()
            .ok_or_else(|| ClientError::Usage("only an app makes this call".into()))
    }

    /// Refuse a call only the signer makes.
    pub(crate) fn signer_only(&self) -> Result<(), ClientError> {
        match self.credentials {
            Credentials::Signer { .. } | Credentials::SignerRequests { .. } => Ok(()),
            _ => Err(ClientError::Usage("only the signer makes this call".into())),
        }
    }

    /// Build and sign a request at the client's clock (Switch wire 7.1, 7.2).
    ///
    /// The timestamp is the clock's time to the second. An app calling another identity's
    /// account sends `Switch-Cert`; the next service signs over the transfer label.
    ///
    /// The request's timeout class is [`TimeoutClass::Ordinary`]; a caller whose request
    /// or answer can be large sets [`Request::timeout`] before sending it.
    ///
    /// # Errors
    ///
    /// [`ClientError::Usage`] for an invite code that isn't a token, or a request header
    /// the service would refuse at routing (Switch wire 7.1 "Each header once, as text").
    pub fn sign_request(
        &self,
        method: &str,
        path_and_query: &str,
        body: Vec<u8>,
        invite_code: Option<&str>,
    ) -> Result<SignedRequest, ClientError> {
        let content = if body.is_empty() {
            Body::Empty
        } else {
            Body::Json
        };
        self.build(
            method,
            path_and_query,
            body,
            content,
            Auth {
                invite_code,
                ..Auth::default()
            },
        )
    }

    pub(crate) fn build(
        &self,
        method: &str,
        path_and_query: &str,
        body: Vec<u8>,
        content: Body,
        auth: Auth<'_>,
    ) -> Result<SignedRequest, ClientError> {
        let method = method.to_ascii_uppercase();
        check_body_cap(&method, path_and_query, &body)?;
        let mut headers = Vec::new();
        match content {
            Body::Empty => {}
            Body::Json => headers.push(Header::new("content-type", "application/json")),
            Body::Octets => headers.push(Header::new("content-type", "application/octet-stream")),
        }
        if auth.public {
            return Ok(SignedRequest {
                request: Request {
                    method,
                    origin: self.origin.clone(),
                    path_and_query: path_and_query.to_owned(),
                    headers,
                    body,
                    timeout: auth.timeout,
                },
            });
        }
        if let Some(code) = auth.invite_code
            && !is_token(code)
        {
            return Err(ClientError::Usage(
                "Switch wire 1.7: an invite code is a base64url token".into(),
            ));
        }
        let created = self.request_created(&method, path_and_query, &body)?;
        if path_and_query == self.path("account") && auth.invite_code.is_some() {
            return Err(ClientError::Usage(
                "Switch account-binding 2: discovery carries no invite code".into(),
            ));
        }
        let timestamp = rfc3339_seconds(auth.timestamp_ms.unwrap_or_else(|| self.clock.now_ms()));
        let identity = pubky_id(&self.credentials.identity());
        let target = RequestTarget {
            method: &method,
            path_and_query,
            body: &body,
            origin: &self.origin,
        };
        let signature = match &self.credentials {
            Credentials::NextService { transfer, .. } => {
                let transfer_headers = TransferHeaders {
                    timestamp: timestamp.clone(),
                    identity: identity.clone(),
                    transfer: transfer.signed().compact(),
                };
                let signature = self.credentials.sign(
                    labels::sig::TRANSFER_REQUEST,
                    &http::transfer_request_fields(&target, &transfer_headers),
                )?;
                headers.push(Header::new(header::IDENTITY, &identity));
                headers.push(Header::new(header::TRANSFER, &transfer_headers.transfer));
                signature
            }
            Credentials::App { keys, cert, .. } => {
                let request_headers = RequestHeaders {
                    timestamp: timestamp.clone(),
                    identity: identity.clone(),
                    app: Some(keys.app_id()),
                    cert: (self.is_foreign() || auth.with_cert).then(|| cert.signed().compact()),
                    invite_code: auth.invite_code.map(str::to_owned),
                    created: None,
                };
                let signature = self.credentials.sign(
                    labels::sig::HTTP,
                    &http::request_fields(&target, &request_headers),
                )?;
                push_request_headers(&mut headers, &request_headers);
                signature
            }
            Credentials::Signer { .. } | Credentials::SignerRequests { .. } => {
                let request_headers = RequestHeaders {
                    timestamp: timestamp.clone(),
                    identity: identity.clone(),
                    invite_code: auth.invite_code.map(str::to_owned),
                    created: created.map(rfc3339),
                    ..RequestHeaders::default()
                };
                let signature = self.credentials.sign(
                    labels::sig::HTTP,
                    &http::request_fields(&target, &request_headers),
                )?;
                push_request_headers(&mut headers, &request_headers);
                signature
            }
        };
        headers.push(Header::new(header::TIMESTAMP, &timestamp));
        headers.push(Header::new(header::SIGNATURE, &b64(&signature)));
        // Nothing the service refuses at routing is sent: each signed header once, with a
        // printable value, never empty (Switch wire 7.1 "Each header once, as text").
        let received = http::ReceivedHeaders::of(
            headers
                .iter()
                .map(|header| (header.name.as_str(), header.value.as_bytes())),
        );
        if let Some(reason) = received.broken_rule() {
            return Err(ClientError::Usage(format!("Switch wire {reason}")));
        }
        Ok(SignedRequest {
            request: Request {
                method,
                origin: self.origin.clone(),
                path_and_query: path_and_query.to_owned(),
                headers,
                body,
                timeout: auth.timeout,
            },
        })
    }

    /// Sign, send and check a call with the pinned key. A missing pin refuses the call before
    /// it is sent (Switch wire 7.1). A verified `401 stale_timestamp` that
    /// carries `current.server_time` is retried once, the same call signed at that time; the
    /// time is used for nothing else, and a second `stale_timestamp` is the answer.
    pub(crate) async fn call(
        &self,
        method: &str,
        path_and_query: &str,
        body: Vec<u8>,
        content: Body,
        auth: Auth<'_>,
    ) -> Result<CheckedResponse, ClientError> {
        self.call_with_head(method, path_and_query, body, content, auth)
            .await
            .map_err(ClientError::from)
    }

    async fn call_with_head(
        &self,
        method: &str,
        path_and_query: &str,
        body: Vec<u8>,
        content: Body,
        auth: Auth<'_>,
    ) -> Result<CheckedResponse, CallError> {
        let step = self
            .start_call(method, path_and_query, body, content, auth, &mut None)
            .await?;
        self.finish_call_before(step, &mut None, auth.first_send)
            .await
    }

    pub(crate) async fn start_call(
        &self,
        method: &str,
        path_and_query: &str,
        body: Vec<u8>,
        content: Body,
        auth: Auth<'_>,
        public_time: &mut Option<u64>,
    ) -> Result<CallStep, CallError> {
        let key = self.pinned_key().ok_or(ClientError::Unpinned)?;
        self.forget_latest();
        let retry_body = body.clone();
        let signed = self.build(method, path_and_query, body, content, auth)?;
        let checked = self
            .send_checked(signed, key, auth.success_key, public_time, auth.first_send)
            .await;
        let Some(at) = stale_timestamp_hint(checked.as_ref().err().map(|failure| &failure.error))
        else {
            return checked.map(CallStep::Answer);
        };
        let auth = Auth {
            timestamp_ms: Some(at),
            ..auth
        };
        let signed = self.build(method, path_and_query, retry_body, content, auth)?;
        Ok(CallStep::Retry(Box::new(TimestampRetry {
            signed,
            key,
            success_key: auth.success_key,
        })))
    }

    pub(crate) async fn finish_call(
        &self,
        step: CallStep,
        public_time: &mut Option<u64>,
    ) -> Result<CheckedResponse, CallError> {
        self.finish_call_before(step, public_time, None).await
    }

    async fn finish_call_before(
        &self,
        step: CallStep,
        public_time: &mut Option<u64>,
        first: Option<&crate::transport::FirstSend>,
    ) -> Result<CheckedResponse, CallError> {
        match step {
            CallStep::Answer(answer) => Ok(answer),
            CallStep::Retry(retry) => {
                self.send_checked(
                    retry.signed,
                    retry.key,
                    retry.success_key,
                    public_time,
                    first,
                )
                .await
            }
        }
    }

    /// Receive an answer without losing a protected header (Switch wire 7.1).
    async fn send_response(&self, request: Request) -> Result<Response, ClientError> {
        self.send_response_before(request, None).await
    }

    async fn send_response_before(
        &self,
        request: Request,
        first: Option<&crate::transport::FirstSend>,
    ) -> Result<Response, ClientError> {
        check_body_cap(&request.method, &request.path_and_query, &request.body)?;
        self.check_request_binding(&request)?;
        match first {
            Some(first) if !first.confirmed() => {
                first.check()?;
                self.transport.send_before(request, first).await
            }
            _ => self.transport.send(request).await,
        }
        .map_err(|error| match error {
            TransportError::UnreadableSignedHeader { status } => {
                ClientError::BadServiceSignature { status }
            }
            error => error.into(),
        })
    }

    /// The creation selected by this request, never by an answer (account-binding 1-3).
    fn request_created(
        &self,
        method: &str,
        path: &str,
        body: &[u8],
    ) -> Result<Option<u64>, ClientError> {
        if http::is_public_read(method, path) {
            return Ok(None);
        }
        let account_path = self.path("account");
        if path.split('?').next() == Some(account_path.as_str()) {
            self.signer_only()?;
            if method != "GET" || path != account_path || !body.is_empty() {
                return Err(ClientError::Usage(
                    "Switch account-binding 2: discovery is the canonical empty GET".into(),
                ));
            }
            return Ok(None);
        }
        if self.signer_only().is_err() {
            return Ok(None);
        }
        if method == "POST" && path == "/v1/enroll" {
            let value: Value = pubky_switch_core::json::parse_json(body)?;
            let signed = value.get("enrollment").and_then(read::doc).ok_or_else(|| {
                ClientError::Usage("Switch wire 3.7: a signed enrollment is required".into())
            })?;
            let enrollment = Enrollment::verify(&signed, &self.account, &self.origin)?;
            let created = enrollment.body().intent.created();
            if self.created.is_some() && self.created != created {
                return Err(ClientError::Usage(
                    "Switch account-binding 3: the enrollment names another account creation"
                        .into(),
                ));
            }
            return Ok(created);
        }
        let created = self.created.ok_or_else(|| {
            ClientError::Usage(
                "Switch account-binding 1: the signer needs its account creation".into(),
            )
        })?;
        if method == "POST" && path == self.path("erase") {
            let value: Value = pubky_switch_core::json::parse_json(body)?;
            if value
                .get("created")
                .and_then(Value::as_str)
                .and_then(|text| http::parse_created(text).ok())
                != Some(created)
            {
                return Err(ClientError::Usage(
                    "Switch account-binding 1: erasure body and request creation must agree".into(),
                ));
            }
        }
        Ok(Some(created))
    }

    /// Public signed requests can be changed before `send`; check their actual binding.
    fn check_request_binding(&self, request: &Request) -> Result<(), ClientError> {
        if http::is_public_read(&request.method, &request.path_and_query) {
            return Ok(());
        }
        let received = http::ReceivedHeaders::of(
            request
                .headers
                .iter()
                .map(|h| (h.name.as_str(), h.value.as_bytes())),
        );
        if let Some(reason) = received.broken_rule() {
            return Err(ClientError::Usage(format!("Switch wire {reason}")));
        }
        let expected =
            self.request_created(&request.method, &request.path_and_query, &request.body)?;
        let actual = request
            .header(header::CREATED)
            .map(http::parse_created)
            .transpose()?;
        if request.origin != self.origin || actual != expected {
            return Err(ClientError::Usage(
                "Switch account-binding 1: the request must retain its original account target"
                    .into(),
            ));
        }
        if request.path_and_query == self.path("account") {
            let forbidden = [
                header::APP,
                header::CERT,
                header::INVITE_CODE,
                header::TRANSFER,
            ];
            if request.header(header::IDENTITY) != Some(pubky_id(&self.account).as_str())
                || forbidden.iter().any(|name| request.header(name).is_some())
                || request.header(header::TIMESTAMP).is_none()
                || request.header(header::SIGNATURE).is_none()
            {
                return Err(ClientError::Usage(
                    "Switch account-binding 2: discovery carries only identity authentication"
                        .into(),
                ));
            }
        }
        Ok(())
    }

    /// Send a signed request and check its answer: a `2xx` with `success_key` where given,
    /// anything else with `key`.
    async fn send_checked(
        &self,
        signed: SignedRequest,
        key: [u8; 32],
        success_key: Option<[u8; 32]>,
        public_time: &mut Option<u64>,
        first: Option<&crate::transport::FirstSend>,
    ) -> Result<CheckedResponse, CallError> {
        *public_time = None;
        let sent = SentRequest::of(&signed.request);
        let response = self.send_response_before(signed.request, first).await?;
        let key = match success_key {
            Some(success) if (200..300).contains(&response.status) => success,
            _ => key,
        };
        let checked = check_response_with_head(&key, &self.account, &sent, &response);
        // The service signed an answer bound to this exact request body. A header-only
        // refusal or a possibly-sent stamp does not establish handoff (Switch wire 7.1).
        if let Some(first) = first
            && (checked.is_ok()
                || matches!(
                    checked.as_ref().map_err(|error| &error.error),
                    Err(ClientError::Switch { .. })
                ))
        {
            first.confirm();
        }
        let checked = if http::is_public_read(&sent.method, &sent.path_and_query) {
            // Only an authenticated answer supplies the time for this check (Switch wire 7.1).
            let signed_ms = match checked.as_ref().map_err(|failure| &failure.error) {
                Ok(answer) => Some(answer.server_time_ms),
                Err(ClientError::Switch { .. } | ClientError::BodyUnread { .. }) => Some(
                    response
                        .header(header::SERVER_TIME)
                        .and_then(|time| parse_rfc3339(time).ok())
                        .ok_or_else(|| {
                            ClientError::InvalidResponse(
                                "Switch wire 7.1: Switch-Server-Time doesn't parse".into(),
                            )
                        })?,
                ),
                Err(_) => None,
            };
            match signed_ms {
                Some(server_time_ms)
                    if self.clock.now_ms().abs_diff(server_time_ms)
                        > http::PUBLIC_READ_CACHE_MS
                            + 2 * pubky_switch_core::records::CLOCK_TOLERANCE_MS =>
                {
                    Err(ClientError::StaleAnswer { server_time_ms }.into())
                }
                _ => {
                    *public_time = signed_ms;
                    checked
                }
            }
        } else {
            checked
        };
        self.note_server_time(
            &sent,
            checked.as_ref().map_err(|failure| &failure.error),
            &response,
        );
        checked
    }

    /// Send a request this client signed, as built by [`SwitchClient::sign_request`], and
    /// check its answer with the pinned key.
    ///
    /// # Errors
    ///
    /// [`ClientError::Unpinned`] without a pinned key, or [`ClientError::BodyOverCap`] if
    /// the final request exceeds its call's cap, before anything is sent; otherwise as
    /// [`check_response`].
    pub async fn send(&self, signed: SignedRequest) -> Result<CheckedResponse, ClientError> {
        let key = self.pinned_key().ok_or(ClientError::Unpinned)?;
        self.forget_latest();
        self.send_checked(signed, key, None, &mut None, None)
            .await
            .map_err(ClientError::from)
    }

    /// The App ID as a path segment.
    pub(crate) fn app_segment(app_id: &[u8; 16]) -> String {
        zbase32_encode(app_id)
    }

    /// Check a path segment the caller supplies, such as a chunk ID.
    pub(crate) fn segment(text: &str) -> Result<&str, ClientError> {
        if is_token(text) {
            Ok(text)
        } else {
            Err(ClientError::Usage(
                "a path segment holds only base64url characters".into(),
            ))
        }
    }
}

/// Refuse oversized bytes locally: the service's before-body refusal is final for nothing
/// (Switch wire 7.1 Body caps). Check both before signing and before transport, since a
/// public signed request can be assembled or changed by its caller.
fn check_body_cap(method: &str, path: &str, body: &[u8]) -> Result<(), ClientError> {
    if let Some(cap) = http::body_cap(method, path)
        && body.len() > cap
    {
        return Err(ClientError::BodyOverCap { cap });
    }
    Ok(())
}

fn push_request_headers(headers: &mut Vec<Header>, request: &RequestHeaders) {
    headers.push(Header::new(header::IDENTITY, &request.identity));
    if let Some(app) = &request.app {
        headers.push(Header::new(header::APP, app));
    }
    if let Some(cert) = &request.cert {
        headers.push(Header::new(header::CERT, cert));
    }
    if let Some(code) = &request.invite_code {
        headers.push(Header::new(header::INVITE_CODE, code));
    }
    if let Some(created) = &request.created {
        headers.push(Header::new(header::CREATED, created));
    }
}

#[cfg(test)]
mod tests;
