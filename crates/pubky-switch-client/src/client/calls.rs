//! The typed calls of every endpoint (Switch wire 7.4, 8.1, 10).

use pubky_switch_core::chain::{ChainError, ItemType, SignedHead, TransitionProof, item_hash};
use pubky_switch_core::enc::{b64, pubky_id};
use pubky_switch_core::export::{
    ActivateAnswer, ActivateRequest, ChunkAnswer, ImportStart, ImportStatus, Manifest,
};
use pubky_switch_core::http::{self, IdentityDelivery, erase_body, header};
use pubky_switch_core::json::{Doc, parse_json};
use pubky_switch_core::records::{
    AccountObservation, AccountObservationBody, CarriedAccountObservation, DiscardAnswer,
    Enrollment, EnrollmentAnswer, Freeze, IdentityDoc, Unfreeze,
};
use pubky_switch_core::sig::SignedDoc;

use super::answers::{
    AllowList, AppendAnswer, AppsAnswer, ClaimAnswer, ConnectAnswer, ConnectList, Directory,
    FeedPage, FeedQuery, HandoverStored, KeysAnswer, PeersAnswer, PublicIdentity, PushAnswer,
    PushSetting, RecordAnswer, RecordPage, RecoveryUpload, SharedRecordView, StoredHandover,
    UploadAnswer, WriteAnswer,
};
use super::read::{self, Obj};
use super::{
    Auth, Body, CheckedResponse, SentRequest, SwitchClient, check_response, stale_timestamp_hint,
    verify_head,
};
use crate::error::ClientError;
use crate::transport::{Request, Response, TimeoutClass};

/// An append answer or the single authenticated timestamp retry, not yet sent.
pub(crate) struct AppendCall(super::CallStep);

impl AppendCall {
    pub(crate) fn needs_retry(&self) -> bool {
        matches!(self.0, super::CallStep::Retry(_))
    }
}

/// What the proofs of a write answer must show (Switch wire 6.5).
enum Expect<'a> {
    /// A service transition whose proof names `object`.
    Transition(String),
    /// The delivery of this `identity.json`.
    Identity(&'a SignedDoc),
}

fn proof_error(why: &str) -> ClientError {
    ClientError::Chain(ChainError::Proof(format!("Switch wire 6.5: {why}")))
}

impl SwitchClient {
    fn key(&self) -> Result<[u8; 32], ClientError> {
        self.pinned_key().ok_or(ClientError::Unpinned)
    }

    async fn get(&self, rest: &str, timeout: TimeoutClass) -> Result<CheckedResponse, ClientError> {
        self.call(
            "GET",
            &self.path(rest),
            Vec::new(),
            Body::Empty,
            Auth {
                timeout,
                ..Auth::default()
            },
        )
        .await
    }

    async fn post_empty(&self, rest: &str) -> Result<CheckedResponse, ClientError> {
        self.call(
            "POST",
            &self.path(rest),
            Vec::new(),
            Body::Empty,
            Auth::default(),
        )
        .await
    }

    async fn send_json(
        &self,
        method: &str,
        rest: &str,
        body: Vec<u8>,
        timeout: TimeoutClass,
    ) -> Result<CheckedResponse, ClientError> {
        let auth = Auth {
            timeout,
            ..Auth::default()
        };
        self.call(method, &self.path(rest), body, Body::Json, auth)
            .await
    }

    /// Verify a proof with `key` (Switch wire 6.5).
    fn proof(&self, signed: &SignedDoc, key: &[u8; 32]) -> Result<TransitionProof, ClientError> {
        TransitionProof::verify(signed, key, &self.account())
            .map_err(|error| ClientError::Chain(ChainError::Signature(error.to_string())))
    }

    /// Read a write answer, `{ "proofs": [...], "head" }`, verifying the head and every
    /// proof with the pinned key and checking that the proofs are of what was written: at
    /// most one, of the expected item (Switch wire 6.5, 7.1).
    fn write_answer(
        &self,
        checked: &CheckedResponse,
        expect: Expect<'_>,
    ) -> Result<WriteAnswer, ClientError> {
        self.write_answer_under(checked, expect, &self.key()?)
    }

    /// [`SwitchClient::write_answer`], with the head and the proofs verified with `key`.
    fn write_answer_under(
        &self,
        checked: &CheckedResponse,
        expect: Expect<'_>,
        key: &[u8; 32],
    ) -> Result<WriteAnswer, ClientError> {
        let (value, what) = read::body(&checked.body, Doc::Plain, "a write answer")?;
        let o = Obj::of(&value, what)?;
        let head = o.head("head")?;
        verify_head(&head, key, &self.account())?;
        let docs = o.required_each("proofs", read::doc)?;
        if docs.len() > 1 {
            return Err(proof_error("one proof for one item written"));
        }
        let proofs = docs
            .iter()
            .map(|signed| self.proof(signed, key))
            .collect::<Result<Vec<_>, _>>()?;
        for proof in &proofs {
            let envelope = proof.envelope();
            match &expect {
                Expect::Transition(object) => {
                    if envelope.item_type != ItemType::Service || &proof.body().object != object {
                        return Err(proof_error("the proof isn't of the transition written"));
                    }
                }
                Expect::Identity(doc) => {
                    let bytes = doc.doc_bytes()?;
                    if envelope.item_type != ItemType::Identity
                        || envelope.item_hash != item_hash(ItemType::Identity, &bytes)
                        || proof.body().object != "identity"
                    {
                        return Err(proof_error(
                            "the proof isn't of the delivered identity.json",
                        ));
                    }
                }
            }
        }
        Ok(WriteAnswer { proofs, head })
    }

    fn json_answer<'a>(
        checked: &CheckedResponse,
        doc: Doc<'_>,
        what: &'a str,
    ) -> Result<(serde_json::Value, &'a str), ClientError> {
        read::body(&checked.body, doc, what)
    }

    /// `POST /v1/enroll` (signer, Switch wire 3.7, 7.4.1): send the signed enrollment, kept
    /// by the signer so that a retry sends the same one.
    ///
    /// The answer is checked as the core checks it, and its response signature with the key
    /// it names. A client without a pinned key pins that key. One that holds a key keeps it:
    /// at a serving account the answer names that key, unless the service changed its key
    /// since (Switch spec 12.5), and then [`SwitchClient::put_identity`] pins the new one once
    /// the delivery naming it is accepted.
    ///
    /// # Errors
    ///
    /// [`ClientError::Usage`] for an enrollment of another identity or origin;
    /// [`ClientError::BadServiceSignature`] for an answer that doesn't verify, among them
    /// every error answer to a client that holds no key, which can't check it;
    /// [`ClientError::Core`] for an answer that names another enrollment.
    pub async fn enroll(&self, enrollment: &Enrollment) -> Result<EnrollmentAnswer, ClientError> {
        self.signer_only()?;
        // No answer to an enrollment counts in the comparison of service times, nor
        // measures the clock (Switch wire 7.1 Timestamp).
        self.forget_latest();
        if enrollment.body().identity != self.account() || enrollment.body().origin != self.origin()
        {
            return Err(ClientError::Usage(
                "Switch wire 3.7: the enrollment names another identity or origin".into(),
            ));
        }
        let body = enrollment.to_request_json()?;
        let auth = Auth {
            timeout: TimeoutClass::Bulk,
            ..Auth::default()
        };
        let signed = self.build("POST", "/v1/enroll", body.clone(), Body::Json, auth)?;
        let sent = SentRequest::of(&signed.request);
        let response = self.send_response(signed.request).await?;
        let checked = self.enrollment_answer(enrollment, &sent, &response);
        let Some(at) = stale_timestamp_hint(checked.as_ref().err()) else {
            return checked;
        };
        let signed = self.build(
            "POST",
            "/v1/enroll",
            body,
            Body::Json,
            Auth {
                timestamp_ms: Some(at),
                ..auth
            },
        )?;
        let sent = SentRequest::of(&signed.request);
        let response = self.send_response(signed.request).await?;
        self.enrollment_answer(enrollment, &sent, &response)
    }

    fn enrollment_answer(
        &self,
        enrollment: &Enrollment,
        sent: &SentRequest,
        response: &Response,
    ) -> Result<EnrollmentAnswer, ClientError> {
        let status = response.status;
        if response.header(header::HEAD).is_some() {
            return Err(ClientError::BadServiceSignature { status });
        }
        if !(200..300).contains(&status) {
            // Errors are signed with the service key: a client that pinned it checks them,
            // one that holds none can't (Switch wire 7.1, 7.4.1 Errors).
            return Err(match self.pinned_key() {
                Some(key) => match check_response(&key, &self.account(), sent, response) {
                    Err(error) => error,
                    Ok(_) => ClientError::BadServiceSignature { status },
                },
                None => ClientError::BadServiceSignature { status },
            });
        }
        // The key that verifies the answer is the one it names (Switch wire 3.7).
        let answer = EnrollmentAnswer::from_json(&response.body)
            .map_err(|_| ClientError::BadServiceSignature { status })?;
        check_response(&answer.service_key, &self.account(), sent, response)?;
        answer.check(enrollment)?;
        if self.pinned_key().is_none() {
            self.pin(answer.service_key);
        }
        Ok(answer)
    }

    /// Read an authenticated observation of this account (Switch account-binding Section 2).
    /// The carried result retains the exact response and original request authentication.
    /// It changes neither the client's pin nor its account creation binding, and its time
    /// counts in no account-time comparison. It does not establish an identity document.
    ///
    /// An unpinned signer checks the successful answer with its body's service key at this
    /// explicitly selected HTTPS origin. With a pin, that key must verify the answer.
    /// Observation validity and current-state authorization are the service's locked checks.
    ///
    /// # Errors
    ///
    /// [`ClientError::Usage`] for non-signer credentials; otherwise as every checked call.
    /// A verified stale-timestamp answer is retried once with only the request time changed.
    /// An unpinned client cannot authenticate an error answer.
    pub async fn observe_account(&self) -> Result<AccountObservation, ClientError> {
        self.signer_only()?;
        self.forget_latest();
        let path = self.path("account");
        let signed = self.build("GET", &path, Vec::new(), Body::Empty, Auth::default())?;
        let response = self.send_response(signed.request.clone()).await?;
        let checked = self.account_observation(&signed.request, &response);
        let Some(at) = stale_timestamp_hint(checked.as_ref().err()) else {
            return checked;
        };
        let signed = self.build(
            "GET",
            &path,
            Vec::new(),
            Body::Empty,
            Auth {
                timestamp_ms: Some(at),
                ..Auth::default()
            },
        )?;
        let response = self.send_response(signed.request.clone()).await?;
        self.account_observation(&signed.request, &response)
    }

    fn account_observation(
        &self,
        request: &Request,
        response: &Response,
    ) -> Result<AccountObservation, ClientError> {
        let status = response.status;
        let invalid = || ClientError::BadServiceSignature { status };
        if response
            .headers
            .iter()
            .any(|h| h.name.eq_ignore_ascii_case(header::HEAD))
        {
            return Err(invalid());
        }
        let key = match self.pinned_key() {
            Some(key) => key,
            None if status == 200 => {
                AccountObservationBody::from_json(&response.body)
                    .map_err(|_| invalid())?
                    .service_key
            }
            None => return Err(invalid()),
        };
        check_response(&key, &self.account, &SentRequest::of(request), response)?;
        if status != 200 {
            return Err(invalid());
        }
        let signature = |text: Option<&str>| {
            text.and_then(|text| http::decode_signature(text).ok())
                .ok_or_else(invalid)
        };
        let carried = CarriedAccountObservation {
            body: response.body.clone(),
            sig: signature(response.header(header::SERVICE_SIGNATURE))?,
            request_timestamp: request
                .header(header::TIMESTAMP)
                .ok_or_else(invalid)?
                .to_owned(),
            request_signature: signature(request.header(header::SIGNATURE))?,
        };
        let observation = carried.verify(&self.account, &self.origin)?;
        if observation.body().service_key != key {
            return Err(invalid());
        }
        Ok(observation)
    }

    /// `PUT /v1/{id}/identity` (signer, Switch wire 7.4.2): deliver an `identity.json`,
    /// naming the version it builds on. The answer's proof is checked as the delivery's.
    ///
    /// A delivery whose document names this origin with another service key than the pinned
    /// one starts a generation under that key, the service's new key after a key change
    /// (Switch spec 12.5), which signs its `200`: the answer, its proof and its head are
    /// checked with it, and it is pinned once they verify.
    /// Any other status is checked with the pinned key, which stays pinned (Switch wire
    /// 7.4.2 "Which key signs the answer").
    ///
    /// # Errors
    ///
    /// As every call; `409 stale_identity` and `409 conflict` carry `current`.
    pub async fn put_identity(
        &self,
        delivery: &IdentityDelivery,
    ) -> Result<WriteAnswer, ClientError> {
        self.signer_only()?;
        let pinned = self.key()?;
        let new_key = IdentityDoc::verify(&delivery.identity, &self.account())
            .ok()
            .filter(|doc| doc.inbox().url == self.origin())
            .map(|doc| doc.inbox().service_key)
            .filter(|named| *named != pinned);
        let checked = self
            .call(
                "PUT",
                &self.path("identity"),
                delivery.to_json(),
                Body::Json,
                Auth {
                    success_key: new_key,
                    ..Auth::default()
                },
            )
            .await?;
        let key = new_key.unwrap_or(pinned);
        let answer =
            self.write_answer_under(&checked, Expect::Identity(&delivery.identity), &key)?;
        if new_key.is_some() {
            self.pin(key);
        }
        Ok(answer)
    }

    /// `POST /v1/{id}/inbox` (Switch wire 7.4.3): append an envelope sealed for the
    /// recipient's `apps_version`, presenting an invite code if given.
    ///
    /// # Errors
    ///
    /// As every call; `409 stale_key` carries the records to seal to again.
    pub async fn append(
        &self,
        envelope: Vec<u8>,
        apps_version: u64,
        invite_code: Option<&str>,
    ) -> Result<AppendAnswer, ClientError> {
        let call = self
            .start_append(envelope, apps_version, invite_code)
            .await?;
        self.finish_append(call).await
    }

    pub(crate) async fn start_append(
        &self,
        envelope: Vec<u8>,
        apps_version: u64,
        invite_code: Option<&str>,
    ) -> Result<AppendCall, ClientError> {
        let path = self.path(&format!("inbox?apps_version={apps_version}"));
        let step = self
            .start_call(
                "POST",
                &path,
                envelope,
                Body::Octets,
                Auth {
                    invite_code,
                    timeout: TimeoutClass::Bulk,
                    ..Auth::default()
                },
                &mut None,
            )
            .await?;
        Ok(AppendCall(step))
    }

    pub(crate) async fn finish_append(
        &self,
        call: AppendCall,
    ) -> Result<AppendAnswer, ClientError> {
        let checked = self.finish_call(call.0, &mut None).await?;
        let (value, what) =
            Self::json_answer(&checked, Doc::Plain, "Switch wire 7.4.3: an append answer")?;
        AppendAnswer::read(Obj::of(&value, what)?)
    }

    /// `GET /v1/{id}/feed` (own app, Switch wire 7.4.4). The page's head and checkpoint are
    /// verified with the pinned key, and its freeze with the identity key.
    ///
    /// # Errors
    ///
    /// As every call.
    pub async fn feed(&self, query: FeedQuery) -> Result<FeedPage, ClientError> {
        let checked = self.get(&query.path(), query.timeout()).await?;
        let (value, what) =
            Self::json_answer(&checked, Doc::FeedPage, "Switch wire 7.4.4: a feed page")?;
        let key = self.key()?;
        let page = FeedPage::read(
            Obj::of(&value, what)?,
            &self.account(),
            checked.server_time_ms,
            key,
        )?;
        verify_head(&page.head, &key, &self.account())?;
        if let Some(checkpoint) = &page.checkpoint {
            verify_head(checkpoint, &key, &self.account())?;
        }
        Ok(page)
    }

    /// `PUT /v1/{id}/peers` (Switch wire 7.4.5): deliver an `identity.json` as signed.
    ///
    /// # Errors
    ///
    /// As every call; `409 stale_identity` carries the held version, and the held document
    /// for another body at that version.
    pub async fn put_peers(
        &self,
        identity: &SignedDoc,
        invite_code: Option<&str>,
    ) -> Result<PeersAnswer, ClientError> {
        let body = serde_json::to_vec(identity)
            .map_err(|_| ClientError::Usage("the document can't be written".into()))?;
        let checked = self
            .call(
                "PUT",
                &self.path("peers"),
                body,
                Body::Json,
                Auth {
                    invite_code,
                    ..Auth::default()
                },
            )
            .await?;
        let (value, what) =
            Self::json_answer(&checked, Doc::Plain, "Switch wire 7.4.5: a peers answer")?;
        PeersAnswer::read(Obj::of(&value, what)?)
    }

    /// `GET /v1/{id}/allow` (own app with `lists.read`, Switch wire 7.4.6).
    ///
    /// # Errors
    ///
    /// As every call.
    pub async fn allow(&self) -> Result<AllowList, ClientError> {
        let checked = self.get("allow", TimeoutClass::Bulk).await?;
        let (value, what) =
            Self::json_answer(&checked, Doc::AllowList, "Switch wire 7.4.6: an allow list")?;
        AllowList::read(Obj::of(&value, what)?)
    }

    /// `POST /v1/{id}/connect` (app of another identity, Switch wire 7.4.7).
    ///
    /// # Errors
    ///
    /// As every call.
    pub async fn connect(&self) -> Result<ConnectAnswer, ClientError> {
        let checked = self.post_empty("connect").await?;
        let (value, what) =
            Self::json_answer(&checked, Doc::Plain, "Switch wire 7.4.7: a connect answer")?;
        ConnectAnswer::read(Obj::of(&value, what)?)
    }

    /// `GET /v1/{id}/connect` (own app with `lists.read`, Switch wire 7.4.7).
    ///
    /// # Errors
    ///
    /// As every call.
    pub async fn connect_requests(&self) -> Result<ConnectList, ClientError> {
        let checked = self.get("connect", TimeoutClass::Ordinary).await?;
        let (value, what) = Self::json_answer(
            &checked,
            Doc::Plain,
            "Switch wire 7.4.7: the connect requests",
        )?;
        ConnectList::read(Obj::of(&value, what)?)
    }

    /// `DELETE /v1/{id}/connect/{pubky}` (own app with `conversation.add`, Switch wire
    /// 7.4.7). Returns the declined sender.
    ///
    /// # Errors
    ///
    /// As every call; `404` when no request is pending from it.
    pub async fn decline_connect(&self, pubky: &[u8; 32]) -> Result<[u8; 32], ClientError> {
        let path = self.path(&format!("connect/{}", pubky_id(pubky)));
        let checked = self
            .call("DELETE", &path, Vec::new(), Body::Empty, Auth::default())
            .await?;
        let (value, what) =
            Self::json_answer(&checked, Doc::Plain, "Switch wire 7.4.7: a decline answer")?;
        Obj::of(&value, what)?.pubky("declined")
    }

    /// `GET /v1/{id}/claims/{claim_key}` (own app with `claims.read`, Switch wire 7.4.8).
    ///
    /// # Errors
    ///
    /// As every call; `404` when the service holds nothing for the claim key.
    pub async fn claim(&self, claim_key: &[u8; 32]) -> Result<ClaimAnswer, ClientError> {
        let checked = self
            .get(&format!("claims/{}", b64(claim_key)), TimeoutClass::Bulk)
            .await?;
        let (value, what) = Self::json_answer(&checked, Doc::Plain, "Switch wire 7.4.8: a claim")?;
        ClaimAnswer::read(Obj::of(&value, what)?)
    }

    /// `GET /v1/{id}/records/{key}` (own app with the record's read scope, Switch wire
    /// 7.4.9).
    ///
    /// # Errors
    ///
    /// As every call; `404` for an unknown or forgotten key.
    pub async fn record(&self, key: &[u8; 32]) -> Result<RecordAnswer, ClientError> {
        self.record_with_head(key).await.map_err(ClientError::from)
    }

    /// Keep a hosted absence's own verified position for the write the app follows.
    pub(crate) async fn record_with_head(
        &self,
        key: &[u8; 32],
    ) -> Result<RecordAnswer, super::CallError> {
        let checked = self
            .call_with_head(
                "GET",
                &self.path(&format!("records/{}", b64(key))),
                Vec::new(),
                Body::Empty,
                Auth {
                    timeout: TimeoutClass::Bulk,
                    ..Auth::default()
                },
            )
            .await?;
        let (value, what) =
            Self::json_answer(&checked, Doc::Plain, "Switch wire 7.4.9: a record view")?;
        Ok(RecordAnswer {
            view: SharedRecordView::read(Obj::of(&value, what)?)?,
            head: own_head(&checked, "a record view")?,
        })
    }

    /// `GET /v1/{id}/records?collection=&after=&limit=` (own app, Switch wire 7.4.9).
    ///
    /// # Errors
    ///
    /// As every call.
    pub async fn records(
        &self,
        collection: &[u8; 32],
        after: Option<&[u8; 32]>,
        limit: Option<u32>,
    ) -> Result<RecordPage, ClientError> {
        let mut rest = format!("records?collection={}", b64(collection));
        if let Some(after) = after {
            rest.push_str(&format!("&after={}", b64(after)));
        }
        if let Some(limit) = limit {
            rest.push_str(&format!("&limit={limit}"));
        }
        let checked = self.get(&rest, TimeoutClass::Bulk).await?;
        let (value, what) =
            Self::json_answer(&checked, Doc::Plain, "Switch wire 7.4.9: a record page")?;
        RecordPage::read(Obj::of(&value, what)?, own_head(&checked, "a record page")?)
    }

    /// `GET /v1/{id}/directory` (own app, or an admitted app of another identity, Switch wire
    /// 7.4.10). The `identity.json`, the app records and the receive key records are
    /// verified for the account's identity.
    ///
    /// # Errors
    ///
    /// As every call; [`ClientError::Core`] for a document that doesn't verify.
    pub async fn directory(&self, invite_code: Option<&str>) -> Result<Directory, ClientError> {
        let checked = self
            .call(
                "GET",
                &self.path("directory"),
                Vec::new(),
                Body::Empty,
                Auth {
                    invite_code,
                    timeout: TimeoutClass::Bulk,
                    ..Auth::default()
                },
            )
            .await?;
        let (value, what) =
            Self::json_answer(&checked, Doc::Plain, "Switch wire 7.4.10: a directory")?;
        Directory::read(Obj::of(&value, what)?, &self.account())
    }

    /// `GET /v1/{id}/apps/{app_id}/keys` for the calling app (Switch wire 7.4.11).
    ///
    /// # Errors
    ///
    /// [`ClientError::Usage`] for credentials other than an app's; otherwise as every call,
    /// `404` when the service holds no part.
    pub async fn keys(&self) -> Result<KeysAnswer, ClientError> {
        let app = Self::app_segment(&self.own_app_id()?);
        let checked = self
            .get(&format!("apps/{app}/keys"), TimeoutClass::Bulk)
            .await?;
        let (value, what) =
            Self::json_answer(&checked, Doc::Plain, "Switch wire 7.4.11: a keys answer")?;
        KeysAnswer::read(Obj::of(&value, what)?)
    }

    /// `POST /v1/{id}/apps/{app_id}/keys` for the calling app (Switch wire 7.4.11): ask the
    /// signer for a full key bundle. Returns the time of the first request, in Unix
    /// milliseconds.
    ///
    /// # Errors
    ///
    /// As [`SwitchClient::keys`].
    pub async fn request_full_bundle(&self) -> Result<u64, ClientError> {
        let app = Self::app_segment(&self.own_app_id()?);
        let checked = self.post_empty(&format!("apps/{app}/keys")).await?;
        let (value, what) =
            Self::json_answer(&checked, Doc::Plain, "Switch wire 7.4.11: a request answer")?;
        Obj::of(&value, what)?.time("requested")
    }

    /// `PUT /v1/{id}/push` (own app, Switch wire 8.1): start a registration or set its
    /// handles.
    ///
    /// # Errors
    ///
    /// As every call; `409 conflict` carries the current push key.
    pub async fn put_push(&self, setting: &PushSetting) -> Result<PushAnswer, ClientError> {
        let checked = self
            .send_json("PUT", "push", setting.to_json(), TimeoutClass::Ordinary)
            .await?;
        let (value, what) =
            Self::json_answer(&checked, Doc::Plain, "Switch wire 8.1: a push answer")?;
        PushAnswer::read(Obj::of(&value, what)?)
    }

    /// `POST /v1/{id}/apps/{app_id}/leave` for the calling app (Switch wire 7.4.12),
    /// answered with the `leave` transition's proof.
    ///
    /// # Errors
    ///
    /// [`ClientError::Usage`] for credentials other than an app's; otherwise as every call.
    pub async fn leave(&self) -> Result<WriteAnswer, ClientError> {
        let app = Self::app_segment(&self.own_app_id()?);
        let checked = self.post_empty(&format!("apps/{app}/leave")).await?;
        self.write_answer(&checked, Expect::Transition(app))
    }

    /// `GET /v1/{id}/apps` (signer, Switch wire 7.4.12).
    ///
    /// # Errors
    ///
    /// As every call.
    pub async fn apps(&self) -> Result<AppsAnswer, ClientError> {
        self.signer_only()?;
        let checked = self.get("apps", TimeoutClass::Bulk).await?;
        let (value, what) =
            Self::json_answer(&checked, Doc::Plain, "Switch wire 7.4.12: an apps answer")?;
        AppsAnswer::read(Obj::of(&value, what)?, checked.server_time_ms)
    }

    /// `POST /v1/{id}/apps/{app_id}/revoke` (signer, Switch wire 7.4.12), answered with the
    /// `revoke` transition's proof, or none for an app revoked before.
    ///
    /// # Errors
    ///
    /// As every call; `404` for an app neither the service nor `identity.json` knows.
    pub async fn revoke(&self, app_id: &[u8; 16]) -> Result<WriteAnswer, ClientError> {
        self.signer_only()?;
        let app = Self::app_segment(app_id);
        let checked = self.post_empty(&format!("apps/{app}/revoke")).await?;
        self.write_answer(&checked, Expect::Transition(app))
    }

    /// `POST /v1/{id}/freeze` (signer, Switch wire 7.4.13), answered with the `freeze`
    /// transition's proof.
    ///
    /// # Errors
    ///
    /// As every call; `409 conflict` carries the freeze the account is frozen by.
    pub async fn freeze(&self, freeze: &Freeze) -> Result<WriteAnswer, ClientError> {
        self.signer_only()?;
        let body = serde_json::to_vec(freeze.signed())
            .map_err(|_| ClientError::Usage("the freeze can't be written".into()))?;
        let checked = self
            .send_json("POST", "freeze", body, TimeoutClass::Ordinary)
            .await?;
        self.write_answer(&checked, Expect::Transition("freeze".into()))
    }

    /// `POST /v1/{id}/unfreeze` at the frozen old service (signer, Switch wire 7.4.13), with
    /// the next service's discard answer; answered with the `unfreeze` transition's proof.
    ///
    /// # Errors
    ///
    /// [`ClientError::Usage`] for an unfreeze without the discard answer; otherwise as every
    /// call.
    pub async fn unfreeze(&self, unfreeze: &Unfreeze) -> Result<WriteAnswer, ClientError> {
        self.signer_only()?;
        if unfreeze.discarded.is_none() {
            return Err(ClientError::Usage(
                "Switch wire 3.6: the unfreeze at the old service carries the discard answer"
                    .into(),
            ));
        }
        let body = serde_json::to_vec(unfreeze)
            .map_err(|_| ClientError::Usage("the unfreeze can't be written".into()))?;
        let checked = self
            .send_json("POST", "unfreeze", body, TimeoutClass::Ordinary)
            .await?;
        self.write_answer(&checked, Expect::Transition("unfreeze".into()))
    }

    /// `POST /v1/{id}/unfreeze` at the staged next service: the abort of a move (signer,
    /// Switch wire 10.6). The discard answer is verified with the pinned key, the next
    /// service's key the freeze names.
    ///
    /// # Errors
    ///
    /// [`ClientError::Usage`] for an unfreeze that carries a discard answer;
    /// [`ClientError::Core`] for a discard answer that doesn't verify; otherwise as every
    /// call.
    pub async fn abort_import(&self, unfreeze: &Unfreeze) -> Result<DiscardAnswer, ClientError> {
        self.signer_only()?;
        if unfreeze.discarded.is_some() {
            return Err(ClientError::Usage(
                "Switch wire 3.6: the unfreeze sent to the next service carries no answer".into(),
            ));
        }
        let body = serde_json::to_vec(unfreeze)
            .map_err(|_| ClientError::Usage("the unfreeze can't be written".into()))?;
        let checked = self
            .send_json("POST", "unfreeze", body, TimeoutClass::Ordinary)
            .await?;
        let answer: DiscardAnswer = parse_json(&checked.body).map_err(|_| {
            ClientError::InvalidResponse("Switch wire 3.6: a discard answer doesn't read".into())
        })?;
        answer.verify(&self.account(), &unfreeze.freeze_hash, &self.key()?)?;
        Ok(answer)
    }

    /// `GET /v1/{id}/export` (signer, at a frozen account, Switch wire 10.3): the manifest,
    /// verified with the pinned key.
    ///
    /// # Errors
    ///
    /// As every call; [`ClientError::Core`] for a manifest that doesn't verify.
    pub async fn export(&self) -> Result<Manifest, ClientError> {
        self.signer_only()?;
        let checked = self.get("export", TimeoutClass::Bulk).await?;
        let (value, what) =
            Self::json_answer(&checked, Doc::Plain, "Switch wire 10.3: an export answer")?;
        let signed = Obj::of(&value, what)?.doc("manifest")?;
        Ok(Manifest::verify(&signed, &self.key()?, &self.account())?)
    }

    /// `GET /v1/{id}/export/chunks/{chunk_id}` (signer, or the next service under the export
    /// transfer, Switch wire 10.3). Whoever fetches a chunk checks its length and hash
    /// against the manifest ([`Manifest::check_fetched`]) before storing it.
    ///
    /// # Errors
    ///
    /// [`ClientError::Usage`] for a chunk ID that isn't a path segment;
    /// [`ClientError::InvalidResponse`] for an answer naming another chunk; otherwise as
    /// every call.
    pub async fn export_chunk(&self, chunk_id: &str) -> Result<ChunkAnswer, ClientError> {
        if matches!(self.credentials(), super::Credentials::App { .. }) {
            return Err(ClientError::Usage(
                "only the signer or the next service fetches export chunks".into(),
            ));
        }
        let id = Self::segment(chunk_id)?;
        let checked = self
            .get(&format!("export/chunks/{id}"), TimeoutClass::Bulk)
            .await?;
        let answer = ChunkAnswer::parse(&checked.body).map_err(|_| {
            ClientError::InvalidResponse("Switch wire 10.3: a chunk answer doesn't read".into())
        })?;
        if answer.id != chunk_id {
            return Err(ClientError::InvalidResponse(
                "Switch wire 10.3: the answer names another chunk".into(),
            ));
        }
        Ok(answer)
    }

    /// `POST /v1/{id}/import` (signer, at a staged account, Switch wire 10.4).
    ///
    /// # Errors
    ///
    /// As every call.
    pub async fn import_start(&self, start: &ImportStart) -> Result<ImportStatus, ClientError> {
        self.signer_only()?;
        let checked = self
            .send_json("POST", "import", start.to_json(), TimeoutClass::Bulk)
            .await?;
        ImportStatus::parse(&checked.body).map_err(|_| {
            ClientError::InvalidResponse("Switch wire 10.4: an import status doesn't read".into())
        })
    }

    /// `PUT /v1/{id}/import/chunks/{chunk_id}` (signer, at a staged account, Switch wire
    /// 10.4): the exact chunk bytes.
    ///
    /// # Errors
    ///
    /// [`ClientError::Usage`] for a chunk ID that isn't a path segment; otherwise as every
    /// call, `409 conflict` carrying the chunk reference for a chunk that doesn't match.
    pub async fn import_chunk(
        &self,
        chunk_id: &str,
        chunk: Vec<u8>,
    ) -> Result<ImportStatus, ClientError> {
        self.signer_only()?;
        let id = Self::segment(chunk_id)?;
        let checked = self
            .send_json(
                "PUT",
                &format!("import/chunks/{id}"),
                chunk,
                TimeoutClass::Bulk,
            )
            .await?;
        ImportStatus::parse(&checked.body).map_err(|_| {
            ClientError::InvalidResponse("Switch wire 10.4: an import status doesn't read".into())
        })
    }

    /// `POST /v1/{id}/import/activate` (signer, at a staged account, Switch wire 10.5). The
    /// answer's head is verified with the pinned key.
    ///
    /// # Errors
    ///
    /// As every call; `409 conflict` carries the chunks missing.
    pub async fn import_activate(
        &self,
        manifest_hash: &[u8; 32],
    ) -> Result<ActivateAnswer, ClientError> {
        self.signer_only()?;
        let body = ActivateRequest {
            manifest: *manifest_hash,
        }
        .to_json();
        let checked = self
            .send_json("POST", "import/activate", body, TimeoutClass::Bulk)
            .await?;
        let answer = ActivateAnswer::parse(&checked.body).map_err(|_| {
            ClientError::InvalidResponse(
                "Switch wire 10.5: an activation answer doesn't read".into(),
            )
        })?;
        verify_head(&answer.head, &self.key()?, &self.account())?;
        Ok(answer)
    }

    /// `POST /v1/{id}/recovery/admission` (signer, Switch wire 7.4.14): end staged
    /// admission, answered with the `admission` transition's proof.
    ///
    /// # Errors
    ///
    /// As every call; `404` without a recovery.
    pub async fn recovery_admission(&self) -> Result<WriteAnswer, ClientError> {
        self.signer_only()?;
        let checked = self.post_empty("recovery/admission").await?;
        self.write_answer(&checked, Expect::Transition("admission".into()))
    }

    /// `POST /v1/{id}/recovery/upload` (own app, Switch wire 7.4.14). `staged` marks the
    /// staged head upload before an import, which authenticates with `Switch-Cert` (Switch
    /// wire 7.2). The `upload` transition's proof and the head, where present, are verified
    /// with the pinned key.
    ///
    /// # Errors
    ///
    /// [`ClientError::Usage`] for credentials other than an app's; otherwise as every call,
    /// `409 conflict` carrying the import conflicts.
    pub async fn recovery_upload(
        &self,
        upload: &RecoveryUpload,
        staged: bool,
    ) -> Result<UploadAnswer, ClientError> {
        self.recovery_upload_body(upload.to_json(), staged).await
    }

    pub(crate) async fn recovery_upload_body(
        &self,
        body: Vec<u8>,
        staged: bool,
    ) -> Result<UploadAnswer, ClientError> {
        self.own_app_id()?;
        let checked = self
            .call(
                "POST",
                &self.path("recovery/upload"),
                body,
                Body::Json,
                Auth {
                    with_cert: staged,
                    timeout: TimeoutClass::Bulk,
                    ..Auth::default()
                },
            )
            .await?;
        let (value, what) =
            Self::json_answer(&checked, Doc::Plain, "Switch wire 7.4.14: an upload answer")?;
        let o = Obj::of(&value, what)?;
        let mut answer = UploadAnswer::read_counts(o)?;
        answer.head = match o.opt_head("head")? {
            None => None,
            Some(head) => {
                verify_head(&head, &self.key()?, &self.account())?;
                Some(head)
            }
        };
        answer.proof = match o.opt_doc("proof")? {
            None => None,
            Some(signed) => {
                let proof = self.proof(&signed, &self.key()?)?;
                if proof.envelope().item_type != ItemType::Service
                    || proof.body().object != "upload"
                {
                    return Err(proof_error("the proof isn't of the upload transition"));
                }
                Some(proof)
            }
        };
        Ok(answer)
    }

    /// `GET /v1/{id}/identity`, the unauthenticated public read (Switch wire 7.4.15): sent
    /// without any `Switch-*` header, and the document and the freeze verified with the
    /// account's identity key. The service signature and the signed time are checked
    /// before the document or freeze is used (Switch wire 7.1).
    ///
    /// # Errors
    ///
    /// [`ClientError::Unpinned`] before sending without a service key, [`ClientError::StaleAnswer`]
    /// for a response outside the time window, or [`ClientError::Core`] for an invalid document.
    pub async fn public_identity(&self) -> Result<PublicIdentity, ClientError> {
        self.public_identity_with_time(&mut None).await
    }

    /// Also keep the verified time of a fresh refusal, including a staged successor
    /// that completes a public lookup without supplying a document (Switch wire 3.3).
    pub(crate) async fn public_identity_with_time(
        &self,
        public_time: &mut Option<u64>,
    ) -> Result<PublicIdentity, ClientError> {
        let step = self
            .start_call(
                "GET",
                &self.path("identity"),
                Vec::new(),
                Body::Empty,
                Auth {
                    public: true,
                    ..Auth::default()
                },
                public_time,
            )
            .await?;
        let checked = self.finish_call(step, public_time).await?;
        let (value, what) =
            Self::json_answer(&checked, Doc::Plain, "Switch wire 7.4.15: a public read")?;
        PublicIdentity::read(
            Obj::of(&value, what)?,
            &self.account(),
            checked.server_time_ms,
        )
    }

    /// `POST /v1/{id}/erase` (signer, Switch wire 7.4.16), naming `created`, the account's
    /// creation time its enrollment answer gave, or none for a signer that holds none, and
    /// `identity_hash`, the document hash of the newest `identity.json` the account holds, or
    /// none for an account that holds none: a switch that created the account at another time
    /// or holds another document answers `409 conflict`, carrying `current.created`, and
    /// erases nothing.
    ///
    /// A signer whose `200` was lost gets, on a retry, the `404` of an identity the service
    /// doesn't host, signed with the key it pinned and bound to the retry
    /// ([`ClientError::is_not_hosted`]); it takes that as the erasure done (Switch wire
    /// 7.4.16).
    ///
    /// # Errors
    ///
    /// As every call.
    pub async fn erase(
        &self,
        created: Option<u64>,
        identity_hash: Option<[u8; 32]>,
    ) -> Result<(), ClientError> {
        self.signer_only()?;
        let body = erase_body(created, identity_hash.as_ref());
        let checked = self
            .send_json("POST", "erase", body, TimeoutClass::Ordinary)
            .await?;
        let (value, what) = Self::json_answer(
            &checked,
            Doc::Plain,
            "Switch wire 7.4.16: an erasure answer",
        )?;
        if Obj::of(&value, what)?.bool("erased")? {
            Ok(())
        } else {
            Err(ClientError::InvalidResponse(
                "Switch wire 7.4.16: the answer doesn't confirm the erasure".into(),
            ))
        }
    }

    /// `PUT /v1/{id}/handover` (signer, Switch wire 7.4.17): store the hand-over for its
    /// target app.
    ///
    /// # Errors
    ///
    /// As every call.
    pub async fn put_handover(
        &self,
        stored: &StoredHandover,
    ) -> Result<HandoverStored, ClientError> {
        self.signer_only()?;
        let checked = self
            .send_json("PUT", "handover", stored.to_json()?, TimeoutClass::Bulk)
            .await?;
        let (value, what) = Self::json_answer(
            &checked,
            Doc::Plain,
            "Switch wire 7.4.17: a hand-over answer",
        )?;
        HandoverStored::read(Obj::of(&value, what)?)
    }

    /// `GET /v1/{id}/handover` (the target app, or the signer, Switch wire 7.4.17).
    ///
    /// # Errors
    ///
    /// As every call; `404` when none is held for the caller.
    pub async fn get_handover(&self) -> Result<StoredHandover, ClientError> {
        let checked = self.get("handover", TimeoutClass::Bulk).await?;
        let (value, what) =
            Self::json_answer(&checked, Doc::Plain, "Switch wire 7.4.17: a hand-over")?;
        StoredHandover::read(Obj::of(&value, what)?)
    }
}

/// The head of an own app's answer, which every one carries (Switch wire 7.1): an answer
/// without it isn't the service's, whatever it says.
fn own_head(checked: &CheckedResponse, what: &str) -> Result<SignedHead, ClientError> {
    checked.head.ok_or_else(|| {
        ClientError::InvalidResponse(format!(
            "Switch wire 7.1: {what} for an own app carries no Switch-Head"
        ))
    })
}
