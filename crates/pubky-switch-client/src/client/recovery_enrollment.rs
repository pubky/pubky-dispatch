//! The signer-authenticated recovery enrollment exchange (Switch account binding 3.3).

use pubky_switch_core::http::{ErrorCode, header};
use pubky_switch_core::records::recovery_enrollment::{
    MAX_RESPONSE_BYTES, RecoveryDisposition, RecoveryEnrollmentReceipt, RecoveryEnrollmentRequest,
    RecoveryExpiryTicket, RecoveryPreparation, recovery_commit_digest,
};
use pubky_switch_core::records::{AccountObservation, Enrollment, EnrollmentIntent, IdentityDoc};
use pubky_switch_core::sig::SignedDoc;

use super::{Auth, Body, SentRequest, SwitchClient, check_response, stale_timestamp_hint};
use crate::error::{ClientError, TransportError};
use crate::transport::TimeoutClass;

/// The checked answer to a pending recovery enrollment (Switch account binding 3.3).
#[derive(Clone, Debug, PartialEq)]
pub enum RecoveryEnrollmentAnswer {
    /// The service prepared the enrollment, or reserved its exact replacement on renewal.
    Preparation(RecoveryPreparation),
    /// The service accepted both the enrollment and the frozen signed identity document.
    Committed(RecoveryEnrollmentReceipt),
    /// A signed conflict bound to this commit. An expiry ticket alone cannot settle it.
    Disposition(RecoveryDisposition),
}

fn invalid() -> ClientError {
    ClientError::InvalidResponse("Switch account binding 3.3: recovery enrollment bindings".into())
}

impl SwitchClient {
    /// Send the exact saved prepare, commit or renewal packet with the original creation
    /// selected by `observation`. A timestamp retry changes only the request headers.
    ///
    /// # Errors
    ///
    /// The credentials, pinned service key, observation or signed packet do not agree;
    /// the exchange fails; or the response does not establish the indicated result.
    pub async fn recovery_enrollment(
        &self,
        observation: &AccountObservation,
        bytes: &[u8],
    ) -> Result<RecoveryEnrollmentAnswer, ClientError> {
        self.signer_only()?;
        self.forget_latest();
        let key = self.pinned_key().ok_or(ClientError::Unpinned)?;
        let observed = observation.body();
        if self.account != observed.identity
            || self.origin != observed.origin
            || key != observed.service_key
            || self.created.is_none()
            || self.created != observed.created
        {
            return Err(ClientError::Usage(
                "Switch account binding 3.3: the original account is required".into(),
            ));
        }
        let packet = RecoveryEnrollmentRequest::from_json(bytes)
            .map_err(|error| ClientError::Usage(error.to_string()))?;
        let raw_enrollment = match &packet {
            RecoveryEnrollmentRequest::Prepare { enrollment }
            | RecoveryEnrollmentRequest::Commit { enrollment, .. }
            | RecoveryEnrollmentRequest::Renew { enrollment, .. } => enrollment,
        };
        let enrollment = Enrollment::verify(raw_enrollment, &self.account, &self.origin)?;
        if !matches!(enrollment.body().intent, EnrollmentIntent::Existing { .. })
            || enrollment.body().intent != observation.enrollment_intent()?
        {
            return Err(ClientError::Usage(
                "Switch account binding 3.3: another enrollment selection".into(),
            ));
        }
        let action = Action::check(&packet, bytes, observation, &enrollment)?;
        let path = self.path("recovery/enrollment");
        let mut auth = Auth {
            timeout: TimeoutClass::Bulk,
            ..Auth::default()
        };
        loop {
            let signed = self.build("POST", &path, bytes.to_vec(), Body::Json, auth)?;
            let sent = SentRequest::of(&signed.request);
            let response = self.send_response(signed.request).await?;
            if response.body.len() > MAX_RESPONSE_BYTES {
                return Err(TransportError::TooLarge(MAX_RESPONSE_BYTES as u64).into());
            }
            let checked = check_response(&key, &self.account, &sent, &response);
            let head_expected = response.status == 200 && matches!(action, Action::Commit { .. });
            if matches!(checked, Ok(_) | Err(ClientError::Switch { .. }))
                && response.header(header::HEAD).is_some() != head_expected
            {
                return Err(invalid());
            }
            self.note_server_time(&sent, checked.as_ref(), &response);
            if auth.timestamp_ms.is_none()
                && let Some(time) = stale_timestamp_hint(checked.as_ref().err())
            {
                auth.timestamp_ms = Some(time);
                continue;
            }
            match checked {
                Ok(answer) if answer.status == 200 => {
                    return action.success(&answer, observation, &enrollment);
                }
                Ok(_) => return Err(invalid()),
                Err(
                    error @ ClientError::Switch {
                        code: ErrorCode::Conflict,
                        ..
                    },
                ) if matches!(action, Action::Commit { .. }) => {
                    let Some(found) =
                        RecoveryDisposition::from_error_body(&response.body, &key, &self.account)?
                    else {
                        return Err(error);
                    };
                    action.check_disposition(&found, &enrollment, bytes)?;
                    return Ok(RecoveryEnrollmentAnswer::Disposition(found));
                }
                Err(error) => return Err(error),
            }
        }
    }
}

/// The verified operands against which to check the returned preparation or receipt.
enum Action {
    Prepare,
    Commit {
        preparation: Box<RecoveryPreparation>,
        document: IdentityDoc,
        prior: Option<[u8; 32]>,
    },
    Renew(RecoveryExpiryTicket),
}

impl Action {
    fn check(
        packet: &RecoveryEnrollmentRequest,
        bytes: &[u8],
        observation: &AccountObservation,
        enrollment: &Enrollment,
    ) -> Result<Self, ClientError> {
        let observed = observation.body();
        let verify_doc = |raw: &SignedDoc| IdentityDoc::verify(raw, &observed.identity);
        let prior_hash = |raw: &Option<SignedDoc>| {
            raw.as_ref()
                .map(verify_doc)
                .transpose()
                .map(|doc| doc.map(|doc| doc.hash()))
        };
        match packet {
            RecoveryEnrollmentRequest::Prepare { .. } => Ok(Self::Prepare),
            RecoveryEnrollmentRequest::Commit {
                preparation,
                identity,
                prior,
                ..
            } => {
                let prep = RecoveryPreparation::verify(
                    preparation,
                    &observed.service_key,
                    &observed.identity,
                )?;
                let document = verify_doc(identity)?;
                let prior = prior_hash(prior)?;
                let binding = &prep.body().binding;
                if !prep.covers_existing(observation, enrollment)
                    || prep.body().replaces.is_some() && packet.to_json()? != bytes
                    || prior.is_some() && prior != prep.body().prior
                    || !binding.permits_document(&document)
                {
                    return Err(invalid());
                }
                Ok(Self::Commit {
                    preparation: Box::new(prep),
                    document,
                    prior,
                })
            }
            RecoveryEnrollmentRequest::Renew {
                ticket,
                identity,
                prior,
                ..
            } => {
                let ticket = RecoveryExpiryTicket::verify(
                    ticket,
                    &observed.service_key,
                    &observed.identity,
                )?;
                let terms = ticket.body();
                if !terms.binding.matches_observation(observation)
                    || terms.enrollment_terms != enrollment.hash()
                    || terms.document != verify_doc(identity)?.hash()
                    || terms.prior != prior_hash(prior)?
                {
                    return Err(invalid());
                }
                Ok(Self::Renew(ticket))
            }
        }
    }

    fn success(
        &self,
        answer: &super::CheckedResponse,
        observation: &AccountObservation,
        enrollment: &Enrollment,
    ) -> Result<RecoveryEnrollmentAnswer, ClientError> {
        let observed = observation.body();
        if let Self::Commit {
            preparation,
            document,
            ..
        } = self
        {
            return Ok(RecoveryEnrollmentAnswer::Committed(
                RecoveryEnrollmentReceipt::verify(
                    &answer.body,
                    enrollment,
                    preparation,
                    document,
                    answer.head.as_ref().ok_or_else(invalid)?,
                )?,
            ));
        }
        let prep = RecoveryPreparation::from_response(
            &answer.body,
            &observed.service_key,
            &observed.identity,
        )?;
        let replacement = match self {
            Self::Renew(ticket) => {
                if prep.body().binding != ticket.body().binding {
                    return Err(invalid());
                }
                Some(ticket.body().commit)
            }
            _ => None,
        };
        if !prep.covers_existing(observation, enrollment) || prep.body().replaces != replacement {
            return Err(invalid());
        }
        Ok(RecoveryEnrollmentAnswer::Preparation(prep))
    }

    fn check_disposition(
        &self,
        found: &RecoveryDisposition,
        enrollment: &Enrollment,
        bytes: &[u8],
    ) -> Result<(), ClientError> {
        let Self::Commit {
            preparation,
            document,
            prior,
        } = self
        else {
            return Err(invalid());
        };
        let digest = recovery_commit_digest(bytes);
        let matches = match found {
            RecoveryDisposition::Expired(ticket) => {
                let body = ticket.body();
                body.commit == digest
                    && body.document == document.hash()
                    && body.prior == *prior
                    && body.preparation == preparation.signed().doc_hash()?
                    && body.enrollment_terms == enrollment.hash()
                    && body.binding == preparation.body().binding
            }
            RecoveryDisposition::Renewed(prep) => {
                prep.body().replaces == Some(digest)
                    && prep.body().binding == preparation.body().binding
                    && prep.body().prior == preparation.body().prior
            }
        };
        if matches { Ok(()) } else { Err(invalid()) }
    }
}
