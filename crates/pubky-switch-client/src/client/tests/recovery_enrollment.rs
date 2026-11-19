//! The paired signed results of a recovery enrollment.

use super::*;
use pubky_switch_core::records::recovery_enrollment::{
    RecoveryBinding, RecoveryDisposition, RecoveryEnrollmentReceipt, RecoveryEnrollmentRequest,
    RecoveryExpiryTicket, RecoveryExpiryTicketBody, RecoveryPreparation, RecoveryPreparationBody,
    recovery_commit_digest,
};

fn preparation(enrollment: &Enrollment, replaces: Option<[u8; 32]>) -> RecoveryPreparation {
    let observed = observation(Some(0));
    RecoveryPreparation::sign(
        &service_key(),
        RecoveryPreparationBody {
            binding: RecoveryBinding {
                origin: ORIGIN.into(),
                identity: observed.identity,
                service_key: service_public(),
                created: 0,
                result_created: 0,
                store_id: observed.store_id,
                erased_at: None,
                association: observed.association,
                predecessor: [6; 32],
                enrollment: enrollment.hash(),
                limits: Limits::default(),
                generation_floor: 1,
                version_floor: 2,
            },
            issued_at: NOW,
            expires_at: NOW + 300_000,
            replaces,
            prior: None,
        },
    )
    .unwrap()
}

fn document() -> IdentityDoc {
    let mut body = IdentityBody::first(
        identity().public(),
        [2; 16],
        Inbox::new(ORIGIN, service_public()),
        IdentityPolicy::default(),
    );
    body.version = 3;
    body.generation = 2;
    body.recovery_from = Some(1);
    IdentityDoc::sign(&identity(), body).unwrap()
}

fn commit(
    enrollment: &Enrollment,
    preparation: &RecoveryPreparation,
    doc: &IdentityDoc,
) -> Vec<u8> {
    RecoveryEnrollmentRequest::Commit {
        enrollment: enrollment.signed().clone(),
        preparation: preparation.signed().clone(),
        identity: doc.signed().clone(),
        prior: None,
    }
    .to_json()
    .unwrap()
}

fn receipt(enrollment: &Enrollment, doc: &IdentityDoc) -> RecoveryEnrollmentReceipt {
    let tip = ChainTip {
        generation: 2,
        seq: 0,
        chain_hash: [0; 32],
    };
    let (stub, tip) = tip
        .append(
            1,
            NOW,
            ItemType::Identity,
            item_hash(ItemType::Identity, &doc.signed().doc_bytes().unwrap()),
            None,
        )
        .unwrap();
    let proof = TransitionProof::sign(
        &service_key(),
        &identity().public(),
        ProofBody::new(
            stub,
            "identity".into(),
            &ProofState::Identity {
                version: doc.version(),
                generation: doc.generation(),
                data_epoch: doc.data_epoch(),
            },
        ),
    )
    .unwrap();
    RecoveryEnrollmentReceipt {
        enrollment: EnrollmentAnswer::new(enrollment, service_public(), Limits::default(), 0),
        proof,
        head: SignedHead::sign(&service_key(), &identity().public(), &tip),
    }
}

#[tokio::test]
async fn test_recovery_enrollment_preserves_the_document_through_renewal() {
    let enrollment = enrollment([3; 16]);
    let original = preparation(&enrollment, None);
    let doc = document();
    let body = commit(&enrollment, &original, &doc);
    let digest = recovery_commit_digest(&body);
    let response = receipt(&enrollment, &doc);
    let ticket = RecoveryExpiryTicket::sign(
        &service_key(),
        RecoveryExpiryTicketBody {
            binding: original.body().binding.clone(),
            commit: digest,
            document: doc.hash(),
            prior: None,
            preparation: original.signed().doc_hash().unwrap(),
            enrollment_terms: enrollment.hash(),
        },
    )
    .unwrap();
    let replacement = preparation(&enrollment, Some(digest));
    let prepare = RecoveryEnrollmentRequest::Prepare {
        enrollment: enrollment.signed().clone(),
    }
    .to_json()
    .unwrap();
    let renew = RecoveryEnrollmentRequest::Renew {
        ticket: ticket.signed().clone(),
        enrollment: enrollment.signed().clone(),
        identity: doc.signed().clone(),
        prior: None,
    }
    .to_json()
    .unwrap();
    let next = commit(&enrollment, &replacement, &doc);
    let transport = Arc::new(MockTransport::with_handler({
        let bodies = [prepare.clone(), body.clone(), renew.clone(), next.clone()];
        let answers = [
            json!({"preparation":original.signed()}).to_string().into_bytes(),
            json!({"code":"conflict","message":"expired","current":{"recovery":"expired","ticket":ticket.signed()}}).to_string().into_bytes(),
            json!({"preparation":replacement.signed()}).to_string().into_bytes(),
            response.to_json().unwrap(),
        ];
        let head = response.head.to_header();
        move |request| {
            if request.method == "GET" {
                return Ok(observation_reply(request, &observation(Some(0))));
            }
            assert_eq!(request.header(header::CREATED), Some(rfc3339(0).as_str()));
            let ix = bodies.iter().position(|b| *b == request.body).unwrap();
            Ok(respond_with_head(
                &service_key(),
                request,
                if ix == 1 { 409 } else { 200 },
                &answers[ix],
                (ix == 3).then_some(head.as_str()),
            ))
        }
    }));
    let client = client_with(signer_requests(), Some(service_public()), transport);
    let observed = client.observe_account().await.unwrap();
    for (packet, expected) in [
        (prepare, RecoveryEnrollmentAnswer::Preparation(original)),
        (
            body,
            RecoveryEnrollmentAnswer::Disposition(RecoveryDisposition::Expired(ticket)),
        ),
        (renew, RecoveryEnrollmentAnswer::Preparation(replacement)),
        (next, RecoveryEnrollmentAnswer::Committed(response)),
    ] {
        assert_eq!(
            client
                .recovery_enrollment(&observed, &packet)
                .await
                .unwrap(),
            expected
        );
    }
}

#[tokio::test]
async fn test_recovery_enrollment_requires_the_original_creation_and_headless_prepare() {
    let enrollment = enrollment([7; 16]);
    let original = preparation(&enrollment, None);
    let packet = RecoveryEnrollmentRequest::Prepare {
        enrollment: enrollment.signed().clone(),
    }
    .to_json()
    .unwrap();
    let head = receipt(&enrollment, &document()).head.to_header();
    let transport = Arc::new(MockTransport::with_handler(move |request| {
        if request.method == "GET" {
            return Ok(observation_reply(request, &observation(Some(0))));
        }
        Ok(respond_with_head(
            &service_key(),
            request,
            200,
            json!({"preparation":original.signed()})
                .to_string()
                .as_bytes(),
            Some(&head),
        ))
    }));
    let bound = client_with(signer(), Some(service_public()), transport.clone());
    let observed = bound.observe_account().await.unwrap();
    assert!(matches!(
        bound.recovery_enrollment(&observed, &packet).await,
        Err(ClientError::InvalidResponse(_))
    ));
    let other = unbound_signer(transport.clone(), Some(service_public()))
        .with_account_created(17)
        .unwrap();
    assert!(matches!(
        other.recovery_enrollment(&observed, &packet).await,
        Err(ClientError::Usage(_))
    ));
    assert_eq!(transport.requests().len(), 2);
}
