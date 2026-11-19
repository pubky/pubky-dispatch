//! The two service signatures and exact recovery commit (Switch account binding 3.3).

use pubky_switch_core::enc::{b64, pubky_id};
use pubky_switch_core::keys::IdentityKey;
use pubky_switch_core::labels::sig;
use pubky_switch_core::records::recovery_enrollment::*;
use pubky_switch_core::records::{
    AccountAssociation, Enrollment, EnrollmentIntent, IdentityDoc, Limits,
};
use pubky_switch_core::sig::SignedDoc;
use serde_json::json;

use super::{common::*, signatures::generated_case};

#[test]
fn test_vectors_recovery_enrollment() {
    let documents = load("documents.json");
    let original = |name| -> SignedDoc {
        let case = arr(&documents, "documents")
            .iter()
            .find(|c| st(c, "name") == name)
            .unwrap();
        serde_json::from_value(case["signed"].clone()).unwrap()
    };
    let keys = keys();
    let alice = keys.identity("alice");
    let identity = IdentityKey::from_secret(keys.identity_secrets[&alice]);
    let service_key = keys.service_key(&pubky_id(&alice));
    let signer = ed25519_dalek::SigningKey::from_bytes(&keys.secret(&service_key).unwrap());
    let origin = "https://inbox.example";
    let created = 1_767_225_600_000;
    let original_enrollment =
        Enrollment::verify(&original("alice enrollment"), &alice, origin).unwrap();
    let mut body = original_enrollment.body().clone();
    body.intent = EnrollmentIntent::Existing { created };
    let enrollment = Enrollment::sign(&identity, body).unwrap();
    let prior = IdentityDoc::verify(&original("alice identity.json"), &alice).unwrap();
    let mut next = prior.body().clone();
    next.generation += 1;
    next.version += 1;
    next.recovery_from = Some(prior.generation());
    let next = IdentityDoc::sign(&identity, next).unwrap();
    let binding = RecoveryBinding {
        origin: origin.into(),
        identity: alice,
        service_key,
        store_id: [7; 16],
        association: AccountAssociation::Account,
        created,
        erased_at: None,
        enrollment: enrollment.hash(),
        predecessor: [8; 32],
        generation_floor: prior.generation(),
        version_floor: prior.version(),
        result_created: created,
        limits: Limits::default(),
    };
    let first = RecoveryPreparation::sign(
        &signer,
        RecoveryPreparationBody {
            binding: binding.clone(),
            prior: Some(prior.hash()),
            issued_at: created + 1000,
            expires_at: created + 301000,
            replaces: None,
        },
    )
    .unwrap();
    let packet = |preparation: &RecoveryPreparation| {
        RecoveryEnrollmentRequest::Commit {
            enrollment: enrollment.signed().clone(),
            preparation: preparation.signed().clone(),
            identity: next.signed().clone(),
            prior: Some(prior.signed().clone()),
        }
        .to_json()
        .unwrap()
    };
    let old_commit = packet(&first);
    let digest = recovery_commit_digest(&old_commit);
    let ticket = RecoveryExpiryTicket::sign(
        &signer,
        RecoveryExpiryTicketBody {
            binding: binding.clone(),
            commit: digest,
            document: next.hash(),
            prior: Some(prior.hash()),
            preparation: first.signed().doc_hash().unwrap(),
            enrollment_terms: enrollment.hash(),
        },
    )
    .unwrap();
    let replacement = RecoveryPreparation::sign(
        &signer,
        RecoveryPreparationBody {
            binding,
            issued_at: created + 302000,
            expires_at: created + 602000,
            prior: Some(prior.hash()),
            replaces: Some(digest),
        },
    )
    .unwrap();
    let renewed = packet(&replacement);
    generated(
        "documents.json",
        &[(
            Place::Member("/recovery_enrollment"),
            json!({
                "enrollment":enrollment.signed(),"identity":next.signed(),"prior":prior.signed(),"preparation":first.signed(),"ticket":ticket.signed(),
                "replacement":replacement.signed(),"original_commit":b64(&old_commit),"replacement_commit":b64(&renewed),"replacement_commit_digest":b64(&recovery_commit_digest(&renewed))
            }),
        )],
    );
    for (label, signed) in [
        (sig::RECOVERY_PREPARATION, first.signed()),
        (sig::RECOVERY_EXPIRY, ticket.signed()),
    ] {
        generated_case(
            label,
            &["identity", "body"],
            &[&alice, &signed.body_bytes().unwrap()],
            &signed.sig_bytes().unwrap(),
        );
    }
}

#[test]
fn test_recovery_enrollment_limits_apply_to_exact_received_bytes() {
    let fixed = load("documents.json")["recovery_enrollment"].clone();
    let prepare = json!({"enrollment":fixed["enrollment"],"op":"prepare"});
    let mut raw = serde_json::to_vec(&prepare).unwrap();
    raw.resize(MAX_PREPARE_BYTES, b' ');
    assert!(matches!(
        RecoveryEnrollmentRequest::from_json(&raw),
        Ok(RecoveryEnrollmentRequest::Prepare { .. })
    ));
    raw.push(b' ');
    assert_eq!(
        RecoveryEnrollmentRequest::from_json(&raw)
            .unwrap_err()
            .status(),
        413
    );
    let old = crate::common::b64(fixed["original_commit"].as_str().unwrap());
    let parsed = RecoveryEnrollmentRequest::from_json(&old).unwrap();
    assert_eq!(parsed.to_json().unwrap(), old);
    let h = pubky_switch_core::http::body_cap("POST", "/v1/alice/recovery/enrollment");
    assert_eq!(h, Some(MAX_REQUEST_BYTES));
    for status in [200, 400, 401, 409, 413, 503] {
        assert_eq!(
            pubky_switch_core::http::response_body_cap(
                "POST",
                "/v1/alice/recovery/enrollment",
                status
            ),
            Some(MAX_RESPONSE_BYTES)
        );
    }
    let keys = keys();
    let id = keys.identity("alice");
    let key = keys.service_key(&pubky_id(&id));
    let mut carrier = serde_json::to_string(&fixed["preparation"]).unwrap();
    carrier.insert_str(1, &" ".repeat(MAX_EVIDENCE_BYTES - carrier.len()));
    let answer = |carrier: &str| format!("{{\"preparation\":{carrier}}}");
    RecoveryPreparation::from_response(answer(&carrier).as_bytes(), &key, &id).unwrap();
    carrier.insert(1, ' ');
    assert!(RecoveryPreparation::from_response(answer(&carrier).as_bytes(), &key, &id).is_err());
    let disposition = |member: &str, reason: &str| {
        serde_json::to_vec(&json!({"code":"conflict","message":"expired","current":{"recovery":reason,member:fixed[member]}})).unwrap()
    };
    assert!(matches!(
        RecoveryDisposition::from_error_body(&disposition("ticket", "expired"), &key, &id),
        Ok(Some(RecoveryDisposition::Expired(_)))
    ));
    let renewed=serde_json::to_vec(&json!({"code":"conflict","message":"renewed","current":{"recovery":"renewed","preparation":fixed["replacement"]}})).unwrap();
    assert!(matches!(
        RecoveryDisposition::from_error_body(&renewed, &key, &id),
        Ok(Some(RecoveryDisposition::Renewed(_)))
    ));
}

#[test]
fn test_recovery_enrollment_receipt_checks_the_document_and_response_head() {
    use pubky_switch_core::chain::{
        ChainTip, ItemType, ProofBody, ProofState, SignedHead, TransitionProof, ZERO_HASH,
        item_hash,
    };
    use pubky_switch_core::records::EnrollmentAnswer;
    let v = load("documents.json")["recovery_enrollment"].clone();
    let signed = |name: &str| -> SignedDoc { serde_json::from_value(v[name].clone()).unwrap() };
    let keys = keys();
    let alice = keys.identity("alice");
    let key = keys.service_key(&pubky_id(&alice));
    let signer = ed25519_dalek::SigningKey::from_bytes(&keys.secret(&key).unwrap());
    let prep = RecoveryPreparation::verify(&signed("preparation"), &key, &alice).unwrap();
    let binding = &prep.body().binding;
    let enrollment = Enrollment::verify(&signed("enrollment"), &alice, &binding.origin).unwrap();
    let doc = IdentityDoc::verify(&signed("identity"), &alice).unwrap();
    let initial = ChainTip {
        generation: doc.generation(),
        seq: 0,
        chain_hash: ZERO_HASH,
    };
    let (stub, tip) = initial
        .append(
            1,
            prep.body().issued_at,
            ItemType::Identity,
            item_hash(ItemType::Identity, &doc.signed().doc_bytes().unwrap()),
            None,
        )
        .unwrap();
    let proof = TransitionProof::sign(
        &signer,
        &alice,
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
    let head = SignedHead::sign(&signer, &alice, &tip);
    let receipt = RecoveryEnrollmentReceipt {
        enrollment: EnrollmentAnswer::new(&enrollment, key, binding.limits, binding.result_created),
        proof,
        head,
    };
    let bytes = receipt.to_json().unwrap();
    assert_eq!(
        RecoveryEnrollmentReceipt::verify(&bytes, &enrollment, &prep, &doc, &head).unwrap(),
        receipt
    );
    let earlier = SignedHead::sign(&signer, &alice, &initial);
    assert!(RecoveryEnrollmentReceipt::verify(&bytes, &enrollment, &prep, &doc, &earlier).is_err());
    let prior = IdentityDoc::verify(&signed("prior"), &alice).unwrap();
    assert!(RecoveryEnrollmentReceipt::verify(&bytes, &enrollment, &prep, &prior, &head).is_err());
}
