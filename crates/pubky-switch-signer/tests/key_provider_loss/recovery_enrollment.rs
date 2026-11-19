//! A key holder resumes the exact recovery at the provider selected by the survey.

use super::*;
use pubky_switch_client::client::SentRequest;
use pubky_switch_client::clock::{Clock, TestClock};
use pubky_switch_client::transport::{Header, MockTransport, Request, Response};
use pubky_switch_client::{ClientError, TransportError};
use pubky_switch_core::chain::{SignedHead, TransitionProof};
use pubky_switch_core::enc::b64;
use pubky_switch_core::http::{self, NoticeReason, RecoveryNotice, header};
use pubky_switch_core::keys::IdentityKey;
use pubky_switch_core::records::recovery_enrollment::{
    RecoveryBinding, RecoveryEnrollmentReceipt, RecoveryEnrollmentRequest, RecoveryExpiryTicket,
    RecoveryExpiryTicketBody, RecoveryPreparation, RecoveryPreparationBody, recovery_commit_digest,
};
use pubky_switch_core::records::{AccountObservationBody, Enrollment, EnrollmentAnswer, Limits};
use pubky_switch_core::sig::SignedDoc;
use pubky_switch_core::time::rfc3339;
use serde_json::json;

fn response(
    request: &Request,
    now: u64,
    status: u16,
    bytes: Vec<u8>,
    head: Option<&SignedHead>,
) -> Response {
    let time = rfc3339(now);
    let head = head.map(SignedHead::to_header);
    let sent = SentRequest::of(request);
    let key = IdentityKey::from_secret(SERVICE_SECRET);
    let sig = http::sign_response(
        &key,
        &http::ResponseParts {
            status,
            request: sent.received(true),
            server_time: &time,
            head: head.as_deref(),
            body: &bytes,
        },
    );
    let mut headers = vec![
        Header::new(header::SERVER_TIME, &time),
        Header::new(header::SERVICE_SIGNATURE, &b64(&sig)),
    ];
    if let Some(head) = head {
        headers.push(Header::new(header::HEAD, &head));
    }
    Response {
        status,
        headers,
        body: bytes,
    }
}

fn recovery_notice() -> serde_json::Value {
    RecoveryNotice {
        generation: 5,
        reason: NoticeReason::Behind,
        permanent: false,
    }
    .to_current()
}

fn prepare(
    account: &AccountObservationBody,
    enrollment: &SignedDoc,
    prior: [u8; 32],
) -> RecoveryPreparation {
    let created = account.created.unwrap();
    RecoveryPreparation::sign(
        &IdentityKey::from_secret(SERVICE_SECRET),
        RecoveryPreparationBody {
            binding: RecoveryBinding {
                origin: account.origin.clone(),
                identity: account.identity,
                service_key: account.service_key,
                store_id: account.store_id,
                association: account.association,
                created,
                erased_at: account.erased_at,
                enrollment: enrollment.doc_hash().unwrap(),
                predecessor: [9; 32],
                generation_floor: 5,
                version_floor: 50,
                result_created: created,
                limits: Limits::default(),
            },
            prior: Some(prior),
            issued_at: START_MS,
            expires_at: START_MS + 300_000,
            replaces: None,
        },
    )
    .unwrap()
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Interrupt {
    ReceiptLost,
    RenewalLost,
    Unknown,
    MissingFlow,
    Fenced,
}

impl Interrupt {
    fn unknown(self) -> bool {
        matches!(self, Self::Unknown | Self::MissingFlow | Self::Fenced)
    }
}

#[derive(Default)]
struct Provider {
    observed: Option<AccountObservationBody>,
    commit: Option<RecoveryEnrollmentRequest>,
    renewal: Option<Vec<u8>>,
    receipt: Option<(Vec<u8>, RecoveryEnrollmentReceipt)>,
    replacement: Option<SignedDoc>,
}

impl Provider {
    fn answer(
        &mut self,
        request: &Request,
        service: &ScriptedSwitch,
        recovered: &ScriptedSwitch,
        prior: [u8; 32],
        interrupt: Interrupt,
        clock: &TestClock,
    ) -> Result<Response, TransportError> {
        let send = |status, bytes, head| response(request, clock.now_ms(), status, bytes, head);
        if !request.path_and_query.ends_with("/recovery/enrollment") {
            let provider = if self.receipt.is_some() {
                recovered
            } else {
                service
            };
            let reply = provider.handle(request)?;
            if request.path_and_query.ends_with("/account") && reply.status == 200 {
                self.observed = Some(AccountObservationBody::from_json(&reply.body).unwrap());
            }
            return Ok(reply);
        }
        let account = self.observed.as_ref().unwrap();
        let created = account.created.unwrap();
        assert_eq!(
            request.header(header::CREATED),
            Some(rfc3339(created).as_str())
        );
        let packet = RecoveryEnrollmentRequest::from_json(&request.body).unwrap();
        let service_key = IdentityKey::from_secret(SERVICE_SECRET);
        match &packet {
            RecoveryEnrollmentRequest::Prepare { enrollment } => {
                let prep = prepare(account, enrollment, prior);
                Ok(send(
                    200,
                    json!({"preparation":prep.signed()})
                        .to_string()
                        .into_bytes(),
                    None,
                ))
            }
            RecoveryEnrollmentRequest::Commit {
                enrollment,
                preparation,
                identity,
                prior: proof,
            } => {
                assert_eq!(proof.as_ref().unwrap().doc_hash().unwrap(), prior);
                let doc = IdentityDoc::verify(identity, &account.identity).unwrap();
                assert_eq!(doc.generation(), 6);
                assert!(doc.version() > 50);
                let signed =
                    Enrollment::verify(enrollment, &account.identity, &account.origin).unwrap();
                let prep = RecoveryPreparation::verify(
                    preparation,
                    &account.service_key,
                    &account.identity,
                )
                .unwrap();
                if let Some(RecoveryEnrollmentRequest::Commit {
                    identity: original,
                    enrollment: old,
                    prior,
                    ..
                }) = &self.commit
                {
                    assert_eq!((identity, enrollment, proof), (original, old, prior));
                } else {
                    self.commit = Some(packet.clone());
                    if matches!(interrupt, Interrupt::RenewalLost | Interrupt::Fenced) {
                        // The original commit never reached the provider before the device stopped.
                        return Err(TransportError::Timeout);
                    }
                }
                if let Some(replacement) = &self.replacement
                    && prep.body().replaces.is_none()
                {
                    return Ok(send(
                        409,
                        json!({"code":"conflict","message":"renewed",
                        "current":{"recovery":"renewed","preparation":replacement}})
                        .to_string()
                        .into_bytes(),
                        None,
                    ));
                }
                if matches!(interrupt, Interrupt::Unknown | Interrupt::MissingFlow) {
                    return Ok(send(
                        503,
                        json!({"code":"unavailable","message":"unavailable","current":null})
                            .to_string()
                            .into_bytes(),
                        None,
                    ));
                }
                if matches!(interrupt, Interrupt::RenewalLost | Interrupt::Fenced)
                    && prep.body().replaces.is_none()
                {
                    assert!(clock.now_ms() > prep.body().expires_at);
                    let ticket = RecoveryExpiryTicket::sign(
                        &service_key,
                        RecoveryExpiryTicketBody {
                            binding: prep.body().binding.clone(),
                            commit: recovery_commit_digest(&request.body),
                            document: doc.hash(),
                            prior: Some(prior),
                            preparation: preparation.doc_hash().unwrap(),
                            enrollment_terms: signed.hash(),
                        },
                    )
                    .unwrap();
                    return Ok(send(409,json!({"code":"conflict","message":"expired","current":{"recovery":"expired","ticket":ticket.signed()}}).to_string().into_bytes(),None));
                }
                if let Some((exact, receipt)) = &self.receipt {
                    assert_eq!(&request.body, exact);
                    return Ok(send(200, receipt.to_json().unwrap(), Some(&receipt.head)));
                }
                let (proof, head) = recovered.deliver_identity_with_proof(&doc).unwrap();
                let receipt = RecoveryEnrollmentReceipt {
                    enrollment: EnrollmentAnswer::new(
                        &signed,
                        account.service_key,
                        Limits::default(),
                        created,
                    ),
                    proof: TransitionProof::verify(&proof, &account.service_key, &account.identity)
                        .unwrap(),
                    head,
                };
                let reply = send(200, receipt.to_json().unwrap(), Some(&receipt.head));
                self.receipt = Some((request.body.clone(), receipt));
                if interrupt == Interrupt::ReceiptLost {
                    Err(TransportError::Timeout)
                } else {
                    Ok(reply)
                }
            }
            RecoveryEnrollmentRequest::Renew {
                ticket,
                enrollment,
                identity,
                prior: proof,
            } => {
                let Some(RecoveryEnrollmentRequest::Commit {
                    enrollment: old,
                    identity: frozen,
                    prior: frozen_proof,
                    ..
                }) = &self.commit
                else {
                    panic!("a signed commit comes first")
                };
                assert_eq!((enrollment, identity, proof), (old, frozen, frozen_proof));
                let ticket =
                    RecoveryExpiryTicket::verify(ticket, &account.service_key, &account.identity)
                        .unwrap();
                let mut fresh = prepare(account, enrollment, prior).body().clone();
                fresh.replaces = Some(ticket.body().commit);
                fresh.issued_at = clock.now_ms();
                fresh.expires_at = fresh.issued_at + 300_000;
                let prep = RecoveryPreparation::sign(&service_key, fresh).unwrap();
                if let Some(exact) = &self.renewal {
                    assert_eq!(&request.body, exact);
                    Ok(send(
                        200,
                        json!({"preparation":prep.signed()})
                            .to_string()
                            .into_bytes(),
                        None,
                    ))
                } else {
                    self.replacement = Some(prep.signed().clone());
                    self.renewal = Some(request.body.clone());
                    Err(TransportError::Timeout)
                }
            }
        }
    }
}

async fn recover(interrupt: Interrupt) {
    let world = World::new();
    let (mut old, _) = world.enrolled().await;
    let revoked = if interrupt.unknown() {
        let (app, _) = joined(&world, &mut old, 78).await;
        let id = app.keys.app_id_bytes();
        old.revoke(id, None, confirmed()).await.unwrap();
        old.purge_removed(id).await.unwrap();
        Some(id)
    } else {
        None
    };
    let old_doc = old.identity_doc().unwrap().unwrap();
    let old_backup = world.homeserver.file(SIGNER_BACKUP_PATH).unwrap();
    drop(old);
    let memory = Arc::new(MemoryStore::new());
    let recovered =
        ScriptedSwitch::recovering(&world.key, SERVICE_SECRET, world.clock.clone(), 6, 5).unwrap();
    let transport = Arc::new(MockTransport::with_handler({
        let provider = Mutex::new(Provider::default());
        let service = world.switch.clone();
        let clock = world.clock.clone();
        let new_service = recovered.clone();
        move |request| {
            provider.lock().unwrap().answer(
                request,
                &service,
                &new_service,
                old_doc.hash(),
                interrupt,
                &clock,
            )
        }
    }));
    let mut env = world.env(memory.clone());
    env.transport = transport.clone();
    let shown = Signer::survey_provider_loss_with_key(env.clone(), world.keyring(), SWITCH_ORIGIN)
        .await
        .unwrap();
    world.switch.fail_next(SwitchFault::Error {
        path: "/enroll".into(),
        code: ErrorCode::RecoveryRequired,
        current: recovery_notice(),
    });
    let result = Signer::declare_provider_loss_with_key(
        env.clone(),
        world.keyring(),
        KeyRecoveryConfirmed::shown_and_confirmed(&shown, &[]),
    )
    .await;
    assert_eq!(
        world.homeserver.file(SIGNER_BACKUP_PATH).unwrap(),
        old_backup
    );
    if matches!(interrupt, Interrupt::RenewalLost | Interrupt::Fenced) {
        assert!(matches!(
            result,
            Err(SignerError::Switch(ClientError::Transport(
                TransportError::Timeout
            )))
        ));
        let ns = signer_namespace(&world.key.public());
        let initial = memory.get(&ns, b"flow").unwrap().unwrap();
        world.clock.advance_ms(300_001);
        let mut signer = Signer::open(env.clone(), world.keyring()).await.unwrap();
        assert!(matches!(
            signer.resume().await,
            Err(SignerError::Switch(ClientError::Transport(
                TransportError::Timeout
            )))
        ));
        drop(signer);
        assert_eq!(
            world.homeserver.file(SIGNER_BACKUP_PATH).unwrap(),
            old_backup
        );
        if interrupt == Interrupt::Fenced {
            // An earlier copy of the action still knows the original commit, but the
            // provider has already reserved the replacement whose response was lost.
            let mut batch = WriteBatch::new();
            batch.put(&ns, b"flow", initial).unwrap();
            memory.commit(batch).unwrap();
        }
    }
    if interrupt.unknown() {
        let mut held = Signer::open(env.clone(), world.keyring()).await.unwrap();
        if interrupt == Interrupt::Fenced {
            assert!(matches!(
                held.resume().await,
                Err(SignerError::Refused(Refusal::FlowInProgress))
            ));
            assert_eq!(
                held.status(),
                SignerStatus::RecoveryRefused {
                    origin: SWITCH_ORIGIN.into()
                }
            );
            let requests = transport.requests().len();
            assert!(held.resume().await.is_err());
            assert_eq!(transport.requests().len(), requests);
        } else {
            assert!(matches!(
                result,
                Err(SignerError::Switch(ClientError::Switch {
                    code: ErrorCode::Unavailable,
                    ..
                }))
            ));
        }
        assert!(matches!(
            held.declare_provider_loss(NEW_ORIGIN, confirmed()).await,
            Err(SignerError::Refused(Refusal::FlowInProgress))
        ));
        drop(held);
        // No remaining source shows the purged exclusion except the uncertain local records.
        remove_file(&world, SIGNER_BACKUP_PATH);
        remove_file(&world, IDENTITY_PATH);
        if interrupt == Interrupt::MissingFlow {
            let ns = signer_namespace(&world.key.public());
            let mut batch = WriteBatch::new();
            batch.delete(&ns, b"flow").unwrap();
            memory.commit(batch).unwrap();
            assert!(Signer::open(env.clone(), world.keyring()).await.is_err());
            assert!(
                Signer::declare_provider_loss_with_key(
                    env,
                    world.keyring(),
                    KeyRecoveryConfirmed::shown_and_confirmed(&shown, &[])
                )
                .await
                .is_err()
            );
        }
        let (new, router) = picked_service(&world);
        let shown = survey(&world, &memory, &router).await.unwrap();
        assert_eq!(shown.generation, 6);
        assert!(shown.version > 50);
        assert!(shown.revoked.contains(&revoked.unwrap()));
        let mut signer = Signer::declare_provider_loss_with_key(
            env_on(&world, &memory, &router),
            world.keyring(),
            KeyRecoveryConfirmed::shown_and_confirmed(&shown, &[]),
        )
        .await
        .unwrap();
        assert!(signer.identity_doc().unwrap().unwrap().version() > shown.version);
        assert!(new.kept_app_ids().contains(&revoked.unwrap()));
        signs_at(&world, &new, &mut signer, 6).await;
        return;
    }
    assert!(matches!(
        result,
        Err(SignerError::Switch(ClientError::Transport(
            TransportError::Timeout
        )))
    ));
    let mut signer = Signer::open(env, world.keyring()).await.unwrap();
    signer.resume().await.unwrap();
    let doc = signer.identity_doc().unwrap().unwrap();
    assert_eq!(doc.signed(), recovered.identity_doc().unwrap().signed());
    assert_eq!(doc.signed(), world.published().unwrap().signed());
    assert_ne!(
        world.homeserver.file(SIGNER_BACKUP_PATH).unwrap(),
        old_backup
    );
    assert!(
        transport
            .requests()
            .iter()
            .all(|request| !(request.method == "PUT"
                && request.path_and_query.ends_with("/identity")))
    );
    signer.set_record_max_age(Some(60)).await.unwrap();
}

#[tokio::test]
async fn test_key_recovery_enrollment_resumes_the_signed_commit_before_backup() {
    recover(Interrupt::ReceiptLost).await;
}

#[tokio::test]
async fn test_key_recovery_enrollment_replays_the_reserved_renewal_after_restart() {
    recover(Interrupt::RenewalLost).await;
}

#[tokio::test]
async fn test_key_recovery_enrollment_unknown_outcome_spends_its_version_and_generation() {
    recover(Interrupt::Unknown).await;
}

#[tokio::test]
async fn test_key_recovery_holds_a_fenced_commit_without_its_renewal_evidence() {
    recover(Interrupt::Fenced).await;
}

#[tokio::test]
async fn test_key_recovery_preserves_exclusions_and_signed_floors_when_the_flow_is_lost() {
    recover(Interrupt::MissingFlow).await;
}

#[tokio::test]
async fn test_exceptional_recovery_requires_a_verified_notice_and_the_backup_after_win_class() {
    for (have_own_store, code, current) in [
        (false, ErrorCode::Unavailable, serde_json::Value::Null),
        (false, ErrorCode::RecoveryRequired, serde_json::Value::Null),
        (true, ErrorCode::RecoveryRequired, recovery_notice()),
    ] {
        let world = World::new();
        let (old, own_store) = world.enrolled().await;
        let old_backup = world.homeserver.file(SIGNER_BACKUP_PATH).unwrap();
        let old_doc = old.identity_doc().unwrap().unwrap();
        drop(old);
        let store = if have_own_store {
            own_store
        } else {
            Arc::new(MemoryStore::new())
        };
        let env = world.env(store);
        let shown =
            Signer::survey_provider_loss_with_key(env.clone(), world.keyring(), SWITCH_ORIGIN)
                .await
                .unwrap();
        let before = world.transport.requests().len();
        world.switch.fail_next(SwitchFault::Error {
            path: "/enroll".into(),
            code,
            current,
        });
        let result = Signer::declare_provider_loss_with_key(
            env,
            world.keyring(),
            KeyRecoveryConfirmed::shown_and_confirmed(&shown, &[]),
        )
        .await;
        assert!(matches!(result, Err(SignerError::Switch(_))));
        assert!(world.transport.requests()[before..].iter().all(|request| {
            !request.path_and_query.ends_with("/recovery/enrollment") && request.method != "PUT"
        }));
        assert_eq!(
            world.homeserver.file(SIGNER_BACKUP_PATH).unwrap(),
            old_backup
        );
        assert_eq!(
            world.switch.identity_doc().unwrap().signed(),
            old_doc.signed()
        );
    }
}
