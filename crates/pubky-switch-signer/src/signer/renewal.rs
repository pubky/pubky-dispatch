//! Renewals and reductions (Switch spec 3.2, 12.2; Switch wire 3.5, 3.8).
//!
//! A renewal gives a listed app a new certificate with the same App ID, signing key and
//! bundle key, and a later `issued_at`; its scopes, switch permissions and expiry may change.
//! [`Signer::renew`] signs, sign once, and commits together:
//!
//! 1. the new certificate, stored with `cert.put` in the batch of the first part of a full key
//!    bundle made for it (Switch wire 3.8 step 1);
//! 2. when the new certificate lacks a scope with keys, the rotation to the next data epoch:
//!    the full bundle runs through it, and every other current app gets its bundle for it,
//!    holding its own scopes' keys (Switch wire 3.8 "A removed scope's keys rotate");
//! 3. the renewing `identity.json`, listing the new certificate's hash, the earlier one in
//!    `renewed` with `until: null`, and the raised `data_epoch` of a rotation (step 2).
//!
//! It sends the batches in order, recording the parts each stores once the switch took it, then
//! delivers and publishes the version.
//!
//! A rotation goes to the epoch after the newest version's `data_epoch`. When a rotation that was
//! given up had sent keys of a later epoch, that epoch is completed first, in a version of its
//! own: every current app holding each keyed scope gets its keys through it, the app whose
//! reduction was given up included, and the version raises `data_epoch` to it. So no app holds
//! the new epoch's keys early, and no epoch is skipped (Switch spec 3.2, 3.5).
//!
//! A scope no registered protocol owns may be removed, never kept, and removing one rotates. A
//! rotation gives an app whose certificate holds one no part, with [`Alert::RotationSkipped`]
//! (design note, decision 2).
//!
//! A renewal that removes a scope or a switch permission, or expires earlier, is a reduction.
//! It closes at once: the next version sets `until` of the app's open renewals to the service
//! time at which the switch took the renewing version, plus the clock tolerance. That closing
//! delivery comes before any other, also when a crash came between the two (Switch wire 3.8
//! "A closing delivery owed"). If the exact retry gives no proof, an authenticated account
//! read confirming the same document and generation can supply its last committed service
//! time. A cooperative renewal closes once the switch holds the app's record carrying the
//! new certificate ([`Signer::complete_renewals`]).
//!
//! The signer writes only `key_bundle.put` and `cert.put` (Switch spec 13.5).

use pubky_switch_client::ClientError;
use pubky_switch_client::client::answers::AppStatus;

use pubky_switch_core::ops::{KeyBundlePut, OpKind};
use pubky_switch_core::records::{
    AppCert, AppCertBody, AppRequest, Approval, ApprovalClaim, AuthRequest, BundlePart,
    CLOCK_TOLERANCE_MS, IdentityDoc, ListedApp, MAX_CERT_LIFETIME_MS, RenewedCert, StoredPart,
    incremental_first_epoch, is_reduction, owed_closings, seal_bundle_parts,
};
use pubky_switch_core::scopes::Permission;
use pubky_switch_core::sig::SignedDoc;

use super::Signer;
use crate::Counter;
use crate::alert::{Alert, RenewalSkip};
use crate::error::{RecordsFault, Refusal, Result, SignerError};
use crate::key::SigningKey;
use crate::protocol::Protocols;
use crate::state::{
    AskedRenewal, Bytes, DeliverStep, Flow, PendingClaim, RenewBatch, Service, SignerState,
};

/// The most signed operations in one batch (Switch wire 6.4).
const MAX_OPS: usize = 8;

/// What a renewal changes. What it leaves `None` stays as it is, but the expiry, which a
/// renewal always sets: by default, the certificate lifetime from now.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct CertChange {
    /// The new scopes; their switch permissions come from the registered protocols' tables.
    pub scopes: Option<Vec<String>>,
    /// The new expiry, in Unix milliseconds.
    pub expires_at: Option<u64>,
}

/// How many automatic renewals in a row no record of an app may leave untaken before the
/// signer stops renewing it by itself (Switch spec 3.1).
const RENEWALS_LEFT_UNTAKEN: usize = 2;

/// Who a renewal is for, which sets its expiry and what it does to the count of untaken
/// automatic renewals, committed with the renewing version itself (Switch spec 3.1).
#[derive(Clone, Copy)]
pub(super) enum RenewedBy {
    /// The user's renewal, or an approval's: the expiry is the change's, and the count starts
    /// again.
    User,
    /// An automatic renewal, keeping `lifetime` from its `issued_at`: one more in the count.
    Automatic {
        /// The lifetime the certificate has, its `expires_at` less its `issued_at`.
        lifetime: u64,
    },
}

impl Signer {
    /// Renew the certificate of the listed app `app_id` with `change` (Switch spec 3.2,
    /// Switch wire 3.8), then deliver and publish the renewing version. A reduction's
    /// closing version follows at once. Returns the renewing version.
    ///
    /// The new scopes must all be owned by registered protocols, so a scope none owns can be
    /// removed but never kept; removing one rotates, as its keys can't be judged (design
    /// note, decision 2).
    ///
    /// # Errors
    ///
    /// [`Refusal::NotListed`] for an app the newest `identity.json` doesn't list; the scope
    /// refusals of [`crate::Protocols::terms`] for new scopes; [`SignerError::InvalidData`]
    /// for an expiry the certificate rules refuse; otherwise as [`Signer::resume`].
    ///
    /// When the switch refuses the renewal for good, at a batch or at the delivery, the error
    /// is its refusal and [`Alert::RenewalRefused`] is raised with it: the renewal didn't
    /// happen, and for a reduction the access was not reduced. A later [`Signer::resume`] or
    /// [`Signer::run_due`] that meets the refusal, after this call was cut off, raises the same
    /// alert, so the host tells the user the same way whichever call met it (Switch spec 3.2).
    /// A rotating renewal first completes an epoch a given-up rotation sent keys for; when that
    /// completion is cut off, this renewal is never signed, no later call makes it, and the
    /// alert is raised with this call's error.
    pub async fn renew(&mut self, app_id: [u8; 16], change: CertChange) -> Result<IdentityDoc> {
        self.ready().await?;
        self.renew_listed(app_id, change, None, RenewedBy::User)
            .await
    }

    /// [`Signer::renew`], once the signer is ready: with `answering`, the renewal answers that
    /// app request, and its approval's companion claim is committed with the renewing version,
    /// released once the switch has taken it (Switch wire 3.9 step 5, 3.10). `by` sets the
    /// expiry and the count of untaken renewals, which change in the commit of the renewing
    /// version, so a renewal whose delivery or publication fails after it is counted all the
    /// same.
    pub(super) async fn renew_listed(
        &mut self,
        app_id: [u8; 16],
        change: CertChange,
        answering: Option<&Answering<'_>>,
        by: RenewedBy,
    ) -> Result<IdentityDoc> {
        // A revoked or departing app gets no new certificate, expiry or key (Switch spec 12.2).
        if self.cut_off(&app_id) {
            return Err(Refusal::CutOff.into());
        }
        let identity = self.state.identity;
        let newest = self.state.newest_doc()?.ok_or(Refusal::NotSetUp)?;
        let listed = newest.listed_cert(&app_id).ok_or(Refusal::NotListed)?;
        let old = self
            .held_certs()?
            .into_iter()
            .find(|cert| cert.hash() == listed)
            .ok_or(SignerError::Records(RecordsFault::Invariant(
                "the listed certificate isn't held",
            )))?;
        let scopes = change.scopes.unwrap_or_else(|| old.scopes().to_vec());
        let terms = self.env.protocols.terms(&scopes)?;
        let now = self.env.clock.now_ms();
        let issued = now.max(old.issued_at().saturating_add(1));
        let expires = match by {
            // The lifetime from the time it is issued at, exactly (Switch spec 3.1).
            RenewedBy::Automatic { lifetime } => issued.saturating_add(lifetime),
            RenewedBy::User => change
                .expires_at
                .unwrap_or_else(|| issued.saturating_add(self.state.cert_lifetime_ms)),
        }
        .min(issued.saturating_add(MAX_CERT_LIFETIME_MS));
        // The switch's view, read before anything is signed: this install still signs, the
        // app has joined, and the device clock the certificate is stamped with agrees with
        // the switch's time.
        let (statuses, switch_time) = self.switch_apps_at().await?;
        clock_agrees(now, switch_time)?;
        let joined = statuses
            .iter()
            .any(|s| s.app_id == app_id && s.record_cert.is_some());
        if !joined {
            return Err(Refusal::NotJoined.into());
        }

        let protocols = self.env.protocols.clone();
        let keyed = keyed(&protocols);
        let rotates = old
            .scopes()
            .iter()
            .any(|s| keyed(s) && !pubky_switch_core::scopes::holds(&scopes, s));
        let highest_spent_epoch =
            Counter::Epoch.next(newest.data_epoch(), Some(self.state.epoch_through), 0)?;
        self.state.next_version(newest.version())?;
        if rotates {
            Counter::Epoch.next(highest_spent_epoch, None, 1)?;
        }
        let key = self.signing_key()?;
        let new = AppCert::issue(
            &key,
            AppCertBody::new(
                identity,
                old.signing_key(),
                old.bundle_key(),
                scopes,
                &terms.permissions,
                issued,
                expires,
            ),
        )?;
        drop(key);
        // A rotation goes to the epoch after the newest version's. When a rotation that was
        // given up sent keys above that one, the epoch it sent is completed first, so no app
        // holds the new epoch's keys early and no epoch is skipped (Switch spec 3.2, 3.5).
        let (newest, statuses, switch_time) =
            if rotates && highest_spent_epoch > newest.data_epoch() {
                // The renewal is signed only once the completion is delivered: cut off there,
                // no later call makes it, so the user is told now (Switch spec 3.2).
                if let Err(error) = self
                    .rotate_through(&statuses, switch_time, highest_spent_epoch)
                    .await
                {
                    if matches!(by, RenewedBy::User) {
                        let mut state = self.state.clone();
                        let asked = AskedRenewal::between(app_id, &old, &new);
                        refused_in(&mut state, app_id, Some(asked));
                        self.commit(state, self.flow.clone()).await?;
                    }
                    return Err(error);
                }
                let newest = self.state.newest_doc()?.ok_or(Refusal::NotSetUp)?;
                if newest.listed_cert(&app_id) != Some(listed) {
                    return Err(Refusal::Superseded {
                        version: newest.version(),
                    }
                    .into());
                }
                let (statuses, switch_time) = self.switch_apps_at().await?;
                (newest, statuses, switch_time)
            } else {
                (newest, statuses, switch_time)
            };
        let current = newest.data_epoch();
        let last = if rotates {
            Counter::Epoch.next(current, None, 1)?
        } else {
            current
        };

        let key = self.signing_key()?;
        // The full bundle for the new certificate, the cert.put in its first batch.
        let mut ops = vec![(
            OpKind::CertPut {
                target_app_id: app_id,
                cert: new.signed().clone(),
            },
            None,
        )];
        let full = seal_bundle_parts(&key, &new, 1, last, &keyed)?;
        push_parts(&mut ops, app_id, new.hash(), full);
        // A rotation: every other current app's bundle through the new epoch.
        let mut alerts = Vec::new();
        if rotates {
            let (more, skipped) =
                self.catch_up(&key, &newest, &statuses, switch_time, &[app_id], last)?;
            ops.extend(more);
            alerts = skipped;
        }
        let batches = self.sign_batches(&key, newest.generation(), ops)?;
        let (doc, flow) = self.next_version(&key, |body| {
            if let Some(listed) = body.apps.iter_mut().find(|a| a.app_id == app_id) {
                listed.cert = new.hash();
            }
            body.renewed.push(RenewedCert {
                app_id,
                cert: old.hash(),
                until: None,
            });
            body.data_epoch = last;
        })?;
        let claim = answering
            .map(|answering| {
                let has_keys = |scope: &str| protocols.has_keys(scope);
                let approval =
                    Approval::issue(&key, answering.request, new.clone(), doc.clone(), &has_keys)?;
                let claim = ApprovalClaim::sign(&key, answering.auth, &approval)?;
                Ok::<_, SignerError>(PendingClaim {
                    request: answering.request.hash(),
                    app_id,
                    cert: new.hash(),
                    caps: answering.caps.to_owned(),
                    plaintext: claim.plaintext(),
                })
            })
            .transpose()?;
        drop(key);
        let mut state = self.state.clone();
        state.certs.push(new.signed().clone());
        if let Some(claim) = claim {
            state.claims.retain(|held| held.request != claim.request);
            state.claims.push(claim);
        }
        state.epoch_through = highest_spent_epoch.max(last);
        match by {
            RenewedBy::Automatic { .. } => state.untaken_renewals.push((app_id, new.hash())),
            RenewedBy::User => {
                renewals_taken_in(&mut state, &[app_id]);
                state.user_renewals.retain(|(app, _)| *app != app_id);
                state.user_renewals.push((app_id, new.hash()));
            }
        }
        self.commit_batches(state, &newest, &statuses, alerts, batches, &doc, flow)
            .await?;
        self.resume().await?;
        Ok(doc)
    }

    /// Bring every current app the newest version lists through epoch `through`, and deliver
    /// the version that raises `data_epoch` to it (Switch spec 3.5): an epoch's completion,
    /// or one more rotation after a removal at an epoch the removed apps may hold the keys of
    /// ([`Signer::remove_unheld`]).
    pub(super) async fn rotate_through(
        &mut self,
        statuses: &[AppStatus],
        switch_time: u64,
        through: u64,
    ) -> Result<()> {
        let newest = self.state.newest_doc()?.ok_or(Refusal::NotSetUp)?;
        let key = self.signing_key()?;
        self.state.next_version(newest.version())?;
        let (ops, alerts) = self.catch_up(&key, &newest, statuses, switch_time, &[], through)?;
        let batches = self.sign_batches(&key, newest.generation(), ops)?;
        let (doc, flow) = self.next_version_closing(&key, |body| body.data_epoch = through)?;
        drop(key);
        let mut state = self.state.clone();
        state.epoch_through = through;
        self.commit_batches(state, &newest, statuses, alerts, batches, &doc, flow)
            .await?;
        self.resume().await
    }

    /// The bundles that bring every current app the newest version lists, but `except`,
    /// through epoch `last`, each with its own scopes' keys for the epochs it lacks, and the
    /// alerts for the apps left out (Switch wire 3.5, 3.8).
    ///
    /// The signer's own records decide who is cut off, never the switch's status alone: an
    /// App ID that is a tombstone or has a revocation asked for gets no part, whatever the
    /// switch shows (Switch spec 12.2: a removed app reads nothing written later).
    ///
    /// An app the switch doesn't serve now, one not current, not joined or expired at
    /// `switch_time`, the switch's signed time of `statuses`, gets no
    /// part, nor does one whose certificate holds a scope no registered protocol owns, with
    /// [`Alert::RotationSkipped`]. Either gets the epochs it lacks from its next bundle, which
    /// starts after `keys_through`.
    pub(super) fn catch_up(
        &self,
        key: &SigningKey,
        newest: &IdentityDoc,
        statuses: &[AppStatus],
        switch_time: u64,
        except: &[[u8; 16]],
        last: u64,
    ) -> Result<(Vec<Op>, Vec<Alert>)> {
        let certs = self.held_certs()?;
        let now = switch_time;
        let keyed = keyed(&self.env.protocols);
        let mut ops = Vec::new();
        let mut alerts = Vec::new();
        for listed in &newest.body().apps {
            if except.contains(&listed.app_id) || self.cut_off(&listed.app_id) {
                continue;
            }
            let Some(status) = statuses.iter().find(|s| s.app_id == listed.app_id) else {
                continue;
            };
            let served = status.current
                && status.record_cert.is_some()
                && status.cert_expires_at.is_none_or(|at| at > now);
            if !served {
                continue;
            }
            let Some(cert) = certs.iter().find(|c| c.hash() == listed.cert) else {
                return Err(SignerError::Records(RecordsFault::Invariant(
                    "a listed certificate isn't held",
                )));
            };
            let unowned = self.env.protocols.unowned(cert.scopes());
            if !unowned.is_empty() {
                alerts.push(Alert::RotationSkipped {
                    app_id: listed.app_id,
                    scopes: unowned,
                });
                continue;
            }
            let (held, stored) = listed_bundle_ranges(&self.state.bundle_parts, listed, status);
            let first =
                incremental_first_epoch(held, &stored, status.full_bundle_requested.is_some());
            if first > last {
                continue;
            }
            let sealed = seal_bundle_parts(key, cert, first, last, &keyed)?;
            push_parts(&mut ops, listed.app_id, listed.cert, sealed);
        }
        Ok((ops, alerts))
    }

    /// Sign `ops` in batches at `generation`, each with the parts it stores.
    pub(super) fn sign_batches(
        &self,
        key: &SigningKey,
        generation: u64,
        ops: Vec<Op>,
    ) -> Result<Vec<RenewBatch>> {
        let client = self.signing_client(key)?;
        ops.chunks(MAX_OPS)
            .map(|chunk| {
                let entries = chunk
                    .iter()
                    .map(|(op, _)| (Vec::new(), op.clone()))
                    .collect();
                let batch = client.sign_batch(generation, entries, None)?;
                Ok(RenewBatch {
                    bytes: Bytes(batch.body().to_vec()),
                    parts: chunk.iter().filter_map(|(_, part)| *part).collect(),
                })
            })
            .collect()
    }

    /// Commit `state` with the flow that sends `batches` and then delivers `doc`, the
    /// version `flow` delivers, built on `newest`; `alerts` are added. Parts the switch no
    /// longer keeps go: those of apps `newest` doesn't list, and those made for the listed
    /// certificate that an app has passed, which the switch may drop (Switch wire 3.5,
    /// 7.4.12).
    #[allow(clippy::too_many_arguments)]
    pub(super) async fn commit_batches(
        &mut self,
        mut state: SignerState,
        newest: &IdentityDoc,
        statuses: &[AppStatus],
        alerts: Vec<Alert>,
        batches: Vec<RenewBatch>,
        doc: &IdentityDoc,
        flow: Flow,
    ) -> Result<()> {
        let Flow::Deliver { account, prev, .. } = flow else {
            return Err(SignerError::Records(RecordsFault::Invariant(
                "a version without its delivery",
            )));
        };
        state.signed_through = doc.version();
        for alert in alerts {
            state.alert(alert);
        }
        state.bundle_parts.retain(|held| {
            let Some(listed) = newest.listed_cert(&held.app_id) else {
                return false;
            };
            // A part made for another certificate stays until a part for the listed one
            // replaces it: the app skipped it, so `keys_through`, which counts the parts the
            // app's cursor passed, says nothing of the keys it holds (Switch wire 3.5).
            held.cert != listed
                || statuses
                    .iter()
                    .find(|s| s.app_id == held.app_id)
                    .and_then(|s| s.keys_through)
                    .is_none_or(|through| held.last_epoch > through)
        });
        let flow = Flow::Renew {
            account,
            batches,
            sent: 0,
            doc: doc.signed().clone(),
            prev,
        };
        self.commit(state, Some(flow)).await
    }

    /// The switch's apps, once its copy is confirmed as this install's mark, and the service
    /// time the answer is signed at.
    pub(super) async fn switch_apps_at(&mut self) -> Result<(Vec<AppStatus>, u64)> {
        let answer = self.read_apps().await?.answer;
        self.confirm_copy(answer.identity.as_ref()).await?;
        Ok((answer.apps, answer.server_time))
    }

    /// Send a renewal's or an epoch completion's batches from `sent` on, each with its signed
    /// bytes, recording the parts each stores once the switch took it, then go on to the
    /// version's delivery. Before each batch it sends, a resumed one included, it checks that
    /// this install still signs: the switch's copy is its mark, and no other install's backup
    /// took over (Switch spec 4.3, 12.8).
    pub(super) async fn send_renewal(
        &mut self,
        account: Service,
        batches: &[RenewBatch],
        sent: usize,
        doc: SignedDoc,
        prev: Option<[u8; 32]>,
    ) -> Result<()> {
        let client = self.account_client(&account)?;
        let document = crate::state::stored_identity(&doc, &self.state.identity)?;
        for (index, batch) in batches.iter().enumerate().skip(sent) {
            // Before each batch, not once: another install may take over between two.
            self.ensure_signer().await?;
            let signed = batch.read(&self.state.identity)?;
            for op in signed.ops() {
                if op.body().generation != document.generation() {
                    return Err(Refusal::CounterCopyNeeded {
                        counter: Counter::Generation,
                    }
                    .into());
                }
                if let OpKind::KeyBundlePut(put) = &op.body().kind
                    && put.last_epoch > document.data_epoch()
                {
                    return Err(Refusal::CounterCopyNeeded {
                        counter: Counter::Epoch,
                    }
                    .into());
                }
            }
            match client.submit(&signed).await {
                Ok(_) => {
                    // Each stored part replaces those whose range it overlaps (Switch wire
                    // 6.2 `key_bundle.put`).
                    let mut state = self.state.clone();
                    for part in &batch.parts {
                        state.bundle_parts.retain(|held| {
                            held.app_id != part.app_id
                                || held.last_epoch < part.first_epoch
                                || part.last_epoch < held.first_epoch
                        });
                        state.bundle_parts.push(*part);
                    }
                    let flow = Flow::Renew {
                        account: account.clone(),
                        batches: batches.to_vec(),
                        sent: index.saturating_add(1),
                        doc: doc.clone(),
                        prev,
                    };
                    self.commit(state, Some(flow)).await?;
                }
                Err(error @ ClientError::Switch { status, .. })
                    if (400..500).contains(&status) && status != 408 && status != 429 =>
                {
                    // A definite refusal: the flow ends, its version and its epochs stay
                    // spent, and the parts already stored stay recorded. A renewal it carried
                    // didn't happen, and the user is told in the same commit.
                    let mut state = self.state.clone();
                    self.note_refused_renewals(&mut state, &doc)?;
                    self.commit(state, None).await?;
                    return Err(error.into());
                }
                Err(error) => return Err(error.into()),
            }
        }
        let deliver = Flow::Deliver {
            account,
            doc,
            prev,
            backup: None,
            step: DeliverStep::Signed,
        };
        self.commit(self.state.clone(), Some(deliver)).await
    }

    /// Raise [`Alert::RenewalRefused`] in `state` for each app whose listed certificate `doc`,
    /// a version the switch refused for good, would have renewed (Switch spec 3.2): one that
    /// lists another certificate for it than the newest version does. A version that renews
    /// no app, such as a removal's or an epoch's completion, raises none.
    pub(super) fn note_refused_renewals(
        &self,
        state: &mut SignerState,
        doc: &SignedDoc,
    ) -> Result<()> {
        let refused = crate::state::stored_identity(doc, &state.identity)?;
        let Some(newest) = state.newest_doc()? else {
            return Ok(());
        };
        // The flow ends: no renewal the user asked for is in progress any more.
        let asked = std::mem::take(&mut state.user_renewals);
        let certs = self.held_certs()?;
        let held = |hash: [u8; 32]| certs.iter().find(|cert| cert.hash() == hash);
        for app in &refused.body().apps {
            let Some(listed) = newest.listed_cert(&app.app_id) else {
                continue;
            };
            // An app cut off meanwhile, revoked or to be, is told of by its removal.
            let cut_off = state.tombstones.contains(&app.app_id)
                || state.revoking.iter().any(|r| r.app_id == app.app_id);
            if listed == app.cert || cut_off {
                continue;
            }
            // What the user asked, judged from the two certificates; an automatic renewal's
            // asks nothing of the user's.
            let by_user = asked.contains(&(app.app_id, app.cert)).then(|| {
                match (held(listed), held(app.cert)) {
                    (Some(old), Some(new)) => AskedRenewal::between(app.app_id, old, new),
                    _ => AskedRenewal {
                        app_id: app.app_id,
                        remove: Vec::new(),
                        remove_permissions: Vec::new(),
                        expires_by: None,
                        add: Vec::new(),
                        add_permissions: Vec::new(),
                        expires_from: None,
                    },
                }
            });
            refused_in(state, app.app_id, by_user);
        }
        Ok(())
    }

    /// Whether the records cut `app_id` off: a tombstone, or a revocation asked for. Such an
    /// app gets no key bundle part (Switch spec 12.2).
    pub(super) fn cut_off(&self, app_id: &[u8; 16]) -> bool {
        self.state.tombstones.contains(app_id)
            || self.state.revoking.iter().any(|r| &r.app_id == app_id)
    }

    /// Every certificate the signer holds, verified.
    pub(super) fn held_certs(&self) -> Result<Vec<AppCert>> {
        let identity = self.state.identity;
        self.state
            .certs
            .iter()
            .map(|cert| AppCert::verify(cert, &identity).map_err(SignerError::StoredData))
            .collect::<std::result::Result<Vec<_>, _>>()
    }

    /// The apps whose closing delivery the signer owes: open renewals in the newest version
    /// that were reductions (Switch wire 3.8).
    pub(super) fn owed(&self) -> Result<Vec<[u8; 16]>> {
        match self.state.newest_doc()? {
            Some(doc) => self.owed_in(&doc),
            None => Ok(Vec::new()),
        }
    }

    /// The apps whose closing `doc` owes: its open renewals that were reductions.
    pub(super) fn owed_in(&self, doc: &IdentityDoc) -> Result<Vec<[u8; 16]>> {
        let certs = self.held_certs()?;
        Ok(owed_closings(doc, |hash| {
            certs.iter().find(|cert| &cert.hash() == hash)
        }))
    }

    /// Whether a closing delivery is owed and can be made now: the signing gate lets it
    /// through ([`super::gate::refusal`]).
    pub(super) fn owes_closing(&self) -> Result<bool> {
        Ok(super::gate::refusal(&self.state).is_none() && !self.owed()?.is_empty())
    }

    /// Queue the signed closure before another delivery (Switch wire 3.8). Prefer the
    /// renewing delivery's original proof. After its bounded exact retry, a verified
    /// account read of that same document can supply a conservative cutoff instead.
    /// The signing gate and all copy checks apply to either source.
    pub(super) async fn queue_owed_closing(&mut self) -> Result<bool> {
        // Nothing is signed while another install signs or the records are behind.
        if self.flow.is_some() || self.check_named().is_err() {
            return Ok(false);
        }
        let owed = self.owed()?;
        // The version that drops certificates this install doesn't hold comes first: no
        // backup of a closing that still names them can be sealed (Switch spec 12.8).
        let stalled = super::gate::refusal(&self.state).is_some() || self.unheld_references()?;
        let mut state = self.state.clone();
        state
            .alerts
            .retain(|a| !matches!(a, Alert::ReductionNotClosed { .. }) || !owed.is_empty());
        for alert in &mut state.alerts {
            if let Alert::ReductionNotClosed { apps } = alert {
                apps.clone_from(&owed);
            }
        }
        let mark = self.high_water()?;
        let awaiting_read = self
            .state
            .newest
            .as_ref()
            .is_some_and(|n| n.delivered_at.is_none())
            && mark.is_some_and(|m| self.state.time_asked == Some(m.version));
        if (stalled || awaiting_read) && !owed.is_empty() {
            state.alert(Alert::ReductionNotClosed { apps: owed.clone() });
        }
        if state.alerts != self.state.alerts {
            self.commit(state, None).await?;
        }
        if owed.is_empty() || stalled {
            return Ok(false);
        }
        let Some(newest) = self.state.newest.clone() else {
            return Ok(false);
        };
        if newest.delivered_at.is_none() && !awaiting_read {
            let mut state = self.state.clone();
            state.time_asked = mark.map(|m| m.version);
            let again = Flow::Deliver {
                account: self.newest_account()?,
                doc: newest.doc,
                prev: newest.prev,
                backup: None,
                step: DeliverStep::BackupWritten,
            };
            self.commit(state, Some(again)).await?;
            return Ok(true);
        }
        let read = self.check_copies().await?;
        if self.flow.is_some() || super::gate::refusal(&self.state).is_some() {
            return Ok(false);
        }
        let accepted = self.state.newest_doc()?.ok_or(Refusal::NotSetUp)?;
        if accepted.signed() != &newest.doc {
            return Err(Refusal::Superseded {
                version: accepted.version(),
            }
            .into());
        }
        let owed = self.owed_in(&accepted)?;
        if owed.is_empty() {
            return Ok(false);
        }
        let at = match newest.delivered_at {
            Some(original) => original,
            None => {
                let service = self.service()?;
                let target = self.service_target(&service);
                let account = self.newest_account()?;
                let time = read
                    .filter(|_| {
                        target.origin == account.origin
                            && target.created == Some(account.created)
                            && target.pinned == Some(account.service_key)
                    })
                    .and_then(|read| read.cutoff_for(&accepted));
                time.ok_or_else(|| {
                    SignerError::InvalidData(pubky_switch_core::Error::Invalid(
                        "Switch wire 3.8: the account read did not confirm the reducing document"
                            .into(),
                    ))
                })?
            }
        };
        let until = at.saturating_add(CLOCK_TOLERANCE_MS);
        let key = self.signing_key()?;
        let (doc, flow) = self.next_version_closing(&key, |body| {
            for app in &owed {
                body.close_renewals(app, until);
            }
        })?;
        drop(key);
        let mut state = self.state.clone();
        state.signed_through = doc.version();
        self.commit(state, Some(flow)).await?;
        Ok(true)
    }

    /// Close every cooperative renewal whose app the switch now holds a record of carrying
    /// the new certificate: `until` is the time the switch took that record plus the clock
    /// tolerance (Switch spec 3.2 step 4, Switch wire 3.8 step 4). Returns the apps closed.
    ///
    /// While no renewal is open, nothing is checked or read: it returns none, whatever the
    /// state, an erased account, another install named, records behind or a flow in
    /// progress included.
    ///
    /// # Errors
    ///
    /// With a renewal open, as [`Signer::resume`].
    pub async fn complete_renewals(&mut self) -> Result<Vec<[u8; 16]>> {
        // With no renewal open, nothing is read: the step is a no-op (design note, section
        // 4.5).
        self.refresh().await?;
        if self.open_renewals()?.is_empty() {
            return Ok(Vec::new());
        }
        let statuses = self.ready_at_switch().await?.answer.apps;
        let Some(doc) = self.state.newest_doc()? else {
            return Ok(Vec::new());
        };
        let open = self.open_renewals()?;
        let mut closing: Vec<([u8; 16], u64)> = Vec::new();
        for app in open {
            let status = statuses.iter().find(|s| s.app_id == app);
            let carries = status.is_some_and(|s| s.record_cert == doc.listed_cert(&app));
            if let (true, Some(at)) = (carries, status.and_then(|s| s.record_at))
                && !closing.iter().any(|(id, _)| *id == app)
            {
                closing.push((app, at.saturating_add(CLOCK_TOLERANCE_MS)));
            }
        }
        if closing.is_empty() {
            return Ok(Vec::new());
        }
        let key = self.signing_key()?;
        let (next, flow) = self.next_version_closing(&key, |body| {
            for (app, until) in &closing {
                body.close_renewals(app, *until);
            }
        })?;
        drop(key);
        let mut state = self.state.clone();
        state.signed_through = next.version();
        self.commit(state, Some(flow)).await?;
        self.resume().await?;
        Ok(closing.into_iter().map(|(app, _)| app).collect())
    }

    /// The apps whose cooperative renewal in the newest version is still open: not a
    /// reduction, which closes on its own, and not a cut-off app's, which goes with it.
    fn open_renewals(&self) -> Result<Vec<[u8; 16]>> {
        let Some(doc) = self.state.newest_doc()? else {
            return Ok(Vec::new());
        };
        let certs = self.held_certs()?;
        Ok(doc
            .body()
            .renewed
            .iter()
            .filter(|entry| entry.until.is_none())
            // A cut-off app's renewals go with it when it is removed.
            .filter(|entry| !self.cut_off(&entry.app_id))
            .filter(|entry| {
                // Reductions close on their own.
                let old = certs.iter().find(|c| c.hash() == entry.cert);
                let new = doc
                    .listed_cert(&entry.app_id)
                    .and_then(|h| certs.iter().find(|c| c.hash() == h));
                matches!((old, new), (Some(old), Some(new)) if !is_reduction(old, new))
            })
            .map(|entry| entry.app_id)
            .collect())
    }

    /// Run at startup and periodically. If [`RunDue::more_due`] is true, a limit left work
    /// for another run. Schedule it soon, for example in a minute.
    ///
    /// Resume pending work and deliver owed closings (Switch wire 3.8), then remove revoked
    /// or departed apps (Switch spec 12.2 and 12.3). Four later steps rotate. Close
    /// cooperative renewals whose apps took the new certificate, answer full-bundle requests
    /// (wire 3.5), [renew certificates past half their lifetime](Signer::renew_expiring), and
    /// repair a missing, older or unreadable Homeserver publication (wire 3.3).
    ///
    /// # Errors
    ///
    /// During hand-over or take-over, only [`Signer::resume`] runs after the store refresh.
    /// A run that completes erasure returns the resume result. If resume fails with a pending
    /// flow or any error other than a Homeserver error, try to send pending revocations and
    /// return the resume error. Otherwise, continue the routine steps within their limits.
    /// Store refresh and cursor-save errors return immediately. Otherwise return the first
    /// routine error, or the deferred Homeserver error if the routine steps succeeded.
    ///
    /// # Limits
    ///
    /// The whole run, including nested calls, shares four renewals, four full-bundle answers,
    /// 32 deletion checks and 32 record deletions. Ineligible apps leave room for others.
    /// Failed deletion checks, failed deletions and refused renewals move behind other work.
    /// The signer raises every owed grant reminder even when a deletion waits. It combines
    /// removals in one version and sends one `POST /revoke` per pending revocation, at most
    /// the number of listed apps. Separate calls to [`Signer::resume`],
    /// [`Signer::renew_expiring`] and [`Signer::serve_full_bundles`] each get a fresh budget.
    ///
    /// After 30 seconds on the device clock, or if it goes backwards, allow the first later
    /// step with work to run. Defer the rest once a later step has done work or failed.
    /// Continue next time from the first deferred step, or after the first failing later
    /// step if it supplied the first routine error. The host sets request timeouts.
    ///
    /// For example, an automatic renewal sends a certificate and its bundle parts in batches
    /// of up to eight operations. With one part each, four renewals send four `POST /ops`
    /// batches. Four completed renewals also make four deliveries and write four backups
    /// and four publications. Account and Homeserver reads add requests, as do other due
    /// steps (design note, section 4.5).
    pub async fn run_due(&mut self) -> Result<RunDue> {
        // One budget for the whole run, however its steps nest: a `resume` inside a step
        // spends from it too. The guard gives it back when the run ends or is dropped.
        self.left = RunDue::default();
        let _budget = self.budget();
        self.run_due_steps().await
    }

    /// The steps of [`Signer::run_due`], within its budget.
    async fn run_due_steps(&mut self) -> Result<RunDue> {
        let began = self.env.clock.now_ms();
        // While a hand-over or a take-over is in progress, only its own step runs: nothing
        // routine is signed, and what is owed stays owed (Switch wire 3.12).
        self.refresh().await?;
        if self.state.handing_over.is_some() || self.state.taking_over {
            self.resume().await?;
            return Ok(self.left);
        }
        // A publication that failed doesn't hold back the closings owed at the switch.
        let erased_before = self.state.erased;
        let resumed = self.resume().await;
        // The run that completes an erasure has nothing more to do (Switch spec 12.7).
        if self.state.erased && !erased_before {
            return resumed.map(|()| self.left);
        }
        if let Err(error) = &resumed
            && (self.flow.is_some() || !matches!(error, SignerError::Homeserver(_)))
        {
            // A pending revocation still goes to the switch: it signs nothing new, and
            // cutting the app off is the safe step. What it can't send stays pending.
            let _ = self.revoke_at_switch().await;
            return resumed.map(|()| self.left);
        }
        // One step's failure holds back no other: the steps after it run all the same, and the
        // first error is returned once they have.
        let mut failed = self.complete_removals().await.err();
        // The later steps start only within the run's time, and the next run does the rest,
        // from the step this one didn't start, or from the one after a step that failed, so
        // that one goes last. Past the run's time, a step that had nothing to do passes the
        // turn on, so one that has work always runs: a device clock that jumps, or goes back
        // and so can't be read as time spent, holds none of them back for good.
        let from = usize::from(self.state.due_from) % LATER.len();
        let mut next = 0;
        let mut worked = false;
        for n in 0..LATER.len() {
            let at = (from + n) % LATER.len();
            let now = self.env.clock.now_ms();
            let past = now < began || now - began >= super::RUN_DUE_STEPS_MS;
            if past && worked {
                self.left.steps_left = true;
                next = at;
                break;
            }
            let did = match LATER[at] {
                Later::Closings => self.complete_renewals().await.map(|done| !done.is_empty()),
                Later::FullBundles => self.serve_full_bundles().await.map(|done| !done.is_empty()),
                Later::Renewals => self.renew_expiring().await.map(|done| !done.is_empty()),
                Later::Publication => self.republish().await,
            };
            match did {
                Ok(did) => worked |= did,
                Err(error) => {
                    worked = true;
                    if failed.is_none() {
                        next = (at + 1) % LATER.len();
                        failed = Some(error);
                    }
                }
            }
        }
        if usize::from(self.state.due_from) != next {
            let mut state = self.state.clone();
            state.due_from = u8::try_from(next).unwrap_or(0);
            self.commit(state, self.flow.clone()).await?;
        }
        if let Some(error) = failed {
            return Err(error);
        }
        resumed.map(|()| self.left)
    }

    /// Renew the certificate of every current app once less than half its lifetime remains,
    /// each with the lifetime its certificate has, from now, in a renewing version of its own:
    /// a lifetime the user chose short stays short (Switch spec 3.1, 3.2; Switch wire 3.8,
    /// Appendix A, A28). Returns the apps renewed.
    ///
    /// - Current is spec 3.4's sense, whatever the certificate's expiry: the newest
    ///   `identity.json` lists the app, and it is neither revoked, being revoked, nor departed.
    ///   An app whose certificate has expired already is renewed too, which is how it comes
    ///   back: the switch takes the signer's renewal for it although its certificate has
    ///   expired (Switch wire 3.8 "An expired certificate"). One that hasn't joined is left:
    ///   the switch takes no `cert.put` for it yet (Switch wire 6.2).
    /// - An app with a renewal still open is renewed again, once: each renewal adds a
    ///   `renewed` entry, and a newer `cert.put` replaces the one the switch stores (Switch
    ///   wire 3.3, 3.8). After two automatic renewals in a row that no record of the app took
    ///   up, it isn't renewed again by itself, with [`Alert::RenewalsStopped`], and lapses at
    ///   its expiry. A renewal the user asks for, or a record carrying the newest certificate,
    ///   starts the count again (Switch spec 3.1).
    /// - Half the lifetime is judged on the switch's signed time, from its `GET /apps` answer.
    ///   The certificate is stamped with the device clock, so while that clock and the
    ///   switch's time differ by more than the clock tolerance, nothing is renewed by itself,
    ///   with [`Alert::ClockOff`] (Switch spec 10.1).
    /// - A renewal the user didn't ask for never changes what a certificate grants: an app
    ///   whose scopes a registered protocol no longer owns or a scope rule now refuses, or
    ///   which the protocols' tables now give other switch permissions, is skipped, with
    ///   [`Alert::RenewalSkipped`] naming why (design note, decision 2). A refusal that
    ///   concerns one app only doesn't hold back the others.
    /// - [`Alert::ClockOff`] clears itself at the first run that finds the clocks agreeing.
    /// - At most four are renewed in one call, the soonest to expire first, an app whose
    ///   renewal the switch refused, automatic or the user's, behind the others; the rest at
    ///   the next run, which half a lifetime leaves ample time for. Outside a run the call
    ///   has a budget of its own, which the steps each renewal runs again share
    ///   ([`Signer::run_due`]).
    ///
    /// # Errors
    ///
    /// As [`Signer::renew`]. A renewal the switch refuses for good holds back none of the
    /// others: the first refusal is returned once they are made. Any other failure of the
    /// switch, the Homeserver or the store stops the call; a renewal it cut short is finished
    /// by [`Signer::resume`], and the apps left are renewed at the next run.
    pub async fn renew_expiring(&mut self) -> Result<Vec<[u8; 16]>> {
        let _budget = self.budget();
        let read = self.ready_at_switch().await?;
        let (statuses, switch_time) = (read.answer.apps, read.answer.server_time);
        let newest = self.state.newest_doc()?.ok_or(Refusal::NotSetUp)?;
        // The device clock when the answer came, not after the reads since.
        if clock_agrees(read.device_ms, switch_time).is_err() {
            return self.skip_renewals(vec![Alert::ClockOff]).await;
        }
        // The clocks agree again: the alert has served.
        if self.state.alerts.contains(&Alert::ClockOff) {
            let mut state = self.state.clone();
            state.alerts.retain(|alert| *alert != Alert::ClockOff);
            self.commit(state, None).await?;
        }
        let certs = self.held_certs()?;
        let mut due = Vec::new();
        let mut skipped = Vec::new();
        // The apps a record shows back, which leave the count of untaken renewals.
        let mut taken = Vec::new();
        for listed in &newest.body().apps {
            let removed = statuses.iter().any(|s| {
                s.app_id == listed.app_id && (s.revoked_at.is_some() || s.departed_at.is_some())
            });
            let Some(cert) = certs.iter().find(|c| c.hash() == listed.cert) else {
                continue;
            };
            let carried = statuses
                .iter()
                .any(|s| s.app_id == listed.app_id && s.record_cert == Some(listed.cert));
            if carried {
                taken.push(listed.app_id);
            }
            // An app that hasn't joined can't be renewed yet (Switch wire 6.2), and one being
            // cut off goes: neither takes a place among the renewals a run makes.
            let joined = statuses
                .iter()
                .any(|s| s.app_id == listed.app_id && s.record_cert.is_some());
            if removed
                || !joined
                || self.cut_off(&listed.app_id)
                || !past_half_lifetime(cert, switch_time)
            {
                continue;
            }
            // Two automatic renewals in a row untaken: the app stays away, and the user
            // decides (Switch spec 3.1).
            if !carried && self.untaken_renewals(&listed.app_id) >= RENEWALS_LEFT_UNTAKEN {
                skipped.push(Alert::RenewalsStopped {
                    app_id: listed.app_id,
                    expires_at: cert.expires_at(),
                });
                continue;
            }
            // The certificate as it is: the same scopes, and the permissions it holds.
            let reason = match self.env.protocols.terms(cert.scopes()) {
                Err(SignerError::Refused(Refusal::UnknownScopes { scopes })) => {
                    Some(RenewalSkip::UnownedScopes { scopes })
                }
                Err(SignerError::Refused(Refusal::ProtocolRule { protocol, reason })) => {
                    Some(RenewalSkip::ScopesRefused {
                        protocol: Some(protocol),
                        reason,
                    })
                }
                Err(SignerError::Refused(Refusal::Scopes(reason))) => {
                    Some(RenewalSkip::ScopesRefused {
                        protocol: None,
                        reason,
                    })
                }
                Err(error) => return Err(error),
                Ok(terms) if terms.permissions != cert.permissions() => {
                    let names = |all: &[Permission]| all.iter().map(ToString::to_string).collect();
                    Some(RenewalSkip::PermissionsChanged {
                        held: names(cert.permissions()),
                        now: names(&terms.permissions),
                    })
                }
                Ok(_) => None,
            };
            match reason {
                Some(reason) => skipped.push(Alert::RenewalSkipped {
                    app_id: listed.app_id,
                    reason,
                }),
                // The lifetime it has, from now: a short one the user chose stays short.
                None => due.push((
                    listed.app_id,
                    cert.expires_at().saturating_sub(cert.issued_at()),
                    cert.expires_at(),
                )),
            }
        }
        self.renewals_taken(&taken).await?;
        // A stopped app that owns open or `unknown` attempts: they are its own until its
        // expiry, and orphaned then, so the user is told so beside the stop (Switch spec 3.2,
        // 10.2). In the same commit as the stops.
        let lapsing: Vec<([u8; 16], u64, u64)> = skipped
            .iter()
            .filter_map(|alert| match alert {
                Alert::RenewalsStopped { app_id, expires_at } => Some((
                    *app_id,
                    *expires_at,
                    super::revocation::open_attempts_of(&statuses, app_id),
                )),
                _ => None,
            })
            .collect();
        let mut state = self.state.clone();
        for alert in skipped {
            state.alert(alert);
        }
        lapsing_in(&mut state, &lapsing);
        if state != self.state {
            self.commit(state, None).await?;
        }
        // The soonest to expire first, as many as the run's budget renews: the rest are due at
        // the next. Only apps that can be renewed are due, and an app whose renewal the switch
        // refused, automatic or the user's own, goes behind the others, so none holds a place
        // for good.
        let refused = |app: &[u8; 16]| {
            self.state
                .alerts
                .iter()
                .any(|alert| matches!(alert, Alert::RenewalRefused { app_id, .. } if app_id == app))
        };
        due.sort_by_key(|(app_id, _, expires_at)| (refused(app_id), *expires_at));
        let allowed = self.allowance().renewals;
        if due.len() > allowed {
            self.left.renewals_left = true;
            due.truncate(allowed);
        }
        let tried = due.len();
        self.spend(|run| run.renewals = run.renewals.saturating_sub(tried));
        let mut renewed = Vec::new();
        let mut refused_now = None;
        for (app_id, lifetime, _) in due {
            self.ready().await?;
            let by = RenewedBy::Automatic { lifetime };
            match self
                .renew_listed(app_id, CertChange::default(), None, by)
                .await
            {
                Ok(_) => renewed.push(app_id),
                // At the size a delivery may carry: no renewal can be delivered, and the
                // near-limit alert tells the user (design note, section 11).
                Err(SignerError::Refused(Refusal::IdentityTooLarge { .. }))
                    if self.flow.is_none() =>
                {
                    break;
                }
                Err(SignerError::Refused(
                    Refusal::NotJoined
                    | Refusal::NotListed
                    | Refusal::CutOff
                    | Refusal::Superseded { .. }
                    | Refusal::Scopes { .. }
                    | Refusal::UnknownScopes { .. }
                    | Refusal::ProtocolRule { .. },
                )) if self.flow.is_none() => {}
                // The switch refused it for good, and its flow has ended with the alert: the
                // next app's renewal goes on, as a refusal for one app doesn't concern another,
                // and the first refusal is returned once the others are made.
                Err(
                    error @ SignerError::Switch(ClientError::Switch {
                        status: 400..=499, ..
                    }),
                ) if self.flow.is_none() => {
                    refused_now.get_or_insert(error);
                }
                Err(error) => return Err(error),
            }
        }
        match refused_now {
            Some(error) => Err(error),
            None => Ok(renewed),
        }
    }

    /// How many automatic renewals of `app_id` in a row no record has taken up.
    fn untaken_renewals(&self, app_id: &[u8; 16]) -> usize {
        self.state
            .untaken_renewals
            .iter()
            .filter(|(id, _)| id == app_id)
            .count()
    }

    /// The apps in `apps` are back: their count of untaken renewals starts again, and
    /// [`Alert::RenewalsStopped`] goes (Switch spec 3.1).
    async fn renewals_taken(&mut self, apps: &[[u8; 16]]) -> Result<()> {
        let mut state = self.state.clone();
        renewals_taken_in(&mut state, apps);
        if state != self.state {
            self.commit(state, self.flow.clone()).await?;
        }
        Ok(())
    }

    /// Raise `alerts` for renewals the signer leaves to the user; renews nothing.
    async fn skip_renewals(&mut self, alerts: Vec<Alert>) -> Result<Vec<[u8; 16]>> {
        let mut state = self.state.clone();
        for alert in alerts {
            state.alert(alert);
        }
        if state != self.state {
            self.commit(state, None).await?;
        }
        Ok(Vec::new())
    }
}

/// The count of untaken renewals of each app in `apps` starts again in `state`, and its
/// [`Alert::RenewalsStopped`] and [`Alert::LapsingWithOpenAttempts`] go: the app is back,
/// the user renewed it, or it is removed (Switch spec 3.1).
pub(super) fn renewals_taken_in(state: &mut SignerState, apps: &[[u8; 16]]) {
    state.untaken_renewals.retain(|(id, _)| !apps.contains(id));
    state.alerts.retain(|alert| {
        !matches!(alert, Alert::RenewalsStopped { app_id, .. }
            | Alert::LapsingWithOpenAttempts { app_id, .. } if apps.contains(app_id))
    });
}

/// Bring [`Alert::LapsingWithOpenAttempts`] in `state` up to date with `stopped`, each app
/// whose renewals stopped this run with its expiry and its count of attempts open or
/// `unknown`: a held warning keeps its place with the count and expiry brought up to date,
/// a new one goes last, and one for an app not stopped now, or with none, goes.
fn lapsing_in(state: &mut SignerState, stopped: &[([u8; 16], u64, u64)]) {
    for (app_id, expires_at, count) in stopped {
        let held = state.alerts.iter_mut().find_map(|alert| match alert {
            Alert::LapsingWithOpenAttempts {
                app_id: held,
                expires_at,
                open_attempts,
            } if held == app_id => Some((expires_at, open_attempts)),
            _ => None,
        });
        match held {
            Some((held_expiry, open_attempts)) => {
                *held_expiry = *expires_at;
                *open_attempts = *count;
            }
            None if *count > 0 => state.alert(Alert::LapsingWithOpenAttempts {
                app_id: *app_id,
                expires_at: *expires_at,
                open_attempts: *count,
            }),
            None => {}
        }
    }
    state.alerts.retain(|alert| match alert {
        Alert::LapsingWithOpenAttempts {
            app_id,
            open_attempts,
            ..
        } => *open_attempts > 0 && stopped.iter().any(|(id, _, _)| id == app_id),
        _ => true,
    });
}

/// Whether the device clock, `now`, agrees with the switch's signed time within the clock
/// tolerance (Switch spec 10.1): a certificate is stamped with the device clock.
pub(super) fn clock_agrees(now: u64, switch_time: u64) -> Result<()> {
    if now.abs_diff(switch_time) > CLOCK_TOLERANCE_MS {
        return Err(Refusal::ClockOff {
            device_ms: now,
            switch_ms: switch_time,
        }
        .into());
    }
    Ok(())
}

/// Whether less than half of `cert`'s lifetime remains at `now` (Switch spec 3.2).
fn past_half_lifetime(cert: &AppCert, now: u64) -> bool {
    let lifetime = cert.expires_at().saturating_sub(cert.issued_at());
    cert.expires_at().saturating_sub(now).saturating_mul(2) < lifetime
}

/// The app request a renewal answers (Switch wire 3.9 step 5): the request, the auth request
/// it travels with, and the capabilities the grant covers.
pub(super) struct Answering<'a> {
    pub(super) request: &'a AppRequest,
    pub(super) auth: &'a AuthRequest,
    pub(super) caps: &'a str,
}

/// A batch operation, with the key bundle part it stores, if any.
pub(super) type Op = (OpKind, Option<StoredPart>);

/// Match the signer's parts for the listed certificate with the ranges still at the
/// service. If it stored parts for another certificate of this app, the cursor cannot
/// say which keys the app holds (Switch wire 3.5, 7.4.12).
pub(super) fn listed_bundle_ranges(
    parts: &[StoredPart],
    listed: &ListedApp,
    status: &AppStatus,
) -> (Option<u64>, Vec<(u64, u64)>) {
    let mut held = status.keys_through;
    let mut stored = Vec::new();
    for part in parts.iter().filter(|part| part.app_id == listed.app_id) {
        if part.cert != listed.cert {
            held = None;
        } else if status
            .bundle_ranges
            .iter()
            .any(|r| r.first == part.first_epoch && r.last == part.last_epoch)
        {
            stored.push((part.first_epoch, part.last_epoch));
        }
    }
    (held, stored)
}

/// Whether a scope has keys, for a rotation: one no registered protocol owns counts as keyed,
/// so removing it rotates, as its keys can't be judged (design note, decision 2).
pub(super) fn keyed(protocols: &Protocols) -> impl Fn(&str) -> bool + '_ {
    |scope| protocols.has_keys(scope) || !protocols.knows_scope(scope)
}

/// Add `sealed`'s parts for `app_id`, made for the certificate `cert`, to the operations.
pub(super) fn push_parts(
    ops: &mut Vec<Op>,
    app_id: [u8; 16],
    cert: [u8; 32],
    sealed: Vec<BundlePart>,
) {
    for part in sealed {
        let stored = StoredPart {
            app_id,
            first_epoch: part.first_epoch,
            last_epoch: part.last_epoch,
            cert,
        };
        ops.push((
            OpKind::KeyBundlePut(KeyBundlePut {
                target_app_id: app_id,
                bundle: part.bundle,
                first_epoch: part.first_epoch,
                last_epoch: part.last_epoch,
            }),
            Some(stored),
        ));
    }
}

/// Raise [`Alert::RenewalRefused`] for `app_id` in `state`, or bring the one held up to date
/// in its place (Switch spec 3.2). `asked` is what the user asked of the renewal, `None` for an
/// automatic one. One alert per app, and the user's wins: an automatic renewal's refusal
/// leaves the user's alert and what they asked as they are, while a second renewal the user
/// asked for adds what it asks to the first's.
pub(super) fn refused_in(state: &mut SignerState, app_id: [u8; 16], asked: Option<AskedRenewal>) {
    keep_asked_with_alerts(state);
    let fresh = match asked {
        None if state.asked_renewals.iter().any(|a| a.app_id == app_id) => return,
        None => Alert::RenewalRefused {
            app_id,
            reduction: false,
            by_user: false,
        },
        Some(asked) => {
            let merged = match state.asked_renewals.iter_mut().find(|a| a.app_id == app_id) {
                Some(held) => {
                    held.merge(&asked);
                    held.clone()
                }
                None => {
                    state.asked_renewals.push(asked.clone());
                    asked
                }
            };
            Alert::RenewalRefused {
                app_id,
                reduction: merged.reduction(),
                by_user: true,
            }
        }
    };
    let held = state.alerts.iter_mut().find(
        |alert| matches!(alert, Alert::RenewalRefused { app_id: held, .. } if *held == app_id),
    );
    match held {
        Some(held) => *held = fresh,
        None => state.alert(fresh),
    }
}

/// Keep what the user asked only beside the alert it goes with: an alert cleared, by the user
/// or by its rule, takes it along (Switch spec 3.2).
pub(super) fn keep_asked_with_alerts(state: &mut SignerState) {
    let alerts = &state.alerts;
    state.asked_renewals.retain(|asked| {
        alerts.iter().any(|alert| {
            matches!(alert, Alert::RenewalRefused { app_id, by_user: true, .. }
                if *app_id == asked.app_id)
        })
    });
}

/// The steps of [`Signer::run_due`] after the removals, in their order: past the run's time,
/// one starts only while none before it in the run has had work.
#[derive(Clone, Copy)]
enum Later {
    Closings,
    FullBundles,
    Renewals,
    Publication,
}

/// [`Later`]'s steps in their order, a run starting from the one the last run didn't start.
const LATER: [Later; 4] = [
    Later::Closings,
    Later::FullBundles,
    Later::Renewals,
    Later::Publication,
];

/// What a [`Signer::run_due`] left for the next run because one of its bounds cut it short
/// (design note, section 4.5): a host that sees [`RunDue::more_due`] may run again soon
/// instead of waiting for its schedule, a minute later say, and not at once: a bound can cut
/// run after run short while what it holds back is blocked, such as a device clock that
/// jumps at every run, so `more_due` may stay true. Work owed for another reason, such as a
/// switch that can't be reached, isn't counted: the errors and alerts say that.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct RunDue {
    /// More certificates were due for renewal than one run renews.
    pub renewals_left: bool,
    /// More full-bundle requests were pending than one run answers.
    pub full_bundles_left: bool,
    /// More removed apps' records were owed, to check or to delete, than one run handles.
    pub deletions_left: bool,
    /// The run's time passed before all its later steps started.
    pub steps_left: bool,
}

impl RunDue {
    /// Whether any bound cut the run short.
    pub fn more_due(&self) -> bool {
        self.renewals_left || self.full_bundles_left || self.deletions_left || self.steps_left
    }
}
