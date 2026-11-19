# App host guide

Embed `App` to act for one approved app of an identity. The signer approves the app and can later renew or revoke it. The client holds the app's keys, checks signed documents and service answers, follows the feed and saves work across restarts. The host supplies the user interface, storage, clock, network and the rules of each protocol. It chooses how to present events and which diagnostic details to show. For the other side of approval, see the [signer host guide](signer-host-guide.md).

## Joining an identity

- Supply an `AppEnv` with a `StoreHandle`, a millisecond Unix `Clock`, a `Transport` and a `HomeserverReader`. Return a missing file only for an actual absence. A timeout, denied read or malformed reply is a failure. For a publishing app, set `AppConfig::publishes_record` and supply a `HomeserverWriter`. Report success only once a put took effect or the deleted file is absent.
- Use a device-bound, encrypted `StateStore` excluded from system backups. Physically delete values. Apply each batch atomically and durably before returning success. Reads across handles must see complete commits in order. Scans return ascending byte keys after the exclusive start key. Support 16 MiB per value and 32 MiB per batch. Use a blocking store handle for slow storage when the runtime supports it.
- Serialize writers to the same app namespace across threads, extensions and processes. `App` uses ordinary store commits. The store also has an ownership API for callers that acquire a namespace. A memory store cannot preserve keys or unanswered writes across a restart.
- Have the signer approve the request for this app's keys. Verify the enclosing companion claim's signature before passing the approval bytes, original request, identity and keys in `JoinRequest`. `App::join` checks the approval against them, the certificate against the registered protocols, and saves the first app record and receive-key registration before sending. Keep the App ID. If a call failed after that save, use `App::load` and `receive` to resume. A second join on that store is refused.
- On startup, load the same App ID and protocols. Loading reads local state. Use `app_id`, `identity`, `own_identity`, `cert` and `record` for the app's current details. The app signs its own requests. The identity signing key stays with the signer.
- A protocol SDK taking ownership of a built `App` can check its registered protocol with `protocols()` and use the app's `clock()`, `homeserver_reader()` and `publishes_record()` so its reads and publication decisions use the same settings.

| Case | What happened and what to do |
|---|---|
| `Refusal::Approval` | Approval bytes failed a check against the request, keys or identity. Show the reason and return to the signer for a matching approval. |
| `Refusal::NotJoined` | There is no app metadata for this ID. Check the ID and store, then offer restore or join. |
| `Refusal::Certificate` | A registered protocol refused the app's own certificate during setup, load or restore. Show the protocol and its reason. Correct the registration or obtain suitable authority from the signer. |
| `IdentityRefresh::Newer` | The app took the newer verified Homeserver document. Its confirmation time is the start of the read. Check `identity_confirmation_age_ms` immediately before acting. |
| `IdentityRefresh::Current` | The Homeserver served the exact document the app holds. Its confirmation time is the start of the read. Check `identity_confirmation_age_ms` immediately before acting. |
| `IdentityRefresh::ClockMovedBack` | The device clock moved backwards during the read. The app took a newer verified document if `newer` is true and kept the same document otherwise. The current document awaits confirmation. Call `refresh_identity` again before an action that requires a current observation. |
| `IdentityRefresh::Older` | The homeserver served an older version. Keep the higher version and repeat the lookup later for confirmation. |
| `IdentityRefresh::Missing` | The homeserver has no own document. Check publication with the signer. This read gives no confirmation. |
| `IdentityRefresh::Unavailable` | The homeserver read failed in transport. Retry later. A failed document check instead raises an error. |
| `AppEvent::IdentityUpdated` | The client took a newer own identity document. Refresh the displayed membership and provider from it. |
| `AppEvent::RenewalSeen` | The feed supplied a candidate renewal of this app's certificate. Keep using the held certificate while waiting for the identity to list the new one. |
| `AppEvent::CertificateTaken` | The client committed a new certificate and its app record. Use the new permissions. A record delivery can still be pending. |
| `AppEvent::MemberDropped` | The record signed for a renewal the app took has no member of the named protocol: the member it gave for the renewal broke the JSON rules or came with an expiry that can't be signed, or its expiry ask without a member can no longer be signed, or the protocol isn't registered on this device and the renewal removed a scope or permission. That protocol writes its member again on a device that runs it. |
| `AppEvent::MemberChanged` | A duty event for the named protocol. The app took a record another device signed, and that protocol's member in it is new, changed or gone; a gone member takes its expiry ask. Write the member again if it is still wanted, then acknowledge. |
| `AppEvent::CertificateRefused` | A proposed certificate could not run with the registered protocols. Tell every owner, show the reason and retain the current certificate. Ask the signer for a compatible renewal. |
| `CertificateRefusal::UnownedRoot` | No registered protocol owns a scope root in the renewal. Correct the renewal or register the missing protocol at restore. |
| `CertificateRefusal::Protocol` | The named protocol rejected this certificate. Use its reason to request a corrected one. |

## Receiving and waking the app

Call `receive(None)` on startup and after a wake. Act on the report's events. Inspect `take_events()` after other calls, including failures. A report with `more` has bounded work left to do now, so read again. If `stopped` is set, act on the reason. Use `cursor` for the committed local position, `service_cursor` for the position last confirmed at the service, and `flush_cursor` to send a deferred move. A local cursor can advance before that send. `received_order` lets a protocol order inputs the client has handed it.

An event with an `id()` is a duty (`is_duty`). Save what it requires before acknowledging it. Delivery is at least once. Recover outstanding duties with `unacknowledged_events`. Use `pending_duty_events` for inspection without handing them over; each `PendingDuty` names the protocols that still owe its acknowledgement, in `owners`. Events without IDs are information from this run. They can be lost across a crash. An event ID can be stored with `to_bytes` and read with `from_bytes`. `EventIdError` means the encoded ID is invalid. Compare `counter()` values only within the same store epoch (`same_store`, `cmp_same_store`).

| Case | What happened and what to do |
|---|---|
| `AppEvent::MessageReceived` | The receive effect succeeded for this sender, kind and message ID. Show the resulting protocol state. Applying the effect again could repeat the action. |
| `AppEvent::MessageDropped` | The client skipped this copy after a recipient check failed. Use `check` and `reason` to explain why. If the read also reports `StoredEntryDropped`, handle that notice before acknowledging it. |
| `AppEvent::Duplicate` | The sender and message ID were already seen. Suppress the second effect. If the bytes differed, show a conflict. |
| `AppEvent::Held` | The client has temporarily left an entry on the feed because its sender could not yet be verified. Later entries can run. Read again later. |
| `AppEvent::StoreFailing` | The same receive step still fails. On the feed this is reported from the third consecutive retry. A retry of an already parked input can report it sooner. Show the storage failure and duration, repair or free the store and read again. The input remains pending. |
| `AppEvent::Parked` | The input was saved locally so the cursor can pass. Use its stable `stored_id` and the reason below. An ID for acknowledgement is present when automatic retry has stopped. |
| `AppEvent::Unparked` | A locally saved entry has finished or been removed during the stored-input pass. Refresh the stored-entry list. |
| `AppEvent::EffectRefused` | The saved input's proposed work cannot be applied in this form. Inspect the reason and optional code, then decide how to handle it in the protocol. The client will not send that effect again. |
| `AppEvent::EffectUncertain` | A saved effect's answer can no longer settle whether it ran. Check current records and every named attempt before deciding whether to release the input. Blind replay can repeat work. |
| `AppEvent::ReleasedDuplicate` | A released input's sender and ID had already been handled in the meantime. Its effect did not run again. Finish the release in the UI and flag differing bytes. |
| `AppEvent::StoredEntryDropped` | The client dropped a copy waiting for sender verification, a key or admission and saved the notice in the same commit. Keep the stable `notice_id`, sender, message identity and acceptance time. Use `waiting` to see what the copy needed and `reason` to decide on a resend. Acknowledge the current delivery ID. The receipt records the original observation. Verifying the signature again would require the lost bytes. Other copies and effects have their own outcomes. |
| `DropReason::Age` | A waiting input exceeded 21 days from acceptance by verified service time. Request another copy while the sender still has it. |
| `DropReason::PerSender` | One sender exceeded 64 waiting inputs. Its earliest accepted eligible copy was lost. Use the notice to identify it. |
| `DropReason::Total` | The shared pool exceeded 128 waiting inputs. It loses an earliest eligible copy from a sender with the most. Use the notice for that copy. |
| `DropReason::Rules` | On retry, the waiting copy failed the recipient check identified by `check`. For example, the current body rules may reject a value they used to allow. Record the failed check and ask for a resend only if the same signed bytes could now pass it. |
| `WaitingReason::Sender` | This lost copy was awaiting verification of its sender. Check the sender afresh for any resend. |
| `WaitingReason::Key` | The copy was waiting for a key for the named epoch. Check the signer's bundle for the key. Consult the drop reason before asking for another copy. |
| `WaitingReason::Admission` | The protocol had deferred this copy under its admission rule. If a waiting limit caused the drop, check whether the protocol can admit another copy before asking for one. |
| `ParkReason::Unverifiable` | Sender standing could not be checked within the feed wait. Keep reading. The local retry shares the waiting pool's limits. |
| `ParkReason::AwaitingAdmission` | The protocol deferred admission. Keep the input for a scheduled retry against current protocol state, within the shared limits. |
| `ParkReason::AwaitingKey` | A scope key is missing. The client waits for a change in the keys it holds and the required epoch's granted keys. Check the signer's bundle. The waiting pool can lose this copy. |
| `ParkReason::Quota` | The record work hit a service quota or size limit. Free capacity or adjust the record. A later stored-input pass can try it. |
| `ParkReason::StoreUnavailable` | The host store stayed unavailable through the feed wait. Restore service and read again for a local retry. |
| `ParkReason::StoreRejected` | The store failed on this particular input, such as a corrupt value. Repair it. The client retains the input and schedules further tries. |
| `ParkReason::Refused` | The effect received a lasting refusal. Handle the saved input explicitly. Its original effect has stopped. |
| `ParkReason::TooManyOperations` | The remote operations cannot fit one batch beside the cursor movement. Change the protocol's handling. No automatic retry. |
| `ParkReason::EffectTooLarge` | The effect or local changes exceed what a single save can hold. Reduce them before arranging replacement work. No automatic retry. |
| `ParkReason::TooManyReads` | The callback requested more than four distinct claim reads or requested no new claim. Correct the callback and handle the saved input. No automatic retry. |
| `ParkReason::LifecycleOperation` | The protocol proposed a registration, certificate, key bundle or app-record operation reserved to the client. Correct the effect. No automatic retry. |
| `ParkReason::Uncertain` | An earlier effect might already have run. Keep the payload as evidence. Release it only after establishing that the earlier effect did not run. |
| `ParkReason::Released` | The host released an uncertain entry using its ID and hash. A later read tries it with the released flag set. Inspect the result. |
| `AppEvent::Unopenable` | The entry targeted a receive key this device lacks. It passed unopened. Check `resend_asked` to see whether the protocol took a resend request. |
| `AppEvent::Unreadable` | An entry was left unread after its target apps departed. A resend is requested only within the allowed time range and with verified departure evidence. Check `resend_asked`. |
| `ResendReason::Unopenable` | The resend callback names the sender and acceptance interval for an input this app could not open. Queue the protocol's request for that interval. |
| `ResendReason::Unreadable` | The callback asks on behalf of a departed target. Ask that sender for the indicated interval. |
| `AppEvent::Missed` | Tell the user unread inbox entries were lost. The event includes the count. The client owes a collection listing and calls the protocol about the gap when the acceptance times allow it. Rebuild from records and available senders. |
| `AppEvent::OwedCallHeld` | Repeated reads are stalled before further handoff by a required callback or its lookup. Check `owed_protocol_calls`, repair storage or connectivity, then read again. |

Use `parked_entries` to list saved inputs and `parked_entry` to inspect one. A waiting input stays readable when the protocol's body rules change. The client uses the signed common fields to load, inspect, back up and restore it, and to identify it in a drop notice. The next retry checks the current rules. Check `sender_verified` before showing the sender as verified.

`release_parked` takes the ID and original plaintext hash of an uncertain input. `forget_parked` can discard multiple stored copies for the same sender and message in one call. It checks the supplied hash and refuses while an unanswered effect or an unacknowledged duty protects a copy. Show which copies can be lost before deletion. `forget_processed` lets the owning protocol remove an eligible duplicate marker together with its local writes, so the next copy can run again.

### Implementing the receive step

The client verifies the envelope and signed message, recipient, sender standing, scopes and duplicate status as applicable. The owning protocol supplies its kind, scope and body checks. Build changes in `ReceiveContext` so discarded or repeated callback runs have no external side effects. Use `local_get` and `local_scan` for protocol state, `record_at` and `claim_view` for held views, and `holds_scope_key` before staging a sealed write. The context also exposes the certificate, identity, record and claim conditions, sender disposition, and `highest_service_time`. A current record may postdate the input. It can stage record puts/deletes, claim entries, operations, local writes and eligible duplicate-marker removals.

| Case | What happened and what to do |
|---|---|
| `Outcome::Apply` | Return the effect to commit. The client coordinates its remote batch with the input's completion and local changes. On a conflict the callback may run again with new information. |
| `Outcome::Drop` | The protocol rejects the message itself. Give a reason without content. The entry passes with a duplicate marker. |
| `Outcome::Pass` | Discard staged changes and let a feed copy pass without a marker. Only a resend brings that feed copy back. A locally stored input stays for a later pass. |
| `Outcome::Consume` | Commit only eligible local writes and marker removals. The input goes away without a new marker, so a resend can reach the callback again. Oversized local work is parked. |
| `Outcome::Retry` | A host or storage failure prevented a decision. Return `StoreFailure::unavailable` for a temporary failure or `of_entry` for a particular bad entry. The client discards staged changes and retains the input for retry. Inspect `StoreFailure::error` and `is_of_entry` for the cause. |
| `Outcome::Need` | Discard this run's staged changes and ask the client to read missing facts. Expect a fresh callback with those facts, subject to the read limit. |
| `Need::Claim` | Ask for this claim key once. Inspect `switch_claim` on the next callback. A transient lookup failure leaves the input waiting. |
| `ClaimFetch::Read` | A checked claim view was fetched. Use the supplied view and entries. |
| `ClaimFetch::Absent` | The service answered that it holds no claim at this key. Handle absence under the protocol's rules. |
| `ClaimFetch::Refused` | The service gave a lasting refusal for this read. Handle the code without asking for the same read again. |
| `Outcome::AwaitAdmission` | The protocol's ordinary storage rule cannot admit the input yet. Staged changes are discarded. The client keeps either the waiting payload or its drop notice before passing it. |
| `Outcome::AwaitKey` | The step needs a scope key at this epoch. The client discards staged changes. Obtain the missing key and read again. The waiting copy can reach a shared limit or fail a recipient check on retry. |

### Waiting and push notifications

Use `feed_wait(seconds)` and its `wait()` between reads. The handle makes no change to the app, even when cancelled. Use `WaitPace::after_wait` with the requested seconds and elapsed time. Use `after_failed_read` for a retryable read failure. The host supplies the timer.

| Case | What happened and what to do |
|---|---|
| `Woken::Ready` | The page has an item or more pages. Read now to verify and handle them. |
| `Woken::Quiet` | The wait returned an empty page with no read due. Take another wait handle, respecting the pace after a short wait. |
| `Woken::ReadNow` | A real read is due, or the wait failed, saw a freeze or could not interpret the answer. Call `receive(None)` once with the prescribed pacing. |
| `Woken::ReadLater` | No wait was sent. The last read stopped, needs keys, or the app is halted or gone. Address that condition and use the pause before another read. |
| `AppEvent::PushRegistered` | The service accepted the push handles. The count is available for diagnostics. |
| `AppEvent::PushRemoved` | The old service registration no longer applies or the app ceased to be current. Register again when current and push is wanted. |
| `Peeked::Show` | Read-only `peek` checked this message using available state. Show content according to the user's notification settings. The main app still has to receive it. |
| `Peeked::Generic` | The peek could not safely show the contents. Show only a generic notification. If `PeekReport::more` is set, use one generic notification for the unchecked remainder. |

Supply a `PushRelay` for `register_push`, `rotate_push_key` and `reregister_push`. Bind the device token to the service's public push key at the relay. Read `push_registration` and `push_handles`, and exchange `take_device_push_handles` through the app's own device sync. A push is a wake-up. Use the feed to decide what happened.

## Looking up a recipient and sending

Use `identity_of` for the newest checked peer document available. For an action on a peer's public app data, use `begin_identity_lookup` to allow a short wait for the service. Keep polling its switch future while the user decides and pass the answer to `finish_identity_lookup`. Re-evaluate `PeerIdentity::may_act` before acting. `forget_directory` clears cached directory information. `recipients_for` selects eligible recipient apps for the message.

| Case | What happened and what to do |
|---|---|
| `HomeserverCopy::Read` | The lookup read the homeserver document. Check the service's status too. `PeerIdentity::read_at_ms` records when a source supplied the selected version. A version seen only in a directory answer has no read time and `fresh_until_ms` returns zero. A pending lookup's grace runs from `switch_lookup_ms`. |
| `HomeserverCopy::Unavailable` | The file was absent or the lookup failed. A previously held or service copy can still exist. Use its actual read time. |
| `HomeserverCopy::Held` | The lookup reused a recent copy and recent switch lookup. Consult the saved switch outcome. |
| `SwitchCopy::Read` | The lookup obtained a switch copy. Use the selected document under the version floor and the freshness decision. |
| `SwitchCopy::Unavailable` | The switch copy could not be obtained. Ask `may_act` before relying on public app data. |
| `SwitchCopy::Stale` | The pinned switch signed a response outside the accepted time window. Check `may_act` on the held document before acting. Automatic actions wait for a fresh lookup. |
| `SwitchCopy::Pending` | The switch half has yet to finish. Run it on the host executor and deliver the result. |
| `Initiator::User` | Use for a user-started action where the user can explicitly confirm proceeding. |
| `Initiator::Automatic` | Use for an unattended action. It needs service confirmation. |
| `MayAct::Now` | The lookup is fresh and the service confirmed its copy. The action may proceed. |
| `MayAct::WaitUntil` | The pending lookup is still within the grace interval. Wait until it answers or the given device time and check again. |
| `MayAct::IfUserConfirms` | The user's fresh lookup lacks service confirmation after failure or expiry of the grace interval. Explain that the peer's apps could not be confirmed, obtain explicit consent and record the decision before acting. |
| `MayAct::WaitForLookup` | A pending lookup must finish. This also applies to a stale copy after the grace interval, even for a user action. |
| `MayAct::No` | An automatic lookup failed to obtain service confirmation. Skip the action. A fresh lookup can be tried. |
| `MayAct::LookUpAgain` | The copy or its last switch lookup is too old. Refresh it before acting. If it comes again straight after a refresh, no source confirmed the copy the app holds (each was unavailable or served an older one): treat the copy as not confirmed and do not retry in a tight loop. |
| `AppEvent::PeerEquivocation` | Two bodies signed by this peer's identity have the same version. Show the identity and version. Suspend actions for that peer while the conflict remains. |

`send` queues an `OutgoingMessage` then tries its jobs. Use `queue` to defer delivery or `sign_message` and `queue_signed` for a newly signed message. Set `OutgoingMessage::record` or call `SignedMessage::with_record` when a record write must follow acceptance. Use `msg_id` to track the signed message. Use `queue_stored` for previously signed plaintext belonging to this app. It checks the replay deadline and give-up markers. `queue_signed` skips those checks. Keep a given message ID through retries.

Call `flush_message` for one message or `flush_outbox` for a bounded pass. Continue when its report says `more`. `delivery` gives current status or no retained entry. `sent_to` lists retained plaintexts and their acceptance times. `accepted_times_ms` includes the first and subsequent acceptances. `resend` uses the same signed plaintext with current recipient keys. The client can confirm inbox acceptance. Only the recipient's protocol can establish that someone read or acted on the message.

| Case | What happened and what to do |
|---|---|
| `DeliveryOrigin::Original` | The client has retained the original intent. Use this in the owning protocol's `may_send` check. The separate `resend` flag says whether a copy was accepted before. |
| `DeliveryOrigin::Reconstructed` | The copy came from signed plaintext without a retained original intent. Apply the protocol's rules for reconstructed sends. |
| `Delivery::Queued` | A pending resend also reads as queued. If the matching entry in the owning protocol's `queued_messages` has `resend: true`, the inbox accepted this message before. The client reads a queued copy by its signed common fields, so it can still send a body that newer rules would reject. Check the tries, last error, host holds and the owning protocol's `may_send` decision. Flush the existing copy when it can go out. |
| `Delivery::Kept` | A saved, unanswered batch owns this delivery. Follow its batch ID. It enters the outbox when the batch settles successfully. |
| `Delivery::Accepted` | The inbox accepted the message at the reported time. Show delivery. A failed later resend can still leave this original acceptance visible. |
| `Delivery::Failed` | A lasting refusal or a discarded carrying batch ended this delivery. Show the reason and time while the failure is retained. Stop flushing it. The refusal answers only the last try: if the app also told `AppEvent::DeliveryUnknown`, an earlier try may have been accepted. |
| `UndeliverableReason::NotAdmitted` | The recipient's inbox has not admitted this sender. Ask for an invite or admission and let the queued copy retry. |
| `UndeliverableReason::NotCurrent` | The sender's own certificate was refused as no longer current. Check membership and renewal with the signer before retry. |
| `AppEvent::MessageAccepted` | A checked append answer supplied the recipient's acceptance time. Update the status for this message ID. |
| `AppEvent::UnreachableApp` | One eligible recipient app lacks a usable receive-key record. Other eligible apps can still receive. Show which app is unreachable if delivery matters on that device. |
| `AppEvent::MessageUndelivered` | The app gave up or withdrew delivery. With `resend: false`, no request carrying the message can have reached the recipient's switch, from this app or a copy of its store: the recipient never had it, and the protocol may send a replacement. Causes include repeated admission/current-certificate refusals before any envelope was sent, delivery writes that exceed the store's size limits, or a withdrawal; a re-send also past its replay deadline. For a first send the plaintext is gone. With `resend: true`, only a re-send ended, and the earlier inbox acceptance still stands. `OutboxReport::undelivered` lists the messages a flush gave up so. Tell the owning protocol before acknowledging. |
| `AppEvent::DeliveryUnknown` | The app gave up delivery, or the message was refused for good, and the app can't know whether the recipient got it. An earlier try may have reached the switch with its answer lost, or the device a backup came from may have delivered it: a restored or left-out outbox message, a `queue_stored` copy, or an acceptance a restore in place dropped. A message the app sent once and that was then refused is reported here too. Treat the message as possibly delivered: never send a replacement the recipient would act on twice. Learn the outcome from the counterparty's reply or receipt, the shared records and claims it would change, or by asking the counterparty. The app reports nothing more about it, and `queue_stored` refuses it. `OutboxReport::unknown` lists the messages a flush ended so; they are never in `undelivered`. A backup carries the event until it is acknowledged. Tell the owning protocol before acknowledging. |
| `AppEvent::ResendAfterLoss` | A peer lost its old service. The client queued retained eligible messages accepted since its previous check. Flush the reported work with the original IDs. |
| `AppEvent::RecordJobDropped` | The post-acceptance record job remained unfinished through its retention window. The client stopped building it. Check the optional kept batch ID before repairing the record. Delivery itself already succeeded. |
| `AppEvent::RecordJobStopped` | The post-acceptance record job met a delete of its record that it was not queued against, so it stopped: writing would have replaced a delete the protocol has not seen. A job whose earlier try is known to have applied is done and raises no stop event. The event names the record key and the delete's generation, version and operation item hash. A recovery upload of the same operation at the same record version can have a new feed position and the job can still write over it. The stopping try wrote nothing. If the outbox kept a batch ID for an earlier uncertain try, `batch_id` names it and `App::kept_batch` shows its retained status. An older backup can lack any record of a write made before the delete. The protocol that owns the collection reads the record and decides again. The message kind's owner also receives the duty. If the owners differ, each acknowledges the same event ID independently with `ack_event_with` or `ack_events_for`. Delivery itself already succeeded. |
| `Refusal::WontDeliver` | The client declined a stored copy, or a resend was already given up. Nothing new was queued. Use the detailed reason below. |
| `WontDeliver::PastReplayWindow` | The signed creation time plus 30 days, less clock tolerance, has passed by the later of device and verified service time. Stop. A recipient may have forgotten its duplicate marker. |
| `WontDeliver::GivenUp` | This store remembers giving up delivery. Preserve that decision. No further undelivered notice is needed for this refusal. |
| `WontDeliver::TooLarge` | The reconstructed outbox item cannot fit the store. Show that it could not be queued. Repeating those bytes cannot help. |

For admission or current-certificate refusals, the client gives up after five qualifying answers spread across at least 30 days (at least 7.5 days between counted tries). Once 45 days have passed since the first such answer, the next flush that reaches the message gives up without another delivery try. A held message can still reach a deadline. Only a new user intent should become a new message.

## Writing records and claims

A collection declares its policy. Use `Collection::new` or `with_sub_scopes`, and `sub_scope` for a particular member. Build a `RecordTarget` from the collection and natural key. `record_key` derives the private lookup key. Read locally with `shared_record`, `records_of`, `record_seen` and `flagged_writes`. Use `read_record_fresh` when a decision depends on whether the service actually confirmed the copy. `read_record` can return what the client kept. `list_collection` and `list_collections` populate the local view in pages. Check `listing_owed` and continue unfinished listings. After recovery uploads, an older page leaves the listing at the same continuation. A fresh lookup for an outstanding upload returns `KeptReason::Refused` if the service observation cannot establish its current state.

| Case | What happened and what to do |
|---|---|
| `PolicyFamily::Fixed` | Only the collection's declared policy is a member. Use that policy for its records. |
| `PolicyFamily::SubScopes` | The collection admits the declared family of policies with sub-scopes. Derive and check the member with the collection's methods before reading or writing. |
| `PolicyFamily::PermanentGenerations` | `Collection::with_permanent_generations` reads permanent records naming a positive generation and carrying exactly the declared read and write scopes. For a record key or write, use `Collection::new` with its concrete generation policy. |
| `RecordRead::Fresh` | A read verified the service's current write as the one held. Use its content and flags. |
| `RecordRead::Kept` | The lookup did not replace or confirm the held copy as current. Show the reason and the optional local record. |
| `KeptReason::NotFound` | The current service reports no record here at a signed head covering the app's observations of this key. Preserve any earlier trusted value and show its age. |
| `KeptReason::Refused` | The client could not establish the current value or absence. An earlier hosted absence can leave a newer write held. Inspect the flags and trusted content before acting. |
| `KeptReason::Older` | The service showed an older write than the held one, or one not shown newer, as the record's current write. With both versions authenticated it would be a rollback alarm instead. The held copy remains available. When `SharedRecord::different_write_at_held_version` is true, the next write would build on a different signed operation at that version. A protocol that needs the contents of the current write can wait for an accepted successor. An unauthenticated `write.version` is the service's claim of the record now, as after a recovery upload. |
| `KeptReason::Overtaken` | The answer was current at `current_at`, before the held write, so it says nothing of the record now. Continue with the held copy. |
| `KeptReason::SwitchRefused` | The service gave the indicated lasting refusal to the read. Address its cause before another lookup. |
| `KeptReason::Unreachable` | No usable fresh answer was available. Show any held record as cached and retry the read later. |
| `RecordContent::Value` | The value opened. Interpret the JSON bytes under the protocol's rules. |
| `PutBack::Observe` | Save the collection owner's local observation in the deletion transaction. The service cursor may continue. |
| `PutBack::Prepare` | Save the owner's observation and retain the signed deletion while another authorized writer publishes the required value. A verified feed observation ahead of the service cursor holds the cursor before its deletion. |
| `PutBack::Write` | Save the local observation and publish the supplied JSON over the exact original deletion after a covering read. |
| `PutBackSuccessor::Merge` | Publish the complete combined JSON over the authenticated live application. Include all members the collection must preserve. |
| `PutBackSuccessor::Wait` | Keep waiting for the collection's required value. A newer version alone does not settle the deletion. |
| `PutBackSuccessor::Covered` | The owner verified that this applied value covers the deletion. Release that deletion's hold. |
| `AppEvent::PutBackWaits` | The collection is waiting at this record key, delete version and signed item hash. Keep any preparation in the owner's local state and acknowledge the notice. |
| `AppEvent::PutBackRefused` | Publication ended because this app lost its write scope, left, or learned of provider loss. Show the reason and keep any separate local restrictions. |
| `RecordContent::Deleted` | The accepted record contains a deletion. Remove the value from the active view and retain its version. |
| `RecordContent::Unreadable` | A write exists but its value is unavailable. Show the reason and keep the version distinct from deletion. |
| `Unopened::KeyNotHeld` | The client lacks the key for this epoch. It can reopen the value if a bundle brings the key. The certificate might never grant it. |
| `Unopened::DoesNotOpen` | Opening failed with the key available. Inspect the flagged write. This value is not scheduled to open again. |
| `Unopened::Refused` | The protocol's check refused the first write the client read of this record, so nothing of it is trusted. The record reads as flagged; the next write builds on that write's version. |
| `AppEvent::RecordChanged` | A record the client tracks changed. Read its current local version before updating the screen. |
| `AppEvent::WriteNotTaken` | A service-supplied date or writer certificate did not establish a trustworthy change. The client follows the shown version for its next write while preserving trusted content. Show the record's `not_taken` state without blaming a writer. |
| `AppEvent::RecordShownOlder` | The client kept its held copy because the write shown as current was older or could not be shown newer. Read the shared record to see whether the next write would build on a different signed operation at that version. Treat an unauthenticated `write.version` as the service's claim of the record now, as after a recovery upload. |
| `AppEvent::WriteFlagged` | A write failed a check, including possible regression against previously seen data. Inspect the rule and named writer in `flagged_writes`. Do not act on the rejected content. |
| `AppEvent::RecordUncheckable` | The protocol's `record_seen` mark exceeded 64 KiB. Future writes cannot be checked against this mark. An earlier mark is kept for another writer's change and cleared for an own write. Show the affected record/version and reduce the mark size. |
| `AppEvent::RecordDivergent` | Uploaded copies conflicted with a record after provider loss. Re-read its current `divergent` flag before asking the user to resolve it. A later write may already have cleared it and a restore may report the same conflict under another ID. |
| `AppEvent::ListingWaitsForKey` | A required collection listing lacks its current scope key. The affected protocol waits, while another with a complete listing can receive. Obtain the key bundle and read again. |
| `AppEvent::ReopeningOwed` | A key arrived but reopening held records failed. Keep them marked unreadable, address the reported problem and read again. The client retains the work. |

Implement `Protocol::mark_ends_at_delete` for an ordinary collection whose next creation starts with a new seen mark. The client checks a proposed deletion against the previous mark and gives the observer its predecessor. A verified current deletion clears the mark when its record commits. If the app is waiting for a read after a recovery upload, an earlier view of the deletion keeps the mark until the app observes the record through that upload. An unreadable live record keeps its mark through restart and key recovery. Implement `Protocol::record_lifetime_ended` to clear or update the collection owner's local data for the verified key and deletion version in the same store commit. The callback also runs when a later read first covers the deletion, including when no native mark was present. The same deletion can be observed again, so bind each change to the record lifetime it ends.

The client persists the signed conditional operation before its first send. A replacement can move the feed cursor through its own deletion atomically. A retry uses the original signed operation and ID. If a competing writer publishes, check the applied value separately. An earlier submission can still have an unknown outcome. A backup or exclusive store handoff carries the outstanding operations.

The collection owner can implement `Protocol::record_put_back` to save what it saw when another app deleted a record. Identify the deletion by record key, version and signed item hash. `writer` identifies the signing app. `exact_value` contains the readable, authenticated predecessor when the delete builds on that write. The owner's earlier `seen` mark can contain different bytes. `page_time_ms` is available for a deletion seen on a verified feed page. Return `PutBack::Observe` with up to 4 MiB of owner-local writes, or `None` to pass. An unanswered observation is retried with its saved evidence before later work reaches that owner. `PutBack::Prepare` keeps the obligation through restart and backup. When the owner is unavailable the service cursor waits before a feed deletion until the owner decides. A prepared deletion from a record view protects the service cursor when its authenticated feed entry arrives ahead of that cursor. Another installation using the same App ID must share the authoritative store or complete a synchronized handoff before advancing its cursor (Switch spec 3.1).

Implement `Protocol::record_put_back_successor` to check a readable later write against the original evidence. Return `PutBackSuccessor::Wait` on incomplete evidence. Return `PutBackSuccessor::Covered` when the applied value contains everything required. The ordinary `record_regression` check can use `WriteBase::repair` when two signed writes in the original generation name their exact predecessors. Its `prior_value` is the complete value the delete built on and its `held_value` is the complete value of the write over that delete. The owner receives this evidence first in `RecordSuccessor::repair`. Use the receive context to bind the values to the record key. Only the owner's `Covered` for that exact deletion and candidate passes the evidence to the ordinary check. Verify all domain restrictions and retained fields before accepting the new value. Without those proofs use the ordinary regression rule. `original_in_current_generation` distinguishes the delete's original application from a recovery upload. `exact_version_authenticated` says a transition proof or verified chain stub binds the predecessor to the expected version.

Acknowledge the wait notification independently of the hold. To relinquish publication the owner returns `PutBack::Observe` on a later check of that exact delete or on `release_put_back(key, version, item_hash)`. Refusals and a read behind another device's service position cannot recreate custody already lost.

A layered backup carries a completed observation with its owner's layer. During an in-place restore, `RestoreContext::previous_local_scan` lets the owner retain verified evidence in its own namespace that the selected layer predates. When the previous installation holds the only signed copy of a record, iterate `RestoreContext::previous_records_of` for the owner's registered collection. Each result carries the accepted value, version trust and flags. The stored write must open under its original scope key, and both the installed and selected certificates must permit that scope. The protocol can verify a receipt from those bytes and preserve it through its local restore writes. Propagate a read error to refuse the restore. A fresh destination can recover only the evidence available in the backup or from later reads.

Use `record_op` to build a write in a batch, `put_record` or `delete_record` for a single change, and `update_record` for a bounded read/modify/write. A protocol's update function can be called again on conflict. Build an `OpBatch` with operations and conditions, optionally local writes and queued messages, then `submit_batch`. Use `for_protocol` to identify the owner of local state. Use `record_condition` and `claim_condition` for the version or step the change depends on. Add operations with `op`, `op_if` or `entry` and conditions with `when`. `server_time_in` constrains service time to a half-open interval. `obligation_deadline`, `local`, `locals` and `queue` attach the deadline, local changes and deliveries to settle with the batch. Inspect `ops`, `len` and `is_empty`, or take the operations with `into_ops`.

Use `keep_id_at` on a protocol batch when a restart must associate an outstanding operation with its original batch. It stores the original 16-byte batch ID under a vacant protocol-local key in the first commit that keeps the batch. Read it with `protocol_get` and check `kept_batch`. An applied-only local write can remove the marker. A backup omits native pending batches and their outcomes, so let the protocol preserve unresolved markers in its layer. After a provider loss a refusal of newly signed bytes can leave the earlier send uncertain.

A refused batch can report the competing write on the key it tried to write or the key of a record condition. The app checks that write at the signed head of the refusal, including when it retries a stored batch. A conflict that reports only a version leaves the held value in place. Use `read_record` when the protocol needs the current value of that key.

A claim coordinates attempts between apps. Use `read_claim`, `claim_evidence`, `set_obligation_deadline` and `write_claim`. `ClaimOp` constructs an attempt, done, failed or unknown entry. Before carrying out an attempt, verify its operation and proof with `check_attempt` and apply the protocol's own rules. `may_attempt` checks local gates. Call `refresh_identity` when needed and check `identity_confirmation_age_ms` immediately before authorizing an outside action. The exact own document must have been observed less than 60 seconds ago. Sample device time through `App::clock` so the host and client observe backwards adjustments together. A backwards sample during or after the read requires a new Homeserver observation. `claim_doubt`, `doubtful_claims` and `claim_conflict` expose unresolved evidence. `ClaimDoubt::doubtful` also covers a possible duplicate, divergence, distrust or an early pin. Consult the individual reasons before acting. `shared_evidence` collects record and claim evidence for recovery. `prune_claim_evidence` removes evidence only within the client's retention rules.

| Case | What happened and what to do |
|---|---|
| `ObligationDeadline::NotKnown` | The protocol has supplied no independent deadline. Keep uncertainty explicit when deciding what evidence to retain. |
| `ObligationDeadline::NoDeadline` | The protocol positively knows the obligation has no deadline. Supply that fact. |
| `ObligationDeadline::At` | The protocol knows the pinned deadline value in Unix milliseconds (the obligation deadline plus one millisecond). Supply it independently of the service's claim. |
| `AppEvent::ClaimChanged` | The client saved a changed claim view or proof. Re-read the named claim before updating an obligation. |
| `AppEvent::ClaimPinDiffers` | While checking a missing claim the client could legitimately have lost to service retention, it found that the held pin disagrees with the protocol's known deadline or absence of one. Show the discrepancy and reconcile using the retained evidence. |
| `AppEvent::AttemptNotHeld` | A resubmitted batch was applied, but the proof did not show this app holding its open attempt. Skip the outside action. The client makes a best-effort failed entry. |

### When a batch has no final answer

Keep the local batch ID returned in `AppError::Kept`. Look it up with `kept_batch`, or look up an attempt with `kept_attempt`. A read or write helps settle earlier batches. For a kept batch the client resends its signed body. Only the request authentication needs a new timestamp. A missing status means the client has no retained answer for that ID.

| Case | What happened and what to do |
|---|---|
| `AppError::Kept` | The call's own batch is saved, possibly still unsent. Show pending, save its ID and read again. Building a replacement could apply the same work twice. |
| `AppError::Ahead` | An older batch could not be settled first. Nothing from this new write was kept or sent. Call `receive` to let the client try the older batch first. When the client reaches a sent batch whose answer window has closed, it drops that batch. Check the outcome before deciding whether the new write is still needed. |
| `Refusal::KeptBatchesAhead` | Earlier saved batches still need to go first. Inside a kept error, this call's batch is already queued behind them. Let reads drain the queue. The count and oldest ID can help diagnose a delay. |
| `KeptBatchStatus::Kept` | The batch is still outstanding. `wire_batch_id` names its current bytes. An absent send stamp means those bytes are unsent. If the client reseals record writes after `409 stale_epoch`, the original ID shows the dropped batch. Track the new local ID if the replacement is kept. |
| `KeptBatchStatus::Applied` | The client has committed the batch's outcome. Use its local effects and stop retrying. |
| `KeptBatchStatus::Dropped` | The client has discarded this batch with its proposed local writes and queued messages. Read the reason before deciding on replacement work. |
| `KeptBatchDrop::Refused` | A lasting refusal establishes non-application of the batch. Use the code to correct the request or abandon it. |
| `KeptBatchDrop::Unsent` | The client discarded the batch before sending. No remote operation from it ran. Consider a new intent only if it is still allowed. |
| `KeptBatchDrop::Uncertain` | The earlier send may have succeeded. Examine current records, proofs and claims, and withhold automatic repetitions. |
| `AppEvent::KeptBatchesWaiting` | A read could not send earlier batches yet (including rate-limit backoff), but could continue its feed work. Leave the queue in place, observe any retry interval and read again. |
| `AppEvent::KeptBatchApplied` | The client established application of a saved batch and committed what it settles. Look up the original ID and use the result. |
| `AppEvent::KeptBatchSignedAgain` | The client prepared bytes for the new generation under a new wire ID. The local tracking ID stays the same. Wait for settlement there. After loss, this does not establish what happened at the lost service. |
| `AppEvent::KeptBatchDropped` | A saved batch expired, could not safely cross a loss or contained an unsent attempt that is now prohibited. Check the drop reason and reconcile any attached attempts. |
| `AppEvent::BatchRefused` | A retry established a lasting refusal. The batch and its attached local work were discarded. Use the code and current state to decide whether a different write is appropriate. |
| `AppEvent::AttemptDropped` | A discarded batch contained this attempt. It will not be signed again. Check the batch's end and the claim. An unsent batch never started the attempt, while a previously sent one may have done so. |

`KeptAhead::kept_since_ms` uses a verified service time held at the first send. It can precede the send by about a day. Use elapsed time since that stamp as an upper bound on age. `answer_until_ms` marks the end of the answer window (30 days less an hour from the stamp). Unsent bytes have neither time. A bare store read error can prevent the client from telling whether its own batch is kept. Reopen or read the store before deciding to issue the work again.

## Publishing the app's own record and rotating keys

Use `set_protocol_member` for a protocol's public data with an absolute expiry, or `set_protocol_member_with_lifetime` for a lifetime measured from each newly signed timestamp. Use `renew_record` or `renew_record_with_lifetime` to renew it, `update_accepts` when accepted kinds change, and `publish_record` to check the public copy. The earliest requested expiry wins across protocols. Before a renewed certificate's record is signed, each protocol's `member_for` gives its member and expiry ask under that certificate; the default keeps both, so a protocol whose member depends on its scopes overrides it, and must not panic. Publish only data intended for anyone to read. `sign_protocol` signs permitted protocol-labelled fields with the app key.

| Case | What happened and what to do |
|---|---|
| `Publication::NotPublishing` | Public record publication is off. The app uses its service record. No homeserver write is due. |
| `Publication::NothingAccepted` | The client knows of no service-accepted record to publish yet. Finish registration or delivery first. |
| `Publication::Published` | The public copy is up to date with the accepted record. Show publication complete. |
| `Publication::Superseded` | The homeserver has a valid later record, for example from another device. Leave that newer copy in place. |
| `Publication::Owed` | A required read or put failed. Show that the service accepted the record but publication is pending. The client retries on reads or changes. |
| `Publication::Unchecked` | No publication was outstanding, but the check of the public copy failed. Show its status as unconfirmed and check again. |
| `Publication::AwaitingRead` | A shared-key app's public copy is absent. Another device may be leaving. Read the service to establish current membership before restoring it. |
| `AppEvent::RecordPublishFailed` | A required public write failed, or deleting the file during immediate or compromise leave failed. While active, publication remains owed. After leaving, ask the signer to clean up the public record. |
| `AppEvent::Rotated` | The new receive key was registered. Update the encrypted backup and sync the new key to other devices. |
| `AppEvent::RotationLost` | Another registration won this key number. The losing private key was discarded. Use the winning key if known, otherwise follow the sync or security notice. |
| `AppEvent::KeysDeleted` | The cursor passed successor registrations, so retired receive keys were deleted locally. This device can no longer use those keys to open old envelopes. |
| `AppEvent::AwaitingDeviceSync` | Another registration needs a receive key this shared-key device lacks. Bring keys through trusted device sync and read again. |
| `AppEvent::AwaitingKeys` | Stored inputs need scope keys for the listed epochs. Fetch available bundle parts and ask the signer for missing grants or keys. Waiting copies remain subject to the shared limits. |
| `AppEvent::KeysThrough` | The contiguous range for which the app holds its granted scope keys changed. Use the reported epoch to update readiness. |
| `AppEvent::BundlePartSkipped` | A part failed a check, or the entire parts list could not be read. Show the reason and the range if available (a whole-list error carries `(0, 0)`). If `alert` is set, warn that the naming key differs and contact the signer. |
| `AppEvent::FullBundleRequested` | The service accepted the request for a full key bundle. Wait for the signer to supply it and read again. |

`member_for` takes and gives a protocol's expiry ask. `RecordExpiry` is non-exhaustive, so match it with a wildcard arm:

| Ask | Meaning |
|---|---|
| `RecordExpiry::Never` | No expiry asked. |
| `RecordExpiry::At` | An absolute expiry time. It must be later than the new record's time, or the member is dropped. |
| `RecordExpiry::Lifetime` | A lifetime from each new record's time, capped by the identity's maximum record age. |

`rotate` handles receive-key registration. `receive_key_numbers` shows the keys held. Use `fetch_key_bundle`, `keys_through`, `data_epoch` and `scope_key` for scope-key availability. Use `blind` for names derived under the app's `naming_key`. Treat keys and decrypted values as secrets. For devices sharing the same App ID, use authenticated private sync for `device_keys` and `take_device_keys`. Set `set_multi_device` on the giving device too. Sharing a cursor means missing history behind a checkpoint can require reconciliation with the other devices.

## Backing up, restoring and leaving

Offer an encrypted app backup and replace it after rotation. `AppBackup::to_bytes` serializes the app's signing and decryption material in recoverable form. Supply encryption, access control and a recovery key outside that byte string. Decode with `from_bytes`. Never send the raw backup to diagnostics.

`backup` captures app keys, identity, cursor and chain data, bounded waiting inputs and their drop notices, and selected owed callbacks. It carries outbox items in queue-time order within an 8 MiB budget. It omits sent history and give-up markers. A restore reports each omitted outbox ID as `AppEvent::DeliveryUnknown`, since the source device may still deliver it, or as `AppEvent::MessageUndelivered` with `resend: true` for a re-send of a message accepted before. Restored deliveries retain their ID and a replay deadline derived from backup time with a clock margin. A flush checks that deadline before delivery. A plain backup has no protocol state layer.

Use `backup_layered` when the protocol's local state matters. It captures that state, parked inputs, duplicate markers and work beyond the cursor together, and checks that the restore commit fits. It may enforce waiting limits or reserve an input ID in the live store even if the backup then fails. A pending receive effect becomes an uncertain stored input in the backup. The live client still has its pending effect. A backup does not transfer an arbitrary unanswered batch to a new device.

Before calling `App::restore`, ask whether the previous device is still under the user's control. For a stolen or lost device, have the signer revoke that app and approve a new one. Restore replaces this app's namespace in one commit. On an unknown commit result, load the store to learn the outcome. Only registered owners receive carried obligations. A fresh store gets a new event epoch. A stored-entry drop retains its original notice identity even when it gets a new delivery ID.

Call `refresh_identity` before the first post-restore read. Check `restore_question`, `restore_held_cursor`, and `reconcile_mode` before allowing attempts. The client compares the device's receive key and service cursor, but only the host can ask whether the app ran after the backup or whether other devices acted. Resolve outstanding obligations against current state. Construct `UserConfirmed` only after showing the consequence and receiving the user's answer.

| Case | What happened and what to do |
|---|---|
| `AppEvent::BackupRefused` | A layered backup failed the size check for its restore commit. Tell the user there is no new backup and preserve the last good one. Inspect the accompanying error. |
| `BackupRefusal::TooLarge` | The candidate restore contains a value over 16 MiB or a batch over 32 MiB. Reduce the layer or let retained entries and duplicate markers drain before backing up again. |
| `Refusal::CarriedTooLarge` | The backup fits on its own, but existing duties and owed calls do not fit beside it. Nothing was replaced. Handle and acknowledge completed duties and retry owed callbacks, then restore. Using an empty store forfeits obligations held only in the old store. |
| `AppEvent::RestoreLeftBehind` | Unreadable or ownerless carried duties or calls were skipped. Their contents cannot be recovered from this notice. Tell surviving protocols the counts and reconcile from their records. |
| `AppEvent::RestoreQuestion` | The client found registrations after the backup it cannot account for. Ask whether this app ran on that device after the backup. Use `confirm_restored_registrations` only on yes. On no or uncertainty use `refuse_restored_registrations`, which raises compromise and attempts to leave. |
| `Refusal::RestoreQuestionOpen` | An attempt or the end of reconciliation was refused while registrations still require an answer. Return to the restore question. |
| `HeldCursor::Clean` | The reported position did not exceed the comparison position. For the restore verdict the client also required confirmation of the own document, a comparable sequence and a successful key check indicating the key was current. Check protocol state and any activity outside the client before ending reconciliation. |
| `HeldCursor::Ahead` | The service claims to have passed more than this single-device state accounts for. Explain the discrepancy and ask about restoration or another copy. Both positions are available for diagnosis. The report alone cannot prove which party moved it. |
| `HeldCursor::Unknown` | The positions cannot settle continuity, for example across a loss, with a shared cursor ahead, or with a changed restore key. Reconcile with other devices and current claims. Before a verdict `restore_held_cursor` returns no value. |
| `AppEvent::HeldCursorAhead` | A feed page reports a higher cursor than this non-sharing app committed or sent. Ask about other use or restored state. The client does not leave solely on the service's claim. |
| `AppEvent::ContinuityUnverified` | The client resumed at a checkpoint without verifying the intervening history. Show the gap, compare current records and claims, and finish reconciliation before new attempts. |
| `LeaveMode::TwoStep` | For an app whose public data people act on, delete its public record when publishing, leave the service, then wait for the signer to publish removal and caches to expire. Retry `leave` if its first stage fails. |
| `LeaveReport::AwaitingRemoval` | The app left the service but has yet to observe its removal on the homeserver. Ask the signer to publish it and call `finish_leave` later. |
| `LeaveReport::Removed` | Published removal has been observed. Show the supplied deletion time. Call `finish_leave` after the ten-minute cache interval. |
| `LeaveMode::Immediate` | After warning that cached readers may still use the record, pass confirmation to `leave`. The client attempts public deletion, leaves at the service and deletes its local keys without the cache wait. |
| `AppEvent::Left` | The service accepted departure or already regarded the app as no longer current. Stop offering normal use. Complete key deletion for the chosen leave mode. |
| `AppEvent::KeysDestroyed` | The leave cleanup committed deletion of app, naming, scope and receive keys and local data including parked inputs and protocol state. Remove any host-held copies that should also be destroyed. |
| `LeaveReport::Done` | Local key deletion completed. Close this app. Check any separately managed backup or synced device under the user's retention policy. |
| `Refusal::Left` | A leave has begun, or the app's deleted keys prevent loading it. Continue any outstanding leave step. Ordinary operations cannot resume on deleted keys. |

## Provider changes, loss and alarms

A freeze, a new provider and a lost provider require different user messages. Use `check_for_move` for an explicit check and `follow_provider` to continue the verified change. The client saves its steps and checks the service key named by the identity. A declared loss starts reconciliation. Read `recovery_info` for the lost and current generations, declaration time, interval for resend requests, upper time for uncertain authorizations, unfinished steps and counts left out. A completed recovery can still leave obligations whose outcome only the protocol or user can determine.

| Case | What happened and what to do |
|---|---|
| `AppEvent::ProviderChanged` | The newest own identity document points to another generation. Follow it and update the provider display when the change completes. |
| `AppEvent::Moved` | A verified freeze suspends writes at the old service. Show the move in progress and keep pending writes. |
| `ProviderStatus::AwaitingMove` | The client is waiting for the next generation to be published. Poll later. Avoid creating new copies of pending work. |
| `ProviderStatus::Current` | No change needs following now. Continue with the current service. |
| `ProviderStatus::Followed` | The client now uses the named generation after a move, key change or loss. Read there and check reconciliation status. |
| `AppEvent::ProviderFollowed` | The client completed following a move or service key change. Show the current generation and resume reads. |
| `ProviderStatus::MoveCancelled` | The freeze was cancelled. Stay at the current service and let queued writes resume. |
| `AppEvent::MoveCancelled` | The client observed cancellation of the move. Clear the pending-move display. |
| `AppEvent::ProviderChangeSuperseded` | A later signed generation overtook an unfinished move or recovery. Follow the newer one instead of retrying the abandoned generation. |
| `AppEvent::ReceiveKeyRolledBack` | The new service showed an older receive-key registration. Show the discrepancy and let the client re-register its current key. |
| `AppEvent::ListsDiffer` | The new service's lists differed. Show how many contacts or denies were added back, unknown contacts left in place and codes withdrawn. Ask the user to check the unknown contacts. |
| `AppEvent::EvidenceUploaded` | The service answered the evidence upload. The reported counts (zero if absent) can help diagnose what was uploaded. This answer alone does not settle every missing record or claim. |
| `AppEvent::EvidenceRefused` | The upload received a service refusal, or was too large to send. The client reports the code and goes on. Keep the evidence and involve the signer for import conflicts. Other transport failures can be retried. |
| `AppEvent::ProviderLost` | The identity declared the old generation lost. Suspend new attempts. Show that old inbox entries and unbacked records may be unavailable, and that an unanswered action may already have run. |
| `AppEvent::ProviderRecovered` | The client's registration, upload, admission and resend-request steps are finished. Inspect omitted-entry counts and resolve outstanding obligations before ending reconciliation. |
| `LossUploadOutcome::Pending` | The app kept the inventory but lacks a verified answer. Recheck the relevant records and claims before resolving a duty. |
| `LossUploadOutcome::NoRequest` | The scan produced no upload request. Check omitted items, the protocol checkpoint and local duties before declaring the inventory empty. |
| `LossUploadOutcome::TooLarge` | The inventory exceeded the request limit. Keep its outstanding duties until their effects can be verified. |
| `LossUploadOutcome::Refused` | The service refused the upload. Use the refusal code to explain the pending recovery work. |
| `LossUploadOutcome::Answered` | The authenticated head and transition identify the changes the service accepted. Compare the exact retained inputs with the current applications before resolving each duty. |
| `Evidence::Op` | Use `keep_evidence` for a signed record write or claim entry with writer certificate and any held proof. This gives recovery a copy to upload. |
| `Evidence::Proof` | Keep a transition proof available for upload even without an operation. Use `forget_evidence` only when the protocol no longer needs that evidence. |
| `AppError::ExpiredUnsent` | The client retired this batch before its first handoff. Account for earlier candidates before issuing a replacement. |
| `AppError::NotAnsweringAsAccount` | An unverified 404 and a genuinely absent homeserver identity document suggest erasure. Show unreachable since the supplied device time. Keep local state. Five matching observations spaced at least six hours apart over at least a day are required on this path. |
| `AppEvent::AccountGone` | The client concluded the account was erased. A signed, request-bound account-not-hosted answer plus an absent identity document can establish this immediately. The unverified path needs the repeated checks above. Tell the protocol and retain local state for possible reappearance. |
| `ProviderStatus::Gone` | The app is no longer current or its account is gone. Stop ordinary service work. Let provider checks look for a current identity document. |
| `Refusal::Gone` | A gated operation encountered a removed app or an account considered erased. Stop retrying that operation and check membership through the signer. |
| `AppEvent::Removed` | The app is no longer listed as current or is recorded as departed. Disable actions requiring membership. Ask the signer about the change. |
| `AppEvent::AccountBack` | The account previously considered gone is current for this app again. Obsolete unacknowledged account-gone duties were removed. Refresh the UI, resume reads and re-register push if wanted. |
| `AppEvent::ClockSkew` | A stamped offset or a verified service-time lower bound exceeds clock tolerance. Ask the user to correct the device clock, then refresh. The offset `clock_skew_ms` is available for diagnostics. Automatic attempts pause while the difference remains too large. |
| `AppEvent::Alarm` | The app detected a security failure. Show the specific alarm below and keep its evidence. Read `alarm()` when reopening the store. |
| `AppError::Alarm` | The call detected an alarm and stopped normal work. Show the details even on the error path. |
| `Refusal::Stopped` | An alarm already blocks this operation. Consult the recorded alarm. Repeated service calls cannot clear it. |
| `Alarm::Rollback` | Signed service evidence contradicts the chain or a fact already verified. A later feed page can show a different readable item or change the acceptance time at a position where the app still holds the entry's observation. A page can still [omit that position entirely](known-issues.md#client). Stop actions, preserve the evidence and bring it to the signer for provider resolution. |
| `Alarm::ProtocolRollback` | A registered protocol supplied a rule broken by signed service data via `raise_rollback`. Display the protocol and rule. Resolve it with the signer as a service rollback. |
| `Alarm::Equivocation` | Two signed bodies for the own identity have the same version. Stop using the conflicting authority and ask the signer to resolve it. |
| `Alarm::IdentityRollback` | An own identity update violated its history, for example by reinstating a removed app. Keep the held history and involve the signer. |
| `Alarm::ServiceTimeBackwards` | Comparable verified times under one service key went backwards. Explain that the service reported an earlier time and take both verified times to the signer as evidence. Adjusting the device clock cannot repair signed history. |
| `Alarm::Compromise` | An unexplained own receive-key registration indicates another holder of this app's signing key. The client raises the alarm and attempts a leave. Ask the signer to revoke the App ID, supplying `compromise_distrust_from` if known. It may be a conservative bound, or unknown. The compromise leave keeps the local keys. Revocation is the signer's job. |

In `Protocol::provider_lost`, use the supplied acceptance interval to queue resend requests in local writes. Return known conversations to restore admission where permitted. Blocked identities are excluded. Surface `conversations_left_out` and `claim_entries_left_out`: some senders may need fresh admission and some evidence may exist only with its writer. Resolve attempts that could have been authorized through `uncertain_until_ms`. Use `end_reconcile_for` as each protocol finishes or `end_reconcile` when the user confirms completion for all of them. The client does not decide an outside action's outcome for the host.

## Blocking a sender and managing invitations

Use `add_contact`, `remove_contact`, `invite` (add a conversation), `remove_conversation`, `deny` and `undeny` for service admission. `admits` reads the local copy. `allow_list` fetches the service's lists when permitted. `register_invite_code`, `invite_codes` and `withdraw_invite_code` manage bearer invitations. Share their `uri` only with intended recipients. The invitation context is visible to the service. Use `ask_to_connect`, `connect_requests`, `allow_connect` and `decline_connect` for a request requiring approval.

A service deny controls incoming admission. For an immediate outgoing block, call `hold_queued` on the recipient **before** the next delivery call. It holds pending sends, including messages a saved batch may later put in the outbox. Use `held_counterparties` and `release_queued` for a reversible hold. Use `withdraw_queued` to give up outstanding deliveries, including those still in saved batches. Other operations in those batches can still run. For a single message, use the owning protocol's `hold_message`, `held_messages`, `release_message` or `withdraw_message`. None can recall a copy already accepted. Reapply any holds made after a backup before the first post-restore send or flush.

In the receive callback, read `sender_disposition`. A flag records repeated rate limiting. A missing `lists_as_of_ms` means the copy may be incomplete, including after restore or provider loss. A false blocked or flagged bit then cannot clear a sender. Apply the protocol's rule for unknown standing. With list-read permission the client attempts refresh. Handle `deny_list_changed` in order, and `deny_list_gap` from the current snapshot when history is missing. `DenyListGap::list_read` tells whether the snapshot was available. When false, treat the history as unknown and keep protective restrictions even though the returned list is empty. A callback may be retried. Put its state changes in the returned local writes.

| Case | What happened and what to do |
|---|---|
| `WrittenBy::Service` | The service created this conversation from an invite-code append. Inspect its code hash and context to decide what the invitation authorized. |
| `WrittenBy::App` | The named app wrote this conversation. Use the writer ID for attribution. |
| `AppEvent::DenyListChangeRefused` | A feed change failed the writer, identity or authority checks. The client ignored it. Keep the previous trusted list and flag that the change was refused. The failed rule and feed position can help diagnose the refusal. |

## Running several protocols

Construct `ProtocolSet::single` or `ProtocolSet::new` from the registered protocols. Names must be distinct, and a collection name has only one owner. Each protocol supplies its own kinds, scopes, record policies and rules. Use `protocols()`, `names`, `contains` and `get` for the roster. Loading requires the stored roster. Restore can add a protocol with no earlier layer, subject to the certificate and layer checks.

Route a kind by the root before its first dot. The owning protocol supplies `check_scopes`, `check_body`, `receives`, `sends_to`, `adds_conversation`, `message_adds_conversation` and `may_send`. The kind and the signed message must both permit adding the recipient to the sender's conversation list. Use `plaintext.json()` for rules on exact signed bytes. Its `accepts` and `opaque_members` describe the messages it accepts, `has_keys` identifies keyed scopes, and `sent_between_own_apps` identifies traffic within the identity. Use a protocol-specific label in inputs to `blind`. `collections`, `record_seen`, `record_regression` and `sent_record` govern its records. `record_regression` checks every write of another app that the client would take, the first of a record too, with `seen` `None`; its `WriteBase` carries the service time the write's stub or proof dates it at. A failed resend or missed-entries callback can hold back its owner while other owners receive. A deny-list change or gap is a barrier for all owners. Use `queued_messages(protocol)` to inspect outstanding copies, including those in saved batches. A message waits if held individually, its recipient is held, or the current `may_send` callback withholds it. That callback sees the signed bytes, origin, resend flag, durable local state and current cert. Its failure must preserve the delivery for a later try.

Use `protocol_get`, `protocol_scan` and `protocol_commit` with the registered name. Local callbacks see their own namespace. Return bounded writes from resend, missed, deny-list and loss callbacks. `backup_layer` and `restore_layer` handle one protocol's state. Restore validates the layers against the backup identity, certificate and naming key before committing them. Use `AppBackup::layers` to inspect the named layers. `encode_local_state` and `decode_local_state` encode and read key/value layers. Use `local_writes_bytes` to check the 4 MiB callback budget.

For a duty shared by protocols, use `event_is_for` and `event_owners` to route it. If using `unacknowledged_events_for`, list **every** protocol, since listing hands over all current delivery IDs. Use `ack_event_with` to save one owner's local writes and acknowledge just that duty atomically. `ack_events_for` acknowledges that owner's delivered duties through the supplied ID. `ack_events` covers all owners through that ID. Acknowledge through an ID only after handling everything it covers. When each owner finishes reconciliation use its own `end_reconcile_for`. Attempts stay gated until every registered owner has finished.

| Case | What happened and what to do |
|---|---|
| `LocalWrite::Put` | Return a key and value to retain in this protocol's local state with the callback's outcome. |
| `LocalWrite::Delete` | Return a key to remove when the associated local commit succeeds. |
| `LocalWrite::DeletePrefix` | Return a prefix to remove all matching keys inside this protocol's namespace. Choose the prefix with care. |
| `AppEvent::LocalWritesRefused` | A required callback returned more than the permitted local write budget. Its writes were discarded and the callback will not be made again for this occurrence. Use the supplied call to reconstruct smaller work and acknowledge only once handled. |
| `RefusedCall::ResendNeeded` | The write set meant to request a resend was discarded. Use the sender, time interval and reason to queue the request yourself. |
| `RefusedCall::Missed` | The changes meant to handle missing entries were discarded. Recover from the indicated gap using smaller writes. |
| `RefusedCall::DenyListChanged` | The protocol's local response to a block or unblock did not fit. Apply that change to its local decisions before trusting the sender. |
| `RefusedCall::DenyListGap` | The list snapshot was taken without the protocol's local changes. Rebuild its blocking state from the current lists and the indicated gap. |
| `RefusedCall::ProviderLost` | Recovery continued without this callback's oversized local writes. Reconstruct missing resend requests and uncertain obligations from the supplied loss and durable records. |

## Handling storage and network failures

A failed multi-step call may already have saved work. Read its outer error before inspecting `unkept()` or `code()`, which look through the batch wrappers. Read events and saved state before deciding whether a retry means resuming an existing operation or starting a new one. Error text and user-visible reasons should describe the failed rule without revealing keys, plaintext, invitations or record bodies.

| Case | What happened and what to do |
|---|---|
| `AppError::Switch` | A service call or client check failed. Use the nested client error and any authenticated refusal code below. |
| `AppError::Transport` | The network, homeserver or relay operation failed. Check whether the request could have left and resume any saved work. |
| `AppError::Store` | Reading or writing the host's store failed. Show the storage problem and follow its certainty about that commit. |
| `AppError::Protocol` | A protocol callback failed in its own store, for example during loss recovery. Repair that store and resume the saved step. |
| `AppError::InvalidData` | A document, proof, saved value or host input failed its checks. Use the failed rule to inspect the source. Some proof checks happen after the remote write, so check its outcome before repeating any action. |
| `AppError::Refused` | An app rule blocked a step. Use its detailed refusal. Earlier steps of the call may already be durable. |
| `Refusal::NotNow` | A prerequisite is missing, such as completed reconciliation, a usable lookup or a required upload. Show the reason and retry after the prerequisite changes. |
| `Refusal::Usage` | A host argument, permission, protocol registration or requested operation violates this API's rules. Correct the cause before calling again. |

Implement `StateStore::get`, `scan`, `commit`, `acquire` and `commit_if` with the same guarantees across all handles. A raw commit touching an owned namespace must refuse the entire batch. The conditional path checks the exact owner, namespace and batch size atomically. Use `StoreHandle` or its owned handle to keep the lease alive across outstanding work.

| Case | What happened and what to do |
|---|---|
| `Write::Put` | Store or replace these opaque bytes at the supplied key as part of the whole batch. |
| `Write::Delete` | Remove the key and physically delete its data with this commit. |
| `Write::DeletePrefix` | Remove every key with the prefix in this namespace and physically delete their data. |
| `AcquireOutcome::Acquired` | Return a lease for exclusive ownership. Keep it until its final holder drops. |
| `AcquireOutcome::Busy` | A competing lease is active. Leave the namespace intact and retry after its owner releases it. |
| `CommitOutcome::Applied` | Every conditional write is durable. Only then report success. |
| `CommitOutcome::NotOwner` | The supplied owner is no longer active. Apply no writes. Obtain valid ownership before another conditional write. |
| `StoreError::InUse` | Another writer owns the namespace. Wait or use the active instance. Nothing in the refused commit was applied. |
| `StoreError::NotOwner` | This handle lost the right to commit. Stop using it and reacquire ownership. No writes landed. |
| `StoreError::Unavailable` | Storage is temporarily unavailable. Nothing landed. Restore access and resume. |
| `StoreError::Unknown` | The whole commit may or may not have landed. Re-read durable state before taking action. Never replay an external effect on this error alone. |
| `StoreError::Full` | No writes landed for lack of space. Ask the user to free storage, then retry. |
| `StoreError::Corrupt` | The client could not decode the stored bytes or found a state no writer produces, such as a waiting input whose saved receipt predates its acceptance. Stop using the damaged state. Diagnose the store or offer recovery from a known backup. |
| `StoreError::TooLarge` | One value or batch exceeds the byte cap. No part of that commit was applied. Reduce the writes. Freeing disk space will not make identical writes fit. |
| `StoreError::Other` | The host reports another definite failure. No writes landed. Fix the stated cause before retry. |
| `BatchError::ValueTooLarge` | A proposed value exceeds the per-value limit. Reduce that value before constructing the batch again. |
| `BatchError::BatchTooLarge` | The aggregate write size exceeds the cap. Reduce it or separate work that can safely commit independently. |
| `BatchError::Namespace` | The batch contains a write outside the checked namespace. Fix the caller's namespace before committing. |

The supplied HTTPS transport restricts connections to allowed public destinations. A custom transport must enforce the origin rules, follow no redirects, preserve the signed path, query, headers and body, and return responses regardless of HTTP status. Honor `Request::timeout`. An app time budget bounds when loops start more requests. Each in-flight request still needs a network timeout.

For a batch with `OpBatch::first_send_before`, the HTTPS transport checks the exclusive deadline at the nonblocking socket write, after waiting for writability. A custom transport implements `Transport::send_before` at its own last cancellable handoff. Its default leaves the batch pending. Only report `FirstSendExpired` if no request bytes left. A partial write has an uncertain outcome. Network transit and service scheduling take additional time, so use a `server_time_in` condition to bound application as well.

| Case | What happened and what to do |
|---|---|
| `TimeoutClass::Ordinary` | Use a deadline for a small call, such as a setting or service-time read. |
| `TimeoutClass::Bulk` | Allow time for a page, record view, upload or record-writing batch with a potentially large answer. |
| `TimeoutClass::LongPoll` | Allow the requested `wait_s` at the service plus time to return a bulk page. |
| `TransportError::Refused` | Local origin or address policy prevented sending. Return this only when zero request bytes left. Correct the destination. |
| `TransportError::Connect` | A connection could not be made and zero request bytes left. Retry connection later. |
| `TransportError::FirstSendExpired` | The cutoff passed before this request left. An earlier submission of these bytes may still be unresolved. |
| `TransportError::FirstSendUnavailable` | The transport or clock cannot establish a timely first handoff. Keep the batch for a later decision. |
| `TransportError::Timeout` | The deadline passed. The service may have applied the request. Resume with the same saved bytes. |
| `TransportError::TooLarge` | The answer exceeded the transport's limit. No usable answer is available. Check the limit and resume the original operation. |
| `TransportError::InvalidRequest` | The transport could not construct a request, for example because of an invalid header. Fix the input. This error does not give a kept batch the never-sent exception. |
| `TransportError::UnreadableSignedHeader` | A signed header occurred more than once or could not be represented faithfully. Report its status and discard the answer. The service client maps this to a bad service signature. |
| `TransportError::Other` | A connection broke after sending began, a proxy failed, or another transport fault occurred. Treat the outcome as unknown and resume saved work. |

Only `TransportError::Refused` and `TransportError::Connect` allow the client to undo the first-send stamp of a kept batch. Map a TLS failure after sending began, a partial write or a lost response to a timeout or other failure. Calling it a connection failure could let the client sign an already applied batch under a new ID and apply it twice.

| Case | What happened and what to do |
|---|---|
| `ClientError::Switch` | The pinned key authenticated a refusal bound to the request. Use `code()`, `retry()`, the current value and any retry interval. Honour backoff and conditions. A caller-level refusal may leave a batch pending. |
| `ClientError::BodyUnread` | A signed size, rate or not-found answer binds the request without its body. It cannot settle that body's fate. Honour any retry delay and keep the original batch. |
| `ClientError::BadServiceSignature` | The response signature is missing, unreadable or fails under the pin. Even the status is untrusted. Keep any pending write and check the provider through the signed identity. |
| `ClientError::StaleAnswer` | The pinned service signed the public identity response at `server_time_ms`, outside the reader's accepted time window. Retry the lookup before treating the switch copy as current. |
| `ClientError::BodyOverCap` | The client refused an oversized outbound body before sending. Reduce it. Retrying the same bytes cannot work. |
| `ClientError::Transport` | No usable service answer came back. Use the underlying transport error's delivery guarantee. |
| `ClientError::Unpinned` | The call requires a pinned service key and none was supplied. Obtain the correct key through the identity or enrollment flow before retrying. |
| `ClientError::InvalidResponse` | The response failed a wire check. For example, a feed page showed an entry, readable or unreadable, accepted after the page's own service time. Discard the unusable answer, preserve pending writes and check the service or integration. |
| `ClientError::Chain` | A head, proof or its binding failed verification. Preserve evidence and stop dependent action. The app can raise a rollback alarm for a contradictory signed answer. |
| `ClientError::Core` | An underlying format, signing or verification operation failed. Inspect the rule and correct the input or its source. |
| `ClientError::Usage` | The credentials or arguments cannot make this call. Correct them before sending. |

### Using the service client directly

`SwitchClient` exposes the HTTP calls beneath `App`. Supply the right `Credentials`, clock, transport, origin, account and service pin. Inspect `credentials`, `account`, `origin`, `is_foreign`, `pinned_key` and `last_server_time`. Set the authenticated key with `pin`. For direct calls use `sign_request` and `send`. To retry a write, persist the signed batch from `sign_batch` before `submit`, or reconstruct its exact body with `Batch::from_body`. The low-level caller owns persistence, feed handling and recovery. A signer can use `observe_account` before a pin exists to inspect the account observation, then `with_account_created` to bind calls that need the known creation time. `check_response` checks a response against the pinned key, account and exact sent request. `is_not_hosted` distinguishes the authenticated account-absence answer from an ordinary missing object.

| Case | What happened and what to do |
|---|---|
| `Credentials::App` | Supply the app keys, identity and certificate for an app acting on its own account or writing to a peer. |
| `Credentials::Signer` | The signer authorizes identity-level calls through its signing interface. Keep that authority with the signer. |
| `Credentials::SignerRequests` | A request-only signer authenticates reads and delivery of previously signed material. Obtain separately signed documents when the operation needs them. |
| `RecoveryEnrollmentAnswer::Preparation` | The service returned a preparation for the enrollment or its reserved replacement. Save the exact preparation and frozen signed identity document before sending the matching commit. |
| `RecoveryEnrollmentAnswer::Committed` | The service confirmed the enrollment and its frozen signed identity document. Persist the verified receipt before advancing recovery. |
| `RecoveryEnrollmentAnswer::Disposition` | The service returned a signed conflict for this commit. An expiry ticket leaves its outcome open. Persist the renewal before sending it. If the service reports a selected replacement, keep that preparation and follow the signer recovery flow. |
| `Credentials::NextService` | During a cooperative move the destination service uses the signer's transfer and its own key to request export data. This is a service role. |
| `FeedItem::Entry` | An encrypted inbox entry is available. Run recipient checks before exposing any content. |
| `FeedItem::Unreadable` | A departed target left an unread entry. Check departure and acceptance time before asking its sender for a new copy. |
| `FeedItem::Missed` | Entries aged out before this app read them. Re-list shared state. Ask for resends only when the interval is usable. |
| `FeedItem::Chain` | The page carries a full chain item. Verify its place, contents and authority before acting. |
| `FeedItem::Stub` | Only the chain link is available. Verify continuity and obtain current claim or record data separately where needed. |

The typed calls for app traffic are `feed`, `append`, `directory`, `keys`, `request_full_bundle`, `record`, `records`, `claim`, `allow`, `connect`, `connect_requests`, `decline_connect`, `put_peers`, `put_push`, `public_identity` and `leave`. The service client also exposes `observe_account`, `enroll`, `put_identity`, `apps`, `revoke`, `freeze`, `unfreeze`, `abort_import`, `export`, `export_chunk`, `import_start`, `import_chunk`, `import_activate`, `recovery_admission`, `recovery_upload`, `erase`, `put_handover` and `get_handover` for callers with the corresponding role. Use the [wire format](../spec/wire-format.md) for the authority, limits and signed response of each call.

### Exercising failure paths in a host test

The optional `test-support` feature exposes a scripted service and store. The following cases belong to the fixture. Use them to check the host's decisions before relying on real storage or a real network.

| Case | What to exercise |
|---|---|
| `ScriptError::Core` | Fixture document creation, reading, signing or sealing failed. Fix its input before continuing. |
| `ScriptError::Json` | A fixture value failed JSON conversion. Fix the value or encoding. |
| `ScriptError::Missing` | A fixture prerequisite is absent. Supply the missing app, key or other state named in the error. |
| `ScriptError::Refused` | The scripted service refused an injected batch. Check its status and body or correct the batch. |
| `store::Fault::None` | Run against the backing store with no injected commit failure. |
| `store::Fault::FailBefore` | One commit is refused before writing. Check that a later retry can succeed. |
| `store::Fault::FailAfter` | One commit lands but reports an unknown outcome. Check that reopening observes the committed state. |
| `store::Fault::StopBefore` | The store stops before the selected commit. Reopen the backing store and expect the earlier state. |
| `store::Fault::StopAfter` | The store stops after applying the selected commit. Check the durable outcome on reopening. |
| `testing::Fault::Error` | Return the chosen service refusal on a matching path. Exercise its retry or correction rule. |
| `testing::Fault::LoseAnswer` | Apply the request and lose the reply. Resume the saved operation and check for a single effect. |
| `testing::Fault::Unanswered` | Let the configured number of matches through, then time out without applying the selected request. Exercise unknown delivery. |
| `testing::Fault::LoseAnswerAfter` | Lose the answer after applying a later matching request. Verify the same recovery after earlier successes. |
| `testing::Fault::Unreachable` | On the selected matching request, simulate failure to connect. Check the never-sent path. |
| `testing::Fault::LeaveOut` | Return a signed answer missing a member. Check that invalid data cannot authorize work. |
| `testing::Fault::Replace` | Replace an answer member before signing. Check validation of the returned contents. |
| `testing::Fault::SignWith` | Use a different service key on the targeted answer. Verify the host keeps its pin and discards the answer. |
| `testing::Fault::Head` | Give the targeted answer an earlier head, or none. Verify the host reports an overtaken answer apart and refuses one without a head. |
| `testing::Fault::ErrorSignedWith` | Sign a refusal under the wrong key. Verify the status cannot settle a write. |
| `testing::Fault::BeforeTheBody` | Return a signed refusal before reading the body. Check the unresolved batch is retained. |
| `ErasureOutcome::Unresolved` | Leave the account present with no known erasure outcome. Keep the attempt unresolved. |
| `ErasureOutcome::UnresolvedAbsent` | Simulate an absent account without outcome evidence. Exercise the missing-evidence path. |
| `ErasureOutcome::Committed` | Deletion committed before its external completion record was published. Exercise resumption from durable deletion. |
| `ErasureOutcome::Rejected` | Erasure did not apply and the pending attempt has yet to be withdrawn. Exercise cleanup after a definite rejection. |
