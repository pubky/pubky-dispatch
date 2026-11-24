//! Counter floors for signing and replay (Switch spec 4.3, 12.8).

use pubky_switch_core::json::MAX_INT;
use pubky_switch_core::records::IdentityDoc;

use crate::error::{Refusal, Result};

/// Maximum absolute version floor without a verified document (Switch spec 12.8).
const VERSION_CEILING: u64 = 1 << 52;
/// Maximum absolute generation floor without a verified document (Switch spec 12.8).
const GENERATION_CEILING: u64 = 1 << 32;
/// Maximum absolute epoch without a verified document or bundle range.
const EPOCH_CEILING: u64 = 65_536;
/// Honor a nearby scalar: skipping a slot is safer than signing two bodies at a spent
/// version. Beyond 2^20, discard the bare hint to avoid exhausting the wire counter
/// on damaged records (Switch spec 4.3, 12.8).
const MAX_LOCAL_AHEAD: u64 = 1 << 20;

/// A counter carried by the signed identity document (Switch wire 3.3).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum Counter {
    /// The identity document version.
    Version,
    /// The service generation.
    Generation,
    /// The data epoch used for scope keys.
    Epoch,
}

impl Counter {
    fn ceiling(self) -> u64 {
        match self {
            Self::Version => VERSION_CEILING,
            Self::Generation => GENERATION_CEILING,
            Self::Epoch => EPOCH_CEILING,
        }
    }

    fn value(self, doc: &IdentityDoc) -> u64 {
        match self {
            Self::Version => doc.version(),
            Self::Generation => doc.generation(),
            Self::Epoch => doc.data_epoch(),
        }
    }

    /// Keep a nearby spent floor. A distant scalar alone cannot advance a verified head.
    pub(crate) fn floor(self, verified: u64, local: Option<u64>) -> u64 {
        local
            .filter(|&n| {
                let ahead = if self == Self::Epoch && n > EPOCH_CEILING {
                    1
                } else {
                    MAX_LOCAL_AHEAD
                };
                n <= MAX_INT && n.checked_sub(verified).is_some_and(|d| d <= ahead)
            })
            .unwrap_or(verified)
    }

    /// Repair a damaged hint on an authenticated read, preserving an unspent lower mark.
    pub(crate) fn repair(self, verified: u64, local: &mut u64) {
        if *local > verified {
            *local = self.floor(verified, Some(*local));
        }
    }

    /// Advance the floor, or copy it with a zero step. Verified steps may cross a ceiling.
    pub(crate) fn next(self, verified: u64, local: Option<u64>, step: u64) -> Result<u64> {
        let mut floor = self.floor(verified, local);
        // A high epoch needs its verified predecessor (Switch spec 12.8).
        if self == Self::Epoch && step > 0 && floor >= EPOCH_CEILING {
            floor = verified;
        }
        floor
            .checked_add(step)
            .filter(|n| *n <= MAX_INT)
            .ok_or_else(|| Refusal::CounterExhausted { counter: self }.into())
    }

    /// A no-copy recovery can bootstrap only from a representable, bounded clock floor.
    pub(crate) fn clock_floor(self, value: Option<u64>) -> Result<u64> {
        value
            .filter(|n| *n <= self.ceiling())
            .ok_or_else(|| Refusal::CounterClock { counter: self }.into())
    }
}

/// Whether an ordinary queued delivery needs a counter witness (Switch spec 4.3, 12.8).
pub(crate) fn needs_witness(doc: &IdentityDoc) -> bool {
    [Counter::Version, Counter::Generation, Counter::Epoch]
        .into_iter()
        .any(|counter| counter.value(doc) > counter.ceiling())
}

/// Check immutable signed bytes against independent evidence before their first use.
/// A zero step needs an existing witness for every counter. For delivery the spent floor
/// precedes the candidate by one, or by two for an abort (Switch wire 3.12).
pub(crate) fn check_copy<'a>(
    doc: &IdentityDoc,
    copies: impl IntoIterator<Item = &'a IdentityDoc>,
    version_step: u64,
) -> Result<()> {
    let counters = [Counter::Version, Counter::Generation, Counter::Epoch];
    let mut highest = [0; 3];
    let mut has_copy = false;
    for copy in copies {
        has_copy = true;
        for (floor, counter) in highest.iter_mut().zip(counters) {
            *floor = (*floor).max(counter.value(copy));
        }
    }
    for (verified, counter) in highest.into_iter().zip(counters) {
        let value = counter.value(doc);
        if value <= verified {
            counter.next(value, None, 0)?;
            continue;
        }
        if version_step == 0 {
            return Err(Refusal::CounterCopyNeeded { counter }.into());
        }
        let step = if has_copy && counter == Counter::Version {
            version_step
        } else {
            1
        };
        let step = step.min(value.saturating_sub(verified));
        let spent = value.checked_sub(step).filter(|_| has_copy);
        if counter.next(verified, spent, step)? != value {
            return Err(Refusal::CounterCopyNeeded { counter }.into());
        }
    }
    Ok(())
}

/// A queued first recovery without a predecessor must fit the same clock floors as its signer.
pub(crate) fn check_bootstrap(doc: &IdentityDoc) -> Result<()> {
    for counter in [Counter::Version, Counter::Generation, Counter::Epoch] {
        let value = counter.value(doc);
        let floor = counter
            .clock_floor(value.checked_sub(1))
            .map_err(|_| Refusal::CounterCopyNeeded { counter })?;
        if (counter == Counter::Epoch && value != 1)
            || (counter == Counter::Generation && doc.body().recovery_from != Some(floor))
            || counter.next(floor, None, 1)? != value
        {
            return Err(Refusal::CounterCopyNeeded { counter }.into());
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use pubky_switch_core::keys::IdentityKey;
    use pubky_switch_core::records::{IdentityBody, IdentityPolicy, Inbox};

    fn signed(key: &IdentityKey, version: u64, epoch: u64) -> IdentityDoc {
        let mut body = IdentityBody::first(
            key.public(),
            [2; 16],
            Inbox::new("https://switch.example", [3; 32]),
            IdentityPolicy::default(),
        );
        body.version = version;
        body.data_epoch = epoch;
        IdentityDoc::sign(key, body).unwrap()
    }

    #[test]
    fn test_counters_replayed_high_epoch_needs_its_predecessor() {
        let key = IdentityKey::from_secret([1; 32]);
        let head = signed(&key, 4, EPOCH_CEILING);
        let next = signed(&key, 5, EPOCH_CEILING + 1);
        let skipped = signed(&key, 6, EPOCH_CEILING + 2);
        assert_eq!(
            check_copy(&skipped, Some(&head), 1),
            Err(Refusal::CounterCopyNeeded {
                counter: Counter::Epoch
            }
            .into())
        );
        assert_eq!(check_copy(&skipped, Some(&next), 1), Ok(()));
    }

    #[test]
    fn test_counters_steps_and_spent_slots() {
        assert_eq!(Counter::Version.next(40, None, 2).unwrap(), 42);
        assert_eq!(Counter::Version.next(40, Some(39), 1).unwrap(), 41);
        let edge = 40 + MAX_LOCAL_AHEAD;
        assert_eq!(Counter::Version.next(40, Some(edge), 1), Ok(edge + 1));
        assert_eq!(Counter::Version.next(40, Some(edge + 1), 1), Ok(41));
        assert_eq!(
            Counter::Version.next(MAX_INT - 2, Some(MAX_INT - 1), 1),
            Ok(MAX_INT)
        );
        assert_eq!(Counter::Epoch.next(40, Some(MAX_INT), 0).unwrap(), 40);
    }

    #[test]
    fn test_counters_thousand_refused_spends_with_only_the_scalar() {
        let head = 40;
        let mut spent = head;
        for n in 1..=1_001 {
            Counter::Version.repair(head, &mut spent);
            spent = Counter::Version.next(head, Some(spent), 1).unwrap();
            assert_eq!(spent, head + n);
        }
    }

    #[test]
    fn test_counters_versions_increase_through_repairs_and_refusals() {
        use crate::state::SignerState;

        fn walk(key: &IdentityKey, state: &SignerState, head: u64, last: u64, depth: usize) {
            let verified = state.verified_version(head).unwrap();
            for hint in [
                head,
                state.signed_through,
                verified + 17,
                verified + MAX_LOCAL_AHEAD,
                verified + MAX_LOCAL_AHEAD + 1,
            ] {
                let mut branch = state.clone();
                branch.signed_through = hint;
                let next = branch.next_version(head).unwrap();
                Counter::Version.repair(verified, &mut branch.signed_through);
                assert_eq!(branch.next_version(head).unwrap(), next);
                assert!(next > last);
                if depth > 1 {
                    branch.signed_through = next;
                    let doc = signed(key, next, 1);
                    branch.keep_spent(doc.signed()).unwrap();
                    walk(key, &branch, head, next, depth - 1);
                    branch.spent_doc = None;
                    walk(key, &branch, next, next, depth - 1);
                }
            }
        }
        let key = IdentityKey::from_secret([1; 32]);
        walk(&key, &SignerState::new(key.public(), [2; 16]), 1, 1, 3);
    }

    #[test]
    fn test_counters_absolute_and_verified_limits() {
        for counter in [Counter::Version, Counter::Generation, Counter::Epoch] {
            let limit = counter.ceiling();
            assert_eq!(counter.clock_floor(Some(limit)).unwrap(), limit);
            assert!(counter.clock_floor(Some(limit + 1)).is_err());
            assert!(counter.clock_floor(None).is_err());
            assert_eq!(counter.next(limit + 1, None, 1).unwrap(), limit + 2);
            assert_eq!(counter.next(MAX_INT - 1, None, 1).unwrap(), MAX_INT);
            assert_eq!(
                counter.next(MAX_INT, None, 1),
                Err(Refusal::CounterExhausted { counter }.into())
            );
            assert!(counter.next(MAX_INT - 1, None, 2).is_err());
            assert!(counter.next(u64::MAX, None, 1).is_err());
        }
    }
}
