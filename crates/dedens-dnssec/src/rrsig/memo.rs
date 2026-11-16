//! The signatures a validator verified (D86): a check of the same signature, by the same key, over the same data
//! is not done again.
//!
//! A verification is a fact of mathematics, true whenever it is asked: what an entry holds is that `ring` accepted
//! the signature, nothing of its time window, of the key's trust or of the zone, which each check judges anew
//! before it asks here. So an entry needs no TTL, and a change of anchors
//! or of keys makes no entry wrong. Each is the SHA-256 digest of the algorithm, the public key, the signature and
//! the signed data, all four length-delimited or last: forging a hit is finding a SHA-256 collision. Only
//! successes are kept: a failure, kept, would be a free slot for whoever sends forged signatures.
//!
//! Bounded by entries in two generations, the newest and the one before it: an entry is put in the newest, a hit
//! in the older moves it to the newest, and once the newest holds half the bound the older is dropped and the
//! newest takes its place. What was not asked about for a generation goes, as an LRU's oldest would, without its
//! order to keep.

use std::collections::HashSet;
use std::mem;
use std::sync::{Mutex, MutexGuard, PoisonError};

use dedens_proto::SecAlgorithm;
use ring::digest::{Context, SHA256, SHA256_OUTPUT_LEN};

/// What identifies one verification: [`Memo::digest`].
pub(crate) type Digest = [u8; SHA256_OUTPUT_LEN];

/// The two generations of entries.
#[derive(Debug, Default)]
struct Generations {
    newest: HashSet<Digest>,
    older: HashSet<Digest>,
}

/// The signatures verified by the validations of one validator, shared as its key cache is (D86).
#[derive(Debug)]
pub(crate) struct Memo {
    /// Entries per generation, at least one.
    generation: usize,
    sets: Mutex<Generations>,
}

impl Memo {
    /// A memo of `entries` verifications (two generations of half, rounded up), `None` for 0: nothing kept,
    /// nothing digested.
    pub(crate) fn new(entries: usize) -> Option<Self> {
        (entries > 0).then(|| Self {
            generation: entries.div_ceil(2),
            sets: Mutex::default(),
        })
    }

    /// The digest of a check of `signature` by `public_key` over `signed` with `algorithm`. The key and the signature
    /// go behind their two-octet lengths (each is RDATA, under 65536 octets), the signed data last, so no two
    /// checks share their input.
    pub(crate) fn digest(
        algorithm: SecAlgorithm,
        public_key: &[u8],
        signature: &[u8],
        signed: &[u8],
    ) -> Digest {
        let mut context = Context::new(&SHA256);
        context.update(&[algorithm.0]);
        for field in [public_key, signature] {
            let [.., high, low] = field.len().to_be_bytes();
            context.update(&[high, low]);
            context.update(field);
        }
        context.update(signed);
        let mut digest = [0; SHA256_OUTPUT_LEN];
        digest.copy_from_slice(context.finish().as_ref());
        digest
    }

    /// The generations. A panic of another thread leaves them whole (an insert or a move between two sets cannot
    /// panic halfway but by allocating), so poisoning is ignored.
    fn lock(&self) -> MutexGuard<'_, Generations> {
        self.sets.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Whether the check of `digest` succeeded before, and was asked about recently enough to be kept.
    pub(crate) fn holds(&self, digest: &Digest) -> bool {
        let mut sets = self.lock();
        if sets.newest.contains(digest) {
            return true;
        }
        let held = sets.older.remove(digest);
        if held {
            self.put(&mut sets, *digest);
        }
        held
    }

    /// Keeps `digest`, a check that succeeded.
    pub(crate) fn insert(&self, digest: Digest) {
        let mut sets = self.lock();
        self.put(&mut sets, digest);
    }

    fn put(&self, sets: &mut Generations, digest: Digest) {
        if sets.newest.len() >= self.generation {
            sets.older = mem::take(&mut sets.newest);
        }
        sets.newest.insert(digest);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn digest(n: u8) -> Digest {
        Memo::digest(SecAlgorithm::ECDSAP256SHA256, &[n], b"signature", b"signed")
    }

    #[test]
    fn no_entries_is_no_memo() {
        assert!(Memo::new(0).is_none());
    }

    #[test]
    fn a_digest_tells_every_field_and_their_bounds_apart() {
        let base = Memo::digest(SecAlgorithm::ECDSAP256SHA256, b"key", b"sig", b"data");
        let others = [
            Memo::digest(SecAlgorithm::ED25519, b"key", b"sig", b"data"),
            Memo::digest(SecAlgorithm::ECDSAP256SHA256, b"keys", b"ig", b"data"),
            Memo::digest(SecAlgorithm::ECDSAP256SHA256, b"key", b"sigd", b"ata"),
            Memo::digest(SecAlgorithm::ECDSAP256SHA256, b"key", b"sig", b"date"),
        ];
        assert!(others.iter().all(|other| *other != base));
    }

    #[test]
    fn a_digest_is_held_once_inserted_and_not_before() {
        let memo = Memo::new(4).expect("4 entries");
        assert!(!memo.holds(&digest(1)));
        memo.insert(digest(1));
        assert!(memo.holds(&digest(1)));
        assert!(!memo.holds(&digest(2)));
    }

    /// The digests of each generation, newest first.
    fn generations(memo: &Memo) -> [HashSet<Digest>; 2] {
        let sets = memo.lock();
        [sets.newest.clone(), sets.older.clone()]
    }

    /// Two generations of two: the third insert starts a generation; 1, asked about, moves to it; the fourth
    /// insert starts another and drops 2, not asked about since the first.
    #[test]
    fn what_is_not_asked_about_for_a_generation_goes() {
        let memo = Memo::new(4).expect("4 entries");
        for n in 1..=3 {
            memo.insert(digest(n));
        }
        assert!(memo.holds(&digest(1)));
        memo.insert(digest(4));
        let [newest, older] = generations(&memo);
        assert_eq!(newest, HashSet::from([digest(4)]));
        assert_eq!(older, HashSet::from([digest(3), digest(1)]));
        assert!(!memo.holds(&digest(2)));
    }

    #[test]
    fn the_entries_never_exceed_the_bound() {
        let memo = Memo::new(5).expect("5 entries");
        for n in 0..100 {
            memo.insert(digest(n));
            let [newest, older] = generations(&memo);
            assert!(newest.len() + older.len() <= 6, "two generations of 3");
        }
    }
}
