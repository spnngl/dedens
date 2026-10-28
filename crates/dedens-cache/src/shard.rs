//! One shard: entries in a slab, indexed by key hash, evicted by S3-FIFO under a byte budget.
//!
//! S3-FIFO (Yang et al., SOSP 2023): new entries enter a small FIFO queue taking a tenth of the budget; those hit
//! while there move to the main queue, the others leave and their hash is remembered in a ghost queue, so that
//! coming back soon sends them straight to main. Main is a FIFO with a two-bit hit counter reinserting hit
//! entries. One-hit wonders, most of DNS traffic's long tail, leave fast without flushing popular names.

use std::collections::{HashMap, VecDeque};
use std::hash::{BuildHasherDefault, Hasher};

use crate::key::MAX_KEY_LEN;
use crate::response::Response;

/// Bytes counted for an entry besides its key and response: slab slot, index slot, queue slot.
const ENTRY_OVERHEAD: usize = 128;

/// The least budget of a shard: one failure record of the longest key, so a failure always fits.
pub(crate) const MIN_BUDGET: usize = ENTRY_OVERHEAD + MAX_KEY_LEN;

/// Highest hit count kept, so an entry popular once leaves main after a few rounds without hits.
const MAX_FREQ: u8 = 3;

/// The hashes are already keyed `SipHash`: pass them through.
#[derive(Default)]
struct Prehashed(u64);

impl Hasher for Prehashed {
    fn finish(&self) -> u64 {
        self.0
    }

    fn write(&mut self, bytes: &[u8]) {
        for &b in bytes {
            self.0 = self.0.rotate_left(8) ^ u64::from(b);
        }
    }

    fn write_u64(&mut self, n: u64) {
        self.0 = n;
    }
}

type Prehash = BuildHasherDefault<Prehashed>;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Queue {
    Small,
    Main,
}

/// What a shard knows of one key.
#[derive(Debug)]
pub(crate) struct Entry {
    hash: u64,
    key: Box<[u8]>,
    queue: Queue,
    freq: u8,
    /// The last response stored, fresh or stale; none while only failures are known.
    pub(crate) response: Option<Response>,
    /// Whether a prefetch was already asked for the current response.
    pub(crate) prefetched: bool,
    /// Resolution failures in a row (RFC 9520 §3.2).
    pub(crate) failures: u32,
    /// No resolution before this time.
    pub(crate) hold_until: u32,
}

impl Entry {
    fn new(hash: u64, key: &[u8], queue: Queue) -> Self {
        Self {
            hash,
            key: key.into(),
            queue,
            freq: 0,
            response: None,
            prefetched: false,
            failures: 0,
            hold_until: 0,
        }
    }

    fn cost(&self) -> usize {
        ENTRY_OVERHEAD + self.key.len() + self.response.as_ref().map_or(0, Response::cost)
    }

    /// Counts a hit, which keeps the entry through eviction rounds.
    pub(crate) fn hit(&mut self) {
        self.freq = (self.freq + 1).min(MAX_FREQ);
    }
}

/// Hashes of entries evicted from small without a hit, oldest first (S3-FIFO's ghost queue): a key met again while
/// remembered goes straight to main.
#[derive(Debug, Default)]
struct Ghosts {
    /// Each hash remembered, with the stamp of its newest place in `order`.
    stamps: HashMap<u64, u64, Prehash>,
    /// Hashes and stamps, oldest first. A place whose stamp is not the hash's in `stamps` is stale: the hash was
    /// met again, or remembered again later.
    order: VecDeque<(u64, u64)>,
    next: u64,
}

impl Ghosts {
    /// Forgets `hash`, returning whether it was remembered.
    fn take(&mut self, hash: u64) -> bool {
        self.stamps.remove(&hash).is_some()
    }

    /// Remembers `hash` as the newest, forgetting the oldest beyond `most`.
    fn remember(&mut self, hash: u64, most: usize) {
        let stamp = self.next;
        self.next += 1;
        self.stamps.insert(hash, stamp);
        self.order.push_back((hash, stamp));
        while self.stamps.len() > most {
            let Some((old, stamp)) = self.order.pop_front() else {
                break;
            };
            if self.stamps.get(&old) == Some(&stamp) {
                self.stamps.remove(&old);
            }
        }
        // Stale places outnumbering live ones are dropped at once, so `order` stays within twice the hashes.
        if self.order.len() > 2 * self.stamps.len() {
            let stamps = &self.stamps;
            self.order
                .retain(|(hash, stamp)| stamps.get(hash) == Some(stamp));
        }
    }

    #[cfg(test)]
    fn len(&self) -> usize {
        self.stamps.len()
    }
}

/// A shard; [`crate::Cache`] holds each behind its own lock.
#[derive(Debug)]
pub(crate) struct Shard {
    index: HashMap<u64, u32, Prehash>,
    slab: Vec<Option<Entry>>,
    free: Vec<u32>,
    small: VecDeque<u32>,
    main: VecDeque<u32>,
    ghosts: Ghosts,
    small_bytes: usize,
    main_bytes: usize,
    budget: usize,
}

impl Shard {
    pub(crate) fn new(budget: usize) -> Self {
        Self {
            index: HashMap::default(),
            slab: Vec::new(),
            free: Vec::new(),
            small: VecDeque::new(),
            main: VecDeque::new(),
            ghosts: Ghosts::default(),
            small_bytes: 0,
            main_bytes: 0,
            budget,
        }
    }

    /// Whether an entry with this key length and response fits the budget alone.
    pub(crate) fn fits(&self, key_len: usize, response: &Response) -> bool {
        ENTRY_OVERHEAD + key_len + response.cost() <= self.budget
    }

    /// Bytes taken by the entries.
    pub(crate) const fn used(&self) -> usize {
        self.small_bytes + self.main_bytes
    }

    /// Number of entries.
    pub(crate) fn len(&self) -> usize {
        self.index.len()
    }

    /// The entry of `key`; [`Entry::hit`] counts a hit.
    pub(crate) fn get(&mut self, hash: u64, key: &[u8]) -> Option<&mut Entry> {
        let slot = *self.index.get(&hash)?;
        let entry = self.slab[slot as usize].as_mut()?;
        (*entry.key == *key).then_some(entry)
    }

    /// Changes the entry of `key`, creating it if needed, then evicts down to the budget, and returns the number of
    /// entries evicted. An entry of another key with the same hash is replaced.
    pub(crate) fn update(
        &mut self,
        hash: u64,
        key: &[u8],
        change: impl FnOnce(&mut Entry),
    ) -> usize {
        let slot = if let Some(&slot) = self.index.get(&hash) {
            let entry = self.slab[slot as usize]
                .as_mut()
                .expect("indexed slots hold an entry");
            let before = entry.cost();
            if *entry.key != *key {
                *entry = Entry::new(hash, key, entry.queue);
            }
            change(entry);
            let (queue, after) = (entry.queue, entry.cost());
            *self.bytes(queue) = *self.bytes(queue) - before + after;
            slot
        } else {
            let queue = if self.ghosts.take(hash) {
                Queue::Main
            } else {
                Queue::Small
            };
            let mut entry = Entry::new(hash, key, queue);
            change(&mut entry);
            *self.bytes(queue) += entry.cost();
            let slot = self.alloc(entry);
            self.index.insert(hash, slot);
            match queue {
                Queue::Small => self.small.push_back(slot),
                Queue::Main => self.main.push_back(slot),
            }
            slot
        };
        self.evict(slot)
    }

    fn bytes(&mut self, queue: Queue) -> &mut usize {
        match queue {
            Queue::Small => &mut self.small_bytes,
            Queue::Main => &mut self.main_bytes,
        }
    }

    fn alloc(&mut self, entry: Entry) -> u32 {
        if let Some(slot) = self.free.pop() {
            self.slab[slot as usize] = Some(entry);
            slot
        } else {
            self.slab.push(Some(entry));
            u32::try_from(self.slab.len() - 1)
                .expect("a shard's budget holds fewer than 2^32 entries")
        }
    }

    /// Evicts until the entries fit the budget, never `keep`, the entry just changed; returns the number evicted.
    fn evict(&mut self, keep: u32) -> usize {
        let mut evicted = 0;
        let others = |q: &VecDeque<u32>| q.len() > 1 || q.front().is_some_and(|&s| s != keep);
        while self.used() > self.budget {
            let from_small = match (others(&self.small), others(&self.main)) {
                (false, false) => break,
                (true, false) => true,
                (false, true) => false,
                (true, true) => self.small_bytes > self.budget / 10,
            };
            let queue = if from_small {
                &mut self.small
            } else {
                &mut self.main
            };
            let slot = queue.pop_front().expect("the queue holds another entry");
            if slot == keep {
                queue.push_back(slot);
                continue;
            }
            let entry = self.slab[slot as usize]
                .as_mut()
                .expect("queued slots hold an entry");
            if !from_small && entry.freq > 0 {
                entry.freq -= 1;
                self.main.push_back(slot);
            } else if from_small && entry.freq > 0 {
                // Hit while in small: on to main.
                entry.freq = 0;
                entry.queue = Queue::Main;
                let cost = entry.cost();
                self.small_bytes -= cost;
                self.main_bytes += cost;
                self.main.push_back(slot);
            } else {
                let hash = entry.hash;
                self.remove(slot);
                evicted += 1;
                if from_small {
                    // As many ghosts as entries.
                    self.ghosts.remember(hash, self.index.len().max(1));
                }
            }
        }
        evicted
    }

    fn remove(&mut self, slot: u32) {
        let entry = self.slab[slot as usize]
            .take()
            .expect("removed slots hold an entry");
        *self.bytes(entry.queue) -= entry.cost();
        self.index.remove(&entry.hash);
        self.free.push(slot);
    }
}

#[cfg(test)]
mod tests {
    use proptest::prelude::*;

    use super::*;

    impl Shard {
        /// Checks the byte counts against the entries, the queues against the index, and the budget.
        fn check(&self) {
            for (queue, slots, bytes) in [
                (Queue::Small, &self.small, self.small_bytes),
                (Queue::Main, &self.main, self.main_bytes),
            ] {
                let mut sum = 0;
                for &slot in slots {
                    let entry = self.slab[slot as usize]
                        .as_ref()
                        .expect("queued slots hold an entry");
                    assert_eq!(entry.queue, queue);
                    assert_eq!(self.index[&entry.hash], slot);
                    sum += entry.cost();
                }
                assert_eq!(sum, bytes, "{queue:?}");
            }
            assert_eq!(self.small.len() + self.main.len(), self.index.len());
            assert!(
                self.used() <= self.budget,
                "{} > {}",
                self.used(),
                self.budget
            );
            assert!(
                self.index
                    .keys()
                    .all(|hash| !self.ghosts.stamps.contains_key(hash))
            );
        }
    }

    /// An entry of `len` key bytes for `hash`.
    fn key(hash: u64, len: usize) -> Vec<u8> {
        vec![u8::try_from(hash % 256).expect("a byte"); len]
    }

    proptest! {
        /// Any run of updates and hits keeps the byte counts exact and the entries within the budget.
        #[test]
        fn accounting_stays_exact(
            budget in MIN_BUDGET..8 * MIN_BUDGET,
            ops in prop::collection::vec((0_u64..24, 1..=MAX_KEY_LEN, any::<bool>()), 1..300),
        ) {
            let mut shard = Shard::new(budget);
            for (hash, len, hit) in ops {
                let key = key(hash, len);
                if hit {
                    if let Some(entry) = shard.get(hash, &key) {
                        entry.hit();
                    }
                } else {
                    shard.update(hash, &key, |entry| entry.failures += 1);
                }
                shard.check();
            }
        }
    }

    /// An entry hit in small moves to main, and stays while hit; without hits it leaves after a few rounds.
    #[test]
    fn hits_keep_an_entry_for_a_while() {
        let mut shard = Shard::new(10 * MIN_BUDGET);
        failure(&mut shard, 0);
        shard.get(0, &[0; MAX_KEY_LEN]).expect("stored").hit();
        for hash in 1..=30 {
            failure(&mut shard, hash);
            shard.check();
        }
        let slot = shard.index[&0];
        assert_eq!(
            shard.slab[slot as usize].as_ref().map(|e| e.queue),
            Some(Queue::Main)
        );
        // Hits in main buy rounds; keys coming back from the ghosts go to main and push it out in the end.
        for _ in 0..2 {
            shard.get(0, &[0; MAX_KEY_LEN]).expect("stored").hit();
        }
        for _ in 0..10 {
            // Back within ten evictions, while their ghosts last.
            for hash in 1..=15 {
                failure(&mut shard, hash);
                shard.check();
            }
        }
        assert!(shard.get(0, &[0; MAX_KEY_LEN]).is_none());
    }

    /// A key of another length under a stored hash replaces its entry.
    #[test]
    fn another_key_under_a_hash_replaces_the_entry() {
        let mut shard = Shard::new(10 * MIN_BUDGET);
        shard.update(7, &key(7, 10), |_| {});
        shard.update(7, &key(7, 200), |_| {});
        shard.check();
        assert_eq!(shard.len(), 1);
        assert!(shard.get(7, &key(7, 10)).is_none());
        assert_eq!(shard.used(), ENTRY_OVERHEAD + 200);
    }

    /// A hash met again, then remembered again, survives the trimming of its first, stale place.
    #[test]
    fn a_ghost_remembered_again_is_kept() {
        let mut ghosts = Ghosts::default();
        ghosts.remember(1, 2);
        assert!(ghosts.take(1));
        ghosts.remember(2, 2);
        ghosts.remember(1, 2);
        ghosts.remember(3, 2);
        assert_eq!(ghosts.len(), 2);
        assert!(ghosts.take(1));
        assert!(!ghosts.take(2));
        assert!(ghosts.take(3));
    }

    /// Hashes met again leave no place behind for long: the queue stays within twice the hashes remembered.
    #[test]
    fn stale_ghost_places_are_dropped() {
        let mut ghosts = Ghosts::default();
        for hash in 0..1_000 {
            ghosts.remember(hash, 10);
            ghosts.remember(hash + 10_000, 10);
            assert!(ghosts.take(hash));
            assert!(ghosts.order.len() <= 2 * ghosts.len() + 1);
        }
        assert!(ghosts.len() <= 10);
    }

    /// Entries of the longest key and no response: the failure records of `Cache::fail`.
    fn failure(shard: &mut Shard, hash: u64) {
        shard.update(hash, &[0; MAX_KEY_LEN], |_| {});
    }

    #[test]
    fn the_least_budget_holds_a_failure() {
        let mut shard = Shard::new(MIN_BUDGET);
        for hash in 0..10 {
            failure(&mut shard, hash);
            assert!(shard.used() <= MIN_BUDGET);
            assert_eq!(shard.len(), 1);
        }
    }

    /// A key evicted from small without a hit and asked again goes to main.
    #[test]
    fn a_ghost_goes_to_main() {
        let mut shard = Shard::new(10 * MIN_BUDGET);
        for hash in 0..20 {
            failure(&mut shard, hash);
        }
        assert_eq!(shard.ghosts.len(), 10);
        failure(&mut shard, 0);
        let slot = shard.index[&0];
        let entry = shard.slab[slot as usize].as_ref().unwrap();
        assert_eq!(entry.queue, Queue::Main);
    }
}
