//! One shard: entries in a slab, indexed by key hash, evicted by S3-FIFO under a byte budget.
//!
//! S3-FIFO (Yang et al., SOSP 2023): new entries enter a small FIFO queue taking a tenth of the budget; those hit
//! while there move to the main queue, the others leave and their hash is remembered in a ghost queue, so that
//! coming back soon sends them straight to main. Main is a FIFO with a two-bit hit counter reinserting hit
//! entries. One-hit wonders, most of DNS traffic's long tail, leave fast without flushing popular names.

use std::collections::{HashMap, VecDeque};
use std::hash::{BuildHasherDefault, Hasher};

use crate::response::Response;

// What a slot of the slab takes in each table, at the worst moment of its growth (D116: why these, and what the
// memory test holds them to). `a_slot_costs_what_the_tables_take_at_worst` checks each against the real tables.

/// A slab slot: an entry, the cache mark of its response included (D118), grown by an eighth at a time.
const SLAB: usize = size_of::<Option<Entry>>() * 9 / 8;
/// An index bucket just after the table doubled: 16 buckets for 7 items, and a control byte each.
const INDEX: usize = ((size_of::<(u64, u32)>() + 1) * 16).div_ceil(7);
/// The two queues and the free list, each at most twice as long as needed.
const LISTS: usize = 3 * 2 * size_of::<u32>();
/// A ghost in the table of stamps, as for the index.
const STAMPS: usize = ((size_of::<(u64, u64)>() + 1) * 16).div_ceil(7);
/// Places of the ghost queue: twice as many as ghosts, in a queue at most twice as long as needed.
const PLACES: usize = 4 * size_of::<(u64, u64)>();

/// Bytes charged for each slot of the slab, live or free, besides the key and response of its entry: the slot and its
/// places in the index, the queues, the free list and the ghosts (D116).
pub(crate) const SLOT_COST: usize = (SLAB + INDEX + LISTS + STAMPS + PLACES).next_multiple_of(16);

/// The most times one call of `Shard::evict` spares an entry of main for its hits, sending it to the back, before it
/// evicts without regard to hits (D116). Entries of small with hits move to main, each once: not counted.
const MAX_ROTATIONS: usize = 32;

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

/// What [`Shard::evict`] makes room for.
#[derive(Debug, Clone, Copy)]
enum Room {
    /// A new entry of this cost: a slot, free or grown to, and the bytes.
    Entry(usize),
    /// The entries within the budget, the entry of this slot just changed.
    Budget(u32),
}

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
        SLOT_COST + self.key.len() + self.response.as_ref().map_or(0, Response::cost)
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
        self.trim(most);
    }

    /// Forgets the oldest hashes beyond `most`.
    fn trim(&mut self, most: usize) {
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

    /// Gives back the memory the tables hold beyond their contents.
    fn shrink(&mut self) {
        let stamps = &self.stamps;
        self.order
            .retain(|(hash, stamp)| stamps.get(hash) == Some(stamp));
        self.order.shrink_to_fit();
        self.stamps.shrink_to_fit();
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
    /// Bytes of the live entries, [`Entry::cost`]; the slots of the free list are charged on top of both.
    small_bytes: usize,
    main_bytes: usize,
    budget: usize,
    /// Most slots the slab grows to, each charged [`SLOT_COST`] whether free or not: the budget less the largest
    /// entry, which so still fits with every slot in use.
    slots: usize,
}

impl Shard {
    /// A shard of `budget` bytes whose entries take at most `max_entry` bytes of key and response each (an
    /// entry of the shard in all costs [`SLOT_COST`] more).
    pub(crate) fn new(budget: usize, max_entry: usize) -> Self {
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
            slots: budget.saturating_sub(max_entry) / SLOT_COST,
        }
    }

    /// Bytes taken: the entries, each with its slot, and the slots free.
    pub(crate) const fn used(&self) -> usize {
        self.small_bytes + self.main_bytes + SLOT_COST * self.free.len()
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
        let (slot, mut evicted) = if let Some(&slot) = self.index.get(&hash) {
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
            (slot, 0)
        } else {
            let queue = if self.ghosts.take(hash) {
                Queue::Main
            } else {
                Queue::Small
            };
            let mut entry = Entry::new(hash, key, queue);
            change(&mut entry);
            let evicted = self.evict(Room::Entry(entry.cost()));
            *self.bytes(queue) += entry.cost();
            let slot = self.alloc(entry);
            self.index.insert(hash, slot);
            match queue {
                Queue::Small => self.small.push_back(slot),
                Queue::Main => self.main.push_back(slot),
            }
            (slot, evicted)
        };
        evicted += self.evict(Room::Budget(slot));
        // Free slots are charged like live ones: with over half of them free, drop them and the tables' slack.
        if self.free.len() > self.slab.len() / 2 {
            self.compact();
        }
        evicted
    }

    /// Renumbers the entries to fill the slab and gives back the room of the free slots and of what the tables held
    /// at their peak. Work in the number of slots, under the shard's lock, once the slots free outnumber the live
    /// ones; the `Vec` mapping the old numbers to the new is not counted in the budget.
    fn compact(&mut self) {
        let mut renumbered = vec![u32::MAX; self.slab.len()];
        let mut slab = Vec::with_capacity(self.index.len());
        for (old, entry) in self.slab.drain(..).enumerate() {
            if entry.is_some() {
                renumbered[old] = u32::try_from(slab.len()).expect("fewer than 2^32 slots");
                slab.push(entry);
            }
        }
        self.slab = slab;
        self.free = Vec::new();
        for queue in [&mut self.small, &mut self.main] {
            for slot in queue.iter_mut() {
                *slot = renumbered[*slot as usize];
            }
            queue.shrink_to_fit();
        }
        for slot in self.index.values_mut() {
            *slot = renumbered[*slot as usize];
        }
        self.index.shrink_to_fit();
        // Ghosts count as slots too, and the evictions from main left more of them than entries.
        self.ghosts.trim(self.slab.len());
        self.ghosts.shrink();
    }

    /// [`Shard::update`] if the shard holds `key`, else nothing.
    pub(crate) fn update_existing(
        &mut self,
        hash: u64,
        key: &[u8],
        change: impl FnOnce(&mut Entry),
    ) -> usize {
        if self.get(hash, key).is_some() {
            self.update(hash, key, change)
        } else {
            0
        }
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
            // Grows by an eighth, the slack of a larger step would count against the budget.
            if self.slab.len() == self.slab.capacity() {
                self.slab.reserve_exact(
                    (self.slab.len() / 8 + 1).min(self.slots.saturating_sub(self.slab.len())),
                );
            }
            self.slab.push(Some(entry));
            u32::try_from(self.slab.len() - 1)
                .expect("a shard's budget holds fewer than 2^32 entries")
        }
    }

    /// Evicts until there is `room`, never the entry it keeps; returns the number evicted.
    ///
    /// An entry of main with hits is spared and goes to the back, at most [`MAX_ROTATIONS`] times in one call, so that
    /// the call, which holds the shard's lock, does bounded work. After that it takes from small while that holds
    /// others, the entries of main when it does not, hits or not (D116). An entry of small with hits moves to main,
    /// once.
    fn evict(&mut self, room: Room) -> usize {
        let mut evicted = 0;
        let mut rotations = 0;
        let keep = match room {
            Room::Entry(_) => None,
            Room::Budget(slot) => Some(slot),
        };
        let others = |q: &VecDeque<u32>| q.len() > 1 || q.front().is_some_and(|&s| Some(s) != keep);
        while self.lacks(room) {
            let from_small = match (others(&self.small), others(&self.main)) {
                (false, false) => break,
                (true, false) => true,
                (false, true) => false,
                (true, true) => self.small_bytes > self.budget / 10 || rotations >= MAX_ROTATIONS,
            };
            let queue = if from_small {
                &mut self.small
            } else {
                &mut self.main
            };
            let slot = queue.pop_front().expect("the queue holds another entry");
            if Some(slot) == keep {
                queue.push_back(slot);
                continue;
            }
            let entry = self.slab[slot as usize]
                .as_mut()
                .expect("queued slots hold an entry");
            if entry.freq > 0 && (from_small || rotations < MAX_ROTATIONS) {
                if from_small {
                    // Hit while in small: on to main.
                    entry.freq = 0;
                    entry.queue = Queue::Main;
                    let cost = entry.cost();
                    self.small_bytes -= cost;
                    self.main_bytes += cost;
                } else {
                    rotations += 1;
                    entry.freq -= 1;
                }
                self.main.push_back(slot);
            } else {
                let hash = entry.hash;
                self.remove(slot);
                evicted += 1;
                if from_small {
                    // As many ghosts as entries, the one to come included.
                    let coming = usize::from(matches!(room, Room::Entry(_)));
                    self.ghosts.remember(hash, self.index.len() + coming);
                }
            }
        }
        evicted
    }

    /// Whether `room` is still to make.
    fn lacks(&self, room: Room) -> bool {
        match room {
            // A free slot is charged already: the entry takes it over.
            Room::Entry(cost) if self.free.is_empty() => {
                self.slab.len() >= self.slots || self.used() + cost > self.budget
            }
            Room::Entry(cost) => self.used() + cost - SLOT_COST > self.budget,
            Room::Budget(_) => self.used() > self.budget,
        }
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
    use crate::key::MAX_KEY_LEN;

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
            assert_eq!(self.index.len() + self.free.len(), self.slab.len());
            assert!(
                self.slab.len() <= self.slots.max(1),
                "{} slots",
                self.slab.len()
            );
            assert!(
                self.ghosts.len() <= self.slab.len(),
                "ghosts have slots too"
            );
            assert_eq!(
                self.used(),
                self.small_bytes + self.main_bytes + SLOT_COST * self.free.len()
            );
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

    /// Grows `table` one item at a time, holding the bytes it takes (`room`) to `per_item` an item at every length from
    /// 4 up (below, the fixed minimum of a table outweighs the item).
    fn grows_within<T>(
        mut table: T,
        per_item: usize,
        push: impl Fn(&mut T, u64),
        room: impl Fn(&T) -> usize,
    ) {
        for n in 1..=20_000_u64 {
            push(&mut table, n);
            let len = usize::try_from(n).expect("a count");
            if len >= 4 {
                let room = room(&table);
                assert!(
                    room <= per_item * len,
                    "{len} items take {room}, over {per_item} each"
                );
            }
        }
    }

    /// Each table of a slot takes no more than the part of `SLOT_COST` charged to it, whatever the length it has
    /// grown to: the `size_of` terms are only as good as the growth they assume.
    #[test]
    fn a_slot_costs_what_the_tables_take_at_worst() {
        // A table of buckets: `capacity` is 7/8 of them, a power of two.
        let buckets = |capacity: usize| (capacity * 8 / 7).next_power_of_two().max(4);
        grows_within(
            HashMap::<u64, u32, Prehash>::default(),
            INDEX,
            |table, n| {
                table.insert(n, 0);
            },
            |table| buckets(table.capacity()) * (size_of::<(u64, u32)>() + 1),
        );
        grows_within(
            HashMap::<u64, u64, Prehash>::default(),
            STAMPS,
            |table, n| {
                table.insert(n, 0);
            },
            |table| buckets(table.capacity()) * (size_of::<(u64, u64)>() + 1),
        );
        // Each of the queues and the free list.
        grows_within(
            VecDeque::<u32>::new(),
            LISTS / 3,
            |table, _| table.push_back(0),
            |table| table.capacity() * size_of::<u32>(),
        );
        grows_within(
            Vec::<u32>::new(),
            LISTS / 3,
            |table, _| table.push(0),
            |table| table.capacity() * size_of::<u32>(),
        );
        // The slab, grown as `alloc` does.
        grows_within(
            Shard::new(usize::MAX / 2, MAX_KEY_LEN),
            SLAB,
            |shard, n| {
                shard.alloc(Entry::new(n, &[], Queue::Small));
            },
            |shard| shard.slab.capacity() * size_of::<Option<Entry>>(),
        );

        // The places of the ghost queue: `remember` and `take` in turn leave stale places behind.
        let mut ghosts = Ghosts::default();
        let most = 1_000;
        let mut worst = 0;
        for hash in 0..50_000_u64 {
            ghosts.remember(hash, most);
            if hash % 3 == 0 {
                ghosts.take(hash);
            }
            worst = worst.max(ghosts.order.capacity() * size_of::<(u64, u64)>());
        }
        assert!(worst <= PLACES * most, "{worst} > {}", PLACES * most);
    }

    /// Puts the failure records of `hashes` in main, hit as often as they count.
    fn make_hot(shard: &mut Shard, hashes: std::ops::Range<u64>) {
        for hash in hashes {
            // A ghost goes to main.
            shard.ghosts.remember(hash, usize::MAX);
            failure(shard, hash);
            for _ in 0..MAX_FREQ {
                shard.get(hash, &[0; MAX_KEY_LEN]).expect("stored").hit();
            }
        }
        shard.check();
    }

    /// A shard of `n` entries in main, hit as often as they count.
    fn all_hot(n: usize) -> Shard {
        let mut shard = shard(n);
        make_hot(&mut shard, 0..u64::try_from(n).expect("a count"));
        assert_eq!(shard.main.len(), n);
        shard
    }

    /// Entries all hit to the most are each passed over `MAX_FREQ` times before one goes: a call to evict one entry
    /// out of many did that many rotations under the lock, 300 for 100 entries; now it stops at 32 (`MAX_ROTATIONS`).
    #[test]
    fn an_eviction_passes_over_a_bounded_number_of_entries() {
        let mut shard = all_hot(100);
        assert_eq!(shard.update(1_000, &[0; MAX_KEY_LEN], |_| {}), 1);
        shard.check();
        let rotations: usize = shard
            .slab
            .iter()
            .flatten()
            .filter(|entry| entry.queue == Queue::Main)
            .map(|entry| usize::from(MAX_FREQ - entry.freq))
            .sum();
        assert!(rotations <= 32, "{rotations} rotations");
        assert_eq!(shard.len(), 100);
    }

    /// Once the rotations are spent, the entry to go is one of small's if it holds any: hot entries of main are not
    /// evicted while cold ones wait in small.
    #[test]
    fn a_spent_eviction_takes_from_small_before_main() {
        let mut shard = shard(100);
        make_hot(&mut shard, 0..98);
        failure(&mut shard, 1_000);
        failure(&mut shard, 1_001);
        // Small holds two entries, under a tenth of the budget: main is the queue to take from first.
        assert_eq!(shard.small.len(), 2);
        assert_eq!(failure_evictions(&mut shard, 1_002), 1);
        shard.check();
        assert_eq!(shard.main.len(), 98, "a hot entry of main went");
        assert!(
            shard.get(1_000, &[0; MAX_KEY_LEN]).is_none(),
            "the oldest cold entry stays"
        );
    }

    /// Updates the failure record of `hash`, returning the number evicted.
    fn failure_evictions(shard: &mut Shard, hash: u64) -> usize {
        shard.update(hash, &[0; MAX_KEY_LEN], |_| {})
    }

    /// A shard whose slots mostly sit free is compacted: the slab, the free list and the tables shrink, and the
    /// entries are found again under their new slots.
    #[test]
    fn a_shard_mostly_free_is_compacted() {
        let mut shard = Shard::new(1_000 * FAILURE, 600 * FAILURE);
        for hash in 0..1_000 {
            failure(&mut shard, hash);
        }
        let full = shard.slab.len();
        assert!(full > 100, "{full} slots");
        // A large entry takes the room of most of them, leaving their slots free.
        let large = vec![7_u8; 600 * FAILURE - SLOT_COST];
        let survivors = full - shard.update(5_000, &large, |_| {});
        shard.check();
        assert!(survivors <= 1, "{survivors} left");
        assert!(shard.free.is_empty(), "{} slots free", shard.free.len());
        assert_eq!(shard.slab.len(), shard.len());
        assert!(shard.get(5_000, &large).is_some());
        // Entries still work after the renumbering, and fill the slots as before.
        for hash in 0..1_000 {
            failure(&mut shard, hash);
            shard.check();
        }
    }

    /// A shard with room for `entries` failure records of the longest key.
    fn shard(entries: usize) -> Shard {
        Shard::new(entries * FAILURE, MAX_KEY_LEN)
    }

    /// Bytes of a failure record of the longest key: what `failure` makes.
    const FAILURE: usize = SLOT_COST + MAX_KEY_LEN;

    /// An entry of `len` key bytes for `hash`.
    fn key(hash: u64, len: usize) -> Vec<u8> {
        vec![u8::try_from(hash % 256).expect("a byte"); len]
    }

    proptest! {
        /// Any run of updates and hits keeps the byte counts exact and the entries within the budget.
        #[test]
        fn accounting_stays_exact(
            budget in FAILURE..8 * FAILURE,
            ops in prop::collection::vec((0_u64..24, 1..=MAX_KEY_LEN, any::<bool>()), 1..300),
        ) {
            let mut shard = Shard::new(budget, MAX_KEY_LEN);
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
        let mut shard = shard(10);
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
        let mut shard = shard(10);
        shard.update(7, &key(7, 10), |_| {});
        shard.update(7, &key(7, 200), |_| {});
        shard.check();
        assert_eq!(shard.len(), 1);
        assert!(shard.get(7, &key(7, 10)).is_none());
        assert_eq!(shard.used(), SLOT_COST + 200);
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
        let mut shard = shard(1);
        for hash in 0..10 {
            failure(&mut shard, hash);
            assert!(shard.used() <= FAILURE);
            assert_eq!(shard.len(), 1);
        }
    }

    /// A key evicted from small without a hit and asked again goes to main.
    #[test]
    fn a_ghost_goes_to_main() {
        let mut shard = shard(10);
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
