//! One shard: entries in a slab, indexed by key hash, evicted by S3-FIFO under a byte budget.
//!
//! S3-FIFO (Yang et al., SOSP 2023): new entries enter a small FIFO queue taking a tenth of the budget; those hit
//! while there move to the main queue, the others leave and their hash is remembered in a ghost queue, so that
//! coming back soon sends them straight to main. Main is a FIFO with a two-bit hit counter reinserting hit
//! entries. One-hit wonders, most of DNS traffic's long tail, leave fast without flushing popular names.

use std::collections::{HashMap, HashSet, VecDeque};
use std::hash::{BuildHasherDefault, Hasher};

use crate::response::Response;

/// Bytes counted for an entry besides its key and response: slab slot, index slot, queue slot.
const ENTRY_OVERHEAD: usize = 128;

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
}

/// A shard; [`crate::Cache`] holds each behind its own lock.
#[derive(Debug)]
pub(crate) struct Shard {
    index: HashMap<u64, u32, Prehash>,
    slab: Vec<Option<Entry>>,
    free: Vec<u32>,
    small: VecDeque<u32>,
    main: VecDeque<u32>,
    ghost: VecDeque<u64>,
    ghosts: HashSet<u64, Prehash>,
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
            ghost: VecDeque::new(),
            ghosts: HashSet::default(),
            small_bytes: 0,
            main_bytes: 0,
            budget,
        }
    }

    /// Whether an entry with this key length and response fits the budget alone.
    pub(crate) const fn fits(&self, key_len: usize, response: &Response) -> bool {
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

    /// The entry of `key`, counting a hit.
    pub(crate) fn get(&mut self, hash: u64, key: &[u8]) -> Option<&mut Entry> {
        let slot = *self.index.get(&hash)?;
        let entry = self.slab[slot as usize].as_mut()?;
        if *entry.key != *key {
            return None;
        }
        entry.freq = (entry.freq + 1).min(MAX_FREQ);
        Some(entry)
    }

    /// Changes the entry of `key`, creating it if needed, then evicts down to the budget. An entry of another key
    /// with the same hash is replaced.
    pub(crate) fn update(&mut self, hash: u64, key: &[u8], change: impl FnOnce(&mut Entry)) {
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
            let queue = if self.ghosts.remove(&hash) {
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
        self.evict(slot);
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

    /// Evicts until the entries fit the budget, never `keep`, the entry just changed.
    fn evict(&mut self, keep: u32) {
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
                if from_small {
                    self.remember(hash);
                }
            }
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

    /// Remembers an evicted hash, as many as there are entries.
    fn remember(&mut self, hash: u64) {
        if self.ghosts.insert(hash) {
            self.ghost.push_back(hash);
        }
        while self.ghost.len() > self.index.len().max(1) {
            if let Some(old) = self.ghost.pop_front() {
                self.ghosts.remove(&old);
            }
        }
    }
}
