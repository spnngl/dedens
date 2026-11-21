//! The spans of secure NSEC and NSEC3 records the cache holds, by zone: the order in which the names of a zone are
//! chained, which a store of keys cannot give, so that the record covering a name can be found (RFC 8198 §4).
//!
//! The index holds only the owners (NSEC) or the hashes (NSEC3); the records stay in the `RRset` cache, whose
//! entries are fresh, secure or gone: an owner whose record is not found there is a miss, never a proof (D199).
//! Zones are evicted whole, the least recently used first, to keep each shard within its share of the byte budget.
//! An owner whose record is gone is dropped when a lookup misses it, so that it does not shadow its range.

use std::cmp::Ordering;
use std::collections::{BTreeSet, HashMap};
use std::hash::{BuildHasher, RandomState};
use std::mem::size_of;
use std::ops::Bound;
use std::sync::{Mutex, MutexGuard, PoisonError};

use dedens_dnssec::denial::{canonical_cmp, owner_hash};
use dedens_proto::Name;

/// The bytes of a hash of NSEC3 (RFC 5155 §3.1.4: SHA-1).
pub(crate) const HASH_LEN: usize = 20;

/// What the index counts for each owner or hash it holds, besides the bytes of the owner: the node of the B-tree it
/// sits in, an estimate, as the allocator's own rounding is not counted (D193).
const NODE: usize = 24;

/// What a hash counts for.
const HASH_COST: usize = HASH_LEN + NODE;

/// What an NSEC owner counts for.
fn owner_cost(owner: &Name<'_>) -> usize {
    size_of::<Owner>() + owner.wire_len() + NODE
}

/// An NSEC owner, ordered as RFC 4034 §6.1 orders names.
#[derive(Debug, Clone)]
struct Owner(Name<'static>);

impl PartialEq for Owner {
    fn eq(&self, other: &Self) -> bool {
        self.cmp(other) == Ordering::Equal
    }
}

impl Eq for Owner {}

impl PartialOrd for Owner {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for Owner {
    fn cmp(&self, other: &Self) -> Ordering {
        canonical_cmp(&self.0, &other.0)
    }
}

/// How a zone's records are chained, and what is indexed of them.
#[derive(Debug)]
enum Zone {
    Nsec(BTreeSet<Owner>),
    Nsec3 {
        salt: Box<[u8]>,
        iterations: u16,
        hashes: BTreeSet<[u8; HASH_LEN]>,
    },
}

/// The chain a name's zone has: what a lookup needs to find the records and to hash.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Chain {
    Nsec,
    Nsec3 { salt: Box<[u8]>, iterations: u16 },
}

/// A zone, the bytes the index counts for it, and when it was last used (the shard's `clock` then).
#[derive(Debug)]
struct Indexed {
    zone: Zone,
    used: usize,
    touched: u64,
}

/// One shard: the zones whose apex hashes to it.
#[derive(Debug, Default)]
struct Shard {
    zones: HashMap<Name<'static>, Indexed>,
    /// Counts the uses of the zones: the one with the least `touched` is evicted first.
    clock: u64,
    used: usize,
}

impl Shard {
    /// A use of a zone: a number greater than any before it in the shard.
    fn tick(&mut self) -> u64 {
        self.clock += 1;
        self.clock
    }
}

/// The index of spans, in shards behind their own locks, held for one call and never across an `.await`.
#[derive(Debug)]
pub(crate) struct Spans {
    shards: Box<[Mutex<Shard>]>,
    hasher: RandomState,
    /// The bytes a shard may count.
    share: usize,
}

impl Spans {
    /// An empty index of at most `budget` bytes in `shards` shards (a power of two).
    pub(crate) fn new(budget: usize, shards: usize) -> Self {
        Self {
            shards: (0..shards).map(|_| Mutex::default()).collect(),
            hasher: RandomState::new(),
            share: budget / shards.max(1),
        }
    }

    /// Bytes counted, at most the budget.
    pub(crate) fn used(&self) -> usize {
        self.shards.iter().map(|s| lock(s).used).sum()
    }

    fn shard(&self, apex: &Name<'_>) -> &Mutex<Shard> {
        let at = usize::try_from(self.hasher.hash_one(apex) >> 40).unwrap_or_default()
            & (self.shards.len() - 1);
        &self.shards[at]
    }

    /// Indexes `owner`, an NSEC of the zone `apex`. A zone that was chained otherwise starts over.
    pub(crate) fn add_nsec(&self, apex: &Name<'static>, owner: &Name<'static>) {
        self.add(apex, owner_cost(owner), &Chain::Nsec, |zone| match zone {
            Zone::Nsec(owners) => owners.insert(Owner(owner.clone())),
            Zone::Nsec3 { .. } => false,
        });
    }

    /// Indexes `hash`, an NSEC3 of the zone `apex` hashed as `salt` and `iterations` say. A zone that was chained
    /// otherwise, or hashed otherwise, starts over.
    pub(crate) fn add_nsec3(
        &self,
        apex: &Name<'static>,
        salt: &[u8],
        iterations: u16,
        hash: [u8; HASH_LEN],
    ) {
        let chain = Chain::Nsec3 {
            salt: salt.into(),
            iterations,
        };
        self.add(apex, HASH_COST, &chain, |zone| match zone {
            Zone::Nsec3 { hashes, .. } => hashes.insert(hash),
            Zone::Nsec(_) => false,
        });
    }

    /// Runs `insert` on the zone `apex` as `chain` says, new or reset if it was not, then evicts down to the budget;
    /// `insert` says whether it added an item of `cost` bytes.
    fn add(
        &self,
        apex: &Name<'static>,
        cost: usize,
        chain: &Chain,
        insert: impl FnOnce(&mut Zone) -> bool,
    ) {
        let mut shard = lock(self.shard(apex));
        let shard = &mut *shard;
        let fresh = || match chain {
            Chain::Nsec => Zone::Nsec(BTreeSet::new()),
            Chain::Nsec3 { salt, iterations } => Zone::Nsec3 {
                salt: salt.clone(),
                iterations: *iterations,
                hashes: BTreeSet::new(),
            },
        };
        let overhead = size_of::<Indexed>() + 2 * apex.wire_len();
        let touched = shard.tick();
        let indexed = shard.zones.entry(apex.clone()).or_insert_with(|| {
            shard.used += overhead;
            Indexed {
                zone: fresh(),
                used: overhead,
                touched,
            }
        });
        indexed.touched = touched;
        if !is_chained(&indexed.zone, chain) {
            shard.used -= indexed.used - overhead;
            indexed.zone = fresh();
            indexed.used = overhead;
        }
        if insert(&mut indexed.zone) {
            indexed.used += cost;
            shard.used += cost;
        }
        while shard.used > self.share {
            let oldest = shard
                .zones
                .iter()
                .min_by_key(|(_, indexed)| indexed.touched)
                .map(|(oldest, _)| oldest.clone());
            match oldest {
                Some(oldest) if oldest != *apex => {
                    if let Some(gone) = shard.zones.remove(&oldest) {
                        shard.used -= gone.used;
                    }
                }
                _ => {
                    // The one zone, too big: start it over, with nothing, rather than evict what was just added.
                    if let Some(indexed) = shard.zones.get_mut(apex) {
                        shard.used -= indexed.used - overhead;
                        indexed.zone = fresh();
                        indexed.used = overhead;
                    }
                    break;
                }
            }
        }
    }

    /// Drops `owner`, an NSEC of the zone `apex` whose record the cache no longer holds secure.
    pub(crate) fn forget_nsec(&self, apex: &Name<'_>, owner: &Name<'_>) {
        self.forget(apex, owner_cost(owner), |zone| match zone {
            Zone::Nsec(owners) => owners.remove(&Owner(owner.clone().into_owned())),
            Zone::Nsec3 { .. } => false,
        });
    }

    /// Drops `hash`, an NSEC3 of the zone `apex` whose record the cache no longer holds secure.
    pub(crate) fn forget_nsec3(&self, apex: &Name<'_>, hash: &[u8; HASH_LEN]) {
        self.forget(apex, HASH_COST, |zone| match zone {
            Zone::Nsec3 { hashes, .. } => hashes.remove(hash),
            Zone::Nsec(_) => false,
        });
    }

    /// Runs `remove` on the zone `apex` if the index holds it; `remove` says whether it dropped an item of `cost`
    /// bytes. The zone keeps its place in the order of use: a lookup that misses is no use.
    fn forget(&self, apex: &Name<'_>, cost: usize, remove: impl FnOnce(&mut Zone) -> bool) {
        let mut shard = lock(self.shard(apex));
        let shard = &mut *shard;
        if let Some(indexed) = shard.zones.get_mut(&apex.clone().into_owned())
            && remove(&mut indexed.zone)
        {
            indexed.used -= cost;
            shard.used -= cost;
        }
    }

    /// The deepest zone `name` is within that the index holds, with how it is chained. The zone found is the most
    /// recently used.
    pub(crate) fn zone_of(&self, name: &Name<'_>) -> Option<(Name<'static>, Chain)> {
        (0..=name.label_count()).find_map(|skip| {
            let apex = Name::from_labels(name.labels().skip(skip)).ok()?;
            let mut shard = lock(self.shard(&apex));
            let touched = shard.tick();
            let indexed = shard.zones.get_mut(&apex)?;
            indexed.touched = touched;
            Some((apex, chain_of(&indexed.zone)))
        })
    }

    /// The NSEC owner of the zone `apex` that `name` is at or after in canonical order: the one whose record covers
    /// it, or is at it; the last of the zone for a name before its first, the chain being a circle (RFC 4034 §4).
    pub(crate) fn owner_before(&self, apex: &Name<'_>, name: &Name<'_>) -> Option<Name<'static>> {
        let shard = lock(self.shard(apex));
        let Zone::Nsec(owners) = &shard.zones.get(apex)?.zone else {
            return None;
        };
        let at = Owner(name.clone().into_owned());
        let before = owners.range(..=&at).next_back().or_else(|| owners.last());
        before.map(|owner| owner.0.clone())
    }

    /// The hash of the zone `apex` that `hash` is at or after, as [`Spans::owner_before`] for NSEC3.
    pub(crate) fn hash_before(
        &self,
        apex: &Name<'_>,
        hash: &[u8; HASH_LEN],
    ) -> Option<[u8; HASH_LEN]> {
        let shard = lock(self.shard(apex));
        let Zone::Nsec3 { hashes, .. } = &shard.zones.get(apex)?.zone else {
            return None;
        };
        let before = hashes
            .range((Bound::Unbounded, Bound::Included(*hash)))
            .next_back()
            .or_else(|| hashes.last());
        before.copied()
    }
}

/// The chain `zone` has.
fn chain_of(zone: &Zone) -> Chain {
    match zone {
        Zone::Nsec(_) => Chain::Nsec,
        Zone::Nsec3 {
            salt, iterations, ..
        } => Chain::Nsec3 {
            salt: salt.clone(),
            iterations: *iterations,
        },
    }
}

/// Whether `zone` is chained and hashed as `chain` says.
fn is_chained(zone: &Zone, chain: &Chain) -> bool {
    match (zone, chain) {
        (Zone::Nsec(_), Chain::Nsec) => true,
        (
            Zone::Nsec3 {
                salt, iterations, ..
            },
            Chain::Nsec3 {
                salt: wanted,
                iterations: asked,
            },
        ) => salt == wanted && iterations == asked,
        _ => false,
    }
}

/// A shard is consistent between calls (no panic within), so a poisoned lock is still usable.
fn lock(shard: &Mutex<Shard>) -> MutexGuard<'_, Shard> {
    shard.lock().unwrap_or_else(PoisonError::into_inner)
}

/// The hash an NSEC3 record owner's first label spells, if it does.
pub(crate) fn hash_of(owner: &Name<'_>) -> Option<[u8; HASH_LEN]> {
    owner.labels().next().and_then(owner_hash)
}
