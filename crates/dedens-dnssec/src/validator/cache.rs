//! The key cache: what validations learned of zones, shared by the validations of one validator (D86).
//!
//! It holds what [`Zone::lifetime`] lets it hold, written by `Validation::settle` and read by
//! `Validation::zone_of`, and nothing else: secure keys, insecure zones and names that are no zone cut for the
//! TTL of the proof, none for more than a day. A failure never gets here: not what a validation could not decide
//! (a question left unanswered, a limit, the budget), nor a bogus zone, which whoever answers a DNSKEY question
//! could make for every validation (D92).
//!
//! Time is the caller's: every call is given `now` in Unix seconds. An entry is a hit while
//! `at <= now < at + ttl`; a `now` before `at`, the clock gone back, is a miss, so that no entry lives longer
//! than its TTL.
//!
//! Two tables by kind, each with its own bounds in entries and bytes and its own least-recently-used order, so
//! that an attacker's flood of cheap entries (names under a zone of its own, each with a proof of no DS) evicts
//! entries of its kind and never the keys of the zones everyone asks about; and an entry of a weaker kind never
//! replaces a live one of a stronger.

use std::collections::{BTreeMap, HashMap};
use std::fmt;
use std::sync::{Mutex, MutexGuard, PoisonError};

use dedens_proto::{Name, Ttl};

use super::chain::{Settled, Zone};

/// The longest an entry is kept, whatever its proof says: Unbound's `cache-max-ttl` (D86). A signature may be
/// valid for months; a key rolled over or a DS removed should not wait for it.
const MAX_TTL: Ttl = Ttl::from_wire(86_400);

/// What an entry costs besides its names and records: the map slots, the `Arc`, the outcome. An estimate of what
/// the allocator holds, not a measurement (D86).
const ENTRY_BASE: usize = 256;

/// What the allocator holds beyond the bytes asked for, for each heap allocation of a record or a name.
const ALLOCATION: usize = 16;

/// The most one entry may cost: the keys of a zone with more than that (a DNSKEY `RRset` padded with keys that
/// no DS names, which the signature covers all the same) are used by the validation that found them and not
/// kept, so a signed zone of an attacker pins no more than this per name (D86).
const MAX_ENTRY_BYTES: usize = 16 * 1024;

/// What an entry is, which sets the table it is in and what may replace it: from the weakest to the strongest.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum Kind {
    /// A name that is no zone cut, or an insecure zone: a proof anyone can replay while its signatures last.
    Names,
    /// The keys of a secure zone.
    Keys,
}

impl Kind {
    const ALL: [Self; 2] = [Self::Names, Self::Keys];

    /// The kind of a `zone` with a [`Zone::lifetime`], the one gate of what is kept: keys, or names.
    const fn of(zone: &Zone) -> Self {
        match zone {
            Zone::Apex(Settled::Secure { .. }) => Self::Keys,
            _ => Self::Names,
        }
    }
}

/// What `zone`, kept under `name`, costs in bytes: the base, `name` twice (the slot and its recency entry), and for
/// keys their owner again and each record as the struct and the allocation of its bytes.
fn cost(name: &Name<'_>, zone: &Zone) -> usize {
    let names = ENTRY_BASE + 2 * (name.wire_len() + ALLOCATION);
    match zone {
        Zone::Apex(Settled::Secure { keys, .. }) => keys.rdatas().iter().fold(
            names + keys.owner().wire_len() + ALLOCATION,
            |bytes, rdata| {
                bytes.saturating_add(size_of_val(rdata) + rdata.wire().len() + ALLOCATION)
            },
        ),
        _ => names,
    }
}

/// An outcome, when it was learned and for how long it holds.
#[derive(Debug)]
struct Entry {
    zone: Zone,
    at: u64,
    ttl: Ttl,
}

impl Entry {
    /// When the entry stops holding, in Unix seconds.
    fn expires(&self) -> u64 {
        self.at.saturating_add(u64::from(self.ttl.get()))
    }

    /// The outcome with the TTL it has left, while it holds at `now`.
    fn live(&self, now: u64) -> Option<Zone> {
        if now < self.at {
            return None;
        }
        let left = u32::try_from(self.expires().checked_sub(now)?).ok()?;
        (left > 0).then(|| self.zone.clone().with_ttl(Ttl::from_wire(left)))
    }
}

/// An entry in a table, with its place in the recency order and its cost.
#[derive(Debug)]
struct Slot {
    entry: Entry,
    tick: u64,
    cost: usize,
}

/// The entries of one kind, bound in number and in bytes, the least recently used out first. Every operation
/// is logarithmic, so that the lock is never held for a scan.
#[derive(Debug)]
struct Table {
    slots: HashMap<Name<'static>, Slot>,
    /// The names by the tick of their last use: the first is the next to go.
    recency: BTreeMap<u64, Name<'static>>,
    tick: u64,
    bytes: usize,
    max_entries: usize,
    max_bytes: usize,
}

impl Table {
    fn new(max_entries: usize, max_bytes: usize) -> Self {
        Self {
            slots: HashMap::new(),
            recency: BTreeMap::new(),
            tick: 0,
            bytes: 0,
            max_entries,
            max_bytes,
        }
    }

    /// Whether an entry of `cost` bytes may be kept at all.
    const fn admits(&self, cost: usize) -> bool {
        self.max_entries > 0 && cost <= self.max_bytes
    }

    /// Whether a live entry of `name` is here, without counting as a use.
    fn holds(&self, name: &Name<'static>, now: u64) -> bool {
        self.slots
            .get(name)
            .is_some_and(|slot| slot.entry.live(now).is_some())
    }

    /// The live entry of `name`, which is then the most recently used; one that has expired is dropped, one
    /// from a clock that has gone back is a miss and stays.
    fn get(&mut self, name: &Name<'static>, now: u64) -> Option<Zone> {
        let slot = self.slots.get(name)?;
        let Some(zone) = slot.entry.live(now) else {
            if now >= slot.entry.at {
                self.remove(name);
            }
            return None;
        };
        self.tick += 1;
        if let Some(slot) = self.slots.get_mut(name)
            && let Some(key) = self.recency.remove(&slot.tick)
        {
            slot.tick = self.tick;
            self.recency.insert(self.tick, key);
        }
        Some(zone)
    }

    fn remove(&mut self, name: &Name<'static>) {
        if let Some(slot) = self.slots.remove(name) {
            self.recency.remove(&slot.tick);
            self.bytes = self.bytes.saturating_sub(slot.cost);
        }
    }

    /// Keeps `entry` of `cost` bytes (checked by [`Table::admits`]) for `name`, dropping the least recently used
    /// until it fits.
    fn insert(&mut self, name: &Name<'static>, entry: Entry, cost: usize) {
        self.remove(name);
        while self.slots.len() >= self.max_entries
            || self.bytes.saturating_add(cost) > self.max_bytes
        {
            let Some((_, oldest)) = self.recency.pop_first() else {
                break;
            };
            if let Some(slot) = self.slots.remove(&oldest) {
                self.bytes = self.bytes.saturating_sub(slot.cost);
            }
        }
        self.tick += 1;
        self.recency.insert(self.tick, name.clone());
        self.bytes = self.bytes.saturating_add(cost);
        self.slots.insert(
            name.clone(),
            Slot {
                entry,
                tick: self.tick,
                cost,
            },
        );
    }
}

/// The two tables.
#[derive(Debug)]
struct Tables {
    keys: Table,
    names: Table,
}

impl Tables {
    const fn of(&mut self, kind: Kind) -> &mut Table {
        match kind {
            Kind::Keys => &mut self.keys,
            Kind::Names => &mut self.names,
        }
    }
}

/// The entries of the validations of one validator.
///
/// A [`Mutex`] around plain tables: a validation takes the lock for one lookup or one insert, never across a
/// signature check, and runs only for a response the response cache lacked (D86).
pub(super) struct KeyCache {
    entries: usize,
    bytes: usize,
    tables: Mutex<Tables>,
}

impl fmt::Debug for KeyCache {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("KeyCache")
            .field("entries", &self.entries)
            .field("bytes", &self.bytes)
            .finish_non_exhaustive()
    }
}

impl KeyCache {
    /// An empty cache of at most `entries` in each of its tables, and `bytes` in all: half for keys, half
    /// for names. 0 entries keeps nothing.
    pub(super) fn new(entries: usize, bytes: usize) -> Self {
        let table = |share: usize| Table::new(entries, bytes / share);
        Self {
            entries,
            bytes,
            tables: Mutex::new(Tables {
                keys: table(2),
                names: table(2),
            }),
        }
    }

    /// The tables. A panic of another thread leaves them whole (an insert is a few steps that cannot panic), so
    /// poisoning is ignored.
    fn lock(&self) -> MutexGuard<'_, Tables> {
        self.tables.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// What is known of `name` at `now`, with the TTL it has left.
    pub(super) fn get(&self, name: &Name<'static>, now: u64) -> Option<Zone> {
        let mut tables = self.lock();
        Kind::ALL
            .into_iter()
            .rev()
            .find_map(|kind| tables.of(kind).get(name, now))
    }

    /// Keeps `zone`, learned of `name` at `now`, for [`Zone::lifetime`] and at most a day; what has no lifetime,
    /// or costs more than an entry may, is not kept, and nor is what a live entry of a stronger kind outranks:
    /// keys over names and insecure zones, so that an answer that can be replayed never takes the place of the
    /// keys.
    pub(super) fn put(&self, name: &Name<'static>, zone: &Zone, now: u64) {
        let Some(ttl) = zone.lifetime().filter(|ttl| *ttl != Ttl::ZERO) else {
            return;
        };
        let kind = Kind::of(zone);
        let cost = cost(name, zone);
        if cost > MAX_ENTRY_BYTES {
            return;
        }
        let mut tables = self.lock();
        if !tables.of(kind).admits(cost) {
            return;
        }
        if Kind::ALL
            .into_iter()
            .filter(|other| *other > kind)
            .any(|other| tables.of(other).holds(name, now))
        {
            return;
        }
        for other in Kind::ALL.into_iter().filter(|other| *other != kind) {
            tables.of(other).remove(name);
        }
        let entry = Entry {
            zone: zone.clone(),
            at: now,
            ttl: ttl.min(MAX_TTL),
        };
        tables.of(kind).insert(name, entry, cost);
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use dedens_proto::edns::InfoCode;
    use dedens_proto::rdata::{Dnskey, RData};
    use dedens_proto::{Class, Record, SecAlgorithm, WireRdata};

    use super::*;
    use crate::rrsig::RrSet;
    use crate::validator::verdict::{Failure, InsecureReason, Unusable};

    fn name(text: &str) -> Name<'static> {
        text.parse().expect("a name")
    }

    /// Keys of `owner`: `count` of them, of 32 bytes.
    fn keys(owner: &str, count: u8, ttl: u32) -> Zone {
        padded(owner, count, 32, ttl)
    }

    /// Keys of `owner`: `count` of them, of `size` bytes.
    fn padded(owner: &str, count: u8, size: usize, ttl: u32) -> Zone {
        let records: Vec<Record<'static>> = (0..count)
            .map(|index| {
                let bytes = vec![index; size];
                let key = Dnskey::new(0x0101, SecAlgorithm::ED25519, &bytes).expect("a key");
                Record {
                    name: name(owner),
                    class: Class::IN,
                    ttl: Ttl::from_wire(ttl),
                    rdata: WireRdata::new(&RData::Dnskey(key)),
                }
            })
            .collect();
        let keys = RrSet::group(&records).pop().expect("a set");
        Zone::Apex(Settled::Secure {
            keys: Arc::new(keys),
            ttl: Ttl::from_wire(ttl),
        })
    }

    fn inside(ttl: u32) -> Zone {
        Zone::Inside {
            apex: name("example"),
            ttl: Ttl::from_wire(ttl),
        }
    }

    fn insecure(ttl: u32) -> Zone {
        Zone::Apex(Settled::Unusable(Unusable::Insecure {
            reason: InsecureReason::UnsignedDelegation,
            ttl: Ttl::from_wire(ttl),
        }))
    }

    fn bogus() -> Zone {
        Zone::Apex(Settled::Unusable(Unusable::Failed(Failure::bogus(
            InfoCode::DNSSEC_BOGUS,
            "bogus",
        ))))
    }

    fn indeterminate() -> Zone {
        Zone::Apex(Settled::Unusable(Unusable::Failed(Failure::indeterminate(
            InfoCode::DNSSEC_INDETERMINATE,
            "indeterminate",
        ))))
    }

    fn is_keys(cache: &KeyCache, name: &Name<'static>, now: u64) -> bool {
        matches!(
            cache.get(name, now),
            Some(Zone::Apex(Settled::Secure { .. }))
        )
    }

    #[test]
    fn a_flood_of_names_evicts_names_and_never_keys() {
        let cache = KeyCache::new(64, 1 << 20);
        let hot = name("hot.example");
        cache.put(&hot, &keys("hot.example", 2, 300), 1000);
        for index in 0..10_000 {
            // The longest TTLs an attacker can have, to outlast anything.
            cache.put(&name(&format!("n{index}.evil")), &inside(10_800), 1000);
            cache.put(&name(&format!("i{index}.evil")), &insecure(10_800), 1000);
        }
        assert!(is_keys(&cache, &hot, 1100));
        assert!(cache.lock().names.slots.len() <= 64);
    }

    #[test]
    fn a_failure_is_never_kept() {
        // D92: a bogus zone is whatever the last answerer made of it, so the next walk asks again.
        let cache = KeyCache::new(64, 1 << 20);
        let zone = name("zone");
        for failed in [bogus(), indeterminate()] {
            cache.put(&zone, &failed, 1000);
            assert!(cache.get(&zone, 1000).is_none());
        }
        let beneath = Zone::Beneath(Unusable::Failed(Failure::bogus(
            InfoCode::DNSSEC_BOGUS,
            "bogus",
        )));
        cache.put(&name("below.zone"), &beneath, 1000);
        let tables = cache.lock();
        assert!(tables.keys.slots.is_empty() && tables.names.slots.is_empty());
    }

    #[test]
    fn the_least_recently_used_goes_first_whatever_its_ttl() {
        let cache = KeyCache::new(2, 1 << 20);
        let (a, b, c) = (name("a"), name("b"), name("c"));
        cache.put(&a, &keys("a", 1, 100), 0);
        cache.put(&b, &keys("b", 1, 100_000), 0);
        // Reading `a` makes `b` the one to go, though `a` expires first.
        assert!(is_keys(&cache, &a, 1));
        cache.put(&c, &keys("c", 1, 100), 1);
        assert!(is_keys(&cache, &a, 2) && is_keys(&cache, &c, 2));
        assert!(cache.get(&b, 2).is_none());
    }

    #[test]
    fn bytes_bound_the_tables_and_an_entry_over_its_limit_is_not_kept() {
        let one = cost(&name("a"), &keys("a", 1, 1));
        // Room for two entries of keys: half of the bytes.
        let cache = KeyCache::new(100, one * 2 * 2);
        for owner in ["a", "b", "c"] {
            cache.put(&name(owner), &keys(owner, 1, 300), 0);
        }
        assert!(cache.get(&name("a"), 1).is_none());
        assert!(is_keys(&cache, &name("b"), 1) && is_keys(&cache, &name("c"), 1));
        // A set of 255 keys of 100 bytes is over the entry limit, though a table could hold it.
        let padded = padded("padded", 255, 100, 300);
        assert!(cost(&name("padded"), &padded) > MAX_ENTRY_BYTES);
        let cache = KeyCache::new(100, 1 << 30);
        cache.put(&name("padded"), &padded, 0);
        assert!(cache.get(&name("padded"), 1).is_none());
        // Without entries or bytes, nothing is kept.
        for cache in [KeyCache::new(0, 1 << 20), KeyCache::new(10, 0)] {
            cache.put(&name("a"), &keys("a", 1, 300), 0);
            assert!(cache.get(&name("a"), 1).is_none());
        }
    }

    #[test]
    fn a_weaker_entry_never_replaces_a_live_stronger_one() {
        let cache = KeyCache::new(8, 1 << 20);
        let zone = name("zone");
        cache.put(&zone, &keys("zone", 1, 300), 0);
        for weaker in [insecure(300), inside(300)] {
            cache.put(&zone, &weaker, 10);
            assert!(is_keys(&cache, &zone, 11));
        }
        // Once the keys have expired the others may take the name, and one table holds it.
        cache.put(&zone, &insecure(300), 300);
        assert!(matches!(
            cache.get(&zone, 301),
            Some(Zone::Apex(Settled::Unusable(Unusable::Insecure { .. })))
        ));
        cache.put(&zone, &keys("zone", 1, 300), 301);
        assert!(is_keys(&cache, &zone, 302));
        assert_eq!(cache.lock().names.slots.len(), 0);
    }

    #[test]
    fn no_entry_outlives_a_day_and_none_a_clock_gone_back() {
        let cache = KeyCache::new(8, 1 << 20);
        let zone = name("zone");
        cache.put(&zone, &keys("zone", 1, 172_800), 1000);
        assert!(is_keys(&cache, &zone, 1000 + 86_399));
        assert!(cache.get(&zone, 1000 + 86_400).is_none());
        cache.put(&zone, &keys("zone", 1, 300), 1000);
        assert!(cache.get(&zone, 999).is_none());
        assert!(is_keys(&cache, &zone, 1000));
    }
}
