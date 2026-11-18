//! Values under byte keys, in shards picked by key hash, each behind its own lock and held to its share of a byte
//! budget by S3-FIFO: what [`crate::Cache`] keeps its responses in, and the resolver its other caches (D116, D193).

use std::hash::{BuildHasher, RandomState};
use std::sync::{Mutex, MutexGuard, PoisonError};

use crate::config::{ConfigError, DEFAULT_ENTRY_BYTES, MAX_SHARDS};
use crate::key::MAX_KEY_LEN;
use crate::shard::Shard;

/// What a value of a [`Store`] takes besides its slot: the heap bytes it owns, charged to the byte budget (D116).
pub trait Cost {
    /// Heap bytes the value owns. Exact, or the budget does not hold: count what the allocator gives, as a boxed
    /// slice's length does, never a `Vec`'s capacity unseen.
    fn cost(&self) -> usize;
}

impl<T: Cost> Cost for Option<T> {
    fn cost(&self) -> usize {
        self.as_ref().map_or(0, T::cost)
    }
}

/// Values `V` under byte keys, shared by threads, sharded to keep lock waits short, within a byte budget.
///
/// Each shard takes an even share of the capacity and evicts by S3-FIFO when an update would take it over (D116).
/// The locks are `std`'s, held for one call and never across an `.await`.
#[derive(Debug)]
pub struct Store<V> {
    shards: Box<[Mutex<Shard<V>>]>,
    hasher: RandomState,
    limit: usize,
}

impl<V: Cost + Default> Store<V> {
    /// An empty store of `capacity` bytes in `shards` shards, whose entries take at most `max_entry_bytes` of key
    /// and value each; `None` takes [`Store::entry_limit`]'s default. The rules of `Config::capacity`,
    /// `Config::shards` and `Config::max_entry_bytes`, with the slot of `V` (D116).
    ///
    /// # Errors
    ///
    /// [`ConfigError::Shards`], [`ConfigError::Capacity`] or [`ConfigError::EntryBytes`], as `Config::validate`.
    pub fn new(
        capacity: usize,
        shards: usize,
        max_entry_bytes: Option<usize>,
    ) -> Result<Self, ConfigError> {
        let slot = Shard::<V>::SLOT_COST;
        check(capacity, shards, max_entry_bytes, slot)?;
        let limit = entry_limit(capacity, shards, max_entry_bytes, slot);
        Ok(Self {
            shards: (0..shards)
                .map(|_| Mutex::new(Shard::new(capacity / shards, limit)))
                .collect(),
            // Keyed SipHash: names chosen to collide cannot pile up in one shard or slot.
            hasher: RandomState::new(),
            limit,
        })
    }

    /// Most bytes of key and value ([`Cost`]) an entry may take: `max_entry_bytes`, else 8 KiB, or a tenth of a
    /// shard's share of the capacity less a slot if that is less (D116). The caller keeps its entries within it.
    #[must_use]
    pub const fn entry_limit(&self) -> usize {
        self.limit
    }

    /// What `read` gives of the value of `key`, if stored; `Some` counts a hit, which keeps the entry longer.
    pub fn get<R>(&self, key: &[u8], read: impl FnOnce(&V) -> Option<R>) -> Option<R> {
        let (hash, shard) = self.shard(key);
        let mut shard = lock(shard);
        let entry = shard.get(hash, key)?;
        let found = read(&entry.value)?;
        entry.hit();
        Some(found)
    }

    /// Changes the value of `key`, a default one if none is stored, then evicts down to the budget. Returns what
    /// `change` returned and the number of entries evicted. The changed entry must stay within
    /// [`Store::entry_limit`]: check the value before.
    ///
    /// # Panics
    ///
    /// Never: the shard calls `change` on every update.
    pub fn update<R>(&self, key: &[u8], change: impl FnOnce(&mut V) -> R) -> (R, usize) {
        let (hash, shard) = self.shard(key);
        let mut changed = None;
        let evicted = lock(shard).update(hash, key, |entry| {
            changed = Some(change(&mut entry.value));
        });
        (changed.expect("`Shard::update` calls `change`"), evicted)
    }

    /// The shard of `key`, and the hash it is indexed by there.
    pub(crate) fn shard(&self, key: &[u8]) -> (u64, &Mutex<Shard<V>>) {
        let hash = self.hasher.hash_one(key);
        // High bits pick the shard; the shard's table uses the low ones.
        let at = usize::try_from(hash >> 40).unwrap_or_default() & (self.shards.len() - 1);
        (hash, &self.shards[at])
    }
}

impl<V> Store<V> {
    /// Number of entries.
    #[must_use]
    pub fn len(&self) -> usize {
        self.shards.iter().map(|s| lock(s).len()).sum()
    }

    /// Whether there is no entry.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Bytes taken by the entries and what the shards keep for them (D116), at most the capacity.
    #[must_use]
    pub fn used(&self) -> usize {
        self.shards.iter().map(|s| lock(s).used()).sum()
    }
}

/// A shard is consistent between calls (no panic within), so a poisoned lock is still usable.
pub(crate) fn lock<V>(shard: &Mutex<Shard<V>>) -> MutexGuard<'_, Shard<V>> {
    shard.lock().unwrap_or_else(PoisonError::into_inner)
}

/// The most bytes an entry may hold in shards of slot `slot`: `max_entry`, else 8 KiB, or a tenth of a shard's share
/// of `capacity` less a slot if that is less (D116). Only meaningful once [`check`] passes.
pub(crate) const fn entry_limit(
    capacity: usize,
    shards: usize,
    max_entry: Option<usize>,
    slot: usize,
) -> usize {
    if let Some(bytes) = max_entry {
        return bytes;
    }
    let Some(share) = capacity.checked_div(shards) else {
        return 0;
    };
    let tenth = (share / 10).saturating_sub(slot);
    if tenth < DEFAULT_ENTRY_BYTES {
        tenth
    } else {
        DEFAULT_ENTRY_BYTES
    }
}

/// Checks the sizes of shards of slot `slot` (D116): a power of two of shards up to [`MAX_SHARDS`], and a share of
/// `capacity` holding one entry of `max_entry` bytes, at least the longest key, or, unset, a tenth of the share
/// holding the longest key; each with its slot.
pub(crate) const fn check(
    capacity: usize,
    shards: usize,
    max_entry: Option<usize>,
    slot: usize,
) -> Result<(), ConfigError> {
    if !shards.is_power_of_two() || shards > MAX_SHARDS {
        return Err(ConfigError::Shards(shards));
    }
    let share = capacity / shards;
    if let Some(bytes) = max_entry {
        if bytes < MAX_KEY_LEN {
            return Err(ConfigError::EntryBytes(MAX_KEY_LEN));
        }
        let least = slot.saturating_add(bytes);
        if share < least {
            return Err(ConfigError::Capacity(least.saturating_mul(shards)));
        }
    } else if entry_limit(capacity, shards, max_entry, slot) < MAX_KEY_LEN {
        // A tenth of the share holds a failure record and its slot.
        let least = (slot + MAX_KEY_LEN) * 10;
        return Err(ConfigError::Capacity(least.saturating_mul(shards)));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{Cost, Store};
    use crate::config::DEFAULT_ENTRY_BYTES;

    /// A value owning its bytes on the heap.
    #[derive(Debug, Default)]
    struct Bytes(Box<[u8]>);

    impl Cost for Bytes {
        fn cost(&self) -> usize {
            self.0.len()
        }
    }

    fn bytes(len: usize) -> Bytes {
        Bytes(vec![0; len].into_boxed_slice())
    }

    #[test]
    fn a_value_is_found_and_its_bytes_counted() {
        let store = Store::<Option<Bytes>>::new(1 << 20, 4, None).expect("valid sizes");
        assert!(store.is_empty());
        // A tenth of a 256 KiB share is more than the default.
        assert_eq!(store.entry_limit(), DEFAULT_ENTRY_BYTES);
        let (was, evicted) = store.update(b"key", |value| value.replace(bytes(100)).is_some());
        assert_eq!((was, evicted), (false, 0));
        assert!(!store.is_empty());
        assert_eq!(store.len(), 1);
        let used = store.used();
        store.update(b"key", |value| *value = Some(bytes(300)));
        assert_eq!(store.used() - used, 200, "the value's cost counted");
        assert_eq!(
            store.get(b"key", |value| value.as_ref().map(|b| b.0.len())),
            Some(300)
        );
        assert_eq!(
            store.get(b"other", |value| value.as_ref().map(|b| b.0.len())),
            None
        );
    }
}
