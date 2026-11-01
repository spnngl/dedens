//! The key cache: what validations learned of zones, shared by the validations of one validator (D86).
//!
//! It holds what [`Zone::lifetime`] lets it hold, written by `Validation::settle` and read by
//! `Validation::zone_of`, and nothing else: secure keys, insecure zones and names that are no zone cut for the
//! TTL of the proof, and a bogus zone for 60 s. What a validation could not decide (a question left
//! unanswered, a limit, the budget) never gets here.
//!
//! Time is the caller's: every call is given `now` in Unix seconds. An entry is a hit while
//! `at <= now < at + ttl`; a `now` before `at`, the clock gone back, is a miss, so that no entry lives longer
//! than its TTL.

use std::collections::HashMap;
use std::fmt;
use std::sync::{Mutex, MutexGuard, PoisonError};

use dedens_proto::{Name, Ttl};

use super::chain::Zone;

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

/// The entries, in two tables each bound on its own: a flood of names below a signed zone, each with a proof
/// of no DS, evicts names, never the keys of zones. A name is in one table only.
#[derive(Debug, Default)]
struct Tables {
    /// Outcomes of zone apexes: keys, insecure zones, bogus ones.
    zones: HashMap<Name<'static>, Entry>,
    /// Names that are no zone cut.
    names: HashMap<Name<'static>, Entry>,
}

/// The entries of the validations of one validator.
///
/// A [`Mutex`] around plain maps: a validation takes the lock for one lookup or one insert, never across a
/// signature check, and runs only for a response the response cache lacked (D86).
pub(super) struct KeyCache {
    /// Entries of each table; 0 keeps nothing.
    capacity: usize,
    tables: Mutex<Tables>,
}

impl fmt::Debug for KeyCache {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("KeyCache")
            .field("capacity", &self.capacity)
            .finish_non_exhaustive()
    }
}

impl KeyCache {
    /// An empty cache of at most `capacity` entries in each of its two tables.
    pub(super) fn new(capacity: usize) -> Self {
        Self {
            capacity,
            tables: Mutex::new(Tables::default()),
        }
    }

    /// The tables. A panic of another thread leaves them whole (an insert is one step), so poisoning is
    /// ignored.
    fn lock(&self) -> MutexGuard<'_, Tables> {
        self.tables.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// What is known of `name` at `now`, with the TTL it has left.
    pub(super) fn get(&self, name: &Name<'static>, now: u64) -> Option<Zone> {
        let tables = self.lock();
        tables
            .zones
            .get(name)
            .or_else(|| tables.names.get(name))?
            .live(now)
    }

    /// Keeps `zone`, learned of `name` at `now`, for [`Zone::lifetime`]; what has none is not kept. A full
    /// table drops the entry that stops holding first.
    pub(super) fn put(&self, name: &Name<'static>, zone: &Zone, now: u64) {
        let Some(ttl) = zone.lifetime().filter(|ttl| *ttl != Ttl::ZERO) else {
            return;
        };
        if self.capacity == 0 {
            return;
        }
        let entry = Entry {
            zone: zone.clone(),
            at: now,
            ttl,
        };
        let mut guard = self.lock();
        let tables = &mut *guard;
        let (table, other) = match zone {
            Zone::Inside { .. } => (&mut tables.names, &mut tables.zones),
            _ => (&mut tables.zones, &mut tables.names),
        };
        other.remove(name);
        if table.len() >= self.capacity && !table.contains_key(name) {
            let first = table
                .iter()
                .min_by_key(|(_, entry)| entry.expires())
                .map(|(name, _)| name.clone());
            if let Some(first) = first {
                table.remove(&first);
            }
        }
        table.insert(name.clone(), entry);
    }
}
