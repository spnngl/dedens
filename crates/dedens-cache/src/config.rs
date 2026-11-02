//! Limits and timers, with the defaults the RFCs recommend.

use thiserror::Error;

use crate::key::MAX_KEY_LEN;
use crate::shard::SLOT_COST;

/// Most a resolution failure may be cached (RFC 9520 §3.2, after RFC 2308 §7).
const MAX_FAILURE_SECS: u32 = 300;

/// Cap on the TTL of an answer proved insecure unless `max_insecure_ttl` says otherwise (D93): a day, as the key
/// cache's (D86).
const INSECURE_TTL: u32 = 86_400;

/// Most bytes of an entry when `Config::max_entry_bytes` is unset and the capacity allows it (D116).
pub(crate) const DEFAULT_ENTRY_BYTES: usize = 8 << 10;

/// Most shards: bits 40 to 55 of a key's hash pick its shard, as the shard's table takes its buckets from the low
/// bits and its tags from the top 7.
pub(crate) const MAX_SHARDS: usize = 1 << 16;

/// Cache settings; [`Config::default`] follows the RFCs' recommendations. With the `serde` feature, read with
/// these field names, each defaulting to its value in [`Config::default`].
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(
    feature = "serde",
    derive(serde::Deserialize),
    serde(default, deny_unknown_fields)
)]
pub struct Config {
    /// Memory budget, in bytes, split evenly between shards: the keys and responses of the entries and what the
    /// shard keeps for each of them (its slot, index and queue places and ghost, D116). The tables' growth steps and
    /// the transient buffers of an insert are not counted; the worst case of the tables is held by a unit test, the
    /// typical one by the memory test. Each share holds at least one entry of the most `max_entry_bytes` allows, and
    /// its slot.
    pub capacity: usize,
    /// Most bytes one entry holds, its key and response, as stored (a little over the response as sent): a response
    /// larger is answered and not stored (D116). `None`: 8 KiB, or a tenth of a shard's share of the capacity less a
    /// slot if that is less, see [`Config::entry_limit`]. Keep an explicit value under a tenth of the share: a larger
    /// entry takes the small queue over, and the entries behind it leave before they are asked twice. At least the
    /// longest key, a failure record's size.
    pub max_entry_bytes: Option<usize>,
    /// Number of shards, each behind its own lock: a power of two up to 65536, a few per thread.
    pub shards: usize,
    /// Least TTL of a stored response, so that a flood of short-TTL names is not asked upstream again and again
    /// (D124): the smallest TTL of its records is raised to it, and clients see TTLs counting down from the raised
    /// lifetime, as under Unbound's `cache-min-ttl`. Not applied to a response with a TTL of 0, which stays
    /// uncached ([`NotCached::ZeroTtl`](crate::NotCached::ZeroTtl)), nor to a [`Checked::Secure`](crate::Checked::Secure)
    /// one, which its signatures' expiration bounds (RFC 4035 §5.3.3); a bogus response keeps `bogus_ttl`. Applies
    /// to negative answers too. 0 turns it off. At most `max_ttl`, `max_negative_ttl` and the insecure cap, see
    /// [`Config::insecure_ttl`].
    pub min_ttl: u32,
    /// Cap on the TTL of stored records, so that no data is served fresh for longer (D124; RFC 8767 §4 suggests 7
    /// days): 48 hours.
    pub max_ttl: u32,
    /// Cap on the TTL of negative answers (RFC 2308 §5: 1 to 3 hours).
    pub max_negative_ttl: u32,
    /// TTL of records in a stale answer (RFC 8767 §4: 30 seconds), so clients come back soon for fresh data.
    pub stale_answer_ttl: u32,
    /// How long expired data is kept to answer with when resolution fails (RFC 8767 §5: 1 to 3 days).
    pub max_stale: u32,
    /// First hold after a resolution failure, doubled on each further failure (RFC 9520 §3.2: at least 1 s).
    pub failure_min: u32,
    /// Longest hold after repeated failures (RFC 9520 §3.2: at most 5 minutes).
    pub failure_max: u32,
    /// Shortest hold when stale data answers meanwhile (RFC 8767 §5 failure recheck timer: 30 seconds), at most
    /// `failure_max`.
    pub stale_recheck: u32,
    /// Percent of its TTL left under which an entry still in use is flagged for prefetch.
    pub prefetch_percent: u8,
    /// Milliseconds a client waits for resolution before expired data answers it, resolution going on to refresh
    /// the entry (RFC 8767 §5 client response timer: 1.8 seconds); 0 waits for resolution to end. The cache's
    /// user runs the timer and looks up with [`StalePolicy::Always`](crate::StalePolicy::Always) once it ends.
    pub stale_answer_after_ms: u32,
    /// Seconds a response that failed DNSSEC validation is kept, so that a query repeated meanwhile is not
    /// validated again (D77; Unbound's `val-bogus-ttl`: 60 seconds); at least 1.
    pub bogus_ttl: u32,
    /// Cap on the TTL of a response stored as [`Checked::Insecure`](crate::Checked::Insecure), within `max_ttl`
    /// (D93): a zone that turns secure gets AD on its answers within that time. `None`: a day, or `max_ttl` if it
    /// is less. At least 1, at most `max_ttl`.
    pub max_insecure_ttl: Option<u32>,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            capacity: 64 << 20,
            max_entry_bytes: None,
            shards: 64,
            min_ttl: 60,
            max_ttl: 2 * 86_400,
            max_negative_ttl: 3 * 3_600,
            stale_answer_ttl: 30,
            max_stale: 3 * 86_400,
            failure_min: 5,
            failure_max: MAX_FAILURE_SECS,
            stale_recheck: 30,
            prefetch_percent: 10,
            stale_answer_after_ms: 1_800,
            bogus_ttl: 60,
            max_insecure_ttl: None,
        }
    }
}

/// Why a [`Config`] is refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
#[non_exhaustive]
pub enum ConfigError {
    /// The shard count is not a power of two, or above 65536.
    #[error("the shard count must be a power of two up to 65536, not {0}")]
    Shards(usize),
    /// A shard's share of the capacity cannot hold an entry of `max_entry_bytes` and its slot, or, if that is unset,
    /// a tenth of it holds less than a failure record and its slot; the least capacity is given.
    #[error("the capacity must be at least {0} bytes for this shard count and entry size")]
    Capacity(usize),
    /// `max_entry_bytes` is under the longest key, so a failure record might not fit; the least is given.
    #[error("the entry size must be at least {0} bytes")]
    EntryBytes(usize),
    /// The failure holds break RFC 9520 §3.2: at least 1 second, at most 5 minutes, the first and the stale
    /// recheck not above the longest.
    #[error(
        "failure holds must lie within 1..=300 seconds, the first and the stale recheck not above the longest"
    )]
    FailureHold,
    /// A stale answer with TTL 0 is refused by RFC 8767 §4.
    #[error("the stale answer TTL must be above 0")]
    StaleAnswerTtl,
    /// Over 100 percent.
    #[error("the prefetch threshold is a percentage, not {0}")]
    PrefetchPercent(u8),
    /// A bogus response kept for 0 seconds would not be kept.
    #[error("the bogus TTL must be above 0")]
    BogusTtl,
    /// An insecure response kept for 0 seconds would not be kept, and one kept longer than `max_ttl` would outlive
    /// the cap on every response.
    #[error("the insecure TTL must lie within 1 second and `max_ttl`")]
    InsecureTtl,
    /// A minimum TTL above `max_ttl`, `max_negative_ttl` or the insecure cap would make the cap meaningless; the
    /// least of the three is given.
    #[error(
        "the minimum TTL must be at most {0}, the least of `max_ttl`, `max_negative_ttl` and the insecure TTL"
    )]
    MinTtl(u32),
}

impl Config {
    /// The cap on the TTL of an insecure response: `max_insecure_ttl`, else a day within `max_ttl`.
    #[must_use]
    pub const fn insecure_ttl(&self) -> u32 {
        match self.max_insecure_ttl {
            Some(ttl) => ttl,
            None if self.max_ttl < INSECURE_TTL => self.max_ttl,
            None => INSECURE_TTL,
        }
    }

    /// The most bytes an entry may hold: `max_entry_bytes`, else 8 KiB, or a tenth of a shard's share of the
    /// capacity less a slot if that is less (D116). Only meaningful once [`Config::validate`] passes.
    #[must_use]
    pub const fn entry_limit(&self) -> usize {
        if let Some(bytes) = self.max_entry_bytes {
            return bytes;
        }
        let Some(share) = self.capacity.checked_div(self.shards) else {
            return 0;
        };
        let tenth = (share / 10).saturating_sub(SLOT_COST);
        if tenth < DEFAULT_ENTRY_BYTES {
            tenth
        } else {
            DEFAULT_ENTRY_BYTES
        }
    }

    /// Checks the settings against each other and the RFCs.
    ///
    /// # Errors
    ///
    /// [`ConfigError`] naming the first setting refused.
    pub const fn validate(&self) -> Result<(), ConfigError> {
        if !self.shards.is_power_of_two() || self.shards > MAX_SHARDS {
            return Err(ConfigError::Shards(self.shards));
        }
        let share = self.capacity / self.shards;
        if let Some(bytes) = self.max_entry_bytes {
            if bytes < MAX_KEY_LEN {
                return Err(ConfigError::EntryBytes(MAX_KEY_LEN));
            }
            let least = SLOT_COST.saturating_add(bytes);
            if share < least {
                return Err(ConfigError::Capacity(least.saturating_mul(self.shards)));
            }
        } else if self.entry_limit() < MAX_KEY_LEN {
            // A tenth of the share holds a failure record and its slot.
            let least = (SLOT_COST + MAX_KEY_LEN) * 10;
            return Err(ConfigError::Capacity(least.saturating_mul(self.shards)));
        }
        if self.failure_min == 0
            || self.failure_min > self.failure_max
            || self.stale_recheck > self.failure_max
            || self.failure_max > MAX_FAILURE_SECS
        {
            return Err(ConfigError::FailureHold);
        }
        if self.stale_answer_ttl == 0 {
            return Err(ConfigError::StaleAnswerTtl);
        }
        if self.prefetch_percent > 100 {
            return Err(ConfigError::PrefetchPercent(self.prefetch_percent));
        }
        if self.bogus_ttl == 0 {
            return Err(ConfigError::BogusTtl);
        }
        if let Some(ttl) = self.max_insecure_ttl
            && (ttl == 0 || ttl > self.max_ttl)
        {
            return Err(ConfigError::InsecureTtl);
        }
        let mut most = self.max_ttl;
        if self.max_negative_ttl < most {
            most = self.max_negative_ttl;
        }
        if self.insecure_ttl() < most {
            most = self.insecure_ttl();
        }
        if self.min_ttl > most {
            return Err(ConfigError::MinTtl(most));
        }
        Ok(())
    }
}
