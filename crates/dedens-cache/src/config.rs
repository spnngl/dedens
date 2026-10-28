//! Limits and timers, with the defaults the RFCs recommend.

use thiserror::Error;

use crate::shard::MIN_BUDGET;

/// Most a resolution failure may be cached (RFC 9520 §3.2, after RFC 2308 §7).
const MAX_FAILURE_SECS: u32 = 300;

/// Most shards: bits 40 to 55 of a key's hash pick its shard, as the shard's table takes its buckets from the low
/// bits and its tags from the top 7.
pub(crate) const MAX_SHARDS: usize = 1 << 16;

/// Cache settings; [`Config::default`] follows the RFCs' recommendations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Config {
    /// Memory budget for entries, in bytes, split evenly between shards; each share holds at least the largest
    /// failure record.
    pub capacity: usize,
    /// Number of shards, each behind its own lock: a power of two up to 65536, a few per thread.
    pub shards: usize,
    /// Cap on the TTL of stored records (RFC 8767 §4: 7 days).
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
}

impl Default for Config {
    fn default() -> Self {
        Self {
            capacity: 64 << 20,
            shards: 64,
            max_ttl: 7 * 86_400,
            max_negative_ttl: 3 * 3_600,
            stale_answer_ttl: 30,
            max_stale: 3 * 86_400,
            failure_min: 5,
            failure_max: MAX_FAILURE_SECS,
            stale_recheck: 30,
            prefetch_percent: 10,
        }
    }
}

/// Why a [`Config`] is refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum ConfigError {
    /// The shard count is not a power of two, or above 65536.
    #[error("the shard count must be a power of two up to 65536, not {0}")]
    Shards(usize),
    /// A shard's share of the capacity cannot hold one failure record; the least capacity is given.
    #[error("the capacity must be at least {0} bytes for this shard count")]
    Capacity(usize),
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
}

impl Config {
    /// Checks the settings against each other and the RFCs.
    ///
    /// # Errors
    ///
    /// [`ConfigError`] naming the first setting refused.
    pub const fn validate(&self) -> Result<(), ConfigError> {
        if !self.shards.is_power_of_two() || self.shards > MAX_SHARDS {
            return Err(ConfigError::Shards(self.shards));
        }
        if self.capacity / self.shards < MIN_BUDGET {
            return Err(ConfigError::Capacity(MIN_BUDGET * self.shards));
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
        Ok(())
    }
}
