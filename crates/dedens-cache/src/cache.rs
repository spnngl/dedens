//! The shared cache: shards picked by key hash, each behind its own lock.

use std::hash::{BuildHasher, RandomState};
use std::sync::{Mutex, MutexGuard, PoisonError};

use dedens_proto::{Message, Query};

use crate::config::{Config, ConfigError};
use crate::key::Key;
use crate::response::{NotCached, Response};
use crate::shard::Shard;

/// When expired data may answer (RFC 8767 §5).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StalePolicy {
    /// Never: fresh data or nothing.
    Never,
    /// While resolving the key fails, as `Cache::fail` recorded.
    IfFailing,
    /// Whenever kept: the client's timer ran out (RFC 8767 §5 suggests 1.8 seconds) and resolution goes on.
    Always,
}

/// How fresh a hit is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Freshness {
    /// Within its TTL; `prefetch` once, the first time under `Config::prefetch_percent` of it is left.
    Fresh {
        /// Refresh the entry in the background now.
        prefetch: bool,
    },
    /// Expired, served under RFC 8767 with `Config::stale_answer_ttl`; add EDE 3 (Stale Answer, RFC 8914).
    Stale,
}

/// A response written to the caller's buffer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Hit {
    /// Bytes written.
    pub len: usize,
    /// Fresh or stale.
    pub freshness: Freshness,
    /// The response did not fit the buffer and was truncated (TC set if answer or authority records were lost).
    pub truncated: bool,
}

/// Outcome of [`Cache::lookup`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Lookup {
    /// A response for the query is in the buffer.
    Hit(Hit),
    /// Resolution failed recently and the hold is on (RFC 9520 §3.2): answer SERVFAIL, do not resolve.
    Failed,
    /// Resolve.
    Miss,
}

/// A response cache shared by threads, sharded to keep lock waits short.
#[derive(Debug)]
pub struct Cache {
    shards: Box<[Mutex<Shard>]>,
    hasher: RandomState,
    config: Config,
}

impl Cache {
    /// An empty cache.
    ///
    /// # Errors
    ///
    /// [`ConfigError`] when `config` is refused by [`Config::validate`].
    pub fn new(config: Config) -> Result<Self, ConfigError> {
        config.validate()?;
        let budget = config.capacity / config.shards;
        Ok(Self {
            shards: (0..config.shards)
                .map(|_| Mutex::new(Shard::new(budget)))
                .collect(),
            // Keyed SipHash: names chosen to collide cannot pile up in one shard or slot.
            hasher: RandomState::new(),
            config,
        })
    }

    /// The settings.
    #[must_use]
    pub const fn config(&self) -> &Config {
        &self.config
    }

    /// Looks the first question of `query` up at time `now` (seconds, any monotonic origin) and writes the
    /// response into `out`, patched for the query: its ID, RD and CD bits, question case, TTLs counted down.
    /// `out` is as long as the response may be, less the OPT record the caller appends.
    #[must_use]
    pub fn lookup(
        &self,
        query: &Query<'_>,
        now: u32,
        stale: StalePolicy,
        out: &mut [u8],
    ) -> Lookup {
        let Some(key) = Key::of(query) else {
            return Lookup::Miss;
        };
        let (hash, shard) = self.shard(&key);
        let (freshness, full) = {
            let mut shard = lock(shard);
            let Some(entry) = shard.get(hash, key.as_bytes()) else {
                return Lookup::Miss;
            };
            let held = now < entry.hold_until;
            let nothing = if held { Lookup::Failed } else { Lookup::Miss };
            let Some(response) = &entry.response else {
                return nothing;
            };
            let (ttl, freshness) = if now < response.expires {
                let prefetch =
                    !entry.prefetched && response.ending(now, self.config.prefetch_percent);
                entry.prefetched |= prefetch;
                (response.expires - now, Freshness::Fresh { prefetch })
            } else if now < response.stale_until
                && match stale {
                    StalePolicy::Never => false,
                    StalePolicy::IfFailing => held,
                    StalePolicy::Always => true,
                }
            {
                (self.config.stale_answer_ttl, Freshness::Stale)
            } else {
                return nothing;
            };
            if let Some(len) = response.serve(query, ttl, out) {
                return Lookup::Hit(Hit {
                    len,
                    freshness,
                    truncated: false,
                });
            }
            (freshness, response.serve_full(query, ttl))
        };
        // Too large for the client: the slow path, outside the lock.
        let Ok(decoded) = Message::decode(&full) else {
            return Lookup::Miss;
        };
        match decoded.message.encode_truncated(out) {
            Ok(encoded) => Lookup::Hit(Hit {
                len: encoded.len,
                freshness,
                truncated: true,
            }),
            Err(_) => Lookup::Miss,
        }
    }

    /// Stores `response`, received at `now` for the question of `key`, under the RFC 2308 rules; ends any failure
    /// hold of the key.
    ///
    /// # Errors
    ///
    /// [`NotCached`] says why the response is not stored.
    pub fn insert(&self, key: &Key, response: &[u8], now: u32) -> Result<(), NotCached> {
        let response = Response::build(key, response, now, &self.config)?;
        let (hash, shard) = self.shard(key);
        let mut shard = lock(shard);
        if !shard.fits(key.as_bytes().len(), &response) {
            return Err(NotCached::TooLarge);
        }
        shard.update(hash, key.as_bytes(), |entry| {
            entry.response = Some(response);
            entry.prefetched = false;
            entry.failures = 0;
            entry.hold_until = 0;
        });
        Ok(())
    }

    /// Records that resolving `key` failed at `now`, and returns the seconds it is held (RFC 9520 §3.2): the
    /// first hold doubled on each failure in a row up to the longest, and the RFC 8767 recheck time at least
    /// when stale data answers meanwhile.
    #[expect(
        clippy::must_use_candidate,
        reason = "the hold is for logs; recording the failure is the point"
    )]
    pub fn fail(&self, key: &Key, now: u32) -> u32 {
        let config = &self.config;
        let (hash, shard) = self.shard(key);
        let mut hold = 0;
        lock(shard).update(hash, key.as_bytes(), |entry| {
            entry.failures = entry.failures.saturating_add(1);
            let doubling = 1_u32.checked_shl(entry.failures - 1).unwrap_or(u32::MAX);
            hold = config
                .failure_min
                .saturating_mul(doubling)
                .min(config.failure_max);
            if entry.response.as_ref().is_some_and(|r| now < r.stale_until) {
                hold = hold.max(config.stale_recheck);
            }
            entry.hold_until = now.saturating_add(hold);
        });
        hold
    }

    /// Number of entries, responses and failure records.
    #[must_use]
    pub fn len(&self) -> usize {
        self.shards.iter().map(|s| lock(s).len()).sum()
    }

    /// Whether there is no entry.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Bytes taken by the entries, at most `Config::capacity`.
    #[must_use]
    pub fn used(&self) -> usize {
        self.shards.iter().map(|s| lock(s).used()).sum()
    }

    fn shard(&self, key: &Key) -> (u64, &Mutex<Shard>) {
        let hash = self.hasher.hash_one(key.as_bytes());
        // High bits pick the shard; the shard's table uses the low ones.
        let at = usize::try_from(hash >> 40).unwrap_or_default() & (self.shards.len() - 1);
        (hash, &self.shards[at])
    }
}

/// A shard is consistent between calls (no panic within), so a poisoned lock is still usable.
fn lock(shard: &Mutex<Shard>) -> MutexGuard<'_, Shard> {
    shard.lock().unwrap_or_else(PoisonError::into_inner)
}
