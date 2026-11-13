//! The shared cache: shards picked by key hash, each behind its own lock.

use std::hash::{BuildHasher, RandomState};
use std::sync::{Mutex, MutexGuard, PoisonError};

use dedens_proto::edns::EDE_LEN;
use dedens_proto::{Decoded, HEADER_LEN, MAX_NAME_LEN, Query};

use crate::config::{Config, ConfigError};
use crate::key::Key;
use crate::metrics::Metrics;
use crate::response::{Checked, NotCached, Refresh, Response};
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
    /// What the caller found out about the response when it stored it (D77). A [`Checked::Bogus`] hit holds the
    /// data it was stored with, which the caller does not serve.
    pub checked: Checked,
    /// The mark the response was stored with, or set by [`Cache::mark`]: 0 if none.
    pub mark: u64,
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
    /// Resolve: expired data is kept, which `stale` did not allow; [`StalePolicy::Always`] would serve it, once
    /// the client response timer runs out (RFC 8767 §5).
    Expired,
}

/// A response cache shared by threads, sharded to keep lock waits short.
#[derive(Debug)]
pub struct Cache {
    shards: Box<[Mutex<Shard>]>,
    hasher: RandomState,
    config: Config,
    metrics: Metrics,
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
                .map(|_| Mutex::new(Shard::new(budget, config.entry_limit())))
                .collect(),
            // Keyed SipHash: names chosen to collide cannot pile up in one shard or slot.
            hasher: RandomState::new(),
            config,
            metrics: Metrics::new(),
        })
    }

    /// The settings.
    #[must_use]
    pub const fn config(&self) -> &Config {
        &self.config
    }

    /// Bytes a stale hit leaves free at the end of `out` for a query with an OPT record: an EDE option without text,
    /// which the caller adds to its own OPT record (RFC 8914 §2, RFC 8767 §4). A fresh hit, and a stale one for a
    /// query without EDNS, use all of `out`.
    pub const STALE_ROOM: usize = EDE_LEN;

    /// Shortest `out` [`Cache::lookup`] takes: a header and the longest question, what a truncated response
    /// keeps at least (RFC 2181 §9), and [`Cache::STALE_ROOM`]. A shorter buffer may turn a hit into
    /// [`Lookup::Miss`]; debug builds panic.
    pub const MIN_OUT: usize = HEADER_LEN + MAX_NAME_LEN + 4 + Self::STALE_ROOM;

    /// Looks the first question of `query` up at time `now` (seconds, any monotonic origin) and writes the
    /// response into `out`, patched for the query: its ID, RD and CD bits, question case, TTLs counted down.
    /// `out` is as long as the response may be, less the OPT record the caller appends, and at least
    /// [`Cache::MIN_OUT`]; a stale hit for a query with EDNS leaves its last [`Cache::STALE_ROOM`] bytes free.
    ///
    /// A hit is copied and patched under the shard's lock, without decoding or allocating. One too large for
    /// `out` is cut where `Message::encode_truncated` cuts it, read off the offsets stored with it (D116).
    #[must_use]
    pub fn lookup(
        &self,
        query: &Query<'_>,
        now: u32,
        stale: StalePolicy,
        out: &mut [u8],
    ) -> Lookup {
        let found = self.find(query, now, stale, out, true);
        self.metrics.lookup(found);
        found
    }

    /// Writes the response [`Cache::insert`] just stored for `query` at `now` into `out`, as [`Cache::lookup`]
    /// writes a fresh hit. Not a use of the entry: no hit counted for eviction, so a name asked once stays the
    /// first to go (S3-FIFO), and no lookup counted in the metrics, so a miss is not counted a hit too. `None` when
    /// nothing fresh is stored for `query`.
    #[must_use]
    pub fn stored(&self, query: &Query<'_>, now: u32, out: &mut [u8]) -> Option<Hit> {
        match self.find(query, now, StalePolicy::Never, out, false) {
            Lookup::Hit(hit) => Some(hit),
            Lookup::Failed | Lookup::Miss | Lookup::Expired => None,
        }
    }

    /// When the response stored for `query` is due a refresh, for the one that keeps it fresh without a client.
    /// `None` when nothing fresh is stored for `query` at `now`: expired data and a failure hold do not count. Not a
    /// use of the entry, as [`Cache::stored`], and not a lookup in the metrics.
    #[must_use]
    pub fn refresh(&self, query: &Query<'_>, now: u32) -> Option<Refresh> {
        let key = Key::of(query)?;
        let (hash, shard) = self.shard(&key);
        let mut shard = lock(shard);
        let response = shard.get(hash, key.as_bytes())?.response.as_ref()?;
        (now < response.expires).then(|| response.refresh(self.config.prefetch_percent))
    }

    /// [`Cache::lookup`] without the metrics; `used` counts a hit and may ask for a prefetch.
    fn find(
        &self,
        query: &Query<'_>,
        now: u32,
        stale: StalePolicy,
        out: &mut [u8],
        used: bool,
    ) -> Lookup {
        debug_assert!(
            out.len() >= Self::MIN_OUT,
            "lookup takes at least Cache::MIN_OUT bytes"
        );
        let Some(key) = Key::of(query) else {
            return Lookup::Miss;
        };
        let (hash, shard) = self.shard(&key);
        let mut end = out.len();
        let mut shard = lock(shard);
        let Some(entry) = shard.get(hash, key.as_bytes()) else {
            return Lookup::Miss;
        };
        let nothing = if self.held(entry.hold_until, now) {
            Lookup::Failed
        } else {
            Lookup::Miss
        };
        let Some(response) = &entry.response else {
            return nothing;
        };
        let (ttl, freshness) = if now < response.expires {
            let prefetch =
                used && !entry.prefetched && response.ending(now, self.config.prefetch_percent);
            entry.prefetched |= prefetch;
            (response.left(now), Freshness::Fresh { prefetch })
        } else if now < response.stale_until {
            let allowed = match stale {
                StalePolicy::Never => false,
                StalePolicy::IfFailing => nothing == Lookup::Failed,
                StalePolicy::Always => true,
            };
            if !allowed {
                return if nothing == Lookup::Failed {
                    nothing
                } else {
                    Lookup::Expired
                };
            }
            (self.config.stale_answer_ttl, Freshness::Stale)
        } else {
            return nothing;
        };
        // The EDE option rides in the OPT record, which only a client with EDNS gets.
        if matches!(freshness, Freshness::Stale) && query.edns().is_some() {
            end = end.saturating_sub(Self::STALE_ROOM);
        }
        let served = response.serve(
            query,
            ttl,
            matches!(freshness, Freshness::Stale),
            &mut out[..end],
        );
        let (checked, mark) = (response.checked(), response.mark);
        if used {
            entry.hit();
        }
        served.map_or(Lookup::Miss, |served| {
            Lookup::Hit(Hit {
                len: served.len,
                freshness,
                truncated: served.truncated,
                checked,
                mark,
            })
        })
    }

    /// Stores `response`, received at `now` in answer to `query`, under the RFC 2308 rules; ends any failure hold
    /// of the query's key.
    ///
    /// `query` is the client's: the response is stored under its question and its DO and CD bits ([`Key::of`]).
    /// The caller asked upstream with those bits, so that a response with signatures, or unchecked, only goes to
    /// clients that asked for it. The response is [`Checked::Unchecked`]: replies have AD clear (D114). `mark` is
    /// kept with it, opaque to the cache: [`Hit::mark`] gives it back, 0 for a caller that marks nothing.
    ///
    /// # Errors
    ///
    /// [`NotCached`] says why the response is not stored.
    pub fn insert(
        &self,
        query: &Query<'_>,
        response: &Decoded<'_>,
        now: u32,
        mark: u64,
    ) -> Result<(), NotCached> {
        self.insert_checked(query, response, now, Checked::Unchecked, mark)
    }

    /// [`Cache::insert`] of a response the caller validated (D77): `checked` is kept with it and sets the AD bit of
    /// the replies served.
    ///
    /// A [`Checked::Bogus`] response lives at most `Config::bogus_ttl`, never stale, and is also stored for the
    /// clients that check for themselves, as [`Checked::Insecure`] data they are served: the bogus response
    /// answers them, not the others (RFC 4035 §3.2.2, §4.7).
    ///
    /// # Errors
    ///
    /// [`NotCached`] says why the response is not stored.
    pub fn insert_checked(
        &self,
        query: &Query<'_>,
        response: &Decoded<'_>,
        now: u32,
        checked: Checked,
        mark: u64,
    ) -> Result<(), NotCached> {
        let key = Key::of(query).ok_or(NotCached::Query)?;
        let bad = matches!(checked, Checked::Bogus(_));
        self.store(&key, response, now, (checked, mark), bad)?;
        if bad {
            self.store(
                &key.with_checking_disabled(),
                response,
                now,
                (Checked::Insecure, mark),
                bad,
            )?;
        }
        Ok(())
    }

    /// Sets the mark of the response stored for `query` to `mark`, if it is `seen` still: the caller read `seen` in
    /// a [`Hit`] and has checked the response since. A response stored meanwhile keeps its own mark. Returns
    /// whether the mark was set.
    #[must_use]
    pub fn mark(&self, query: &Query<'_>, seen: u64, mark: u64) -> bool {
        let Some(key) = Key::of(query) else {
            return false;
        };
        let (hash, shard) = self.shard(&key);
        lock(shard)
            .get(hash, key.as_bytes())
            .and_then(|entry| entry.response.as_mut())
            .is_some_and(|response| {
                let found = response.mark == seen;
                if found {
                    response.mark = mark;
                }
                found
            })
    }

    fn store(
        &self,
        key: &Key,
        response: &Decoded<'_>,
        now: u32,
        (checked, mark): (Checked, u64),
        bad: bool,
    ) -> Result<(), NotCached> {
        let (hash, shard) = self.shard(key);
        let mut response = match Response::build(key, response, now, checked, bad, &self.config) {
            Err(NotCached::TooLarge) => {
                // Answered and not stored; an answer the cache holds is stale by it, and a failure held is over.
                let evicted = lock(shard).update_existing(hash, key.as_bytes(), |entry| {
                    entry.response = None;
                    entry.prefetched = false;
                    entry.failures = 0;
                    entry.hold_until = 0;
                });
                self.metrics.evicted(evicted);
                return Err(NotCached::TooLarge);
            }
            built => built?,
        };
        response.mark = mark;
        let evicted = {
            let mut shard = lock(shard);
            shard.update(hash, key.as_bytes(), |entry| {
                entry.response = Some(response);
                entry.prefetched = false;
                entry.failures = 0;
                entry.hold_until = 0;
            })
        };
        self.metrics.inserted();
        self.metrics.evicted(evicted);
        Ok(())
    }

    /// Records that resolving `key` failed at `now`, and returns the seconds it is held (RFC 9520 §3.2): the
    /// first hold doubled on each failure in a row up to the longest, and the RFC 8767 recheck time at least
    /// when stale data answers meanwhile.
    ///
    /// A failure reported while the key is held, by a resolution started before the hold, is not counted: the
    /// seconds left of the hold are returned. Failures stop being in a row once more than the longest hold has
    /// passed since the last hold ended.
    #[expect(
        clippy::must_use_candidate,
        reason = "the hold is for logs; recording the failure is the point"
    )]
    pub fn fail(&self, key: &Key, now: u32) -> u32 {
        let config = &self.config;
        let (hash, shard) = self.shard(key);
        let mut hold = 0;
        let evicted = lock(shard).update(hash, key.as_bytes(), |entry| {
            if self.held(entry.hold_until, now) {
                hold = entry.hold_until - now;
                return;
            }
            if now.saturating_sub(entry.hold_until) > config.failure_max {
                entry.failures = 0;
            }
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
        self.metrics.evicted(evicted);
        hold
    }

    /// Whether a hold until `hold_until` is on at `now`. A hold more than `failure_max` ahead, after the clock went
    /// back, is over: no hold lasts longer (RFC 9520 §3.2).
    const fn held(&self, hold_until: u32, now: u32) -> bool {
        now < hold_until && hold_until - now <= self.config.failure_max
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

    /// Bytes taken by the entries and what the shards keep for them (D116), at most `Config::capacity`.
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
