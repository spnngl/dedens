//! Cache counters through the `metrics` facade (D30), compiled in by the `metrics` feature; without it every
//! method is empty and compiles away.
//!
//! - `dedens_cache_lookups_total{outcome}`: lookups by result, `hit` (fresh), `stale`, `failed` (failure hold
//!   on, RFC 9520) or `miss`.
//! - `dedens_cache_prefetches_total`: fresh hits that asked for a prefetch.
//! - `dedens_cache_inserts_total`: responses stored.
//! - `dedens_cache_evictions_total`: entries evicted to stay under the byte budget.
//!
//! Handles are taken once, when the cache is built, from the recorder installed then: install the recorder first.
//! With no recorder they are no-ops.

use crate::cache::Lookup;
#[cfg(feature = "metrics")]
use crate::cache::{Freshness, Hit};

/// The counters of one cache.
#[cfg(feature = "metrics")]
pub(crate) struct Metrics {
    hits: metrics::Counter,
    stale: metrics::Counter,
    failed: metrics::Counter,
    misses: metrics::Counter,
    prefetches: metrics::Counter,
    inserts: metrics::Counter,
    evictions: metrics::Counter,
}

/// The counters of one cache: none without the `metrics` feature.
#[cfg(not(feature = "metrics"))]
pub(crate) struct Metrics;

#[cfg(feature = "metrics")]
impl Metrics {
    pub(crate) fn new() -> Self {
        const LOOKUPS: &str = "dedens_cache_lookups_total";
        metrics::describe_counter!(
            LOOKUPS,
            "Cache lookups by outcome: hit, stale, failed or miss."
        );
        metrics::describe_counter!(
            "dedens_cache_prefetches_total",
            "Fresh cache hits that asked for a prefetch."
        );
        metrics::describe_counter!(
            "dedens_cache_inserts_total",
            "Responses stored in the cache."
        );
        metrics::describe_counter!(
            "dedens_cache_evictions_total",
            "Cache entries evicted to stay under the byte budget."
        );
        Self {
            hits: metrics::counter!(LOOKUPS, "outcome" => "hit"),
            stale: metrics::counter!(LOOKUPS, "outcome" => "stale"),
            failed: metrics::counter!(LOOKUPS, "outcome" => "failed"),
            misses: metrics::counter!(LOOKUPS, "outcome" => "miss"),
            prefetches: metrics::counter!("dedens_cache_prefetches_total"),
            inserts: metrics::counter!("dedens_cache_inserts_total"),
            evictions: metrics::counter!("dedens_cache_evictions_total"),
        }
    }

    pub(crate) fn lookup(&self, lookup: Lookup) {
        match lookup {
            Lookup::Hit(Hit {
                freshness: Freshness::Fresh { prefetch },
                ..
            }) => {
                self.hits.increment(1);
                if prefetch {
                    self.prefetches.increment(1);
                }
            }
            Lookup::Hit(Hit {
                freshness: Freshness::Stale,
                ..
            }) => self.stale.increment(1),
            Lookup::Failed => self.failed.increment(1),
            Lookup::Miss => self.misses.increment(1),
        }
    }

    pub(crate) fn inserted(&self) {
        self.inserts.increment(1);
    }

    pub(crate) fn evicted(&self, entries: usize) {
        if entries > 0 {
            self.evictions
                .increment(u64::try_from(entries).unwrap_or(u64::MAX));
        }
    }
}

#[cfg(not(feature = "metrics"))]
impl Metrics {
    pub(crate) const fn new() -> Self {
        Self
    }

    #[expect(
        clippy::unused_self,
        reason = "the same calls with and without the feature"
    )]
    pub(crate) const fn lookup(&self, _: Lookup) {}

    #[expect(
        clippy::unused_self,
        reason = "the same calls with and without the feature"
    )]
    pub(crate) const fn inserted(&self) {}

    #[expect(
        clippy::unused_self,
        reason = "the same calls with and without the feature"
    )]
    pub(crate) const fn evicted(&self, _: usize) {}
}

impl core::fmt::Debug for Metrics {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Metrics").finish_non_exhaustive()
    }
}
