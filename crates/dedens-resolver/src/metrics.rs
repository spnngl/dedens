//! Counters of the caches through the `metrics` facade (D30), compiled in by the `metrics` feature; without it every
//! method is empty and compiles away.
//!
//! The `RRset` cache's:
//!
//! - `dedens_resolver_rrset_lookups_total{outcome}`: lookups by result, `hit` (fresh) or `miss`.
//! - `dedens_resolver_rrset_inserts_total{outcome}`: inserts by result, as [`Inserted`]: `stored`, `verdict` (the
//!   same data held unchecked took a verdict) or `kept` (the cache trusted what it held more, RFC 2181 §5.4.1);
//!   those refused, TTL 0 or too large, are not counted.
//! - `dedens_resolver_rrset_evictions_total`: entries evicted to stay under the byte budget.
//!
//! The infra cache's:
//!
//! - `dedens_resolver_infra_selections_total{outcome}`: server selections by result, `chosen`, or `none` when every
//!   server was skipped for its timeouts.
//! - `dedens_resolver_infra_evictions_total`: entries evicted to stay under the byte budget.
//!
//! Handles are taken once, when the cache is built, from the recorder installed then: install the recorder first.

use crate::rrset_cache::Inserted;

/// The counters of one cache.
#[cfg(feature = "metrics")]
#[derive(Debug)]
pub(crate) struct Metrics {
    hits: metrics::Counter,
    misses: metrics::Counter,
    stored: metrics::Counter,
    verdict: metrics::Counter,
    kept: metrics::Counter,
    evictions: metrics::Counter,
}

/// The counters of one cache: none without the `metrics` feature.
#[cfg(not(feature = "metrics"))]
#[derive(Debug)]
pub(crate) struct Metrics;

#[cfg(feature = "metrics")]
impl Metrics {
    pub(crate) fn new() -> Self {
        const LOOKUPS: &str = "dedens_resolver_rrset_lookups_total";
        const INSERTS: &str = "dedens_resolver_rrset_inserts_total";
        const EVICTIONS: &str = "dedens_resolver_rrset_evictions_total";
        metrics::describe_counter!(LOOKUPS, "RRset cache lookups by outcome: hit or miss.");
        metrics::describe_counter!(
            INSERTS,
            "RRset cache inserts by outcome: stored, verdict or kept."
        );
        metrics::describe_counter!(
            EVICTIONS,
            "RRset cache entries evicted to stay under the byte budget."
        );
        Self {
            hits: metrics::counter!(LOOKUPS, "outcome" => "hit"),
            misses: metrics::counter!(LOOKUPS, "outcome" => "miss"),
            stored: metrics::counter!(INSERTS, "outcome" => "stored"),
            verdict: metrics::counter!(INSERTS, "outcome" => "verdict"),
            kept: metrics::counter!(INSERTS, "outcome" => "kept"),
            evictions: metrics::counter!(EVICTIONS),
        }
    }

    pub(crate) fn lookup(&self, hit: bool) {
        if hit {
            self.hits.increment(1);
        } else {
            self.misses.increment(1);
        }
    }

    pub(crate) fn inserted(&self, inserted: &Inserted, evicted: usize) {
        match inserted {
            Inserted::Stored(_) => &self.stored,
            Inserted::Verdict(_) => &self.verdict,
            Inserted::Kept(_) => &self.kept,
        }
        .increment(1);
        self.evictions
            .increment(u64::try_from(evicted).unwrap_or(u64::MAX));
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
    pub(crate) const fn lookup(&self, _: bool) {}

    #[expect(
        clippy::unused_self,
        reason = "the same calls with and without the feature"
    )]
    pub(crate) const fn inserted(&self, _: &Inserted, _: usize) {}
}

/// The counters of one infra cache.
#[cfg(feature = "metrics")]
#[derive(Debug)]
pub(crate) struct Infra {
    chosen: metrics::Counter,
    none: metrics::Counter,
    evictions: metrics::Counter,
}

/// The counters of one infra cache: none without the `metrics` feature.
#[cfg(not(feature = "metrics"))]
#[derive(Debug)]
pub(crate) struct Infra;

#[cfg(feature = "metrics")]
impl Infra {
    pub(crate) fn new() -> Self {
        const SELECTIONS: &str = "dedens_resolver_infra_selections_total";
        const EVICTIONS: &str = "dedens_resolver_infra_evictions_total";
        metrics::describe_counter!(
            SELECTIONS,
            "Infra cache server selections by outcome: chosen or none."
        );
        metrics::describe_counter!(
            EVICTIONS,
            "Infra cache entries evicted to stay under the byte budget."
        );
        Self {
            chosen: metrics::counter!(SELECTIONS, "outcome" => "chosen"),
            none: metrics::counter!(SELECTIONS, "outcome" => "none"),
            evictions: metrics::counter!(EVICTIONS),
        }
    }

    pub(crate) fn selected(&self, chosen: bool) {
        if chosen {
            self.chosen.increment(1);
        } else {
            self.none.increment(1);
        }
    }

    pub(crate) fn evicted(&self, evicted: usize) {
        self.evictions
            .increment(u64::try_from(evicted).unwrap_or(u64::MAX));
    }
}

#[cfg(not(feature = "metrics"))]
impl Infra {
    pub(crate) const fn new() -> Self {
        Self
    }

    #[expect(
        clippy::unused_self,
        reason = "the same calls with and without the feature"
    )]
    pub(crate) const fn selected(&self, _: bool) {}

    #[expect(
        clippy::unused_self,
        reason = "the same calls with and without the feature"
    )]
    pub(crate) const fn evicted(&self, _: usize) {}
}
