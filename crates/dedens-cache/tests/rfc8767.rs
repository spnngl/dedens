//! RFC 8767 serve-stale.

mod common;

use common::{T0, a, insert, key_of, lookup, query, response, small_cache, ttls};
use dedens_cache::{Freshness, Hit, Lookup, StalePolicy};
use dedens_proto::{Rcode, RecordType};

fn cached() -> (dedens_cache::Cache, Vec<u8>) {
    let cache = small_cache();
    let q = query(1, "www.example", RecordType::A);
    let r = response(
        "www.example",
        RecordType::A,
        Rcode::NOERROR,
        vec![a("www.example", 60, 1)],
        vec![],
    );
    insert(&cache, &q, &r, T0).expect("a cacheable answer");
    (cache, q)
}

fn freshness(found: Lookup) -> Option<Freshness> {
    match found {
        Lookup::Hit(Hit { freshness, .. }) => Some(freshness),
        _ => None,
    }
}

#[test]
fn expired_data_answers_only_when_allowed() {
    let (cache, q) = cached();
    let later = T0 + 61;
    // Kept, not served: the caller resolves, and may answer with it once the client's timer runs out.
    assert_eq!(
        lookup(&cache, &q, later, StalePolicy::Never).0,
        Lookup::Expired
    );
    assert_eq!(
        lookup(&cache, &q, later, StalePolicy::IfFailing).0,
        Lookup::Expired
    );
    let (found, served) = lookup(&cache, &q, later, StalePolicy::Always);
    assert_eq!(freshness(found), Some(Freshness::Stale));
    // §4: stale records carry a short TTL, 30 seconds recommended.
    assert_eq!(ttls(&served.unwrap()), [30]);
}

/// §5: when resolution fails, stale data answers.
#[test]
fn stale_data_answers_while_resolution_fails() {
    let (cache, q) = cached();
    let later = T0 + 61;
    let hold = cache.fail(&key_of(&q), later);
    // §5 failure recheck timer: no new attempt for 30 seconds.
    assert_eq!(hold, 30);
    let (found, _) = lookup(&cache, &q, later + 1, StalePolicy::IfFailing);
    assert_eq!(freshness(found), Some(Freshness::Stale));
    // Without stale allowed, the hold still forbids resolving.
    assert_eq!(
        lookup(&cache, &q, later + 1, StalePolicy::Never).0,
        Lookup::Failed
    );
    assert_eq!(
        lookup(&cache, &q, later + 30, StalePolicy::IfFailing).0,
        Lookup::Expired
    );
}

/// §5: expired data is kept for a bounded time, 1 to 3 days recommended.
#[test]
fn stale_data_is_dropped_after_max_stale() {
    let (cache, q) = cached();
    let end = T0 + 60 + cache.config().max_stale;
    assert!(freshness(lookup(&cache, &q, end - 1, StalePolicy::Always).0).is_some());
    assert_eq!(lookup(&cache, &q, end, StalePolicy::Always).0, Lookup::Miss);
}

#[test]
fn fresh_data_is_never_stale() {
    let (cache, q) = cached();
    let (found, _) = lookup(&cache, &q, T0 + 10, StalePolicy::Always);
    assert_eq!(freshness(found), Some(Freshness::Fresh { prefetch: false }));
}
