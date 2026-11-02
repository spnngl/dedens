//! The counters of the `metrics` feature (D30).

#![cfg(feature = "metrics")]

mod common;

use std::collections::HashMap;

use common::{a, insert, key_of, lookup, query, response};
use dedens_cache::{Cache, Config, Lookup, StalePolicy};
use dedens_proto::{Query, Rcode, RecordType};
use metrics_util::debugging::{DebugValue, DebuggingRecorder, Snapshotter};

/// A cache whose counters go to the recorder behind the returned snapshotter.
fn recorded(config: Config) -> (Cache, Snapshotter) {
    let recorder = DebuggingRecorder::new();
    let snapshotter = recorder.snapshotter();
    let cache =
        metrics::with_local_recorder(&recorder, || Cache::new(config)).expect("a valid config");
    (cache, snapshotter)
}

/// Every counter, read once (reading drains them), as `name` or `name{label=value}`.
fn counters(snapshotter: &Snapshotter) -> HashMap<String, u64> {
    snapshotter
        .snapshot()
        .into_vec()
        .into_iter()
        .filter_map(|(key, _, _, value)| {
            let DebugValue::Counter(n) = value else {
                return None;
            };
            let (_, key) = key.into_parts();
            let labels: Vec<String> = key
                .labels()
                .map(|l| format!("{}={}", l.key(), l.value()))
                .collect();
            let name = if labels.is_empty() {
                key.name().to_owned()
            } else {
                format!("{}{{{}}}", key.name(), labels.join(","))
            };
            Some((name, n))
        })
        .collect()
}

#[test]
fn lookups_count_by_outcome() {
    let (cache, metrics) = recorded(Config::default());
    let q = query(1, "example.com.", RecordType::A);
    let r = response(
        "example.com.",
        RecordType::A,
        Rcode::NOERROR,
        vec![a("example.com.", 100, 1)],
        vec![],
    );
    assert_eq!(lookup(&cache, &q, 0, StalePolicy::Never).0, Lookup::Miss);
    insert(&cache, &q, &r, 0).unwrap();
    // Fresh, then fresh under 10% of the TTL left (a prefetch), then expired and served stale.
    lookup(&cache, &q, 10, StalePolicy::Never);
    lookup(&cache, &q, 95, StalePolicy::Never);
    lookup(&cache, &q, 200, StalePolicy::Always);
    let other = query(2, "example.net.", RecordType::A);
    let _hold = cache.fail(&key_of(&other), 0);
    assert_eq!(
        lookup(&cache, &other, 1, StalePolicy::Never).0,
        Lookup::Failed
    );

    let expected = [
        ("dedens_cache_lookups_total{outcome=hit}", 2),
        ("dedens_cache_lookups_total{outcome=stale}", 1),
        ("dedens_cache_lookups_total{outcome=failed}", 1),
        ("dedens_cache_lookups_total{outcome=miss}", 1),
        ("dedens_cache_prefetches_total", 1),
        ("dedens_cache_inserts_total", 1),
        ("dedens_cache_evictions_total", 0),
    ];
    let expected: HashMap<String, u64> = expected.map(|(name, n)| (name.to_owned(), n)).into();
    assert_eq!(counters(&metrics), expected);
}

/// A miss served from what it stored counts as the miss alone, not as a hit too.
#[test]
fn serving_what_was_just_stored_counts_no_lookup() {
    let (cache, metrics) = recorded(Config::default());
    let q = query(1, "example.com.", RecordType::A);
    let r = response(
        "example.com.",
        RecordType::A,
        Rcode::NOERROR,
        vec![a("example.com.", 100, 1)],
        vec![],
    );
    assert_eq!(lookup(&cache, &q, 0, StalePolicy::Never).0, Lookup::Miss);
    insert(&cache, &q, &r, 0).unwrap();
    let query = Query::read(&q).unwrap();
    assert!(cache.stored(&query, 0, &mut [0; 512]).is_some());
    // Under 10% of the TTL left: still no prefetch asked.
    assert!(cache.stored(&query, 95, &mut [0; 512]).is_some());
    let counters = counters(&metrics);
    assert_eq!(counters["dedens_cache_lookups_total{outcome=miss}"], 1);
    assert_eq!(counters["dedens_cache_lookups_total{outcome=hit}"], 0);
    assert_eq!(counters["dedens_cache_prefetches_total"], 0);
}

#[test]
fn evictions_count_entries_pushed_out() {
    let (cache, metrics) = recorded(Config {
        capacity: 4096,
        max_entry_bytes: Some(512),
        shards: 1,
        ..Config::default()
    });
    for i in 0..100 {
        let qname = format!("host{i}.example.com.");
        let q = query(1, &qname, RecordType::A);
        let r = response(
            &qname,
            RecordType::A,
            Rcode::NOERROR,
            vec![a(&qname, 100, 1)],
            vec![],
        );
        insert(&cache, &q, &r, 0).unwrap();
    }
    let counters = counters(&metrics);
    let evicted = counters["dedens_cache_evictions_total"];
    assert!(evicted > 0);
    assert_eq!(evicted + u64::try_from(cache.len()).unwrap(), 100);
    assert_eq!(counters["dedens_cache_inserts_total"], 100);
}
