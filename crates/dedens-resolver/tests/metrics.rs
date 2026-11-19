//! The counters of the `metrics` feature (D30): the caches' (D193, D194) and the resolution's (D191).

use std::net::{IpAddr, Ipv6Addr, SocketAddr};
use std::time::Duration;

use dedens_cache::{Checked, Config};
use dedens_proto::Name;
use dedens_resolver::{InfraCache, Inserted, Limits, Marks, Rank, Rrset, RrsetCache};
use dedens_testkit::{captured, message};
use metrics_util::debugging::{DebugValue, DebuggingRecorder, Snapshotter};

use crate::infra_cache::Seeded;

/// The counters `snapshotter` holds, as `name label` and value.
fn counters(snapshotter: &Snapshotter) -> Vec<(String, u64)> {
    snapshotter
        .snapshot()
        .into_vec()
        .into_iter()
        .filter_map(|(key, _, _, value)| {
            let DebugValue::Counter(n) = value else {
                return None;
            };
            let (_, key) = key.into_parts();
            let label = key
                .labels()
                .map(|l| l.value().to_owned())
                .collect::<String>();
            Some((format!("{} {label}", key.name()), n))
        })
        .collect()
}

#[test]
fn lookups_inserts_and_evictions_count() {
    let recorder = DebuggingRecorder::new();
    let snapshotter = recorder.snapshotter();
    let config = Config {
        shards: 1,
        max_entry_bytes: Some(2048),
        ..Config::default()
    };
    let cache = metrics::with_local_recorder(&recorder, || RrsetCache::new(4096, config))
        .expect("a valid config");
    let referral = message(&captured("referral_root"));
    let glue = Rrset::group(&referral.additional);
    let first = glue[0].clone();
    assert!(
        cache
            .get(first.owner(), first.rtype(), first.class(), 0)
            .is_none()
    );
    for set in glue {
        cache
            .insert(set, Rank::AdditionalNonAuthoritative, Checked::Unchecked, 0)
            .expect("stored");
    }
    let last = Rrset::group(&referral.additional).pop().expect("glue");
    // Kept: the same data.
    let kept = cache.insert(
        last.clone(),
        Rank::AdditionalNonAuthoritative,
        Checked::Unchecked,
        0,
    );
    assert!(matches!(kept, Ok(Inserted::Kept(_))), "{kept:?}");
    // A verdict: the same data, checked.
    let verdict = cache.insert(
        last.clone(),
        Rank::AdditionalNonAuthoritative,
        Checked::Insecure,
        0,
    );
    assert!(matches!(verdict, Ok(Inserted::Verdict(_))), "{verdict:?}");
    assert!(
        cache
            .get(last.owner(), last.rtype(), last.class(), 0)
            .is_some()
    );

    let counters = counters(&snapshotter);
    let count = |name: &str| {
        counters
            .iter()
            .find(|(n, _)| n == name)
            .map_or(0, |(_, n)| *n)
    };
    assert_eq!(count("dedens_resolver_rrset_lookups_total miss"), 1);
    assert_eq!(count("dedens_resolver_rrset_lookups_total hit"), 1);
    assert_eq!(count("dedens_resolver_rrset_inserts_total stored"), 26);
    assert_eq!(count("dedens_resolver_rrset_inserts_total kept"), 1);
    assert_eq!(count("dedens_resolver_rrset_inserts_total verdict"), 1);
    assert!(cache.len() < 26, "{} entries", cache.len());
    let evicted = count("dedens_resolver_rrset_evictions_total ");
    assert_eq!(usize::try_from(evicted).ok(), Some(26 - cache.len()));
}

#[test]
fn selections_and_evictions_count() {
    let recorder = DebuggingRecorder::new();
    let snapshotter = recorder.snapshotter();
    let capacity = 16 << 10;
    let cache = metrics::with_local_recorder(&recorder, || InfraCache::new(capacity, 1))
        .expect("a valid size");
    let servers: Vec<SocketAddr> = (0..1000)
        .map(|n| {
            SocketAddr::new(
                IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, n)),
                53,
            )
        })
        .collect();
    let mut rng = Seeded(1);
    let zone = Name::root();
    let first = servers[0];
    for _ in 0..InfraCache::TIMEOUT_LIMIT {
        cache.timeout(first, InfraCache::UNKNOWN_TIMEOUT, 0);
    }
    assert!(
        cache
            .select(&[first], &zone, InfraCache::MAX_TIMEOUT, 0, &mut rng)
            .is_none()
    );
    for &server in &servers {
        cache.reply(server, Duration::from_millis(20), Marks::default(), 0);
    }
    assert!(
        cache
            .select(&servers, &zone, InfraCache::MAX_TIMEOUT, 0, &mut rng)
            .is_some()
    );

    let counters = counters(&snapshotter);
    let count = |name: &str| {
        counters
            .iter()
            .find(|(n, _)| n == name)
            .map_or(0, |(_, n)| *n)
    };
    assert_eq!(count("dedens_resolver_infra_selections_total none"), 1);
    assert_eq!(count("dedens_resolver_infra_selections_total chosen"), 1);
    let evicted = count("dedens_resolver_infra_evictions_total ");
    assert_eq!(usize::try_from(evicted).ok(), Some(1000 - cache.len()));
}

#[test]
fn limits_count() {
    let recorder = DebuggingRecorder::new();
    let snapshotter = recorder.snapshotter();
    metrics::with_local_recorder(&recorder, || {
        let queries = Limits {
            queries: 2,
            ..Limits::default()
        };
        crate::iteration::limited("unsigned", queries);
        crate::iteration::unanswered(Limits::default());
    });
    let counters = counters(&snapshotter);
    let count = |name: &str| {
        counters
            .iter()
            .find(|(n, _)| n == name)
            .map_or(0, |(_, n)| *n)
    };
    assert_eq!(count("dedens_resolver_limits_total queries"), 1);
    assert_eq!(count("dedens_resolver_limits_total servers"), 1);
    assert_eq!(count("dedens_resolver_limits_total time"), 0);
}
