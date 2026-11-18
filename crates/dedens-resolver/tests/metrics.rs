//! The counters of the `metrics` feature (D30).

use dedens_cache::{Checked, Config};
use dedens_proto::Section;
use dedens_resolver::{Rank, Rrset, RrsetCache};
use dedens_testkit::{captured, message};
use metrics_util::debugging::{DebugValue, DebuggingRecorder};

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
            .insert(
                set,
                Rank::of(Section::Additional, false),
                Checked::Unchecked,
                0,
            )
            .expect("stored");
    }
    let last = Rrset::group(&referral.additional).pop().expect("glue");
    // Kept: the same data.
    cache
        .insert(
            last.clone(),
            Rank::AdditionalNonAuthoritative,
            Checked::Unchecked,
            0,
        )
        .expect("kept");
    assert!(
        cache
            .get(last.owner(), last.rtype(), last.class(), 0)
            .is_some()
    );

    let counters: Vec<(String, u64)> = snapshotter
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
        .collect();
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
    assert!(cache.len() < 26, "{} entries", cache.len());
    let evicted = count("dedens_resolver_rrset_evictions_total ");
    assert_eq!(usize::try_from(evicted).ok(), Some(26 - cache.len()));
}
