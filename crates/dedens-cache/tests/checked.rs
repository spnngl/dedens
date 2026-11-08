//! What the cache keeps of a verdict (D77): the AD bit of the replies follows it, never the response's own; a
//! bogus response is kept briefly (RFC 4035 §4.7), answers clients that check, and its data answers those that do
//! not (RFC 4035 §3.2.2).

mod common;

use common::{T0, a, lookup, query_with, response, small_cache, small_config, ttls};
use dedens_cache::{Cache, Checked, Config, ConfigError, Freshness, Hit, Lookup, StalePolicy};
use dedens_proto::edns::InfoCode;
use dedens_proto::{Flags, Message, Query, Rcode, RecordType};
use dedens_testkit::{captured, dns};

/// Stores a response for `www.example` A with AD as `upstream_ad` says, as `checked`.
fn store(cache: &Cache, upstream_ad: bool, checked: Checked) {
    store_for(cache, upstream_ad, true, checked);
}

/// [`store`] for the clients that set DO as `dnssec_ok` says.
fn store_for(cache: &Cache, upstream_ad: bool, dnssec_ok: bool, checked: Checked) {
    store_ttl(cache, 3600, upstream_ad, dnssec_ok, checked);
}

/// [`store_for`] of a record with TTL `ttl`.
fn store_ttl(cache: &Cache, ttl: u32, upstream_ad: bool, dnssec_ok: bool, checked: Checked) {
    let mut wire = response(
        "www.example",
        RecordType::A,
        Rcode::NOERROR,
        vec![a("www.example", ttl, 1)],
        vec![],
    );
    if upstream_ad {
        wire[3] |= 0x20;
    }
    let query = query_with(1, "www.example", RecordType::A, Flags::RD, dnssec_ok);
    cache
        .insert_checked(
            &Query::read(&query).expect("a query"),
            &Message::decode(&wire).expect("a response"),
            T0,
            checked,
            0,
        )
        .expect("a cacheable response");
}

fn ad(cache: &Cache, flags: Flags, dnssec_ok: bool) -> bool {
    let query = query_with(2, "www.example", RecordType::A, flags, dnssec_ok);
    let (found, served) = lookup(cache, &query, T0 + 1, StalePolicy::Never);
    assert!(matches!(found, Lookup::Hit(_)), "{found:?}");
    served
        .expect("a served response")
        .header
        .flags
        .contains(Flags::AD)
}

#[test]
fn a_secure_response_is_served_with_ad_to_clients_that_asked_for_it() {
    let cache = small_cache();
    store(&cache, false, Checked::Secure);
    assert!(ad(&cache, Flags::RD, true));
    assert!(ad(&cache, Flags::RD | Flags::AD, true));
}

#[test]
fn ad_is_left_out_for_clients_with_neither_ad_nor_do() {
    let cache = small_cache();
    store_for(&cache, false, false, Checked::Secure);
    assert!(!ad(&cache, Flags::RD, false), "RFC 6840 §5.8");
    assert!(ad(&cache, Flags::RD | Flags::AD, false));
}

#[test]
fn the_ad_bit_of_upstream_does_not_outlive_the_verdict() {
    // The key of a CD client holds the bogus response's data, the other's holds the verdict.
    for (checked, flags) in [
        (Checked::Insecure, Flags::RD),
        (
            Checked::Bogus(InfoCode::DNSSEC_BOGUS),
            Flags::RD | Flags::CD,
        ),
    ] {
        let cache = small_cache();
        store(&cache, true, checked);
        assert!(!ad(&cache, flags, true), "{checked:?}");
    }
    // No verdict is not secure: the AD of an unvalidated response is upstream's word, never ours (RFC 6840 §5.8,
    // RFC 4035 §3.2.3), however the client asks.
    let cache = small_cache();
    store(&cache, true, Checked::Unchecked);
    assert!(!ad(&cache, Flags::RD, true), "unchecked: AD cleared");
    assert!(!ad(&cache, Flags::RD | Flags::AD, true));
}

#[test]
fn a_bogus_response_is_kept_for_the_bogus_ttl_never_stale() {
    let cache = small_cache();
    let code = InfoCode::DNSSEC_BOGUS;
    store(&cache, false, Checked::Bogus(code));
    let query = query_with(2, "www.example", RecordType::A, Flags::RD, true);
    let (found, _) = lookup(&cache, &query, T0 + 59, StalePolicy::Always);
    let Lookup::Hit(Hit { checked, .. }) = found else {
        panic!("{found:?}")
    };
    assert_eq!(checked, Checked::Bogus(code));
    let (found, _) = lookup(&cache, &query, T0 + 61, StalePolicy::Always);
    assert!(!matches!(found, Lookup::Hit(_)), "{found:?}");
}

#[test]
fn the_data_of_a_bogus_response_answers_clients_that_disabled_checking() {
    let cache = small_cache();
    store(&cache, false, Checked::Bogus(InfoCode::DNSSEC_BOGUS));
    let query = query_with(2, "www.example", RecordType::A, Flags::RD | Flags::CD, true);
    let (found, served) = lookup(&cache, &query, T0 + 50, StalePolicy::Never);
    let Lookup::Hit(Hit { checked, .. }) = found else {
        panic!("{found:?}")
    };
    assert_eq!(checked, Checked::Insecure);
    let served = served.expect("data");
    assert_eq!(served.answer[0].name, dns("www.example"));
    assert_eq!(
        served.answer[0].ttl.get(),
        10,
        "60 seconds, not the 3600 of the record"
    );
    let (found, _) = lookup(&cache, &query, T0 + 61, StalePolicy::Always);
    assert!(!matches!(found, Lookup::Hit(_)), "{found:?}");
}

/// RFC 8767 §4: expired data answers without the signatures' time to vouch for it: a secure entry served stale
/// has no AD, whatever the client asked.
#[test]
fn a_secure_response_served_stale_has_no_ad() {
    let cache = small_cache();
    store(&cache, false, Checked::Secure);
    let query = query_with(2, "www.example", RecordType::A, Flags::RD | Flags::AD, true);
    let (found, served) = lookup(&cache, &query, T0 + 3601, StalePolicy::Always);
    assert!(matches!(found, Lookup::Hit(_)), "{found:?}");
    let served = served.expect("a served response");
    assert!(!served.header.flags.contains(Flags::AD));
}

const WEEK: u32 = 7 * 86_400;
const DAY: u32 = 86_400;
/// `Config::max_ttl` by default (D124).
const TWO_DAYS: u32 = 2 * DAY;

/// The TTL served for `www.example` A at `at`, `None` when the cache has no hit.
fn served_ttl(cache: &Cache, at: u32, stale: StalePolicy) -> Option<(u32, Freshness)> {
    let query = query_with(2, "www.example", RecordType::A, Flags::RD, true);
    let (found, served) = lookup(cache, &query, at, stale);
    let Lookup::Hit(hit) = found else { return None };
    Some((ttls(&served.expect("a served response"))[0], hit.freshness))
}

fn cache_with(max_ttl: u32, max_insecure_ttl: Option<u32>) -> Cache {
    Cache::new(Config {
        capacity: 1 << 20,
        shards: 4,
        max_ttl,
        max_insecure_ttl,
        ..Config::default()
    })
    .expect("a valid config")
}

/// D93: an answer proved insecure is kept a day at most, where `max_ttl` is two days; serve-stale works on that.
#[test]
fn an_insecure_response_is_kept_a_day_not_two() {
    let cache = small_cache();
    store_ttl(&cache, WEEK, false, true, Checked::Insecure);
    assert_eq!(
        served_ttl(&cache, T0 + 1, StalePolicy::Never),
        Some((DAY - 1, Freshness::Fresh { prefetch: false }))
    );
    assert!(served_ttl(&cache, T0 + DAY, StalePolicy::Never).is_none());
    assert_eq!(
        served_ttl(&cache, T0 + DAY, StalePolicy::Always).map(|(_, freshness)| freshness),
        Some(Freshness::Stale)
    );
}

#[test]
fn a_secure_or_unchecked_response_keeps_max_ttl() {
    for checked in [Checked::Secure, Checked::Unchecked] {
        let cache = small_cache();
        store_ttl(&cache, WEEK, false, true, checked);
        assert_eq!(
            served_ttl(&cache, T0 + 1, StalePolicy::Never),
            Some((TWO_DAYS - 1, Freshness::Fresh { prefetch: false })),
            "{checked:?}"
        );
    }
}

#[test]
fn an_insecure_response_with_a_short_ttl_is_kept_as_is() {
    let cache = small_cache();
    store_ttl(&cache, 3600, false, true, Checked::Insecure);
    assert_eq!(
        served_ttl(&cache, T0 + 1, StalePolicy::Never).map(|(ttl, _)| ttl),
        Some(3599)
    );
}

#[test]
fn the_insecure_cap_is_set_and_never_above_max_ttl() {
    let set = cache_with(WEEK, Some(600));
    store_ttl(&set, WEEK, false, true, Checked::Insecure);
    assert_eq!(
        served_ttl(&set, T0 + 1, StalePolicy::Never).map(|(ttl, _)| ttl),
        Some(599)
    );
    // Left unset, the day yields to a lower `max_ttl`.
    let low = cache_with(3600, None);
    assert_eq!(low.config().insecure_ttl(), 3600);
    store_ttl(&low, WEEK, false, true, Checked::Insecure);
    assert_eq!(
        served_ttl(&low, T0 + 1, StalePolicy::Never).map(|(ttl, _)| ttl),
        Some(3599)
    );
}

#[test]
fn the_insecure_cap_is_refused_above_max_ttl_or_at_zero() {
    let with = |max_insecure_ttl| Config {
        max_ttl: 3600,
        max_insecure_ttl: Some(max_insecure_ttl),
        min_ttl: 0,
        ..Config::default()
    };
    assert_eq!(with(3601).validate(), Err(ConfigError::InsecureTtl));
    assert_eq!(with(0).validate(), Err(ConfigError::InsecureTtl));
    assert_eq!(with(3600).validate(), Ok(()));
    assert_eq!(with(1).validate(), Ok(()));
    assert_eq!(Config::default().validate(), Ok(()));
}

/// Stores the captured answer `a.bin` (example.com A, 29 s) as `checked` in a cache with `config`, and gives the
/// TTL served at `T0` and the second it expires at.
fn captured_ttl(config: Config, checked: Checked) -> (u32, u32) {
    let cache = Cache::new(config).expect("a valid config");
    let wire = captured("a");
    let query = query_with(1, "example.com", RecordType::A, Flags::RD, true);
    cache
        .insert_checked(
            &Query::read(&query).expect("a query"),
            &Message::decode(&wire).expect("a response"),
            T0,
            checked,
            0,
        )
        .expect("a cacheable response");
    let (found, served) = lookup(&cache, &query, T0, StalePolicy::Never);
    assert!(matches!(found, Lookup::Hit(_)), "{found:?}");
    let ttl = ttls(&served.expect("a served response"))[0];
    let alive = (0..=200).take_while(|s| {
        matches!(
            lookup(&cache, &query, T0 + s, StalePolicy::Never).0,
            Lookup::Hit(_)
        )
    });
    (ttl, alive.count().try_into().expect("a few seconds"))
}

/// D124: the minimum raises what no verdict bounds, and the insecure; a secure answer is bounded by its signatures
/// (RFC 4035 §5.3.3), which the cache cannot read, so it keeps the TTL the validator gave; a bogus one keeps
/// `bogus_ttl`.
#[test]
fn the_minimum_does_not_raise_a_secure_or_bogus_response() {
    let config = |min_ttl| Config {
        min_ttl,
        bogus_ttl: 30,
        ..small_config()
    };
    assert_eq!(captured_ttl(config(60), Checked::Unchecked), (60, 60));
    assert_eq!(captured_ttl(config(60), Checked::Insecure), (60, 60));
    assert_eq!(captured_ttl(config(60), Checked::Secure), (29, 29));
    assert_eq!(
        captured_ttl(config(60), Checked::Bogus(InfoCode::DNSSEC_BOGUS)),
        (30, 30)
    );
    // Off: the 29 seconds of the zone.
    assert_eq!(captured_ttl(config(0), Checked::Unchecked), (29, 29));
}

/// D124: an insecure answer is raised within its cap.
#[test]
fn an_insecure_response_is_raised_within_the_insecure_cap() {
    let config = Config {
        min_ttl: 100,
        max_insecure_ttl: Some(100),
        ..small_config()
    };
    assert_eq!(captured_ttl(config, Checked::Insecure), (100, 100));
}

/// D124: the minimum may not exceed any cap on the TTL it raises towards.
#[test]
fn the_minimum_is_refused_above_every_cap() {
    let with = |min_ttl, max_ttl, max_negative_ttl, max_insecure_ttl| Config {
        min_ttl,
        max_ttl,
        max_negative_ttl,
        max_insecure_ttl,
        ..Config::default()
    };
    assert_eq!(
        with(61, 60, 3600, None).validate(),
        Err(ConfigError::MinTtl(60))
    );
    assert_eq!(
        with(61, 3600, 60, None).validate(),
        Err(ConfigError::MinTtl(60))
    );
    assert_eq!(
        with(61, 3600, 3600, Some(60)).validate(),
        Err(ConfigError::MinTtl(60))
    );
    // A default insecure cap of a day yields to `max_ttl`: the least of the three is the one given.
    assert_eq!(
        with(3601, 3600, 7200, None).validate(),
        Err(ConfigError::MinTtl(3600))
    );
    assert_eq!(with(7200, 7200, 7200, Some(7200)).validate(), Ok(()));
    // 0 is off, whatever the caps.
    assert_eq!(with(0, 1, 1, Some(1)).validate(), Ok(()));
}
