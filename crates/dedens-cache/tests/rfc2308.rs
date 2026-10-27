//! RFC 2308 negative caching, and the TTL rules of RFC 1035 §3.2.1 and RFC 2181 §8.

mod common;

use common::{T0, a, key_of, lookup, query, response, small_cache, soa, ttls};
use dedens_cache::{Lookup, NotCached, StalePolicy};
use dedens_proto::{Flags, Message, Rcode, RecordType};

const NEVER: StalePolicy = StalePolicy::Never;

#[test]
fn positive_answer_lives_as_long_as_its_shortest_ttl() {
    let cache = small_cache();
    let q = query(1, "www.example", RecordType::A);
    let r = response(
        "www.example",
        RecordType::A,
        Rcode::NOERROR,
        vec![a("www.example", 300, 1), a("www.example", 100, 2)],
        vec![],
    );
    cache.insert(&key_of(&q), &r, T0).unwrap();
    let (_, served) = lookup(&cache, &q, T0 + 40, NEVER);
    assert_eq!(ttls(&served.unwrap()), [60, 60]);
    assert_eq!(lookup(&cache, &q, T0 + 100, NEVER).0, Lookup::Miss);
}

/// §5: the negative TTL is the lesser of the SOA's TTL and its MINIMUM.
#[test]
fn nxdomain_lives_as_long_as_the_soa_allows() {
    let cache = small_cache();
    let q = query(1, "nope.example", RecordType::A);
    let r = response(
        "nope.example",
        RecordType::A,
        Rcode::NXDOMAIN,
        vec![],
        vec![soa("example", 3600, 60)],
    );
    cache.insert(&key_of(&q), &r, T0).unwrap();
    let (_, served) = lookup(&cache, &q, T0 + 10, NEVER);
    let served = served.unwrap();
    assert_eq!(served.rcode(), Rcode::NXDOMAIN);
    assert_eq!(ttls(&served), [50]);
    assert_eq!(lookup(&cache, &q, T0 + 60, NEVER).0, Lookup::Miss);
}

/// §2.2 NODATA: NOERROR, no answer, SOA in authority.
#[test]
fn nodata_is_cached_like_nxdomain() {
    let cache = small_cache();
    let q = query(1, "www.example", RecordType::AAAA);
    let r = response(
        "www.example",
        RecordType::AAAA,
        Rcode::NOERROR,
        vec![],
        vec![soa("example", 120, 900)],
    );
    cache.insert(&key_of(&q), &r, T0).unwrap();
    let (_, served) = lookup(&cache, &q, T0, NEVER);
    assert_eq!(ttls(&served.unwrap()), [120]);
}

/// §5: "Negative responses without SOA records SHOULD NOT be cached"; a referral is one too.
#[test]
fn negative_answer_without_soa_is_not_cached() {
    let cache = small_cache();
    let q = query(1, "nope.example", RecordType::A);
    let r = response(
        "nope.example",
        RecordType::A,
        Rcode::NXDOMAIN,
        vec![],
        vec![],
    );
    assert_eq!(cache.insert(&key_of(&q), &r, T0), Err(NotCached::NoSoa));
}

/// §5: negative TTLs capped, 1 to 3 hours recommended.
#[test]
fn negative_ttl_is_capped() {
    let cache = small_cache();
    let q = query(1, "nope.example", RecordType::A);
    let r = response(
        "nope.example",
        RecordType::A,
        Rcode::NXDOMAIN,
        vec![],
        vec![soa("example", 86_400, 86_400)],
    );
    cache.insert(&key_of(&q), &r, T0).unwrap();
    let (_, served) = lookup(&cache, &q, T0, NEVER);
    assert_eq!(ttls(&served.unwrap()), [cache.config().max_negative_ttl]);
}

#[test]
fn positive_ttl_is_capped() {
    let cache = small_cache();
    let q = query(1, "www.example", RecordType::A);
    let r = response(
        "www.example",
        RecordType::A,
        Rcode::NOERROR,
        vec![a("www.example", 0x7FFF_FFFF, 1)],
        vec![],
    );
    cache.insert(&key_of(&q), &r, T0).unwrap();
    let (_, served) = lookup(&cache, &q, T0, NEVER);
    assert_eq!(ttls(&served.unwrap()), [7 * 86_400]);
}

/// RFC 1035 §3.2.1: TTL 0 means use for this transaction only.
#[test]
fn ttl_zero_is_not_cached() {
    let cache = small_cache();
    let q = query(1, "www.example", RecordType::A);
    let r = response(
        "www.example",
        RecordType::A,
        Rcode::NOERROR,
        vec![a("www.example", 0, 1)],
        vec![],
    );
    assert_eq!(cache.insert(&key_of(&q), &r, T0), Err(NotCached::ZeroTtl));
}

#[test]
fn failures_and_unusable_responses_are_refused() {
    let cache = small_cache();
    let q = query(1, "www.example", RecordType::A);
    let key = key_of(&q);
    let answer = || vec![a("www.example", 60, 1)];

    let servfail = response(
        "www.example",
        RecordType::A,
        Rcode::SERVFAIL,
        vec![],
        vec![],
    );
    assert_eq!(
        cache.insert(&key, &servfail, T0),
        Err(NotCached::Rcode(Rcode::SERVFAIL))
    );

    let other = response(
        "other.example",
        RecordType::A,
        Rcode::NOERROR,
        answer(),
        vec![],
    );
    assert_eq!(
        cache.insert(&key, &other, T0),
        Err(NotCached::OtherQuestion)
    );

    let other_type = response(
        "www.example",
        RecordType::AAAA,
        Rcode::NOERROR,
        answer(),
        vec![],
    );
    assert_eq!(
        cache.insert(&key, &other_type, T0),
        Err(NotCached::OtherQuestion)
    );

    let fine = response(
        "www.example",
        RecordType::A,
        Rcode::NOERROR,
        answer(),
        vec![],
    );
    let mut truncated = Message::decode(&fine).unwrap().message;
    truncated.header.flags = truncated.header.flags.with(Flags::TC);
    assert_eq!(
        cache.insert(&key, &truncated.to_vec().unwrap(), T0),
        Err(NotCached::Truncated)
    );

    assert_eq!(cache.insert(&key, &q, T0), Err(NotCached::NotResponse));
    assert!(matches!(
        cache.insert(&key, &[0; 5], T0),
        Err(NotCached::Malformed(_))
    ));
    assert!(cache.is_empty());
}
