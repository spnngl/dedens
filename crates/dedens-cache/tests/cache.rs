//! Serving hits, keys, prefetch, truncation and the byte budget.

mod common;

use common::{T0, a, dns, key_of, lookup, query, query_with, response, small_cache, ttls};
use dedens_cache::{Cache, Config, Freshness, Hit, Lookup, NotCached, StalePolicy};
use dedens_proto::{Flags, Message, Query, Rcode, RecordType};
use proptest::prelude::*;

const NEVER: StalePolicy = StalePolicy::Never;

fn www(ttl: u32, count: u8) -> Vec<u8> {
    let answer = (0..count).map(|i| a("www.example", ttl, i)).collect();
    response("www.example", RecordType::A, Rcode::NOERROR, answer, vec![])
}

#[test]
fn a_hit_is_patched_for_the_query() {
    let cache = small_cache();
    let asked = query_with(1, "www.example", RecordType::A, Flags::CD, false);
    cache.insert(&key_of(&asked), &www(60, 2), T0).unwrap();
    let q = query_with(0xBEEF, "WwW.ExAmPlE", RecordType::A, Flags::CD, false);
    let (found, served) = lookup(&cache, &q, T0 + 1, NEVER);
    assert!(matches!(
        found,
        Lookup::Hit(Hit {
            truncated: false,
            ..
        })
    ));
    let served = served.unwrap();
    assert_eq!(served.header.id, 0xBEEF);
    // RD and CD echo the query; a cache is not authoritative.
    assert_eq!(
        served.header.flags,
        Flags::QR.with(Flags::RA).with(Flags::CD)
    );
    // RFC 4343 §4: the question in the case asked.
    assert_eq!(served.questions[0].name.to_string(), "WwW.ExAmPlE.");
    assert_eq!(ttls(&served), [59, 59]);
    // The caller adds its own OPT record.
    assert_eq!(served.edns, None);
}

#[test]
fn keys_ignore_case_but_not_type_class_do_or_cd() {
    let q = |name, qtype, flags, dnssec_ok| key_of(&query_with(1, name, qtype, flags, dnssec_ok));
    let plain = q("www.example", RecordType::A, Flags::RD, false);
    assert_eq!(plain, q("WWW.EXAMPLE", RecordType::A, Flags::NONE, false));
    assert_ne!(plain, q("www.example", RecordType::AAAA, Flags::RD, false));
    assert_ne!(plain, q("www.example", RecordType::A, Flags::RD, true));
    assert_ne!(plain, q("www.example", RecordType::A, Flags::CD, false));
}

#[test]
fn a_query_without_question_misses() {
    let cache = small_cache();
    let wire = query(1, "www.example", RecordType::A);
    let mut message = Message::decode(&wire).unwrap().message;
    message.questions.clear();
    let wire = message.to_vec().unwrap();
    let query = Query::read(&wire).unwrap();
    assert_eq!(cache.lookup(&query, T0, NEVER, &mut [0; 512]), Lookup::Miss);
}

#[test]
fn prefetch_is_asked_once_near_expiry() {
    let cache = small_cache();
    let q = query(1, "www.example", RecordType::A);
    cache.insert(&key_of(&q), &www(100, 1), T0).unwrap();
    let freshness = |now| match lookup(&cache, &q, now, NEVER).0 {
        Lookup::Hit(hit) => hit.freshness,
        other => panic!("expected a hit, got {other:?}"),
    };
    assert_eq!(freshness(T0 + 50), Freshness::Fresh { prefetch: false });
    assert_eq!(freshness(T0 + 91), Freshness::Fresh { prefetch: true });
    assert_eq!(freshness(T0 + 92), Freshness::Fresh { prefetch: false });
    // A new answer re-arms it.
    cache.insert(&key_of(&q), &www(100, 1), T0 + 95).unwrap();
    assert_eq!(freshness(T0 + 190), Freshness::Fresh { prefetch: true });
}

#[test]
fn a_response_too_large_for_the_client_is_truncated() {
    let cache = small_cache();
    let q = query(1, "www.example", RecordType::A);
    cache.insert(&key_of(&q), &www(60, 60), T0).unwrap();
    let mut out = [0; 512];
    let found = cache.lookup(&Query::read(&q).unwrap(), T0, NEVER, &mut out);
    let Lookup::Hit(hit) = found else {
        panic!("expected a hit, got {found:?}");
    };
    assert!(hit.truncated);
    let served = Message::decode(&out[..hit.len]).unwrap().message;
    assert!(served.header.flags.contains(Flags::TC));
    assert!(served.answer.len() < 60);
    assert_eq!(served.header.id, 1);
}

#[test]
fn the_budget_holds_and_popular_entries_survive_a_scan() {
    let cache = Cache::new(Config {
        capacity: 64 << 10,
        shards: 1,
        ..Config::default()
    })
    .unwrap();
    let hot = query(1, "www.example", RecordType::A);
    cache.insert(&key_of(&hot), &www(600, 1), T0).unwrap();
    for _ in 0..3 {
        assert!(matches!(lookup(&cache, &hot, T0, NEVER).0, Lookup::Hit(_)));
    }
    for i in 0..5_000 {
        let name = format!("cold{i}.example");
        let q = query(1, &name, RecordType::A);
        let r = response(
            &name,
            RecordType::A,
            Rcode::NOERROR,
            vec![a(&name, 600, 1)],
            vec![],
        );
        cache.insert(&key_of(&q), &r, T0).unwrap();
        assert!(cache.used() <= cache.config().capacity);
        if i % 500 == 0 {
            // Popular names keep being asked while the scan goes on.
            assert!(
                matches!(lookup(&cache, &hot, T0, NEVER).0, Lookup::Hit(_)),
                "evicted at {i}"
            );
        }
    }
    assert!(cache.len() < 5_000);
    assert!(matches!(lookup(&cache, &hot, T0, NEVER).0, Lookup::Hit(_)));
}

#[test]
fn an_entry_over_the_shard_budget_is_refused() {
    let cache = Cache::new(Config {
        capacity: 1024,
        shards: 1,
        ..Config::default()
    })
    .unwrap();
    let q = query(1, "www.example", RecordType::A);
    assert_eq!(
        cache.insert(&key_of(&q), &www(60, 100), T0),
        Err(NotCached::TooLarge)
    );
}

#[test]
fn a_new_answer_replaces_the_old() {
    let cache = small_cache();
    let q = query(1, "www.example", RecordType::A);
    cache.insert(&key_of(&q), &www(60, 1), T0).unwrap();
    cache.insert(&key_of(&q), &www(60, 3), T0 + 10).unwrap();
    let (_, served) = lookup(&cache, &q, T0 + 10, NEVER);
    assert_eq!(ttls(&served.unwrap()), [60, 60, 60]);
    assert_eq!(cache.len(), 1);
}

proptest! {
    /// A hit is the stored response with the query's ID and TTLs counted down.
    #[test]
    fn hits_serve_the_stored_records(
        ttl in 1_u32..100_000,
        age in 0_u32..100_000,
        count in 1_u8..20,
        id: u16,
    ) {
        prop_assume!(age < ttl);
        let cache = small_cache();
        let r = www(ttl, count);
        cache.insert(&key_of(&query(1, "www.example", RecordType::A)), &r, T0).unwrap();
        let (_, served) = lookup(&cache, &query(id, "www.example", RecordType::A), T0 + age, NEVER);
        let served = served.unwrap();
        let mut stored = Message::decode(&r).unwrap().message;
        for record in &mut stored.answer {
            record.ttl = dedens_proto::Ttl::new(ttl - age).unwrap();
        }
        prop_assert_eq!(served.header.id, id);
        prop_assert_eq!(&served.questions[0].name, &dns("www.example"));
        prop_assert_eq!(served.answer, stored.answer);
    }
}
