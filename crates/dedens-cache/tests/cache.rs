//! Serving hits, keys, prefetch, truncation and the byte budget.

mod common;

use std::net::{IpAddr, Ipv4Addr};

use common::{T0, a, dns, insert, key_of, lookup, query, query_with, response, small_cache, ttls};
use dedens_cache::{
    Cache, Config, ConfigError, Freshness, Hit, Key, Lookup, NotCached, StalePolicy,
};
use dedens_proto::edns::{ClientSubnet, EdnsOption};
use dedens_proto::{Edns, Flags, Message, Opcode, Query, Rcode, RecordType};
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
    insert(&cache, &asked, &www(60, 2), T0).unwrap();
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
    insert(&cache, &q, &www(100, 1), T0).unwrap();
    let freshness = |now| match lookup(&cache, &q, now, NEVER).0 {
        Lookup::Hit(hit) => hit.freshness,
        other => panic!("expected a hit, got {other:?}"),
    };
    assert_eq!(freshness(T0 + 50), Freshness::Fresh { prefetch: false });
    assert_eq!(freshness(T0 + 91), Freshness::Fresh { prefetch: true });
    assert_eq!(freshness(T0 + 92), Freshness::Fresh { prefetch: false });
    // A new answer re-arms it.
    insert(&cache, &q, &www(100, 1), T0 + 95).unwrap();
    assert_eq!(freshness(T0 + 190), Freshness::Fresh { prefetch: true });
}

#[test]
fn a_response_too_large_for_the_client_is_truncated() {
    let cache = small_cache();
    let q = query(1, "www.example", RecordType::A);
    insert(&cache, &q, &www(60, 60), T0).unwrap();
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
    insert(&cache, &hot, &www(600, 1), T0).unwrap();
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
        insert(&cache, &q, &r, T0).unwrap();
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
        insert(&cache, &q, &www(60, 100), T0),
        Err(NotCached::TooLarge)
    );
}

#[test]
fn a_new_answer_replaces_the_old() {
    let cache = small_cache();
    let q = query(1, "www.example", RecordType::A);
    insert(&cache, &q, &www(60, 1), T0).unwrap();
    insert(&cache, &q, &www(60, 3), T0 + 10).unwrap();
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
        insert(&cache, &query(1, "www.example", RecordType::A), &r, T0).unwrap();
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

/// A hit served at `now` into a buffer of `len` bytes, decoded.
fn served(cache: &Cache, query: &[u8], now: u32, len: usize) -> (Hit, Message<'static>) {
    let mut out = vec![0; len];
    let found = cache.lookup(
        &Query::read(query).expect("a valid query"),
        now,
        NEVER,
        &mut out,
    );
    let Lookup::Hit(hit) = found else {
        unreachable!("expected a hit, got {found:?}");
    };
    let decoded = Message::decode(&out[..hit.len]).expect("a served response decodes");
    assert!(decoded.violations.is_empty(), "{:?}", decoded.violations);
    (hit, decoded.message.into_owned())
}

/// RFC 1035 §4.1.1: only standard queries are answered from the cache, and only they fill it.
#[test]
fn only_standard_queries_have_a_key() {
    let cache = small_cache();
    let plain = query(1, "www.example", RecordType::A);
    insert(&cache, &plain, &www(60, 1), T0).unwrap();
    let mut message = Message::decode(&plain).unwrap().message;
    message.header.flags = message.header.flags.with(Flags::QR);
    let response = message.to_vec().unwrap();
    message.header.flags = message.header.flags.without(Flags::QR);
    message.header.opcode = Opcode::NOTIFY;
    let notify = message.to_vec().unwrap();
    message.header.opcode = Opcode::IQUERY;
    let iquery = message.to_vec().unwrap();
    for asked in [&response, &notify, &iquery] {
        assert!(Key::of(&Query::read(asked).unwrap()).is_none());
        assert_eq!(lookup(&cache, asked, T0, NEVER).0, Lookup::Miss);
        assert_eq!(
            insert(&cache, asked, &www(60, 1), T0),
            Err(NotCached::Query)
        );
    }
}

/// RFC 6895 §3.1: answers to the meta types and QTYPEs are not data to cache; ANY is (RFC 8482).
#[test]
fn meta_query_types_have_no_key() {
    let types = [
        RecordType::AXFR,
        RecordType::IXFR,
        RecordType::OPT,
        // TKEY, TSIG, MAILB, MAILA: no constants in dedens-proto.
        RecordType::from(249),
        RecordType::from(250),
        RecordType::from(253),
        RecordType::from(254),
    ];
    for qtype in types {
        let asked = query(1, "www.example", qtype);
        assert!(Key::of(&Query::read(&asked).unwrap()).is_none(), "{qtype}");
    }
    assert!(Key::of(&Query::read(&query(1, "www.example", RecordType::ANY)).unwrap()).is_some());
}

/// RFC 7871 §7.3.1: an answer with a client subnet scope above 0 is for that subnet only.
#[test]
fn an_answer_for_a_client_subnet_is_refused() {
    let cache = small_cache();
    let q = query(1, "www.example", RecordType::A);
    let with_scope = |scope| {
        let mut message = Message::decode(&www(60, 1)).unwrap().message.into_owned();
        let subnet = ClientSubnet::new(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 0)), 24, scope).unwrap();
        message.edns = Some(Edns {
            options: vec![EdnsOption::ClientSubnet(subnet)],
            ..Edns::default()
        });
        message.to_vec().unwrap()
    };
    assert_eq!(
        insert(&cache, &q, &with_scope(24), T0),
        Err(NotCached::ClientSubnet)
    );
    insert(&cache, &q, &with_scope(0), T0).unwrap();
}

/// RFC 6840 §5.8: AD goes only to a client that set AD or DO.
#[test]
fn ad_is_served_only_when_asked() {
    let cache = small_cache();
    let mut message = Message::decode(&www(60, 1)).unwrap().message.into_owned();
    message.header.flags = message.header.flags.with(Flags::AD);
    let r = message.to_vec().unwrap();
    let ad = |flags, dnssec_ok| {
        let q = query_with(7, "www.example", RecordType::A, flags, dnssec_ok);
        served(&cache, &q, T0, 512)
            .1
            .header
            .flags
            .contains(Flags::AD)
    };
    insert(&cache, &query(1, "www.example", RecordType::A), &r, T0).unwrap();
    assert!(!ad(Flags::RD, false));
    assert!(ad(Flags::RD.with(Flags::AD), false));
    insert(
        &cache,
        &query_with(1, "www.example", RecordType::A, Flags::RD, true),
        &r,
        T0,
    )
    .unwrap();
    assert!(ad(Flags::RD, true));
}

/// RFC 1035 §4.1.1: Z is zero in every response served, whatever upstream set.
#[test]
fn z_is_cleared() {
    let cache = small_cache();
    let mut message = Message::decode(&www(60, 1)).unwrap().message.into_owned();
    message.header.flags = message.header.flags.with(Flags::Z);
    let q = query(1, "www.example", RecordType::A);
    insert(&cache, &q, &message.to_vec().unwrap(), T0).unwrap();
    assert!(
        !served(&cache, &q, T0, 512)
            .1
            .header
            .flags
            .contains(Flags::Z)
    );
}

/// RFC 2181 §9: a response that loses only additional records is truncated without TC.
#[test]
fn losing_only_additional_records_is_not_tc() {
    let cache = small_cache();
    let mut message = Message::decode(&www(60, 1)).unwrap().message.into_owned();
    message.additional = (0..60).map(|i| a("ns.example", 60, i)).collect();
    let q = query(1, "www.example", RecordType::A);
    insert(&cache, &q, &message.to_vec().unwrap(), T0).unwrap();
    let (hit, served) = served(&cache, &q, T0, 512);
    assert!(hit.truncated);
    assert!(!served.header.flags.contains(Flags::TC));
    assert_eq!(served.answer.len(), 1);
    assert!(served.additional.len() < 60);
}

/// The shortest buffer still takes a truncated response.
#[test]
fn min_out_holds_a_truncated_response() {
    let cache = small_cache();
    let q = query(1, "www.example", RecordType::A);
    insert(&cache, &q, &www(60, 60), T0).unwrap();
    let (hit, served) = served(&cache, &q, T0, Cache::MIN_OUT);
    assert!(hit.truncated);
    assert!(served.header.flags.contains(Flags::TC));
    assert_eq!(served.header.id, 1);
}

#[cfg(debug_assertions)]
#[test]
#[should_panic = "MIN_OUT"]
fn a_buffer_under_min_out_panics_in_debug() {
    let cache = small_cache();
    let q = query(1, "www.example", RecordType::A);
    let _ = cache.lookup(&Query::read(&q).unwrap(), T0, NEVER, &mut [0; 64]);
}

/// A caller's clock behind the insert serves no TTL above the one stored.
#[test]
fn a_clock_going_back_serves_at_most_the_stored_ttl() {
    let cache = small_cache();
    let q = query(1, "www.example", RecordType::A);
    insert(&cache, &q, &www(60, 2), T0).unwrap();
    assert_eq!(ttls(&served(&cache, &q, T0 - 100, 512).1), [60, 60]);
    assert_eq!(ttls(&served(&cache, &q, T0 + 10, 512).1), [50, 50]);
}

/// Looking up an expired entry is no hit: it does not keep the entry through a scan.
#[test]
fn only_hits_keep_an_entry() {
    let cache = Cache::new(Config {
        capacity: 64 << 10,
        shards: 1,
        ..Config::default()
    })
    .unwrap();
    let expired = query(1, "expired.example", RecordType::A);
    let r = response(
        "expired.example",
        RecordType::A,
        Rcode::NOERROR,
        vec![a("expired.example", 1, 1)],
        vec![],
    );
    insert(&cache, &expired, &r, T0).unwrap();
    for _ in 0..3 {
        assert_eq!(lookup(&cache, &expired, T0 + 10, NEVER).0, Lookup::Miss);
    }
    for i in 0..5_000 {
        let name = format!("cold{i}.example");
        let r = response(
            &name,
            RecordType::A,
            Rcode::NOERROR,
            vec![a(&name, 600, 1)],
            vec![],
        );
        insert(&cache, &query(1, &name, RecordType::A), &r, T0).unwrap();
    }
    assert_eq!(
        lookup(&cache, &expired, T0 + 10, StalePolicy::Always).0,
        Lookup::Miss
    );
}

/// Threads inserting and looking up at once: every hit is whole and for its query, the budget holds.
#[test]
fn threads_share_the_cache() {
    let cache = Cache::new(Config {
        capacity: 256 << 10,
        shards: 4,
        ..Config::default()
    })
    .unwrap();
    std::thread::scope(|scope| {
        for thread in 0..8_u16 {
            let cache = &cache;
            scope.spawn(move || {
                for i in 0..2_000_u16 {
                    let name = format!("n{}.example", i % 300);
                    let id = thread * 8_000 + i;
                    let q = query(id, &name, RecordType::A);
                    let r = response(
                        &name,
                        RecordType::A,
                        Rcode::NOERROR,
                        vec![a(&name, 600, 1)],
                        vec![],
                    );
                    if let (Lookup::Hit(_), Some(served)) = lookup(cache, &q, T0, NEVER) {
                        assert_eq!(served.header.id, id);
                        assert_eq!(served.questions[0].name, dns(&name));
                        assert_eq!(served.answer.len(), 1);
                    } else {
                        insert(cache, &q, &r, T0).unwrap();
                    }
                    assert!(cache.used() <= cache.config().capacity);
                }
            });
        }
    });
    assert!(!cache.is_empty());
}

/// RFC 9520 §3.2 bounds every hold to 5 minutes, the RFC 8767 recheck included; each shard holds one failure.
#[test]
fn configs_breaking_the_bounds_are_refused() {
    let refused = |config: Config| Cache::new(config).unwrap_err();
    let base = Config::default;
    assert_eq!(
        refused(Config {
            stale_recheck: 301,
            failure_max: 300,
            ..base()
        }),
        ConfigError::FailureHold
    );
    assert_eq!(
        refused(Config {
            stale_recheck: 30,
            failure_max: 20,
            ..base()
        }),
        ConfigError::FailureHold
    );
    assert_eq!(
        refused(Config {
            failure_max: 301,
            ..base()
        }),
        ConfigError::FailureHold
    );
    assert!(matches!(
        refused(Config {
            capacity: 0,
            ..base()
        }),
        ConfigError::Capacity(_)
    ));
    let ConfigError::Capacity(least) = refused(Config {
        capacity: 1000,
        shards: 16,
        ..base()
    }) else {
        panic!("expected a capacity error");
    };
    Cache::new(Config {
        capacity: least,
        shards: 16,
        ..base()
    })
    .unwrap();
    assert_eq!(
        refused(Config {
            shards: 1 << 17,
            capacity: usize::MAX,
            ..base()
        }),
        ConfigError::Shards(1 << 17)
    );
}

/// A failure record fits the smallest budget, keeping `used` within the capacity.
#[test]
fn failures_keep_to_the_budget() {
    let least = match Cache::new(Config {
        capacity: 0,
        shards: 1,
        ..Config::default()
    }) {
        Err(ConfigError::Capacity(least)) => least,
        other => panic!("expected a capacity error, got {other:?}"),
    };
    let cache = Cache::new(Config {
        capacity: least,
        shards: 1,
        ..Config::default()
    })
    .unwrap();
    for i in 0..100 {
        let name = format!(
            "{}example",
            format!("{}.", "a".repeat(60)).repeat(1 + i % 3)
        );
        let _ = cache.fail(&key_of(&query(1, &name, RecordType::A)), T0);
        assert!(cache.used() <= least);
    }
}
