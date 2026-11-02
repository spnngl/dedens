//! Serving hits, keys, prefetch, truncation and the byte budget.

mod common;

use std::net::{IpAddr, Ipv4Addr};

use common::{
    T0, a, dns, insert, key_of, lookup, query, query_plain, query_with, response, small_cache,
    small_config, ttls,
};
use dedens_cache::{
    Cache, Checked, Config, ConfigError, Freshness, Hit, Key, Lookup, NotCached, StalePolicy,
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
fn a_mark_follows_the_stored_response() {
    let cache = small_cache();
    let asked = query(1, "www.example", RecordType::A);
    let query = Query::read(&asked).unwrap();
    let wire = www(60, 1);
    let decoded = Message::decode(&wire).unwrap();
    let mark = |cache: &Cache| match cache.lookup(&query, T0 + 1, NEVER, &mut [0; 512]) {
        Lookup::Hit(hit) => hit.mark,
        other => panic!("expected a hit, got {other:?}"),
    };
    // Stored unmarked, marked once: only a caller that saw the mark it replaces sets it.
    cache.insert(&query, &decoded, T0, 0).unwrap();
    assert_eq!(mark(&cache), 0);
    assert!(!cache.mark(&query, 7, 9));
    assert!(cache.mark(&query, 0, 9));
    assert_eq!(mark(&cache), 9);
    // A response stored meanwhile takes its own mark.
    cache.insert(&query, &decoded, T0, 3).unwrap();
    assert!(!cache.mark(&query, 9, 11));
    assert_eq!(mark(&cache), 3);
    // Nothing stored, nothing to mark.
    let other = query_with(1, "none.example", RecordType::A, Flags::NONE, false);
    let other = Query::read(&other).unwrap();
    assert!(!cache.mark(&other, 0, 1));
}

/// The mark goes with its entry when the shard is compacted (D116): a large response evicts most of the small ones
/// and leaves their slots free, the entries left are renumbered.
#[test]
fn a_mark_survives_a_compaction() {
    let cache = Cache::new(Config {
        capacity: 100_000,
        shards: 1,
        max_entry_bytes: Some(60_000),
        ..Config::default()
    })
    .unwrap();
    let marked = |name: &str, mark| {
        let asked = query(1, name, RecordType::A);
        let small = response(
            name,
            RecordType::A,
            Rcode::NOERROR,
            (0..60).map(|i| a(name, 60, i)).collect(),
            vec![],
        );
        let decoded = Message::decode(&small).unwrap();
        cache
            .insert(&Query::read(&asked).unwrap(), &decoded, T0, mark)
            .unwrap();
    };
    for n in 0..100_u64 {
        marked(&format!("n{n}.example"), n + 1);
    }
    let large = query(1, "large.example", RecordType::A);
    let wire = (0..3_000_u16)
        .map(|i| a("large.example", 60, u8::try_from(i % 250).unwrap()))
        .collect();
    let wire = response("large.example", RecordType::A, Rcode::NOERROR, wire, vec![]);
    cache
        .insert(
            &Query::read(&large).unwrap(),
            &Message::decode(&wire).unwrap(),
            T0,
            99,
        )
        .unwrap();
    let mark_of = |asked: &[u8]| match cache.lookup(
        &Query::read(asked).unwrap(),
        T0,
        NEVER,
        &mut [0; 4096],
    ) {
        Lookup::Hit(hit) => Some(hit.mark),
        _ => None,
    };
    assert_eq!(mark_of(&large), Some(99));
    // Under 30 entries are left (a compaction ran: 47 slots of 71 were free), each with the mark it had.
    assert!(cache.len() < 30, "{} entries left", cache.len());
    for n in 0..100_u64 {
        let asked = query(1, &format!("n{n}.example"), RecordType::A);
        assert!(mark_of(&asked).is_none_or(|mark| mark == n + 1));
    }
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
    // 10 of 100 seconds left is not under 10%.
    assert_eq!(freshness(T0 + 90), Freshness::Fresh { prefetch: false });
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

/// A response over `Config::max_entry_bytes` is not stored (D116), a smaller one is: the limit is on the entry, not
/// on the shard (L12).
#[test]
fn an_entry_over_max_entry_bytes_is_refused() {
    let cache = Cache::new(Config {
        capacity: 1 << 20,
        max_entry_bytes: Some(1024),
        shards: 4,
        ..Config::default()
    })
    .unwrap();
    let q = query(1, "www.example", RecordType::A);
    assert_eq!(
        insert(&cache, &q, &www(60, 100), T0),
        Err(NotCached::TooLarge)
    );
    assert!(cache.is_empty());
    insert(&cache, &q, &www(60, 10), T0).unwrap();
    assert_eq!(cache.len(), 1);
}

/// The limit is inclusive: an entry of exactly `max_entry_bytes` is stored, one byte less allowed is refused. An
/// entry is the key, the response without its OPT record, 2 bytes for each record (where its TTL is) and the cuts of
/// the additional section, 1 byte for up to 7 records.
#[test]
fn max_entry_bytes_is_inclusive() {
    let q = query(1, "www.example", RecordType::A);
    let r = www(60, 40);
    // Find the size of the entry by search: its key and response as stored.
    let stores = |max_entry_bytes| {
        let cache = Cache::new(Config {
            max_entry_bytes: Some(max_entry_bytes),
            ..small_config()
        })
        .unwrap();
        insert(&cache, &q, &r, T0).is_ok()
    };
    let least = (300..4096)
        .find(|&max| stores(max))
        .expect("a size that stores");
    let wire = Message::decode(&r)
        .unwrap()
        .message
        .to_vec_without_edns()
        .unwrap();
    assert_eq!(least, key_of(&q).as_bytes().len() + wire.len() + 2 * 40 + 1);
    assert!(!stores(least - 1));
    assert!(stores(least + 1));
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

/// RFC 6840 §5.8: AD goes only to a client that set AD or DO, and only for a response checked secure (D114).
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
    let secure = |q: &[u8]| {
        cache
            .insert_checked(
                &Query::read(q).unwrap(),
                &Message::decode(&r).unwrap(),
                T0,
                Checked::Secure,
                0,
            )
            .unwrap();
    };
    secure(&query(1, "www.example", RecordType::A));
    assert!(!ad(Flags::RD, false));
    assert!(ad(Flags::RD.with(Flags::AD), false));
    secure(&query_with(
        1,
        "www.example",
        RecordType::A,
        Flags::RD,
        true,
    ));
    assert!(ad(Flags::RD, true));
}

/// D114: the AD bit of a response stored without a verdict is not served, to a client with AD or DO either.
#[test]
fn ad_of_an_unchecked_response_is_not_served() {
    let cache = small_cache();
    let mut message = Message::decode(&www(60, 1)).unwrap().message.into_owned();
    message.header.flags = message.header.flags.with(Flags::AD);
    let q = query_with(1, "www.example", RecordType::A, Flags::RD | Flags::AD, true);
    insert(&cache, &q, &message.to_vec().unwrap(), T0).unwrap();
    assert!(
        !served(&cache, &q, T0, 512)
            .1
            .header
            .flags
            .contains(Flags::AD)
    );
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

/// The longest name (255 bytes on the wire) is a key, and its truncated response fits `MIN_OUT`, stale too with
/// room for the EDE option.
#[test]
fn min_out_holds_the_longest_question() {
    let longest = format!("{0}.{0}.{0}.{1}.", "a".repeat(63), "a".repeat(61));
    assert_eq!(dns(&longest).wire_len(), 255);
    let cache = small_cache();
    let q = query(1, &longest, RecordType::A);
    let answer = (0..20).map(|i| a(&longest, 60, i)).collect();
    let r = response(&longest, RecordType::A, Rcode::NOERROR, answer, vec![]);
    insert(&cache, &q, &r, T0).unwrap();
    let (hit, served) = served(&cache, &q, T0, Cache::MIN_OUT);
    assert!(hit.truncated);
    assert_eq!(served.questions[0].name, dns(&longest));
    let mut out = vec![0; Cache::MIN_OUT];
    let found = cache.lookup(
        &Query::read(&q).unwrap(),
        T0 + 61,
        StalePolicy::Always,
        &mut out,
    );
    let Lookup::Hit(stale) = found else {
        panic!("expected a stale hit, got {found:?}");
    };
    assert_eq!(stale.len, Cache::MIN_OUT - Cache::STALE_ROOM);
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
        assert_eq!(lookup(&cache, &expired, T0 + 10, NEVER).0, Lookup::Expired);
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

/// What a server does on a miss: store the response, then serve it from the cache (`Cache::stored`).
fn store_and_serve(cache: &Cache, name: &str) -> Vec<u8> {
    let q = query(1, name, RecordType::A);
    let r = response(
        name,
        RecordType::A,
        Rcode::NOERROR,
        vec![a(name, 600, 1)],
        vec![],
    );
    insert(cache, &q, &r, T0).expect("a response to store");
    let mut out = [0; 512];
    let hit = cache
        .stored(&Query::read(&q).expect("a valid query"), T0, &mut out)
        .expect("the response just stored");
    let served = Message::decode(&out[..hit.len])
        .expect("a served response decodes")
        .message;
    assert_eq!(served.answer.len(), 1);
    q
}

/// Serving the response just stored is no use of it: names asked once still go first, and names asked again
/// survive a scan of one-off names (S3-FIFO).
#[test]
fn serving_what_was_just_stored_keeps_scan_resistance() {
    let cache = Cache::new(Config {
        capacity: 64 << 10,
        max_entry_bytes: Some(1024),
        shards: 1,
        ..Config::default()
    })
    .unwrap();
    let warm: Vec<_> = (0..40)
        .map(|i| store_and_serve(&cache, &format!("warm{i}.example")))
        .collect();
    for q in &warm {
        assert!(matches!(lookup(&cache, q, T0, NEVER).0, Lookup::Hit(_)));
    }
    for i in 0..5_000 {
        store_and_serve(&cache, &format!("cold{i}.example"));
    }
    for q in &warm {
        assert!(matches!(lookup(&cache, q, T0, NEVER).0, Lookup::Hit(_)));
    }
}

/// A stale hit leaves `Cache::STALE_ROOM` bytes for the caller's EDE option; a fresh one uses all of `out`.
#[test]
fn only_a_stale_hit_leaves_room_for_its_ede_option() {
    let cache = small_cache();
    let q = query(1, "www.example", RecordType::A);
    insert(&cache, &q, &www(60, 20), T0).unwrap();
    let (hit, _) = served(&cache, &q, T0, 512);
    let len = hit.len;
    assert!(!served(&cache, &q, T0, len).0.truncated);
    let mut out = vec![0; len];
    let found = cache.lookup(
        &Query::read(&q).unwrap(),
        T0 + 61,
        StalePolicy::Always,
        &mut out,
    );
    let Lookup::Hit(stale) = found else {
        panic!("expected a stale hit, got {found:?}");
    };
    assert!(stale.truncated);
    assert!(stale.len <= len - Cache::STALE_ROOM);
}

/// Only a client with EDNS gets the EDE option of a stale answer: for one without, a stale hit uses all of `out`.
#[test]
fn a_stale_hit_leaves_room_only_for_a_query_with_edns() {
    let cache = small_cache();
    let (with, without) = (
        query(1, "www.example", RecordType::A),
        query_plain(1, "www.example", RecordType::A),
    );
    insert(&cache, &with, &www(60, 20), T0).unwrap();
    let len = served(&cache, &with, T0, 512).0.len;
    let stale = |q: &[u8], room: usize| {
        let mut out = vec![0; room];
        let found = cache.lookup(
            &Query::read(q).unwrap(),
            T0 + 61,
            StalePolicy::Always,
            &mut out,
        );
        let Lookup::Hit(hit) = found else {
            panic!("expected a stale hit, got {found:?}");
        };
        hit
    };
    assert!(stale(&with, len).truncated);
    assert!(!stale(&with, len + Cache::STALE_ROOM).truncated);
    let whole = stale(&without, len);
    assert!(!whole.truncated);
    assert_eq!(whole.len, len);
}

/// A response too large to store ends what the cache held of its key, the old response, which the new answer
/// outdates, and the failure hold (D116).
#[test]
fn a_response_too_large_clears_what_was_held() {
    let cache = Cache::new(Config {
        max_entry_bytes: Some(1024),
        ..small_config()
    })
    .unwrap();
    let q = query(1, "www.example", RecordType::A);
    let key = key_of(&q);
    insert(&cache, &q, &www(60, 1), T0).unwrap();
    assert!(matches!(lookup(&cache, &q, T0, NEVER).0, Lookup::Hit(_)));
    // The mark leaves with the response it was on.
    let read = Query::read(&q).unwrap();
    assert!(cache.mark(&read, 0, 5));
    assert_eq!(
        insert(&cache, &q, &www(60, 100), T0 + 1),
        Err(NotCached::TooLarge)
    );
    assert_eq!(lookup(&cache, &q, T0 + 1, NEVER).0, Lookup::Miss);
    assert!(!cache.mark(&read, 5, 6));
    // A failure held, and then a response too large for the entry: the hold ends, as a stored one would end it.
    assert!(cache.fail(&key, T0 + 2) > 0);
    assert_eq!(lookup(&cache, &q, T0 + 2, NEVER).0, Lookup::Failed);
    assert_eq!(
        insert(&cache, &q, &www(60, 100), T0 + 3),
        Err(NotCached::TooLarge)
    );
    assert_eq!(lookup(&cache, &q, T0 + 3, NEVER).0, Lookup::Miss);
    // Nothing is stored for a key the cache does not know.
    let other = query(1, "other.example", RecordType::A);
    let answer = (0..100).map(|i| a("other.example", 60, i)).collect();
    let large = response(
        "other.example",
        RecordType::A,
        Rcode::NOERROR,
        answer,
        vec![],
    );
    assert_eq!(
        insert(&cache, &other, &large, T0 + 3),
        Err(NotCached::TooLarge)
    );
    assert_eq!(cache.len(), 1);
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

/// An entry of `max_entry_bytes` must fit a shard with its slot, and a failure record must fit an entry (D116).
#[test]
fn max_entry_bytes_is_checked_against_the_other_bounds() {
    let base = small_config;
    let ConfigError::EntryBytes(longest_key) = Cache::new(Config {
        max_entry_bytes: Some(0),
        ..base()
    })
    .unwrap_err() else {
        panic!("expected an entry size error");
    };
    Cache::new(Config {
        max_entry_bytes: Some(longest_key),
        ..base()
    })
    .unwrap();
    assert_eq!(
        Config {
            max_entry_bytes: Some(longest_key - 1),
            ..base()
        }
        .validate(),
        Err(ConfigError::EntryBytes(longest_key))
    );
    // A shard's share under the largest entry: the capacity needed is told, and enough.
    let ConfigError::Capacity(least) = Cache::new(Config {
        max_entry_bytes: Some(1 << 20),
        ..base()
    })
    .unwrap_err() else {
        panic!("expected a capacity error");
    };
    assert!(least > 4 * (1 << 20));
    let config = Config {
        capacity: least,
        max_entry_bytes: Some(1 << 20),
        ..base()
    };
    Cache::new(config.clone()).unwrap();
    assert!(matches!(
        Config {
            capacity: least - 4,
            ..config
        }
        .validate(),
        Err(ConfigError::Capacity(_))
    ));
}

/// Unset, `max_entry_bytes` is 8 KiB, or a tenth of a shard's share less a slot when that is less; a capacity whose
/// tenth cannot hold a failure record is refused, naming the least (D116).
#[test]
fn an_unset_max_entry_bytes_follows_the_capacity() {
    assert_eq!(Config::default().entry_limit(), 8 << 10);
    let with = |capacity| Config {
        capacity,
        shards: 1,
        ..Config::default()
    };
    let ConfigError::Capacity(least) = with(0).validate().unwrap_err() else {
        panic!("expected a capacity error");
    };
    let ConfigError::EntryBytes(longest_key) = Config {
        max_entry_bytes: Some(0),
        ..Config::default()
    }
    .validate()
    .unwrap_err() else {
        panic!("expected an entry size error");
    };
    // The least capacity leaves a failure record's size, and one byte of share less is refused.
    assert_eq!(with(least).validate(), Ok(()));
    assert_eq!(with(least).entry_limit(), longest_key);
    assert!(matches!(
        with(least - 10).validate(),
        Err(ConfigError::Capacity(_))
    ));
    // Between, the limit grows with the share by a tenth, and stops at 8 KiB.
    let (small, large) = (with(least * 2).entry_limit(), with(least * 4).entry_limit());
    assert!(longest_key < small && small < large && large < 8 << 10);
    assert_eq!(with(1 << 30).entry_limit(), 8 << 10);
    assert_eq!(with(1 << 30).validate(), Ok(()));
}

/// Each bound is inclusive: the edge values are taken, one past refused.
#[test]
fn config_bounds_are_inclusive() {
    let base = Config::default;
    for config in [
        Config {
            failure_min: 300,
            failure_max: 300,
            stale_recheck: 300,
            ..base()
        },
        Config {
            prefetch_percent: 100,
            ..base()
        },
        Config {
            shards: 1 << 16,
            capacity: usize::MAX,
            ..base()
        },
    ] {
        assert_eq!(config.validate(), Ok(()), "{config:?}");
    }
    for (config, error) in [
        (
            Config {
                failure_min: 0,
                ..base()
            },
            ConfigError::FailureHold,
        ),
        (
            Config {
                failure_min: 21,
                failure_max: 20,
                stale_recheck: 20,
                ..base()
            },
            ConfigError::FailureHold,
        ),
        (
            Config {
                prefetch_percent: 101,
                ..base()
            },
            ConfigError::PrefetchPercent(101),
        ),
    ] {
        assert_eq!(config.validate(), Err(error), "{config:?}");
    }
}

/// Keys spread over the shards: the cache holds more than one shard's budget.
#[test]
fn keys_spread_over_the_shards() {
    let name = |i: u32| format!("n{i:02}.example");
    let store = |cache: &Cache, i| {
        let r = response(
            &name(i),
            RecordType::A,
            Rcode::NOERROR,
            vec![a(&name(i), 600, 1)],
            vec![],
        );
        insert(cache, &query(1, &name(i), RecordType::A), &r, T0).unwrap();
    };
    let probe = small_cache();
    assert_eq!(probe.used(), 0);
    store(&probe, 0);
    let entry = probe.used();
    assert!(entry > 0);
    // Four shards of 30 entries each: 40 keys fit unless most land in one shard.
    let cache = Cache::new(Config {
        capacity: 4 * 30 * entry,
        max_entry_bytes: Some(512),
        shards: 4,
        ..Config::default()
    })
    .unwrap();
    for i in 0..40 {
        store(&cache, i);
    }
    assert_eq!(cache.len(), 40);
    assert_eq!(cache.used(), 40 * entry);
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
