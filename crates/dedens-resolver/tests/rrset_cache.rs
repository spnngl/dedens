//! The `RRset` cache on captured responses (`testdata/proto`, `testdata/dnssec`): RFC 2181 §5 (`RRsets`), §5.2 (one
//! TTL), §5.4.1 (ranking), §8 (TTL past 2^31 - 1); RFC 1035 §3.2.1 (TTL 0); RFC 4343 (case); RFC 4035 §4.7 (bogus
//! data); D124 (TTL bounds), D116 (byte budget), D193.

use dedens_cache::{Checked, Config, ConfigError};
use dedens_proto::edns::InfoCode;
use dedens_proto::{Class, Message, Record, RecordType, Section, Ttl};
use dedens_resolver::{Hit, NotCached, Rank, Rrset, RrsetCache};
use dedens_testkit::{captured, dns, dnssec, message};

const RANKS: [Rank; 6] = [
    Rank::AdditionalNonAuthoritative,
    Rank::AuthorityNonAuthoritative,
    Rank::AdditionalAuthoritative,
    Rank::AnswerNonAuthoritative,
    Rank::AuthorityAuthoritative,
    Rank::AnswerAuthoritative,
];

const BOGUS: Checked = Checked::Bogus(InfoCode::DNSSEC_BOGUS);

fn cache() -> RrsetCache {
    RrsetCache::new(1 << 20, Config::default()).expect("a valid config")
}

fn section<'m>(message: &'m Message<'static>, section: Section) -> &'m [Record<'static>] {
    match section {
        Section::Answer => &message.answer,
        Section::Authority => &message.authority,
        Section::Additional => &message.additional,
    }
}

/// The `RRsets` of `section` of the response captured as `case` in `testdata/proto`.
fn rrsets(case: &str, from: Section) -> Vec<Rrset> {
    Rrset::group(section(&message(&captured(case)), from))
}

/// The one `RRset` of `section` of `case`.
fn rrset(case: &str, from: Section) -> Rrset {
    let [rrset] = <[Rrset; 1]>::try_from(rrsets(case, from)).expect("one RRset");
    rrset
}

/// The records of `section` of `case` but the first: another `RRset` of the same name, type and class.
fn fewer(case: &str, from: Section) -> Rrset {
    let message = message(&captured(case));
    let [rrset] =
        <[Rrset; 1]>::try_from(Rrset::group(&section(&message, from)[1..])).expect("one RRset");
    rrset
}

/// `example.com. A`, two records, TTL 29, from a recursive resolver.
fn a() -> Rrset {
    rrset("a", Section::Answer)
}

fn get(cache: &RrsetCache, rrset: &Rrset, now: u32) -> Option<Hit> {
    cache.get(rrset.owner(), rrset.rtype(), rrset.class(), now)
}

#[test]
fn rfc2181_5_group_keeps_one_rrset_per_name_type_and_class() {
    let glue = rrsets("referral_root", Section::Additional);
    // 13 servers, an A and an AAAA RRset each.
    assert_eq!(glue.len(), 26);
    let ns = rrset("referral_root", Section::Authority);
    assert_eq!((ns.rtype(), ns.rdatas().len()), (RecordType::NS, 13));
    // The same data in another order compares equal.
    let message = message(&captured("referral_root"));
    let mut reversed = message.authority.clone();
    reversed.reverse();
    assert_eq!(Rrset::group(&reversed), [ns]);
}

#[test]
fn rfc2181_5_group_drops_duplicates() {
    let message = message(&captured("a"));
    let twice: Vec<Record<'_>> = message
        .answer
        .iter()
        .chain(&message.answer)
        .cloned()
        .collect();
    assert_eq!(Rrset::group(&twice), [a()]);
}

#[test]
fn rfc4034_3_group_pairs_signatures_with_the_rrset_they_cover() {
    let message = dnssec::response("alg13_a");
    let sets = Rrset::group(&message.answer);
    let [set] = sets.as_slice() else {
        panic!("one RRset, its RRSIG with it: {sets:?}");
    };
    assert_eq!(set.rtype(), RecordType::A);
    assert_eq!(set.rrsigs().len(), 1);
    let smallest = message.answer.iter().map(|r| r.ttl).min();
    assert_eq!(Some(set.ttl()), smallest);
}

#[test]
fn rfc2181_5_2_the_ttl_is_the_smallest_of_the_rrset() {
    let message = message(&captured("a"));
    let mut records = message.answer.clone();
    records[1].ttl = Ttl::from_wire(7);
    let [set] = <[Rrset; 1]>::try_from(Rrset::group(&records)).expect("one RRset");
    assert_eq!(set.ttl().get(), 7);
}

#[test]
fn rfc4343_lookups_ignore_case() {
    let cache = cache();
    cache
        .insert(a(), Rank::AnswerNonAuthoritative, Checked::Unchecked, 0)
        .expect("stored");
    let hit = cache.get(&dns("EXAMPLE.Com."), RecordType::A, Class::IN, 0);
    assert_eq!(hit.map(|h| h.rrset.rdatas().len()), Some(2));
    assert_eq!(
        cache.get(&dns("example.com."), RecordType::AAAA, Class::IN, 0),
        None
    );
}

#[test]
fn rfc2181_5_4_1_ranks_are_ordered() {
    assert!(RANKS.is_sorted());
    assert_eq!(Rank::of(Section::Answer, true), Rank::AnswerAuthoritative);
    assert_eq!(
        Rank::of(Section::Authority, true),
        Rank::AuthorityAuthoritative
    );
    assert_eq!(
        Rank::of(Section::Answer, false),
        Rank::AnswerNonAuthoritative
    );
    assert_eq!(
        Rank::of(Section::Additional, true),
        Rank::AdditionalAuthoritative
    );
    assert_eq!(
        Rank::of(Section::Authority, false),
        Rank::AuthorityNonAuthoritative
    );
    assert_eq!(
        Rank::of(Section::Additional, false),
        Rank::AdditionalNonAuthoritative
    );
}

/// Each pair of ranks, other data: the higher replaces the lower, the lower leaves the higher.
#[test]
fn rfc2181_5_4_1_a_higher_rank_replaces_a_lower_one_and_not_the_reverse() {
    for (i, &low) in RANKS.iter().enumerate() {
        for &high in &RANKS[i + 1..] {
            let cache = cache();
            cache
                .insert(fewer("a", Section::Answer), low, Checked::Unchecked, 0)
                .expect("stored");
            let hit = cache
                .insert(a(), high, Checked::Unchecked, 1)
                .expect("stored");
            assert_eq!(
                (hit.rank, hit.rrset.rdatas().len()),
                (high, 2),
                "{high:?} over {low:?}"
            );

            let cache = self::cache();
            cache
                .insert(a(), high, Checked::Unchecked, 0)
                .expect("stored");
            let hit = cache
                .insert(fewer("a", Section::Answer), low, Checked::Unchecked, 1)
                .expect("kept");
            assert_eq!(
                (hit.rank, hit.rrset.rdatas().len()),
                (high, 2),
                "{low:?} under {high:?}"
            );
            assert_eq!(get(&cache, &a(), 1).map(|h| h.rank), Some(high));
        }
    }
}

#[test]
fn rfc2181_5_4_1_equal_rank_other_data_replaces_same_data_keeps() {
    let cache = cache();
    let first = cache
        .insert(a(), Rank::AnswerNonAuthoritative, Checked::Unchecked, 0)
        .expect("stored");
    // The same data later: the entry stays, its time running.
    let again = cache
        .insert(a(), Rank::AnswerNonAuthoritative, Checked::Unchecked, 10)
        .expect("kept");
    assert!(std::sync::Arc::ptr_eq(&first.rrset, &again.rrset));
    assert_eq!(again.ttl.get(), 50);
    // Other data at the same rank: the last heard of.
    let other = cache
        .insert(
            fewer("a", Section::Answer),
            Rank::AnswerNonAuthoritative,
            Checked::Unchecked,
            10,
        )
        .expect("stored");
    assert_eq!((other.rrset.rdatas().len(), other.ttl.get()), (1, 60));
}

/// The glue of a referral does not replace an answer: `example.com. NS` answered, then from `com`'s referral.
#[test]
fn rfc2181_5_4_1_referral_data_does_not_replace_an_answer() {
    let cache = cache();
    let answer = rrset("ns", Section::Answer);
    cache
        .insert(
            answer.clone(),
            Rank::AnswerNonAuthoritative,
            Checked::Unchecked,
            0,
        )
        .expect("stored");
    let referral = rrset("referral_com", Section::Authority);
    assert_eq!(referral, answer, "the same name servers");
    let hit = cache
        .insert(
            referral,
            Rank::AuthorityNonAuthoritative,
            Checked::Unchecked,
            0,
        )
        .expect("kept");
    assert_eq!(
        (hit.rank, hit.ttl.get()),
        (Rank::AnswerNonAuthoritative, 81_811)
    );

    let glue = fewer("a", Section::Answer);
    cache
        .insert(a(), Rank::AnswerNonAuthoritative, Checked::Unchecked, 0)
        .expect("stored");
    let hit = cache
        .insert(
            glue,
            Rank::AdditionalNonAuthoritative,
            Checked::Unchecked,
            0,
        )
        .expect("kept");
    assert_eq!(hit.rrset.rdatas().len(), 2);
}

#[test]
fn rfc2181_5_4_1_secure_data_is_trusted_above_any_rank() {
    let cache = cache();
    cache
        .insert(a(), Rank::AnswerAuthoritative, Checked::Unchecked, 0)
        .expect("stored");
    let hit = cache
        .insert(
            fewer("a", Section::Answer),
            Rank::AdditionalNonAuthoritative,
            Checked::Secure,
            0,
        )
        .expect("stored");
    assert_eq!(
        (hit.checked, hit.rrset.rdatas().len()),
        (Checked::Secure, 1)
    );
    let hit = cache
        .insert(a(), Rank::AnswerAuthoritative, Checked::Insecure, 0)
        .expect("kept");
    assert_eq!(hit.checked, Checked::Secure);
}

#[test]
fn rfc4035_4_7_bogus_data_gives_way_to_other_data_not_its_own() {
    let cache = cache();
    cache
        .insert(a(), Rank::AnswerAuthoritative, BOGUS, 0)
        .expect("stored");
    // The same data, trusted more: not stored, which would extend the life of bogus data.
    let hit = cache
        .insert(a(), Rank::AnswerAuthoritative, Checked::Insecure, 0)
        .expect("kept");
    assert_eq!(hit.checked, BOGUS);
    let hit = cache
        .insert(a(), Rank::AnswerAuthoritative, Checked::Secure, 0)
        .expect("stored");
    assert_eq!(hit.checked, Checked::Secure);

    let cache = self::cache();
    cache
        .insert(a(), Rank::AnswerAuthoritative, BOGUS, 0)
        .expect("stored");
    // Other data, of a lower rank: stored.
    let hit = cache
        .insert(
            fewer("a", Section::Answer),
            Rank::AdditionalNonAuthoritative,
            Checked::Unchecked,
            0,
        )
        .expect("stored");
    assert_eq!(
        (hit.checked, hit.rank),
        (Checked::Unchecked, Rank::AdditionalNonAuthoritative)
    );
}

#[test]
fn rfc1035_3_2_1_an_expired_rrset_is_replaced_by_anything() {
    let cache = cache();
    // TTL 29, raised to `min_ttl`, 60 (D124).
    cache
        .insert(a(), Rank::AnswerAuthoritative, Checked::Secure, 0)
        .expect("stored");
    assert_eq!(get(&cache, &a(), 28).map(|h| h.ttl.get()), Some(1));
    assert_eq!(get(&cache, &a(), 29), None);
    let hit = cache
        .insert(
            fewer("a", Section::Answer),
            Rank::AdditionalNonAuthoritative,
            BOGUS,
            29,
        )
        .expect("stored");
    assert_eq!(
        (hit.rank, hit.checked),
        (Rank::AdditionalNonAuthoritative, BOGUS)
    );
}

/// A delegation is not extended past its TTL by data that replaces it (ghost domain names): `example.com. NS` from
/// `com`'s referral, then answered 100 000 seconds later.
#[test]
fn rfc2181_5_4_1_an_ns_rrset_replacing_one_does_not_extend_its_ttl() {
    let cache = cache();
    let referral = rrset("referral_com", Section::Authority);
    let stored = cache
        .insert(
            referral,
            Rank::AuthorityNonAuthoritative,
            Checked::Unchecked,
            0,
        )
        .expect("stored");
    assert_eq!(stored.ttl.get(), 172_800);
    let answer = rrset("ns", Section::Answer);
    let hit = cache
        .insert(
            answer,
            Rank::AnswerNonAuthoritative,
            Checked::Unchecked,
            100_000,
        )
        .expect("stored");
    assert_eq!(
        (hit.rank, hit.ttl.get()),
        (Rank::AnswerNonAuthoritative, 72_800)
    );
    // Other servers, same rank: still the time left.
    let fewer = fewer("referral_com", Section::Authority);
    let hit = cache
        .insert(
            fewer,
            Rank::AnswerNonAuthoritative,
            Checked::Unchecked,
            172_000,
        )
        .expect("stored");
    assert_eq!((hit.rrset.rdatas().len(), hit.ttl.get()), (1, 800));
    // Once expired, the TTL received.
    let hit = cache
        .insert(
            rrset("ns", Section::Answer),
            Rank::AdditionalNonAuthoritative,
            Checked::Unchecked,
            172_800,
        )
        .expect("stored");
    assert_eq!(hit.ttl.get(), 81_811);
}

/// Other types take the TTL of the data replacing them.
#[test]
fn rfc2181_5_4_1_an_address_rrset_replacing_one_takes_its_own_ttl() {
    let cache = cache();
    cache
        .insert(a(), Rank::AdditionalNonAuthoritative, Checked::Unchecked, 0)
        .expect("stored");
    let hit = cache
        .insert(a(), Rank::AnswerNonAuthoritative, Checked::Unchecked, 30)
        .expect("stored");
    assert_eq!(hit.ttl.get(), 60);
}

#[test]
fn d124_ttls_follow_the_response_cache_config() {
    let config = Config {
        max_ttl: 3600,
        max_insecure_ttl: Some(600),
        bogus_ttl: 30,
        ..Config::default()
    };
    let cache = RrsetCache::new(1 << 20, config).expect("a valid config");
    let ttl = |rrset: Rrset, checked| {
        cache
            .insert(rrset, Rank::AnswerAuthoritative, checked, 0)
            .map(|h| h.ttl.get())
    };
    // Capped by `max_ttl`, the insecure and the bogus caps.
    let ns = || rrset("referral_root", Section::Authority);
    assert_eq!(ttl(ns(), Checked::Unchecked), Ok(3600));
    let glue = || rrsets("referral_root", Section::Additional);
    assert_eq!(ttl(glue().remove(0), Checked::Insecure), Ok(600));
    assert_eq!(ttl(glue().remove(1), BOGUS), Ok(30));
    // TTL 29 raised to `min_ttl` unless secure; secure data replaces the rest.
    assert_eq!(ttl(a(), Checked::Unchecked), Ok(60));
    assert_eq!(ttl(a(), Checked::Secure), Ok(29));
}

#[test]
fn rfc2181_8_ttl_0_and_past_2_pow_31_are_not_cached() {
    let cache = cache();
    cache
        .insert(a(), Rank::AdditionalNonAuthoritative, Checked::Unchecked, 0)
        .expect("stored");
    for wire in [0, 0x8000_0000, u32::MAX] {
        let message = message(&captured("a"));
        let mut records = message.answer.clone();
        records[0].ttl = Ttl::from_wire(wire);
        let [set] = <[Rrset; 1]>::try_from(Rrset::group(&records)).expect("one RRset");
        assert_eq!(
            cache.insert(set, Rank::AnswerAuthoritative, Checked::Secure, 0),
            Err(NotCached::ZeroTtl),
            "TTL {wire:#x}"
        );
    }
    // The cache is left as it was.
    assert_eq!(
        get(&cache, &a(), 0).map(|h| h.rank),
        Some(Rank::AdditionalNonAuthoritative)
    );
}

#[test]
fn d116_an_rrset_larger_than_an_entry_may_be_is_not_cached() {
    let config = Config {
        max_entry_bytes: Some(512),
        ..Config::default()
    };
    let cache = RrsetCache::new(1 << 20, config).expect("a valid config");
    let ns = rrset("referral_root", Section::Authority);
    assert_eq!(
        cache.insert(ns, Rank::AnswerAuthoritative, Checked::Unchecked, 0),
        Err(NotCached::TooLarge)
    );
    assert!(cache.is_empty());
}

#[test]
fn d116_the_capacity_must_hold_an_entry() {
    assert!(matches!(
        RrsetCache::new(1024, Config::default()),
        Err(ConfigError::Capacity(_))
    ));
    let invalid = Config {
        shards: 3,
        ..Config::default()
    };
    assert_eq!(
        RrsetCache::new(1 << 20, invalid).err(),
        Some(ConfigError::Shards(3))
    );
}

/// Every `RRset` of the captures, into a cache of 8 KiB: entries are evicted, the bytes stay within the capacity.
#[test]
fn d116_the_memory_bound_evicts() {
    const CAPACITY: usize = 8 << 10;
    let config = Config {
        shards: 1,
        max_entry_bytes: Some(2048),
        ..Config::default()
    };
    let cache = RrsetCache::new(CAPACITY, config).expect("a valid config");
    let mut stored = 0;
    for case in [
        "referral_root",
        "referral_com",
        "ns",
        "a",
        "aaaa",
        "mx",
        "txt_large",
        "srv",
        "caa",
        "https",
    ] {
        let message = message(&captured(case));
        for (from, records) in [
            (Section::Answer, &message.answer),
            (Section::Authority, &message.authority),
            (Section::Additional, &message.additional),
        ] {
            for set in Rrset::group(records) {
                if cache
                    .insert(set, Rank::of(from, false), Checked::Unchecked, 0)
                    .is_ok()
                {
                    stored += 1;
                }
                assert!(cache.used() <= CAPACITY, "{} bytes used", cache.used());
            }
        }
    }
    assert!(
        cache.len() < stored,
        "{} entries of {stored} stored",
        cache.len()
    );
    // The last stored is still there.
    let https = rrset("https", Section::Answer);
    assert!(get(&cache, &https, 0).is_some());
}
