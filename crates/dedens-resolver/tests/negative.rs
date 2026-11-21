//! Negative caching (D199) on the captured resolutions of `testdata/recursion/`: RFC 2308 §5 (a negative answer
//! cached by name and type, its TTL), RFC 8020 §2 (no name below a secure NXDOMAIN), RFC 8198 §4 and §5
//! (denials proved by the NSEC and NSEC3 records cached, the wildcard checked, an opt-out span never) and RFC 9520
//! §3.2 (a failure held, backing off). A question that must not be asked meets a server that times out: what the
//! resolution sends shows whether it asked.

use std::sync::Arc;
use std::time::Duration;

use dedens_cache::{Checked, Config, Cost};
use dedens_dnssec::crypto::Budget;
use dedens_dnssec::denial::{canonical_cmp, hashed_owner, owner_hash};
use dedens_dnssec::{TrustAnchors, Validator};
use dedens_proto::rdata::{Nsec3, RData};
use dedens_proto::{Class, Message, Name, Question, Record, RecordType, Ttl};
use dedens_resolver::{
    Caches, Failure, Kind, Limits, Minimisation, NotCached, Rank, Ranked, Resolution, Resolved,
    Rrset, RrsetCache,
};
use dedens_testkit::recursion;

use crate::iteration::{Answered, at, configured, name, response, run, served, start};

/// The captured resolution `id`.
fn capture(id: &str) -> recursion::Resolution {
    recursion::Resolution::read(id)
}

/// A validator from the root's anchors, as the validation tests have it.
fn validator() -> Validator {
    Validator::new(TrustAnchors::root(), dedens_dnssec::Limits::default())
}

/// Resolves the question of capture `id` on `caches` from the captured servers, validated if `validating`.
fn first(id: &str, caches: &Arc<Caches>, validating: bool) -> Resolved {
    let capture = capture(id);
    let mut resolution = start(&capture, caches, Limits::default());
    if validating {
        resolution = resolution.validated(validator(), at(&capture).as_secs());
    }
    served(&capture, caches, &mut resolution, &|_, _| {}).0
}

/// A resolution of `name` and `rtype` at `now` on `caches`, validated if `validating`.
fn resolution(
    caches: &Arc<Caches>,
    (text, rtype): (&str, RecordType),
    now: Duration,
    validating: bool,
) -> Resolution {
    let resolution = Resolution::start(
        Question::new(name(text), rtype),
        Arc::clone(caches),
        now,
        Limits {
            queries: 1000,
            servers: 1000,
            ..Limits::default()
        },
        Minimisation::Off,
    )
    .expect("an IN question");
    if validating {
        resolution.validated(validator(), now.as_secs())
    } else {
        resolution
    }
}

/// What a resolution of `question` at `now` comes to when no server answers, and how many queries it sent.
fn silent(
    caches: &Arc<Caches>,
    question: (&str, RecordType),
    now: Duration,
    validating: bool,
) -> (Resolved, usize) {
    let mut resolution = resolution(caches, question, now, validating);
    let (resolved, sent) = run(&mut resolution, &|_| Answered::Timeout, now);
    (resolved, sent.len())
}

/// The SOA TTL and MINIMUM field of the negative answer in `response`.
fn soa_of(response: &Message<'_>) -> (u32, u32) {
    response
        .authority
        .iter()
        .find_map(|record| match record.data() {
            RData::Soa(soa) => Some((record.ttl.get(), soa.minimum)),
            _ => None,
        })
        .expect("an SOA in the authority section")
}

/// The NSEC3 records of `response`'s authority section: each owner's hash and the record.
fn nsec3s<'r>(response: &'r Message<'_>) -> Vec<([u8; 20], Nsec3<'r>)> {
    response
        .authority
        .iter()
        .filter_map(|record| match record.data() {
            RData::Nsec3(nsec3) => {
                let label = record.name.labels().next()?;
                Some((owner_hash(label)?, nsec3))
            }
            _ => None,
        })
        .collect()
}

/// Whether `hash` is covered by the span from `owner` to `next`, which wraps from the last to the first.
fn covers(owner: &[u8; 20], next: &[u8], hash: &[u8; 20]) -> bool {
    if owner.as_slice() < next {
        owner < hash && hash.as_slice() < next
    } else {
        owner < hash || hash.as_slice() < next
    }
}

/// A name `<n>.apex` that is not `exclude`, whose hash is covered by an NSEC3 record of `response` with the opt-out
/// flag `opt_out`: a name the response proves absent as well as the one asked.
fn spanned(response: &Message<'_>, apex: &str, opt_out: bool, exclude: &str) -> String {
    let records = nsec3s(response);
    let hash = |name: &Name<'_>| {
        let (_, any) = records.first().expect("an NSEC3 record");
        Budget::default()
            .nsec3_hash(any.salt(), any.iterations, name)
            .expect("a hash")
    };
    let covered = |hash: &[u8; 20]| {
        records.iter().any(|(owner, nsec3)| {
            covers(owner, nsec3.next_hashed_owner(), hash) && nsec3.is_opt_out() == opt_out
        })
    };
    (0..100_000)
        .map(|n| format!("dedens-{n}.{apex}"))
        .find(|text| text != exclude && covered(&hash(&name(text))))
        .expect("a name in a span")
}

/// A name `dedens-<n>.<apex>` other than `exclude` that an NSEC record of `response` covers, as it covers the one
/// asked: strictly between its owner and next name.
fn nsec_spanned(response: &Message<'_>, exclude: &str) -> String {
    let spans: Vec<(Name<'_>, Name<'_>)> = response
        .authority
        .iter()
        .filter_map(|record| match record.data() {
            RData::Nsec(nsec) => Some((record.name.clone(), nsec.next.clone().into_owned())),
            _ => None,
        })
        .collect();
    let apex = exclude
        .split_once('.')
        .map(|(_, apex)| apex)
        .expect("a name below an apex");
    (0..100_000)
        .map(|n| format!("dedens-{n}.{apex}"))
        .find(|text| {
            let at = name(text);
            text != exclude
                && spans.iter().any(|(owner, next)| {
                    canonical_cmp(owner, &at).is_lt() && canonical_cmp(&at, next).is_lt()
                })
        })
        .expect("a name in a span")
}

/// The response from `zone`'s server to `asked` in capture `id`.
fn denial(id: &str, zone: &str, asked: &str) -> Message<'static> {
    response(&capture(id), zone, asked)
}

/// The SOA of the negative answer of `zone`'s server to `asked` in capture `id`, as a cache holds it for `ttl`.
fn ranked_soa(id: &str, zone: &str, asked: &str, ttl: u32) -> Ranked {
    let soa = Rrset::group(&denial(id, zone, asked).authority)
        .into_iter()
        .find(|set| set.rtype() == RecordType::SOA)
        .expect("an SOA RRset");
    Ranked {
        rrset: Arc::new(soa),
        rank: Rank::AuthorityAuthoritative,
        checked: Checked::Unchecked,
        ttl: Ttl::from_wire(ttl),
    }
}

/// The least TTL a negative answer in `cache` under `owner` has at `now`, `None` if it holds none.
fn left(cache: &RrsetCache, owner: &Name<'_>, now: u32) -> Option<(u32, String)> {
    let held = cache.negative(owner, Kind::NxDomain, now)?;
    Some((held.soa.ttl.get(), held.soa.rrset.owner().to_string()))
}

#[test]
fn d199_a_negative_answer_judged_secure_gives_way_to_nothing_less() {
    let cache = RrsetCache::new(1 << 20, Config::default()).expect("a cache");
    let owner = name("dedens-nxdomain.google.com.");
    let google = ranked_soa(
        "nxdomain-unsigned",
        "google.com.",
        "dedens-nxdomain.google.com.",
        60,
    );
    let sidn = ranked_soa(
        "nxdomain-signed",
        "sidn.nl.",
        "dedens-nxdomain.sidn.nl.",
        60,
    );
    cache
        .insert_negative(&owner, Kind::NxDomain, &google, &[], Checked::Secure, 0)
        .expect("stored");
    for checked in [Checked::Insecure, Checked::Unchecked] {
        cache
            .insert_negative(&owner, Kind::NxDomain, &sidn, &[], checked, 0)
            .expect("stored");
        assert_eq!(
            left(&cache, &owner, 0),
            Some((60, "google.com.".into())),
            "{checked:?} replaced secure"
        );
    }
    // Secure data replaces secure data of another content, the latest heard of.
    cache
        .insert_negative(&owner, Kind::NxDomain, &sidn, &[], Checked::Secure, 0)
        .expect("stored");
    assert_eq!(left(&cache, &owner, 0), Some((60, "sidn.nl.".into())));
}

#[test]
fn d199_an_unchecked_negative_answer_gives_way_to_a_verdict_and_the_same_data_does_not_renew() {
    let cache = RrsetCache::new(1 << 20, Config::default()).expect("a cache");
    let owner = name("dedens-nxdomain.google.com.");
    let google = ranked_soa(
        "nxdomain-unsigned",
        "google.com.",
        "dedens-nxdomain.google.com.",
        60,
    );
    let sidn = ranked_soa(
        "nxdomain-signed",
        "sidn.nl.",
        "dedens-nxdomain.sidn.nl.",
        60,
    );
    cache
        .insert_negative(&owner, Kind::NxDomain, &google, &[], Checked::Unchecked, 0)
        .expect("stored");
    // Another unchecked answer replaces it: the last heard of.
    cache
        .insert_negative(&owner, Kind::NxDomain, &sidn, &[], Checked::Unchecked, 0)
        .expect("stored");
    assert_eq!(left(&cache, &owner, 0), Some((60, "sidn.nl.".into())));
    // The same data, judged insecure, replaces it...
    cache
        .insert_negative(&owner, Kind::NxDomain, &sidn, &[], Checked::Insecure, 10)
        .expect("stored");
    assert_eq!(
        left(&cache, &owner, 10),
        Some((60, "sidn.nl.".into())),
        "the verdict gave way to nothing"
    );
    // ... and the same data again, with the same verdict, does not renew it.
    cache
        .insert_negative(&owner, Kind::NxDomain, &sidn, &[], Checked::Insecure, 30)
        .expect("stored");
    assert_eq!(
        left(&cache, &owner, 30),
        Some((40, "sidn.nl.".into())),
        "renewed"
    );
    // Another verdict's data of the same kind: Insecure replaces by another Insecure, not by Unchecked.
    cache
        .insert_negative(&owner, Kind::NxDomain, &google, &[], Checked::Unchecked, 30)
        .expect("stored");
    assert_eq!(left(&cache, &owner, 30), Some((40, "sidn.nl.".into())));
    // Once expired, anything replaces it.
    cache
        .insert_negative(&owner, Kind::NxDomain, &google, &[], Checked::Unchecked, 71)
        .expect("stored");
    assert_eq!(left(&cache, &owner, 71), Some((60, "google.com.".into())));
}

#[test]
fn d199_an_entry_over_the_limit_is_not_stored_and_a_longest_name_is_keyed() {
    let soa = ranked_soa(
        "nxdomain-unsigned",
        "google.com.",
        "dedens-nxdomain.google.com.",
        60,
    );
    let small = Config {
        max_entry_bytes: Some(270),
        ..Config::default()
    };
    let cache = RrsetCache::new(1 << 20, small).expect("a cache");
    let owner = name("dedens-nxdomain.google.com.");
    let denials = vec![soa.clone(); 3];
    let stored = cache.insert_negative(&owner, Kind::NxDomain, &soa, &denials, Checked::Secure, 0);
    assert_eq!(stored, Err(NotCached::TooLarge));
    assert!(cache.negative(&owner, Kind::NxDomain, 0).is_none());
    // The longest name, 253 octets, with a key longer than any other: a negative answer and a failure held.
    let label = "a".repeat(63);
    let longest = name(&format!("{label}.{label}.{label}.{}.", "b".repeat(61)));
    let cache = RrsetCache::new(1 << 20, Config::default()).expect("a cache");
    cache
        .insert_negative(
            &longest,
            Kind::NoData(RecordType::TXT),
            &soa,
            &[],
            Checked::Secure,
            0,
        )
        .expect("stored");
    assert!(
        cache
            .negative(&longest, Kind::NoData(RecordType::TXT), 0)
            .is_some()
    );
}

#[test]
fn d199_a_secure_set_not_within_its_signer_is_not_indexed() {
    // The NSEC3 record of nl. moved to a name of another zone: its signer does not sign there.
    let counted = |owner: &Name<'static>| {
        let config = Config {
            shards: 1,
            ..Config::default()
        };
        let cache = RrsetCache::new(1 << 20, config).expect("a cache");
        for set in nsec3_sets(0) {
            let records: Vec<Record<'static>> = set
                .rdatas()
                .iter()
                .map(|rdata| Record {
                    name: owner.clone(),
                    class: Class::IN,
                    ttl: Ttl::from_wire(300),
                    rdata: rdata.clone(),
                })
                .chain(set.rrsigs().iter().map(|rdata| Record {
                    name: owner.clone(),
                    class: Class::IN,
                    ttl: Ttl::from_wire(300),
                    rdata: rdata.clone(),
                }))
                .collect();
            for set in Rrset::group(&records) {
                let rank = Rank::AuthorityAuthoritative;
                cache.insert(set, rank, Checked::Secure, 0).expect("stored");
            }
        }
        cache.used()
    };
    let within = counted(&hashed_owner(&name("nl."), &[1; 20]).expect("a name"));
    let outside = counted(&hashed_owner(&name("com."), &[1; 20]).expect("a name"));
    assert!(
        within > outside,
        "{within} for a set within nl., {outside} for one outside"
    );
}

#[test]
fn d199_a_negative_answer_costs_what_its_sets_do() {
    let owner = name("dedens-nxdomain.google.com.");
    let soa = ranked_soa(
        "nxdomain-unsigned",
        "google.com.",
        "dedens-nxdomain.google.com.",
        60,
    );
    let sets = soa.rrset.cost();
    let cache = RrsetCache::new(1 << 20, Config::default()).expect("a cache");
    let before = cache.used();
    cache
        .insert_negative(&owner, Kind::NxDomain, &soa, &[], Checked::Secure, 0)
        .expect("stored");
    // The sets, and the entry's own bytes, its key and slot: some hundreds.
    let held = cache.used() - before;
    assert!(
        (sets..sets + 600).contains(&held),
        "{held} bytes for sets of {sets}"
    );
}

#[cfg(feature = "metrics")]
#[test]
fn d199_the_denials_and_the_holds_are_counted() {
    use metrics_util::debugging::DebuggingRecorder;

    let recorder = DebuggingRecorder::new();
    let snapshotter = recorder.snapshotter();
    metrics::with_local_recorder(&recorder, || {
        let caches = configured(false, Config::default());
        let capture = capture("nxdomain-signed");
        let denial = denial("nxdomain-signed", "sidn.nl.", &capture.name.to_string());
        let second = nsec_spanned(&denial, &capture.name.to_string());
        first("nxdomain-signed", &caches, true);
        let text = capture.name.to_string();
        silent(&caches, (&text, capture.rtype), at(&capture), true);
        silent(
            &caches,
            (&format!("www.{text}"), capture.rtype),
            at(&capture),
            true,
        );
        silent(&caches, (&second, capture.rtype), at(&capture), true);
        let unsigned = self::capture("unsigned");
        let caches = configured(false, Config::default());
        let name = unsigned.name.to_string();
        for _ in 0..2 {
            let mut failing = resolution(&caches, (&name, unsigned.rtype), at(&unsigned), false);
            run(&mut failing, &|_| Answered::ServerError, at(&unsigned));
        }
    });
    let counters = crate::metrics::counters(&snapshotter);
    let count = |name: &str| {
        counters
            .iter()
            .find(|(n, _)| n == name)
            .map_or(0, |(_, n)| *n)
    };
    assert_eq!(count("dedens_resolver_denials_total exact"), 1);
    assert_eq!(count("dedens_resolver_denials_total below_nxdomain"), 1);
    assert_eq!(count("dedens_resolver_denials_total aggressive"), 1);
    assert_eq!(count("dedens_resolver_failure_holds_total recorded"), 1);
    assert_eq!(count("dedens_resolver_failure_holds_total served"), 1);
}

/// The first NSEC3 record of nl.'s denial in capture `nxdomain-nsec3`, with its signature, as `RRset`s with their
/// owner another hash `i` of the zone nl., a new one for the index of spans.
fn nsec3_sets(i: usize) -> Vec<Rrset> {
    let capture = capture("nxdomain-nsec3");
    let response = denial("nxdomain-nsec3", "nl.", &capture.name.to_string());
    let records: Vec<_> = response
        .authority
        .iter()
        .filter(|record| match record.data() {
            RData::Nsec3(_) => true,
            RData::Rrsig(sig) => sig.type_covered == RecordType::NSEC3,
            _ => false,
        })
        .cloned()
        .collect();
    let first = records.first().expect("an NSEC3 record").name.clone();
    let mut hash = [0; 20];
    hash[..8].copy_from_slice(&(u64::try_from(i).expect("a small index") + 1).to_be_bytes());
    let moved: Vec<_> = records
        .into_iter()
        .filter(|record| record.name == first)
        .map(|record| Record {
            name: hashed_owner(&name("nl."), &hash).expect("a name"),
            ..record
        })
        .collect();
    Rrset::group(&moved)
}

/// The bytes the index of spans takes in a cache of `capacity` bytes in one shard after `count` secure NSEC3 sets
/// are inserted, `judged` as it is: the cache's `used` less that of one holding the same sets unchecked.
fn spans_used(capacity: usize, count: usize) -> usize {
    let config = Config {
        shards: 1,
        ..Config::default()
    };
    let indexed = RrsetCache::new(capacity, config.clone()).expect("a cache");
    let apart = RrsetCache::new(capacity, config).expect("a cache");
    for i in 0..count {
        for set in nsec3_sets(i) {
            let rank = Rank::AuthorityAuthoritative;
            indexed
                .insert(set.clone(), rank, Checked::Secure, 0)
                .expect("stored");
            apart
                .insert(set, rank, Checked::Insecure, 0)
                .expect("stored");
        }
    }
    assert!(
        indexed.used() <= capacity,
        "{} of {capacity}",
        indexed.used()
    );
    indexed.used() - apart.used()
}

#[test]
fn d199_the_index_of_spans_counts_its_zone_and_each_hash_it_holds() {
    // A zone's own bytes and a hash's, node included: the index is no free of charge.
    let one = spans_used(1 << 20, 1);
    let two = spans_used(1 << 20, 2);
    assert!((60..300).contains(&one), "{one}");
    assert!((two - one) >= 44 && (two - one) < 100, "{one} then {two}");
}

#[test]
fn d199_the_index_of_spans_stays_within_its_share_of_the_capacity() {
    let capacity = 1 << 16;
    let used = spans_used(capacity, 400);
    // 400 hashes of 44 bytes are over the 2 KiB the index may have: it started over, more than once.
    assert!(used <= capacity / 32, "{used} of {}", capacity / 32);
    assert!(used > capacity / 64, "{used}: kept next to nothing");
}

#[test]
fn rfc2308_5_a_negative_answer_is_cached_for_its_name_and_type() {
    for (id, validating) in [("nodata-signed", true), ("nodata-unsigned", false)] {
        let capture = capture(id);
        let caches = configured(false, Config::default());
        let first = first(id, &caches, validating);
        assert!(matches!(first, Resolved::NoData { .. }), "{id}: {first:?}");
        let text = capture.name.to_string();
        let (again, sent) = silent(&caches, (&text, capture.rtype), at(&capture), validating);
        assert_eq!(sent, 0, "{id}: asked again");
        assert_eq!(again, first, "{id}");
        // Not for the other types of the name: a type it has is asked.
        let (_, sent) = silent(&caches, (&text, RecordType::A), at(&capture), validating);
        assert!(sent > 0, "{id}: A not asked");
    }
}

#[test]
fn rfc2308_5_the_ttl_is_the_least_of_the_soa_ttl_and_its_minimum_bounded_by_max_negative_ttl() {
    let capture = capture("nxdomain-unsigned");
    let (ttl, minimum) = soa_of(&denial(
        "nxdomain-unsigned",
        "google.com.",
        "dedens-nxdomain.google.com.",
    ));
    let least = ttl.min(minimum);
    assert!(least > 2, "a capture whose TTL can be bounded: {least}");
    for bound in [None, Some(least - 1)] {
        let config = Config {
            min_ttl: 0,
            max_negative_ttl: bound.unwrap_or(Config::default().max_negative_ttl),
            ..Config::default()
        };
        let lives = bound.unwrap_or(least);
        let caches = configured(false, config);
        let Resolved::NxDomain { soa, .. } = first("nxdomain-unsigned", &caches, false) else {
            panic!("an NXDOMAIN")
        };
        let _ = soa;
        let (answer, _) = silent(
            &caches,
            (capture.name.to_string().as_str(), capture.rtype),
            at(&capture),
            false,
        );
        let Resolved::NxDomain { soa, .. } = answer else {
            panic!("an NXDOMAIN from the cache")
        };
        assert_eq!(soa.ttl.get(), lives, "{bound:?}");
        let text = capture.name.to_string();
        let question = (text.as_str(), capture.rtype);
        let before = at(&capture) + Duration::from_secs(u64::from(lives) - 1);
        let (_, sent) = silent(&caches, question, before, false);
        assert_eq!(sent, 0, "{bound:?}: asked within its lifetime");
        let after = at(&capture) + Duration::from_secs(u64::from(lives));
        let (_, sent) = silent(&caches, question, after, false);
        assert!(sent > 0, "{bound:?}: not asked after its lifetime");
    }
}

#[test]
fn rfc8020_2_no_name_exists_below_a_secure_nxdomain() {
    let caches = configured(false, Config::default());
    let capture = capture("nxdomain-signed");
    let asked = first("nxdomain-signed", &caches, true);
    assert!(matches!(asked, Resolved::NxDomain { .. }), "{asked:?}");
    let base = capture.name.to_string();
    for (below, rtype) in [
        (format!("www.{base}"), RecordType::A),
        (format!("a.b.{base}"), RecordType::TXT),
        (format!("alpha.beta.{base}"), RecordType::TXT),
        (format!("_dmarc.{base}"), RecordType::MX),
    ] {
        // Without the aggressive use of the NSEC records the zone's span would answer these as well.
        let mut resolution =
            resolution(&caches, (&below, rtype), at(&capture), true).aggressive_nsec(false);
        let (resolved, sent) = run(&mut resolution, &|_| Answered::Timeout, at(&capture));
        assert!(sent.is_empty(), "{below} asked");
        let Resolved::NxDomain { soa, denials, .. } = resolved else {
            panic!("{below}: {resolved:?}")
        };
        assert_eq!(soa.checked, dedens_cache::Checked::Secure, "{below}");
        assert!(!denials.is_empty(), "{below}: no proof");
    }
    // A name beside it is another matter.
    let (_, sent) = silent(&caches, ("sidn.nl.", RecordType::TXT), at(&capture), true);
    assert!(sent > 0);
}

#[test]
fn rfc8020_2_a_name_below_an_insecure_or_unchecked_nxdomain_is_asked() {
    let capture = capture("nxdomain-unsigned");
    for validating in [true, false] {
        let caches = configured(false, Config::default());
        let asked = first("nxdomain-unsigned", &caches, validating);
        assert!(matches!(asked, Resolved::NxDomain { .. }), "{asked:?}");
        let below = format!("www.{}", capture.name);
        let (_, sent) = silent(&caches, (&below, RecordType::A), at(&capture), validating);
        assert!(sent > 0, "validating {validating}: not asked");
    }
}

#[test]
fn rfc8198_4_a_name_in_an_nsec_span_the_cache_holds_is_answered_without_a_query() {
    // sidn.nl is signed with NSEC: the name, the closest encloser and the wildcard are proved by its records.
    let caches = configured(false, Config::default());
    let capture = capture("nxdomain-signed");
    let denial = denial("nxdomain-signed", "sidn.nl.", &capture.name.to_string());
    let second = nsec_spanned(&denial, &capture.name.to_string());
    let asked = first("nxdomain-signed", &caches, true);
    assert!(matches!(asked, Resolved::NxDomain { .. }), "{asked:?}");
    let (resolved, sent) = silent(&caches, (&second, RecordType::A), at(&capture), true);
    assert_eq!(sent, 0, "{second} asked");
    let Resolved::NxDomain { soa, denials, .. } = resolved else {
        panic!("{second}: {resolved:?}")
    };
    assert_eq!(soa.checked, dedens_cache::Checked::Secure);
    assert!(!denials.is_empty(), "no denial records");
    // Whatever the type: the name does not exist.
    let (resolved, sent) = silent(&caches, (&second, RecordType::MX), at(&capture), true);
    assert_eq!(
        (sent, matches!(resolved, Resolved::NxDomain { .. })),
        (0, true)
    );
    // A name the NSEC records do not cover is asked.
    let (_, sent) = silent(&caches, ("www.sidn.nl.", RecordType::A), at(&capture), true);
    assert!(sent > 0, "www.sidn.nl asked of no one");
}

#[test]
fn rfc8198_4_a_name_in_an_nsec3_span_the_cache_holds_is_answered_without_a_query() {
    // nl is signed with NSEC3 without opt-out? Its closest encloser proof covers the name and the wildcard.
    let caches = configured(false, Config::default());
    let capture = capture("nxdomain-nsec3");
    let denial = denial("nxdomain-nsec3", "nl.", "dedens-nxdomain.nl.");
    let second = spanned(&denial, "nl.", false, "dedens-nxdomain.nl.");
    let asked = first("nxdomain-nsec3", &caches, true);
    assert!(matches!(asked, Resolved::NxDomain { .. }), "{asked:?}");
    let (resolved, sent) = silent(&caches, (&second, RecordType::A), at(&capture), true);
    assert_eq!(sent, 0, "{second} asked");
    assert!(
        matches!(resolved, Resolved::NxDomain { .. }),
        "{resolved:?}"
    );
}

#[test]
fn rfc8198_4_a_type_the_nsec_record_of_a_name_lacks_is_answered_nodata_without_a_query() {
    // The NSEC record of sidn.nl, read to answer an SRV question, says the name has no HINFO either.
    let caches = configured(false, Config::default());
    let capture = capture("nodata-signed");
    let asked = first("nodata-signed", &caches, true);
    assert!(matches!(asked, Resolved::NoData { .. }), "{asked:?}");
    let name = capture.name.to_string();
    let (resolved, sent) = silent(&caches, (&name, RecordType::HINFO), at(&capture), true);
    assert_eq!(sent, 0, "{name} HINFO asked");
    let Resolved::NoData { soa, denials, .. } = resolved else {
        panic!("{name}: {resolved:?}")
    };
    assert_eq!(soa.checked, dedens_cache::Checked::Secure);
    assert!(!denials.is_empty(), "no denial records");
    // A type the record lists exists: asked.
    let (resolved, _) = silent(&caches, (&name, RecordType::SOA), at(&capture), true);
    assert!(!matches!(resolved, Resolved::NoData { .. }), "{resolved:?}");
}

#[test]
fn rfc8198_4_a_resolution_with_the_switch_off_asks() {
    let caches = configured(false, Config::default());
    let capture = capture("nxdomain-signed");
    let denial = denial("nxdomain-signed", "sidn.nl.", &capture.name.to_string());
    let second = nsec_spanned(&denial, &capture.name.to_string());
    first("nxdomain-signed", &caches, true);
    let mut off =
        resolution(&caches, (&second, RecordType::A), at(&capture), true).aggressive_nsec(false);
    let (_, sent) = run(&mut off, &|_| Answered::Timeout, at(&capture));
    assert!(!sent.is_empty(), "switch off: nothing asked");
}

#[test]
fn rfc8198_5_an_opt_out_span_proves_no_name_absent() {
    // dedens.ws is an unsigned delegation proved by an opt-out span of ws (RFC 5155 §6, §9.2): the answer is judged
    // insecure and its NSEC3 records are not kept as secure ones, so no other name in the span is taken as absent,
    // as one in an opt-out span may be an unsigned delegation too (`aggressive` refuses a proof with the flag).
    let caches = configured(false, Config::default());
    let capture = capture("wildcard-optout");
    first("wildcard-optout", &caches, true);
    let denial = denial("wildcard-optout", "ws.", &capture.name.to_string());
    let second = spanned(&denial, "ws.", true, &capture.name.to_string());
    let (_, sent) = silent(&caches, (&second, RecordType::A), at(&capture), true);
    assert!(sent > 0, "{second} answered from an opt-out span");
}

/// The records of `response`'s authority section at `owner` of type `rtype`, with the signatures over them, as
/// `RRset`s moved to the name `to` and signed by `signer`: the data stays as the zone served it, its place and its
/// signer are another zone's.
fn relocated(
    response: &Message<'_>,
    (owner, rtype): (&Name<'_>, RecordType),
    (to, signer): (&Name<'static>, &Name<'static>),
) -> Vec<Rrset> {
    let moved: Vec<_> = response
        .authority
        .iter()
        .filter(|record| record.name == *owner)
        .filter_map(|record| {
            let rdata = match record.data() {
                RData::Rrsig(mut sig) if sig.type_covered == rtype => {
                    sig.signer = signer.clone();
                    (&RData::Rrsig(sig)).into()
                }
                _ if record.rtype() == rtype => record.rdata.clone().into_owned(),
                _ => return None,
            };
            Some(Record {
                name: to.clone(),
                class: Class::IN,
                ttl: record.ttl,
                rdata,
            })
        })
        .collect();
    Rrset::group(&moved)
}

/// Stores `sets` as the validator leaves them, secure, at the rank of an authority section, at `now`.
fn store_secure(cache: &RrsetCache, sets: Vec<Rrset>, now: Duration) {
    let now = u32::try_from(now.as_secs()).expect("a time in 32 bits");
    for set in sets {
        let rank = Rank::AuthorityAuthoritative;
        cache
            .insert(set, rank, Checked::Secure, now)
            .expect("stored");
    }
}

#[test]
fn d199_the_nsec_at_the_apex_of_a_child_is_not_its_parents_proof_and_does_not_replace_it() {
    // sidn.nl's records of the denial: sidn.nl NSEC _amazonses.sidn.nl and cybersterk.sidn.nl NSEC dev.sidn.nl. A
    // child zone cybersterk.sidn.nl has an NSEC at its own apex, the apex record of sidn.nl moved there: its chain
    // runs round the whole zone, past m.sidn.nl, which the parent's records leave open.
    let capture = capture("nxdomain-signed");
    let asked = capture.name.to_string();
    let response = denial("nxdomain-signed", "sidn.nl.", &asked);
    let covered = nsec_spanned(&response, &asked);
    let caches = configured(false, Config::default());
    store_secure(
        &caches.rrsets,
        Rrset::group(&response.authority),
        at(&capture),
    );
    let child = name("cybersterk.sidn.nl.");
    let apex = relocated(
        &response,
        (&name("sidn.nl."), RecordType::NSEC),
        (&child, &child),
    );
    assert_eq!(apex.len(), 1);
    store_secure(&caches.rrsets, apex, at(&capture));
    // The parent's record still proves what it did.
    let (resolved, sent) = silent(&caches, (&covered, RecordType::A), at(&capture), true);
    assert_eq!(sent, 0, "{covered} asked");
    assert!(
        matches!(resolved, Resolved::NxDomain { .. }),
        "{resolved:?}"
    );
    // The child's does not prove what the parent's leaves open: the name is asked.
    let (resolved, sent) = silent(&caches, ("m.sidn.nl.", RecordType::A), at(&capture), true);
    assert!(
        sent > 0 && !matches!(resolved, Resolved::NxDomain { .. }),
        "{sent} asked, {resolved:?}"
    );
}

#[test]
fn d199_an_nsec3_signed_by_a_child_at_the_name_of_a_hash_of_its_parent_is_not_its_proof() {
    // nl.'s NSEC3 records of the denial of dedens-nxdomain.nl: the cover of its hash is `cover`. A child zone named
    // like that hash signs an NSEC3 at its own apex, another record of nl. moved there, whose span is the widest of
    // those held: it replaces the parent's record, and a hash between the cover and the next owner held, which the
    // parent's span leaves open, falls in it.
    let capture = capture("nxdomain-nsec3");
    let asked = capture.name.to_string();
    let response = denial("nxdomain-nsec3", "nl.", &asked);
    let records = nsec3s(&response);
    let mut budget = Budget::default();
    let mut hash = |text: &str| {
        let (_, any) = records.first().expect("an NSEC3 record");
        budget
            .nsec3_hash(any.salt(), any.iterations, &name(text))
            .expect("a hash")
    };
    let wanted = hash(&asked);
    let (cover, _) = records
        .iter()
        .find(|(owner, nsec3)| covers(owner, nsec3.next_hashed_owner(), &wanted))
        .expect("a record covering the name");
    let (wide, widest) = records
        .iter()
        .max_by_key(|(_, nsec3)| nsec3.next_hashed_owner().to_vec())
        .expect("a record");
    // The next owner held after the cover's: the hashes between are those the index sends to the cover's record.
    let after = records
        .iter()
        .map(|(owner, _)| owner)
        .filter(|owner| *owner > cover)
        .min()
        .expect("an owner after the cover");
    assert!(
        after.as_slice() < widest.next_hashed_owner(),
        "the widest span runs past it"
    );
    let outside = (0..100_000)
        .map(|n| format!("dedens-{n}.nl."))
        .find(|text| {
            let hash = hash(text);
            cover < &hash
                && &hash < after
                && !records
                    .iter()
                    .any(|(owner, nsec3)| covers(owner, nsec3.next_hashed_owner(), &hash))
        })
        .expect("a name the parent's records leave open");
    let nl = name("nl.");
    let moved = |hash: &[u8; 20]| hashed_owner(&nl, hash).expect("a name");
    let child = moved(cover);
    let forged = relocated(
        &response,
        (&moved(wide), RecordType::NSEC3),
        (&child, &child),
    );
    assert_eq!(forged.len(), 1);
    let caches = configured(false, Config::default());
    store_secure(
        &caches.rrsets,
        Rrset::group(&response.authority),
        at(&capture),
    );
    store_secure(&caches.rrsets, forged, at(&capture));
    let (resolved, sent) = silent(&caches, (&outside, RecordType::A), at(&capture), true);
    assert!(
        sent > 0 && !matches!(resolved, Resolved::NxDomain { .. }),
        "{outside}: {sent} asked, {resolved:?}"
    );
}

#[test]
fn rfc9520_3_2_a_failing_set_of_servers_is_not_asked_again_at_once_and_backs_off() {
    let capture = capture("unsigned");
    let caches = configured(false, Config::default());
    let text = capture.name.to_string();
    let question = (text.as_str(), capture.rtype);
    let base = at(&capture);
    let secs = |s: u64| base + Duration::from_secs(s);
    let fails = |caches: &Arc<Caches>, now: Duration| {
        let mut resolution = resolution(caches, question, now, false);
        let (resolved, sent) = run(&mut resolution, &|_| Answered::ServerError, now);
        (resolved, sent.len())
    };
    // Config::failure_min, 5 s: held from the first failure.
    let (resolved, sent) = fails(&caches, base);
    assert_eq!(resolved, Resolved::Failed(Failure::Network));
    assert!(sent > 0);
    for held in [0, 4] {
        let (resolved, sent) = fails(&caches, secs(held));
        assert_eq!(
            (resolved, sent),
            (Resolved::Failed(Failure::Network), 0),
            "at {held}"
        );
    }
    // Asked again once it ends; it fails again, and the hold doubles to 10 s.
    let (_, sent) = fails(&caches, secs(5));
    assert!(sent > 0, "asked at 5");
    let (_, sent) = fails(&caches, secs(14));
    assert_eq!(sent, 0, "held until 15");
    let (_, sent) = fails(&caches, secs(15));
    assert!(sent > 0, "asked at 15");
    // Another question of the same servers is not held.
    let (resolved, _) = silent(&caches, (&text, RecordType::AAAA), secs(15), false);
    assert_ne!(resolved, Resolved::Failed(Failure::Network), "AAAA held");
}

#[test]
fn rfc9520_3_2_a_hold_is_never_longer_than_failure_max() {
    let capture = capture("unsigned");
    let config = Config {
        failure_min: 100,
        failure_max: 150,
        ..Config::default()
    };
    let caches = configured(false, config);
    let text = capture.name.to_string();
    let question = (text.as_str(), capture.rtype);
    let base = at(&capture);
    let fails = |now: Duration| {
        let mut resolution = resolution(&caches, question, now, false);
        let (_, sent) = run(&mut resolution, &|_| Answered::ServerError, now);
        sent.len()
    };
    assert!(fails(base) > 0);
    assert!(fails(base + Duration::from_secs(100)) > 0, "asked at 100");
    // The second hold, 200 s doubled, is 150 s: until 250.
    assert_eq!(fails(base + Duration::from_secs(249)), 0, "held until 250");
    assert!(fails(base + Duration::from_secs(250)) > 0, "asked at 250");
}

#[test]
fn rfc9520_3_2_a_hold_is_of_the_servers_that_failed_not_of_the_next_delegation() {
    let capture = capture("unsigned");
    let caches = configured(false, Config::default());
    let text = capture.name.to_string();
    let question = (text.as_str(), capture.rtype);
    let base = at(&capture);
    let fails = |now: Duration| {
        let mut resolution = resolution(&caches, question, now, false);
        let (resolved, sent) = run(&mut resolution, &|_| Answered::ServerError, now);
        (resolved, sent.len())
    };
    assert!(fails(base).1 > 0);
    assert_eq!(fails(base).1, 0, "held");
    // The servers asked, the root's, are other ones: asked again, though the hold has not ended.
    let zone = Name::root();
    let moved = Record {
        name: zone.clone(),
        class: Class::IN,
        ttl: Ttl::from_wire(3600),
        rdata: (&RData::Ns(name("ns.other.example."))).into(),
    };
    let address = Record {
        name: name("ns.other.example."),
        class: Class::IN,
        ttl: Ttl::from_wire(3600),
        rdata: (&RData::A(std::net::Ipv4Addr::new(9, 9, 9, 9))).into(),
    };
    let now = u32::try_from(base.as_secs()).expect("a time in 32 bits");
    for set in Rrset::group(&[moved, address]) {
        let rank = Rank::AnswerAuthoritative;
        caches
            .rrsets
            .insert(set, rank, Checked::Unchecked, now)
            .expect("stored");
    }
    assert!(fails(base).1 > 0, "held across a delegation");
}

#[test]
fn rfc9520_3_2_a_clock_gone_back_does_not_extend_a_hold() {
    let capture = capture("unsigned");
    let caches = configured(false, Config::default());
    let text = capture.name.to_string();
    let question = (text.as_str(), capture.rtype);
    let early = at(&capture);
    let base = early + Duration::from_secs(10_000);
    let fails = |now: Duration| {
        let mut resolution = resolution(&caches, question, now, false);
        let (_, sent) = run(&mut resolution, &|_| Answered::ServerError, now);
        sent.len()
    };
    assert!(fails(base) > 0);
    assert_eq!(fails(base + Duration::from_secs(1)), 0, "held");
    // The hold ends 5 s after the first failure: a clock 10 000 s earlier is outside the longest hold.
    assert!(fails(early) > 0, "held across a clock gone back");
    // The hold of the failure heard then is a first one, 5 s: not a doubled one of a clock that did not go back.
    let secs = |s: u64| early + Duration::from_secs(s);
    assert_eq!(fails(secs(4)), 0, "held until 5");
    assert!(fails(secs(5)) > 0, "asked at 5");
    assert_eq!(fails(secs(14)), 0, "held until 15");
}

#[test]
fn rfc2308_7_a_failure_of_the_limits_is_not_held() {
    let capture = capture("unsigned");
    let caches = configured(false, Config::default());
    let limits = Limits {
        queries: 1,
        ..Limits::default()
    };
    let now = at(&capture);
    let text = capture.name.to_string();
    for _ in 0..2 {
        let mut resolution = Resolution::start(
            Question::new(name(&text), capture.rtype),
            Arc::clone(&caches),
            now,
            limits,
            Minimisation::Off,
        )
        .expect("an IN question");
        let (resolved, sent) = run(&mut resolution, &|_| Answered::Timeout, now);
        assert!(
            matches!(resolved, Resolved::Failed(Failure::Limit(_))),
            "{resolved:?}"
        );
        assert_eq!(sent.len(), 1, "asked despite a hold");
    }
}
