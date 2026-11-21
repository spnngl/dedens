//! Negative caching (D199) on the captured resolutions of `testdata/recursion/`: RFC 2308 §5 (a negative answer
//! cached by name and type, its TTL), RFC 8020 §2 (no name below a secure NXDOMAIN), RFC 8198 §4 and §5
//! (denials proved by the NSEC and NSEC3 records cached, the wildcard checked, an opt-out span never) and RFC 9520
//! §3.2 (a failure held, backing off). A question that must not be asked meets a server that times out: what the
//! resolution sends shows whether it asked.

use std::cell::Cell;
use std::sync::Arc;
use std::time::Duration;

use dedens_cache::{Checked, Config, Cost};
use dedens_dnssec::crypto::Budget;
use dedens_dnssec::denial::{canonical_cmp, hashed_owner, owner_hash};
use dedens_dnssec::{TrustAnchors, Validator};
use dedens_proto::edns::InfoCode;
use dedens_proto::rdata::{Nsec3, RData};
use dedens_proto::{Class, Message, Name, Question, Record, RecordType, Ttl};
use dedens_resolver::{
    Caches, Failure, Kind, Limits, Minimisation, NotCached, Rank, Ranked, Resolution, Resolved,
    Rrset, RrsetCache,
};
use dedens_testkit::recursion;

use crate::iteration::{Answered, at, configured, name, response, run, served, sized, start};

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

/// The SOA of the negative answer of `zone`'s server to `asked` in capture `id`, as a cache holds it for `ttl`: the
/// TTL of the records is `ttl` too, so that it may differ from the MINIMUM field the zone gave.
fn ranked_soa(id: &str, zone: &str, asked: &str, ttl: u32) -> Ranked {
    let records: Vec<_> = (denial(id, zone, asked).authority.into_iter())
        .map(|record| Record {
            ttl: Ttl::from_wire(ttl),
            ..record
        })
        .collect();
    let soa = Rrset::group(&records)
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
    index_bytes(capacity, (0..count).map(nsec3_sets))
}

/// [`spans_used`] of the `sets` given, in order.
fn index_bytes(capacity: usize, sets: impl IntoIterator<Item = Vec<Rrset>>) -> usize {
    let config = Config {
        shards: 1,
        ..Config::default()
    };
    let indexed = RrsetCache::new(capacity, config.clone()).expect("a cache");
    let apart = RrsetCache::new(capacity, config).expect("a cache");
    for set in sets.into_iter().flatten() {
        let rank = Rank::AuthorityAuthoritative;
        indexed
            .insert(set.clone(), rank, Checked::Secure, 0)
            .expect("stored");
        apart
            .insert(set, rank, Checked::Insecure, 0)
            .expect("stored");
    }
    assert!(
        indexed.used() <= capacity,
        "{} of {capacity}",
        indexed.used()
    );
    indexed.used() - apart.used()
}

/// The real NSEC3 record of nl. [`nsec3_sets`] moves, at a hash of the zone `zone` (a name of 7 octets, whatever
/// the number), signed by it: one more zone for the index of spans.
fn zone_sets(zone: usize) -> Vec<Rrset> {
    nsec3_in(&format!("zzz{zone:04}.nl."))
}

/// The real NSEC3 record of nl. [`nsec3_sets`] moves, at a hash of the zone `apex`, signed by it.
fn nsec3_in(apex: &str) -> Vec<Rrset> {
    let apex = name(apex);
    let response = denial(
        "nxdomain-nsec3",
        "nl.",
        &capture("nxdomain-nsec3").name.to_string(),
    );
    let (own, _) = nsec3s(&response).into_iter().next().expect("a record");
    let from = hashed_owner(&name("nl."), &own).expect("a name");
    let to = hashed_owner(&apex, &own).expect("a name");
    relocated(&response, (&from, RecordType::NSEC3), (&to, &apex))
}

/// A real NSEC record of sidn.nl, moved to `label.apex` and signed by `apex`.
fn nsec_sets(apex: &str, label: &str) -> Vec<Rrset> {
    let response = denial(
        "nxdomain-signed",
        "sidn.nl.",
        &capture("nxdomain-signed").name.to_string(),
    );
    let apex = name(apex);
    let to = name(&format!("{label}.{apex}"));
    relocated(
        &response,
        (&name("cybersterk.sidn.nl."), RecordType::NSEC),
        (&to, &apex),
    )
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
fn d199_the_index_of_spans_counts_the_names_of_an_nsec_zone_by_their_length() {
    // A zone's bytes are its apex twice (the key and the entry) and each owner's wire form: a longer apex is dearer
    // by three times the difference (twice, and the owner is below it), a longer label by its own.
    let capacity = 1 << 20;
    let short = index_bytes(capacity, [nsec_sets("nl.", "a")]);
    let long = index_bytes(capacity, [nsec_sets("sidn.nl.", "a")]);
    let wide = index_bytes(capacity, [nsec_sets("nl.", "abc")]);
    assert_eq!(long - short, 3 * "sidn.".len(), "{short} then {long}");
    assert_eq!(wide - short, 2, "{short} then {wide}");
    let two = index_bytes(capacity, [nsec_sets("nl.", "a"), nsec_sets("nl.", "b")]);
    // An owner is a name, its bytes and a node: more than half and less than twice a hash, a node and its 20 octets.
    let hash = spans_used(capacity, 2) - spans_used(capacity, 1);
    let owner = two - short;
    assert!(
        2 * owner > hash && owner < 2 * hash,
        "{owner} for an owner, {hash} for a hash"
    );
    // The one owner's bytes, size of the node and the owner's own, are counted again for another owner.
    let three = index_bytes(
        capacity,
        ["a", "b", "c"].map(|label| nsec_sets("nl.", label)),
    );
    assert_eq!(three - two, two - short, "{short}, {two}, {three}");
}

#[test]
fn d199_a_zone_that_changes_its_chain_is_counted_for_what_it_holds_now() {
    // Three hashes of nl., then an NSEC of it: the index starts over, and holds the one owner, as if it had never
    // had the hashes.
    let capacity = 1 << 20;
    let started = index_bytes(
        capacity,
        [
            nsec3_sets(0),
            nsec3_sets(1),
            nsec3_sets(2),
            nsec_sets("nl.", "a"),
        ],
    );
    assert_eq!(started, index_bytes(capacity, [nsec_sets("nl.", "a")]));
}

#[test]
fn d199_a_zone_too_big_for_its_share_starts_over_with_nothing_and_goes_on() {
    // The share is 1 KiB: a zone of hashes grows to it and is then emptied, the zone itself (its own bytes) kept.
    let capacity = 1 << 15;
    let one = spans_used(capacity, 1);
    let hash = spans_used(capacity, 2) - one;
    let sizes: Vec<usize> = (1..=30).map(|n| spans_used(capacity, n)).collect();
    assert!(sizes.iter().all(|used| *used <= capacity / 32), "{sizes:?}");
    assert!(
        sizes.contains(&(one - hash)),
        "never started over, nor to the zone alone: {sizes:?}"
    );
    assert!(
        sizes
            .windows(2)
            .all(|pair| pair[1] == pair[0] + hash || pair[1] == one - hash),
        "{sizes:?}"
    );
}

#[test]
fn d199_the_index_of_spans_evicts_whole_zones_down_to_its_share_and_no_further() {
    // The share is 2 KiB, of zones that cost the same: once it is full, each new zone takes the place of the
    // oldest, the bytes stay at as many zones as fit.
    let capacity = 1 << 16;
    let zone = index_bytes(capacity, [zone_sets(0)]);
    let fit = capacity / 32 / zone;
    assert!(fit > 3, "{fit} zones of {zone} bytes fit");
    for n in [fit + 1, fit + 5, 3 * fit] {
        let used = index_bytes(capacity, (0..n).map(zone_sets));
        assert_eq!(used, fit * zone, "{n} zones");
    }
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
fn rfc2308_5_the_ttl_is_never_more_than_the_minimum_field_of_the_soa() {
    // google.com's SOA has a TTL and a MINIMUM of 60; given a TTL of an hour, the entry still ends at the MINIMUM.
    let config = Config {
        min_ttl: 0,
        ..Config::default()
    };
    let cache = RrsetCache::new(1 << 20, config).expect("a cache");
    let owner = name("dedens-nxdomain.google.com.");
    let soa = ranked_soa(
        "nxdomain-unsigned",
        "google.com.",
        "dedens-nxdomain.google.com.",
        3600,
    );
    cache
        .insert_negative(&owner, Kind::NxDomain, &soa, &[], Checked::Unchecked, 0)
        .expect("stored");
    assert_eq!(left(&cache, &owner, 0), Some((60, "google.com.".into())));
    assert!(cache.negative(&owner, Kind::NxDomain, 60).is_none());
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

#[test]
fn rfc8198_5_an_opt_out_span_the_cache_holds_secure_proves_no_name_absent() {
    // The NODATA of ws. for the DS of dedens.ws: its opt-out NSEC3 records, which match ws. and `*.ws`, and cover
    // dedens.ws, and its SOA, stored as secure sets. The record that matches `*.ws` is moved to the hash just before
    // it, where it covers it: the records prove every name the cover of dedens.ws spans absent but for the opt-out
    // flag, which says an unsigned delegation may be there (RFC 5155 §6).
    let capture = capture("wildcard-optout");
    let exchange = capture
        .exchanges
        .iter()
        .find(|e| e.zone == name("ws.") && e.rtype == RecordType::DS)
        .expect("the DS question of dedens.ws");
    let response = dedens_testkit::message(&exchange.response);
    let records = nsec3s(&response);
    let (_, any) = records.first().expect("an NSEC3 record");
    let hash = |text: &str| {
        Budget::default()
            .nsec3_hash(any.salt(), any.iterations, &name(text))
            .expect("a hash")
    };
    let (cover, next) = records
        .iter()
        .find(|(owner, nsec3)| covers(owner, nsec3.next_hashed_owner(), &hash("dedens.ws.")))
        .map(|(owner, nsec3)| (owner, nsec3.next_hashed_owner()))
        .expect("a record covering dedens.ws");
    let second = (0..100_000)
        .map(|n| format!("dedens-{n}.ws."))
        .find(|text| text != "dedens.ws." && covers(cover, next, &hash(text)))
        .expect("a name in the span");
    let ws = name("ws.");
    let wildcard = hash("*.ws.");
    assert!(
        records.iter().any(|(owner, _)| *owner == wildcard),
        "a record that matches *.ws"
    );
    let mut just_before = wildcard;
    for byte in just_before.iter_mut().rev() {
        *byte = byte.wrapping_sub(1);
        if *byte != u8::MAX {
            break;
        }
    }
    let at_wildcard = hashed_owner(&ws, &wildcard).expect("a name");
    let moved = relocated(
        &response,
        (&at_wildcard, RecordType::NSEC3),
        (&hashed_owner(&ws, &just_before).expect("a name"), &ws),
    );
    assert_eq!(moved.len(), 1);
    let kept: Vec<_> = (response.authority.iter())
        .filter(|record| record.name != at_wildcard)
        .cloned()
        .collect();
    let caches = configured(false, Config::default());
    store_secure(&caches.rrsets, Rrset::group(&kept), at(&capture));
    store_secure(&caches.rrsets, moved, at(&capture));
    let (_, sent) = silent(&caches, (&second, RecordType::A), at(&capture), true);
    assert!(sent > 0, "{second} answered from an opt-out span");
}

#[test]
fn rfc8198_4_a_record_that_came_again_unchecked_or_bogus_after_it_expired_proves_nothing() {
    // sidn.nl's records, secure at the capture: the index names their owners until the zone goes. Once they have
    // expired the rest is stored secure again, as a validator leaves them, and the cover of the name comes as an
    // unchecked set (before its validation, or a spoofed one) or a bogus one: neither is a proof.
    let capture = capture("nxdomain-signed");
    let asked = capture.name.to_string();
    let response = denial("nxdomain-signed", "sidn.nl.", &asked);
    let covered = nsec_spanned(&response, &asked);
    let later = at(&capture) + Duration::from_secs(1000);
    let cover = name("cybersterk.sidn.nl.");
    for checked in [
        Checked::Secure,
        Checked::Unchecked,
        Checked::Bogus(InfoCode::RRSIGS_MISSING),
    ] {
        let caches = configured(false, Config::default());
        store_secure(
            &caches.rrsets,
            Rrset::group(&response.authority),
            at(&capture),
        );
        let (covers, rest): (Vec<_>, Vec<_>) = Rrset::group(&response.authority)
            .into_iter()
            .partition(|set| set.rtype() == RecordType::NSEC && *set.owner() == cover);
        assert_eq!(covers.len(), 1);
        store_secure(&caches.rrsets, rest, later);
        store(&caches.rrsets, covers, checked, later);
        let (_, sent) = silent(&caches, (&covered, RecordType::A), later, true);
        assert_eq!(sent == 0, checked == Checked::Secure, "{checked:?}: {sent}");
    }
}

#[test]
fn rfc8198_5_a_ds_question_is_asked_not_denied_from_a_span() {
    // A name sidn.nl's records prove absent for any other type: the cache does not answer the question of its DS
    // with it, that is the parent's own answer (RFC 8198 §5.2). ANY, RRSIG and NXNAME are not started at all.
    let capture = capture("nxdomain-signed");
    let asked = capture.name.to_string();
    let covered = nsec_spanned(&denial("nxdomain-signed", "sidn.nl.", &asked), &asked);
    for rtype in [RecordType::A, RecordType::DS] {
        let caches = configured(false, Config::default());
        first("nxdomain-signed", &caches, true);
        let (_, sent) = silent(&caches, (&covered, rtype), at(&capture), true);
        assert_eq!(sent == 0, rtype == RecordType::A, "{rtype}: {sent} asked");
    }
}

#[test]
fn d199_a_validating_resolution_does_not_take_an_answer_cached_unchecked() {
    for id in ["nxdomain-unsigned", "nodata-unsigned"] {
        let capture = capture(id);
        let caches = configured(false, Config::default());
        first(id, &caches, false);
        let text = capture.name.to_string();
        let question = (text.as_str(), capture.rtype);
        let (_, sent) = silent(&caches, question, at(&capture), false);
        assert_eq!(sent, 0, "{id}: not cached");
        // The zones' delegations are cached now, so a validating resolution that takes the cached answer asks the
        // zone's servers nothing; one that does not asks them the question, as the zone's answer is the one it
        // validates.
        let mut validating = start(&capture, &caches, Limits::default())
            .validated(validator(), at(&capture).as_secs());
        let (_, sent) = served(&capture, &caches, &mut validating, &|_, _| {});
        assert!(
            sent.iter()
                .any(|(_, asked, rtype)| *asked == capture.name && *rtype == capture.rtype),
            "{id}: a validating resolution took it: {sent:?}"
        );
    }
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

/// The `RRset`s of `response`'s authority section, the NSEC at `owner` with a second signature over it (the first's
/// but for its key tag) signed by `signer`.
fn doubly_signed(response: &Message<'_>, owner: &Name<'_>, signer: &Name<'static>) -> Vec<Rrset> {
    let mut records = Vec::new();
    for record in &response.authority {
        let own = |rdata| Record {
            name: record.name.clone().into_owned(),
            class: Class::IN,
            ttl: record.ttl,
            rdata,
        };
        records.push(own(record.rdata.clone().into_owned()));
        if record.name == *owner
            && let RData::Rrsig(mut sig) = record.data()
            && sig.type_covered == RecordType::NSEC
        {
            sig.key_tag = sig.key_tag.wrapping_add(1);
            sig.signer = signer.clone();
            records.push(own((&RData::Rrsig(sig)).into()));
        }
    }
    Rrset::group(&records)
}

/// Stores `sets` as `checked`, at the rank of an authority section, at `now`.
fn store(cache: &RrsetCache, sets: Vec<Rrset>, checked: Checked, now: Duration) {
    let now = u32::try_from(now.as_secs()).expect("a time in 32 bits");
    for set in sets {
        let rank = Rank::AuthorityAuthoritative;
        cache.insert(set, rank, checked, now).expect("stored");
    }
}

/// Stores `sets` as the validator leaves them, secure.
fn store_secure(cache: &RrsetCache, sets: Vec<Rrset>, now: Duration) {
    store(cache, sets, Checked::Secure, now);
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
fn d199_a_set_with_two_signers_proves_only_when_they_are_the_same_zone() {
    // RFC 6840 §4.1: a verdict does not say which signature it checked. A second signature by the zone is its own
    // proof still; one by another zone makes the set the proof of neither.
    let capture = capture("nxdomain-signed");
    let asked = capture.name.to_string();
    let response = denial("nxdomain-signed", "sidn.nl.", &asked);
    let owner = name("cybersterk.sidn.nl.");
    for (signer, proves) in [("sidn.nl.", true), ("nl.", false)] {
        let caches = configured(false, Config::default());
        let sets = doubly_signed(&response, &owner, &name(signer));
        assert!(sets.iter().any(|set| set.rrsigs().len() == 2));
        store_secure(&caches.rrsets, sets, at(&capture));
        let (resolved, sent) = silent(&caches, (&asked, RecordType::A), at(&capture), true);
        assert_eq!(
            matches!(resolved, Resolved::NxDomain { .. }) && sent == 0,
            proves,
            "{signer}: {sent} asked, {resolved:?}"
        );
    }
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

/// `sets` of NSEC3 records as they are but for the hash they say they use: `iterations` and `salt` are theirs, the
/// rest as the zone served it.
fn rehashed(sets: &[Rrset], iterations: u16, salt: &[u8]) -> Vec<Rrset> {
    let records: Vec<Record<'static>> = sets
        .iter()
        .flat_map(|set| {
            let changed = set.rdatas().iter().map(|wire| match wire.data() {
                RData::Nsec3(nsec3) => {
                    let (alg, flags) = (nsec3.hash_algorithm, nsec3.flags);
                    let (next, types) = (nsec3.next_hashed_owner(), nsec3.types.clone());
                    let changed = Nsec3::new(alg, flags, iterations, salt, next, types)
                        .expect("an NSEC3 record");
                    (&RData::Nsec3(changed)).into()
                }
                _ => wire.clone(),
            });
            let signatures = set.rrsigs().iter().cloned();
            changed
                .chain(signatures)
                .map(|rdata| Record {
                    name: set.owner().clone(),
                    class: set.class(),
                    ttl: set.ttl(),
                    rdata,
                })
                .collect::<Vec<_>>()
        })
        .collect();
    Rrset::group(&records)
}

#[test]
fn d199_a_zone_that_changes_its_chain_or_its_hash_starts_its_index_over() {
    // The records of nl. (NSEC3, no salt, no iteration) prove names absent, and those of sidn.nl (NSEC) too. A
    // record of the other chain, or hashed otherwise, comes for the zone: the index is the new chain's, and what
    // proved a name before no longer proves another; the records of the old chain, left in the `RRset` cache, are
    // no span of the new. (A name proved is cached as it was, so the second name is the one asked after.)
    let nl = capture("nxdomain-nsec3");
    let nl_asked = nl.name.to_string();
    let nl_response = denial("nxdomain-nsec3", "nl.", &nl_asked);
    let sidn = capture("nxdomain-signed");
    let sidn_asked = sidn.name.to_string();
    let sidn_response = denial("nxdomain-signed", "sidn.nl.", &sidn_asked);
    let sidn_other = nsec_spanned(&sidn_response, &sidn_asked);
    let nl_other = spanned(&nl_response, "nl.", false, &nl_asked);
    let ws = capture("wildcard-optout");
    let ws_response = response(&ws, "ws.", "dedens.ws.");
    let ws_nsec3s = nsec3s(&ws_response);
    let (_, ws_nsec3) = ws_nsec3s.first().expect("an NSEC3 record of ws.");
    let nl_nsec3s = nsec3s(&nl_response);
    let (own, own_nsec3) = nl_nsec3s.first().expect("an NSEC3 record of nl.");
    let apex = |text: &str| name(text);
    let at_nl = |hash: &[u8; 20]| hashed_owner(&apex("nl."), hash).expect("a name");
    // A record of nl. moved to a name of its own, so that it replaces none of those held.
    let own_set = |signer: &Name<'static>, zone: &Name<'static>| {
        let mut fresh = *own;
        fresh[0] = fresh[0].wrapping_add(1);
        let to = hashed_owner(zone, &fresh).expect("a name");
        relocated(
            &nl_response,
            (&at_nl(own), RecordType::NSEC3),
            (&to, signer),
        )
    };
    let proved = |caches: &Arc<Caches>, asked: &str, now: Duration| {
        let (resolved, sent) = silent(caches, (asked, RecordType::A), now, true);
        (sent == 0).then_some(resolved)
    };
    let cybersterk = name("cybersterk.sidn.nl.");
    let nl_apex = name("nl.");
    let sidn_apex = name("sidn.nl.");
    // The new records, and the zone they are of: another chain than the one held, then the same chain hashed with
    // another number of iterations, then with another salt.
    let cases = [
        (
            [nl_asked.as_str(), nl_other.as_str()],
            Rrset::group(&nl_response.authority),
            relocated(
                &sidn_response,
                (&cybersterk, RecordType::NSEC),
                (&cybersterk, &nl_apex),
            ),
            "NSEC where NSEC3 was",
        ),
        (
            [sidn_asked.as_str(), sidn_other.as_str()],
            Rrset::group(&sidn_response.authority),
            own_set(&sidn_apex, &sidn_apex),
            "NSEC3 where NSEC was",
        ),
        (
            [nl_asked.as_str(), nl_other.as_str()],
            Rrset::group(&nl_response.authority),
            rehashed(
                &own_set(&nl_apex, &nl_apex),
                own_nsec3.iterations + 1,
                own_nsec3.salt(),
            ),
            "other iterations",
        ),
        (
            [nl_asked.as_str(), nl_other.as_str()],
            Rrset::group(&nl_response.authority),
            rehashed(
                &own_set(&nl_apex, &nl_apex),
                own_nsec3.iterations,
                ws_nsec3.salt(),
            ),
            "another salt",
        ),
    ];
    for ([before_name, after_name], held, new, case) in cases {
        assert_eq!(new.len(), 1, "{case}");
        let caches = configured(false, Config::default());
        let now = at(&nl);
        store_secure(&caches.rrsets, held, now);
        let before = proved(&caches, before_name, now);
        assert!(
            matches!(before, Some(Resolved::NxDomain { .. })),
            "{case}: {before_name} before: {before:?}"
        );
        store_secure(&caches.rrsets, new, now);
        let after = proved(&caches, after_name, now);
        assert!(after.is_none(), "{case}: {after_name} after: {after:?}");
    }
}

#[test]
fn d199_the_index_of_spans_evicts_the_zone_used_least_recently_not_the_first_indexed() {
    // nl.'s records come first and prove names absent. Other zones' records come after, more than the index holds:
    // a zone kept in use stays, as the oldest would go first if use did not count.
    let capture = capture("nxdomain-nsec3");
    let asked = capture.name.to_string();
    let response = denial("nxdomain-nsec3", "nl.", &asked);
    let records = nsec3s(&response);
    let (own, _) = records.first().expect("an NSEC3 record");
    let nl = name("nl.");
    let config = Config {
        shards: 1,
        ..Config::default()
    };
    let caches = sized(false, 1 << 15, config);
    let now = at(&capture);
    store_secure(&caches.rrsets, Rrset::group(&response.authority), now);
    for i in 0..10 {
        // Two zones of nothing but a record each, which the index of 1 KiB holds six of.
        for zone in [2 * i, 2 * i + 1] {
            let apex = name(&format!("z{zone}.nl."));
            let to = hashed_owner(&apex, own).expect("a name");
            let moved = relocated(
                &response,
                (&hashed_owner(&nl, own).expect("a name"), RecordType::NSEC3),
                (&to, &apex),
            );
            store_secure(&caches.rrsets, moved, now);
        }
        // A name of nl. is asked, whatever the answer: the zone is in use.
        silent(
            &caches,
            (&format!("in-use-{i}.nl."), RecordType::A),
            now,
            true,
        );
    }
    let (resolved, _) = silent(&caches, (&asked, RecordType::A), now, true);
    assert!(
        matches!(resolved, Resolved::NxDomain { .. }),
        "{asked} after 20 other zones: {resolved:?}"
    );
}

#[test]
fn d199_an_owner_whose_record_expired_leaves_the_index_when_a_lookup_misses_it() {
    // The records of nl. (NSEC3) and sidn.nl (NSEC) are indexed, then expire; the SOA is stored again, fresh. A name
    // they covered is asked: the miss drops the owner it found, which the index counted. The same question under
    // another TLD, as long, leaves the index alone: what is left is the difference of the two caches' bytes. A zone
    // that then starts over (the other chain) leaves the same bytes in both, so the zone's own count was kept right.
    for (id, zone, apex) in [
        ("nxdomain-nsec3", "nl.", "nl."),
        ("nxdomain-signed", "sidn.nl.", "sidn.nl."),
    ] {
        let capture = capture(id);
        let asked = capture.name.to_string();
        let response = denial(id, zone, &asked);
        let other = if id == "nxdomain-nsec3" {
            spanned(&response, apex, false, &asked)
        } else {
            nsec_spanned(&response, &asked)
        };
        let before = at(&capture);
        let after = before + Duration::from_secs(1_000_000);
        let (held, unheld): (Vec<_>, Vec<_>) = Rrset::group(&response.authority)
            .into_iter()
            .partition(|set| set.rtype() != RecordType::SOA);
        let other_chain = if id == "nxdomain-nsec3" {
            nsec_sets(apex, "x")
        } else {
            nsec3_in(apex)
        };
        let used = |question: &str| {
            let caches = configured(false, Config::default());
            store_secure(&caches.rrsets, held.clone(), before);
            let indexed = caches.rrsets.used();
            store_secure(&caches.rrsets, unheld.clone(), after);
            let (resolved, _) = silent(&caches, (question, RecordType::A), after, true);
            assert!(
                !matches!(resolved, Resolved::NxDomain { .. }),
                "{id}: {question} {resolved:?}"
            );
            let missed = caches.rrsets.used();
            store_secure(&caches.rrsets, other_chain.clone(), after);
            (indexed, missed, caches.rrsets.used())
        };
        let (start, dropped, restarted) = used(&other);
        let (same, kept, restarted_kept) = used(&other.replace(".nl.", ".nm."));
        assert_eq!(start, same, "{id}");
        let freed = kept - dropped;
        assert!((44..120).contains(&freed), "{id}: {freed} bytes freed");
        assert_eq!(restarted, restarted_kept, "{id}");
    }
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
fn rfc9520_3_2_a_local_send_error_is_no_failure_of_the_servers_and_holds_nothing() {
    let capture = capture("unsigned");
    let caches = configured(false, Config::default());
    let text = capture.name.to_string();
    let question = (text.as_str(), capture.rtype);
    let now = at(&capture);
    // Our own socket failing, once or for every server, says nothing of them: asked again at once, by anyone.
    for round in 0..2 {
        let mut asking = resolution(&caches, question, now, false);
        let (resolved, sent) = run(&mut asking, &|_| Answered::LocalError, now);
        assert_eq!(
            resolved,
            Resolved::Failed(Failure::Network),
            "round {round}"
        );
        assert!(!sent.is_empty(), "round {round}: held");
    }
    // Nor does one among servers that timed out: the first server's exchange fails here, the others' do not.
    let first = Cell::new(true);
    let mut asking = resolution(&caches, question, now, false);
    let (resolved, _) = run(
        &mut asking,
        &|_| {
            if first.replace(false) {
                Answered::LocalError
            } else {
                Answered::Timeout
            }
        },
        now,
    );
    assert_eq!(resolved, Resolved::Failed(Failure::Network));
    let mut asking = resolution(&caches, question, now, false);
    let (_, sent) = run(&mut asking, &|_| Answered::Timeout, now);
    assert!(!sent.is_empty(), "held after a local error");
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
