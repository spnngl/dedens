//! Negative caching (D199) on the captured resolutions of `testdata/recursion/`: RFC 2308 §5 (a negative answer
//! cached by name and type, its TTL), RFC 8020 §2 (no name below a secure NXDOMAIN), RFC 8198 §4 and §5
//! (denials proved by the NSEC and NSEC3 records cached, the wildcard checked, an opt-out span never) and RFC 9520
//! §3.2 (a failure held, backing off). A question that must not be asked meets a server that times out: what the
//! resolution sends shows whether it asked.

use std::sync::Arc;
use std::time::Duration;

use dedens_cache::Config;
use dedens_dnssec::crypto::Budget;
use dedens_dnssec::denial::{canonical_cmp, owner_hash};
use dedens_dnssec::{TrustAnchors, Validator};
use dedens_proto::rdata::{Nsec3, RData};
use dedens_proto::{Message, Name, Question, RecordType};
use dedens_resolver::{Caches, Failure, Limits, Minimisation, Resolution, Resolved};
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
        (format!("_dmarc.{base}"), RecordType::MX),
    ] {
        let (resolved, sent) = silent(&caches, (&below, rtype), at(&capture), true);
        assert_eq!(sent, 0, "{below} asked");
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
fn rfc9520_3_2_a_clock_gone_back_does_not_extend_a_hold() {
    let capture = capture("unsigned");
    let caches = configured(false, Config::default());
    let text = capture.name.to_string();
    let question = (text.as_str(), capture.rtype);
    let base = at(&capture) + Duration::from_secs(10_000);
    let fails = |now: Duration| {
        let mut resolution = resolution(&caches, question, now, false);
        let (_, sent) = run(&mut resolution, &|_| Answered::ServerError, now);
        sent.len()
    };
    assert!(fails(base) > 0);
    assert_eq!(fails(base + Duration::from_secs(1)), 0, "held");
    // The hold ends 5 s after the first failure: a clock 2 hours earlier is outside the longest hold.
    assert!(
        fails(base - Duration::from_secs(7_200)) > 0,
        "held across a clock gone back"
    );
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
