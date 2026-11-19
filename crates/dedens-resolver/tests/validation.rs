//! Validation of a resolution (D197) on the captured resolutions of `testdata/recursion/`, each question of the
//! validator resolved by the iteration: RFC 4035 §5 (secure, insecure and bogus answers, cached as judged), §5.2
//! (a DS asked of the parent, found below a server serving both sides of the cut), RFC 8914 §4 (the extended error
//! of a bogus answer), and the bounds on a validation: its queries (D197) and its verifications (D75).

use std::sync::Arc;

use dedens_cache::Checked;
use dedens_dnssec::crypto::{Budget, Verifications};
use dedens_dnssec::{TrustAnchors, Validator};
use dedens_proto::edns::InfoCode;
use dedens_proto::rdata::{Dnskey, Ds, RData};
use dedens_proto::{Class, Message, Name, Question, Record, RecordType};
use dedens_resolver::{Caches, Failure, Limit, Limits, Minimisation, Ranked, Resolution, Resolved};
use dedens_testkit::recursion;

use crate::iteration::{Change, Sent, at, caches, is, name, resolvable, served, start, to};

/// The captures whose answer is signed from the root down.
const SIGNED: &[&str] = &[
    "dname",
    "glueless",
    "nodata-signed",
    "nxdomain-nsec3",
    "nxdomain-signed",
    "priming",
    "signed-com",
    "signed-nl",
];

/// The captures whose answer is below a delegation its parent proves unsigned.
const UNSIGNED: &[&str] = &[
    "cname",
    "nodata-unsigned",
    "nxdomain-unsigned",
    "truncated",
    "unsigned",
];

/// A validator from the root's anchors under `limits`.
fn validator(limits: dedens_dnssec::Limits) -> Validator {
    Validator::new(TrustAnchors::root(), limits)
}

/// Resolves and validates `capture`'s question on `caches` under `limits`, each captured response passed through
/// `change`, at the time of the capture.
fn check(
    capture: &recursion::Resolution,
    caches: &Arc<Caches>,
    (limits, validator): (Limits, Validator),
    change: &Change<'_>,
) -> (Resolution, Resolved, Vec<Sent>) {
    let mut resolution = start(capture, caches, limits).validated(validator, at(capture).as_secs());
    let (resolved, sent) = served(capture, caches, &mut resolution, change);
    (resolution, resolved, sent)
}

/// [`check`] on fresh caches, under the default limits, as captured.
fn checked(id: &str) -> (Resolved, Arc<Caches>) {
    let capture = recursion::Resolution::read(id);
    let caches = caches(false);
    let defaults = (
        Limits::default(),
        validator(dedens_dnssec::Limits::default()),
    );
    let (_, resolved, _) = check(&capture, &caches, defaults, &|_, _| {});
    (resolved, caches)
}

/// [`check`] of `signed-nl` on fresh caches, under the default limits, each response passed through `change`.
fn changed(change: &Change<'_>) -> (Resolved, Arc<Caches>) {
    let capture = recursion::Resolution::read("signed-nl");
    let caches = caches(false);
    let defaults = (
        Limits::default(),
        validator(dedens_dnssec::Limits::default()),
    );
    let (_, resolved, _) = check(&capture, &caches, defaults, change);
    (resolved, caches)
}

/// The answer's data, or the SOA of its denial.
fn data(resolved: &Resolved) -> Option<&Ranked> {
    match resolved {
        Resolved::Answer { data, .. } => Some(data),
        Resolved::NoData { soa, .. } | Resolved::NxDomain { soa, .. } => Some(soa),
        Resolved::YxDomain { .. } | Resolved::Failed(_) => None,
    }
}

/// What the `RRset` cache holds of `rrset` at the time of `id`'s capture.
fn cached(caches: &Caches, rrset: &Ranked, id: &str) -> Option<Checked> {
    let now =
        u32::try_from(recursion::Resolution::read(id).captured_at).expect("a time within u32");
    let rrset = &rrset.rrset;
    let held = caches
        .rrsets
        .get(rrset.owner(), rrset.rtype(), Class::IN, now)?;
    Some(held.checked)
}

/// Whether `message` answers `name` and `rtype`.
fn answers(message: &Message<'_>, name: &str, rtype: RecordType) -> bool {
    (message.questions.first()).is_some_and(|q| is(&q.name, name) && q.qtype == rtype)
}

/// The response `capture` holds from a server of `zone` to `name` and `rtype`.
fn exchanged(
    capture: &recursion::Resolution,
    zone: &str,
    name: &str,
    rtype: RecordType,
) -> Message<'static> {
    let exchange = (capture.exchanges.iter())
        .find(|e| is(&e.zone, zone) && is(&e.name, name) && e.rtype == rtype)
        .expect("a captured exchange");
    dedens_testkit::message(&exchange.response)
}

#[test]
fn every_capture_is_signed_or_unsigned() {
    let mut ids: Vec<String> = resolvable().into_iter().map(|(id, _)| id).collect();
    ids.sort_unstable();
    let mut listed: Vec<&str> = SIGNED.iter().chain(UNSIGNED).copied().collect();
    listed.sort_unstable();
    assert_eq!(ids, listed);
}

#[test]
fn rfc4035_5_each_signed_capture_is_secure_and_cached_so() {
    for id in SIGNED {
        let (resolved, caches) = checked(id);
        assert_eq!(resolved.checked(), Checked::Secure, "{id}: {resolved:?}");
        assert_eq!(
            data(&resolved).and_then(|data| cached(&caches, data, id)),
            Some(Checked::Secure),
            "{id}"
        );
    }
}

#[test]
fn rfc4035_5_2_each_unsigned_capture_is_insecure_and_cached_so() {
    // An insecure verdict needs the DS proven absent at the last signed cut: unproven, the answer is bogus.
    for id in UNSIGNED {
        let (resolved, caches) = checked(id);
        assert_eq!(resolved.checked(), Checked::Insecure, "{id}: {resolved:?}");
        assert_eq!(
            data(&resolved).and_then(|data| cached(&caches, data, id)),
            Some(Checked::Insecure),
            "{id}"
        );
    }
}

#[test]
fn rfc4035_5_3_an_answer_stripped_of_its_signatures_is_bogus_and_cached_so() {
    let (resolved, caches) = changed(&|zone, message| {
        if is(zone, "sidn.nl.") && answers(message, "sidn.nl.", RecordType::A) {
            message
                .answer
                .retain(|r| r.rdata.rtype() != RecordType::RRSIG);
        }
    });
    assert_eq!(
        resolved,
        Resolved::Failed(Failure::Bogus(InfoCode::RRSIGS_MISSING))
    );
    let capture = recursion::Resolution::read("signed-nl");
    let a = exchanged(&capture, "sidn.nl.", "sidn.nl.", RecordType::A);
    let a = a
        .answer
        .iter()
        .find(|r| r.rdata.rtype() == RecordType::A)
        .expect("an A");
    let now = u32::try_from(capture.captured_at).expect("a time within u32");
    let held = caches
        .rrsets
        .get(&a.name, RecordType::A, Class::IN, now)
        .expect("cached");
    assert!(matches!(held.checked, Checked::Bogus(_)), "{held:?}");
}

#[test]
fn rfc4035_5_2_a_changed_ds_makes_the_answer_bogus() {
    let (resolved, _) = changed(&|zone, message| {
        if is(zone, "nl.") && answers(message, "sidn.nl.", RecordType::DS) {
            for record in &mut message.answer {
                if let RData::Ds(ds) = record.data() {
                    let mut digest = ds.digest().to_vec();
                    digest[0] ^= 0xff;
                    let changed = Ds::new(ds.key_tag(), ds.algorithm(), ds.digest_type(), &digest)
                        .expect("a DS");
                    *record = Record::new(
                        record.name.clone(),
                        record.class,
                        record.ttl,
                        &RData::Ds(changed),
                    );
                }
            }
        }
    });
    assert!(
        matches!(resolved, Resolved::Failed(Failure::Bogus(_))),
        "{resolved:?}"
    );
}

#[test]
fn rfc4035_5_2_another_zones_keys_make_the_answer_bogus() {
    let capture = recursion::Resolution::read("signed-nl");
    let nl = exchanged(&capture, "nl.", "nl.", RecordType::DNSKEY);
    let (resolved, _) = changed(&|zone, message| {
        if is(zone, "sidn.nl.") && answers(message, "sidn.nl.", RecordType::DNSKEY) {
            let owner = name("sidn.nl.");
            let keys = nl
                .answer
                .iter()
                .filter(|r| r.rdata.rtype() == RecordType::DNSKEY);
            let swapped = keys.map(|r| Record::new(owner.clone(), r.class, r.ttl, &r.data()));
            let signatures = message
                .answer
                .iter()
                .filter(|r| r.rdata.rtype() == RecordType::RRSIG);
            message.answer = swapped.chain(signatures.cloned()).collect();
        }
    });
    assert!(
        matches!(resolved, Resolved::Failed(Failure::Bogus(_))),
        "{resolved:?}"
    );
}

#[test]
fn d75_a_dnskey_set_of_one_tag_is_checked_within_the_budget() {
    // KeyTrap (CVE-2023-50387): keys of the tag of the zone's key, none that verifies. Swapping two bytes of the
    // key two apart keeps the tag (RFC 4034 Appendix B), a sum of 16-bit words.
    const KEYS: usize = 60;
    let capture = recursion::Resolution::read("signed-nl");
    let caches = caches(false);
    let limits = dedens_dnssec::Limits::default();
    let budget = limits.budget.verifications_left().0;
    let change = |zone: &Name<'_>, message: &mut Message<'static>| {
        if !(is(zone, "sidn.nl.") && answers(message, "sidn.nl.", RecordType::DNSKEY)) {
            return;
        }
        let mut colliding = Vec::new();
        for record in &message.answer {
            let RData::Dnskey(key) = record.data() else {
                continue;
            };
            for at in 0..KEYS {
                let mut public = key.public_key().to_vec();
                public.swap(at, at + 2);
                let key = Dnskey::new(key.flags(), key.algorithm(), &public).expect("a key");
                colliding.push(Record::new(
                    record.name.clone(),
                    record.class,
                    record.ttl,
                    &RData::Dnskey(key),
                ));
            }
        }
        message.answer.extend(colliding);
    };
    let (resolution, resolved, _) = check(
        &capture,
        &caches,
        (Limits::default(), validator(limits)),
        &change,
    );
    assert!(
        matches!(resolved, Resolved::Failed(Failure::Bogus(_))),
        "{resolved:?}"
    );
    let cost = resolution.validation_cost().expect("a validation");
    assert!(cost.verifications <= budget, "{cost:?}");
}

#[test]
fn d75_a_validation_past_its_verifications_is_indeterminate() {
    let capture = recursion::Resolution::read("signed-nl");
    let limits = dedens_dnssec::Limits {
        budget: Budget::new(Verifications(1), Budget::DEFAULT_NSEC3_BLOCKS),
        ..dedens_dnssec::Limits::default()
    };
    let checking = (Limits::default(), validator(limits));
    let (_, resolved, _) = check(&capture, &caches(false), checking, &|_, _| {});
    assert!(
        matches!(resolved, Resolved::Failed(Failure::Indeterminate(_))),
        "{resolved:?}"
    );
}

#[test]
fn d197_the_validation_queries_are_bounded() {
    let capture = recursion::Resolution::read("signed-nl");
    let limits = Limits {
        validation: 2,
        ..Limits::default()
    };
    let checking = (limits, validator(dedens_dnssec::Limits::default()));
    let (resolution, resolved, sent) = check(&capture, &caches(false), checking, &|_, _| {});
    assert_eq!(
        resolved,
        Resolved::Failed(Failure::Limit(Limit::Validation))
    );
    let questions = sent
        .iter()
        .filter(|(_, _, rtype)| *rtype == RecordType::A)
        .count();
    assert_eq!((sent.len(), resolution.sent()), (questions + 2, sent.len()));
}

#[test]
fn rfc4035_5_unsigned_glue_is_not_the_answer() {
    // nl's referral carries an address for the name asked: glue for no server, never the answer.
    let (resolved, _) = changed(&|zone, message| {
        if is(zone, "nl.") && answers(message, "sidn.nl.", RecordType::A) {
            let forged: Record<'static> = "sidn.nl. 3600 IN A 192.0.2.1".parse().expect("a record");
            message.additional.push(forged);
        }
    });
    assert_eq!(resolved.checked(), Checked::Secure);
    let addresses: Vec<_> = data(&resolved)
        .expect("an answer")
        .rrset
        .rdatas()
        .iter()
        .map(ToString::to_string)
        .collect();
    assert!(
        !addresses.contains(&"192.0.2.1".to_owned()),
        "{addresses:?}"
    );
}

#[test]
fn rfc4035_5_an_unvalidated_cached_answer_is_validated() {
    // A resolution without the validator caches the answer unchecked: a validated one checks it, stripped of its
    // signatures, and does not take it for secure.
    let capture = recursion::Resolution::read("signed-nl");
    let caches = caches(false);
    let strip = |zone: &Name<'_>, message: &mut Message<'static>| {
        if is(zone, "sidn.nl.") && answers(message, "sidn.nl.", RecordType::A) {
            message
                .answer
                .retain(|r| r.rdata.rtype() != RecordType::RRSIG);
        }
    };
    let (plain, _) = served(
        &capture,
        &caches,
        &mut start(&capture, &caches, Limits::default()),
        &strip,
    );
    assert_eq!(plain.checked(), Checked::Unchecked);
    let checking = (
        Limits::default(),
        validator(dedens_dnssec::Limits::default()),
    );
    let (_, resolved, _) = check(&capture, &caches, checking, &|_, _| {});
    assert!(
        matches!(resolved, Resolved::Failed(Failure::Bogus(_))),
        "{resolved:?}"
    );
}

/// The `DS sidn.nl` question of `nodata-signed` asked from the root, whose servers answer it with sidn.nl's own
/// NODATA, as a server serving the root, nl and sidn.nl would; the root answers `NS nl` with `referral` when given.
fn too_low(referral: bool) -> (Resolved, Vec<Sent>) {
    let capture = recursion::Resolution::read("nodata-signed");
    let caches = caches(false);
    let question = Question::new(name("sidn.nl."), RecordType::DS);
    let own = to(
        exchanged(&capture, "sidn.nl.", "sidn.nl.", RecordType::SRV),
        &question,
    );
    let nl = Question::new(name("nl."), RecordType::NS);
    let cut = to(exchanged(&capture, ".", "sidn.nl.", RecordType::SRV), &nl);
    let change = |zone: &Name<'_>, message: &mut Message<'static>| {
        if is(zone, ".") && answers(message, "sidn.nl.", RecordType::DS) {
            *message = own.clone();
        } else if referral && is(zone, ".") && answers(message, "nl.", RecordType::NS) {
            *message = cut.clone();
        }
    };
    let mut resolution = Resolution::start(
        question.clone(),
        Arc::clone(&caches),
        at(&capture),
        Limits::default(),
        Minimisation::Off,
    )
    .expect("an IN question");
    served(&capture, &caches, &mut resolution, &change)
}

#[test]
fn rfc4035_5_2_a_ds_denied_by_the_child_is_asked_again_of_the_parent() {
    // Unbound's iter_ds_toolow and processDSNSFind: the SOA of the NODATA is the name's own, so the server answered
    // from the child; the NS of the name's parent show the parent, which holds the DS.
    let (resolved, sent) = too_low(true);
    let Resolved::Answer { data, .. } = &resolved else {
        panic!("{resolved:?}");
    };
    assert_eq!(data.rrset.rtype(), RecordType::DS);
    let asked: Vec<_> = sent
        .iter()
        .map(|(zone, name, rtype)| format!("{zone} {name} {rtype}"))
        .collect();
    assert_eq!(asked, [". sidn.nl. DS", ". nl. NS", "nl. sidn.nl. DS"]);
}

#[test]
fn rfc4035_5_2_a_ds_denied_by_the_child_stands_when_no_parent_shows() {
    // No NS of nl to be had: the search reaches the zone asked, whose answer stands.
    let (resolved, sent) = too_low(false);
    assert!(matches!(resolved, Resolved::NoData { .. }), "{resolved:?}");
    let nl = (name("nl."), RecordType::NS);
    assert!(
        sent.iter()
            .any(|(_, name, rtype)| (name, *rtype) == (&nl.0, nl.1)),
        "{sent:?}"
    );
}
