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
use dedens_proto::{Class, Message, Name, Question, Rcode, Record, RecordType};
use dedens_resolver::{Caches, Failure, Limits, Minimisation, Ranked, Resolution, Resolved};
use dedens_testkit::recursion;

use crate::iteration::{
    Answered, Change, Sent, at, caches, captured, is, name, resolvable, run, served, start, steer,
    to,
};

/// The captures whose answer is signed from the root down.
const SIGNED: &[&str] = &[
    "cname-signed",
    "dname",
    "glueless",
    "nodata-signed",
    "nxdomain-nsec3",
    "nxdomain-signed",
    "priming",
    "signed-com",
    "signed-nl",
    "wildcard",
];

/// The captures whose answer is insecure: below a delegation its parent proves unsigned, or a wildcard expansion in
/// an opt-out span (RFC 5155 §9.2).
const UNSIGNED: &[&str] = &[
    "cname",
    "nodata-unsigned",
    "nxdomain-unsigned",
    "truncated",
    "unsigned",
    "wildcard-optout",
];

/// The captures whose chain starts in an unsigned zone and ends in a signed one: insecure, the end secure.
const MIXED: &[&str] = &["cname-to-signed"];

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
    let mut listed: Vec<&str> = (SIGNED.iter().chain(UNSIGNED).chain(MIXED))
        .copied()
        .collect();
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

/// Resolves `question` on `caches` from `capture`'s servers, validated or not (as for a client setting CD, or an
/// address lookup: the same responses cached unchecked), each response passed through `change`.
fn ask(
    capture: &recursion::Resolution,
    caches: &Arc<Caches>,
    question: Question<'static>,
    validated: bool,
    change: &Change<'_>,
) -> (Resolved, Vec<Sent>) {
    let mut resolution = Resolution::start(
        question,
        Arc::clone(caches),
        at(capture),
        Limits::default(),
        Minimisation::Off,
    )
    .expect("an IN question");
    if validated {
        let validator = validator(dedens_dnssec::Limits::default());
        resolution = resolution.validated(validator, at(capture).as_secs());
    }
    served(capture, caches, &mut resolution, change)
}

/// The question of `capture`.
fn question(capture: &recursion::Resolution) -> Question<'static> {
    Question::new(capture.name.clone(), capture.rtype)
}

#[test]
fn d197_each_rrset_of_a_cname_from_an_unsigned_zone_is_cached_as_judged_by_itself() {
    // www.zendesk.com, unsigned, is a CNAME into cdn.cloudflare.net, signed: the answer is insecure, its end
    // secure, and cached so (Unbound's rrset_update_sec_status).
    let id = MIXED[0];
    let (resolved, caches) = checked(id);
    assert_eq!(resolved.checked(), Checked::Insecure, "{resolved:?}");
    let Resolved::Answer { chain, data, .. } = &resolved else {
        panic!("{resolved:?}");
    };
    let cname = chain.first().expect("a CNAME");
    assert_eq!(cached(&caches, cname, id), Some(Checked::Insecure));
    assert_eq!(cached(&caches, data, id), Some(Checked::Secure));
    // Asked by itself, the end is served from the cache, secure: with AD.
    let capture = recursion::Resolution::read(id);
    let end = Question::new(data.rrset.owner().clone(), data.rrset.rtype());
    let (again, sent) = ask(&capture, &caches, end, true, &|_, _| {});
    assert_eq!((again.checked(), sent), (Checked::Secure, Vec::new()));
}

#[test]
fn d197_a_bogus_cname_leaves_its_target_to_be_judged_by_itself() {
    // The CNAME of www.icann.org stripped of its signatures: bogus. Its target in cdn.cloudflare.net, signed, has
    // no verdict of its own then, so stays unchecked, and is secure when asked by itself.
    let id = "cname-signed";
    let capture = recursion::Resolution::read(id);
    let caches = caches(false);
    let (resolved, _) = ask(
        &capture,
        &caches,
        question(&capture),
        true,
        &|zone, message| {
            if is(zone, "icann.org.") && answers(message, "www.icann.org.", RecordType::A) {
                message
                    .answer
                    .retain(|r| r.rdata.rtype() != RecordType::RRSIG);
            }
        },
    );
    let missing = Failure::Bogus(InfoCode::RRSIGS_MISSING);
    assert_eq!(resolved, Resolved::Failed(missing));
    let end = Question::new(name("www.icann.org.cdn.cloudflare.net."), RecordType::A);
    let now = u32::try_from(capture.captured_at).expect("a time within u32");
    let held = (caches.rrsets).get(&end.name, end.qtype, Class::IN, now);
    assert_eq!(held.map(|held| held.checked), Some(Checked::Unchecked));
    let (again, _) = ask(&capture, &caches, end, true, &|_, _| {});
    assert_eq!(again.checked(), Checked::Secure, "{again:?}");
}

#[test]
fn d197_a_bogus_answer_is_asked_again_of_another_server() {
    // Changed: one server of icann.org, 199.4.138.53, strips the signatures of its answer for www.icann.org, as a
    // spoofer or a garbling path would. The other, 2001:500:89::53, answers as captured: asked again, the answer
    // is secure (Unbound's val_blacklist).
    let capture = recursion::Resolution::read("cname-signed");
    let authorities = recursion::Authorities::new([&capture]);
    let garbling = "199.4.138.53"
        .parse::<std::net::IpAddr>()
        .expect("an address");
    let server = |query: &dedens_resolver::Query| {
        let mut response = captured(&authorities, query);
        if query.server.ip() == garbling && answers(&response, "www.icann.org.", RecordType::A) {
            (response.answer).retain(|r| r.rdata.rtype() != RecordType::RRSIG);
        }
        Answered::Response(response)
    };
    let resolve = |limits: Limits| {
        let caches = caches(false);
        let validator = validator(dedens_dnssec::Limits::default());
        let mut resolution =
            start(&capture, &caches, limits).validated(validator, at(&capture).as_secs());
        steer(&caches, &capture);
        run(&mut resolution, &server, at(&capture))
    };
    let (resolved, sent) = resolve(Limits::default());
    assert_eq!(resolved.checked(), Checked::Secure, "{resolved:?} {sent:?}");
    let www = name("www.icann.org.");
    let asked = sent.iter().filter(|(zone, name, rtype)| {
        is(zone, "icann.org.") && *name == www && *rtype == RecordType::A
    });
    assert_eq!(asked.count(), 2, "{sent:?}");
    // The query asked again is the validation's: the client's own, up to the first DS or DNSKEY, are enough.
    let validating = |(_, _, rtype): &Sent| matches!(*rtype, RecordType::DS | RecordType::DNSKEY);
    let queries = sent
        .iter()
        .position(validating)
        .expect("a validator question");
    let (resolved, sent) = resolve(Limits {
        queries,
        ..Limits::default()
    });
    assert_eq!(resolved.checked(), Checked::Secure, "{resolved:?} {sent:?}");
}

#[test]
fn rfc6672_2_2_a_yxdomain_is_validated() {
    // Changed: dns.netmeister.org's answer forged into a YXDOMAIN, its DNAME unsigned, to a target of 255 bytes that
    // makes the name asked too long. Unvalidated, the YXDOMAIN would be served; the DNAME is bogus.
    let target = format!(
        "{0}.{0}.{0}.{1}.netmeister.org.",
        "a".repeat(63),
        "a".repeat(46)
    );
    let forged = crate::scrub::dname("dname.dns.netmeister.org.", &target);
    let (resolved, sent) = ask(
        &recursion::Resolution::read("dname"),
        &caches(false),
        Question::new(name("www.dname.dns.netmeister.org."), RecordType::A),
        true,
        &|zone, message| {
            if is(zone, "dns.netmeister.org.")
                && answers(message, "www.dname.dns.netmeister.org.", RecordType::A)
            {
                message.set_rcode(Rcode::YXDOMAIN).expect("a code");
                message.answer = vec![forged.clone()];
                message.authority.clear();
            }
        },
    );
    assert!(
        matches!(resolved, Resolved::Failed(Failure::Bogus(_))),
        "{resolved:?} {sent:?}"
    );
}

#[test]
fn rfc4035_5_3_4_a_wildcard_expansion_cached_unchecked_is_asked_again() {
    // A client setting CD, or an address lookup (a server name an attacker put under a victim's wildcard), caches
    // the expansion unchecked, without the proof that no closer name exists. Validated from the cache it would be
    // bogus: it is asked again, its proof with it. Secure under NSEC3, insecure under an opt-out span.
    for (id, verdict) in [
        ("wildcard", Checked::Secure),
        ("wildcard-optout", Checked::Insecure),
    ] {
        let capture = recursion::Resolution::read(id);
        let caches = caches(false);
        let (unchecked, _) = ask(&capture, &caches, question(&capture), false, &|_, _| {});
        assert_eq!(unchecked.checked(), Checked::Unchecked, "{id}");
        let (resolved, sent) = ask(&capture, &caches, question(&capture), true, &|_, _| {});
        assert_eq!(resolved.checked(), verdict, "{id}: {resolved:?}");
        let asked = |(_, name, rtype): &Sent| *name == capture.name && *rtype == capture.rtype;
        assert!(sent.iter().any(asked), "{id}: {sent:?}");
    }
}

#[test]
fn rfc4035_5_3_4_a_secure_wildcard_expansion_is_served_with_its_proof_or_without_ad() {
    // The cache holds the expansion without its proof, which a client that validates needs: asked again.
    let capture = recursion::Resolution::read("wildcard");
    let caches = caches(false);
    for _ in 0..2 {
        let (resolved, sent) = ask(&capture, &caches, question(&capture), true, &|_, _| {});
        assert_eq!(resolved.checked(), Checked::Secure, "{resolved:?}");
        let Resolved::Answer { denials, .. } = &resolved else {
            panic!("{resolved:?}");
        };
        assert!(!denials.is_empty(), "{sent:?}");
    }
    // Asked with CD, the expansion held secure is served without its proof: without AD.
    let (resolved, sent) = ask(&capture, &caches, question(&capture), false, &|_, _| {});
    assert!(sent.is_empty(), "{sent:?}");
    assert_eq!(resolved.checked(), Checked::Unchecked, "{resolved:?}");
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
    // Asked again, the cache answers bogus: no query, no retry.
    let (again, sent) = ask(&capture, &caches, question(&capture), true, &|_, _| {});
    assert_eq!(
        again,
        Resolved::Failed(Failure::Bogus(InfoCode::RRSIGS_MISSING))
    );
    assert_eq!(sent, vec![]);
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
    // A validation a bound stops is DNSSEC Indeterminate (RFC 8914 §4.7), not No Reachable Authority.
    let indeterminate = Failure::Indeterminate(InfoCode::DNSSEC_INDETERMINATE);
    assert_eq!(resolved, Resolved::Failed(indeterminate));
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
fn too_low(rtype: RecordType, referral: bool) -> (Resolved, Vec<Sent>) {
    let capture = recursion::Resolution::read("nodata-signed");
    let caches = caches(false);
    let question = Question::new(name("sidn.nl."), rtype);
    let own = to(
        exchanged(&capture, "sidn.nl.", "sidn.nl.", RecordType::SRV),
        &question,
    );
    let nl = Question::new(name("nl."), RecordType::NS);
    let cut = to(exchanged(&capture, ".", "sidn.nl.", RecordType::SRV), &nl);
    let change = |zone: &Name<'_>, message: &mut Message<'static>| {
        if is(zone, ".") && answers(message, "sidn.nl.", rtype) {
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
    let (resolved, sent) = too_low(RecordType::DS, true);
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
fn rfc4035_5_2_a_ds_question_fails_with_its_cut_lookup() {
    // No NS of nl to be had, the root refusing: the lookup fails, which tells nothing of the cut, so the DS question
    // fails with it (Unbound's processDSNSFind) rather than take the child's NODATA, which a validator judges bogus.
    let (resolved, sent) = too_low(RecordType::DS, false);
    assert!(matches!(resolved, Resolved::Failed(_)), "{resolved:?}");
    let nl = (name("nl."), RecordType::NS);
    assert!(
        sent.iter()
            .any(|(_, name, rtype)| (name, *rtype) == (&nl.0, nl.1)),
        "{sent:?}"
    );
}

#[test]
fn rfc4035_3_1_4_1_only_a_ds_question_looks_for_the_parent() {
    // The same NODATA from the child's apex, to its own SRV question: the child's to give, no cut sought.
    let (resolved, sent) = too_low(RecordType::SRV, true);
    assert!(matches!(resolved, Resolved::NoData { .. }), "{resolved:?}");
    let asked: Vec<_> = sent
        .iter()
        .map(|(zone, name, rtype)| format!("{zone} {name} {rtype}"))
        .collect();
    assert_eq!(asked, [". sidn.nl. SRV"]);
}

#[test]
fn d197_a_validator_question_unanswered_is_indeterminate() {
    // The servers of sidn.nl fail its DNSKEY question: the validator has no keys to check the answer with.
    let (resolved, _) = changed(&|zone, message| {
        if is(zone, "sidn.nl.") && answers(message, "sidn.nl.", RecordType::DNSKEY) {
            message.header.rcode = Rcode::SERVFAIL;
            message.answer.clear();
        }
    });
    let unreachable = Failure::Indeterminate(InfoCode::NO_REACHABLE_AUTHORITY);
    assert_eq!(resolved, Resolved::Failed(unreachable));
}

#[test]
fn d197_the_validation_tells_its_cost() {
    let capture = recursion::Resolution::read("signed-nl");
    let unchecked = caches(false);
    let mut unvalidated = start(&capture, &unchecked, Limits::default());
    assert!(unvalidated.validation_cost().is_none());
    let _ = served(&capture, &unchecked, &mut unvalidated, &|_, _| {});
    assert!(unvalidated.validation_cost().is_none());
    let defaults = (
        Limits::default(),
        validator(dedens_dnssec::Limits::default()),
    );
    let (resolution, _, _) = check(&capture, &caches(false), defaults, &|_, _| {});
    let cost = resolution.validation_cost().expect("a validation");
    // The DNSKEY of ., nl and sidn.nl, the DS of nl and sidn.nl; a signature checked for each, and for the A.
    assert_eq!(
        (cost.questions, cost.verifications, cost.nsec3_blocks),
        (5, 6, 0)
    );
}
