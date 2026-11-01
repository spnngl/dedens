//! The validator against the captured responses (`testdata/README.md`): a scripted caller answers each question
//! it asks from the captures, at the time of the capture, and the verdict is the one the README gives (RFC 4035
//! §4.3), but for what an opt-out proof covers, which is insecure (RFC 5155 §9.2, D75).

use std::collections::HashMap;
use std::net::Ipv4Addr;

use dedens_dnssec::anchor::TrustAnchors;
use dedens_dnssec::crypto::{Budget, Nsec3Hashes, Verifications};
use dedens_dnssec::denial::MaxIterations;
use dedens_dnssec::validator::{
    Delegation, InsecureReason, Limits, Next, Validator, Verdict, covered,
};
use dedens_proto::edns::InfoCode;
use dedens_proto::rdata::{Nsec, Rrsig};
use dedens_proto::{
    Class, Flags, Message, Name, Question, RData, Rcode, Record, RecordType, Ttl, WireRdata,
};

mod common;

use common::{capture, captured_at, name, names};

/// What the scripted caller can answer: every capture, by the question it answers.
struct Script(HashMap<(Name<'static>, RecordType), Message<'static>>);

impl Script {
    fn new() -> Self {
        Self(
            names()
                .iter()
                .map(|id| capture(id))
                .filter_map(|message| {
                    let question = message.questions.first()?;
                    Some(((question.name.clone(), question.qtype), message))
                })
                .collect(),
        )
    }

    /// The same captures with every record at `ttl`: a cache hands records out with what is left of their TTL.
    fn with_ttl(mut self, ttl: Ttl) -> Self {
        for message in self.0.values_mut() {
            for record in message
                .answer
                .iter_mut()
                .chain(&mut message.authority)
                .chain(&mut message.additional)
            {
                record.ttl = ttl;
            }
        }
        self
    }

    fn answer(&self, ask: &Question<'_>) -> Option<&Message<'static>> {
        self.0.get(&(ask.name.clone().into_owned(), ask.qtype))
    }

    /// The verdict on `response`, and the questions asked for it, with `answer` as the caller.
    fn drive<'s>(
        validator: &Validator,
        response: &Message<'static>,
        now: u32,
        answer: impl Fn(&Question<'static>) -> Option<&'s Message<'static>>,
    ) -> (Verdict, Vec<String>) {
        let question = response.questions.first().expect("a question").clone();
        let mut validation = validator.start(&question, response, u64::from(now));
        let mut asked = Vec::new();
        loop {
            match validation.step() {
                Next::Ask(ask) => {
                    asked.push(format!("{} {}", ask.name, ask.qtype));
                    validation.answer(answer(&ask));
                    assert!(asked.len() <= 128, "asks without end: {asked:?}");
                }
                Next::Done(verdict) => return (verdict, asked),
            }
        }
    }

    /// The verdict on `response` with `validator`, at `now`.
    fn run(&self, validator: &Validator, response: &Message<'static>, now: u32) -> Verdict {
        Self::drive(validator, response, now, |ask| self.answer(ask)).0
    }

    fn validator() -> Validator {
        Validator::new(TrustAnchors::root(), Limits::default())
    }

    /// The verdict on the capture `id`.
    fn verdict(&self, id: &str) -> Verdict {
        self.run(&Self::validator(), &capture(id), captured_at())
    }
}

/// The records of `rtype` in the answer of `message`, as the text lines a trust anchor file holds.
fn zone_text(message: &Message<'_>, rtype: RecordType) -> String {
    let lines: Vec<String> = message
        .answer
        .iter()
        .filter(|record| record.rtype() == rtype)
        .map(ToString::to_string)
        .collect();
    lines.join("\n")
}

fn secure(verdict: &Verdict) -> bool {
    matches!(verdict, Verdict::Secure { .. })
}

fn bogus(verdict: &Verdict, code: InfoCode) -> bool {
    matches!(verdict, Verdict::Bogus { ede } if ede.code == code)
}

/// The captures of a signed zone's keys and their DS, in the parent: the chain of trust is the response.
const CHAINS: &[&str] = &[
    "root",
    "com",
    "net",
    "org",
    "nl",
    "cat",
    "la",
    "cr",
    "dev",
    "stream",
    "nlnetlabs_nl",
    "cloudflare_com",
    "sidnlabs_nl",
    "example_nl",
    "icann_org",
    "cloudflare_net",
    "ripe_net",
    "verteiltesysteme_net",
    "fedoraproject_org",
    "ed25519_nl",
    "debian_org",
    "rootcanary_net",
    "ippacket_stream",
    "rsa2048_ippacket_stream",
];

#[test]
fn every_chain_of_the_set_is_secure() {
    let script = Script::new();
    for zone in CHAINS {
        for kind in ["ds", "dnskey"] {
            let id = format!("{zone}_{kind}");
            if id == "root_ds" {
                continue;
            }
            let verdict = script.verdict(&id);
            assert!(secure(&verdict), "{id}: {verdict:?}");
        }
    }
}

/// Answers with the algorithms RFC 8624 §3.1 lists, NSEC and NSEC3 denials, wildcards and answers across
/// zones.
const SECURE: &[&str] = &[
    "alg8_a",
    "alg13_a",
    "alg10_soa",
    "alg14_a",
    "alg15_a",
    "alg7_soa",
    "alg8_13_a",
    "rootcanary_soa",
    "nxdomain_root_nsec",
    "nxdomain_nsec",
    "nxdomain_nsec3",
    "nxdomain_nsec3_iterations",
    "nxname_cloudflare",
    "nodata_compact",
    "nodata_root_nsec",
    "nodata_nsec",
    "nodata_nsec3",
    "nodata_nsec3_optout",
    "nodata_nsec3_iterations",
    "ent_nsec",
    "ent_nsec3",
    "wildcard_answer",
    "wildcard_nodata",
    "cname_cross_zone",
    "cname_deep_zone",
    "dname_rr",
    "dname_answer",
    "jm_ds",
];

#[test]
fn every_secure_capture_is_secure() {
    let script = Script::new();
    let failed: Vec<String> = SECURE
        .iter()
        .map(|id| (id, script.verdict(id)))
        .filter(|(_, verdict)| !secure(verdict))
        .map(|(id, verdict)| format!("{id}: {verdict:?}"))
        .collect();
    assert_eq!(failed, Vec::<String>::new());
}

/// D75: `covered` keeps all a secure verdict rests on: the verdict on the cut response is the one on the whole, and
/// cutting it again changes nothing. A capture holds nothing else than the answer, so most are kept as they are.
#[test]
fn the_covered_part_of_every_secure_capture_is_as_secure() {
    let script = Script::new();
    let validator = Script::validator();
    for id in SECURE {
        let response = capture(id);
        let cut = covered(&response);
        let whole = script.run(&validator, &response, captured_at());
        assert_eq!(script.run(&validator, &cut, captured_at()), whole, "{id}");
        assert_eq!(covered(&cut), cut, "{id}");
    }
}

/// D75: what the verdict is not about is cut, whatever it is: the additional section, a class other than IN, a
/// set off the answer's names, an orphan signature, a set in the authority section off the names. What it is
/// about is not touched.
#[test]
fn what_the_verdict_does_not_cover_is_cut() {
    let plain = capture("alg8_a");
    let a = plain
        .answer
        .iter()
        .find(|record| record.rtype() == RecordType::A)
        .expect("an A record")
        .clone();
    let rrsig = plain
        .answer
        .iter()
        .find(|record| is_rrsig_of(record, RecordType::A))
        .expect("its RRSIG")
        .clone();
    let mut response = plain.clone();
    response.answer.push(Record {
        name: name("evil.example"),
        ..a.clone()
    });
    response.answer.push(Record {
        name: name("evil.example"),
        ..rrsig.clone()
    });
    response.answer.push(Record {
        class: Class::CH,
        ..a.clone()
    });
    response.answer.push(Record {
        class: Class::CH,
        ..rrsig
    });
    response.additional.push(a);
    response
        .authority
        .push(ns("evil.example", "ns.evil.example"));
    response.authority.push(ns("com", "ns.evil.example"));
    let cut = covered(&response);
    assert_eq!(cut.additional, []);
    assert_eq!(cut.answer, plain.answer);
    assert_eq!(cut.authority, plain.authority);
    assert_eq!(cut.header, plain.header);
    assert_eq!(cut.questions, plain.questions);
}

/// RFC 6672 \u00a75.3.3, D75: the CNAME a DNAME makes stays, unsigned: its signature is not in the answer, and the
/// DNAME and the answer below it are as they were.
#[test]
fn the_cname_a_dname_makes_stays_without_signature() {
    let response = capture("dname_answer");
    let cut = covered(&response);
    assert_eq!(cut.answer, response.answer);
    assert!(
        response
            .answer
            .iter()
            .any(|r| r.rtype() == RecordType::CNAME)
    );
    // A signature over it, as an attacker adds one, is not kept: nothing verifies it.
    let cname = response
        .answer
        .iter()
        .find(|record| record.rtype() == RecordType::CNAME)
        .expect("the synthesized CNAME")
        .clone();
    let rrsig = response
        .answer
        .iter()
        .find(|record| is_rrsig_of(record, RecordType::DNAME))
        .expect("the RRSIG of the DNAME")
        .clone();
    let RData::Rrsig(signature) = rrsig.data() else {
        panic!("an RRSIG")
    };
    let mut signature = signature.into_owned();
    signature.type_covered = RecordType::CNAME;
    let mut forged = response.clone();
    forged.answer.push(Record {
        rdata: WireRdata::new(&RData::Rrsig(signature)),
        ..cname
    });
    assert_eq!(covered(&forged).answer, response.answer);
}

/// An IPv6 reverse name has 34 labels, and the walk asks the DS of each below `arpa` (a real capture of RIPE
/// NCC's `www.ipv6.ripe.net`): the default limits cover it.
#[test]
fn a_reverse_name_of_34_labels_is_secure() {
    let script = Script::new();
    let (verdict, asked) = Script::drive(
        &Script::validator(),
        &capture("ip6_ptr"),
        captured_at(),
        |ask| script.answer(ask),
    );
    assert!(secure(&verdict), "{verdict:?} after {asked:?}");
    assert!(asked.len() > 34, "{asked:?}");
}

#[test]
fn a_denial_is_kept_three_hours_at_most() {
    // The root's NSEC records are signed for a day (RFC 9077 §3.4).
    let script = Script::new().with_ttl(Ttl::from_wire(86_400));
    for id in ["nxdomain_root_nsec", "nodata_root_nsec", "jm_ds"] {
        let verdict = script.verdict(id);
        let Verdict::Secure { ttl } = verdict else {
            panic!("{id}: {verdict:?}");
        };
        assert_eq!(ttl.get(), 10_800, "{id}");
    }
}

/// What an opt-out NSEC3 record covers may exist unsigned: the README calls these proofs secure, the response
/// is insecure (RFC 5155 §9.2, D75). The unsupported algorithm is Ed448 (D71).
const INSECURE: &[(&str, InsecureReason)] = &[
    ("nxdomain_nsec3_optout", InsecureReason::OptOut),
    ("nxdomain_nsec3_salt", InsecureReason::OptOut),
    ("google_com_ds", InsecureReason::OptOut),
    ("google_com_a", InsecureReason::OptOut),
    ("edgekey_net_ds", InsecureReason::OptOut),
    ("akamaiedge_net_ds", InsecureReason::OptOut),
    ("cname_to_insecure", InsecureReason::OptOut),
    ("alg16_a", InsecureReason::UnsupportedAlgorithm),
    ("ed448_nl_dnskey", InsecureReason::UnsupportedAlgorithm),
];

#[test]
fn every_insecure_capture_is_insecure_for_its_reason() {
    let script = Script::new();
    for &(id, reason) in INSECURE {
        assert_eq!(script.verdict(id), Verdict::Insecure { reason }, "{id}");
    }
}

#[test]
fn an_unsupported_algorithm_has_its_extended_error() {
    let verdict = Script::new().verdict("alg16_a");
    let ede = verdict.ede().expect("an extended error");
    assert_eq!(ede.code, InfoCode::UNSUPPORTED_DNSKEY_ALGORITHM);
}

#[test]
fn a_ds_that_matches_no_key_is_bogus() {
    let script = Script::new();
    for id in ["bogus_no_key", "dnssec_failed_org_dnskey"] {
        let verdict = script.verdict(id);
        assert!(
            bogus(&verdict, InfoCode::DNSKEY_MISSING),
            "{id}: {verdict:?}"
        );
    }
}

#[test]
fn a_signature_that_does_not_verify_is_bogus() {
    let verdict = Script::new().verdict("bogus_signature");
    assert!(bogus(&verdict, InfoCode::DNSSEC_BOGUS), "{verdict:?}");
}

/// `rhybar.cz` is signed by a key its parent's DS does not name, and `cz` is sound.
#[test]
fn the_ds_of_rhybar_cz_matches_no_key() {
    let verdict = Script::new().verdict("bogus_expired");
    assert!(bogus(&verdict, InfoCode::DNSKEY_MISSING), "{verdict:?}");
}

/// The signatures of `sigexpired.bad-dnssec.wb.sidnlabs.nl` ended in 2019, under a sound chain of trust.
#[test]
fn an_expired_signature_under_a_sound_chain_is_bogus() {
    let verdict = Script::new().verdict("bogus_sigexpired");
    assert!(bogus(&verdict, InfoCode::SIGNATURE_EXPIRED), "{verdict:?}");
}

#[test]
fn an_answer_is_validated_from_the_root_down() {
    let script = Script::new();
    let (verdict, asked) = Script::drive(
        &Script::validator(),
        &capture("alg8_a"),
        captured_at(),
        |ask| script.answer(ask),
    );
    assert!(secure(&verdict));
    assert_eq!(
        asked,
        [
            ". DNSKEY",
            "nl. DS",
            "nl. DNSKEY",
            "nlnetlabs.nl. DS",
            "nlnetlabs.nl. DNSKEY"
        ]
    );
}

#[test]
fn a_zone_below_an_insecure_one_is_not_asked_for() {
    let script = Script::new();
    let (verdict, asked) = Script::drive(
        &Script::validator(),
        &capture("cname_to_insecure"),
        captured_at(),
        |ask| script.answer(ask),
    );
    assert!(matches!(verdict, Verdict::Insecure { .. }));
    // `edgekey.net` and `akamaiedge.net` have no DS: their keys are not asked for.
    assert!(
        !asked.iter().any(|ask| ask.ends_with(" DNSKEY")
            && !ask.starts_with("ripe.net.")
            && !ask.starts_with(". ")
            && !ask.starts_with("net.")),
        "{asked:?}"
    );
    assert!(asked.contains(&"edgekey.net. DS".to_owned()), "{asked:?}");
}

#[test]
fn an_answer_nobody_gives_is_indeterminate() {
    let verdict = Script::drive(
        &Script::validator(),
        &capture("alg8_a"),
        captured_at(),
        |_| None,
    )
    .0;
    assert!(
        matches!(&verdict, Verdict::Indeterminate { ede } if ede.code == InfoCode::NO_REACHABLE_AUTHORITY),
        "{verdict:?}"
    );
}

#[test]
fn a_response_to_another_question_is_no_answer() {
    let script = Script::new();
    let wrong = script.answer(&Question::new(name("com"), RecordType::DNSKEY));
    let verdict = Script::drive(
        &Script::validator(),
        &capture("alg8_a"),
        captured_at(),
        |_| wrong,
    )
    .0;
    assert!(
        matches!(verdict, Verdict::Indeterminate { .. }),
        "{verdict:?}"
    );
}

#[test]
fn an_answer_with_another_rcode_is_indeterminate() {
    let script = Script::new();
    let mut response = capture("alg8_a");
    response.header.rcode = Rcode::SERVFAIL;
    let verdict = script.run(&Script::validator(), &response, captured_at());
    assert!(
        matches!(&verdict, Verdict::Indeterminate { ede } if ede.code == InfoCode::DNSSEC_INDETERMINATE),
        "{verdict:?}"
    );
}

/// A day, in seconds.
const DAY: u32 = 86_400;

#[test]
fn an_expired_signature_is_bogus() {
    let script = Script::new();
    let later = captured_at() + 90 * DAY;
    let verdict = script.run(&Script::validator(), &capture("alg8_a"), later);
    assert!(bogus(&verdict, InfoCode::SIGNATURE_EXPIRED), "{verdict:?}");
}

#[test]
fn a_signature_not_yet_valid_is_bogus() {
    let script = Script::new();
    let earlier = captured_at() - 90 * DAY;
    let verdict = script.run(&Script::validator(), &capture("alg8_a"), earlier);
    assert!(
        bogus(&verdict, InfoCode::SIGNATURE_NOT_YET_VALID),
        "{verdict:?}"
    );
}

#[test]
fn a_changed_record_is_bogus() {
    let script = Script::new();
    let mut response = capture("alg8_a");
    let record = response
        .answer
        .iter_mut()
        .find(|record| record.rtype() == RecordType::A)
        .expect("an A record");
    record.rdata = WireRdata::new(&RData::A(Ipv4Addr::new(192, 0, 2, 1)));
    let verdict = script.run(&Script::validator(), &response, captured_at());
    assert!(bogus(&verdict, InfoCode::DNSSEC_BOGUS), "{verdict:?}");
}

#[test]
fn a_stripped_signature_is_bogus() {
    let script = Script::new();
    let mut response = capture("alg8_a");
    response
        .answer
        .retain(|record| record.rtype() != RecordType::RRSIG);
    let verdict = script.run(&Script::validator(), &response, captured_at());
    assert!(bogus(&verdict, InfoCode::RRSIGS_MISSING), "{verdict:?}");
}

#[test]
fn an_unsigned_answer_below_a_secure_zone_is_bogus() {
    // `nlnetlabs.nl` is signed and has no delegation to `www`: an A there with no RRSIG is a forgery.
    let script = Script::new();
    let mut response = capture("alg8_a");
    response
        .answer
        .retain(|record| record.rtype() != RecordType::RRSIG);
    for record in &mut response.answer {
        record.name = name("www.nlnetlabs.nl");
    }
    response.questions = vec![Question::new(name("www.nlnetlabs.nl"), RecordType::A)];
    let verdict = script.run(&Script::validator(), &response, captured_at());
    assert!(bogus(&verdict, InfoCode::RRSIGS_MISSING), "{verdict:?}");
}

#[test]
fn a_wildcard_answer_without_its_proof_is_bogus() {
    // RFC 4035 §5.3.4: the signature alone does not say that no closer name exists.
    let script = Script::new();
    let mut response = capture("wildcard_answer");
    response.authority.clear();
    let verdict = script.run(&Script::validator(), &response, captured_at());
    assert!(bogus(&verdict, InfoCode::NSEC_MISSING), "{verdict:?}");
}

#[test]
fn a_denial_without_its_records_is_bogus() {
    let script = Script::new();
    for id in ["nxdomain_nsec", "nodata_nsec3", "nxdomain_nsec3"] {
        let mut response = capture(id);
        response.authority.clear();
        let verdict = script.run(&Script::validator(), &response, captured_at());
        assert!(bogus(&verdict, InfoCode::NSEC_MISSING), "{id}: {verdict:?}");
    }
}

#[test]
fn a_name_error_in_a_noerror_response_is_bogus() {
    let script = Script::new();
    let mut response = capture("nxdomain_nsec");
    response.header.rcode = Rcode::NOERROR;
    let verdict = script.run(&Script::validator(), &response, captured_at());
    assert!(bogus(&verdict, InfoCode::DNSSEC_BOGUS), "{verdict:?}");
}

#[test]
fn a_no_data_in_an_nxdomain_response_is_bogus() {
    let script = Script::new();
    let mut response = capture("nodata_nsec");
    response.header.rcode = Rcode::NXDOMAIN;
    let verdict = script.run(&Script::validator(), &response, captured_at());
    assert!(bogus(&verdict, InfoCode::DNSSEC_BOGUS), "{verdict:?}");
}

#[test]
fn nsec3_iterations_above_the_limit_are_insecure() {
    // `dev` uses one iteration (RFC 9276 §3.2).
    let script = Script::new();
    let limits = Limits {
        iterations: MaxIterations(0),
        ..Limits::default()
    };
    let validator = Validator::new(TrustAnchors::root(), limits);
    let verdict = script.run(
        &validator,
        &capture("nxdomain_nsec3_iterations"),
        captured_at(),
    );
    assert_eq!(
        verdict,
        Verdict::Insecure {
            reason: InsecureReason::Nsec3Iterations
        }
    );
    let ede = verdict.ede().expect("an extended error");
    assert_eq!(ede.code, InfoCode::UNSUPPORTED_NSEC3_ITERATIONS);
}

#[test]
fn too_many_questions_are_indeterminate() {
    let script = Script::new();
    let limits = Limits {
        questions: 3,
        ..Limits::default()
    };
    let validator = Validator::new(TrustAnchors::root(), limits);
    let (verdict, asked) = Script::drive(&validator, &capture("alg8_a"), captured_at(), |ask| {
        script.answer(ask)
    });
    assert!(
        matches!(verdict, Verdict::Indeterminate { .. }),
        "{verdict:?}"
    );
    assert_eq!(asked.len(), 3);
}

#[test]
fn a_name_too_deep_is_indeterminate() {
    let script = Script::new();
    let limits = Limits {
        depth: 1,
        ..Limits::default()
    };
    let validator = Validator::new(TrustAnchors::root(), limits);
    let verdict = script.run(&validator, &capture("alg8_a"), captured_at());
    assert!(
        matches!(verdict, Verdict::Indeterminate { .. }),
        "{verdict:?}"
    );
}

#[test]
fn an_exhausted_budget_is_indeterminate_not_bogus() {
    let script = Script::new();
    let limits = Limits {
        budget: Budget::new(Verifications(2), Nsec3Hashes(0)),
        ..Limits::default()
    };
    let validator = Validator::new(TrustAnchors::root(), limits);
    let verdict = script.run(&validator, &capture("alg8_a"), captured_at());
    assert!(
        matches!(&verdict, Verdict::Indeterminate { ede } if ede.code == InfoCode::DNSSEC_INDETERMINATE),
        "{verdict:?}"
    );
}

#[test]
fn a_negative_trust_anchor_makes_a_name_insecure() {
    // RFC 7646 §2: the zone's answers are not validated, and `nl` is not asked about.
    let script = Script::new();
    let mut anchors = TrustAnchors::root();
    anchors.add_negative(name("nl"));
    let validator = Validator::new(anchors, Limits::default());
    let (verdict, asked) = Script::drive(&validator, &capture("alg8_a"), captured_at(), |ask| {
        script.answer(ask)
    });
    assert_eq!(
        verdict,
        Verdict::Insecure {
            reason: InsecureReason::NegativeAnchor
        }
    );
    assert!(asked.is_empty(), "{asked:?}");
}

#[test]
fn a_name_with_no_anchor_above_it_is_insecure() {
    let script = Script::new();
    let nl = capture("nl_ds");
    let text = zone_text(&nl, RecordType::DS);
    let validator = Validator::new(
        TrustAnchors::read(&text).expect("anchors"),
        Limits::default(),
    );
    // Under `nl` the anchor serves, and the answer is secure without a question about the root.
    let (verdict, asked) = Script::drive(&validator, &capture("alg15_a"), captured_at(), |ask| {
        script.answer(ask)
    });
    assert!(secure(&verdict), "{verdict:?}");
    assert_eq!(asked.first().map(String::as_str), Some("nl. DNSKEY"));
    // Under `com` none does.
    let verdict = script.run(&validator, &capture("alg13_a"), captured_at());
    assert_eq!(
        verdict,
        Verdict::Insecure {
            reason: InsecureReason::NoAnchor
        }
    );
}

#[test]
fn an_anchor_of_keys_serves_as_one_of_ds_records() {
    let script = Script::new();
    let root = capture("root_dnskey");
    let text = zone_text(&root, RecordType::DNSKEY);
    let validator = Validator::new(
        TrustAnchors::read(&text).expect("anchors"),
        Limits::default(),
    );
    let verdict = script.run(&validator, &capture("alg8_a"), captured_at());
    assert!(secure(&verdict), "{verdict:?}");
}

#[test]
fn asking_again_repeats_and_answering_unasked_does_nothing() {
    let validator = Script::validator();
    let response = capture("alg8_a");
    let question = response.questions.first().expect("a question");
    let mut validation = validator.start(question, &response, u64::from(captured_at()));
    validation.answer(None);
    let first = validation.step();
    assert_eq!(validation.step(), first);
    assert!(matches!(first, Next::Ask(_)));
}

#[test]
fn nxname_is_not_a_type_to_ask_for() {
    let validator = Script::validator();
    let question = Question::new(name("example.nl"), RecordType::NXNAME);
    let mut response = capture("alg8_a");
    response.questions = vec![question.clone()];
    let mut validation = validator.start(&question, &response, u64::from(captured_at()));
    let Next::Done(verdict) = validation.step() else {
        panic!("asks");
    };
    assert!(
        matches!(&verdict, Verdict::Indeterminate { ede } if ede.code == InfoCode::INVALID_QUERY_TYPE),
        "{verdict:?}"
    );
}

// What a forger can do to a response, from the real ones.

/// `response` with every RRSIG changed by `change`.
fn with_rrsigs(response: &mut Message<'static>, change: impl Fn(&mut Rrsig<'static>)) {
    for record in response.answer.iter_mut().chain(&mut response.authority) {
        if let RData::Rrsig(rrsig) = record.data() {
            let mut rrsig = rrsig.into_owned();
            change(&mut rrsig);
            record.rdata = WireRdata::new(&RData::Rrsig(rrsig));
        }
    }
}

/// An NS record, class IN, TTL one hour.
fn ns(owner: &str, target: &str) -> Record<'static> {
    Record {
        name: name(owner),
        class: Class::IN,
        ttl: Ttl::from_wire(3600),
        rdata: WireRdata::new(&RData::Ns(name(target))),
    }
}

/// A validator whose only anchor is the DS of `nl`.
fn nl_validator(script: &Script) -> Validator {
    let text = zone_text(
        script
            .answer(&Question::new(name("nl"), RecordType::DS))
            .expect("nl DS"),
        RecordType::DS,
    );
    Validator::new(
        TrustAnchors::read(&text).expect("anchors"),
        Limits::default(),
    )
}

#[test]
fn a_forged_referral_is_no_secure_answer() {
    // No answer, and an NS record of the root in the authority section: nothing signs it, and nothing denies
    // the A of a name that exists.
    let script = Script::new();
    let mut response = capture("alg8_a");
    response.answer.clear();
    response.authority = vec![ns(".", "a.root-servers.net")];
    let verdict = script.run(&Script::validator(), &response, captured_at());
    assert!(bogus(&verdict, InfoCode::RRSIGS_MISSING), "{verdict:?}");
}

#[test]
fn a_real_referral_is_no_final_answer() {
    // The NS records of a referral are not signed: as an answer it is bogus below a signed zone.
    let script = Script::new();
    let verdict = script.verdict("referral_signed");
    assert!(bogus(&verdict, InfoCode::RRSIGS_MISSING), "{verdict:?}");
}

fn referral(script: &Script, id: &str) -> Verdict {
    let response = capture(id);
    let question = response.questions.first().expect("a question").clone();
    let mut validation =
        Script::validator().start_referral(&question, &response, u64::from(captured_at()));
    loop {
        match validation.step() {
            Next::Ask(ask) => validation.answer(script.answer(&ask)),
            Next::Done(verdict) => return verdict,
        }
    }
}

#[test]
fn a_referral_is_judged_by_its_delegation() {
    let script = Script::new();
    assert_eq!(
        referral(&script, "referral_signed"),
        Verdict::Referral {
            child: name("nlnetlabs.nl"),
            delegation: Delegation::Signed
        }
    );
    // `google.com` has no DS, proven by `com`'s opt-out NSEC3: the child may be unsigned.
    assert_eq!(
        referral(&script, "referral_unsigned"),
        Verdict::Referral {
            child: name("google.com"),
            delegation: Delegation::Unsigned {
                reason: InsecureReason::OptOut
            }
        }
    );
}

#[test]
fn a_referral_cannot_claim_no_ds_for_a_signed_zone() {
    // The DS of `nlnetlabs.nl` taken out of the referral, which the parent signs: bogus, not insecure.
    let script = Script::new();
    let mut response = capture("referral_signed");
    response
        .authority
        .retain(|record| !matches!(record.rtype(), RecordType::DS | RecordType::RRSIG));
    let question = response.questions.first().expect("a question").clone();
    let mut validation =
        Script::validator().start_referral(&question, &response, u64::from(captured_at()));
    let verdict = loop {
        match validation.step() {
            Next::Ask(ask) => validation.answer(script.answer(&ask)),
            Next::Done(verdict) => break verdict,
        }
    };
    assert!(bogus(&verdict, InfoCode::NSEC_MISSING), "{verdict:?}");
}

#[test]
fn a_response_that_is_no_referral_is_not_judged_as_one() {
    let response = capture("alg8_a");
    let question = response.questions.first().expect("a question").clone();
    let mut validation =
        Script::validator().start_referral(&question, &response, u64::from(captured_at()));
    assert!(matches!(
        validation.step(),
        Next::Done(Verdict::Indeterminate { .. })
    ));
}

#[test]
fn the_signer_of_a_signature_does_not_pick_the_keys() {
    // The RRSIGs of an answer of `ed25519.nl` say `.` signed them: the zone of the owner is walked to anyway,
    // and the answer is bogus, not insecure for lack of an anchor at `.`.
    let script = Script::new();
    let validator = nl_validator(&script);
    let mut response = capture("alg15_a");
    with_rrsigs(&mut response, |rrsig| rrsig.signer = Name::root());
    let verdict = script.run(&validator, &response, captured_at());
    assert!(matches!(verdict, Verdict::Bogus { .. }), "{verdict:?}");
    let verdict = script.run(&Script::validator(), &response, captured_at());
    assert!(matches!(verdict, Verdict::Bogus { .. }), "{verdict:?}");
}

#[test]
fn a_signature_of_an_ancestor_zone_is_no_signature_of_the_zone() {
    let script = Script::new();
    let mut response = capture("alg8_a");
    with_rrsigs(&mut response, |rrsig| rrsig.signer = name("nl"));
    let verdict = script.run(&Script::validator(), &response, captured_at());
    assert!(matches!(verdict, Verdict::Bogus { .. }), "{verdict:?}");
}

#[test]
fn a_junk_signature_before_the_real_one_does_not_make_the_answer_bogus() {
    let script = Script::new();
    let mut response = capture("alg8_a");
    let junk = response
        .answer
        .iter()
        .find(|record| record.rtype() == RecordType::RRSIG)
        .cloned()
        .expect("an RRSIG");
    let RData::Rrsig(rrsig) = junk.data() else {
        panic!("an RRSIG")
    };
    let mut rrsig = rrsig.into_owned();
    rrsig.key_tag = rrsig.key_tag.wrapping_add(1);
    let junk = Record {
        rdata: WireRdata::new(&RData::Rrsig(rrsig)),
        ..junk
    };
    let first = response
        .answer
        .iter()
        .position(|record| record.rtype() == RecordType::RRSIG)
        .expect("an RRSIG");
    response.answer.insert(first, junk);
    let verdict = script.run(&Script::validator(), &response, captured_at());
    assert!(secure(&verdict), "{verdict:?}");
}

#[test]
fn an_answer_with_the_rcode_of_a_name_error_is_bogus() {
    let script = Script::new();
    let mut response = capture("alg8_a");
    response.header.rcode = Rcode::NXDOMAIN;
    let verdict = script.run(&Script::validator(), &response, captured_at());
    assert!(bogus(&verdict, InfoCode::DNSSEC_BOGUS), "{verdict:?}");
}

#[test]
fn an_unsigned_record_in_the_authority_section_of_a_secure_zone_is_bogus() {
    let script = Script::new();
    let mut response = capture("alg8_a");
    response.authority.push(ns("nlnetlabs.nl", "evil.example"));
    let verdict = script.run(&Script::validator(), &response, captured_at());
    assert!(bogus(&verdict, InfoCode::RRSIGS_MISSING), "{verdict:?}");
}

#[test]
fn an_unsigned_record_in_the_authority_section_below_an_insecure_zone_changes_nothing() {
    let script = Script::new();
    let mut response = capture("google_com_a");
    response.authority.push(ns("google.com", "evil.example"));
    let verdict = script.run(&Script::validator(), &response, captured_at());
    assert_eq!(
        verdict,
        Verdict::Insecure {
            reason: InsecureReason::OptOut
        }
    );
}

#[test]
fn a_cname_chain_that_stops_short_is_incomplete() {
    let script = Script::new();
    let mut response = capture("cname_cross_zone");
    let target = response
        .answer
        .iter()
        .find_map(|record| match record.data() {
            RData::Cname(target) => Some(target.into_owned()),
            _ => None,
        })
        .expect("a CNAME");
    response.answer.retain(|record| {
        matches!(record.rtype(), RecordType::CNAME) || is_rrsig_of(record, RecordType::CNAME)
    });
    let verdict = script.run(&Script::validator(), &response, captured_at());
    let Verdict::Incomplete { next, .. } = verdict else {
        panic!("{verdict:?}");
    };
    assert_eq!(next, target);
}

/// Whether `record` is an RRSIG over `rtype`.
fn is_rrsig_of(record: &Record<'_>, rtype: RecordType) -> bool {
    matches!(record.data(), RData::Rrsig(rrsig) if rrsig.type_covered == rtype)
}

#[test]
fn a_cname_hop_taken_out_is_bogus() {
    // The A of the target, at the name asked: the chain has no first hop, and nothing denies the name.
    let script = Script::new();
    let mut response = capture("cname_cross_zone");
    response.answer.retain(|record| {
        !matches!(record.rtype(), RecordType::CNAME) && !is_rrsig_of(record, RecordType::CNAME)
    });
    let verdict = script.run(&Script::validator(), &response, captured_at());
    assert!(matches!(verdict, Verdict::Bogus { .. }), "{verdict:?}");
}

#[test]
fn a_cname_with_another_target_is_bogus() {
    let script = Script::new();
    let mut response = capture("cname_cross_zone");
    for record in &mut response.answer {
        if record.rtype() == RecordType::CNAME {
            record.rdata = WireRdata::new(&RData::Cname(name("evil.example")));
        }
    }
    let verdict = script.run(&Script::validator(), &response, captured_at());
    assert!(bogus(&verdict, InfoCode::DNSSEC_BOGUS), "{verdict:?}");
}

#[test]
fn a_dname_with_another_target_is_bogus() {
    let script = Script::new();
    let mut response = capture("dname_answer");
    for record in &mut response.answer {
        if record.rtype() == RecordType::DNAME {
            record.rdata = WireRdata::new(&RData::Opaque(
                dedens_proto::rdata::Opaque::new(
                    RecordType::DNAME,
                    name("evil.example").to_wire(&mut [0; 255]),
                )
                .expect("opaque"),
            ));
        }
    }
    let verdict = script.run(&Script::validator(), &response, captured_at());
    assert!(matches!(verdict, Verdict::Bogus { .. }), "{verdict:?}");
}

/// RFC 6672 §5.3.3: only the CNAME a DNAME makes goes unverified. Derived from the `dname_answer` capture: a second
/// record in that set is unsigned data of a secure zone, and must not ride under the first one.
#[test]
fn a_second_record_in_the_synthesized_cname_is_bogus() {
    let script = Script::new();
    let mut response = capture("dname_answer");
    let at = response
        .answer
        .iter()
        .position(|record| record.rtype() == RecordType::CNAME)
        .expect("the synthesized CNAME");
    let evil = Record {
        rdata: WireRdata::new(&RData::Cname(name("evil.example"))),
        ..response.answer[at].clone()
    };
    response.answer.insert(at + 1, evil.clone());
    let verdict = script.run(&Script::validator(), &response, captured_at());
    assert!(matches!(verdict, Verdict::Bogus { .. }), "{verdict:?}");
    // Before the genuine record as well: the set is compared whole, in any order.
    response.answer.remove(at + 1);
    response.answer.insert(at, evil);
    let verdict = script.run(&Script::validator(), &response, captured_at());
    assert!(matches!(verdict, Verdict::Bogus { .. }), "{verdict:?}");
}

#[test]
fn a_cname_below_a_dname_that_is_gone_is_bogus() {
    // The synthesized CNAME is unsigned by rule only where a DNAME explains it (RFC 6672 §5.3.3).
    let script = Script::new();
    let mut response = capture("dname_answer");
    response.answer.retain(|record| {
        !matches!(record.rtype(), RecordType::DNAME) && !is_rrsig_of(record, RecordType::DNAME)
    });
    let verdict = script.run(&Script::validator(), &response, captured_at());
    assert!(matches!(verdict, Verdict::Bogus { .. }), "{verdict:?}");
}

#[test]
fn a_ds_taken_out_of_a_signed_delegation_is_bogus_not_insecure() {
    let script = Script::new();
    let mut ds = capture("nl_ds");
    ds.answer.clear();
    let verdict = Script::drive(
        &Script::validator(),
        &capture("alg15_a"),
        captured_at(),
        |ask| {
            if ask.name == name("nl") && ask.qtype == RecordType::DS {
                Some(&ds)
            } else {
                script.answer(ask)
            }
        },
    )
    .0;
    assert!(bogus(&verdict, InfoCode::NSEC_MISSING), "{verdict:?}");
}

#[test]
fn a_denial_of_ds_without_signatures_is_bogus() {
    let script = Script::new();
    let mut response = capture("jm_ds");
    response
        .authority
        .retain(|record| record.rtype() != RecordType::RRSIG);
    let verdict = script.run(&Script::validator(), &response, captured_at());
    assert!(bogus(&verdict, InfoCode::RRSIGS_MISSING), "{verdict:?}");
}

#[test]
fn a_denial_of_ds_by_the_child_is_no_denial_by_the_parent() {
    // The NSEC of `nlnetlabs.nl` has SOA in its bitmap: it is the zone's own, and says nothing of a delegation.
    let script = Script::new();
    let mut response = capture("nodata_nsec");
    response.questions = vec![Question::new(name("nlnetlabs.nl"), RecordType::DS)];
    let verdict = script.run(&Script::validator(), &response, captured_at());
    assert!(matches!(verdict, Verdict::Bogus { .. }), "{verdict:?}");
}

#[test]
fn a_denial_with_the_ds_bit_in_its_bitmap_is_bogus() {
    // `jm`'s NSEC with DS added to its bitmap: the signature no longer fits, and the record is no proof.
    let script = Script::new();
    let mut response = capture("jm_ds");
    for record in &mut response.authority {
        if let RData::Nsec(nsec) = record.data() {
            let types = nsec.types.types().chain([RecordType::DS]);
            record.rdata = WireRdata::new(&RData::Nsec(Nsec {
                next: nsec.next.clone().into_owned(),
                types: dedens_proto::rdata::TypeBitmap::from_types(types),
            }));
        }
    }
    let verdict = script.run(&Script::validator(), &response, captured_at());
    assert!(matches!(verdict, Verdict::Bogus { .. }), "{verdict:?}");
}

/// The name with its letters in alternating case, as a server that echoes a mixed-case question (RFC 4343,
/// draft-vixie-dnsext-dns0x20) answers it.
fn mangled(name: &Name<'_>) -> Name<'static> {
    let labels: Vec<Vec<u8>> = name
        .labels()
        .enumerate()
        .map(|(i, label)| {
            label
                .iter()
                .enumerate()
                .map(|(j, byte)| {
                    if (i + j) % 2 == 0 {
                        byte.to_ascii_uppercase()
                    } else {
                        byte.to_ascii_lowercase()
                    }
                })
                .collect()
        })
        .collect();
    Name::from_labels(labels.iter().map(Vec::as_slice)).expect("a name")
}

#[test]
fn a_response_in_mixed_case_is_as_secure_as_one_in_lowercase() {
    let script = Script::new();
    for id in [
        "alg8_a",
        "nxdomain_nsec",
        "cname_cross_zone",
        "wildcard_answer",
        "dname_answer",
    ] {
        let mut response = capture(id);
        for question in &mut response.questions {
            question.name = mangled(&question.name);
        }
        for record in response.answer.iter_mut().chain(&mut response.authority) {
            record.name = mangled(&record.name);
        }
        let verdict = script.run(&Script::validator(), &response, captured_at());
        assert!(secure(&verdict), "{id}: {verdict:?}");
    }
}

#[test]
fn a_response_to_another_question_is_indeterminate_at_once() {
    let validator = Script::validator();
    let response = capture("alg8_a");
    let asked = [
        Question::new(name("example.nl"), RecordType::A),
        Question::new(name("nlnetlabs.nl"), RecordType::AAAA),
        Question {
            qclass: Class::CH,
            ..Question::new(name("nlnetlabs.nl"), RecordType::A)
        },
    ];
    for question in asked {
        let mut validation = validator.start(&question, &response, u64::from(captured_at()));
        assert!(
            matches!(validation.step(), Next::Done(Verdict::Indeterminate { .. })),
            "{question:?}"
        );
    }
    let mut none = response.clone();
    none.questions.clear();
    let question = response.questions.first().expect("a question");
    let mut validation = validator.start(question, &none, u64::from(captured_at()));
    assert!(matches!(
        validation.step(),
        Next::Done(Verdict::Indeterminate { .. })
    ));
}

#[test]
fn a_truncated_response_is_indeterminate() {
    let validator = Script::validator();
    let mut response = capture("alg8_a");
    response.header.flags = response.header.flags.with(Flags::TC);
    let question = response.questions.first().expect("a question").clone();
    let mut validation = validator.start(&question, &response, u64::from(captured_at()));
    assert!(matches!(
        validation.step(),
        Next::Done(Verdict::Indeterminate { .. })
    ));
}

#[test]
fn a_truncated_answer_to_a_question_of_the_validator_is_indeterminate_not_bogus() {
    let script = Script::new();
    let mut truncated = capture("nl_dnskey");
    truncated.header.flags = truncated.header.flags.with(Flags::TC);
    let verdict = Script::drive(
        &Script::validator(),
        &capture("alg15_a"),
        captured_at(),
        |ask| {
            if ask.name == name("nl") && ask.qtype == RecordType::DNSKEY {
                Some(&truncated)
            } else {
                script.answer(ask)
            }
        },
    )
    .0;
    assert!(
        matches!(&verdict, Verdict::Indeterminate { ede } if ede.code == InfoCode::NO_REACHABLE_AUTHORITY),
        "{verdict:?}"
    );
}

#[test]
fn the_depth_is_counted_from_the_anchor_whatever_the_order() {
    let script = Script::new();
    // `nlnetlabs.nl` is two labels below the root.
    for (depth, secure_wanted) in [(2, true), (1, false)] {
        let limits = Limits {
            depth,
            ..Limits::default()
        };
        let validator = Validator::new(TrustAnchors::root(), limits);
        for id in ["alg8_a", "nodata_nsec"] {
            let verdict = script.run(&validator, &capture(id), captured_at());
            assert_eq!(
                secure(&verdict),
                secure_wanted,
                "{id} at {depth}: {verdict:?}"
            );
            if !secure_wanted {
                assert!(
                    matches!(verdict, Verdict::Indeterminate { .. }),
                    "{id}: {verdict:?}"
                );
            }
        }
    }
    // With the anchor at `nl`, the same name is one label below it.
    let script_nl = Script::new();
    let limits = Limits {
        depth: 1,
        ..Limits::default()
    };
    let text = zone_text(
        script_nl
            .answer(&Question::new(name("nl"), RecordType::DS))
            .expect("DS"),
        RecordType::DS,
    );
    let validator = Validator::new(TrustAnchors::read(&text).expect("anchors"), limits);
    let verdict = script.run(&validator, &capture("alg8_a"), captured_at());
    assert!(secure(&verdict), "{verdict:?}");
}

// What the walk asks, and what a response may hold besides its answer.

#[test]
fn the_walk_asks_the_ds_of_an_empty_non_terminal_a_cname_and_a_wildcard() {
    // The DS of a name that has none is answered as the name is: no data at an empty non-terminal, the CNAME at
    // a CNAME's owner, the wildcard's no data at a name a wildcard matches (RFC 4035 §3.1.4.1, RFC 6840 §4.3).
    let script = Script::new();
    for (id, ask) in [
        ("ent_nsec", "_tcp.nlnetlabs.nl. DS"),
        ("cname_cross_zone", "www.icann.org. DS"),
        ("wildcard_answer", "wildcard-test.sidnlabs.nl. DS"),
    ] {
        let (verdict, asked) =
            Script::drive(&Script::validator(), &capture(id), captured_at(), |ask| {
                script.answer(ask)
            });
        assert!(secure(&verdict), "{id}: {verdict:?}");
        assert!(
            asked.iter().any(|a| a == ask),
            "{id} did not ask {ask}: {asked:?}"
        );
    }
}

#[test]
fn a_referral_to_a_zone_of_an_unsupported_algorithm_is_unsigned() {
    // `ed448.nl` has a DS the parent signs, of an algorithm `ring` lacks (D71): a delegation that is signed,
    // but to a zone this validator cannot validate (RFC 4035 §5.2, RFC 6840 §5.2).
    let script = Script::new();
    let mut response = capture("alg8_a");
    response.questions = vec![Question::new(name("www.ed448.nl"), RecordType::A)];
    response.header.flags = response.header.flags.without(Flags::AA);
    response.answer.clear();
    response.authority = capture("ed448_nl_ds").answer;
    response.authority.push(ns("ed448.nl", "ns1.ed448.nl"));
    let question = response.questions.first().expect("a question").clone();
    let mut validation =
        Script::validator().start_referral(&question, &response, u64::from(captured_at()));
    let verdict = loop {
        match validation.step() {
            Next::Ask(ask) => validation.answer(script.answer(&ask)),
            Next::Done(verdict) => break verdict,
        }
    };
    assert_eq!(
        verdict,
        Verdict::Referral {
            child: name("ed448.nl"),
            delegation: Delegation::Unsigned {
                reason: InsecureReason::UnsupportedAlgorithm
            }
        }
    );
}

#[test]
fn records_that_are_not_part_of_the_answer_are_neither_walked_nor_checked() {
    // An unsigned A at another name and an unsigned NS of another zone: out of bailiwick (D75). Nothing is
    // asked for them, and they change no verdict: the caller strips them from what it hands on.
    let script = Script::new();
    let validator = Script::validator();
    let plain = capture("alg8_a");
    let (verdict, asked) =
        Script::drive(&validator, &plain, captured_at(), |ask| script.answer(ask));
    let mut response = plain.clone();
    let a = response
        .answer
        .iter()
        .find(|record| record.rtype() == RecordType::A)
        .expect("an A record")
        .clone();
    response.answer.push(Record {
        name: name("evil.example"),
        ..a
    });
    response
        .authority
        .push(ns("evil.example", "ns.evil.example"));
    response.authority.push(ns("com", "ns.evil.example"));
    // A validator of its own: a shared one would answer the walk from its cache.
    let (forged, forged_asked) =
        Script::drive(&Script::validator(), &response, captured_at(), |ask| {
            script.answer(ask)
        });
    assert!(secure(&verdict), "{verdict:?}");
    assert_eq!(forged, verdict);
    assert_eq!(forged_asked, asked);
}

#[test]
fn proofs_of_two_zones_in_one_response_are_each_checked_by_their_zone() {
    // The DNAME of `sidnlabs.nl` with the AAAA it leads to in `example.nl`, and a proof from each zone: the
    // NSEC3 records of the one are not checked with the keys of the other (D75).
    let script = Script::new();
    let mut response = capture("dname_answer");
    response.authority.extend(capture("ent_nsec3").authority);
    response
        .authority
        .extend(capture("leaf_www_example_nl_ds").authority);
    let verdict = script.run(&Script::validator(), &response, captured_at());
    assert!(secure(&verdict), "{verdict:?}");
    // And a proof of neither zone is still forged data: bogus.
    let mut other = capture("dname_answer");
    other.authority.extend(capture("nxdomain_nsec3").authority);
    let verdict = script.run(&Script::validator(), &other, captured_at());
    assert!(matches!(verdict, Verdict::Bogus { .. }), "{verdict:?}");
}

// The key cache (D86): what a validator learned of the zones, kept for the TTL of the proofs.

/// The captures with every TTL at five minutes, and a validator of its own.
fn cached() -> (Script, Validator) {
    (
        Script::new().with_ttl(Ttl::from_wire(300)),
        Script::validator(),
    )
}

/// The verdict on the capture `id` at `now`, and the questions asked for it.
fn drive_capture(
    script: &Script,
    validator: &Validator,
    id: &str,
    now: u32,
) -> (Verdict, Vec<String>) {
    Script::drive(validator, &capture(id), now, |ask| script.answer(ask))
}

#[test]
fn a_validation_under_a_cached_chain_asks_nothing() {
    let (script, validator) = cached();
    let (first, asked) = drive_capture(&script, &validator, "alg8_a", captured_at());
    assert!(secure(&first), "{first:?}");
    assert_eq!(asked.len(), 5, "{asked:?}");
    let (second, asked) = drive_capture(&script, &validator, "alg8_a", captured_at());
    assert_eq!(second, first);
    assert_eq!(asked, Vec::<String>::new());
}

#[test]
fn a_cache_is_shared_by_the_clones_of_a_validator_and_by_threads() {
    fn shared<T: Send + Sync>() {}
    shared::<Validator>();
    let (script, validator) = cached();
    drive_capture(&script, &validator, "alg8_a", captured_at());
    let clone = validator.clone();
    let (verdict, asked) = drive_capture(&script, &clone, "alg8_a", captured_at());
    assert!(
        secure(&verdict) && asked.is_empty(),
        "{verdict:?} {asked:?}"
    );
    std::thread::scope(|scope| {
        for _ in 0..4 {
            scope.spawn(|| {
                let (verdict, asked) = drive_capture(&script, &validator, "alg8_a", captured_at());
                assert!(
                    secure(&verdict) && asked.is_empty(),
                    "{verdict:?} {asked:?}"
                );
            });
        }
    });
}

#[test]
fn a_validator_of_other_anchors_has_a_cache_of_its_own() {
    let (script, validator) = cached();
    drive_capture(&script, &validator, "alg8_a", captured_at());
    let mut anchors = TrustAnchors::root();
    anchors.add_negative(name("nl"));
    let other = Validator::new(anchors, Limits::default());
    // The keys of `nl` are in the cache of the first: secure there, insecure here.
    let (verdict, _) = drive_capture(&script, &other, "alg8_a", captured_at());
    assert!(matches!(verdict, Verdict::Insecure { .. }), "{verdict:?}");
}

#[test]
fn an_entry_holds_for_its_ttl_and_not_one_second_more() {
    let (script, validator) = cached();
    let at = captured_at();
    let (first, _) = drive_capture(&script, &validator, "alg8_a", at);
    assert!(secure(&first), "{first:?}");
    // The keys hold for the 300 s of the records, the answer for its own, shorter TTL.
    let (verdict, asked) = drive_capture(&script, &validator, "alg8_a", at + 299);
    assert_eq!(asked, Vec::<String>::new());
    // What is left of the keys'' TTL is what the answer may be kept for.
    assert_eq!(
        verdict,
        Verdict::Secure {
            ttl: Ttl::from_wire(1)
        }
    );
    let (verdict, asked) = drive_capture(&script, &validator, "alg8_a", at + 300);
    assert!(secure(&verdict), "{verdict:?}");
    assert_ne!(asked.len(), 0);
}

#[test]
fn a_clock_gone_back_finds_nothing() {
    let (script, validator) = cached();
    let at = captured_at();
    drive_capture(&script, &validator, "alg8_a", at + 100);
    let (verdict, asked) = drive_capture(&script, &validator, "alg8_a", at);
    assert!(secure(&verdict), "{verdict:?}");
    assert_eq!(asked.len(), 5, "{asked:?}");
}

#[test]
fn an_answer_nobody_gave_is_not_kept() {
    let (script, validator) = cached();
    let silent = |ask: &Question<'static>| {
        (ask.name != name("nl") || ask.qtype != RecordType::DNSKEY)
            .then(|| script.answer(ask))
            .flatten()
    };
    let (verdict, _) = Script::drive(&validator, &capture("alg8_a"), captured_at(), silent);
    assert!(
        matches!(verdict, Verdict::Indeterminate { .. }),
        "{verdict:?}"
    );
    // The root's keys were verified and are kept, `nl` was not decided and is asked again.
    let (verdict, asked) = drive_capture(&script, &validator, "alg8_a", captured_at());
    assert!(secure(&verdict), "{verdict:?}");
    assert_eq!(
        asked,
        [
            "nl. DS",
            "nl. DNSKEY",
            "nlnetlabs.nl. DS",
            "nlnetlabs.nl. DNSKEY"
        ]
    );
}

#[test]
fn an_exhausted_budget_is_never_kept_and_the_verified_part_is() {
    let (script, _) = cached();
    let limits = Limits {
        budget: Budget::new(Verifications(2), Nsec3Hashes(0)),
        ..Limits::default()
    };
    let validator = Validator::new(TrustAnchors::root(), limits);
    // Each attempt verifies what it can, and the next starts from there: never bogus, and secure at last.
    let mut verdicts = Vec::new();
    for _ in 0..8 {
        let (verdict, _) = drive_capture(&script, &validator, "alg8_a", captured_at());
        let done = secure(&verdict);
        verdicts.push(verdict);
        if done {
            break;
        }
    }
    let last = verdicts.pop().expect("a verdict");
    assert!(secure(&last), "{last:?} after {verdicts:?}");
    assert!(
        verdicts
            .iter()
            .all(|verdict| matches!(verdict, Verdict::Indeterminate { .. })),
        "{verdicts:?}"
    );
}

#[test]
fn a_bogus_zone_is_held_sixty_seconds_and_not_renewed_by_being_read() {
    // `rhybar.cz`: the DS matches none of its keys, and `cz` is sound.
    let (script, validator) = cached();
    let at = captured_at();
    let (first, asked) = drive_capture(&script, &validator, "bogus_expired", at);
    assert!(bogus(&first, InfoCode::DNSKEY_MISSING), "{first:?}");
    assert_ne!(asked.len(), 0);
    let (again, asked) = drive_capture(&script, &validator, "bogus_expired", at + 59);
    assert_eq!(again, first);
    assert_eq!(asked, Vec::<String>::new());
    // The read at 59 s did not renew it.
    let (again, asked) = drive_capture(&script, &validator, "bogus_expired", at + 60);
    assert!(bogus(&again, InfoCode::DNSKEY_MISSING), "{again:?}");
    assert_eq!(asked.len(), 2, "{asked:?}");
    // The sound zones around it do not suffer, and what is not asked is the keys of `cz`.
    let (verdict, asked) = drive_capture(&script, &validator, "alg8_a", at + 61);
    assert!(secure(&verdict), "{verdict:?}");
    assert!(!asked.contains(&". DNSKEY".to_owned()), "{asked:?}");
}

#[test]
fn a_forged_ds_in_one_validation_poisons_no_other() {
    let (script, validator) = cached();
    let mut forged = capture("nl_ds");
    with_rrsigs(&mut forged, |rrsig| {
        rrsig.key_tag = rrsig.key_tag.wrapping_add(1);
    });
    let (verdict, _) = Script::drive(&validator, &capture("alg8_a"), captured_at(), |ask| {
        if ask.name == name("nl") && ask.qtype == RecordType::DS {
            Some(&forged)
        } else {
            script.answer(ask)
        }
    });
    assert!(matches!(verdict, Verdict::Bogus { .. }), "{verdict:?}");
    let (verdict, asked) = drive_capture(&script, &validator, "alg8_a", captured_at());
    assert!(secure(&verdict), "{verdict:?}");
    assert!(asked.contains(&"nl. DS".to_owned()), "{asked:?}");
}

#[test]
fn the_cache_is_bound_and_a_bound_of_nothing_keeps_nothing() {
    let (script, _) = cached();
    // Another zone's answer between two of `nlnetlabs.nl` pushes the keys of `nlnetlabs.nl` out of a cache
    // of one entry, and leaves them in a cache of room.
    for (key_cache, kept) in [(0, false), (1, false), (4096, true)] {
        let limits = Limits {
            key_cache,
            ..Limits::default()
        };
        let validator = Validator::new(TrustAnchors::root(), limits);
        let (_, first) = drive_capture(&script, &validator, "alg8_a", captured_at());
        drive_capture(&script, &validator, "alg13_a", captured_at());
        let (verdict, second) = drive_capture(&script, &validator, "alg8_a", captured_at());
        assert!(secure(&verdict), "{verdict:?}");
        if kept {
            assert_eq!(second, Vec::<String>::new());
        } else {
            assert!(!second.is_empty(), "{key_cache}: {second:?}");
        }
        assert_ne!(first.len(), 0);
    }
}

/// `nl`'s DNSKEY answer served by `script` but for `nl`, which is `replacement`.
fn with_nl_keys<'s>(
    script: &'s Script,
    replacement: &'s Message<'static>,
) -> impl Fn(&Question<'static>) -> Option<&'s Message<'static>> {
    move |ask| {
        if ask.name == name("nl") && ask.qtype == RecordType::DNSKEY {
            Some(replacement)
        } else {
            script.answer(ask)
        }
    }
}

/// A signature of `nl`'s keys that no longer checks: the TTL it signed is not the one it is given.
fn bad_signature_of_nl_keys() -> Message<'static> {
    let mut keys = capture("nl_dnskey");
    with_rrsigs(&mut keys, |rrsig| rrsig.original_ttl += 1);
    keys
}

#[test]
fn a_dnskey_answer_without_signatures_given_to_start_is_never_kept() {
    // `start` takes its response as the answer to its own question: a DNSKEY answer fetched without DO is no
    // proof about `nl`, and must not make `nl` bogus for the validations after it (D86).
    let (script, validator) = cached();
    let mut seeded = capture("nl_dnskey");
    seeded
        .answer
        .retain(|record| record.rtype() != RecordType::RRSIG);
    let (verdict, _) = Script::drive(&validator, &seeded, captured_at(), |ask| script.answer(ask));
    assert!(matches!(verdict, Verdict::Bogus { .. }), "{verdict:?}");
    let (verdict, asked) = drive_capture(&script, &validator, "alg8_a", captured_at());
    assert!(secure(&verdict), "{verdict:?}");
    assert!(asked.contains(&"nl. DNSKEY".to_owned()), "{asked:?}");
}

#[test]
fn a_dnskey_answer_that_fails_given_to_start_is_never_kept() {
    // Even a signature that fails under the key the DS names: the response is the caller's, not the zone's.
    let (script, validator) = cached();
    let seeded = bad_signature_of_nl_keys();
    let (verdict, _) = Script::drive(&validator, &seeded, captured_at(), |ask| script.answer(ask));
    assert!(matches!(verdict, Verdict::Bogus { .. }), "{verdict:?}");
    let (verdict, asked) = drive_capture(&script, &validator, "alg8_a", captured_at());
    assert!(secure(&verdict), "{verdict:?}");
    assert!(asked.contains(&"nl. DNSKEY".to_owned()), "{asked:?}");
}

#[test]
fn a_dnskey_answer_that_proves_nothing_is_never_kept() {
    // An empty answer, a lame server or a replay says nothing lasting of the zone: bogus for this validation,
    // asked again by the next (D86).
    let (script, validator) = cached();
    let mut empty = capture("nl_dnskey");
    empty.answer.clear();
    let (verdict, _) = Script::drive(
        &validator,
        &capture("alg8_a"),
        captured_at(),
        with_nl_keys(&script, &empty),
    );
    assert!(matches!(verdict, Verdict::Bogus { .. }), "{verdict:?}");
    let mut unsigned = capture("nl_dnskey");
    unsigned
        .answer
        .retain(|record| record.rtype() != RecordType::RRSIG);
    let (verdict, _) = Script::drive(
        &validator,
        &capture("alg8_a"),
        captured_at(),
        with_nl_keys(&script, &unsigned),
    );
    assert!(matches!(verdict, Verdict::Bogus { .. }), "{verdict:?}");
    let (verdict, asked) = drive_capture(&script, &validator, "alg8_a", captured_at());
    assert!(secure(&verdict), "{verdict:?}");
    assert!(asked.contains(&"nl. DNSKEY".to_owned()), "{asked:?}");
}

#[test]
fn a_signature_that_fails_under_the_keys_a_ds_names_is_held_sixty_seconds() {
    let (script, validator) = cached();
    let at = captured_at();
    let forged = bad_signature_of_nl_keys();
    let (first, _) = Script::drive(
        &validator,
        &capture("alg8_a"),
        at,
        with_nl_keys(&script, &forged),
    );
    assert!(matches!(first, Verdict::Bogus { .. }), "{first:?}");
    let (again, asked) = drive_capture(&script, &validator, "alg8_a", at + 59);
    assert_eq!(again, first);
    assert_eq!(asked, Vec::<String>::new());
    let (verdict, asked) = drive_capture(&script, &validator, "alg8_a", at + 60);
    assert!(secure(&verdict), "{verdict:?}");
    assert!(asked.contains(&"nl. DNSKEY".to_owned()), "{asked:?}");
}

#[test]
fn insecure_and_no_cut_outcomes_are_kept_for_their_proofs() {
    // `google.com`: an opt-out proof, insecure. `_tcp.nlnetlabs.nl`: an empty non-terminal, no zone cut.
    for id in ["google_com_a", "ent_nsec"] {
        let (script, validator) = cached();
        let (first, asked) = drive_capture(&script, &validator, id, captured_at());
        assert_ne!(asked.len(), 0, "{id}");
        let (second, asked) = drive_capture(&script, &validator, id, captured_at());
        assert_eq!(second, first, "{id}");
        assert_eq!(asked, Vec::<String>::new(), "{id}");
    }
}

#[test]
fn a_negative_anchor_is_the_validators_own_and_its_zones_are_not_kept() {
    let (script, _) = cached();
    let mut anchors = TrustAnchors::root();
    anchors.add_negative(name("nl"));
    let validator = Validator::new(anchors, Limits::default());
    let (first, _) = drive_capture(&script, &validator, "alg8_a", captured_at());
    assert!(matches!(first, Verdict::Insecure { .. }), "{first:?}");
    let (second, asked) = drive_capture(&script, &validator, "alg8_a", captured_at());
    assert_eq!(second, first);
    assert_eq!(asked, Vec::<String>::new());
    // Another validator with the same negative anchor shares nothing with it, and no other with none is
    // affected by it.
    let (script, plain) = cached();
    let (verdict, _) = drive_capture(&script, &plain, "alg8_a", captured_at());
    assert!(secure(&verdict), "{verdict:?}");
}
