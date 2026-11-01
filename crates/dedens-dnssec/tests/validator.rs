//! The validator against the captured responses (`testdata/README.md`): a scripted caller answers each question
//! it asks from the captures, at the time of the capture, and the verdict is the one the README gives (RFC 4035
//! §4.3), but for what an opt-out proof covers, which is insecure (RFC 5155 §9.2, D75).

use std::collections::HashMap;
use std::net::Ipv4Addr;

use dedens_dnssec::anchor::TrustAnchors;
use dedens_dnssec::crypto::{Budget, Nsec3Hashes, Verifications};
use dedens_dnssec::denial::MaxIterations;
use dedens_dnssec::validator::{InsecureReason, Limits, Next, Validator, Verdict};
use dedens_proto::edns::InfoCode;
use dedens_proto::{Message, Name, Question, RData, Rcode, RecordType, WireRdata};

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
                    assert!(asked.len() <= 64, "asks without end: {asked:?}");
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

#[test]
fn a_denial_is_kept_three_hours_at_most() {
    let script = Script::new();
    for id in ["nxdomain_root_nsec", "nodata_root_nsec", "jm_ds"] {
        // The root's NSEC records have a TTL of a day (RFC 9077 §3.4).
        let Verdict::Secure { ttl } = script.verdict(id) else {
            panic!("{id}");
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

/// `rhybar.cz`'s chain runs through `cz`, which the set does not hold (`testdata/README.md`): the caller has
/// no answer for it.
#[test]
fn the_chain_of_rhybar_cz_stops_at_the_missing_zone() {
    let verdict = Script::new().verdict("bogus_expired");
    assert!(
        matches!(&verdict, Verdict::Indeterminate { ede } if ede.code == InfoCode::NO_REACHABLE_AUTHORITY),
        "{verdict:?}"
    );
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
    // `www.edgekey.net` is below `edgekey.net`, which has no DS: it is not asked about.
    assert!(
        !asked.iter().any(|ask| ask.starts_with("www.")),
        "{asked:?}"
    );
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
    assert!(
        matches!(
            &verdict,
            Verdict::Bogus { .. } | Verdict::Indeterminate { .. }
        ),
        "{verdict:?}"
    );
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
        // Where the name is not a zone's apex, the validator first asks for its DS, which the script lacks.
        assert!(
            bogus(&verdict, InfoCode::NSEC_MISSING)
                || matches!(verdict, Verdict::Indeterminate { .. }),
            "{id}: {verdict:?}"
        );
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
fn an_exhausted_budget_is_bogus() {
    let script = Script::new();
    let limits = Limits {
        budget: Budget::new(Verifications(2), Nsec3Hashes(0)),
        ..Limits::default()
    };
    let validator = Validator::new(TrustAnchors::root(), limits);
    let verdict = script.run(&validator, &capture("alg8_a"), captured_at());
    assert!(bogus(&verdict, InfoCode::DNSSEC_BOGUS), "{verdict:?}");
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
