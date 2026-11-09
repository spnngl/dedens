//! DNSSEC validation (RFC 4035 §5, D76) against the captures of `testdata/dnssec`: the verdict in every format, the
//! chain asked of the same server, with CD set (RFC 6840 §5.9), trust anchor files and negative trust anchors.

use assert_cmd::Command;
use dedens_proto::edns::EdnsFlags;
use dedens_proto::{Class, Flags, Name, Record, RecordType};
use dedens_testkit::dnssec;
use dedens_testkit::responder::Responder;
use predicates::str::contains;

use crate::util::{dedens, queries, redact};

/// The captures `cloudflare.com` A is validated from: its answer and the chain of trust down to it.
const SECURE: [&str; 6] = [
    "alg13_a",
    "root_dnskey",
    "com_ds",
    "com_dnskey",
    "cloudflare_com_ds",
    "cloudflare_com_dnskey",
];

/// `google.com` A, in an unsigned zone: the opt-out proof of its missing DS and the unsigned answer.
const INSECURE: [&str; 5] = [
    "google_com_a",
    "google_com_ds",
    "root_dnskey",
    "com_ds",
    "com_dnskey",
];

/// `dnssec-failed.org` A, whose DS matches no key.
const BOGUS: [&str; 6] = [
    "bogus_no_key",
    "root_dnskey",
    "org_ds",
    "org_dnskey",
    "dnssec_failed_org_ds",
    "dnssec_failed_org_dnskey",
];

/// The command validating against the captures, at the time they were taken.
fn validating(server: &Responder, name: &str, args: &[&str]) -> Command {
    let mut command = dedens();
    command
        .env("DEDENS_NOW", dnssec::captured_at().to_string())
        .arg(server.at())
        .arg(name)
        .args(args);
    command
}

/// The standard output of a validating run that exits with `code`.
fn validated(server: &Responder, name: &str, args: &[&str], code: i32) -> String {
    let output = validating(server, name, args)
        .assert()
        .code(code)
        .get_output()
        .stdout
        .clone();
    redact(
        &String::from_utf8(output).expect("UTF-8"),
        server.addr.port(),
    )
}

#[test]
fn a_secure_response_is_shown_with_its_verdict_in_every_format() {
    let server = Responder::start(&SECURE);
    for (snapshot, flag) in [
        ("validate_secure_human", "--format=human"),
        ("validate_secure_json", "--json"),
        ("validate_secure_yaml", "--yaml"),
        ("validate_secure_short", "+short"),
    ] {
        let out = validated(&server, "cloudflare.com", &["+validate", flag], 0);
        insta::assert_snapshot!(snapshot, out);
    }
}

/// D76: a secure response is shown as the validator covers it (`dedens_dnssec::covered`): the answer
/// of a real capture with what the verdict is not about added, an upstream's injection, is not shown under it:
/// unrelated sets, signatures that sign nothing, other classes, authority sets off the names, the additional
/// section.
#[test]
fn a_secure_response_is_shown_as_far_as_it_was_verified() {
    let mut forged = dnssec::response("alg13_a");
    let a = forged.answer[0].clone();
    let signature = forged
        .answer
        .iter()
        .find(|record| record.rtype() == RecordType::RRSIG)
        .expect("a signature")
        .clone();
    let at = |owner: &str, record: &Record<'static>| Record {
        name: owner.parse::<Name<'static>>().expect("a name"),
        ..record.clone()
    };
    forged.answer.push(at("other.example.", &a));
    forged.answer.push(at("other.example.", &signature));
    forged.answer.push(at("orphan.cloudflare.com.", &signature));
    forged.answer.push(Record {
        class: Class::CH,
        ..a.clone()
    });
    forged.authority.push(at("cloudflare.net.", &a));
    forged.additional.push(at("cloudflare.com.", &a));
    let wire = forged.to_vec().expect("the message fits");
    let genuine = Responder::start(&SECURE);
    let injected = Responder::start_with(&SECURE[1..], &[wire]);
    let shown = |server: &Responder| -> serde_json::Value {
        let output = validating(server, "cloudflare.com", &["+validate", "--json"])
            .assert()
            .code(0)
            .get_output()
            .stdout
            .clone();
        serde_json::from_slice(&output).expect("one JSON object")
    };
    let (genuine, injected) = (shown(&genuine), shown(&injected));
    assert_eq!(injected["dnssec"]["status"], "secure", "{injected}");
    assert_eq!(injected["answer"], genuine["answer"], "{injected}");
    for section in ["authority", "additional"] {
        assert!(
            injected[section].as_array().is_none_or(Vec::is_empty),
            "{section}: {injected}"
        );
    }
}

#[test]
fn validation_asks_the_chain_of_the_same_server_with_do_cd_and_rd() {
    let server = Responder::start(&SECURE);
    validated(&server, "cloudflare.com", &["+validate"], 0);
    let asked: Vec<_> = queries(&server)
        .into_iter()
        .map(|(_, query)| {
            let question = query.questions[0].clone();
            let edns = query.edns.as_ref().expect("EDNS");
            assert!(edns.flags.contains(EdnsFlags::DO), "{question:?}");
            for flag in [Flags::CD, Flags::RD] {
                assert!(query.header.flags.contains(flag), "{question:?}");
            }
            (question.name.to_string(), question.qtype.to_string())
        })
        .collect();
    let want = [
        ("cloudflare.com.", "A"),
        (".", "DNSKEY"),
        ("com.", "DS"),
        ("com.", "DNSKEY"),
        ("cloudflare.com.", "DS"),
        ("cloudflare.com.", "DNSKEY"),
    ];
    assert_eq!(asked, want.map(|(n, t)| (n.to_owned(), t.to_owned())));
}

/// The zones `cname_to_insecure` crosses: the chain of trust of `ripe.net`, and the DS `edgekey.net` and
/// `akamaiedge.net` lack.
const CROSSED: [&str; 8] = [
    "root_dnskey",
    "net_ds",
    "net_dnskey",
    "ripe_net_ds",
    "ripe_net_dnskey",
    "leaf_www_ripe_net_ds",
    "edgekey_net_ds",
    "akamaiedge_net_ds",
];

/// D76: a CNAME chain that stops short of the type asked is chased: the name it goes on at is asked of the same
/// server and validated on its own, the verdict that of its answer. The responses are the capture of `www.ripe.net`
/// A cut in two, its signed CNAME alone and the rest of the chain.
#[test]
fn a_chain_that_stops_short_is_chased() {
    let genuine = dnssec::response("cname_to_insecure");
    let head = "www.ripe.net.".parse::<Name<'static>>().expect("a name");
    let next = "www.ripe.net.edgekey.net."
        .parse::<Name<'static>>()
        .expect("a name");
    let (first, rest): (Vec<_>, Vec<_>) = genuine
        .answer
        .iter()
        .cloned()
        .partition(|record| record.name == head);
    let response = |name: &Name<'static>, answer: Vec<Record<'static>>| {
        let mut message = genuine.clone();
        message.questions[0].name = name.clone();
        message.answer = answer;
        message.authority.clear();
        message.additional.clear();
        message.to_vec().expect("the message fits")
    };
    let server = Responder::start_with(&CROSSED, &[response(&head, first), response(&next, rest)]);
    let output = validating(&server, "www.ripe.net", &["+validate", "--json"])
        .assert()
        .code(0)
        .get_output()
        .stdout
        .clone();
    let report: serde_json::Value = serde_json::from_slice(&output).expect("one JSON object");
    assert_eq!(report["dnssec"]["status"], "insecure", "{report}");
    let chased = queries(&server)
        .iter()
        .any(|(_, query)| query.questions[0].name == next);
    assert!(chased, "{report}");
}

#[test]
fn an_unsigned_zone_is_insecure_not_a_failure() {
    let server = Responder::start(&INSECURE);
    for (snapshot, flag) in [
        ("validate_insecure_human", "--format=human"),
        ("validate_insecure_json", "--json"),
        ("validate_insecure_yaml", "--yaml"),
    ] {
        let out = validated(&server, "google.com", &["+validate", flag], 0);
        insta::assert_snapshot!(snapshot, out);
    }
}

#[test]
fn a_bogus_response_is_shown_with_its_extended_error_and_still_exits_0() {
    let server = Responder::start(&BOGUS);
    for (snapshot, flag) in [
        ("validate_bogus_human", "--format=human"),
        ("validate_bogus_json", "--json"),
        ("validate_bogus_yaml", "--yaml"),
    ] {
        let out = validated(&server, "dnssec-failed.org", &["+validate", flag], 0);
        insta::assert_snapshot!(snapshot, out);
    }
    validating(&server, "dnssec-failed.org", &["+validate", "+short"])
        .assert()
        .code(0)
        .stderr(contains("dnssec bogus (EDE"));
}

#[test]
fn a_trust_anchor_file_replaces_the_root_anchors() {
    let server = Responder::start(&SECURE);
    let dir = tempfile::tempdir().expect("a directory");
    // The root keys themselves, as DNSKEY records: trusted as is.
    let good = dir.path().join("root.keys");
    std::fs::write(&good, records_of("root_dnskey", RecordType::DNSKEY)).expect("written");
    let good = good.to_str().expect("UTF-8");
    let out = validated(&server, "cloudflare.com", &["--trust-anchor", good], 0);
    assert!(out.contains("dnssec secure"), "{out}");
    // The DS of `nl` at the name of the root: no root key matches it.
    let wrong = dir.path().join("wrong.ds");
    let ds = records_of("nl_ds", RecordType::DS).replacen("nl.", ".", 1);
    std::fs::write(&wrong, ds).expect("written");
    let wrong = wrong.to_str().expect("UTF-8");
    let out = validated(&server, "cloudflare.com", &["--trust-anchor", wrong], 0);
    insta::assert_snapshot!("validate_wrong_anchor_human", out);
}

#[test]
fn a_negative_trust_anchor_makes_a_name_insecure() {
    let server = Responder::start(&SECURE);
    let out = validated(&server, "cloudflare.com", &["--insecure", "com"], 0);
    assert!(out.contains("dnssec insecure"), "{out}");
}

#[test]
fn a_dnssec_expectation_fails_the_run_with_exit_1() {
    let server = Responder::start(&SECURE);
    let dir = tempfile::tempdir().expect("a directory");
    let file = dir.path().join("queries.yaml");
    let at = server.addr;
    for (expected, code) in [("secure", 0), ("bogus", 1)] {
        let queries = format!(
            "server: {at}\noptions:\n  validate: true\nqueries:\n  - name: cloudflare.com\n    type: A\n    expect:\n      dnssec: {expected}\n"
        );
        std::fs::write(&file, queries).expect("written");
        let out = dedens()
            .env("DEDENS_NOW", dnssec::captured_at().to_string())
            .arg("-f")
            .arg(&file)
            .assert()
            .code(code)
            .get_output()
            .stdout
            .clone();
        let out = String::from_utf8(out).expect("UTF-8");
        let failed = out.contains("dnssec secure instead of bogus");
        assert_eq!(failed, code == 1, "{out}");
    }
}

#[test]
fn validation_needs_what_it_sets() {
    for (args, text) in [
        (&["+validate", "+noedns"][..], "need EDNS"),
        (&["+validate", "+nodnssec"], "validate sets DO and CD"),
        (&["+validate", "+nocd"], "validate sets DO and CD"),
        (&["+validate", "+trace"], "+trace goes with no"),
        (&["--insecure", "com", "+noedns"], "need EDNS"),
    ] {
        dedens()
            .arg("example.com")
            .args(args)
            .assert()
            .code(2)
            .stderr(contains(text));
    }
    dedens()
        .args([
            "@127.0.0.1",
            "example.com",
            "--trust-anchor",
            "/nonexistent/anchors",
        ])
        .assert()
        .failure()
        .stderr(contains("/nonexistent/anchors"));
}

/// The records of `id`'s answer section of type `keep`, as zone text.
fn records_of(id: &str, keep: RecordType) -> String {
    dnssec::response(id)
        .answer
        .iter()
        .filter(|record| record.rtype() == keep)
        .fold(String::new(), |text, record| {
            text + &record.to_string() + "\n"
        })
}
