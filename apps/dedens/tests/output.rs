//! What the command prints: each output format, colors, verbose, several servers side by side, repeat, and the exit
//! codes of an answer (D33).

use dedens_testkit::responder::Responder;
use predicates::prelude::*;
use predicates::str::contains;

use crate::util::{dedens, redact, run};

#[test]
fn human_output_lists_each_query_in_argument_order() {
    let server = Responder::start(&["ede", "nxdomain_soa", "mx"]);
    let out = run(
        &[
            &server.at(),
            "dnssec-failed.org",
            "nonexistent.invalid",
            "gmail.com",
            "MX",
            "+nocookie",
        ],
        0,
    );
    insta::assert_snapshot!("human", redact(&out, server.addr.port()));
}

#[test]
fn short_output_is_the_answer_data() {
    let server = Responder::start(&["mx"]);
    let out = run(&[&server.at(), "gmail.com", "MX", "+short"], 0);
    insta::assert_snapshot!("short", out);
}

#[test]
fn json_output_is_one_object_per_line() {
    let server = Responder::start(&["nsid", "aaaa"]);
    let out = run(&[&server.at(), "example.com", "+nsid", "--json"], 0);
    insta::assert_snapshot!("json", redact(&out, server.addr.port()));
    let out = run(
        &[
            &server.at(),
            "example.com",
            "cloudflare.com",
            "AAAA",
            "A",
            "--json",
            "+tries=1",
            "+time=200ms",
        ],
        9,
    );
    assert_eq!(out.lines().count(), 2, "two answered of four: {out}");
    for line in out.lines() {
        serde_json::from_str::<serde_json::Value>(line).expect("a JSON object");
    }
}

#[test]
fn yaml_output_is_one_document_per_response() {
    let server = Responder::start(&["a", "nxdomain_soa"]);
    let out = run(
        &[&server.at(), "example.com", "nonexistent.invalid", "--yaml"],
        0,
    );
    insta::assert_snapshot!("yaml", redact(&out, server.addr.port()));
    let same = run(
        &[
            &server.at(),
            "example.com",
            "nonexistent.invalid",
            "--format=yaml",
        ],
        0,
    );
    assert_eq!(
        redact(&same, server.addr.port()),
        redact(&out, server.addr.port())
    );
}

#[test]
fn colors_follow_the_choice_and_no_color() {
    let server = Responder::start(&["a"]);
    let at = server.at();
    let escape = contains("\u{1b}[");
    dedens()
        .args([&at, "example.com", "--color=always"])
        .assert()
        .success()
        .stdout(escape.clone());
    dedens()
        .args([&at, "example.com"])
        .assert()
        .success()
        .stdout(escape.clone().not());
    dedens()
        .args([&at, "example.com"])
        .env("CLICOLOR_FORCE", "1")
        .assert()
        .stdout(escape.clone());
    dedens()
        .args([&at, "example.com"])
        .env("CLICOLOR_FORCE", "1")
        .env("NO_COLOR", "1")
        .assert()
        .stdout(escape.clone().not());
    dedens()
        .args([&at, "example.com"])
        .env("CLICOLOR_FORCE", "1")
        .env("NO_COLOR", "")
        .assert()
        .stdout(escape);
}

#[test]
fn several_servers_answer_side_by_side() {
    let (validating, not) = (Responder::start(&["ede"]), Responder::start(&["ede_cd"]));
    let (first, second) = (validating.addr.port(), not.addr.port());
    let at = [validating.at(), not.at()];
    let redacted = |out: &str| redact(&redact(out, first), second);
    let out = run(&[&at[0], &at[1], "dnssec-failed.org", "+nocookie"], 0);
    insta::assert_snapshot!("several_servers", redacted(&out));
    let out = run(&[&at[0], &at[1], "dnssec-failed.org", "--json"], 0);
    let ids: Vec<String> = out
        .lines()
        .map(|line| {
            let report: serde_json::Value = serde_json::from_str(line).expect("a JSON object");
            report["id"].as_str().expect("an id").to_owned()
        })
        .collect();
    assert_eq!(
        ids,
        [
            format!("dnssec-failed.org_A@127.0.0.1:{first}"),
            format!("dnssec-failed.org_A@127.0.0.1:{second}")
        ]
    );
    // TTLs and record order aside, these two agree.
    let (a, nsid) = (Responder::start(&["a"]), Responder::start(&["nsid"]));
    let out = run(&[&a.at(), &nsid.at(), "example.com", "--color=never"], 0);
    assert_eq!(out.matches("answer").count(), 2, "{out}");
    assert!(!out.contains("disagree"), "{out}");
}

#[test]
fn repeat_asks_again_and_gives_the_spread() {
    let server = Responder::start(&["a"]);
    let out = run(
        &[&server.at(), "example.com", "+repeat=3", "--color=never"],
        0,
    );
    assert_eq!(server.queries().len(), 3);
    assert!(out.contains("\n3 queries: min "), "{out}");
    assert!(!out.contains("unanswered"), "{out}");
    let out = run(&[&server.at(), "example.com", "--repeat", "2", "--json"], 0);
    let report: serde_json::Value = serde_json::from_str(&out).expect("one JSON object");
    let latency = &report["latency"];
    assert_eq!(
        (latency["sent"].as_u64(), latency.get("errors")),
        (Some(2), None)
    );
    assert!(latency["min_us"].as_u64() <= latency["max_us"].as_u64());
    let once = run(&[&server.at(), "example.com", "--json"], 0);
    assert!(!once.contains("latency"), "{once}");
}

#[test]
fn yaml_output_reads_as_the_json_output() {
    let server = Responder::start(&["a", "nxdomain_soa"]);
    for name in ["example.com", "nonexistent.invalid"] {
        let json: serde_json::Value =
            serde_json::from_str(&run(&[&server.at(), name, "--json"], 0)).expect("a JSON object");
        let yaml: serde_json::Value =
            serde_saphyr::from_str(&run(&[&server.at(), name, "--yaml"], 0))
                .expect("a YAML document");
        // The run's own numbers aside.
        let fixed = |mut report: serde_json::Value| {
            report["exchange"]["rtt_us"] = serde_json::Value::Null;
            report["header"]["id"] = serde_json::Value::Null;
            report
        };
        assert_eq!(fixed(yaml), fixed(json), "{name}");
    }
}

#[test]
fn a_referral_is_shown_as_one() {
    let server = Responder::start(&["referral_com"]);
    let out = run(&[&server.at(), "example.com", "+norec", "--color=never"], 0);
    // Outside +trace, its glue is listed, each owner with its TTL.
    insta::assert_snapshot!("referral", redact(&out, server.addr.port()));
}

#[test]
fn a_silent_server_among_several_is_no_disagreement() {
    let (a, silent) = (Responder::start(&["a"]), Responder::start(&[]));
    dedens()
        .args([
            &a.at(),
            &silent.at(),
            "example.com",
            "+tries=1",
            "+time=100ms",
        ])
        .assert()
        .code(9)
        .stdout(contains("answer").and(contains("disagree").not()));
}

#[test]
fn a_server_given_twice_is_asked_once() {
    let server = Responder::start(&["a"]);
    run(&[&server.at(), &server.at(), "example.com", "+short"], 0);
    assert_eq!(server.queries().len(), 1);
}

#[test]
fn repeat_against_a_silent_server_exits_9() {
    let server = Responder::start(&[]);
    dedens()
        .args([
            &server.at(),
            "example.com",
            "+repeat=3",
            "+tries=1",
            "+time=100ms",
        ])
        .assert()
        .code(9)
        .stdout("");
    assert_eq!(server.queries().len(), 3);
}

#[test]
fn verbose_prints_the_exchange_on_stderr() {
    let server = Responder::start(&["truncated", "txt_large"]);
    let args = [&server.at(), "google.com", "TXT", "+noedns", "+short"];
    dedens().args(args).assert().success().stderr("");
    dedens()
        .args(args)
        .arg("-v")
        .assert()
        .success()
        .stderr(contains("truncated: asking again over TCP").and(contains("sending").not()));
    dedens()
        .args(args)
        .arg("-vv")
        .assert()
        .success()
        .stderr(contains("sending").and(contains("received")));
    let out = run(
        &[
            &server.at(),
            "google.com",
            "TXT",
            "+noedns",
            "--color=never",
        ],
        0,
    );
    assert!(out.contains("over TCP after 2 queries"), "{out}");
}

#[test]
fn a_disagreement_follows_its_own_query() {
    let (validating, not) = (
        Responder::start(&["ede", "a"]),
        Responder::start(&["ede_cd", "a"]),
    );
    let out = run(
        &[
            &validating.at(),
            &not.at(),
            "dnssec-failed.org",
            "example.com",
            "--color=never",
        ],
        0,
    );
    let disagree = out.find("servers disagree").expect("a disagreement");
    assert!(
        disagree < out.find("example.com. A").expect("the second query"),
        "{out}"
    );
    assert_eq!(out.matches("servers disagree").count(), 1, "{out}");
}

#[test]
fn noerror_is_good_news() {
    let server = Responder::start(&["a", "nxdomain_soa"]);
    let good = anstyle::AnsiColor::Green
        .on_default()
        .bold()
        .render()
        .to_string();
    let bad = anstyle::AnsiColor::Red
        .on_default()
        .bold()
        .render()
        .to_string();
    let out = run(&[&server.at(), "example.com", "--color=always"], 0);
    assert!(out.contains(&format!("{good}NOERROR")), "{out:?}");
    let out = run(&[&server.at(), "nonexistent.invalid", "--color=always"], 0);
    assert!(out.contains(&format!("{bad}NXDOMAIN")), "{out:?}");
}

#[test]
fn repeat_counts_the_unanswered_and_keeps_the_answer() {
    let server = Responder::flaky(&["a"]);
    let args = [
        &server.at(),
        "example.com",
        "+repeat=4",
        "+tries=1",
        "+time=100ms",
    ];
    let out = run(&[&args[..], &["--color=never"]].concat(), 0);
    assert!(
        out.contains("\n4 queries: min ") && out.contains(" · 2 unanswered\n"),
        "{out}"
    );
    let out = run(&[&args[..], &["--json"]].concat(), 0);
    let report: serde_json::Value = serde_json::from_str(&out).expect("one JSON object");
    assert_eq!(report["latency"]["errors"].as_u64(), Some(2));
}
