//! The command against a loopback server answering with captured responses: every option, each output, query
//! files, the exit codes (D33).

mod common;

use std::time::{Duration, Instant};

use assert_cmd::Command;
use common::{Responder, TLS_NAME, Transport};
use dedens_proto::edns::{EdnsOption, OptionCode};
use dedens_proto::{EdnsFlags, Flags, Message};
use predicates::prelude::*;
use predicates::str::contains;

/// The command, without colors and with a resolv.conf that does not exist.
fn dedens() -> Command {
    let mut command = assert_cmd::cargo_bin_cmd!("dedens");
    command
        .env("DEDENS_RESOLV_CONF", "/nonexistent/resolv.conf")
        .env_remove("NO_COLOR")
        .env_remove("CLICOLOR_FORCE");
    command
}

/// The standard output of a run that exits with `code`.
fn run(args: &[&str], code: i32) -> String {
    let output = dedens()
        .args(args)
        .assert()
        .code(code)
        .get_output()
        .stdout
        .clone();
    String::from_utf8(output).expect("UTF-8")
}

/// `text` with the run's own numbers replaced by `N`: RTT, message ID, the server's port.
fn redact(text: &str, port: u16) -> String {
    let mut text: String = text
        .replace(&format!(":{port}"), ":PORT")
        .split_inclusive('\n')
        .map(|line| match line.split_once(" ms from ") {
            Some((head, tail)) => {
                let rtt = head.rfind(' ').map_or(0, |at| at + 1);
                format!("{}N ms from {tail}", &head[..rtt])
            }
            None => line.to_owned(),
        })
        .collect();
    for prefix in ["\"rtt_us\":", "\"id\":", "rtt_us: ", "id: "] {
        let mut out = String::new();
        let mut rest = text.as_str();
        while let Some(at) = rest.find(prefix) {
            let (before, after) = rest.split_at(at + prefix.len());
            out.push_str(before);
            let digits = after
                .find(|c: char| !c.is_ascii_digit() && c != '.')
                .unwrap_or(after.len());
            if digits > 0 {
                out.push('N');
            }
            rest = &after[digits..];
        }
        out.push_str(rest);
        text = out;
    }
    text
}

/// The queries `responder` received, decoded.
fn queries(responder: &Responder) -> Vec<(Transport, Message<'static>)> {
    responder
        .queries()
        .into_iter()
        .map(|(transport, wire)| {
            let message = Message::decode(&wire)
                .expect("a query")
                .message
                .into_owned();
            (transport, message)
        })
        .collect()
}

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
        .stdout(escape.not());
}

#[test]
fn query_options_set_the_query() {
    let server = Responder::start(&["nsid"]);
    let at = server.at();
    run(
        &[
            &at,
            "example.com",
            "+norecurse",
            "+cd",
            "+noad",
            "+dnssec",
            "+bufsize=4000",
            "+nsid",
            "+nocookie",
        ],
        0,
    );
    run(&[&at, "example.com", "+noedns", "+tcp"], 0);
    run(&[&at, "example.com", "+cookie=0102030405060708"], 0);
    let queries = queries(&server);
    let [
        (Transport::Udp, flagged),
        (Transport::Tcp, plain),
        (Transport::Udp, cookie),
    ] = &queries[..]
    else {
        panic!("three queries: {queries:?}");
    };
    assert_eq!(flagged.header.flags, Flags::CD);
    let edns = flagged.edns.as_ref().expect("EDNS");
    assert_eq!(edns.udp_payload, 4000);
    assert!(edns.flags.contains(EdnsFlags::DO));
    assert_eq!(
        edns.options
            .iter()
            .map(EdnsOption::code)
            .collect::<Vec<_>>(),
        [OptionCode::NSID]
    );
    assert_eq!(plain.header.flags, Flags::RD.with(Flags::AD));
    assert!(plain.edns.is_none());
    let Some(EdnsOption::Cookie(sent)) = cookie.edns.as_ref().and_then(|e| e.options.first())
    else {
        panic!("a cookie: {cookie:?}");
    };
    assert_eq!(sent.client(), [1, 2, 3, 4, 5, 6, 7, 8]);
}

#[test]
fn a_truncated_answer_is_asked_again_over_tcp_unless_ignored() {
    let server = Responder::start(&["truncated", "txt_large"]);
    let at = server.at();
    let full = run(&[&at, "google.com", "TXT", "+short"], 0);
    assert!(full.lines().count() > 1, "{full}");
    let kept = run(&[&at, "google.com", "TXT", "+ignore", "--json"], 0);
    assert!(kept.contains("\"tc\""), "{kept}");
    let transports: Vec<_> = server.queries().into_iter().map(|(t, _)| t).collect();
    assert_eq!(transports, [Transport::Udp, Transport::Tcp, Transport::Udp]);
}

/// RFC 7858, RFC 8310 §6.6 and §8.1: `tls://` or `+tls` asks over TLS a server whose certificate holds the name
/// after `#`, else its address; another name is refused before any query, unless `+tls-insecure`.
#[test]
fn tls_servers_answer_once_their_certificate_verifies() {
    let (server, ca) = Responder::tls(&["a"]);
    let ca = format!("--tls-ca={}", ca.path().display());
    let port = server.addr.port();
    let named = format!("@tls://127.0.0.1:{port}#{TLS_NAME}");
    for args in [
        vec![named.as_str(), &ca],
        vec![&format!("@tls://127.0.0.1:{port}"), &ca],
        vec!["@127.0.0.1", "+tls", "-p", &port.to_string(), &ca],
    ] {
        let out = run(&[&args[..], &["example.com"]].concat(), 0);
        assert!(out.contains("over TLS"), "{out}");
    }
    let other = format!("@tls://127.0.0.1:{port}#other.example");
    dedens()
        .args([&other, &ca, "example.com"])
        .assert()
        .code(10)
        .stderr(contains("TLS handshake failed"));
    run(&[&other, "+tls-insecure", "example.com"], 0);
    let transports: Vec<_> = server.queries().into_iter().map(|(t, _)| t).collect();
    assert_eq!(transports, [Transport::Tls; 4]);
}

#[test]
fn quic_servers_answer_once_their_certificate_verifies() {
    let (server, ca) = Responder::quic(&["a"]);
    let ca = format!("--tls-ca={}", ca.path().display());
    let port = server.addr.port();
    for args in [
        vec![format!("@quic://127.0.0.1:{port}#{TLS_NAME}"), ca.clone()],
        vec![
            "@127.0.0.1".to_owned(),
            "+quic".to_owned(),
            "-p".to_owned(),
            port.to_string(),
            ca.clone(),
        ],
    ] {
        let args: Vec<&str> = args
            .iter()
            .map(String::as_str)
            .chain(["example.com"])
            .collect();
        let out = run(&args, 0);
        assert!(out.contains("over QUIC"), "{out}");
    }
    dedens()
        .args([
            &format!("@quic://127.0.0.1:{port}#other.example"),
            &ca,
            "example.com",
        ])
        .assert()
        .code(10)
        .stderr(contains("QUIC"));
    let transports: Vec<_> = server.queries().into_iter().map(|(t, _)| t).collect();
    assert_eq!(transports, [Transport::Quic; 2]);
}

#[test]
fn no_reply_exits_9_after_the_tries() {
    let server = Responder::start(&[]);
    let started = Instant::now();
    dedens()
        .args([&server.at(), "example.com", "+tries=2", "+time=100ms"])
        .assert()
        .code(9)
        .stderr(contains("example.com_A"));
    assert!(started.elapsed() < Duration::from_secs(5));
    assert_eq!(server.queries().len(), 2);
}

#[test]
fn usage_errors_exit_2() {
    for args in [
        &["--bogus"][..],
        &["+tries=0"],
        &["+cookie=01"],
        &["-x", "example.com"],
        &["+noedns", "+nsid"],
        &["@"],
        &["-f", "queries.yaml", "example.com"],
        &["+nosave-wire"],
        &["--repeat=0", "example.com"],
        &["--json", "--yaml"],
        &["+short", "--format=human"],
        &["--format=xml"],
        &["+t"],
        &["-t", "example.com"],
        &["+trace", "@127.0.0.1", "example.com"],
        &["+trace", "+repeat=2", "example.com"],
        &["+trace", "+search", "example.com"],
    ] {
        dedens().args(args).assert().code(2);
    }
}

#[test]
fn the_port_applies_to_a_server_without_one() {
    let server = Responder::start(&["a"]);
    let port = server.addr.port().to_string();
    for at in ["@127.0.0.1", "@[127.0.0.1]"] {
        run(&[at, "-p", &port, "-q", "example.com", "+short"], 0);
    }
    assert_eq!(server.queries().len(), 2);
}

#[test]
fn zone_transfers_are_refused() {
    dedens()
        .args(["@192.0.2.1", "example.com", "AXFR"])
        .assert()
        .code(10)
        .stderr(contains("zone transfers"));
}

#[test]
fn search_tries_the_resolv_conf_domains() {
    let server = Responder::start(&["cname_chain"]);
    let conf = tempfile::NamedTempFile::new().expect("a file");
    std::fs::write(conf.path(), "nameserver 192.0.2.1\nsearch github.com\n").expect("written");
    let at = server.at();
    dedens()
        .args([&at, "www", "+search", "+short"])
        .env("DEDENS_RESOLV_CONF", conf.path())
        .assert()
        .success()
        .stdout(contains("github.com."));
    dedens()
        .args([&at, "www", "+tries=1", "+time=100ms"])
        .env("DEDENS_RESOLV_CONF", conf.path())
        .assert()
        .code(9);
    let names: Vec<_> = queries(&server)
        .iter()
        .map(|(_, q)| q.questions[0].name.to_string())
        .collect();
    assert_eq!(names, ["www.github.com.", "www."]);
}

#[test]
fn without_a_server_resolv_conf_gives_it() {
    let conf = tempfile::NamedTempFile::new().expect("a file");
    std::fs::write(conf.path(), "search example.com\n").expect("written");
    dedens()
        .arg("example.com")
        .env("DEDENS_RESOLV_CONF", conf.path())
        .assert()
        .code(10)
        .stderr(contains("no server"));
    dedens()
        .arg("example.com")
        .assert()
        .code(10)
        .stderr(contains("/nonexistent/resolv.conf"));
}

#[test]
fn unicode_names_are_asked_as_a_labels() {
    let server = Responder::start(&[]);
    dedens()
        .args([
            &server.at(),
            "Bücher.example",
            "pаypal.example",
            "+tries=1",
            "+time=100ms",
        ])
        .assert()
        .code(9)
        .stderr(contains("pаypal mixes scripts: Latin, Cyrillic"));
    let mut names: Vec<_> = queries(&server)
        .iter()
        .map(|(_, q)| q.questions[0].name.to_string())
        .collect();
    names.sort();
    assert_eq!(names, ["xn--bcher-kva.example.", "xn--pypal-4ve.example."]);
}

#[test]
fn query_files_check_expectations() {
    let server = Responder::start(&["a", "mx", "nxdomain_soa"]);
    let dir = tempfile::tempdir().expect("a directory");
    let file = dir.path().join("queries.yaml");
    let yaml = r"server: SERVER
options: {cookie: false}
queries:
  - name: example.com
    type: A
    expect: {rcode: NOERROR, flags: [qr, ra]}
  - id: mail
    name: gmail.com
    type: MX
    expect:
      answer:
        - gmail.com. 397 MX 5 gmail-smtp-in.l.google.com.
        - gmail.com. MX 10 alt1.gmail-smtp-in.l.google.com.
        - gmail.com. MX 20 alt2.gmail-smtp-in.l.google.com.
        - gmail.com. MX 30 alt3.gmail-smtp-in.l.google.com.
        - gmail.com. MX 40 alt4.gmail-smtp-in.l.google.com.
  - name: nonexistent.invalid
    type: A
    expect: {rcode: NOERROR, flags: [aa], answer: []}
"
    .replace("SERVER", &server.addr.to_string());
    std::fs::write(&file, yaml).expect("written");
    let file = file.to_str().expect("UTF-8");
    dedens()
        .args([
            "-f",
            file,
            "--only",
            "example.com_A",
            "--only",
            "mail",
            "+short",
        ])
        .assert()
        .success();
    dedens()
        .args(["-f", file, "--only", "nonexistent.invalid_A", "+short"])
        .assert()
        .code(1)
        .stderr(contains(
            "nonexistent.invalid_A: rcode NXDOMAIN instead of NOERROR",
        ))
        .stderr(contains("flag aa not set"));
    dedens()
        .args(["-f", file, "--only", "nope"])
        .assert()
        .code(10)
        .stderr(contains("no query with id nope"));
    let json = format!(
        r#"{{"queries": [{{"name": "example.com", "type": "A", "server": "{}"}}]}}"#,
        server.addr
    );
    dedens()
        .args(["-f", "-", "+short"])
        .write_stdin(json)
        .assert()
        .success();
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
fn trace_starts_from_the_roots_without_recursion() {
    let root = Responder::start(&["a"]);
    let out = dedens()
        .args(["+trace", "example.com", "--color=never"])
        .env("DEDENS_ROOTS", root.addr.to_string())
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let out = String::from_utf8(out).expect("UTF-8");
    assert!(out.contains("example.com. A  NOERROR"), "{out}");
    let asked = queries(&root);
    assert_eq!(asked.len(), 1);
    assert!(!asked[0].1.header.flags.contains(Flags::RD));
}

#[test]
fn trace_exits_9_when_no_root_replies() {
    let (first, second) = (Responder::start(&[]), Responder::start(&[]));
    dedens()
        .args(["+trace", "example.com", "+tries=1", "+time=100ms"])
        .env("DEDENS_ROOTS", format!("{},{}", first.addr, second.addr))
        .assert()
        .code(9)
        .stdout("")
        .stderr(contains("example.com_A"));
    assert_eq!((first.queries().len(), second.queries().len()), (1, 1));
}

#[test]
fn query_files_go_to_every_server_given() {
    let (a, nsid) = (Responder::start(&["a"]), Responder::start(&["nsid"]));
    let file = "queries: [{name: example.com, type: A, server: 192.0.2.1}]";
    let out = dedens()
        .args(["-f", "-", "+short", &a.at(), &nsid.at()])
        .write_stdin(file)
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    assert_eq!(String::from_utf8_lossy(&out).lines().count(), 4);
    assert_eq!((a.queries().len(), nsid.queries().len()), (1, 1));
}

#[test]
fn the_capture_file_reads() {
    let text = std::fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../crates/dedens-proto/tests/testdata/capture.yaml"
    ))
    .expect("capture.yaml");
    dedens_scenario::QueryFile::parse(&text).expect("a query file");
}

#[test]
fn save_wire_writes_each_response() {
    let server = Responder::start(&["a"]);
    let dir = tempfile::tempdir().expect("a directory");
    let out = dir.path().join("wire");
    dedens()
        .args([&server.at(), "example.com", "+short", "--save-wire"])
        .arg(&out)
        .assert()
        .success();
    let saved = std::fs::read(out.join("example.com_A.bin")).expect("saved");
    let captured = std::fs::read(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../crates/dedens-proto/tests/testdata/a.bin"
    ))
    .expect("captured");
    assert_eq!(
        saved[2..],
        captured[2..],
        "the response as received, its ID aside"
    );
}

#[test]
fn a_failed_save_leaves_the_other_results() {
    let server = Responder::start(&["a", "mx"]);
    let dir = tempfile::tempdir().expect("a directory");
    // A directory where the first response goes.
    std::fs::create_dir(dir.path().join("example.com_A.bin")).expect("created");
    let out = dedens()
        .args([
            &server.at(),
            "example.com",
            "gmail.com",
            "MX",
            "+short",
            "--save-wire",
        ])
        .arg(dir.path())
        .assert()
        .code(10)
        .stderr(contains("cannot write"))
        .get_output()
        .stdout
        .clone();
    assert_eq!(String::from_utf8_lossy(&out).lines().count(), 5 + 2);
    assert!(dir.path().join("gmail.com_MX.bin").is_file());
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
fn negated_flags_conflict_with_nothing() {
    let server = Responder::start(&["a"]);
    run(&["+notrace", &server.at(), "example.com", "+short"], 0);
    run(&[&server.at(), "example.com", "+nojson", "--yaml"], 0);
    run(
        &[&server.at(), "example.com", "+noshort", "+noyaml", "--json"],
        0,
    );
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
fn save_wire_names_each_server() {
    let (a, nsid) = (Responder::start(&["a"]), Responder::start(&["nsid"]));
    let dir = tempfile::tempdir().expect("a directory");
    dedens()
        .args([&a.at(), &nsid.at(), "example.com", "+short", "--save-wire"])
        .arg(dir.path())
        .assert()
        .success();
    for server in [&a, &nsid] {
        let path = dir
            .path()
            .join(format!("example.com_A@{}.bin", server.addr));
        assert!(path.exists(), "{}", path.display());
    }
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

/// A `+trace` run with `roots` as the root servers.
fn trace(roots: &[&Responder], args: &[&str]) -> assert_cmd::assert::Assert {
    let roots: Vec<String> = roots.iter().map(|root| root.addr.to_string()).collect();
    dedens()
        .args(["+trace", "--color=never"])
        .args(args)
        .env("DEDENS_ROOTS", roots.join(","))
        .assert()
}

#[test]
fn trace_ends_on_nxdomain() {
    let root = Responder::start(&["nxdomain_soa"]);
    trace(&[&root], &["nonexistent.invalid"])
        .success()
        .stdout(contains("NXDOMAIN"));
    assert_eq!(root.queries().len(), 1);
}

#[test]
fn trace_moves_past_a_broken_server() {
    let (failing, answering) = (Responder::start(&["ede"]), Responder::start(&["ede_cd"]));
    trace(&[&failing, &answering], &["dnssec-failed.org"])
        .success()
        .stdout(contains("SERVFAIL").and(contains("NOERROR")));
    assert_eq!((failing.queries().len(), answering.queries().len()), (1, 1));
}

#[test]
fn trace_fails_on_a_response_that_leads_nowhere() {
    // NOERROR without answer, AA, referral or SOA: lame.
    let root = Responder::start(&["truncated"]);
    let out = trace(&[&root], &["google.com", "TXT", "+ignore"])
        .code(10)
        .stderr(contains("neither an answer nor a referral"))
        .get_output()
        .stdout
        .clone();
    assert_eq!(String::from_utf8_lossy(&out).matches("NOERROR").count(), 1);
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
fn a_closed_port_exits_9() {
    let port = std::net::UdpSocket::bind("127.0.0.1:0")
        .and_then(|socket| socket.local_addr())
        .expect("a free port")
        .port();
    dedens()
        .args([
            &format!("@127.0.0.1:{port}"),
            "example.com",
            "+tries=1",
            "+time=2s",
        ])
        .assert()
        .code(9);
}

#[test]
fn reverse_lookups_ask_only_ptr() {
    let server = Responder::start(&[]);
    dedens()
        .args([&server.at(), "-x", "192.0.2.1", "+tries=1", "+time=100ms"])
        .assert()
        .code(9);
    let asked = queries(&server);
    assert_eq!(asked.len(), 1);
    assert_eq!(asked[0].1.questions[0].qtype, dedens_proto::RecordType::PTR);
}

#[test]
fn flags_without_a_value_leave_the_next_word() {
    let server = Responder::start(&["a"]);
    let out = run(
        &[&server.at(), "example.com", "--json", "-v", "+tries=1"],
        0,
    );
    serde_json::from_str::<serde_json::Value>(&out).expect("one JSON object");
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
