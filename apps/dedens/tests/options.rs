//! The options of a query and how the arguments read: the query flags, the usage errors, search domains and
//! resolv.conf, ports and addresses, Unicode names asked as A-labels (RFC 5891 §5, D18) after the mapping of
//! RFC 5895 §2 (`Bücher` lowercased first), reverse lookups.

use std::time::Duration;

use dedens_proto::Flags;
use dedens_proto::edns::{EdnsFlags, EdnsOption, OptionCode};
use dedens_testkit::responder::{Responder, Transport};
use predicates::str::contains;

use crate::util::{dedens, queries, run};

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
        &["+trace", "+tls", "example.com"],
        &["+trace", "+quic", "example.com"],
        &["+tls", "+noedns", "example.com"],
        &["@quic://127.0.0.1", "+noedns", "example.com"],
        &["+https", "+tcp", "example.com"],
        &["+https", "+tls", "example.com"],
        &["+https", "+quic", "example.com"],
        &["+https", "+noedns", "example.com"],
        &["+https-post", "+noedns", "example.com"],
        &["+https", "+trace", "example.com"],
        &["+https-get", "+https-post", "example.com"],
        &["+https=dns-query", "example.com"],
        &["@https://127.0.0.1", "+tls", "example.com"],
        &["@https://127.0.0.1", "+noedns", "example.com"],
        &["+coap", "+tcp", "example.com"],
        &["+coap", "+tls", "example.com"],
        &["+coap", "+quic", "example.com"],
        &["+coap", "+https", "example.com"],
        &["+coap", "+trace", "example.com"],
        &["@coap://127.0.0.1", "+tcp", "example.com"],
        &["@coap://127.0.0.1", "+quic", "example.com"],
        &["@coap://127.0.0.1", "+https", "example.com"],
        &["+coap", "@https://127.0.0.1", "example.com"],
        &["+doc-discover", "example.com"],
        &["+doc-discover", "@127.0.0.1", "example.com"],
        &[
            "+doc-discover",
            "@coap://127.0.0.1/dns/query",
            "example.com",
        ],
    ] {
        dedens().args(args).assert().code(2);
    }
}

/// An IPv6 address in brackets, with a port, is a server over UDP: no name for TLS to make of it.
#[test]
fn a_bracketed_ipv6_address_with_its_port_is_asked() {
    let server = std::net::UdpSocket::bind("[::1]:0").expect("an IPv6 loopback port");
    server
        .set_read_timeout(Some(Duration::from_secs(5)))
        .expect("a timeout");
    let port = server.local_addr().expect("bound").port();
    dedens()
        .args([&format!("@[::1]:{port}"), "example.com"])
        .args(["+tries=1", "+time=100ms"])
        .assert()
        .code(9);
    server.recv_from(&mut [0; 512]).expect("the query");
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
