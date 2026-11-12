//! The transports a server is asked over, against loopback servers with test certificates: UDP and TCP,
//! TLS (RFC 7858, RFC 8310 §6.6 and §8.1), QUIC (RFC 9250), HTTPS over HTTP/3 (RFC 8484, D83) and CoAP (RFC 9953,
//! D81, D95), their server ids (D38), and the exits when no server replies.

use std::time::{Duration, Instant};

use dedens_testkit::certificates::NAME;
use dedens_testkit::responder::{Responder, Transport};
use predicates::prelude::*;
use predicates::str::contains;

use crate::util::{dedens, queries, redact, run};

/// A port is reused as soon as its socket closes, so a server may get what was meant for the socket before it: the
/// packets a QUIC server of another test keeps sending to the port of a client that has exited. Captured, from the
/// log of a server that held such a port.
#[test]
fn a_datagram_that_is_no_query_is_not_a_query_received() {
    const STRAY: [u8; 42] = [
        0x0f, 0x6f, 0x78, 0x67, 0xe6, 0xf3, 0xbb, 0x40, 0x73, 0xc0, 0x09, 0x45, 0x73, 0x3d, 0xac,
        0xcf, 0x29, 0x4a, 0x64, 0x4b, 0x20, 0x1b, 0xe7, 0xf1, 0x79, 0xcb, 0x6e, 0xdf, 0x6e, 0x26,
        0xcc, 0x22, 0x09, 0xf3, 0xef, 0xad, 0x08, 0xc9, 0xd9, 0xe0, 0x52, 0xb8,
    ];
    let server = Responder::start(&["a"]);
    std::net::UdpSocket::bind("127.0.0.1:0")
        .and_then(|socket| socket.send_to(&STRAY, server.addr))
        .expect("sent");
    // The server reads in order: the stray is behind it once this query is answered.
    run(&[&server.at(), "example.com"], 0);
    assert_eq!(queries(&server).len(), 1);
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
    let named = format!("@tls://127.0.0.1:{port}#{NAME}");
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
        vec![format!("@quic://127.0.0.1:{port}#{NAME}"), ca.clone()],
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

/// D83: DNS over HTTPS goes over HTTP/3, by GET unless `+https-post`, on the path given by the URL, else by
/// `+https`, else `/dns-query`; the certificate must hold the host name or the `#NAME`.
#[test]
fn https_servers_answer_once_their_certificate_verifies() {
    let (server, ca) = Responder::https(&["a"]);
    let ca = format!("--tls-ca={}", ca.path().display());
    let port = server.addr.port();
    let sets: [(Vec<String>, Transport); 5] = [
        (
            vec![format!("@https://127.0.0.1:{port}#{NAME}"), ca.clone()],
            Transport::HttpsGet,
        ),
        (
            vec![
                format!("@https://127.0.0.1:{port}/other/path#{NAME}"),
                ca.clone(),
            ],
            Transport::HttpsGet,
        ),
        (
            vec![
                "@127.0.0.1".to_owned(),
                "+https=/dns".to_owned(),
                "-p".to_owned(),
                port.to_string(),
                ca.clone(),
            ],
            Transport::HttpsGet,
        ),
        (
            vec![
                "@127.0.0.1".to_owned(),
                "+https-get".to_owned(),
                format!("--port={port}"),
                ca.clone(),
            ],
            Transport::HttpsGet,
        ),
        (
            vec![
                "@127.0.0.1".to_owned(),
                "+https-post".to_owned(),
                format!("--port={port}"),
                ca.clone(),
            ],
            Transport::HttpsPost,
        ),
    ];
    for (args, _) in &sets {
        let args: Vec<&str> = args
            .iter()
            .map(String::as_str)
            .chain(["example.com"])
            .collect();
        let out = run(&args, 0);
        assert!(out.contains("over DoH (HTTP/3 200)"), "{out}");
    }
    dedens()
        .args([
            &format!("@https://127.0.0.1:{port}#other.example"),
            &ca,
            "example.com",
        ])
        .assert()
        .code(10)
        .stderr(contains("QUIC"));
    let transports: Vec<_> = server.queries().into_iter().map(|(t, _)| t).collect();
    let expected: Vec<_> = sets.iter().map(|(_, transport)| *transport).collect();
    assert_eq!(transports, expected);
    for (_, query) in queries(&server) {
        assert_eq!(query.header.id, 0);
    }
}

/// D83: `+https` in each format: the HTTP version and status come with the exchange.
#[test]
fn https_output_in_each_format() {
    let (server, ca) = Responder::https(&["a"]);
    let ca = format!("--tls-ca={}", ca.path().display());
    let at = format!("@https://127.0.0.1:{}#{NAME}", server.addr.port());
    for (name, flag) in [
        ("https_human", "--format=human"),
        ("https_json", "--json"),
        ("https_yaml", "--yaml"),
        ("https_short", "--short"),
    ] {
        let out = run(&[&at, &ca, "example.com", flag], 0);
        insta::assert_snapshot!(name, redact(&out, server.addr.port()));
    }
}

/// D81: DNS over CoAP goes by FETCH with the DNS ID 0, to the path of the URL, by `+coap` to the root; an answer's
/// TTLs are its Max-Age added back.
#[cfg(feature = "doc")]
#[test]
fn coap_servers_answer_by_fetch_at_the_path_given() {
    let server = Responder::coap(&["a"], "/dns/query");
    let port = server.addr.port();
    let out = run(
        &[
            &format!("@coap://127.0.0.1:{port}/dns/query"),
            "example.com",
        ],
        0,
    );
    assert!(out.contains("over CoAP") && out.contains("29s"), "{out}");
    // No path is the root: the server of /dns/query has no such resource.
    dedens()
        .args([&format!("@coap://127.0.0.1:{port}"), "example.com"])
        .assert()
        .code(10)
        .stderr(contains("4.04"));
    dedens()
        .args([
            "@127.0.0.1",
            "+coap",
            &format!("--port={port}"),
            "example.com",
        ])
        .assert()
        .code(10)
        .stderr(contains("4.04"));
    let transports: Vec<_> = server.queries().into_iter().map(|(t, _)| t).collect();
    assert_eq!(transports, [Transport::Coap]);
    for (_, query) in queries(&server) {
        assert_eq!(query.header.id, 0);
    }
}

/// D81: `+coap` to the root path, `coap://` with no port to 5683, and the report of each format.
#[cfg(feature = "doc")]
#[test]
fn coap_output_in_each_format() {
    let server = Responder::coap(&["a"], "/");
    let port = server.addr.port();
    let at = format!("@coap://127.0.0.1:{port}");
    for (name, flag) in [
        ("coap_human", "--format=human"),
        ("coap_json", "--json"),
        ("coap_yaml", "--yaml"),
        ("coap_short", "--short"),
    ] {
        let out = run(&[&at, "example.com", flag], 0);
        insta::assert_snapshot!(name, redact(&out, port));
    }
    let out = run(
        &["@127.0.0.1", "+coap", &format!("-p{port}"), "example.com"],
        0,
    );
    assert!(out.contains("over CoAP"), "{out}");
}

/// D81: `-v` shows the CoAP exchange: the code, the Max-Age and the blocks.
#[cfg(feature = "doc")]
#[test]
fn coap_verbose_shows_the_response_code_and_max_age() {
    let server = Responder::coap(&["a"], "/");
    dedens()
        .args([
            &format!("@coap://127.0.0.1:{}", server.addr.port()),
            "example.com",
            "+short",
            "-v",
        ])
        .assert()
        .success()
        .stderr(contains("2.05").and(contains("max_age")));
}

/// D81: a response in blocks is put together.
#[cfg(feature = "doc")]
#[test]
fn coap_responses_in_blocks_are_put_together() {
    let server = Responder::coap(&["txt_large"], "/");
    let out = run(
        &[
            &format!("@coap://127.0.0.1:{}", server.addr.port()),
            "google.com",
            "TXT",
            "+noedns",
            "--color=never",
        ],
        0,
    );
    assert!(out.contains("over CoAP"), "{out}");
    assert_eq!(server.queries().len(), 2);
}

/// D95: `+doc-discover` asks the server for its resource and queries the path it lists, which the report says; no
/// path to discover, or a server that lists none, is an error.
#[cfg(feature = "doc")]
#[test]
fn coap_doc_discover_queries_the_path_the_server_lists() {
    let server = Responder::coap(&["a"], "/dns/query");
    let port = server.addr.port();
    let at = format!("@coap://127.0.0.1:{port}");
    let out = run(&[&at, "+doc-discover", "example.com"], 0);
    assert!(
        out.contains("over CoAP") && out.contains("discovered /dns/query"),
        "{out}"
    );
    let out = run(&[&at, "+doc-discover", "example.com", "--json"], 0);
    assert!(out.contains(r#""doc_path":"/dns/query""#), "{out}");
    let out = run(
        &[
            "@127.0.0.1",
            "+coap",
            "+doc-discover",
            &format!("--port={port}"),
            "example.com",
        ],
        0,
    );
    assert!(out.contains("discovered /dns/query"), "{out}");
    assert_eq!(server.queries().len(), 3);
}

/// D95: a discovery that fails is an error naming `+doc-discover`, not a query to the root. A server written with
/// the root path, `/` (RFC 7252 §6.4), has no path either: it is asked.
#[cfg(feature = "doc")]
#[test]
fn coap_doc_discover_that_fails_is_an_error() {
    // A closed port: no answer to the discovery.
    for server in ["@coap://127.0.0.1:1", "@coap://127.0.0.1:1/"] {
        dedens()
            .args([server, "+doc-discover", "example.com"])
            .args(["+tries=1", "+time=100ms"])
            .assert()
            .code(9)
            .stderr(contains("+doc-discover"));
    }
}

/// D95: a query file names its own servers, so the run checks that `+doc-discover` has a CoAP one with no path: a server
/// over another transport, or a CoAP one with a path of its own, is not asked for its resource.
#[cfg(feature = "doc")]
#[test]
fn coap_doc_discover_in_a_query_file_needs_a_coap_server_with_no_path() {
    let (udp, coap) = (
        Responder::start(&["a"]),
        Responder::coap(&["a"], "/dns/query"),
    );
    let port = coap.addr.port();
    for server in [
        udp.addr.to_string(),
        format!("coap://127.0.0.1:{port}/dns/query"),
    ] {
        let file = format!(
            "server: {server}\noptions: {{doc_discover: true}}\nqueries: [{{name: example.com, type: A}}]"
        );
        dedens()
            .args(["-f", "-", "+short"])
            .write_stdin(file)
            .assert()
            .failure()
            .stderr(contains("+doc-discover needs a CoAP server with no path"));
    }
    assert!(udp.queries().is_empty() && coap.queries().is_empty());
}

/// D81: CoAP is a server of its own, with its id.
#[cfg(feature = "doc")]
#[test]
fn coap_servers_have_their_own_ids() {
    dedens()
        .args(["@127.0.0.1:1", "@coap://127.0.0.1:1", "example.com"])
        .args(["+tries=1", "+time=100ms"])
        .assert()
        .code(9)
        .stderr(contains("example.com_A@127.0.0.1:1+coap:"));
}

/// D38, D83: `https://` to one address is a server of its own, with its id.
#[test]
fn https_servers_have_their_own_ids() {
    dedens()
        .args(["@quic://127.0.0.1:1", "@https://127.0.0.1:1", "example.com"])
        .args(["+tries=1", "+time=100ms"])
        .assert()
        .code(9)
        .stderr(
            contains("example.com_A@127.0.0.1:1+quic:")
                .and(contains("example.com_A@127.0.0.1:1+https:")),
        );
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

/// D38: `tls://` and `quic://` to one address are two servers, each with its id.
#[test]
fn tls_and_quic_to_one_address_have_their_own_ids() {
    dedens()
        .args(["@tls://127.0.0.1:1", "@quic://127.0.0.1:1", "example.com"])
        .args(["+tries=1", "+time=100ms"])
        .assert()
        .code(9)
        .stderr(
            contains("example.com_A@127.0.0.1:1+tls:")
                .and(contains("example.com_A@127.0.0.1:1+quic:")),
        );
}

#[test]
fn a_ca_file_without_a_certificate_is_refused() {
    let empty = tempfile::NamedTempFile::new().expect("a file");
    dedens()
        .arg(format!("--tls-ca={}", empty.path().display()))
        .args(["@tls://127.0.0.1:1", "example.com"])
        .assert()
        .code(10)
        .stderr(contains(format!(
            "no certificate in {}",
            empty.path().display()
        )));
}

#[test]
fn a_closed_port_exits_9() {
    // Port 1, not a port just closed: that one is any test's to take, and its server would answer.
    dedens()
        .args(["@127.0.0.1:1", "example.com", "+tries=1", "+time=2s"])
        .assert()
        .code(9);
}
