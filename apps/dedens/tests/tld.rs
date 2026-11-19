//! `+tld NAME` (D129): IANA's RDAP server asked about a TLD over HTTPS (RFC 7480), by its name in A-labels (RFC 9082
//! §3.1.3), its answer read as a domain (RFC 9083 §5.3) with jCard contacts (RFC 7095), or a 404, from answers
//! captured by `just rdap-capture` and served on the loopback.

use std::net::TcpListener;

use crate::util::{Rdap, STALL, dedens};

const COM: &[u8] = include_bytes!("../../../testdata/rdap/com.json");
const FR: &[u8] = include_bytes!("../../../testdata/rdap/fr.json");
const XN_P1AI: &[u8] = include_bytes!("../../../testdata/rdap/xn--p1ai.json");
const ONION: &[u8] = include_bytes!("../../../testdata/rdap/onion.json");
const ZZZZ: &[u8] = include_bytes!("../../../testdata/rdap/zzzz.json");

/// RFC 7480 §4.2 and RFC 9082 §3.1.3: a GET of `/domain/<label>` accepting RDAP's media type, the TLD's status,
/// contacts, name servers, DS records, dates and own RDAP server printed (RFC 9083 §4.2, §4.5, §4.6, §5.1-5.3).
#[test]
fn s3_1_3_a_tld_answered_is_printed() {
    let rdap = Rdap::start(&[("/domain/fr", 200, FR), ("/domain/com", 200, COM)]);
    let out = rdap.run(&["+tld", "fr", "--color=never"], 0);
    insta::assert_snapshot!("fr", out);
    let com = rdap.run(&["+tld", "com", "--color=never"], 0);
    for line in [
        "  registrant      VeriSign Global Registry Services\n",
        "  a.gtld-servers.net.  192.5.6.30  2001:503:a83e::2:30\n",
        "  https://rdap.verisign.com/com/v1/\n",
    ] {
        assert!(com.contains(line), "{com}");
    }
    let heads = rdap.heads();
    assert_eq!(heads.len(), 2);
    assert!(
        heads[0].starts_with("GET /domain/fr HTTP/1.1\r\n"),
        "{}",
        heads[0]
    );
    assert!(
        heads[0]
            .to_ascii_lowercase()
            .contains("accept: application/rdap+json\r\n"),
        "{}",
        heads[0]
    );
}

/// RFC 9082 §3.1.3: a TLD in U-labels is asked in A-labels; any case, with or without its trailing dot.
#[test]
fn s3_1_3_a_tld_is_asked_in_a_labels() {
    let rdap = Rdap::start(&[("/domain/xn--p1ai", 200, XN_P1AI)]);
    for name in ["рф", "XN--P1AI."] {
        let out = rdap.run(&["+tld", name, "--color=never"], 0);
        assert!(out.starts_with("xn--p1ai. TLD  active  N ms from https://127.0.0.1:PORT/domain/xn--p1ai (HTTP 200)\n"), "{out}");
    }
}

/// D129: `--json` prints the answer as received, `--yaml` the same tree.
#[test]
fn s5_3_json_and_yaml_print_the_answer_as_received() {
    let rdap = Rdap::start(&[("/domain/fr", 200, FR)]);
    let json = rdap.run(&["+tld", "fr", "--json"], 0);
    assert!(json.ends_with("}\n"), "{json}");
    let received: serde_json::Value = serde_json::from_slice(FR).expect("JSON");
    let printed: serde_json::Value = serde_json::from_str(&json).expect("JSON");
    assert_eq!(printed, received);
    let yaml = rdap.run(&["+tld", "fr", "--yaml"], 0);
    let printed: serde_json::Value = serde_saphyr::from_str(&yaml).expect("YAML");
    assert_eq!(printed, received);
}

/// RFC 7480 §5.3: a 404 is an answer, exit 0; the TLD list bundled tells a special-use name's purpose (D126) and
/// that another is no TLD.
#[test]
fn s5_3_a_tld_not_found_is_explained_by_the_tld_list() {
    let rdap = Rdap::start(&[("/domain/onion", 404, ONION), ("/domain/zzzz", 404, ZZZZ)]);
    let onion = rdap.run(&["+tld", "onion", "--color=never"], 0);
    insta::assert_snapshot!("onion", onion);
    let zzzz = rdap.run(&["+tld", "zzzz", "--color=never"], 0);
    insta::assert_snapshot!("zzzz", zzzz);
}

/// RFC 9083 §6: another status is an error, explained by the body's title and description; exit 10 (D33).
#[test]
fn s6_another_status_is_an_error() {
    const UNAVAILABLE: &[u8] =
        br#"{"errorCode":503,"title":"Unavailable","description":["Try later"]}"#;
    let rdap = Rdap::start(&[
        ("/domain/fr", 503, UNAVAILABLE),
        ("/domain/com", 200, b"{}"),
    ]);
    rdap.dedens(&["+tld", "fr"])
        .assert()
        .code(10)
        .stderr(predicates::str::contains(
            "HTTP 503: Unavailable: Try later",
        ));
    // RFC 9083 §4.9: a body that is no domain object.
    rdap.dedens(&["+tld", "com"])
        .assert()
        .code(10)
        .stderr(predicates::str::contains("not an RDAP domain"));
}

/// D33: a server whose certificate does not verify is an error, exit 10, not one that does not answer.
#[test]
fn an_untrusted_server_is_exit_10() {
    let rdap = Rdap::start(&[("/domain/fr", 200, FR)]);
    dedens()
        .env("DEDENS_RDAP", rdap.origin())
        .args(["+tld", "fr"])
        .assert()
        .code(10);
    assert_eq!(rdap.heads(), Vec::<String>::new());
}

/// `--tls-insecure` accepts any certificate, as for DNS over TLS (D60).
#[test]
fn tls_insecure_accepts_any_certificate() {
    let rdap = Rdap::start(&[("/domain/fr", 200, FR)]);
    dedens()
        .env("DEDENS_RDAP", rdap.origin())
        .args(["+tld", "fr", "--tls-insecure"])
        .assert()
        .success();
}

/// D33: a refused connection is exit 9, as for DNS; `127.0.0.1:1` is never handed out (D89).
#[test]
fn a_refused_connection_is_exit_9() {
    dedens()
        .env("DEDENS_RDAP", "https://127.0.0.1:1")
        .args(["+tld", "fr"])
        .assert()
        .code(9);
}

/// D33: a server that does not answer is exit 9, as for DNS.
#[test]
fn a_silent_server_is_exit_9() {
    let listener = TcpListener::bind("127.0.0.1:0").expect("a port");
    let port = listener.local_addr().expect("an address").port();
    dedens()
        .env("DEDENS_RDAP", format!("https://127.0.0.1:{port}"))
        .args(["+tld", "fr", "+time=1"])
        .assert()
        .code(9)
        .stderr(predicates::str::contains("dedens: fr: "));
    drop(listener);
}

/// D33, D129: a server that falls silent inside its answer is exit 9 too: `+time` bounds the whole exchange.
#[test]
fn a_server_silent_inside_its_answer_is_exit_9() {
    let rdap = Rdap::start(&[("/domain/fr", STALL, b"")]);
    rdap.dedens(&["+tld", "fr", "+time=1"])
        .assert()
        .code(9)
        .stderr(predicates::str::contains("dedens: fr: "));
}

/// D129: `+tld` takes one label, and refuses what only applies to DNS queries; exit 2 (D33).
#[test]
fn tld_refuses_what_applies_to_dns() {
    for args in [
        &["example.com"][..],
        &["@127.0.0.1"],
        &["-p", "53"],
        &["-x", "192.0.2.1"],
        &["-f", "queries.txt"],
        &["--save-wire", "wire"],
        &["+repeat=2"],
        &["+trace"],
        &["+search"],
        &["--short"],
        &["+tcp"],
    ] {
        dedens()
            .env("DEDENS_RDAP", "https://127.0.0.1:1")
            .args(["+tld", "fr"])
            .args(args)
            .assert()
            .code(2)
            .stderr(predicates::str::contains("+tld and +rdap go with no name"));
    }
    let long = "a".repeat(64);
    for name in ["example.fr", ".", &long] {
        dedens()
            .env("DEDENS_RDAP", "https://127.0.0.1:1")
            .args(["+tld", name])
            .assert()
            .code(2);
    }
    // RFC 1035 §2.3.4: a label of 63 octets is a TLD to ask about; the server knows no such path, 500.
    let rdap = Rdap::start(&[]);
    rdap.dedens(&["+tld", &long[1..]]).assert().code(10);
    assert_eq!(rdap.heads().len(), 1);
}
