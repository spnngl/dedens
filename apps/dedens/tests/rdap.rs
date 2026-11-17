//! `+rdap NAME` (D130): the RDAP server of a domain's TLD found in IANA's bootstrap file (RFC 9224 §4), asked over
//! HTTPS (RFC 7480 §5.2, its redirects followed) about the domain by its name (RFC 9082 §3.1.3), then its parents;
//! its answer read as a domain (RFC 9083 §5.3) with its redacted fields (RFC 9537 §4.2), or a 404. The answers are
//! captured by `just rdap-capture` and served on the loopback.

use crate::util::{Rdap, dedens};

const BOOTSTRAP: &[u8] = include_bytes!("../../../testdata/rdap/dns.json");
const EXAMPLE_COM: &[u8] = include_bytes!("../../../testdata/rdap/example.com.json");
const NO_SUCH_NAME: &[u8] = include_bytes!("../../../testdata/rdap/dedens-no-such-name.com.json");
const BBC_CO_UK: &[u8] = include_bytes!("../../../testdata/rdap/bbc.co.uk.json");
const WWW_BBC_CO_UK: &[u8] = include_bytes!("../../../testdata/rdap/www.bbc.co.uk.json");
const WIKIPEDIA_ORG: &[u8] = include_bytes!("../../../testdata/rdap/wikipedia.org.json");
const WWW_WIKIPEDIA_ORG: &[u8] = include_bytes!("../../../testdata/rdap/www.wikipedia.org.json");

/// Where `DEDENS_RDAP` puts IANA's bootstrap file: its path at `https://data.iana.org`.
const DNS_JSON: &str = "/rdap/dns.json";

// --- RFC 9224 ---

/// RFC 9224 §4 and RFC 9082 §3.1.3: the bootstrap file fetched, then the HTTPS base URL of the TLD's server asked
/// for `domain/<name>`; the registrar, status, name servers, DS records and dates printed (RFC 9083 §5.3).
#[test]
fn s4_a_domain_is_asked_of_its_tld_server() {
    let rdap = Rdap::start(&[
        (DNS_JSON, 200, BOOTSTRAP),
        ("/com/v1/domain/example.com", 200, EXAMPLE_COM),
    ]);
    let out = rdap.run(&["+rdap", "Example.COM.", "--color=never"], 0);
    insta::assert_snapshot!("example_com", out);
    assert_eq!(rdap.paths(), [DNS_JSON, "/com/v1/domain/example.com"]);
    let heads: Vec<_> = rdap
        .heads()
        .iter()
        .map(|head| head.to_ascii_lowercase())
        .collect();
    assert!(
        heads[0].contains("accept: application/json\r\n"),
        "{}",
        heads[0]
    );
    assert!(
        heads[1].contains("accept: application/rdap+json\r\n"),
        "{}",
        heads[1]
    );
}

/// RFC 9224 §4, D130: a name not registered sends the walk a label up, a 404 (Nominet's) or a 400 (Public Interest
/// Registry's), until a name answers; the TLD itself is never asked.
#[test]
fn s4_a_name_not_registered_is_walked_up() {
    let rdap = Rdap::start(&[
        (DNS_JSON, 200, BOOTSTRAP),
        ("/uk/domain/a.www.bbc.co.uk", 404, WWW_BBC_CO_UK),
        ("/uk/domain/www.bbc.co.uk", 404, WWW_BBC_CO_UK),
        ("/uk/domain/bbc.co.uk", 200, BBC_CO_UK),
        ("/rdap/domain/www.wikipedia.org", 400, WWW_WIKIPEDIA_ORG),
        ("/rdap/domain/wikipedia.org", 200, WIKIPEDIA_ORG),
    ]);
    let out = rdap.run(&["+rdap", "a.www.bbc.co.uk", "--color=never"], 0);
    insta::assert_snapshot!("bbc_co_uk", out);
    let out = rdap.run(&["+rdap", "www.wikipedia.org", "--color=never"], 0);
    assert!(out.starts_with("wikipedia.org. domain  "), "{out}");
    assert_eq!(
        rdap.paths(),
        [
            DNS_JSON,
            "/uk/domain/a.www.bbc.co.uk",
            "/uk/domain/www.bbc.co.uk",
            "/uk/domain/bbc.co.uk",
            DNS_JSON,
            "/rdap/domain/www.wikipedia.org",
            "/rdap/domain/wikipedia.org",
        ]
    );
}

/// RFC 9224 §4, RFC 7480 §5.3: a 404 for the shortest name under the TLD is the answer, `not found`, exit 0 (D33);
/// JSON prints its empty body as nothing.
#[test]
fn s4_a_domain_not_found_is_the_last_404() {
    let rdap = Rdap::start(&[
        (DNS_JSON, 200, BOOTSTRAP),
        (
            "/com/v1/domain/www.dedens-no-such-name.com",
            404,
            NO_SUCH_NAME,
        ),
        ("/com/v1/domain/dedens-no-such-name.com", 404, NO_SUCH_NAME),
    ]);
    let out = rdap.run(
        &["+rdap", "www.dedens-no-such-name.com", "--color=never"],
        0,
    );
    assert_eq!(
        out,
        "dedens-no-such-name.com. domain  not found  N ms from https://127.0.0.1:PORT/com/v1/domain/dedens-no-such-name.com (HTTP 404)\n"
    );
    assert_eq!(
        rdap.run(&["+rdap", "dedens-no-such-name.com", "--json"], 0),
        ""
    );
}

/// RFC 9224 §7: a TLD without an entry in the bootstrap file is an error that says so, the bundled TLD list (D126)
/// telling a TLD without RDAP from no TLD; a server only on HTTP is refused (D130). Exit 10 (D33).
#[test]
fn s7_a_tld_without_an_https_server_is_an_error() {
    let rdap = Rdap::start(&[(DNS_JSON, 200, BOOTSTRAP)]);
    for (name, error) in [
        (
            "example.de",
            "example.de: no RDAP server for de in IANA's bootstrap file (RFC 9224 §7): a TLD without RDAP",
        ),
        (
            "example.zzzz",
            "example.zzzz: no RDAP server for zzzz in IANA's bootstrap file (RFC 9224 §7): not a TLD",
        ),
        (
            "example.kg",
            "example.kg: the RDAP server of kg is not on HTTPS (http://rdap.cctld.kg/)",
        ),
    ] {
        rdap.dedens(&["+rdap", name])
            .assert()
            .code(10)
            .stderr(predicates::str::contains(error));
    }
    assert_eq!(rdap.paths(), [DNS_JSON; 3]);
}

/// D130: a bootstrap file that is not one, or not a 200, is an error, exit 10.
#[test]
fn a_bootstrap_file_unread_is_an_error() {
    let rdap = Rdap::start(&[(DNS_JSON, 200, EXAMPLE_COM)]);
    rdap.dedens(&["+rdap", "example.com"])
        .assert()
        .code(10)
        .stderr(predicates::str::contains("not an RDAP bootstrap file"));
    let rdap = Rdap::start(&[]);
    rdap.dedens(&["+rdap", "example.com"])
        .assert()
        .code(10)
        .stderr(predicates::str::contains("/rdap/dns.json: HTTP 500"));
}

// --- RFC 9537 ---

/// RFC 9537 §4.2, §5.1: each redacted field told by its name and method; an empty contact name redacted (§3.2).
#[test]
fn s4_2_redacted_fields_are_shown() {
    let rdap = Rdap::start(&[
        (DNS_JSON, 200, BOOTSTRAP),
        ("/rdap/domain/wikipedia.org", 200, WIKIPEDIA_ORG),
    ]);
    let out = rdap.run(&["+rdap", "wikipedia.org", "--color=never"], 0);
    insta::assert_snapshot!("wikipedia_org", out);
}

// --- RFC 7480 ---

/// RFC 7480 §5.2: a redirect is followed, and the URL printed is the last; a loop is an error, exit 10.
#[test]
fn s5_2_redirects_are_followed() {
    let rdap = Rdap::start(&[
        (DNS_JSON, 200, BOOTSTRAP),
        ("/com/v1/domain/example.com", 301, b"/moved/example.com"),
        ("/moved/example.com", 200, EXAMPLE_COM),
        (
            "/com/v1/domain/example.net",
            302,
            b"/com/v1/domain/example.net",
        ),
    ]);
    let out = rdap.run(&["+rdap", "example.com", "--color=never"], 0);
    assert!(
        out.starts_with("example.com. domain  client delete prohibited, "),
        "{out}"
    );
    assert!(
        out.lines()
            .next()
            .is_some_and(|line| line
                .ends_with(" ms from https://127.0.0.1:PORT/moved/example.com (HTTP 200)")),
        "{out}"
    );
    rdap.dedens(&["+rdap", "example.net"]).assert().code(10);
}

/// RFC 7480 §5.3 and D129: JSON prints the answer as received, YAML the same tree.
#[test]
fn s5_3_json_and_yaml_print_the_answer_as_received() {
    let rdap = Rdap::start(&[
        (DNS_JSON, 200, BOOTSTRAP),
        ("/com/v1/domain/example.com", 200, EXAMPLE_COM),
    ]);
    let json = rdap.run(&["+rdap", "example.com", "--json"], 0);
    assert_eq!(json.trim_end().as_bytes(), EXAMPLE_COM.trim_ascii_end());
    let yaml = rdap.run(&["+rdap", "example.com", "--yaml"], 0);
    assert!(yaml.starts_with("---\n"), "{yaml}");
    assert!(yaml.contains("ldhName: EXAMPLE.COM\n"), "{yaml}");
}

/// RFC 9083 §6: a 400 for the shortest name is an error, explained by the body; exit 10 (D33).
#[test]
fn s6_another_status_for_the_last_name_is_an_error() {
    let rdap = Rdap::start(&[
        (DNS_JSON, 200, BOOTSTRAP),
        ("/rdap/domain/www.wikipedia.org", 400, WWW_WIKIPEDIA_ORG),
        ("/rdap/domain/wikipedia.org", 400, WWW_WIKIPEDIA_ORG),
    ]);
    rdap.dedens(&["+rdap", "www.wikipedia.org"])
        .assert()
        .code(10)
        .stderr(predicates::str::contains("HTTP 400"));
}

/// D33: a refused connection is exit 9, as for DNS; `127.0.0.1:1` is never handed out (D89).
#[test]
fn a_refused_connection_is_exit_9() {
    dedens()
        .env("DEDENS_RDAP", "https://127.0.0.1:1")
        .args(["+rdap", "example.com"])
        .assert()
        .code(9);
}

/// D130: `+rdap` takes a name of two labels at least, and refuses what only applies to DNS queries; exit 2 (D33).
#[test]
fn rdap_refuses_what_applies_to_dns() {
    for args in [
        &["fr"][..],
        &["example.com", "example.org"],
        &["example.com", "+tcp"],
        &["example.com", "+tld", "fr"],
        &["a_b.example"],
    ] {
        dedens()
            .env("DEDENS_RDAP", "https://127.0.0.1:1")
            .arg("+rdap")
            .args(args)
            .assert()
            .code(2);
    }
    dedens()
        .env("DEDENS_RDAP", "https://127.0.0.1:1")
        .args(["+rdap", "fr"])
        .assert()
        .stderr(predicates::str::contains("+tld asks about a TLD"));
    // RFC 1035 §2.3.4: 253 octets is a name to ask about, the server refusing the connection; 254 is none.
    let label = "a".repeat(63);
    let longest = format!("{label}.{label}.{label}.{}.com", &label[..57]);
    assert_eq!(longest.len(), 253);
    let too_long = format!("{label}.{label}.{label}.{}.com", &label[..58]);
    for (name, code) in [(&longest, 9), (&too_long, 2)] {
        dedens()
            .env("DEDENS_RDAP", "https://127.0.0.1:1")
            .args(["+rdap", name])
            .assert()
            .code(code);
    }
}
