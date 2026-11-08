//! `+odoh-proxy` (D79): Oblivious `DoH` (RFC 9230) over HTTP/3 against a loopback target that is its own proxy, and
//! the usage errors.
#![cfg(feature = "odoh")]

#[allow(
    dead_code,
    reason = "shared with the other tests of the command, which use all of it"
)]
mod common;

use std::io::Write as _;

use assert_cmd::Command;
use common::{Responder, TLS_NAME, Transport};
use dedens_odoh::{Configs, TargetKey};
use dedens_proto::Message;
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

/// RFC 9230 §4, D79: through a proxy to a target, the query is opened by the target with ID 0, the answer comes back
/// sealed, and the transport reads `ODoH`; with `--json` too.
#[test]
fn a_query_goes_through_a_proxy_to_a_target() {
    let (server, ca) = Responder::oblivious(&["a"], TargetKey::derive(&[7; 32]));
    let ca = format!("--tls-ca={}", ca.path().display());
    let port = server.addr.port();
    let target = format!("@https://127.0.0.1:{port}#{TLS_NAME}");
    let proxy = format!("+odoh-proxy=https://127.0.0.1:{port}#{TLS_NAME}");
    let out = run(&[&target, &proxy, &ca, "example.com"], 0);
    assert!(out.contains("over ODoH (HTTP/3 200)"), "{out}");
    let out = run(&[&target, &proxy, &ca, "example.com", "--json"], 0);
    assert!(out.contains("\"transport\":\"odoh\""), "{out}");
    let queries = server.queries();
    assert_eq!(queries.len(), 2);
    for (transport, query) in queries {
        assert_eq!(transport, Transport::Oblivious);
        assert_eq!(
            Message::decode(&query).expect("a query").message.header.id,
            0
        );
    }
}

/// D79: the target must be an `https://` server, and the proxy goes with no other transport.
#[test]
fn odoh_usage_errors_exit_2() {
    let proxy = "+odoh-proxy=https://127.0.0.1:1";
    for args in [
        &[proxy, "example.com"][..],
        &[proxy, "@127.0.0.1", "example.com"],
        &[proxy, "@tls://127.0.0.1", "example.com"],
        &[proxy, "@https://127.0.0.1", "+tcp", "example.com"],
        &[proxy, "@https://127.0.0.1", "+tls", "example.com"],
        &[proxy, "@https://127.0.0.1", "+quic", "example.com"],
        &[proxy, "@https://127.0.0.1", "+https-get", "example.com"],
        &[proxy, "@https://127.0.0.1", "+trace", "example.com"],
    ] {
        dedens().args(args).assert().code(2);
    }
}

/// D79: `+odoh-config=FILE` gives the target's key configurations, which are then not fetched: the right ones work,
/// those of another key are a 401, which is no reason to fetch them either; the option needs `+odoh-proxy`.
#[test]
fn odoh_config_gives_the_configurations() {
    let (server, ca) = Responder::oblivious(&["a"], TargetKey::derive(&[7; 32]));
    let ca = format!("--tls-ca={}", ca.path().display());
    let port = server.addr.port();
    let target = format!("@https://127.0.0.1:{port}#{TLS_NAME}");
    let proxy = format!("+odoh-proxy=https://127.0.0.1:{port}#{TLS_NAME}");
    let configs = |seed: u8| {
        let mut file = tempfile::NamedTempFile::new().expect("a file");
        let key = TargetKey::derive(&[seed; 32]);
        let encoded = Configs::new(vec![key.config().clone()])
            .encode()
            .expect("configurations encode");
        file.write_all(&encoded).expect("written");
        file
    };
    let right = configs(7);
    let given = format!("+odoh-config={}", right.path().display());
    let out = run(&[&target, &proxy, &given, &ca, "example.com"], 0);
    assert!(out.contains("over ODoH (HTTP/3 200)"), "{out}");
    let wrong = configs(8);
    let given = format!("+odoh-config={}", wrong.path().display());
    dedens()
        .args([&target, &proxy, &given, &ca])
        .arg("example.com")
        .assert()
        .failure()
        .stderr(contains("401"));
    dedens()
        .args(["+odoh-config=/nonexistent/odoh.configs", "example.com"])
        .assert()
        .code(2);
}

/// D79: a proxy that is no `https://` URI is refused.
#[test]
fn a_proxy_must_be_an_https_uri() {
    dedens()
        .args(["+odoh-proxy=127.0.0.1", "@https://127.0.0.1", "example.com"])
        .assert()
        .failure()
        .stderr(contains("not an https:// URI"));
}
