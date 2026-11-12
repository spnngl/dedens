//! `+odoh-proxy` (D79): Oblivious `DoH` (RFC 9230) over HTTP/3 against a loopback target that is its own proxy, and
//! the usage errors.

use std::io::Write as _;
use std::time::Duration;

use dedens_odoh::{Configs, TargetKey};
use dedens_proto::Message;
use dedens_testkit::certificates::NAME;
use dedens_testkit::responder::{Responder, Transport};
use predicates::str::contains;

use crate::util::{dedens, run};

/// RFC 9230 §4, D79: through a proxy to a target, the query is opened by the target with ID 0, the answer comes back
/// sealed, and the transport reads `ODoH`; with `--json` too.
#[test]
fn a_query_goes_through_a_proxy_to_a_target() {
    let (server, ca) = Responder::oblivious(&["a"], TargetKey::derive(&[7; 32]));
    let ca = format!("--tls-ca={}", ca.path().display());
    let port = server.addr.port();
    let target = format!("@https://127.0.0.1:{port}#{NAME}");
    let proxy = format!("+odoh-proxy=https://127.0.0.1:{port}#{NAME}");
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
    let target = format!("@https://127.0.0.1:{port}#{NAME}");
    let proxy = format!("+odoh-proxy=https://127.0.0.1:{port}#{NAME}");
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

/// D79: a `+odoh-config` file is read once per run, not again for each query of `--repeat`: a named pipe written
/// once gives its bytes to one read, and a second would wait for a writer that never comes.
#[cfg(unix)]
#[test]
fn odoh_config_is_read_once_per_run() {
    let (server, ca) = Responder::oblivious(&["a"], TargetKey::derive(&[7; 32]));
    let ca = format!("--tls-ca={}", ca.path().display());
    let port = server.addr.port();
    let target = format!("@https://127.0.0.1:{port}#{NAME}");
    let proxy = format!("+odoh-proxy=https://127.0.0.1:{port}#{NAME}");
    let dir = tempfile::tempdir().expect("a directory");
    let pipe = dir.path().join("configs");
    let made = std::process::Command::new("mkfifo")
        .arg(&pipe)
        .status()
        .expect("mkfifo runs");
    assert!(made.success(), "mkfifo: {made}");
    let encoded = Configs::new(vec![TargetKey::derive(&[7; 32]).config().clone()])
        .encode()
        .expect("configurations encode");
    // Opening the pipe waits for the reader: the thread ends once dedens has read it.
    let writer = std::thread::spawn({
        let pipe = pipe.clone();
        move || std::fs::write(pipe, encoded)
    });
    let given = format!("+odoh-config={}", pipe.display());
    dedens()
        .args([&target, &proxy, &given, &ca, "+repeat=3", "example.com"])
        .timeout(Duration::from_secs(10))
        .assert()
        .code(0);
    writer
        .join()
        .expect("the writer does not panic")
        .expect("written");
    assert_eq!(server.queries().len(), 3);
}

/// D33, D79: a `+odoh-config` file that cannot be read, or holds no `ObliviousDoHConfigs` (RFC 9230 §6), is a usage
/// error found before any query, `--repeat` or not, and in a query file too: nothing reaches the target.
#[test]
fn a_bad_odoh_config_is_a_usage_error_before_any_query() {
    let (server, ca) = Responder::oblivious(&["a"], TargetKey::derive(&[7; 32]));
    let ca = format!("--tls-ca={}", ca.path().display());
    let port = server.addr.port();
    let target = format!("https://127.0.0.1:{port}#{NAME}");
    let proxy = format!("https://127.0.0.1:{port}#{NAME}");
    // A captured DNS query: real bytes, and no configurations.
    let query = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../testdata/doh/quad9_mx.query"
    );
    for (file, error) in [
        ("/nonexistent/odoh.configs", "cannot read the file"),
        (query, "not key configurations"),
    ] {
        let message = format!("+odoh-config {file}: {error}");
        let at = format!("@{target}");
        let given = [
            format!("+odoh-proxy={proxy}"),
            format!("+odoh-config={file}"),
        ];
        for repeat in ["+repeat=1", "+repeat=3"] {
            dedens()
                .args([&at, &ca, repeat, "example.com"])
                .args(&given)
                .assert()
                .code(2)
                .stderr(contains(&message));
        }
        let queries = format!(
            "server: {target}\noptions: {{odoh_proxy: '{proxy}', odoh_config: '{file}'}}\n\
             queries: [{{name: example.com, type: A}}]"
        );
        dedens()
            .args(["-f", "-", &ca])
            .write_stdin(queries)
            .assert()
            .code(2)
            .stderr(contains(&message));
    }
    assert_eq!(server.queries().len(), 0, "no query reaches the target");
}

/// D33, D79: a proxy that never answers is no reply, as a `DoH` server that never answers is: exit 9.
#[test]
fn a_silent_proxy_exits_9() {
    dedens()
        .args(["@https://127.0.0.1:1", "+odoh-proxy=https://127.0.0.1:1"])
        .args(["+tries=1", "+time=100ms", "example.com"])
        .assert()
        .code(9)
        .stderr(contains("example.com_A:"));
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
