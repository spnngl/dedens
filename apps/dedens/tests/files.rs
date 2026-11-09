//! The files of a run: query files and their expectations, the capture file, `--save-wire`.

use dedens_testkit::captured;
use dedens_testkit::certificates::NAME;
use dedens_testkit::responder::Responder;
use predicates::str::contains;

use crate::util::dedens;

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
    let text =
        std::fs::read_to_string(dedens_testkit::path("proto/capture.yaml")).expect("capture.yaml");
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
    assert_eq!(
        saved[2..],
        captured("a")[2..],
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

/// A command-line server is reached over the transport of the query's options: with `tls: true` in the file, the
/// certificate must hold the name after `#`, which only TLS takes.
#[test]
fn file_options_choose_the_transport_of_command_line_servers() {
    let (server, ca) = Responder::tls(&["a"]);
    let ca = format!("--tls-ca={}", ca.path().display());
    let port = server.addr.port();
    let file = "options: {tls: true}\nqueries: [{name: example.com, type: A}]";
    let ask = |name: &str| {
        dedens()
            .args(["-f", "-", &format!("@127.0.0.1:{port}#{name}"), &ca])
            .write_stdin(file)
            .assert()
    };
    ask(NAME).success().stdout(contains("over TLS"));
    ask("other.example")
        .code(10)
        .stderr(contains("TLS handshake failed"));
}

/// A query file's server is refused what the command line refuses: no `noedns` over TLS, QUIC or HTTPS, which pad
/// their queries with EDNS (RFC 8467 §4.1), and HTTPS over nothing but QUIC.
#[test]
fn a_file_server_is_refused_the_transports_its_scheme_excludes() {
    for (server, options) in [
        ("tls://192.0.2.1", "{edns: false}"),
        ("quic://192.0.2.1", "{edns: false}"),
        ("https://192.0.2.1", "{edns: false}"),
        ("https://192.0.2.1", "{tcp: true}"),
    ] {
        let file = format!(
            "server: {server}\noptions: {options}\nqueries: [{{name: example.com, type: A}}]"
        );
        dedens()
            .args(["-f", "-", "+tries=1", "+time=100ms"])
            .write_stdin(file)
            .assert()
            .code(10)
            .stderr(contains(format!("server {server}")));
    }
}

/// `--save-wire` never writes two responses to one file: two lookups with one id are refused before any query
/// (D177), and two `DoH` servers at one address, apart by their path, have their own ids.
#[test]
fn save_wire_never_overwrites_a_response() {
    let server = Responder::start(&["a"]);
    dedens()
        .args([&server.at(), "example.com", "example.com"])
        .assert()
        .code(10)
        .stderr(contains("two queries with id example.com_A"));
    assert_eq!(server.queries().len(), 0);
    let (https, ca) = Responder::https(&["a"]);
    let ca = format!("--tls-ca={}", ca.path().display());
    let port = https.addr.port();
    let dir = tempfile::tempdir().expect("a directory");
    dedens()
        .args([
            &format!("@https://127.0.0.1:{port}/a#{NAME}"),
            &format!("@https://127.0.0.1:{port}/b#{NAME}"),
            &ca,
            "example.com",
            "+short",
            "--save-wire",
        ])
        .arg(dir.path())
        .assert()
        .success();
    for path in ["a", "b"] {
        let file = format!("example.com_A@127.0.0.1:{port}+https_{path}.bin");
        assert!(dir.path().join(&file).is_file(), "{file}");
    }
}
