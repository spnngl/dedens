//! Zone transfers (RFC 5936 §2, RFC 1995 §4) and TSIG (RFC 8945 §5) from the command line (D212): `AXFR` and
//! `IXFR=SERIAL` against a primary on the loopback address that replays the captures of D203, signed streams
//! re-signed by `dedens-tsig` for the query it reads (as `dedens-net`'s tests do), and a signed query of any type.

use std::io::{Read as _, Write as _};
use std::net::{Shutdown, SocketAddr, TcpListener, UdpSocket};
use std::thread;
use std::time::{SystemTime, UNIX_EPOCH};

use dedens_net::tcp::frame;
use dedens_proto::{Message, find_tsig};
use dedens_testkit::authoritative::{Peer, Recording, TSIG_KEY, Transport};
use dedens_testkit::dns;
use dedens_tsig::{Key, Keyring, verify_request};
use predicates::str::contains;
use tempfile::NamedTempFile;

use crate::util::{dedens, redact, run};

/// What a primary writes on the connection once it read the query: the framed messages, then it closes.
type Script = Box<dyn FnOnce(&[u8]) -> Vec<Vec<u8>> + Send>;

/// A primary on the loopback address: its first TCP connection gets the reply of `script`.
fn primary(script: Script) -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").expect("a port");
    let addr = listener.local_addr().expect("bound");
    thread::spawn(move || {
        let (mut stream, _) = listener.accept().expect("a connection");
        let mut len = [0; 2];
        stream.read_exact(&mut len).expect("a query's length");
        let mut query = vec![0; usize::from(u16::from_be_bytes(len))];
        stream.read_exact(&mut query).expect("a whole query");
        for bytes in script(&query) {
            // The client may have given up meanwhile.
            let _ = stream.write_all(&bytes);
        }
        let _ = stream.shutdown(Shutdown::Write);
        let _ = stream.read_to_end(&mut Vec::new());
    });
    addr
}

/// The responses of the recording `id` over TCP.
fn responses(id: &str) -> Vec<Vec<u8>> {
    Recording::read(id)
        .messages
        .into_iter()
        .filter(|m| m.from == Peer::Server && m.transport == Transport::Tcp)
        .map(|m| m.message)
        .collect()
}

/// `message` with the ID of `query`.
fn with_id(message: &[u8], query: &[u8]) -> Vec<u8> {
    let mut message = message.to_vec();
    message[..2].copy_from_slice(&query[..2]);
    message
}

/// Replays the responses of the recording `id`.
fn recorded(id: &str) -> Script {
    let messages = responses(id);
    Box::new(move |query| {
        messages
            .iter()
            .map(|m| frame(&with_id(m, query)).expect("under 64 KiB"))
            .collect()
    })
}

/// The key of the captures, as Knot holds it.
fn key() -> Key {
    Key::from_base64(
        dns(&format!("{}.", TSIG_KEY.name)),
        TSIG_KEY.algorithm.parse().expect("hmac-sha256"),
        TSIG_KEY.secret,
    )
    .expect("a valid secret")
}

/// The key as `-y` takes it.
fn key_text() -> String {
    format!("{}:{}", TSIG_KEY.name, TSIG_KEY.secret)
}

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("after 1970")
        .as_secs()
}

/// `wire` without its TSIG record, if it has one.
fn strip(wire: &[u8]) -> Vec<u8> {
    let Some(tsig) = find_tsig(wire).expect("well formed") else {
        return wire.to_vec();
    };
    let mut stripped = wire[..tsig.start].to_vec();
    let additional = u16::from_be_bytes([stripped[10], stripped[11]]) - 1;
    stripped[10..12].copy_from_slice(&additional.to_be_bytes());
    stripped
}

/// Replays the responses of the signed recording `id`, their TSIG made again for the query, now; the MAC of the
/// message of index `corrupt` is changed, when given.
fn resigned(id: &str, corrupt: Option<usize>) -> Script {
    let messages = responses(id);
    Box::new(move |query| {
        let keys = Keyring::new([key()]).expect("one key");
        let request = verify_request(&keys, query, unix_now())
            .expect("a request signed with the key")
            .expect("signed");
        let mut signer = request.signer();
        messages
            .iter()
            .enumerate()
            .map(|(n, m)| {
                let mut m = with_id(&strip(m), query);
                signer.sign(&mut m, unix_now()).expect("signed");
                if corrupt == Some(n) {
                    // The last byte of the MAC: the TSIG record ends with the original ID, the error and an empty
                    // Other Data, 6 bytes.
                    let at = m.len() - 7;
                    m[at] ^= 1;
                }
                frame(&m).expect("under 64 KiB")
            })
            .collect()
    })
}

/// The serial a recorded IXFR request asks from.
fn asked_from(id: &str) -> u32 {
    let request = Recording::read(id)
        .messages
        .into_iter()
        .find(|m| m.from == Peer::Client && m.transport == Transport::Tcp)
        .expect("a request")
        .message;
    let message = Message::decode(&request).expect("a query").message;
    match message.authority[0].data() {
        dedens_proto::rdata::RData::Soa(soa) => soa.serial,
        other => unreachable!("{other:?}"),
    }
}

/// A transfer of `zone` of type `qtype` from `addr`, with `more` arguments, its output redacted.
fn transfer(addr: SocketAddr, zone: &str, qtype: &str, more: &[&str], code: i32) -> String {
    let at = format!("@{}", addr.ip());
    let port = addr.port().to_string();
    let mut args = vec![zone, qtype, &at, "-p", &port, "--color=never"];
    args.extend_from_slice(more);
    redact(&run(&args, code), addr.port())
}

#[test]
fn axfr_prints_the_records_as_they_came_with_the_counts() {
    let addr = primary(recorded("axfr-zonetransfer.me"));
    insta::assert_snapshot!(transfer(addr, "zonetransfer.me", "AXFR", &[], 0));
}

#[test]
fn axfr_short_prints_each_record_with_its_owner() {
    let addr = primary(recorded("axfr-zonetransfer.me"));
    let out = transfer(addr, "zonetransfer.me", "AXFR", &["--short"], 0);
    insta::assert_snapshot!(out);
    let soa = out.lines().next().expect("a record");
    assert!(soa.starts_with("zonetransfer.me. "), "{soa}");
    assert!(soa.contains(" IN SOA "), "{soa}");
}

#[test]
fn axfr_json_counts_the_messages() {
    let addr = primary(recorded("axfr-zonetransfer.me"));
    let at = format!("@{}", addr.ip());
    let port = addr.port().to_string();
    let out = run(&["zonetransfer.me", "AXFR", &at, "-p", &port, "--json"], 0);
    let report: serde_json::Value = serde_json::from_str(&out).expect("JSON");
    assert_eq!(
        report["transfer"]["messages"],
        responses("axfr-zonetransfer.me").len()
    );
    assert_eq!(report["exchange"]["transport"], "tcp");
    assert_eq!(report["answer"][0]["type"], "SOA");
}

#[test]
fn a_dash_t_word_asks_a_transfer_too() {
    let addr = primary(recorded("axfr-zonetransfer.me"));
    let at = format!("@{}", addr.ip());
    let port = addr.port().to_string();
    let out = run(&["zonetransfer.me", "-t", "AXFR", &at, "-p", &port], 0);
    assert!(out.contains(" records"), "{out}");
}

#[test]
fn a_refused_transfer_shows_the_rcode() {
    let addr = primary(recorded("axfr-unsigned-refused"));
    insta::assert_snapshot!(transfer(addr, "zonetransfer.me", "AXFR", &[], 0));
}

#[test]
fn a_signed_axfr_is_verified() {
    let addr = primary(resigned("axfr-tsig", None));
    let out = transfer(addr, "zonetransfer.me", "AXFR", &["-y", &key_text()], 0);
    insta::assert_snapshot!(out);
}

#[test]
fn a_signed_stream_of_messages_is_verified_as_a_whole() {
    let addr = primary(resigned("axfr-tsig-stream", None));
    let out = transfer(addr, ".", "AXFR", &["-y", &key_text()], 0);
    assert!(out.contains("TSIG verified"), "{out}");
}

#[test]
fn a_key_file_signs_as_dash_y_does() {
    let mut file = NamedTempFile::new().expect("a file");
    writeln!(file, "hmac-sha256:{}", key_text()).expect("the key");
    let addr = primary(resigned("axfr-tsig", None));
    let path = file.path().to_str().expect("UTF-8");
    let out = transfer(addr, "zonetransfer.me", "AXFR", &["-k", path], 0);
    assert!(out.contains("TSIG verified"), "{out}");
}

#[test]
fn a_message_that_does_not_verify_fails_the_run_and_shows_no_record_of_it() {
    let addr = primary(resigned("axfr-tsig-stream", Some(1)));
    let out = transfer(addr, ".", "AXFR", &["-y", &key_text()], 1);
    assert!(
        out.contains("failed TSIG: the TSIG MAC does not verify"),
        "{out}"
    );
    // The first message verified and is shown; the corrupt second is counted, not shown.
    assert!(out.contains("2 messages"), "{out}");
    assert!(!out.contains("TSIG verified"), "{out}");
}

#[test]
fn an_unsigned_answer_to_a_signed_transfer_fails() {
    let addr = primary(recorded("axfr-zonetransfer.me"));
    let out = transfer(addr, "zonetransfer.me", "AXFR", &["-y", &key_text()], 1);
    assert!(out.contains("failed TSIG: "), "{out}");
}

#[test]
fn ixfr_up_to_date_is_one_soa() {
    let serial = asked_from("ixfr-uptodate");
    let addr = primary(recorded("ixfr-uptodate"));
    let word = format!("IXFR={serial}");
    insta::assert_snapshot!(transfer(addr, "example.", &word, &[], 0));
}

#[test]
fn ixfr_difference_prints_the_changes() {
    let serial = asked_from("ixfr-difference-tcp");
    let addr = primary(recorded("ixfr-difference-tcp"));
    let word = format!("IXFR={serial}");
    insta::assert_snapshot!(transfer(addr, "example.", &word, &[], 0));
}

#[test]
fn a_primary_that_refuses_connections_is_no_reply() {
    let addr = TcpListener::bind("127.0.0.1:0")
        .expect("a port")
        .local_addr()
        .expect("bound");
    dedens()
        .args([
            "zonetransfer.me",
            "AXFR",
            "@127.0.0.1",
            "-p",
            &addr.port().to_string(),
        ])
        .assert()
        .code(9)
        .stderr(contains("zonetransfer.me_AXFR"));
}

#[test]
fn a_transfer_saves_its_messages_with_their_lengths() {
    let dir = tempfile::tempdir().expect("a directory");
    let addr = primary(recorded("axfr-zonetransfer.me"));
    transfer(
        addr,
        "zonetransfer.me",
        "AXFR",
        &["--save-wire", dir.path().to_str().expect("UTF-8")],
        0,
    );
    let saved = std::fs::read(dir.path().join("zonetransfer.me_AXFR.bin")).expect("saved");
    let sent: usize = responses("axfr-zonetransfer.me")
        .iter()
        .map(|m| m.len() + 2)
        .sum();
    assert_eq!(saved.len(), sent);
}

#[test]
fn a_signed_query_gets_its_response_verified() {
    let socket = UdpSocket::bind("127.0.0.1:0").expect("a port");
    let addr = socket.local_addr().expect("bound");
    thread::spawn(move || {
        let mut buf = vec![0; 4096];
        let (len, client) = socket.recv_from(&mut buf).expect("a query");
        let keys = Keyring::new([key()]).expect("one key");
        let request = verify_request(&keys, &buf[..len], unix_now())
            .expect("a request signed with the key")
            .expect("signed");
        // The query, answered: the same question, no records.
        let mut response = strip(&buf[..len]);
        response[2] |= 0x80;
        request
            .signer()
            .sign(&mut response, unix_now())
            .expect("signed");
        socket.send_to(&response, client).expect("sent");
    });
    let out = run(
        &[
            "example.org",
            "SOA",
            "@127.0.0.1",
            "-p",
            &addr.port().to_string(),
            "-y",
            &key_text(),
            "--color=never",
        ],
        0,
    );
    assert!(out.contains("TSIG verified"), "{out}");
}

#[test]
fn a_signed_query_answered_unsigned_fails() {
    let responder = dedens_testkit::responder::Responder::start(&["a"]);
    dedens()
        .args([
            "example.com",
            "@127.0.0.1",
            "-p",
            &responder.addr.port().to_string(),
        ])
        .args(["-y", &key_text()])
        .assert()
        .code(1)
        .stdout(contains("failed TSIG: "));
}

#[test]
fn usage_errors_exit_2() {
    let refuse = |args: &[&str], message: &str| {
        dedens()
            .args(args)
            .assert()
            .code(2)
            .stderr(contains(message.to_owned()));
    };
    refuse(
        &["example.org", "IXFR", "@127.0.0.1"],
        "IXFR needs the serial it asks from",
    );
    refuse(
        &["example.org", "IXFR=soon", "@127.0.0.1"],
        "IXFR=SERIAL takes a serial",
    );
    refuse(
        &["example.org", "AXFR", "@127.0.0.1", "+tls"],
        "a zone transfer goes with",
    );
    refuse(
        &["example.org", "AXFR", "@127.0.0.1", "+dnssec"],
        "no query option but +time",
    );
    refuse(&["example.org", "-y", "name", "@127.0.0.1"], "name");
    refuse(&["example.org", "-y", "name:%%%", "@127.0.0.1"], "base64");
    refuse(
        &[
            "example.org",
            "-y",
            "name:c2VjcmV0",
            "-k",
            "key",
            "@127.0.0.1",
        ],
        "cannot be used with",
    );
    refuse(
        &["example.org", "-k", "/nonexistent/key", "@127.0.0.1"],
        "/nonexistent/key",
    );
    refuse(
        &["example.org", "-y", "name:c2VjcmV0", "@tls://127.0.0.1"],
        "-y and -k go with a plain @server",
    );
    refuse(
        &["-y", "name:c2VjcmV0", "+trace", "example.org"],
        "+trace goes with",
    );
}
