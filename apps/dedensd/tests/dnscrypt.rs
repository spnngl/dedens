//! `dedensd` as a `DNSCrypt` resolver (D99; draft-denis-dprive-dnscrypt-11, "Certificates", "Client Queries Over UDP",
//! "Client Queries Over TCP", "Key Management"): the `dedens-net` client of D98 against a `dnscrypt://` listener over
//! UDP and TCP, both systems, the certificate query in the clear, queries that must not be answered, and the key and
//! stamp of `dedensd dnscrypt-keygen`. Rotation and expiry on simulated time are `dedens-sim`'s (D182).

use std::io::{ErrorKind, Read, Write};
use std::net::{TcpStream, UdpSocket};
use std::num::NonZero;
use std::path::PathBuf;
use std::process::Command;
use std::time::Duration;

use compio::runtime::Runtime;
use dedens_dnscrypt::{Certificate, ProviderKey};
use dedens_net::client::{Client, ClientError};
use dedens_net::exchange::Options;
use dedens_net::stamp::{DnsCrypt, Endpoint, Stamp};
use dedens_proto::rdata::RData;
use dedens_proto::{Message, Question, Rcode, RecordType, Transport};
use dedens_testkit::responder::Responder;

use crate::util::{Server, ask_tcp, ask_udp, decode, framed, write_config, write_key};

const PROVIDER: &str = "2.dnscrypt-cert.test.example";

/// The resolver stamp `text` is.
fn resolver_stamp(text: &str) -> DnsCrypt {
    match text.parse() {
        Ok(Stamp::DnsCrypt(stamp)) => stamp,
        other => unreachable!("not a resolver stamp: {other:?}"),
    }
}

/// What `dedensd dnscrypt-keygen --provider-name PROVIDER --address 127.0.0.1` printed: the seed's hex and the stamp.
fn keygen() -> (String, DnsCrypt) {
    let out = Command::new(env!("CARGO_BIN_EXE_dedensd"))
        .args(["dnscrypt-keygen", "--provider-name", PROVIDER])
        .args(["--address", "127.0.0.1"])
        .output()
        .expect("dedensd runs");
    assert!(out.status.success(), "{out:?}");
    let text = String::from_utf8(out.stdout).expect("UTF-8");
    let mut lines = text.lines();
    let secret = lines
        .next()
        .and_then(|line| line.strip_prefix("secret_key: "))
        .expect("the key line")
        .to_owned();
    let stamp = lines
        .next()
        .and_then(|line| line.strip_prefix("stamp: "))
        .expect("the stamp line");
    (secret, resolver_stamp(stamp))
}

/// A `dnscrypt://` server forwarding to `upstream`, with `extra` lines in its `dnscrypt` section and `access` lines
/// at the top; the key file is a new one. Its stamp is the one it logged, which names its address.
struct Resolver {
    server: Server,
    stamp: DnsCrypt,
    /// The stamp `dnscrypt-keygen` printed for the key the server reads.
    keygen: DnsCrypt,
}

fn resolver(extra: &str, access: &str, upstream: &str) -> Resolver {
    let (secret, keygen) = keygen();
    let key: PathBuf = write_config("").with_extension("dnscrypt.key");
    write_key(&key, secret);
    let mut server = Server::configured(|listen| {
        format!(
            "listen: ['dnscrypt://{listen}']\n{access}dnscrypt:\n  provider_name: {PROVIDER}\n  secret_key: '{}'\n{extra}pipeline: [up]\nstages:\n  up:\n    type: forward\n    servers: ['{upstream}']\n    timeout_ms: 2000\n    tries: 1\n",
            key.display()
        )
    });
    let logged = server.event("DNSCrypt").expect("the stamp is logged");
    let stamp = resolver_stamp(logged["fields"]["stamp"].as_str().expect("a stamp"));
    assert_eq!(stamp.address.socket_addr(), server.addr);
    Resolver {
        server,
        stamp,
        keygen,
    }
}

/// The options of a test: one try, so that a query that is not answered fails soon.
fn quick(transport: Transport) -> Options {
    let mut options = Options::default();
    options.transport = transport;
    options.tries = NonZero::<u8>::MIN;
    options.timeout = Duration::from_millis(700);
    options
}

fn ask(
    client: &Client,
    stamp: &DnsCrypt,
    case: &str,
    transport: Transport,
) -> Result<dedens_net::exchange::Response, ClientError> {
    let query = dedens_testkit::query(case, 0x0102);
    Runtime::new()
        .expect("a runtime")
        .block_on(client.exchange_dnscrypt(query, stamp, &quick(transport)))
}

/// D99: the stamp `dnscrypt-keygen` printed is read by the stamp parser, and its provider key is the one the server
/// serves: the stamp the server logs at start has the same key and name, at the address it listens on.
#[test]
fn the_stamp_of_keygen_is_the_one_the_server_logs() {
    let resolver = resolver("", "", "192.0.2.1");
    assert_eq!(resolver.stamp.public_key, resolver.keygen.public_key);
    assert_eq!(resolver.stamp.provider_name, resolver.keygen.provider_name);
    assert_eq!(resolver.keygen.address.port, None);
    assert_eq!(resolver.stamp.properties, resolver.keygen.properties);
}

/// D99: the certificates are asked in the clear for the provider name, over UDP and TCP: a TXT record per system,
/// signed by the provider key, valid now; the same query for another name is not answered.
#[test]
fn the_certificates_are_served_in_the_clear() {
    let resolver = resolver("", "", "192.0.2.1");
    let provider = ProviderKey::from_bytes(resolver.stamp.public_key);
    let question = |name: &str| {
        let name = name.parse().expect("a name");
        Message::query(9, Question::new(name, RecordType::TXT))
            .to_vec()
            .expect("a query")
    };
    for reply in [
        ask_udp(resolver.server.addr, &question(PROVIDER)),
        ask_tcp(resolver.server.addr, &question(PROVIDER)),
    ] {
        assert_eq!(reply.rcode(), Rcode::NOERROR);
        assert_eq!(reply.answer.len(), 2);
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("after 1970")
            .as_secs();
        let mut systems: Vec<_> = reply
            .answer
            .iter()
            .map(|record| {
                let RData::Txt(txt) = record.data() else {
                    panic!("a TXT record");
                };
                let certificate = Certificate::from_txt(&txt, &provider).expect("signed");
                assert!(certificate.is_valid_at(now));
                certificate.body().system.es_version()
            })
            .collect();
        systems.sort_unstable();
        assert_eq!(systems, [[0, 1], [0, 2]]);
    }
    // Another name is a query that does not open: no answer.
    let other = question("2.dnscrypt-cert.other.example");
    let socket = UdpSocket::bind("127.0.0.1:0").expect("a socket");
    socket
        .set_read_timeout(Some(Duration::from_millis(300)))
        .expect("a timeout");
    socket.send_to(&other, resolver.server.addr).expect("sent");
    let mut buf = [0; 512];
    let error = socket.recv(&mut buf).expect_err("no answer");
    assert!(matches!(
        error.kind(),
        ErrorKind::WouldBlock | ErrorKind::TimedOut
    ));
}

/// D99: the `dedens-net` client gets the answers of the forward stage over UDP, under the system it prefers, `XChaCha20`
/// (es-version 2), and a client does what the stamp tells with a listing: both certificates.
#[test]
fn a_query_is_answered_under_both_systems() {
    let upstream = Responder::start(&["a"]);
    let resolver = resolver("", "", &upstream.addr.to_string());
    let client = Client::new();
    let response = ask(&client, &resolver.stamp, "a", Transport::Udp).expect("an answer");
    assert_eq!(response.transport, Transport::Udp);
    assert_eq!(response.dnscrypt.expect("a certificate").es_version, 2);
    let reply = decode(&response.wire);
    assert_eq!(reply.rcode(), Rcode::NOERROR);
    assert_eq!(reply.answer, decode(&dedens_testkit::captured("a")).answer);
    let listing = Runtime::new()
        .expect("a runtime")
        .block_on(client.dnscrypt_certificates(&resolver.stamp, &quick(Transport::Udp)))
        .expect("a listing");
    let mut versions: Vec<_> = listing.certificates.iter().map(|c| c.es_version).collect();
    versions.sort_unstable();
    assert_eq!(versions, [1, 2]);
}

/// D99: a server offering `systems` only answers under it, over UDP and over TCP.
#[test]
fn each_system_answers_alone() {
    let upstream = Responder::start(&["a"]);
    for (setting, es_version) in [("xsalsa20", 1), ("xchacha20", 2)] {
        let resolver = resolver(
            &format!("  systems: [{setting}]\n"),
            "",
            &upstream.addr.to_string(),
        );
        for transport in [Transport::Udp, Transport::Tcp] {
            let response = ask(&Client::new(), &resolver.stamp, "a", transport).expect("an answer");
            assert_eq!(response.transport, transport, "{setting}");
            assert_eq!(
                response.dnscrypt.expect("a certificate").es_version,
                es_version
            );
            assert_eq!(decode(&response.wire).rcode(), Rcode::NOERROR);
        }
    }
}

/// Draft "Client Queries Over UDP": a response larger than the query is truncated, and the client asks again over
/// TCP, where the whole of it comes (D99).
#[test]
fn a_large_answer_is_truncated_over_udp_and_whole_over_tcp() {
    let upstream = Responder::start(&["txt_large"]);
    let resolver = resolver("", "", &upstream.addr.to_string());
    let response =
        ask(&Client::new(), &resolver.stamp, "txt_large", Transport::Udp).expect("an answer");
    assert_eq!(response.transport, Transport::Tcp, "asked again over TCP");
    assert_eq!(response.sends, 2);
    let reply = decode(&response.wire);
    assert!(!reply.header.flags.contains(dedens_proto::Flags::TC));
    assert_eq!(
        reply.answer,
        decode(&dedens_testkit::captured("txt_large")).answer
    );
}

/// D99, D91: a client denied is not answered over `DNSCrypt`, whatever `access.action` says, and the pipeline is not
/// asked: the upstream sees no query.
#[test]
fn a_denied_client_gets_no_answer() {
    for action in ["refuse", "drop"] {
        let upstream = Responder::start(&["a"]);
        let access = format!("access:\n  allow: ['10.0.0.0/8']\n  action: {action}\n");
        let resolver = resolver("", &access, &upstream.addr.to_string());
        // The certificates are not a query of the pipeline's, and denied too: nothing is done for this address.
        let socket = UdpSocket::bind("127.0.0.1:0").expect("a socket");
        socket
            .set_read_timeout(Some(Duration::from_millis(300)))
            .expect("a timeout");
        let certificates = Message::query(
            9,
            Question::new(PROVIDER.parse().expect("a name"), RecordType::TXT),
        )
        .to_vec()
        .expect("a query");
        socket
            .send_to(&certificates, resolver.server.addr)
            .expect("sent");
        assert!(socket.recv(&mut [0; 512]).is_err(), "{action}: UDP");
        let outcome = ask(&Client::new(), &resolver.stamp, "a", Transport::Udp);
        assert!(outcome.is_err(), "{action}: no answer to a client denied");
        assert!(upstream.queries().is_empty(), "{action}");
    }
}

/// Draft "Client Queries Over UDP": a packet that does not open is dropped silently: garbage, a packet of a known
/// client magic whose tag is wrong, over UDP and over TCP; the server goes on answering.
#[test]
fn a_packet_that_does_not_open_is_dropped() {
    let upstream = Responder::start(&["a"]);
    let resolver = resolver("", "", &upstream.addr.to_string());
    let provider = ProviderKey::from_bytes(resolver.stamp.public_key);
    let question = Message::query(
        9,
        Question::new(PROVIDER.parse().expect("a name"), RecordType::TXT),
    )
    .to_vec()
    .expect("a query");
    let certificates = ask_udp(resolver.server.addr, &question);
    let RData::Txt(txt) = certificates.answer[0].data() else {
        panic!("a TXT record");
    };
    let magic = *Certificate::from_txt(&txt, &provider)
        .expect("signed")
        .body()
        .client_magic
        .as_bytes();
    let mut forged = magic.to_vec();
    forged.extend((0..120u8).map(|byte| byte.wrapping_mul(7)));
    let garbage: Vec<u8> = (0..200u8).collect();
    let socket = UdpSocket::bind("127.0.0.1:0").expect("a socket");
    socket
        .set_read_timeout(Some(Duration::from_millis(300)))
        .expect("a timeout");
    for packet in [&forged, &garbage, &vec![0; 3]] {
        socket.send_to(packet, resolver.server.addr).expect("sent");
        assert!(socket.recv(&mut [0; 4096]).is_err(), "UDP answered");
        let mut stream = TcpStream::connect(resolver.server.addr).expect("connected");
        stream
            .set_read_timeout(Some(Duration::from_millis(300)))
            .expect("a timeout");
        stream.write_all(&framed(packet)).expect("written");
        let mut buf = [0; 16];
        // The connection stays silent: nothing comes before the timeout, or it is closed.
        match stream.read(&mut buf) {
            Ok(0) => {}
            Ok(n) => panic!("answered with {n} bytes"),
            Err(error) => assert!(matches!(
                error.kind(),
                ErrorKind::WouldBlock | ErrorKind::TimedOut | ErrorKind::ConnectionReset
            )),
        }
    }
    let answered = ask(&Client::new(), &resolver.stamp, "a", Transport::Udp);
    assert!(answered.is_ok(), "{answered:?}");
}

/// D99: the stamp's address and the section's key must go together: a stamp of another provider key finds no
/// certificate its key signed, so it is not answered.
#[test]
fn a_stamp_of_another_key_finds_no_certificate() {
    let resolver = resolver("", "", "192.0.2.1");
    let other = DnsCrypt {
        public_key: [9; 32],
        address: Endpoint {
            ip: resolver.server.addr.ip(),
            port: NonZero::new(resolver.server.addr.port()),
        },
        ..resolver.stamp.clone()
    };
    assert!(ask(&Client::new(), &other, "a", Transport::Udp).is_err());
}

/// D99: a forward stage whose server is an `sdns://` stamp asks it over `DNSCrypt`, for a client over UDP and one over
/// TCP: here a second `dedensd`, its `dnscrypt://` listener the upstream, which forwards to a responder that counts
/// what reaches it.
#[test]
fn a_forward_stage_asks_a_dnscrypt_server() {
    let upstream = Responder::start(&["a"]);
    let resolver = resolver("", "", &upstream.addr.to_string());
    let stamp = Stamp::DnsCrypt(resolver.stamp.clone()).to_string();
    let server = Server::configured(|listen| {
        format!(
            "listen: ['{listen}']\npipeline: [up]\nstages:\n  up:\n    type: forward\n    servers: ['{stamp}']\n    timeout_ms: 2000\n    tries: 1\n"
        )
    });
    let query = dedens_testkit::query("a", 0x0304)
        .to_vec()
        .expect("a query");
    for reply in [ask_udp(server.addr, &query), ask_tcp(server.addr, &query)] {
        assert_eq!(reply.rcode(), Rcode::NOERROR);
        assert_eq!(reply.answer, decode(&dedens_testkit::captured("a")).answer);
    }
    assert_eq!(
        upstream.queries().len(),
        2,
        "both queries went through to the responder"
    );
}

/// D99: a key file others can read, or that is not 64 hex digits, stops the start.
#[cfg(unix)]
#[test]
fn a_key_file_that_is_not_private_stops_the_start() {
    use std::os::unix::fs::PermissionsExt as _;

    let key = write_config("").with_extension("dnscrypt.key");
    std::fs::write(&key, "ab".repeat(32)).expect("written");
    std::fs::set_permissions(&key, std::fs::Permissions::from_mode(0o644)).expect("mode");
    let text = format!(
        "listen: ['dnscrypt://127.0.0.1:5443']\ndnscrypt:\n  provider_name: {PROVIDER}\n  secret_key: '{}'\npipeline: [up]\nstages:\n  up:\n    type: forward\n    servers: ['192.0.2.1']\n",
        key.display()
    );
    let (code, stderr) = crate::util::validate(&text);
    assert_eq!(code, Some(1), "{stderr}");
    assert!(stderr.contains("`dnscrypt`"), "{stderr}");
    std::fs::set_permissions(&key, std::fs::Permissions::from_mode(0o600)).expect("mode");
    assert_eq!(crate::util::validate(&text).0, Some(0));
}
