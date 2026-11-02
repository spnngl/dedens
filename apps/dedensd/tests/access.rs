//! `dedensd` answering the networks `access` allows (D91, RFC 5358 §4) over UDP, TCP and DNS over HTTPS
//! (and, with feature `doc`, `DoC`): a denied client gets REFUSED with EDE 18 (RFC 8914 §4.19) or nothing, a
//! configuration without `access` answers the local networks, a reload changes the lists, and a network that is no
//! network stops the start. Every client is `127.0.0.1`.

#[path = "../../../crates/dedens-net/tests/common/certificates.rs"]
#[allow(
    dead_code,
    reason = "shared with the tests of dedens-net, which use all of it"
)]
mod certificates;
mod common;

use std::io::{ErrorKind, Read, Write};
use std::net::{SocketAddr, TcpStream, UdpSocket};
use std::num::NonZero;
use std::process::Command;
use std::time::Duration;

use certificates::{NAME, certificates, named};
use common::{Server, ask_tcp, ask_udp, decode, framed, write_config};
use compio::runtime::Runtime;
use dedens_net::client::Client;
use dedens_net::exchange::{Options, Transport};
use dedens_net::tls::Trust;
use dedens_proto::edns::{EdnsOption, InfoCode};
use dedens_proto::{Message, Question, Rcode, RecordType};

/// The configuration of a server answering `www.example.` from a hosts stage at `listen`, with `access` (lines of
/// the file, or none).
fn hosts(listen: &str, access: &str) -> String {
    format!(
        "listen: [{listen}]\n{access}pipeline: [hosts]\nstages:\n  hosts:\n    type: hosts\n    entries: ['192.0.2.1 www.example']\n"
    )
}

/// A server over UDP and TCP with `access`.
fn serving(access: &str) -> Server {
    Server::configured(|listen| hosts(&format!("'{listen}'"), access))
}

fn query() -> Message<'static> {
    let name = "www.example.".parse().expect("a name");
    Message::query(7, Question::new(name, RecordType::A))
}

fn wire() -> Vec<u8> {
    query().to_vec().expect("a query fits")
}

/// Whether `reply` is the hosts stage's answer.
fn answered(reply: &Message<'_>) -> bool {
    reply.rcode() == Rcode::NOERROR && reply.answer.len() == 1
}

/// Whether `reply` is REFUSED with EDE 18 and no answer.
fn prohibited(reply: &Message<'_>) -> bool {
    let options = reply.edns.iter().flat_map(|edns| &edns.options);
    reply.rcode() == Rcode::REFUSED
        && reply.answer.is_empty()
        && options
            .filter_map(|option| match option {
                EdnsOption::Ede(e) => Some(e.code),
                _ => None,
            })
            .eq([InfoCode::PROHIBITED])
}

/// Whether no reply to a query over UDP comes within a moment.
fn silent_udp(server: SocketAddr) -> bool {
    let socket = UdpSocket::bind("127.0.0.1:0").expect("a UDP port");
    socket
        .set_read_timeout(Some(Duration::from_millis(500)))
        .expect("a timeout");
    socket.send_to(&wire(), server).expect("sent");
    let error = socket.recv(&mut [0; 512]).expect_err("no reply");
    matches!(error.kind(), ErrorKind::WouldBlock | ErrorKind::TimedOut)
}

/// Whether the server closes a TCP connection with no reply to a query, as it does at accept for `drop` (D91).
fn closed_tcp(server: SocketAddr) -> bool {
    let mut stream = TcpStream::connect(server).expect("connected");
    stream
        .set_read_timeout(Some(Duration::from_millis(500)))
        .expect("a timeout");
    // The server may have closed already, so the write may fail.
    let _ = stream.write_all(&framed(&wire()));
    match stream.read(&mut [0; 2]) {
        Ok(read) => read == 0,
        Err(error) => error.kind() == ErrorKind::ConnectionReset,
    }
}

#[test]
fn without_access_the_local_networks_are_answered() {
    let server = serving("");
    assert!(answered(&ask_udp(server.addr, &wire())));
    assert!(answered(&ask_tcp(server.addr, &wire())));
}

#[test]
fn a_client_outside_the_allowed_networks_is_refused() {
    let server = serving("access:\n  allow: ['10.0.0.0/8']\n");
    assert!(prohibited(&ask_udp(server.addr, &wire())));
    assert!(prohibited(&ask_tcp(server.addr, &wire())));
}

#[test]
fn the_longest_network_decides() {
    let server = serving("access:\n  allow: ['127.0.0.0/8']\n  deny: ['127.0.0.1/32']\n");
    assert!(prohibited(&ask_udp(server.addr, &wire())));
    let server = serving("access:\n  allow: ['127.0.0.1/32']\n  deny: ['127.0.0.0/8']\n");
    assert!(answered(&ask_udp(server.addr, &wire())));
    // A tie is denied.
    let server = serving("access:\n  allow: ['127.0.0.1/32']\n  deny: ['127.0.0.1/32']\n");
    assert!(prohibited(&ask_tcp(server.addr, &wire())));
}

/// An IPv6 network holds no IPv4 client, so `::/0` alone allows nobody over IPv4 (RFC 4291 §2.5.5.2).
#[test]
fn an_ipv6_network_does_not_allow_an_ipv4_client() {
    let server = serving("access:\n  allow: ['::/0']\n");
    assert!(prohibited(&ask_udp(server.addr, &wire())));
    assert!(prohibited(&ask_tcp(server.addr, &wire())));
}

#[test]
fn a_client_outside_the_allowed_networks_gets_nothing_when_the_action_is_drop() {
    let server = serving("access:\n  allow: ['10.0.0.0/8']\n  action: drop\n");
    assert!(silent_udp(server.addr));
    assert!(closed_tcp(server.addr));
    let server = serving("access:\n  allow: ['127.0.0.0/8']\n  action: drop\n");
    assert!(answered(&ask_udp(server.addr, &wire())));
}

#[test]
fn a_reload_changes_the_lists() {
    let mut server = serving("access:\n  allow: ['10.0.0.0/8']\n");
    assert!(prohibited(&ask_udp(server.addr, &wire())));
    let reload = |server: &mut Server, text: String| {
        std::fs::write(&server.config, text).expect("rewritten");
        server.hang_up();
    };
    let listen = format!("'{}'", server.addr);
    let text = |access: &str| hosts(&listen, access);
    let allowed = text("access:\n  allow: ['127.0.0.0/8']\n");
    reload(&mut server, allowed);
    assert!(server.event("reloaded").is_some());
    assert!(answered(&ask_udp(server.addr, &wire())));
    // A list that does not read leaves the running one.
    let broken = text("access:\n  allow: ['127.0.0.1/24']\n");
    reload(&mut server, broken);
    let failed = server
        .event("reload failed, serving the previous configuration")
        .expect("the failure logged");
    let error = failed["fields"]["error"].as_str().expect("its error");
    assert!(error.contains("`127.0.0.0/24`"), "{error}");
    assert!(answered(&ask_udp(server.addr, &wire())));
    // The action changes with the lists.
    let dropping = text("access:\n  deny: ['127.0.0.0/8']\n  action: drop\n");
    reload(&mut server, dropping);
    assert!(server.event("reloaded").is_some());
    assert!(silent_udp(server.addr));
}

#[test]
fn a_network_that_is_no_network_stops_the_start() {
    let validate = |access: &str| {
        let text = hosts("'127.0.0.1:5353'", access);
        let output = Command::new(env!("CARGO_BIN_EXE_dedensd"))
            .arg("validate")
            .arg("--config")
            .arg(write_config(&text))
            .output()
            .expect("dedensd runs");
        (
            output.status.code(),
            String::from_utf8_lossy(&output.stderr).into_owned(),
        )
    };
    assert_eq!(validate("access:\n  allow: ['10.0.0.0/8']\n").0, Some(0));
    for (access, message) in [
        ("allow: ['192.0.2.1/24']", "`192.0.2.0/24`"),
        ("deny: ['2001:db8::1/32']", "`2001:db8::/32`"),
        ("allow: ['192.0.2.0']", "`192.0.2.0` is not ADDRESS/LENGTH"),
        ("allow: ['192.0.2.0/33']", "`192.0.2.0/33`"),
        ("allow: ['::ffff:10.0.0.0/104']", "`10.0.0.0/8`"),
        ("action: ignore", "unknown variant `ignore`"),
        ("allowed: ['10.0.0.0/8']", "allowed"),
    ] {
        let (code, stderr) = validate(&format!("access:\n  {access}\n"));
        assert_eq!(code, Some(1), "{access}: {stderr}");
        assert!(stderr.contains(message), "{access}: {stderr}");
    }
}

/// The reply of a server over HTTP/3 behind `https://` with `certificate`, `Ok` to the query, 200 carrying whatever
/// message the server made, or the error of a client that got no message.
fn ask_https(
    server: SocketAddr,
    ca: &certificates::Certificates,
) -> Result<Message<'static>, String> {
    let client = Client::new().trusting(Trust::Roots(vec![ca.ca.clone()]));
    let mut options = Options::default();
    options.transport = Transport::Https;
    options.tries = NonZero::<u8>::MIN;
    options.timeout = Duration::from_secs(2);
    Runtime::new().expect("a runtime").block_on(async {
        client
            .exchange(decode(&wire()), named(server, NAME), &options)
            .await
            .map(|response| decode(&response.wire))
            .map_err(|error| error.to_string())
    })
}

/// A server over HTTP/3 with the certificates of `ca` and `access`.
fn serving_https(ca: &certificates::Certificates, access: &str) -> Server {
    let config = write_config("");
    let (certificate, key) = (
        config.with_extension("crt.pem"),
        config.with_extension("key.pem"),
    );
    std::fs::write(&certificate, &ca.server_pem).expect("the certificate written");
    common::write_key(&key, &ca.key_pem);
    let tls = format!(
        "tls:\n  certificate: '{}'\n  key: '{}'\n{access}",
        certificate.display(),
        key.display()
    );
    Server::configured(|listen| hosts(&format!("'https://{listen}'"), &tls))
}

/// RFC 8484 §4.2.1: a denied `DoH` request is answered 200 with the DNS message REFUSED; with `drop`, the
/// connection is ignored at accept (D91), so nothing comes, not even an HTTP status.
#[test]
fn a_denied_https_request_is_answered_200_with_refused() {
    let ca = certificates();
    let server = serving_https(&ca, "access:\n  allow: ['10.0.0.0/8']\n");
    assert!(prohibited(&ask_https(server.addr, &ca).expect("a message")));
    let server = serving_https(&ca, "access:\n  allow: ['127.0.0.0/8']\n");
    assert!(answered(&ask_https(server.addr, &ca).expect("a message")));
    let server = serving_https(&ca, "access:\n  allow: ['10.0.0.0/8']\n  action: drop\n");
    let error = ask_https(server.addr, &ca).expect_err("no message");
    assert!(error.contains("no response"), "{error}");
}

/// DNS over CoAP (RFC 9953): `drop` sends no CoAP message, not the 4.00 of a protocol drop, and a reload that denies
/// a client ends the blocks it was served.
#[cfg(feature = "doc")]
mod doc {
    use std::net::{SocketAddr, UdpSocket};
    use std::time::Duration;

    use dedens_net::coap::block::{Block, BlockSize};
    use dedens_net::coap::{Code, Message as Coap, OptionNumber, Options, Token, Type};
    use dedens_proto::{Message, Question, RecordType};

    use crate::common::Server;

    /// A configuration serving `entries` addresses of `www.example.` over `DoC` at `listen`, with `access`.
    fn config(listen: &str, access: &str, entries: u8) -> String {
        let entries: Vec<String> = (1..=entries)
            .map(|n| format!("'192.0.2.{n} www.example'"))
            .collect();
        format!(
            "listen: ['coap://{listen}/dns/query']\n{access}pipeline: [hosts]\nstages:\n  hosts:\n    type: hosts\n    entries: [{}]\n",
            entries.join(", ")
        )
    }

    /// A CON FETCH of the query for `www.example.` (RFC 9953 §4.1), tagged `tag`; with `block`, a follow-up with no
    /// body (RFC 8132 §2.5).
    fn fetch(id: u16, tag: &[u8], block: Option<Block>) -> Coap {
        let name = "www.example.".parse().expect("a name");
        let query = Message::query(0, Question::new(name, RecordType::A))
            .to_vec()
            .expect("a query fits");
        let mut options = Options::new();
        options.push_uri_path([&b"dns"[..], b"query"]);
        options.set_content_format(Options::DNS_MESSAGE);
        options.set_accept(Options::DNS_MESSAGE);
        options.insert(OptionNumber::REQUEST_TAG, tag);
        if let Some(block) = block {
            options.set_block2(block);
        }
        Coap {
            kind: Type::Confirmable,
            code: Code::FETCH,
            id,
            token: Token::new(&[7, 7]).expect("a token"),
            options,
            payload: if block.is_some() { Vec::new() } else { query },
        }
    }

    /// A UDP socket that waits a moment for a datagram.
    fn client() -> UdpSocket {
        let socket = UdpSocket::bind("127.0.0.1:0").expect("a UDP port");
        socket
            .set_read_timeout(Some(Duration::from_millis(500)))
            .expect("a timeout");
        socket
    }

    /// The message `server` sends `socket` back for `request`, `None` after a moment of silence.
    fn send(socket: &UdpSocket, server: SocketAddr, request: &Coap) -> Option<Coap> {
        socket
            .send_to(&request.to_vec().expect("it writes"), server)
            .expect("sent");
        let mut buf = vec![0; 65535];
        let len = socket.recv(&mut buf).ok()?;
        Some(Coap::parse(&buf[..len]).expect("a CoAP message"))
    }

    #[test]
    fn a_denied_client_gets_no_coap_message_when_the_action_is_drop() {
        let server = Server::configured(|listen| {
            config(
                listen,
                "access:\n  allow: ['10.0.0.0/8']\n  action: drop\n",
                1,
            )
        });
        assert_eq!(send(&client(), server.addr, &fetch(1, &[1], None)), None);
        let server = Server::configured(|listen| {
            config(
                listen,
                "access:\n  allow: ['127.0.0.0/8']\n  action: drop\n",
                1,
            )
        });
        let answer = send(&client(), server.addr, &fetch(1, &[1], None)).expect("a response");
        assert_eq!(answer.code, Code::CONTENT);
    }

    #[test]
    fn a_reload_that_denies_the_client_ends_its_blocks() {
        let mut server =
            Server::configured(|listen| config(listen, "access:\n  allow: ['127.0.0.0/8']\n", 100));
        let socket = client();
        let next = Block::new(1, false, BlockSize::MAX);
        let first = send(&socket, server.addr, &fetch(1, &[1, 2], None)).expect("a response");
        let more = first.options.block2().expect("a Block2").expect("one");
        assert!(more.more(), "a response of over 1024 bytes goes in blocks");
        let second = send(&socket, server.addr, &fetch(2, &[1, 2], next)).expect("a response");
        assert_eq!(second.code, Code::CONTENT);
        let denying = config(
            &server.addr.to_string(),
            "access:\n  allow: ['10.0.0.0/8']\n",
            100,
        );
        std::fs::write(&server.config, denying).expect("rewritten");
        server.hang_up();
        assert!(server.event("reloaded").is_some());
        let denied = send(&socket, server.addr, &fetch(3, &[1, 2], next)).expect("a response");
        assert_eq!(denied.code, Code::BAD_REQUEST);
        assert_eq!(denied.payload, b"");
    }
}
