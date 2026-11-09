//! `dedensd`'s listeners and upstreams over real sockets: UDP and TCP, TLS and QUIC on both sides, and broken TCP
//! frames.
//!
//! - Listening over TLS (RFC 7858) and QUIC (RFC 9250), on addresses behind `tls://` and `quic://` with the certificate
//!   of `tls` (D66), replaced by a reload.
//! - `dedensd` over real sockets on loopback: forwarding over UDP and TCP to a responder that answers captured bytes,
//!   several queries on one TCP connection (RFC 7766 §6.2.1), SERVFAIL when upstream stays silent, a start that fails
//!   on a taken address with its text events coloured as `NO_COLOR` and `CLICOLOR_FORCE` say (D169), SIGTERM and
//!   SIGINT ending it, `validate` reading a configuration file without binding, and expired data answering a client
//!   kept waiting while resolution goes on (RFC 8767 §5).

use std::io::Write;
use std::net::{SocketAddr, TcpStream, UdpSocket};
use std::num::NonZero;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::{Arc, Mutex, mpsc};
use std::thread;
use std::time::{Duration, Instant};

use compio::io::AsyncWriteExt;
use compio::quic::crypto::rustls::QuicClientConfig;
use compio::quic::{
    ClientConfig, Connection, ConnectionError, Endpoint, IdleTimeout, TransportConfig, VarInt,
};
use compio::runtime::Runtime;
use compio::rustls::crypto::ring;
use compio::rustls::version::TLS13;
use compio::rustls::{ClientConfig as TlsConfig, RootCertStore};
use dedens_net::client::{Client, ClientError};
use dedens_net::exchange::Options;
use dedens_net::quic::read_message;
use dedens_net::tls::Trust;
use dedens_proto::edns::{EdnsOption, InfoCode};
use dedens_proto::{Message, Opcode, Rcode, Transport};
use dedens_testkit::captured;
use dedens_testkit::certificates::{Certificates, NAME, certificates, named};
use dedens_testkit::responder::Responder;

use crate::util::{
    Server, ask_tcp, ask_udp, config, decode, framed, query_for, read_framed, silent, write_config,
};

// --- Listening over TLS (RFC 7858) and QUIC (RFC 9250), on addresses behind `tls ---

/// The certificate and key of `certificates` in PEM files beside the configuration file `config`.
fn write_pems(certificates: &Certificates, config: &Path) -> (PathBuf, PathBuf) {
    let (certificate, key) = (
        config.with_extension("crt.pem"),
        config.with_extension("key.pem"),
    );
    std::fs::write(&certificate, &certificates.server_pem).expect("the certificate written");
    crate::util::write_key(&key, &certificates.key_pem);
    (certificate, key)
}

/// `dedensd` answering over TLS and QUIC on one port with the certificate of `certificates`, forwarding to
/// `upstream`.
fn listening(certificates: &Certificates, upstream: SocketAddr) -> (Server, PathBuf, PathBuf) {
    let (certificate, key) = write_pems(certificates, &write_config(""));
    let server = serving(&certificate, &key, upstream);
    (server, certificate, key)
}

/// `dedensd` answering over TLS and QUIC on one port with the `certificate` and `key` files, forwarding to
/// `upstream`.
fn serving(certificate: &Path, key: &Path, upstream: SocketAddr) -> Server {
    Server::configured(|listen| {
        format!(
            "listen: ['tls://{listen}', 'quic://{listen}']\ntls:\n  certificate: '{}'\n  key: '{}'\npipeline: [up]\nstages:\n  up:\n    type: forward\n    servers: ['{upstream}']\n    timeout_ms: 2000\n    tries: 1\n",
            certificate.display(),
            key.display()
        )
    })
}

/// The reply of the server at `addr` over `transport`, its certificate checked against `ca`, to the query of the
/// `a` capture.
fn ask(
    addr: SocketAddr,
    transport: Transport,
    ca: &Certificates,
) -> Result<Message<'static>, ClientError> {
    let query = dedens_testkit::query("a", 0);
    let mut options = Options::default();
    options.transport = transport;
    options.tries = NonZero::<u8>::MIN;
    let client = Client::new().trusting(Trust::Roots(vec![ca.ca.clone()]));
    let runtime = Runtime::new().expect("a runtime");
    runtime.block_on(async {
        let response = client.exchange(query, named(addr, NAME), &options).await?;
        Ok(decode(&response.wire))
    })
}

#[test]
fn clients_over_tls_and_quic_get_padded_answers() {
    let response = captured("a");
    let upstream = Responder::start(&["a"]);
    let ca = certificates();
    let (server, ..) = listening(&ca, upstream.addr);
    for transport in [Transport::Tls, Transport::Quic] {
        let reply = ask(server.addr, transport, &ca).expect("an answer");
        assert_eq!(
            (reply.rcode(), &reply.answer),
            (Rcode::NOERROR, &decode(&response).answer),
            "{transport:?}"
        );
        // The client pads its query, so the reply is padded too (RFC 7830 §4, RFC 8467 §4.1).
        assert_eq!(
            reply.to_vec().expect("encodes").len() % 468,
            0,
            "{transport:?}"
        );
    }
}

#[test]
fn a_certificate_from_another_authority_is_refused() {
    let upstream = Responder::start(&["a"]);
    let (server, ..) = listening(&certificates(), upstream.addr);
    let other = certificates();
    for transport in [Transport::Tls, Transport::Quic] {
        assert!(
            ask(server.addr, transport, &other).is_err(),
            "{transport:?}"
        );
    }
}

/// D66: a reload reads the certificate files again; the next handshakes present the new certificate.
#[cfg(unix)]
#[test]
fn a_reload_replaces_the_certificate() {
    let upstream = Responder::start(&["a"]);
    let (old, new) = (certificates(), certificates());
    let (mut server, certificate, key) = listening(&old, upstream.addr);
    std::fs::write(&certificate, &new.server_pem).expect("the certificate replaced");
    crate::util::write_key(&key, &new.key_pem);
    server.hang_up();
    assert!(server.event("reloaded").is_some());
    for transport in [Transport::Tls, Transport::Quic] {
        assert!(ask(server.addr, transport, &new).is_ok(), "{transport:?}");
        assert!(ask(server.addr, transport, &old).is_err(), "{transport:?}");
    }
}

/// D115: a key file others can read stops the start and a reload, which serves the previous configuration on; one
/// its group can read is warned about.
#[cfg(unix)]
#[test]
fn a_key_readable_by_others_is_refused() {
    use std::os::unix::fs::PermissionsExt as _;
    let upstream = Responder::start(&["a"]);
    let ca = certificates();
    let (mut server, _, key) = listening(&ca, upstream.addr);
    let text = std::fs::read_to_string(&server.config).expect("its configuration");
    let mode = |mode| {
        std::fs::set_permissions(&key, std::fs::Permissions::from_mode(mode)).expect("mode set");
    };
    mode(0o644);
    let (code, stderr) = crate::util::validate(&text);
    assert_eq!(code, Some(1), "{stderr}");
    assert!(stderr.contains("by others"), "{stderr}");
    server.hang_up();
    let failed = server
        .event("reload failed, serving the previous configuration")
        .expect("the failure logged");
    let error = failed["fields"]["error"].as_str().expect("its error");
    assert!(error.contains("by others"), "{error}");
    assert!(ask(server.addr, Transport::Tls, &ca).is_ok());
    mode(0o640);
    let (code, stderr) = crate::util::validate(&text);
    assert_eq!(code, Some(0), "{stderr}");
    // The key is owned by the user running the test. `guard_key` warns of its group unless the key is root-owned and
    // the process is root (which reads any key, the read after the drop being the check), so as root it stays quiet.
    let warned = !nix::unistd::geteuid().is_root();
    assert_eq!(stderr.contains("by its group"), warned, "{stderr}");
    server.hang_up();
    assert!(server.event("reloaded").is_some());
    mode(0o600);
    let (code, stderr) = crate::util::validate(&text);
    assert_eq!(code, Some(0), "{stderr}");
    assert!(!stderr.contains("by its group"), "{stderr}");
}

/// D115, D122: a key its group can read is warned about once at the start, the configuration being read again only
/// after a drop to `user`. Root is not warned of a key it owns (see above), so the test skips as root.
#[cfg(unix)]
#[test]
fn a_key_readable_by_its_group_is_warned_about_once() {
    use std::os::unix::fs::PermissionsExt as _;
    if nix::unistd::geteuid().is_root() {
        return eprintln!("skipped: not as root");
    }
    let upstream = Responder::start(&["a"]);
    let (certificate, key) = write_pems(&certificates(), &write_config(""));
    std::fs::set_permissions(&key, std::fs::Permissions::from_mode(0o640)).expect("mode set");
    let server = serving(&certificate, &key, upstream.addr);
    let stderr = server.stderr();
    let warnings = stderr
        .iter()
        .filter(|line| line.contains("by its group"))
        .count();
    assert_eq!(warnings, 1, "{stderr:?}");
}

/// A UDP relay in front of `server`, and the first byte of each datagram the server sends through it.
fn relay(server: SocketAddr) -> (SocketAddr, mpsc::Receiver<u8>) {
    let front = Arc::new(UdpSocket::bind("127.0.0.1:0").expect("a UDP port"));
    let back = Arc::new(UdpSocket::bind("127.0.0.1:0").expect("a UDP port"));
    back.connect(server).expect("connected");
    let addr = front.local_addr().expect("its address");
    let client = Arc::new(Mutex::new(None));
    let (first, bytes) = mpsc::channel();
    // The relay lives as long as the test process: both threads block on their sockets.
    thread::spawn({
        let (front, back, client) = (Arc::clone(&front), Arc::clone(&back), Arc::clone(&client));
        move || {
            let mut buf = vec![0; 65535];
            while let Ok((len, from)) = front.recv_from(&mut buf) {
                *client.lock().expect("not poisoned") = Some(from);
                let _ = back.send(&buf[..len]);
            }
        }
    });
    thread::spawn(move || {
        let mut buf = vec![0; 65535];
        while let Ok(len) = back.recv(&mut buf) {
            let _ = first.send(buf[0]);
            let to = *client.lock().expect("not poisoned");
            if let Some(to) = to {
                let _ = front.send_to(&buf[..len], to);
            }
        }
    });
    (addr, bytes)
}

/// D27, D84: a QUIC client at an address not yet validated is sent a Retry (RFC 9000 §8.1.2) before the server
/// keeps any state or takes a connection slot, and connects once it answers it: spoofed Initials cost a packet.
#[test]
fn an_unvalidated_quic_client_is_sent_a_retry() {
    let upstream = Responder::start(&["a"]);
    let ca = certificates();
    let (server, ..) = listening(&ca, upstream.addr);
    let (addr, first_bytes) = relay(server.addr);
    ask(addr, Transport::Quic, &ca).expect("an answer after the retry");
    let first = first_bytes
        .recv_timeout(Duration::from_secs(10))
        .expect("a datagram from the server");
    // A long header (bit 7) of the type Retry, 0b11 in bits 5-4 (RFC 9000 §17.2): not an Initial, 0b00. The fixed
    // bit (6) may be greased (RFC 9287).
    assert_eq!(first & 0xB0, 0xB0, "the first byte {first:#04x}");
}

/// A `DoQ` connection to `addr` of a client that pings every second, so that only the server's own timers end it, with
/// `window` bytes of flow control credit for what the server sends.
async fn pinging(addr: SocketAddr, ca: &Certificates, window: u32) -> Connection {
    let mut roots = RootCertStore::empty();
    roots.add(ca.ca.clone()).expect("a root");
    let mut tls = TlsConfig::builder_with_provider(Arc::new(ring::default_provider()))
        .with_protocol_versions(&[&TLS13])
        .expect("TLS 1.3")
        .with_root_certificates(roots)
        .with_no_client_auth();
    tls.alpn_protocols = vec![b"doq".to_vec()];
    let tls = QuicClientConfig::try_from(tls).expect("QUIC's initial suite");
    let mut transport = TransportConfig::default();
    transport
        .keep_alive_interval(Some(Duration::from_secs(1)))
        .max_idle_timeout(IdleTimeout::try_from(Duration::from_secs(60)).ok())
        .max_concurrent_uni_streams(VarInt::from_u32(0))
        .stream_receive_window(VarInt::from_u32(window))
        .receive_window(VarInt::from_u32(window));
    let mut config = ClientConfig::new(Arc::new(tls));
    config.transport_config(Arc::new(transport));
    let endpoint = Endpoint::client(("127.0.0.1", 0))
        .await
        .expect("an endpoint");
    endpoint
        .connect(addr, NAME, Some(config))
        .expect("connecting")
        .await
        .expect("connected")
}

/// D47: a QUIC connection without a new stream for the idle time is closed, though its client keeps it alive with
/// pings, as a TCP one without a query is.
#[test]
fn a_quic_connection_without_a_query_is_closed_though_pinged() {
    let upstream = Responder::start(&["a"]);
    let ca = certificates();
    let (server, ..) = listening(&ca, upstream.addr);
    Runtime::new().expect("a runtime").block_on(async {
        let connection = pinging(server.addr, &ca, 1 << 20).await;
        let start = Instant::now();
        compio::time::timeout(Duration::from_secs(30), connection.closed())
            .await
            .expect("closed by the server");
        let lasted = start.elapsed();
        assert!(lasted < Duration::from_secs(15), "{lasted:?}");
    });
}

/// RFC 9250 §4.2.1, §4.3.3: a query with a Message ID other than 0 is a protocol error: no reply, and the connection is
/// closed with `DOQ_PROTOCOL_ERROR`, 2.
#[test]
fn a_quic_query_with_a_message_id_is_a_protocol_error() {
    let upstream = Responder::start(&["a"]);
    let ca = certificates();
    let (server, ..) = listening(&ca, upstream.addr);
    Runtime::new().expect("a runtime").block_on(async {
        let connection = pinging(server.addr, &ca, 1 << 20).await;
        let (mut send, mut recv) = connection.open_bi_wait().await.expect("a stream");
        let query = framed(&query_for("a", 1));
        send.write_all(query).await.0.expect("the query sent");
        send.finish().expect("finished");
        let closed = compio::time::timeout(Duration::from_secs(10), connection.closed())
            .await
            .expect("closed by the server");
        assert!(
            matches!(&closed, ConnectionError::ApplicationClosed(close) if close.error_code == VarInt::from_u32(2)),
            "{closed:?}"
        );
        assert!(read_message(&mut recv).await.is_err(), "no reply came");
    });
}

/// D47: a reply that its client has no credit to receive is given up after the write time, as on TCP: the stream
/// is reset and the connection closes.
#[test]
fn a_quic_reply_the_client_does_not_read_is_given_up() {
    let upstream = Responder::start(&["a"]);
    let ca = certificates();
    let (server, ..) = listening(&ca, upstream.addr);
    Runtime::new().expect("a runtime").block_on(async {
        let connection = pinging(server.addr, &ca, 0).await;
        let (mut send, mut recv) = connection.open_bi_wait().await.expect("a stream");
        let query = framed(&query_for("a", 0));
        send.write_all(query).await.0.expect("the query sent");
        send.finish().expect("finished");
        let read = compio::time::timeout(Duration::from_secs(30), read_message(&mut recv)).await;
        assert!(read.expect("an end within 30 s").is_err(), "no reply came");
        connection.close(VarInt::from_u32(0), b"");
    });
}

// --- `dedensd` over real sockets on loopback ---

#[test]
fn queries_over_udp_and_tcp_are_forwarded() {
    let response = captured("a");
    let upstream = decode(&response);
    // No minimum TTL: the records come back as captured.
    let server = Server::start(Responder::start(&["a"]).addr, "    min_ttl: 0\n");
    let reply = ask_udp(server.addr, &query_for("a", 1));
    assert_eq!((reply.header.id, reply.rcode()), (1, Rcode::NOERROR));
    assert_eq!(reply.answer, upstream.answer);
    let reply = ask_tcp(server.addr, &query_for("a", 2));
    assert_eq!((reply.header.id, reply.rcode()), (2, Rcode::NOERROR));
    assert_eq!(reply.answer, upstream.answer);
}

/// D115: `threads` sets the serving threads, which the "serving" event counts; more than one needs Linux, where
/// `SO_REUSEPORT` spreads queries.
#[test]
fn threads_set_the_serving_threads() {
    let upstream = Responder::start(&["a"]);
    let threads: u64 = if cfg!(target_os = "linux") { 3 } else { 1 };
    let server = Server::configured(|listen| {
        format!(
            "threads: {threads}\nlisten: ['{listen}']\npipeline: [up]\nstages:\n  up:\n    type: forward\n    servers: ['{}']\n    timeout_ms: 1000\n    tries: 1\n",
            upstream.addr
        )
    });
    assert_eq!(server.serving["fields"]["threads"], threads);
    let reply = ask_udp(server.addr, &query_for("a", 1));
    assert_eq!(reply.rcode(), Rcode::NOERROR);
}

#[test]
fn a_tcp_connection_answers_several_queries() {
    let server = Server::start(Responder::start(&["a"]).addr, "");
    // The opcode is bits 1 to 4 of the third byte (RFC 1035 §4.1.1).
    let mut notify = query_for("a", 3);
    notify[2] = notify[2] & 0x87 | Opcode::NOTIFY.0 << 3;
    let mut stream = TcpStream::connect(server.addr).expect("connected");
    for query in [query_for("a", 1), query_for("a", 2), notify] {
        stream.write_all(&framed(&query)).expect("sent");
    }
    let mut replies: Vec<_> = (0..3)
        .map(|_| {
            let reply = decode(&read_framed(&mut stream).expect("a reply"));
            (reply.header.id, reply.rcode())
        })
        .collect();
    replies.sort_unstable();
    assert_eq!(
        replies,
        [(1, Rcode::NOERROR), (2, Rcode::NOERROR), (3, Rcode::NOTIMP)]
    );
}

#[test]
fn a_silent_upstream_gets_servfail() {
    let (_socket, upstream) = silent();
    let server = Server::start(upstream, "");
    let reply = ask_udp(server.addr, &query_for("a", 1));
    assert_eq!((reply.header.id, reply.rcode()), (1, Rcode::SERVFAIL));
}

/// D107: the start says which driver the threads run on, as compio falls back from `io_uring` to `poll` without
/// anyone seeing (D51). Linux has `io_uring` from 5.19, the floor: `poll` there fails the test, unless
/// `DEDENS_TEST_ALLOW_POLL` is set, for a container whose seccomp filter refuses `io_uring`.
#[test]
fn the_start_logs_the_driver() {
    let (_socket, upstream) = silent();
    let server = Server::start(upstream, "");
    let driver = server.serving["fields"]["driver"].as_str();
    let known: &[_] = if !cfg!(target_os = "linux") {
        &["poll", "iocp"]
    } else if std::env::var_os("DEDENS_TEST_ALLOW_POLL").is_some() {
        &["io_uring", "poll"]
    } else {
        &["io_uring"]
    };
    assert!(
        driver.is_some_and(|driver| known.contains(&driver)),
        "{driver:?}"
    );
}

/// D157: SIGTERM and SIGINT end the server at once, with success and its reason logged; as PID 1 of the image the
/// kernel would drop either without a handler.
#[cfg(unix)]
#[test]
fn sigterm_and_sigint_end_the_server() {
    for (name, signal) in [("TERM", "SIGTERM"), ("INT", "SIGINT")] {
        let (_socket, upstream) = silent();
        let mut server = Server::start(upstream, "");
        server.signal(name);
        let stopped = server.event("dedensd ends: stopped").expect("logged");
        assert_eq!(stopped["fields"]["signal"], signal);
        let status = server.exited().expect("exited");
        assert!(status.success(), "{signal}: {status}");
    }
}

#[test]
fn a_taken_address_fails_the_start() {
    let taken = UdpSocket::bind("127.0.0.1:0").expect("a UDP port");
    let addr = taken.local_addr().expect("its address").to_string();
    let output = Command::new(env!("CARGO_BIN_EXE_dedensd"))
        .arg("--config")
        .arg(config(&addr, "127.0.0.1", ""))
        .output()
        .expect("dedensd runs");
    assert_eq!(output.status.code(), Some(1));
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains(&format!("cannot bind UDP {addr}")),
        "{stderr}"
    );
}

/// D169: text events are coloured as anstream decides for stderr, which `NO_COLOR` and `CLICOLOR_FORCE` steer. The
/// warning that no `access` is configured comes before the bind that fails.
#[test]
fn text_events_follow_the_colour_variables() {
    let taken = UdpSocket::bind("0.0.0.0:0").expect("a UDP port");
    let addr = taken.local_addr().expect("its address").to_string();
    let config = config(&addr, "127.0.0.1", "");
    let stderr = |variable: &str| {
        let output = Command::new(env!("CARGO_BIN_EXE_dedensd"))
            .args(["--log-format", "text", "--config"])
            .arg(&config)
            .env_remove("NO_COLOR")
            .env("CLICOLOR_FORCE", "1")
            .env(variable, "1")
            .output()
            .expect("dedensd runs");
        let stderr = String::from_utf8_lossy(&output.stderr).into_owned();
        assert!(stderr.contains("no `access` configured"), "{stderr}");
        stderr
    };
    assert!(stderr("CLICOLOR_FORCE").contains("\u{1b}["));
    assert!(!stderr("NO_COLOR").contains("\u{1b}["));
}

#[test]
fn validate_reads_the_configuration_without_binding() {
    let taken = UdpSocket::bind("127.0.0.1:0").expect("a UDP port");
    let path = config(
        &taken.local_addr().expect("its address").to_string(),
        "${UPSTREAM}",
        "",
    );
    let validate = |upstream: Option<&str>| {
        let mut command = Command::new(env!("CARGO_BIN_EXE_dedensd"));
        command.arg("validate").arg("--config").arg(&path);
        match upstream {
            Some(upstream) => command.env("UPSTREAM", upstream),
            None => command.env_remove("UPSTREAM"),
        };
        command.output().expect("dedensd runs")
    };
    let output = validate(Some("127.0.0.1"));
    assert_eq!(output.status.code(), Some(0));
    assert!(String::from_utf8_lossy(&output.stdout).ends_with(": valid\n"));
    let output = validate(None);
    assert_eq!(output.status.code(), Some(1));
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("variable `UPSTREAM` is not set"),
        "{stderr}"
    );
}

/// The extended error codes of `reply`.
fn errors(reply: &Message<'_>) -> Vec<InfoCode> {
    let options = reply.edns.iter().flat_map(|edns| &edns.options);
    options
        .filter_map(|option| match option {
            EdnsOption::Ede(error) => Some(error.code),
            _ => None,
        })
        .collect()
}

#[test]
fn a_client_kept_waiting_gets_expired_data_and_the_next_one_fresh_data() {
    let upstream = Responder::slow("a", 3, Duration::from_millis(500));
    // No minimum TTL, which would keep the 3 seconds of the answer fresh for a minute.
    let server = Server::start(
        upstream.addr,
        "    min_ttl: 0\n    stale_answer_after_ms: 200\n",
    );
    let first = ask_udp(server.addr, &query_for("a", 1));
    assert_eq!(errors(&first), []);
    // Past the TTL, upstream answers 500 ms late, within the 1 s timeout: expired data answers once the 200 ms
    // timer runs out.
    thread::sleep(Duration::from_millis(3200));
    let asked = Instant::now();
    let stale = ask_udp(server.addr, &query_for("a", 2));
    assert!(
        (Duration::from_millis(200)..Duration::from_millis(450)).contains(&asked.elapsed()),
        "{:?}",
        asked.elapsed()
    );
    assert_eq!((stale.header.id, stale.rcode()), (2, Rcode::NOERROR));
    assert_eq!(errors(&stale), [InfoCode::STALE_ANSWER]);
    assert!(stale.answer.iter().all(|record| record.ttl.get() == 30));
    // Resolution went on and refreshed the entry.
    thread::sleep(Duration::from_millis(800));
    let fresh = ask_udp(server.addr, &query_for("a", 3));
    assert_eq!((upstream.queries().len(), errors(&fresh)), (2, vec![]));
    assert!(fresh.answer.iter().all(|record| record.ttl.get() <= 3));
}

mod upstreams {
    //! Upstream servers over TLS (RFC 7858) and QUIC (RFC 9250), given as `tls://` and `quic://` (D65), checked
    //! against `upstream_ca`: asked whatever transport the client came over, on one connection.

    use std::path::Path;

    use dedens_proto::Rcode;
    use dedens_testkit::captured;
    use dedens_testkit::certificates::NAME;
    use dedens_testkit::responder::{Responder, Transport};

    use crate::util::{Server, ask_tcp, ask_udp, decode, query_for};

    /// `dedensd` forwarding to `upstream` alone, trusting the certificate authority of `ca`.
    fn forwarding(upstream: &str, ca: &Path) -> Server {
        Server::configured(|listen| {
            format!(
                "listen: ['{listen}']\nupstream_ca: '{}'\npipeline: [up]\nstages:\n  up:\n    type: forward\n    servers: ['{upstream}']\n    timeout_ms: 2000\n    tries: 1\n",
                ca.display()
            )
        })
    }

    #[test]
    fn encrypted_upstream_servers_answer_clients_over_udp_and_tcp() {
        let response = captured("a");
        let upstream = decode(&response);
        for (scheme, transport, (responder, ca)) in [
            ("tls", Transport::Tls, Responder::tls(&["a"])),
            ("quic", Transport::Quic, Responder::quic(&["a"])),
        ] {
            let server = forwarding(&format!("{scheme}://{}#{NAME}", responder.addr), ca.path());
            let reply = ask_udp(server.addr, &query_for("a", 1));
            assert_eq!(
                (reply.rcode(), &reply.answer),
                (Rcode::NOERROR, &upstream.answer),
                "{scheme}"
            );
            let reply = ask_tcp(server.addr, &query_for("a", 2));
            assert_eq!(
                (reply.rcode(), &reply.answer),
                (Rcode::NOERROR, &upstream.answer),
                "{scheme}"
            );
            let transports: Vec<_> = responder
                .queries()
                .into_iter()
                .map(|(over, _)| over)
                .collect();
            assert_eq!(transports, [transport; 2], "{scheme}");
        }
    }

    /// D84: an upstream server behind `https://` is asked over HTTP/3 by GET (RFC 8484 §4.1), at its path or
    /// `/dns-query`, whatever transport the client came over.
    #[test]
    fn an_https_upstream_server_answers_clients_over_udp_and_tcp() {
        let response = captured("a");
        let upstream = decode(&response);
        let (responder, ca) = Responder::https(&["a"]);
        for path in ["", "/doh"] {
            let server = forwarding(
                &format!("https://{}{path}#{NAME}", responder.addr),
                ca.path(),
            );
            for (id, ask) in [(1, ask_udp as fn(_, &_) -> _), (2, ask_tcp)] {
                let reply = ask(server.addr, &query_for("a", id));
                assert_eq!(
                    (reply.rcode(), &reply.answer),
                    (Rcode::NOERROR, &upstream.answer),
                    "{path}"
                );
            }
        }
        let transports: Vec<_> = responder
            .queries()
            .into_iter()
            .map(|(over, _)| over)
            .collect();
        assert_eq!(transports, [Transport::HttpsGet; 4]);
    }

    /// RFC 8310 §8.1: without a name given, the certificate must hold the address, which the responder's does.
    #[test]
    fn a_certificate_is_checked_against_the_name_given_else_the_address() {
        let (responder, ca) = Responder::tls(&["a"]);
        let server = forwarding(&format!("tls://{}", responder.addr), ca.path());
        let reply = ask_udp(server.addr, &query_for("a", 1));
        assert_eq!(reply.rcode(), Rcode::NOERROR);
        let server = forwarding(
            &format!("tls://{}#other.example", responder.addr),
            ca.path(),
        );
        let reply = ask_udp(server.addr, &query_for("a", 2));
        assert_eq!(reply.rcode(), Rcode::SERVFAIL);
    }
}

#[cfg(unix)]
mod tcp_frames {
    //! RFC 7766 on `dedensd`'s TCP listener, §6.2.3 and §8: a connection that sends a broken frame costs nothing but its
    //! slot. A length prefix with no message behind it (the frame that made aardvark-dns spin at 100% CPU,
    //! CVE-2026-35406), a length of 0, half a prefix, and a message that trickles in all end the connection, or leave it
    //! to the idle close (D47); a full frame holding a message that does not read gets FORMERR and the connection
    //! stays. Meanwhile a second client's UDP and TCP queries are answered, and the server's CPU time does not grow.

    use std::io::{ErrorKind, Read, Write};
    use std::net::TcpStream;
    use std::process::Command;
    use std::thread::{self, JoinHandle};
    use std::time::{Duration, Instant};

    use dedens_proto::Rcode;
    use dedens_testkit::responder::Responder;

    use crate::util::{Server, ask_tcp, ask_udp, decode, framed, query_for, read_framed};

    /// The idle time of a TCP connection (D47).
    const IDLE: Duration = Duration::from_secs(10);

    /// How long a connection may last past [`IDLE`]: a loaded machine reads late, it does not hold a connection open.
    const SLACK: Duration = Duration::from_secs(20);

    /// How long the server's CPU time is watched.
    const WINDOW: Duration = Duration::from_secs(4);

    /// The CPU time the server may use in [`WINDOW`]: `ps` gives whole seconds on Linux, so a few milliseconds of work
    /// can show as one, where a thread spinning for [`WINDOW`] shows at least three. CPU time, not queries answered late,
    /// because it does not move with the load of the machine.
    const CPU_LIMIT: f64 = 2.0;

    /// A server forwarding to a responder, and the query both clients ask.
    struct Fixture {
        server: Server,
        query: Vec<u8>,
        _upstream: Responder,
    }

    impl Fixture {
        fn start() -> Self {
            let upstream = Responder::start(&["a"]);
            let fixture = Self {
                server: Server::start(upstream.addr, ""),
                query: query_for("a", 1),
                _upstream: upstream,
            };
            fixture.assert_served();
            fixture
        }

        /// A second client, over UDP and over a new TCP connection, gets its answer.
        fn assert_served(&self) {
            for reply in [
                ask_udp(self.server.addr, &self.query),
                ask_tcp(self.server.addr, &self.query),
            ] {
                assert_eq!((reply.header.id, reply.rcode()), (1, Rcode::NOERROR));
            }
        }

        /// The CPU seconds the server used so far.
        fn cpu(&self) -> f64 {
            let output = Command::new("ps")
                .args(["-o", "time=", "-p", &self.server.pid().to_string()])
                .output()
                .expect("ps runs");
            let text = String::from_utf8(output.stdout).expect("ps writes text");
            // `[DD-][[hh:]mm:]ss[.cc]`, the CPU time of every thread, on Linux and on macOS.
            let (days, clock) = text.trim().split_once('-').unwrap_or(("0", text.trim()));
            let number = |text: &str| text.parse::<f64>().expect("a number of ps's time");
            let clock = clock
                .split(':')
                .fold(0.0, |total, part| total * 60.0 + number(part));
            number(days) * 86400.0 + clock
        }

        /// The server answers a second client at both ends of [`WINDOW`], and used less than [`CPU_LIMIT`] seconds of
        /// CPU since `before`, a reading of [`Fixture::cpu`].
        fn assert_unharmed(&self, before: f64) {
            self.assert_served();
            thread::sleep(WINDOW);
            self.assert_served();
            let used = self.cpu() - before;
            assert!(used < CPU_LIMIT, "{used} s of CPU in {WINDOW:?}");
        }
    }

    /// Reads `stream` until the server closes it, each second writing a byte if `trickle`, on a thread: its time. The
    /// server sends nothing more, and closes within [`IDLE`] and [`SLACK`].
    fn until_closed(mut stream: TcpStream, trickle: bool) -> JoinHandle<Duration> {
        stream
            .set_read_timeout(Some(Duration::from_secs(1)))
            .expect("a timeout");
        thread::spawn(move || {
            let start = Instant::now();
            loop {
                assert!(
                    start.elapsed() < IDLE + SLACK,
                    "open after {:?}",
                    start.elapsed()
                );
                if trickle && stream.write_all(&[0]).is_err() {
                    return start.elapsed();
                }
                match stream.read(&mut [0; 1]) {
                    Ok(read) => {
                        assert_eq!(read, 0, "the server wrote to a broken connection");
                        return start.elapsed();
                    }
                    Err(error)
                        if matches!(error.kind(), ErrorKind::WouldBlock | ErrorKind::TimedOut) => {}
                    // Reset: closed with the bytes we sent unread.
                    Err(_) => return start.elapsed(),
                }
            }
        })
    }

    /// A connection to the server, which `bytes` open: sent as they are. A reply that does not come fails the test
    /// within 10 s, as in [`ask_tcp`], and does not hang it.
    fn connect(fixture: &Fixture, bytes: &[u8]) -> TcpStream {
        let mut stream = TcpStream::connect(fixture.server.addr).expect("connected");
        stream
            .set_read_timeout(Some(Duration::from_secs(10)))
            .expect("a timeout");
        stream.write_all(bytes).expect("sent");
        stream
    }

    /// The length of a 60-byte message, as aardvark-dns's test sends it.
    const SIXTY: [u8; 2] = 60_u16.to_be_bytes();

    /// A length with nothing behind it, the client gone: the connection ends, and no thread spins.
    #[test]
    fn a_length_alone_then_a_close_costs_no_cpu() {
        let fixture = Fixture::start();
        let before = fixture.cpu();
        drop(connect(&fixture, &SIXTY));
        fixture.assert_unharmed(before);
    }

    /// The same, the client silent and not gone: the idle close ends it, while others are served.
    #[test]
    fn a_length_alone_then_silence_is_closed_by_the_idle_time() {
        let fixture = Fixture::start();
        let before = fixture.cpu();
        let closed = until_closed(connect(&fixture, &SIXTY), false);
        fixture.assert_unharmed(before);
        closed.join().expect("closed within the idle time");
    }

    /// Half of a length (RFC 7766 §8: a message may arrive in pieces), the client gone.
    #[test]
    fn one_byte_of_a_length_then_a_close_costs_no_cpu() {
        let fixture = Fixture::start();
        let before = fixture.cpu();
        drop(connect(&fixture, &SIXTY[..1]));
        fixture.assert_unharmed(before);
    }

    /// A length of 0 is an empty message: it reads nothing, as a UDP datagram of no bytes, is not answered, and leaves
    /// the connection to the next message and then to the idle close.
    #[test]
    fn a_length_of_zero_is_skipped_and_the_connection_idles_out() {
        let fixture = Fixture::start();
        let before = fixture.cpu();
        let mut stream = connect(&fixture, &framed(&[]));
        stream.write_all(&framed(&fixture.query)).expect("sent");
        // The first reply is the query's, so the empty message got none.
        let reply = decode(&read_framed(&mut stream).expect("a reply"));
        assert_eq!((reply.header.id, reply.rcode()), (1, Rcode::NOERROR));
        let closed = until_closed(stream, false);
        fixture.assert_unharmed(before);
        closed.join().expect("closed within the idle time");
    }

    /// A length promising more than comes, a byte a second: the time of the whole message is limited, not the time
    /// between bytes, so the connection is closed long before the 60 bytes are in.
    #[test]
    fn a_message_trickling_in_is_closed_by_the_idle_time() {
        let fixture = Fixture::start();
        let before = fixture.cpu();
        let closed = until_closed(connect(&fixture, &SIXTY), true);
        fixture.assert_unharmed(before);
        let open = closed.join().expect("closed within the idle time");
        assert!(open < Duration::from_secs(60), "{open:?}");
    }

    /// A frame whole, holding a header that counts a question and carries none: FORMERR to it (RFC 1035 §4.1.1), and the
    /// connection stays for the next query, and for the idle close.
    #[test]
    fn a_whole_frame_of_a_malformed_message_gets_formerr_and_the_connection_stays() {
        let fixture = Fixture::start();
        let before = fixture.cpu();
        // The header of the query, which counts one question: QDCOUNT is its bytes 4 and 5.
        let header = &fixture.query[..12];
        assert_eq!(header[4..6], [0, 1]);
        let mut stream = connect(&fixture, &framed(header));
        let reply = decode(&read_framed(&mut stream).expect("a reply"));
        assert_eq!((reply.header.id, reply.rcode()), (1, Rcode::FORMERR));
        stream.write_all(&framed(&fixture.query)).expect("sent");
        let reply = decode(&read_framed(&mut stream).expect("a second reply"));
        assert_eq!((reply.header.id, reply.rcode()), (1, Rcode::NOERROR));
        let closed = until_closed(stream, false);
        fixture.assert_unharmed(before);
        closed.join().expect("closed within the idle time");
    }
}
