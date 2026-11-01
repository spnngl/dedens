//! Listening over TLS (RFC 7858) and QUIC (RFC 9250), on addresses behind `tls://` and `quic://` with the
//! certificate of `tls` (D66), replaced by a reload.

#[path = "../../../crates/dedens-net/tests/common/certificates.rs"]
#[allow(
    dead_code,
    reason = "shared with the tests of dedens-net, which use all of it"
)]
mod certificates;
mod common;

use std::net::{SocketAddr, UdpSocket};
use std::num::NonZero;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, mpsc};
use std::thread;
use std::time::Duration;

use certificates::{Certificates, NAME, certificates, named};
use common::{Responder, Server, captured, decode, query_for, write_config};
use compio::runtime::Runtime;
use dedens_net::client::{Client, ClientError};
use dedens_net::exchange::{Options, Transport};
use dedens_net::tls::Trust;
use dedens_proto::{Message, Rcode};

/// The certificate and key of `certificates` in PEM files beside the configuration file `config`.
fn write_pems(certificates: &Certificates, config: &Path) -> (PathBuf, PathBuf) {
    let (certificate, key) = (
        config.with_extension("crt.pem"),
        config.with_extension("key.pem"),
    );
    std::fs::write(&certificate, &certificates.server_pem).expect("the certificate written");
    std::fs::write(&key, &certificates.key_pem).expect("the key written");
    (certificate, key)
}

/// `dedensd` answering over TLS and QUIC on one port with the certificate of `certificates`, forwarding to
/// `upstream`.
fn listening(certificates: &Certificates, upstream: SocketAddr) -> (Server, PathBuf, PathBuf) {
    let (certificate, key) = write_pems(certificates, &write_config(""));
    let server = Server::configured(|listen| {
        format!(
            "listen: ['tls://{listen}', 'quic://{listen}']\ntls:\n  certificate: '{}'\n  key: '{}'\npipeline: [up]\nstages:\n  up:\n    type: forward\n    servers: ['{upstream}']\n    timeout_ms: 2000\n    tries: 1\n",
            certificate.display(),
            key.display()
        )
    });
    (server, certificate, key)
}

/// The reply of the server at `addr` over `transport`, its certificate checked against `ca`, to the query of the
/// `a` capture.
fn ask(
    addr: SocketAddr,
    transport: Transport,
    ca: &Certificates,
) -> Result<Message<'static>, ClientError> {
    let query = decode(&query_for(&captured("a"), 0));
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
    std::fs::write(&key, &new.key_pem).expect("the key replaced");
    server.hang_up();
    assert!(server.event("reloaded").is_some());
    for transport in [Transport::Tls, Transport::Quic] {
        assert!(ask(server.addr, transport, &new).is_ok(), "{transport:?}");
        assert!(ask(server.addr, transport, &old).is_err(), "{transport:?}");
    }
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
