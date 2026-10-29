//! Listening over TLS (RFC 7858) and QUIC (RFC 9250), on addresses behind `tls://` and `quic://` with the
//! certificate of `tls` (D66), replaced by a reload.

#[path = "../../../crates/dedens-net/tests/common/certificates.rs"]
#[allow(
    dead_code,
    reason = "shared with the tests of dedens-net, which use all of it"
)]
mod certificates;
mod common;

use std::net::SocketAddr;
use std::num::NonZero;
use std::path::{Path, PathBuf};

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
