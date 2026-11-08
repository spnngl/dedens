//! Upstream servers over TLS (RFC 7858) and QUIC (RFC 9250), given as `tls://` and `quic://` (D65), checked
//! against `upstream_ca`: asked whatever transport the client came over, on one connection.

mod common;

use std::path::Path;

use common::{Server, ask_tcp, ask_udp, decode, query_for};
use dedens_proto::Rcode;
use dedens_testkit::captured;
use dedens_testkit::certificates::NAME;
use dedens_testkit::responder::{Responder, Transport};

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
        let reply = ask_udp(server.addr, &query_for(&response, 1));
        assert_eq!(
            (reply.rcode(), &reply.answer),
            (Rcode::NOERROR, &upstream.answer),
            "{scheme}"
        );
        let reply = ask_tcp(server.addr, &query_for(&response, 2));
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
            let reply = ask(server.addr, &query_for(&response, id));
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
    let response = captured("a");
    let (responder, ca) = Responder::tls(&["a"]);
    let server = forwarding(&format!("tls://{}", responder.addr), ca.path());
    let reply = ask_udp(server.addr, &query_for(&response, 1));
    assert_eq!(reply.rcode(), Rcode::NOERROR);
    let server = forwarding(
        &format!("tls://{}#other.example", responder.addr),
        ca.path(),
    );
    let reply = ask_udp(server.addr, &query_for(&response, 2));
    assert_eq!(reply.rcode(), Rcode::SERVFAIL);
}
