//! RFC 7766 §5 and RFC 1035 §4.2.1: a truncated response over UDP sends the query again over TCP.

mod common;

use common::{expect_response, expect_send, query, response, server, start, t0, udp, wire};
use dedens_net::exchange::{Options, Transport};
use dedens_proto::{Flags, Rcode};

#[test]
fn a_truncated_response_moves_the_query_to_tcp() {
    let now = t0();
    let query = query();
    let exchange = start(&query, Options::default(), now);
    let mut truncated = response(&query, Rcode::NOERROR);
    truncated.header.flags = truncated.header.flags.with(Flags::TC);
    let exchange = expect_send(udp(exchange, &wire(&truncated), now));
    assert_eq!(exchange.transport(), Transport::Tcp);
    // The query again, with another ID (D114) and the TCP options (tests/rfc7828.rs).
    let mut over_tcp = common::sent(&exchange);
    over_tcp.edns.as_mut().expect("EDNS").options.clear();
    assert_eq!(over_tcp.header.id, common::SPARE_IDS[0]);
    over_tcp.header.id = query.header.id;
    assert_eq!(over_tcp, query);
    assert_eq!(exchange.sends(), 2);

    // The UDP socket is gone: only TCP counts now.
    let full = wire(&response(&common::sent(&exchange), Rcode::NOERROR));
    let exchange = common::expect_wait(udp(exchange, &full, now));
    let got = expect_response(exchange.receive(server(), Transport::Tcp, full.clone(), now));
    assert_eq!(got.transport, Transport::Tcp);
    assert_eq!(got.sends, 2);
}

/// dig's `+ignore`.
#[test]
fn without_tcp_fallback_a_truncated_response_is_the_response() {
    let now = t0();
    let query = query();
    let mut options = Options::default();
    options.tcp_fallback = false;
    let mut truncated = response(&query, Rcode::NOERROR);
    truncated.header.flags = truncated.header.flags.with(Flags::TC);
    let got = expect_response(udp(start(&query, options, now), &wire(&truncated), now));
    assert_eq!(got.transport, Transport::Udp);
    assert_eq!(got.wire, wire(&truncated));
}

#[test]
fn a_truncated_response_over_tcp_is_the_response() {
    let now = t0();
    let query = query();
    let mut options = Options::default();
    options.transport = Transport::Tcp;
    let exchange = start(&query, options, now);
    assert_eq!(exchange.transport(), Transport::Tcp);
    let mut truncated = response(&query, Rcode::NOERROR);
    truncated.header.flags = truncated.header.flags.with(Flags::TC);
    let got = expect_response(exchange.receive(server(), Transport::Tcp, wire(&truncated), now));
    assert_eq!(got.wire, wire(&truncated));
}

#[test]
fn over_tcp_the_source_address_is_the_connection() {
    let now = t0();
    let query = query();
    let mut options = Options::default();
    options.transport = Transport::Tcp;
    let exchange = start(&query, options, now);
    let other = "198.51.100.1:4242".parse().expect("a socket address");
    let full = wire(&response(&query, Rcode::NOERROR));
    expect_response(exchange.receive(other, Transport::Tcp, full.clone(), now));
}
