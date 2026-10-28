//! RFC 7828 §3.2.1: a query over TCP carries an empty edns-tcp-keepalive, one over UDP none.

mod common;

use common::{query, sent, start, t0};
use dedens_net::exchange::{Options, Transport};
use dedens_proto::Message;
use dedens_proto::edns::EdnsOption;

/// The query with an edns-tcp-keepalive of its own, which the exchange replaces.
fn with_keepalive() -> Message<'static> {
    let mut query = query();
    query.edns.as_mut().expect("EDNS").options = vec![EdnsOption::Keepalive(Some(5))];
    query
}

fn options(message: Message<'static>) -> Vec<EdnsOption<'static>> {
    message.edns.expect("EDNS").options
}

#[test]
fn over_udp_the_query_has_no_keepalive() {
    let exchange = start(&with_keepalive(), Options::default(), t0());
    assert_eq!(options(sent(&exchange)), Vec::new());
}

#[test]
fn over_tcp_the_query_has_one_empty_keepalive() {
    let mut tcp = Options::default();
    tcp.transport = Transport::Tcp;
    let exchange = start(&with_keepalive(), tcp, t0());
    assert_eq!(options(sent(&exchange)), vec![EdnsOption::Keepalive(None)]);
}
