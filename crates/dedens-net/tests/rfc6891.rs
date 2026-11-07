//! RFC 6891 §7: a server that answers an EDNS query with FORMERR or NOTIMP and no OPT record does not know EDNS;
//! the query goes again without it, once.

mod common;

use common::{
    SPARE_IDS, expect_response, expect_send, expect_wait, query, query_with_cookie, response, sent,
    server, start, t0, udp, wire,
};
use dedens_net::exchange::Options;
use dedens_proto::{Flags, Message, Rcode, Transport};

/// The response of a server without EDNS: `rcode` and no OPT record.
fn without_edns(query: &Message<'_>, rcode: Rcode) -> Vec<u8> {
    let mut answer = response(query, rcode);
    answer.edns = None;
    wire(&answer)
}

#[test]
fn formerr_or_notimp_without_opt_drops_edns_once() {
    for rcode in [Rcode::FORMERR, Rcode::NOTIMP] {
        let now = t0();
        let query = query();
        let exchange = start(&query, Options::default(), now);
        let exchange = expect_send(udp(exchange, &without_edns(&query, rcode), now));
        let plain = sent(&exchange);
        assert_eq!(plain.edns, None);
        assert_eq!(plain.questions, query.questions);
        // The changed query goes with another ID (D114): a late response to the first cannot end the exchange.
        let mut header = query.header;
        header.id = SPARE_IDS[0];
        assert_eq!(plain.header, header);
        assert_eq!(exchange.sends(), 2);
        let late = without_edns(&query, rcode);
        let exchange = expect_wait(udp(exchange, &late, now));

        // Once only: the same answer to the plain query is the response.
        let answer = without_edns(&plain, rcode);
        let got = expect_response(udp(exchange, &answer, now));
        assert_eq!(got.wire, answer);
        assert_eq!(got.query, wire(&plain));
    }
}

/// D114: a server that sent OPT knows EDNS: a later FORMERR without one is a forgery or a glitch, not a reason
/// to drop EDNS.
#[test]
fn no_downgrade_once_the_server_showed_edns() {
    let now = t0();
    let query = query();
    let mut truncated = response(&query, Rcode::NOERROR);
    truncated.header.flags = truncated.header.flags.with(Flags::TC);
    let exchange = expect_send(udp(
        start(&query, Options::default(), now),
        &wire(&truncated),
        now,
    ));
    let asked = sent(&exchange);
    assert!(asked.edns.is_some());
    let answer = without_edns(&asked, Rcode::FORMERR);
    let got = expect_response(exchange.receive(server(), Transport::Tcp, answer.clone(), now));
    assert_eq!(got.wire, answer);
    assert_eq!(got.sends, 2);
}

#[test]
fn the_cookie_goes_with_edns() {
    let now = t0();
    let query = query_with_cookie(None);
    let exchange = start(&query, Options::default(), now);
    let exchange = expect_send(udp(exchange, &without_edns(&query, Rcode::FORMERR), now));
    assert_eq!(sent(&exchange).edns, None);
}

#[test]
fn formerr_with_opt_is_the_response() {
    let now = t0();
    let query = query();
    let answer = wire(&response(&query, Rcode::FORMERR));
    let got = expect_response(udp(start(&query, Options::default(), now), &answer, now));
    assert_eq!(got.wire, answer);
}

#[test]
fn other_errors_without_opt_are_the_response() {
    let now = t0();
    let query = query();
    for rcode in [Rcode::SERVFAIL, Rcode::REFUSED, Rcode::NXDOMAIN] {
        let answer = without_edns(&query, rcode);
        expect_response(udp(start(&query, Options::default(), now), &answer, now));
    }
}

#[test]
fn the_fallback_can_be_turned_off() {
    let now = t0();
    let query = query();
    let mut options = Options::default();
    options.edns_fallback = false;
    let answer = without_edns(&query, Rcode::FORMERR);
    expect_response(udp(start(&query, options, now), &answer, now));
}

#[test]
fn a_query_without_edns_has_nothing_to_drop() {
    let now = t0();
    let mut query = query();
    query.edns = None;
    let answer = without_edns(&query, Rcode::FORMERR);
    expect_response(udp(start(&query, Options::default(), now), &answer, now));
}
