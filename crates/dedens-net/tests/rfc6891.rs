//! RFC 6891 §7: a server that answers an EDNS query with FORMERR or NOTIMP and no OPT record does not know EDNS;
//! the query goes again without it, once.

mod common;

use common::{
    expect_response, expect_send, query, query_with_cookie, response, sent, start, t0, udp, wire,
};
use dedens_net::exchange::Options;
use dedens_proto::{Message, Rcode};

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
        assert_eq!(plain.header, query.header);
        assert_eq!(exchange.sends(), 2);

        // Once only: the same answer to the plain query is the response.
        let answer = without_edns(&plain, rcode);
        let got = expect_response(udp(exchange, &answer, now));
        assert_eq!(got.wire, answer);
        assert_eq!(got.query, wire(&plain));
    }
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
