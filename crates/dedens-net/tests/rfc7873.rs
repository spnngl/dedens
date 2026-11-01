//! RFC 7873 §5.3, client side: a response must carry the client cookie sent, and once the server sent a cookie,
//! a cookie; its server cookie is kept; BADCOOKIE is retried with the fresh server cookie, then over TCP.

mod common;

use std::num::NonZeroU8;

use common::{
    CLIENT_COOKIE, cookie, cookie_of, expect_failure, expect_response, expect_send, expect_wait,
    query, query_with_cookie, response, secs, sent, server, start, t0, udp, wire,
};
use dedens_net::exchange::{Failure, Options, Transport};
use dedens_proto::edns::{Cookie, EdnsOption, OptionCode, UnknownOption};
use dedens_proto::{Message, Rcode};

const SERVER_COOKIE: &[u8] = b"server.cookie.01";

/// A response to `query` with `rcode` and these EDNS options.
fn with_options(query: &Message<'_>, rcode: Rcode, options: Vec<EdnsOption<'static>>) -> Vec<u8> {
    let mut answer = response(query, rcode);
    answer.edns.as_mut().expect("the query has EDNS").options = options;
    wire(&answer)
}

fn the_cookie(server: &[u8]) -> EdnsOption<'static> {
    EdnsOption::Cookie(cookie(Some(server)))
}

#[test]
fn the_server_cookie_comes_back_with_the_response() {
    let now = t0();
    let query = query_with_cookie(None);
    let answer = with_options(&query, Rcode::NOERROR, vec![the_cookie(SERVER_COOKIE)]);
    let got = expect_response(udp(start(&query, Options::default(), now), &answer, now));
    assert_eq!(got.cookie, Some(cookie(Some(SERVER_COOKIE))));
}

#[test]
fn the_server_cookie_is_kept_from_an_error_too() {
    let now = t0();
    let query = query_with_cookie(None);
    let answer = with_options(&query, Rcode::REFUSED, vec![the_cookie(SERVER_COOKIE)]);
    let got = expect_response(udp(start(&query, Options::default(), now), &answer, now));
    assert_eq!(got.cookie, Some(cookie(Some(SERVER_COOKIE))));
}

#[test]
fn a_wrong_client_cookie_is_dropped() {
    let now = t0();
    let query = query_with_cookie(None);
    let wrong = Cookie::new(*b"attacker", Some(SERVER_COOKIE)).expect("a valid cookie");
    let answer = with_options(&query, Rcode::NOERROR, vec![EdnsOption::Cookie(wrong)]);
    expect_wait(udp(start(&query, Options::default(), now), &answer, now));
}

/// The failure says why, unlike plain silence: a packet cache answering with an earlier client's cookie.
#[test]
fn an_exchange_with_only_wrong_cookies_fails_as_forged() {
    let now = t0();
    let query = query_with_cookie(None);
    let wrong = Cookie::new(*b"attacker", Some(SERVER_COOKIE)).expect("a valid cookie");
    let answer = with_options(&query, Rcode::NOERROR, vec![EdnsOption::Cookie(wrong)]);
    let mut options = Options::default();
    options.tries = NonZeroU8::MIN;
    let exchange = expect_wait(udp(start(&query, options, now), &answer, now));
    assert_eq!(
        expect_failure(exchange.time_out(now + secs(5))),
        Failure::Forged { sends: 1 }
    );
}

#[test]
fn a_cookie_of_invalid_length_is_dropped() {
    let now = t0();
    let query = query_with_cookie(None);
    // The client cookie and a 3-byte server cookie: 8 to 32 bytes are allowed (RFC 7873 §4).
    let mut data = CLIENT_COOKIE.to_vec();
    data.extend_from_slice(b"abc");
    let invalid =
        UnknownOption::new(OptionCode::COOKIE, &data).expect("an invalid cookie stays unknown");
    let answer = with_options(
        &query,
        Rcode::NOERROR,
        vec![EdnsOption::Unknown(invalid.into_owned())],
    );
    expect_wait(udp(start(&query, Options::default(), now), &answer, now));
}

#[test]
fn only_the_first_cookie_counts() {
    let now = t0();
    let query = query_with_cookie(None);
    let wrong = Cookie::new(*b"attacker", None).expect("a valid cookie");
    let first_right = with_options(
        &query,
        Rcode::NOERROR,
        vec![the_cookie(SERVER_COOKIE), EdnsOption::Cookie(wrong)],
    );
    let first_wrong = with_options(
        &query,
        Rcode::NOERROR,
        vec![EdnsOption::Cookie(wrong), the_cookie(SERVER_COOKIE)],
    );
    let exchange = start(&query, Options::default(), now);
    let exchange = expect_wait(udp(exchange, &first_wrong, now));
    let got = expect_response(udp(exchange, &first_right, now));
    assert_eq!(got.cookie, Some(cookie(Some(SERVER_COOKIE))));
}

#[test]
fn a_missing_cookie_is_dropped_once_the_server_sent_one() {
    let now = t0();
    let query = query_with_cookie(Some(SERVER_COOKIE));
    let mut plain = response(&query, Rcode::NOERROR);
    let exchange = start(&query, Options::default(), now);
    let exchange = expect_wait(udp(exchange, &wire(&plain), now));
    plain.edns = None;
    expect_wait(udp(exchange, &wire(&plain), now));
}

#[test]
fn a_missing_cookie_is_fine_from_a_server_without_cookies() {
    let now = t0();
    let query = query_with_cookie(None);
    let answer = wire(&response(&query, Rcode::NOERROR));
    let got = expect_response(udp(start(&query, Options::default(), now), &answer, now));
    assert_eq!(got.cookie, None);
}

#[test]
fn cookies_in_a_response_to_a_query_without_one_are_ignored() {
    let now = t0();
    let query = query();
    let wrong = Cookie::new(*b"attacker", None).expect("a valid cookie");
    let answer = with_options(&query, Rcode::NOERROR, vec![EdnsOption::Cookie(wrong)]);
    let got = expect_response(udp(start(&query, Options::default(), now), &answer, now));
    assert_eq!(got.cookie, None);
}

#[test]
fn badcookie_is_retried_with_the_fresh_cookie_then_over_tcp() {
    let now = t0();
    let query = query_with_cookie(Some(b"stale.server.ck"));
    let exchange = start(&query, Options::default(), now);

    let bad = |query: &Message<'_>, fresh: &[u8]| {
        with_options(query, Rcode::BADCOOKIE, vec![the_cookie(fresh)])
    };
    let exchange = expect_send(udp(exchange, &bad(&query, SERVER_COOKIE), now));
    assert_eq!(exchange.transport(), Transport::Udp);
    let retried = sent(&exchange);
    assert_eq!(
        cookie_of(exchange.wire()),
        Some(cookie(Some(SERVER_COOKIE)))
    );

    let newer = b"server.cookie.02";
    let exchange = expect_send(udp(exchange, &bad(&retried, newer), now));
    assert_eq!(exchange.transport(), Transport::Tcp);
    let over_tcp = sent(&exchange);
    assert_eq!(cookie_of(exchange.wire()), Some(cookie(Some(newer))));

    // A third BADCOOKIE is the response.
    let last = bad(&over_tcp, newer);
    let got = expect_response(exchange.receive(server(), Transport::Tcp, last, now));
    assert_eq!(got.sends, 3);
    assert_eq!(
        Message::decode(&got.wire)
            .expect("a response")
            .message
            .rcode(),
        Rcode::BADCOOKIE
    );
}

#[test]
fn badcookie_without_a_cookie_is_the_response() {
    let now = t0();
    let query = query();
    let answer = wire(&{
        let mut answer = response(&query, Rcode::NOERROR);
        answer.set_rcode(Rcode::BADCOOKIE).expect("EDNS");
        answer
    });
    expect_response(udp(start(&query, Options::default(), now), &answer, now));
}
