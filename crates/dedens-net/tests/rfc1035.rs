//! RFC 1035 §4.2.1 and RFC 1123 §6.1.3.2: a query without a response is sent again, a few times, then the
//! exchange gives up. dig's numbers (D27): 3 tries, 5 s each.

mod common;

use std::num::NonZeroU8;

use common::{
    expect_failure, expect_response, expect_send, expect_wait, query, response, secs, start, t0,
    udp, wire,
};
use dedens_net::exchange::{Failure, Options};
use dedens_proto::Rcode;

#[test]
fn nothing_happens_before_the_deadline() {
    let now = t0();
    let exchange = start(&query(), Options::default(), now);
    assert_eq!(exchange.deadline(), now + secs(5));
    let exchange = expect_wait(exchange.time_out(now + secs(4)));
    assert_eq!(exchange.sends(), 1);
}

#[test]
fn a_timeout_sends_the_same_query_again() {
    let now = t0();
    let exchange = start(&query(), Options::default(), now);
    let first = exchange.wire().to_vec();
    let exchange = expect_send(exchange.time_out(now + secs(5)));
    assert_eq!(exchange.wire(), first);
    assert_eq!(exchange.sends(), 2);
    assert_eq!(exchange.deadline(), now + secs(10));
}

#[test]
fn three_tries_then_the_exchange_fails() {
    let now = t0();
    let mut exchange = start(&query(), Options::default(), now);
    for n in 1..=2 {
        exchange = expect_send(exchange.time_out(now + secs(5 * n)));
    }
    let failure = expect_failure(exchange.time_out(now + secs(15)));
    assert_eq!(failure, Failure::TimedOut { sends: 3 });
}

#[test]
fn a_timeout_too_long_for_a_clock_waits_a_century() {
    let now = t0();
    let mut options = Options::default();
    options.timeout = std::time::Duration::MAX;
    let exchange = start(&query(), options, now);
    assert!(exchange.deadline() > now + secs(3_000_000_000));
    let deadline = exchange.deadline();
    let exchange = expect_send(exchange.time_out(deadline));
    assert!(exchange.deadline() > deadline);
}

#[test]
fn tries_and_timeout_are_options() {
    let now = t0();
    let mut options = Options::default();
    options.tries = NonZeroU8::MIN;
    options.timeout = secs(1);
    let exchange = start(&query(), options, now);
    assert_eq!(exchange.deadline(), now + secs(1));
    assert_eq!(
        expect_failure(exchange.time_out(now + secs(1))),
        Failure::TimedOut { sends: 1 }
    );
}

#[test]
fn a_late_response_to_an_earlier_try_is_taken() {
    let now = t0();
    let query = query();
    let exchange = start(&query, Options::default(), now);
    let exchange = expect_send(exchange.time_out(now + secs(5)));
    let got = expect_response(udp(
        exchange,
        &wire(&response(&query, Rcode::NOERROR)),
        now + secs(6),
    ));
    assert_eq!(got.sends, 2);
    assert_eq!(got.rtt, secs(1));
}
