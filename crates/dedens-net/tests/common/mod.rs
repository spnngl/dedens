//! Helpers shared by the exchange tests: messages are built with `dedens-proto`, time is made up.

#![allow(dead_code, reason = "each test file uses its own subset")]

pub(crate) mod loopback;

use std::net::SocketAddr;
use std::time::{Duration, Instant};

use dedens_net::exchange::{Exchange, Failure, Options, Progress, Response, Transport};
use dedens_proto::edns::{Cookie, EdnsOption};
use dedens_proto::{Flags, Message, Name, Question, Rcode, RecordType};

/// The server every test queries.
pub(crate) const SERVER: &str = "192.0.2.53:53";

/// The client cookie of the tests.
pub(crate) const CLIENT_COOKIE: [u8; 8] = *b"client.c";

pub(crate) fn server() -> SocketAddr {
    SERVER.parse().expect("a socket address")
}

pub(crate) fn name(text: &str) -> Name<'static> {
    text.parse().expect("a valid name")
}

/// A recursive query for `example.com. A` with EDNS.
pub(crate) fn query() -> Message<'static> {
    Message::query(0x1234, Question::new(name("example.com."), RecordType::A))
}

/// [`query`] with a cookie: the client cookie, and `server` when the server sent one before.
pub(crate) fn query_with_cookie(server: Option<&[u8]>) -> Message<'static> {
    let mut query = query();
    let edns = query.edns.as_mut().expect("Message::query has EDNS");
    edns.options.push(EdnsOption::Cookie(cookie(server)));
    query
}

pub(crate) fn cookie(server: Option<&[u8]>) -> Cookie {
    Cookie::new(CLIENT_COOKIE, server).expect("a valid cookie")
}

/// The cookie a message carries.
pub(crate) fn cookie_of(wire: &[u8]) -> Option<Cookie> {
    let edns = Message::decode(wire).expect("a message").message.edns?;
    edns.options.into_iter().find_map(|option| match option {
        EdnsOption::Cookie(cookie) => Some(cookie),
        _ => None,
    })
}

/// A response to `query` with `rcode`: same ID, opcode and questions, QR set, EDNS when the query has it.
pub(crate) fn response(query: &Message<'_>, rcode: Rcode) -> Message<'static> {
    let mut response = query.clone().into_owned();
    response.header.flags = response.header.flags.with(Flags::QR).with(Flags::RA);
    response.edns = query.edns.as_ref().map(|_| dedens_proto::Edns::default());
    response
        .set_rcode(rcode)
        .expect("EDNS when the rcode needs it");
    response
}

pub(crate) fn wire(message: &Message<'_>) -> Vec<u8> {
    message.to_vec().expect("the message encodes")
}

/// The start time of every exchange.
pub(crate) fn t0() -> Instant {
    // One fixed instant per test: only the differences matter.
    Instant::now()
}

pub(crate) fn secs(n: u64) -> Duration {
    Duration::from_secs(n)
}

pub(crate) fn start(query: &Message<'_>, options: Options, now: Instant) -> Exchange {
    Exchange::start(query.clone(), server(), options, now).expect("the query encodes")
}

/// Hands `bytes` from the server over UDP to `exchange`.
pub(crate) fn udp(exchange: Exchange, bytes: &[u8], now: Instant) -> Progress {
    exchange.receive(server(), Transport::Udp, bytes, now)
}

pub(crate) fn sent(exchange: &Exchange) -> Message<'static> {
    Message::decode(exchange.wire())
        .expect("the exchange sends a valid message")
        .message
        .into_owned()
}

pub(crate) fn expect_send(progress: Progress) -> Exchange {
    match progress {
        Progress::Send(exchange) => exchange,
        other => unreachable!("expected Send, got {other:?}"),
    }
}

pub(crate) fn expect_wait(progress: Progress) -> Exchange {
    match progress {
        Progress::Wait(exchange) => exchange,
        other => unreachable!("expected Wait, got {other:?}"),
    }
}

pub(crate) fn expect_response(progress: Progress) -> Response {
    match progress {
        Progress::Done(Ok(response)) => response,
        other => unreachable!("expected a response, got {other:?}"),
    }
}

pub(crate) fn expect_failure(progress: Progress) -> Failure {
    match progress {
        Progress::Done(Err(failure)) => failure,
        other => unreachable!("expected a failure, got {other:?}"),
    }
}
