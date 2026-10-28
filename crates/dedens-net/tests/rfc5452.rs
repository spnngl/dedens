//! RFC 5452 §9.1: a response must come from the address queried and repeat the ID and the question; anything else
//! is dropped and the wait goes on. `0x20` (draft-vixie-dnsext-dns0x20) adds the case of the question.

mod common;

use common::{expect_response, expect_wait, name, query, response, server, start, t0, udp, wire};
use dedens_net::exchange::{Options, Progress, Transport};
use dedens_proto::{Class, Flags, Message, Rcode, RecordType};
use proptest::prelude::*;

#[test]
fn the_response_ends_the_exchange() {
    let now = t0();
    let query = query();
    let exchange = start(&query, Options::default(), now);
    let answer = wire(&response(&query, Rcode::NOERROR));
    let got = expect_response(udp(exchange, &answer, now + common::secs(1)));
    assert_eq!(got.wire, answer);
    assert_eq!(got.query, wire(&query));
    assert_eq!(got.transport, Transport::Udp);
    assert_eq!(got.rtt, common::secs(1));
    assert_eq!(got.sends, 1);
    assert_eq!(got.cookie, None);
}

#[test]
fn a_response_from_another_address_is_dropped() {
    let now = t0();
    let query = query();
    let answer = wire(&response(&query, Rcode::NOERROR));
    let mut exchange = start(&query, Options::default(), now);
    for from in ["192.0.2.53:5353", "192.0.2.54:53", "[2001:db8::53]:53"] {
        let from = from.parse().expect("a socket address");
        exchange = expect_wait(exchange.receive(from, Transport::Udp, &answer, now));
    }
    expect_response(udp(exchange, &answer, now));
}

#[test]
fn a_response_over_another_transport_is_dropped() {
    let now = t0();
    let query = query();
    let answer = wire(&response(&query, Rcode::NOERROR));
    let exchange = start(&query, Options::default(), now);
    let exchange = expect_wait(exchange.receive(server(), Transport::Tcp, &answer, now));
    expect_response(udp(exchange, &answer, now));
}

#[test]
fn a_message_that_does_not_answer_the_query_is_dropped() {
    let now = t0();
    let query = query();
    let changes: [fn(&mut Message<'static>); 7] = [
        |m| m.header.id ^= 1,
        |m| m.header.flags = m.header.flags.without(Flags::QR),
        |m| m.header.opcode = dedens_proto::Opcode::NOTIFY,
        |m| m.questions[0].name = name("example.net."),
        |m| m.questions[0].qtype = RecordType::AAAA,
        |m| m.questions[0].qclass = Class::CH,
        |m| m.questions.clear(),
    ];
    let mut exchange = start(&query, Options::default(), now);
    for change in changes {
        let mut forged = response(&query, Rcode::NOERROR);
        change(&mut forged);
        exchange = expect_wait(udp(exchange, &wire(&forged), now));
    }
    for garbage in [&b""[..], &[0x12, 0x34, 0x80], &[0xFF; 40]] {
        exchange = expect_wait(udp(exchange, garbage, now));
    }
    expect_response(udp(exchange, &wire(&response(&query, Rcode::NOERROR)), now));
}

#[test]
fn a_second_question_is_not_the_question() {
    let now = t0();
    let query = query();
    let mut forged = response(&query, Rcode::NOERROR);
    forged.questions.push(forged.questions[0].clone());
    let exchange = start(&query, Options::default(), now);
    expect_wait(udp(exchange, &wire(&forged), now));
}

#[test]
fn formerr_and_notimp_may_leave_the_question_out() {
    let now = t0();
    let mut query = query();
    query.edns = None;
    for rcode in [Rcode::FORMERR, Rcode::NOTIMP] {
        let mut answer = response(&query, rcode);
        answer.questions.clear();
        let got = expect_response(udp(
            start(&query, Options::default(), now),
            &wire(&answer),
            now,
        ));
        assert_eq!(got.wire, wire(&answer));
    }
}

#[test]
fn the_question_matches_in_any_case_by_default() {
    let now = t0();
    let query = query();
    let mut answer = response(&query, Rcode::NOERROR);
    answer.questions[0].name = name("ExAmPlE.CoM.");
    expect_response(udp(
        start(&query, Options::default(), now),
        &wire(&answer),
        now,
    ));
}

#[test]
fn random_case_sets_the_case_and_requires_it_back() {
    let now = t0();
    let query = query();
    let mut options = Options::default();
    // One bit a letter, eight letters a byte, lowest bit first: 1 upper, 0 lower.
    let mut bits = [0xFF; 32];
    bits[0] = 0b1010_0101;
    options.random_case = Some(bits);
    let exchange = start(&query, options, now);
    let sent = common::sent(&exchange);
    assert_eq!(sent.questions[0].name.to_string(), "ExAmpLe.COM.");

    let mut lower = response(&query, Rcode::NOERROR);
    lower.questions[0].name = name("example.com.");
    let exchange = expect_wait(udp(exchange, &wire(&lower), now));

    let mut echoed = response(&query, Rcode::NOERROR);
    echoed.questions[0].name = sent.questions[0].name.clone();
    expect_response(udp(exchange, &wire(&echoed), now));
}

proptest! {
    /// Whatever the bytes, the exchange moves on only for a response to the query: the true response with a few
    /// bytes changed, or random bytes.
    #[test]
    fn only_a_response_moves_the_exchange_on(
        changes in prop::collection::vec((any::<prop::sample::Index>(), any::<u8>()), 0..4),
        random in prop::option::of(prop::collection::vec(any::<u8>(), 0..200)),
    ) {
        let now = t0();
        let query = query();
        let bytes = random.unwrap_or_else(|| {
            let mut bytes = wire(&response(&query, Rcode::NOERROR));
            for (at, byte) in &changes {
                let at = at.index(bytes.len());
                bytes[at] = *byte;
            }
            bytes
        });
        let exchange = start(&query, Options::default(), now);
        if !matches!(udp(exchange, &bytes, now), Progress::Wait(_)) {
            let message = Message::decode(&bytes).expect("a response decodes").message;
            prop_assert_eq!(message.header.id, query.header.id);
            prop_assert!(message.header.flags.contains(Flags::QR));
            prop_assert!(message.questions == query.questions || message.questions.is_empty());
        }
    }
}
