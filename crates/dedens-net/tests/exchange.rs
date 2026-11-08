//! The sans-IO exchange driven by hand: tries, fallbacks and the checks on each response.
//!
//! - RFC 1035 §4.2.1 and RFC 1123 §6.1.3.2: a query without a response is sent again, a few times, then the exchange
//!   gives up. dig's numbers (D27): 3 tries, 5 s each.
//! - RFC 5452 §9.1: a response must come from the address queried and repeat the ID and the question; anything else is
//!   dropped and the wait goes on. §9.2: a changed query goes with another ID. `0x20` (draft-vixie-dnsext-dns0x20) adds
//!   the case of the question.
//! - RFC 6891 §7: a server that answers an EDNS query with FORMERR or NOTIMP and no OPT record does not know EDNS; the
//!   query goes again without it, once.
//! - RFC 7828 §3.2.1: a query over TCP carries an empty edns-tcp-keepalive, one over UDP none.
//! - RFC 7873 §5.3, client side: a response must carry the client cookie sent, and once the server sent a cookie, a
//!   cookie; its server cookie is kept; BADCOOKIE is retried with the fresh server cookie, then over TCP.
//! - RFC 8906 §3 and §8: a server that does not answer may have dropped the packet; a timeout is no sign that it does
//!   not know EDNS, so every try keeps the query as it was.

use std::num::NonZeroU8;

use dedens_net::exchange::{Failure, Options, Progress};
use dedens_proto::edns::{Cookie, EdnsOption, OptionCode, UnknownOption};
use dedens_proto::{Class, Flags, Message, Rcode, RecordType, Transport};
use proptest::prelude::*;

use crate::util::{
    CLIENT_COOKIE, SPARE_IDS, cookie, cookie_of, expect_failure, expect_response, expect_send,
    expect_wait, name, query, query_with_cookie, response, secs, sent, server, start, t0, udp,
    wire,
};

// --- RFC 1035 §4.2.1 and RFC 1123 §6.1.3.2 ---

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

/// A try lost before its deadline, to a socket error or a slow connection, counts as one timed out.
#[test]
fn a_lost_try_counts_as_timed_out() {
    let now = t0();
    let exchange = start(&query(), Options::default(), now);
    let exchange = expect_send(exchange.lose(now + secs(1)));
    assert_eq!(exchange.sends(), 2);
    assert_eq!(exchange.deadline(), now + secs(6));
    let exchange = expect_send(exchange.lose(now + secs(2)));
    assert_eq!(
        expect_failure(exchange.lose(now + secs(3))),
        Failure::TimedOut { sends: 3 }
    );
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

// --- RFC 5452 §9.1 ---

#[test]
fn the_response_ends_the_exchange() {
    let now = t0();
    let query = query();
    let exchange = start(&query, Options::default(), now);
    let answer = wire(&response(&query, Rcode::NOERROR));
    let got = expect_response(udp(exchange, &answer, now + crate::util::secs(1)));
    assert_eq!(got.wire, answer);
    assert_eq!(got.query, wire(&query));
    assert_eq!(got.transport, Transport::Udp);
    assert_eq!(got.rtt, crate::util::secs(1));
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
        exchange = expect_wait(exchange.receive(from, Transport::Udp, answer.clone(), now));
    }
    expect_response(udp(exchange, &answer, now));
}

#[test]
fn a_response_over_another_transport_is_dropped() {
    let now = t0();
    let query = query();
    let answer = wire(&response(&query, Rcode::NOERROR));
    let exchange = start(&query, Options::default(), now);
    let exchange = expect_wait(exchange.receive(server(), Transport::Tcp, answer.clone(), now));
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

/// D114: a FORMERR or NOTIMP without a question is what a server that cannot read the query sends, and what an
/// off-path forger that guessed the ID sends too: it is the response, never a reason to drop EDNS, DO and the
/// cookie (RFC 6891 §7 needs the server to say it does not know EDNS).
#[test]
fn a_forged_formerr_without_a_question_causes_no_downgrade() {
    let now = t0();
    let query = crate::util::query_with_cookie(None);
    for rcode in [Rcode::FORMERR, Rcode::NOTIMP] {
        let mut forged = response(&query, rcode);
        forged.questions.clear();
        forged.edns = None;
        let bytes = wire(&forged);
        let got = expect_response(udp(start(&query, Options::default(), now), &bytes, now));
        assert_eq!(got.wire, bytes);
        assert_eq!(got.sends, 1, "{rcode}: no second query");
        assert_eq!(got.query, wire(&query), "{rcode}: EDNS and cookie kept");
    }
}

/// D114, RFC 5452 §9.2: a query changed by a fallback goes with the next spare ID the caller drew, in order, and
/// never with the ID before, whose late response must not end the exchange.
#[test]
fn a_changed_query_goes_with_a_spare_id() {
    let now = t0();
    let query = query();
    let mut truncated = response(&query, Rcode::NOERROR);
    truncated.header.flags = truncated.header.flags.with(Flags::TC);
    let mut no_edns = response(&query, Rcode::FORMERR);
    no_edns.edns = None;
    let exchange = expect_send(udp(
        start(&query, Options::default(), now),
        &wire(&no_edns),
        now,
    ));
    assert_eq!(sent(&exchange).header.id, SPARE_IDS[0]);
    let mut again = response(&sent(&exchange), Rcode::NOERROR);
    again.header.flags = again.header.flags.with(Flags::TC);
    let exchange = expect_send(udp(exchange, &wire(&again), now));
    assert_eq!(sent(&exchange).header.id, SPARE_IDS[1]);
    // A spare ID equal to the one before is not used.
    let mut same = query.clone();
    same.header.id = SPARE_IDS[0];
    let mut truncated = response(&same, Rcode::NOERROR);
    truncated.header.flags = truncated.header.flags.with(Flags::TC);
    let exchange = expect_send(udp(
        start(&same, Options::default(), now),
        &wire(&truncated),
        now,
    ));
    assert_ne!(sent(&exchange).header.id, SPARE_IDS[0]);
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
    let sent = crate::util::sent(&exchange);
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

// --- RFC 6891 §7 ---

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

// --- RFC 7828 §3.2.1 ---

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

// --- RFC 7873 §5.3, client side ---

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

// --- RFC 8906 §3 and §8 ---

#[test]
fn timeouts_keep_edns_and_the_cookie() {
    let now = t0();
    let query = query_with_cookie(None);
    let mut exchange = start(&query, Options::default(), now);
    let first = exchange.wire().to_vec();
    for n in 1..=2 {
        exchange = expect_send(exchange.time_out(now + secs(5 * n)));
        assert_eq!(exchange.wire(), first);
        assert_eq!(sent(&exchange).edns, query.edns);
    }
    assert_eq!(
        expect_failure(exchange.time_out(now + secs(15))),
        Failure::TimedOut { sends: 3 }
    );
}
