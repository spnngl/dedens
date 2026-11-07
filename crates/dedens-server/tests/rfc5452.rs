//! RFC 5452 §9.1 in the server core (D111): `Pipeline::receive` takes an upstream response for the one asked only
//! when QR is set, the opcode is QUERY and the question is the one sent, in any case (RFC 4343 §4); another
//! response is that server failing, as a timeout, and the next is asked (RFC 1035 §7.3). Upstream answers are the
//! captures of `dedens-proto`, each altered in the checked field alone. The ID is the transport's to check
//! (D27): the core never sees it.

mod common;

use std::net::Ipv4Addr;

use common::{
    Captures, caching_with, captured, client_query, decode, dns, forwarder, query_for, run,
    servers, validating, wire,
};
use dedens_cache::Config;
use dedens_proto::{Class, Flags, Message, Opcode, Rcode, RecordType, Transport};
use dedens_server::Step;

/// The capture `case` with `alter` applied.
fn altered(case: &str, alter: impl FnOnce(&mut Message<'static>)) -> Vec<u8> {
    let mut message = Message::decode(&captured(case))
        .expect("a captured response decodes")
        .message
        .into_owned();
    alter(&mut message);
    wire(&message)
}

/// `bad` from the first server, the capture `a` from the second: the second is asked and its answer comes back.
fn assert_next_server_asked(bad: &[u8], what: &str) {
    let good = captured("a");
    let done = run(
        &forwarder(),
        &wire(&query_for(&good)),
        Transport::Udp,
        &[Some(bad), Some(&good)],
    );
    assert_eq!(done.asked, servers(), "{what}");
    let wire = done.reply.expect("a reply");
    let reply = decode(&wire);
    assert_eq!(reply.rcode(), Rcode::NOERROR, "{what}");
    assert_eq!(
        reply.answer,
        Message::decode(&good).expect("decodes").message.answer,
        "{what}"
    );
}

/// §9.1: a query is no response to a query.
#[test]
fn a_message_without_qr_is_not_the_response() {
    let bad = altered("a", |message| {
        message.header.flags = message.header.flags.without(Flags::QR);
    });
    assert_next_server_asked(&bad, "QR clear");
}

/// §9.1: the opcode of the response is the query's, QUERY.
#[test]
fn a_response_of_another_opcode_is_not_the_response() {
    for opcode in [Opcode::NOTIFY, Opcode::UPDATE] {
        let bad = altered("a", |message| message.header.opcode = opcode);
        assert_next_server_asked(&bad, &format!("{opcode:?}"));
    }
}

/// §9.1: the question is the one asked: name, type and class.
#[test]
fn a_response_to_another_question_is_not_the_response() {
    let name = altered("a", |message| {
        message.questions[0].name = dns("other.example.");
    });
    assert_next_server_asked(&name, "another name");
    let qtype = altered("a", |message| message.questions[0].qtype = RecordType::TXT);
    assert_next_server_asked(&qtype, "another type");
    let qclass = altered("a", |message| message.questions[0].qclass = Class::CH);
    assert_next_server_asked(&qclass, "another class");
    let missing = altered("a", |message| message.questions.clear());
    assert_next_server_asked(&missing, "no question");
    let two = altered("a", |message| {
        let again = message.questions[0].clone();
        message.questions.push(again);
    });
    assert_next_server_asked(&two, "two questions");
}

/// RFC 4343 §4: the case of the name in the response is the server's; `0x20` randomization (D27) depends on it
/// being kept, and a server that lowercases it is no other server.
#[test]
fn the_question_matches_in_any_case() {
    let good = captured("a");
    let upper = altered("a", |message| {
        let name = message.questions[0].name.to_string().to_ascii_uppercase();
        message.questions[0].name = dns(&name);
    });
    let done = run(
        &forwarder(),
        &wire(&query_for(&good)),
        Transport::Udp,
        &[Some(&upper), None],
    );
    assert_eq!(done.asked, servers()[..1]);
    assert_eq!(
        decode(&done.reply.expect("a reply")).rcode(),
        Rcode::NOERROR
    );
}

/// §9.1 with RFC 1035 §7.3: after the last server, the failure is SERVFAIL, whatever the response was.
#[test]
fn a_mismatch_from_every_server_is_servfail() {
    let good = captured("a");
    let bad = altered("a", |message| {
        message.questions[0].name = dns("other.example.");
    });
    let done = run(
        &forwarder(),
        &wire(&query_for(&good)),
        Transport::Udp,
        &[Some(&bad), Some(&bad)],
    );
    assert_eq!(done.asked, servers());
    assert_eq!(
        decode(&done.reply.expect("a reply")).rcode(),
        Rcode::SERVFAIL
    );
}

/// D111: a mismatch is a failure like a timeout, so it is never stored: the next query asks again.
#[test]
fn a_mismatch_is_not_cached() {
    let good = captured("a");
    let bad = altered("a", |message| {
        message.questions[0].name = dns("other.example.");
    });
    // The records come back as captured: no minimum TTL raises them.
    let pipeline = caching_with(Config {
        min_ttl: 0,
        ..Config::default()
    });
    let query = wire(&query_for(&good));
    let first = run(
        &pipeline,
        &query,
        Transport::Udp,
        &[Some(&bad), Some(&good)],
    );
    assert_eq!(first.asked, servers());
    let again = run(&pipeline, &query, Transport::Udp, &[]);
    // Answered from the cache: the second server's answer was stored, not the first's.
    assert_eq!(again.asked, []);
    assert_eq!(
        decode(&again.reply.expect("a reply")).answer,
        Message::decode(&good).expect("decodes").message.answer
    );
}

/// D111: the validator's questions are checked against what the validator asked, not the client's: a response to
/// the client's question, sent for its first question, is a failure of that server.
#[test]
fn a_validators_question_is_checked_against_its_own() {
    let pipeline = validating();
    let captures = Captures::new();
    let query = client_query("cloudflare.com.", RecordType::A, Flags::NONE, true);
    let wrong = Captures::get("alg13_a");
    let mut out = vec![0; 65535];
    let mut asked = Vec::new();
    let mut step = pipeline.query(
        &query,
        Transport::Udp,
        Ipv4Addr::LOCALHOST.into(),
        0,
        &mut out,
    );
    let reply = loop {
        match step {
            Step::Reply(len) => break out[..len].to_vec(),
            Step::Upstream(upstream) => {
                asked.push(upstream.server().addr);
                let request = upstream.request();
                let response = if asked.len() == 2 {
                    assert_ne!(request.questions[0].qtype, RecordType::A);
                    Some(wrong.as_slice())
                } else {
                    captures.answer(&request)
                };
                step = pipeline.receive(upstream, response, 0, &mut out);
            }
            Step::Drop | Step::Refresh(..) => unreachable!("a reply comes"),
        }
    };
    assert_eq!(asked[..3], [servers()[0], servers()[0], servers()[1]]);
    let reply = decode(&reply);
    assert_eq!(reply.rcode(), Rcode::NOERROR);
    assert!(reply.header.flags.contains(Flags::AD));
}
