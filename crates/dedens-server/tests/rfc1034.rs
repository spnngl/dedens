//! Queries without RD (RFC 1034 §4.3.1): answered from fresh cached data only, never asked upstream, never with
//! expired data (RFC 8767 §5), REFUSED with EDE 20 (Not Authoritative, RFC 8914 §4.21) otherwise.

mod common;

use std::borrow::Cow;

use common::{caching, captured, decode, forwarder, query_for, run_at, wire};
use dedens_proto::edns::{Edns, EdnsOption, ExtendedError, InfoCode};
use dedens_proto::{Flags, Message, Rcode, Transport};
use dedens_server::Pipeline;

/// `query` without RD.
fn norec(mut query: Message<'static>) -> Message<'static> {
    query.header.flags = Flags::NONE;
    query
}

/// The reply at `now` to `query` and how many servers were asked.
fn ask(
    pipeline: &Pipeline,
    query: &Message<'_>,
    now: u32,
    responses: &[Option<&[u8]>],
) -> (Message<'static>, usize) {
    let run = run_at(pipeline, &wire(query), Transport::Udp, now, responses);
    (
        decode(&run.reply.expect("a reply")).into_owned(),
        run.asked.len(),
    )
}

fn not_authoritative() -> Edns<'static> {
    Edns {
        options: vec![EdnsOption::Ede(ExtendedError {
            code: InfoCode::NOT_AUTHORITATIVE,
            text: Cow::Borrowed(""),
        })],
        ..Edns::default()
    }
}

#[test]
fn a_miss_is_refused_without_asking_upstream() {
    let response = captured("a");
    let query = norec(query_for(&response));
    for pipeline in [forwarder(), caching()] {
        let (reply, asked) = ask(&pipeline, &query, 0, &[Some(&response)]);
        assert_eq!((reply.rcode(), asked), (Rcode::REFUSED, 0));
        assert_eq!(reply.edns, Some(not_authoritative()));
        assert!(!reply.header.flags.contains(Flags::RD));
    }
}

#[test]
fn fresh_cached_data_answers() {
    let response = captured("a");
    let pipeline = caching();
    let query = query_for(&response);
    let (first, _) = ask(&pipeline, &query, 0, &[Some(&response)]);
    let (reply, asked) = ask(&pipeline, &norec(query), 1, &[]);
    assert_eq!((reply.rcode(), asked), (Rcode::NOERROR, 0));
    assert_eq!(reply.answer.len(), first.answer.len());
    assert_eq!(reply.edns, Some(Edns::default()));
}

#[test]
fn expired_data_does_not_answer_and_nothing_is_held() {
    let response = captured("a");
    let pipeline = caching();
    let query = query_for(&response);
    let (first, _) = ask(&pipeline, &query, 0, &[Some(&response)]);
    let expired = first
        .answer
        .iter()
        .map(|record| record.ttl.get())
        .min()
        .expect("an answer")
        + 1;
    let (reply, asked) = ask(&pipeline, &norec(query.clone()), expired, &[]);
    assert_eq!((reply.rcode(), asked), (Rcode::REFUSED, 0));
    assert_eq!(reply.edns, Some(not_authoritative()));
    // A client asking for recursion gets upstream's answer, not a hold.
    let (reply, asked) = ask(&pipeline, &query, expired, &[Some(&response)]);
    assert_eq!(
        (reply.rcode(), asked, reply.edns),
        (Rcode::NOERROR, 1, Some(Edns::default()))
    );
}

#[test]
fn a_refresh_asks_for_recursion() {
    let response = captured("a");
    let pipeline = caching();
    let query = query_for(&response);
    let (first, _) = ask(&pipeline, &query, 0, &[Some(&response)]);
    let ttl = first
        .answer
        .iter()
        .map(|record| record.ttl.get())
        .min()
        .expect("an answer");
    let late = ttl - ttl / 20;
    let run = run_at(
        &pipeline,
        &wire(&norec(query)),
        Transport::Udp,
        late,
        &[Some(&response)],
    );
    assert_eq!(run.requests.len(), 1, "a refresh");
    assert!(run.requests[0].header.flags.contains(Flags::RD));
    assert!(
        !decode(&run.reply.expect("a reply"))
            .header
            .flags
            .contains(Flags::RD)
    );
}
