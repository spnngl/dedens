//! The cache stage (D43): answers from stored responses with TTLs counted down (RFC 1035 §7.4, RFC 2181 §8),
//! failure holds (RFC 9520 §3.2), expired data while upstream fails or once the client response timer ran out,
//! with EDE 3 or 19 (RFC 8767 §4-5, RFC 8914 §4.4), and refresh of entries near their end.

mod common;

use std::borrow::Cow;
use std::num::NonZeroU8;
use std::time::Duration;

use common::{caching, captured, decode, query_for, run_at, servers, wire};
use dedens_cache::{Cache, Config};
use dedens_proto::edns::{EdnsOption, ExtendedError, InfoCode};
use dedens_proto::{Edns, Flags, Message, Rcode};
use dedens_server::{Forward, Pipeline, Stage, Step, Transport, Upstream};

/// The reply at `now` to `query`, upstream answering `responses` in turn, and the servers asked.
fn ask(
    pipeline: &Pipeline,
    query: &Message<'_>,
    now: u32,
    responses: &[Option<&[u8]>],
) -> (Message<'static>, usize) {
    let run = run_at(pipeline, &wire(query), Transport::Udp, now, responses);
    let reply = decode(&run.reply.expect("a reply")).into_owned();
    (reply, run.asked.len())
}

fn ttls(message: &Message<'_>) -> Vec<u32> {
    message
        .answer
        .iter()
        .map(|record| record.ttl.get())
        .collect()
}

/// Our OPT record with an extended error of `code`.
fn stale(code: InfoCode) -> Edns<'static> {
    Edns {
        options: vec![EdnsOption::Ede(ExtendedError {
            code,
            text: Cow::Borrowed(""),
        })],
        ..Edns::default()
    }
}

#[test]
fn a_second_query_is_answered_from_the_cache() {
    let response = captured("a");
    let pipeline = caching();
    let mut query = query_for(&response);
    let (first, asked) = ask(&pipeline, &query, 0, &[Some(&response)]);
    assert_eq!(asked, 1);
    query.header.id = 8;
    let (second, asked) = ask(&pipeline, &query, 2, &[]);
    assert_eq!(asked, 0);
    assert_eq!((second.header.id, second.rcode()), (8, Rcode::NOERROR));
    assert_eq!(second.header.flags, first.header.flags);
    assert!(!second.header.flags.contains(Flags::AA));
    assert!(second.header.flags.contains(Flags::RA));
    assert_eq!(second.questions, first.questions);
    assert_eq!(second.edns, Some(Edns::default()));
    let counted_down: Vec<_> = ttls(&first).iter().map(|ttl| ttl - 2).collect();
    assert_eq!(ttls(&second), counted_down);
}

#[test]
fn a_query_without_edns_gets_no_opt_record_from_the_cache() {
    let response = captured("a");
    let pipeline = caching();
    let mut query = query_for(&response);
    query.edns = None;
    let _ = ask(&pipeline, &query, 0, &[Some(&response)]);
    let (reply, asked) = ask(&pipeline, &query, 0, &[]);
    assert_eq!((asked, &reply.edns), (0, &None));
    assert_eq!(reply.rcode(), Rcode::NOERROR);
}

#[test]
fn failures_are_held() {
    let pipeline = caching();
    let query = query_for(&captured("a"));
    let (reply, asked) = ask(&pipeline, &query, 0, &[None, None]);
    assert_eq!((reply.rcode(), asked), (Rcode::SERVFAIL, 2));
    // The first hold lasts 5 seconds (RFC 9520 §3.2, at least 1).
    let (reply, asked) = ask(&pipeline, &query, 4, &[]);
    assert_eq!((reply.rcode(), asked), (Rcode::SERVFAIL, 0));
    let (reply, asked) = ask(&pipeline, &query, 5, &[None, None]);
    assert_eq!((reply.rcode(), asked), (Rcode::SERVFAIL, 2));
}

#[test]
fn expired_data_answers_while_upstream_fails() {
    let response = captured("a");
    let pipeline = caching();
    let query = query_for(&response);
    let (first, _) = ask(&pipeline, &query, 0, &[Some(&response)]);
    let expired = ttls(&first).into_iter().min().expect("an answer") + 1;
    let (reply, asked) = ask(&pipeline, &query, expired, &[None, None]);
    assert_eq!((reply.rcode(), asked), (Rcode::NOERROR, 2));
    assert_eq!(reply.answer.len(), first.answer.len());
    // Stale records go out with 30 seconds (RFC 8767 §4), and stale data answers through the hold untried.
    assert!(ttls(&reply).iter().all(|&ttl| ttl == 30));
    assert_eq!(reply.edns, Some(stale(InfoCode::STALE_ANSWER)));
    let (again, asked) = ask(&pipeline, &query, expired + 1, &[]);
    assert_eq!((again.rcode(), asked), (Rcode::NOERROR, 0));
    assert_eq!(again.edns, Some(stale(InfoCode::STALE_ANSWER)));
}

#[test]
fn an_expired_nxdomain_is_a_stale_nxdomain_answer() {
    let response = captured("nxdomain_soa");
    let pipeline = caching();
    let query = query_for(&response);
    let _ = ask(&pipeline, &query, 0, &[Some(&response)]);
    // Past the longest negative TTL (RFC 2308 §5: 3 hours by default).
    let (reply, _) = ask(&pipeline, &query, 3 * 3600 + 1, &[None, None]);
    assert_eq!(reply.rcode(), Rcode::NXDOMAIN);
    assert_eq!(reply.edns, Some(stale(InfoCode::STALE_NXDOMAIN_ANSWER)));
}

#[test]
fn expired_data_does_not_answer_when_upstream_does() {
    let response = captured("a");
    let pipeline = caching();
    let query = query_for(&response);
    let (first, _) = ask(&pipeline, &query, 0, &[Some(&response)]);
    let expired = ttls(&first).into_iter().min().expect("an answer") + 1;
    let (reply, asked) = ask(&pipeline, &query, expired, &[Some(&response)]);
    assert_eq!((asked, &reply.edns), (1, &Some(Edns::default())));
    assert_eq!(ttls(&reply), ttls(&first));
}

#[test]
fn entries_near_their_end_are_refreshed_once() {
    let response = captured("a");
    let pipeline = caching();
    let query = query_for(&response);
    let (first, _) = ask(&pipeline, &query, 0, &[Some(&response)]);
    let ttl = ttls(&first).into_iter().min().expect("an answer");
    assert!(ttl >= 20, "a TTL of {ttl} leaves no time to refresh");
    // Under 10% of the TTL left: the reply comes from the cache and upstream is asked once in the background.
    let late = ttl - ttl / 20;
    let (reply, asked) = ask(&pipeline, &query, late, &[Some(&response)]);
    assert_eq!((asked, ttls(&reply)[0]), (1, ttl - late));
    // The refresh stored the response anew.
    let (refreshed, asked) = ask(&pipeline, &query, late, &[]);
    assert_eq!((asked, ttls(&refreshed)), (0, ttls(&first)));
}

/// The upstream query `query` gets at `now`.
fn upstream_of(pipeline: &Pipeline, query: &Message<'_>, now: u32) -> Box<Upstream> {
    let mut out = vec![0; 65535];
    match pipeline.query(&wire(query), Transport::Udp, now, &mut out) {
        Step::Upstream(upstream) => upstream,
        step => unreachable!("an upstream query, not {step:?}"),
    }
}

/// A cached `a` response and the time it has expired by.
fn expired_a(pipeline: &Pipeline) -> (Vec<u8>, Message<'static>, u32) {
    let response = captured("a");
    let query = query_for(&response);
    let (first, _) = ask(pipeline, &query, 0, &[Some(&response)]);
    let expired = ttls(&first).into_iter().min().expect("an answer") + 1;
    (response, first, expired)
}

#[test]
fn expired_data_answers_once_the_client_timer_runs_out_and_resolution_goes_on() {
    let pipeline = caching();
    let (response, first, expired) = expired_a(&pipeline);
    let query = query_for(&response);
    let upstream = upstream_of(&pipeline, &query, expired);
    // RFC 8767 §5 suggests 1.8 seconds.
    assert_eq!(upstream.stale_after(), Some(Duration::from_millis(1800)));
    let mut out = vec![0; 65535];
    let len = pipeline
        .stale(&upstream, expired, &mut out)
        .expect("expired data");
    let reply = decode(&out[..len]);
    assert_eq!((reply.header.id, reply.rcode()), (7, Rcode::NOERROR));
    assert!(ttls(&reply).iter().all(|&ttl| ttl == 30));
    assert_eq!(reply.edns, Some(stale(InfoCode::STALE_ANSWER)));
    assert_eq!(
        pipeline.stale(&upstream, expired, &mut out),
        None,
        "one reply"
    );
    // The response only refreshes the cache: the next query has it fresh.
    let step = pipeline.receive(upstream, Some(&response), expired, &mut out);
    assert!(matches!(step, Step::Drop), "{step:?}");
    let (fresh, asked) = ask(&pipeline, &query, expired, &[]);
    assert_eq!((asked, ttls(&fresh)), (0, ttls(&first)));
}

#[test]
fn a_failure_after_a_stale_answer_is_held_without_another_reply() {
    let pipeline = caching();
    let (response, _, expired) = expired_a(&pipeline);
    let query = query_for(&response);
    let upstream = upstream_of(&pipeline, &query, expired);
    let mut out = vec![0; 65535];
    assert!(pipeline.stale(&upstream, expired, &mut out).is_some());
    let Step::Upstream(next) = pipeline.receive(upstream, None, expired, &mut out) else {
        panic!("the second server");
    };
    let step = pipeline.receive(next, None, expired, &mut out);
    assert!(matches!(step, Step::Drop), "{step:?}");
    // Held: expired data answers at once, upstream untried.
    let (reply, asked) = ask(&pipeline, &query, expired + 1, &[]);
    assert_eq!((reply.rcode(), asked), (Rcode::NOERROR, 0));
    assert_eq!(reply.edns, Some(stale(InfoCode::STALE_ANSWER)));
}

#[test]
fn without_expired_data_the_client_waits_for_resolution() {
    let pipeline = caching();
    let response = captured("a");
    let upstream = upstream_of(&pipeline, &query_for(&response), 0);
    let mut out = vec![0; 65535];
    assert_eq!(pipeline.stale(&upstream, 0, &mut out), None);
    let step = pipeline.receive(upstream, Some(&response), 0, &mut out);
    assert!(matches!(step, Step::Reply(_)), "{step:?}");
}

#[test]
fn the_timer_is_the_cache_stages_and_the_patience_the_forward_stages() {
    let query = query_for(&captured("a"));
    let forward = Forward::new(&servers()).expect("servers");
    let alone = Pipeline::new(vec![Stage::Forward(forward.clone())]);
    let upstream = upstream_of(&alone, &query, 0);
    assert_eq!(upstream.stale_after(), None);
    assert_eq!(
        upstream.patience(),
        (Duration::from_secs(3), NonZeroU8::MIN.saturating_add(1))
    );
    let config = Config {
        stale_answer_after_ms: 0,
        ..Config::default()
    };
    let tries = NonZeroU8::MIN;
    let patient = Pipeline::new(vec![
        Stage::Cache(Cache::new(config).expect("valid settings")),
        Stage::Forward(
            forward
                .with_timeout(Duration::from_millis(500))
                .with_tries(tries),
        ),
    ]);
    let upstream = upstream_of(&patient, &query, 0);
    assert_eq!(upstream.stale_after(), None);
    assert_eq!(upstream.patience(), (Duration::from_millis(500), tries));
}
