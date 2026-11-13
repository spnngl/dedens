//! Names kept in the cache without a client (D96): what a pipeline makes of a question to keep warm.
//!
//! - RFC 3225 §3: DO is part of a cache key, so a name is kept once for clients without DO and once for those with.
//! - RFC 9520 §3.2: a failed refresh is not held as a resolution failure of a client's.

use std::sync::Arc;

use dedens_cache::{Cache, Config};
use dedens_proto::{Class, Flags, Message, Question, Rcode, RecordType, Transport};
use dedens_server::{Answer, Forward, Pipeline, Plugin, Stage, Step, Upstream, Warm, Warmth};
use dedens_testkit::dnssec::Captures;
use dedens_testkit::{captured, dns, query};

use crate::util::{caching, client_query, decode, run_at, servers, validating};

fn a_of(name: &str) -> Question<'static> {
    Question::new(dns(name), RecordType::A)
}

/// The pipeline `Warm`s kept, in order, as `(name, DO)`.
fn warmed(pipeline: &Pipeline) -> Vec<(String, bool)> {
    pipeline
        .warmed()
        .iter()
        .map(|warm| (warm.question().name.to_string(), warm.dnssec()))
        .collect()
}

/// The upstream query of `warm` at `now`, which must be made.
fn upstream_of(pipeline: &Pipeline, warm: &Warm, now: u32) -> Box<Upstream> {
    match pipeline.prewarm(warm, now) {
        Warmth::Upstream(upstream) => upstream,
        other => panic!("expected a query upstream, got {other:?}"),
    }
}

/// Sends `upstream` and what follows it, `respond` answering each request; the number of requests sent. A prewarm
/// ends without a reply.
fn play(
    pipeline: &Pipeline,
    upstream: Box<Upstream>,
    now: u32,
    mut respond: impl FnMut(&Message<'_>) -> Option<Vec<u8>>,
) -> usize {
    let mut out = vec![0; 65535];
    let mut sent = 0;
    let mut step = Step::Upstream(upstream);
    loop {
        match step {
            Step::Upstream(upstream) => {
                sent += 1;
                assert!(sent < 200, "the query asks for ever");
                let response = respond(&upstream.request());
                step = pipeline.receive(upstream, response.as_deref(), now, &mut out);
            }
            Step::Drop => return sent,
            step @ (Step::Reply(_) | Step::Refresh(..)) => panic!("a prewarm replies: {step:?}"),
        }
    }
}

/// A plugin that answers `blocked.test` NXDOMAIN, as a blocklist does.
#[derive(Debug)]
struct Block;

impl Plugin for Block {
    fn answer(&self, query: &dedens_proto::Query<'_>) -> Option<Answer<'_>> {
        (query.question()?.name == dns("blocked.test")).then_some(Answer {
            rcode: Rcode::NXDOMAIN,
            records: None,
            authoritative: false,
            error: None,
        })
    }
}

#[test]
fn a_name_is_kept_without_do_and_with_it_when_the_forward_stage_validates() {
    let names = || [a_of("www.example"), a_of("cloudflare.com")];
    let plain = caching().with_prewarm(names());
    assert_eq!(
        warmed(&plain),
        [
            ("www.example.".to_owned(), false),
            ("cloudflare.com.".to_owned(), false)
        ]
    );
    let validating = validating().with_prewarm(names());
    assert_eq!(
        warmed(&validating),
        [
            ("www.example.".to_owned(), false),
            ("www.example.".to_owned(), true),
            ("cloudflare.com.".to_owned(), false),
            ("cloudflare.com.".to_owned(), true),
        ]
    );
    // Only class IN has DNSSEC (RFC 4033 §2).
    let chaos = Question {
        qclass: Class::CH,
        ..a_of("www.example")
    };
    let validating = self::validating().with_prewarm([chaos]);
    assert_eq!(warmed(&validating), [("www.example.".to_owned(), false)]);
    assert_eq!(warmed(&Pipeline::default()), []);
}

#[test]
fn the_first_client_hits_what_was_warmed_and_the_refresh_comes_before_expiry() {
    let response = captured("a");
    let query = query("a", 7);
    let pipeline = caching().with_prewarm(query.questions.clone());
    let [warm] = pipeline.warmed() else {
        panic!("one name asked");
    };
    let sent = play(&pipeline, upstream_of(&pipeline, warm, 0), 0, |_| {
        Some(response.clone())
    });
    assert_eq!(sent, 1);
    // The client's query is a hit: nothing goes upstream.
    let done = run_at(
        &pipeline,
        &crate::util::wire(&query),
        Transport::Udp,
        1,
        &[],
    );
    assert_eq!(done.asked.len(), 0);
    assert_eq!(decode(&done.reply.expect("a hit")).rcode(), Rcode::NOERROR);
    // The answer is kept 60 seconds (D124, `min_ttl`), and asked again under 10% of it left, as a prefetch would.
    assert!(matches!(pipeline.prewarm(warm, 1), Warmth::Fresh(55)));
    assert!(matches!(pipeline.prewarm(warm, 54), Warmth::Fresh(55)));
    let upstream = upstream_of(&pipeline, warm, 55);
    // The refreshed answer is kept from the new time.
    let sent = play(&pipeline, upstream, 55, |_| Some(response.clone()));
    assert_eq!(sent, 1);
    assert!(matches!(pipeline.prewarm(warm, 56), Warmth::Fresh(110)));
}

/// A warm check is not a client: it counts no hit, and no use that would keep the entry from being evicted first.
#[test]
fn a_fresh_entry_is_left_alone() {
    let response = captured("a");
    let query = query("a", 7);
    let pipeline = caching().with_prewarm(query.questions.clone());
    let warm = &pipeline.warmed()[0];
    let _ = play(&pipeline, upstream_of(&pipeline, warm, 0), 0, |_| {
        Some(response.clone())
    });
    for now in 0..50 {
        assert!(matches!(pipeline.prewarm(warm, now), Warmth::Fresh(55)));
    }
    // The first client under 10% left still gets the prefetch: the checks used nothing up.
    let done = run_at(
        &pipeline,
        &crate::util::wire(&query),
        Transport::Udp,
        56,
        &[Some(&response)],
    );
    assert_eq!(done.asked.len(), 1, "the client's prefetch");
}

/// RFC 9520 §3.2: a failure of the refresh is the caller's to retry, not held for the clients, who are asked of
/// upstream at once.
#[test]
fn a_failed_prewarm_is_not_held() {
    let response = captured("a");
    let query = query("a", 7);
    let pipeline = caching().with_prewarm(query.questions.clone());
    let warm = &pipeline.warmed()[0];
    let sent = play(&pipeline, upstream_of(&pipeline, warm, 0), 0, |_| None);
    // Each of the two servers, once.
    assert_eq!(sent, servers().len());
    assert!(matches!(pipeline.prewarm(warm, 0), Warmth::Upstream(_)));
    let done = run_at(
        &pipeline,
        &crate::util::wire(&query),
        Transport::Udp,
        0,
        &[Some(&response)],
    );
    assert_eq!(done.asked.len(), 1);
    assert_eq!(
        decode(&done.reply.expect("a reply")).rcode(),
        Rcode::NOERROR
    );
}

#[test]
fn what_a_stage_before_the_cache_answers_is_not_asked() {
    let pipeline = Pipeline::new(vec![
        Stage::Plugin(Box::new(Block)),
        Stage::Cache(Arc::new(Cache::new(Config::default()).expect("settings"))),
        Stage::Forward(Forward::new(servers()).expect("servers")),
    ])
    .with_prewarm([a_of("blocked.test"), a_of("other.test")]);
    let [blocked, other] = pipeline.warmed() else {
        panic!("two names");
    };
    assert!(matches!(pipeline.prewarm(blocked, 0), Warmth::Local));
    assert!(matches!(pipeline.prewarm(other, 0), Warmth::Upstream(_)));
}

#[test]
fn nothing_is_asked_without_a_forward_stage() {
    let cache = Stage::Cache(Arc::new(Cache::new(Config::default()).expect("settings")));
    let pipeline = Pipeline::new(vec![cache]).with_prewarm([a_of("www.example")]);
    assert!(matches!(
        pipeline.prewarm(&pipeline.warmed()[0], 0),
        Warmth::Refused
    ));
}

/// D77: a validated answer is kept with its verdict under both keys, so that the client with DO, and the one
/// without, hit at once, and the one with DO has AD.
#[test]
fn a_validated_name_is_a_hit_with_and_without_do() {
    let pipeline = validating().with_prewarm([a_of("cloudflare.com")]);
    let captures = Captures::new();
    for (n, warm) in pipeline.warmed().iter().enumerate() {
        let upstream = upstream_of(&pipeline, warm, 0);
        let sent = play(&pipeline, upstream, 0, |request| {
            captures.answer(request).map(<[u8]>::to_vec)
        });
        // The chain of trust is asked for once: the second query finds the keys cached (D86).
        assert!(n > 0 || sent > 1, "the chain of trust is asked for");
    }
    // Both kept now: nothing more to ask for either.
    for warm in pipeline.warmed() {
        assert!(matches!(pipeline.prewarm(warm, 1), Warmth::Fresh(_)));
    }
    let hit = |dnssec| {
        let query = client_query("cloudflare.com.", RecordType::A, Flags::AD, dnssec);
        let done = run_at(&pipeline, &query, Transport::Udp, 1, &[]);
        assert_eq!(done.asked.len(), 0, "a hit, DO {dnssec}");
        decode(&done.reply.expect("a reply")).into_owned()
    };
    let with = hit(true);
    assert!(with.header.flags.contains(Flags::AD));
    assert!(with.answer.iter().any(|r| r.rtype() == RecordType::RRSIG));
    let without = hit(false);
    assert!(without.header.flags.contains(Flags::AD));
    assert!(
        without
            .answer
            .iter()
            .all(|r| r.rtype() != RecordType::RRSIG)
    );
}
