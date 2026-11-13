//! Names kept in the cache without a client (D96): what a pipeline makes of a question to keep warm.
//!
//! - RFC 3225 §3: DO is part of a cache key, so a name is kept once for clients without DO and once for those with.
//! - RFC 9520 §3.2: a failed refresh is not held as a resolution failure of a client's.

use std::sync::Arc;

use dedens_cache::{Cache, Config};
use dedens_dnssec::{Limits, TrustAnchors, Validator};
use dedens_proto::{Class, Flags, Message, Question, Rcode, RecordType, Transport};
use dedens_server::{
    Answer, Budget, Budgets, Forward, Pipeline, Plugin, Stage, Step, Upstream, Validating, Warm,
    Warmth,
};
use dedens_testkit::dnssec::Captures;
use dedens_testkit::{captured, dns, query};

use crate::util::{
    caching, caching_with, captured_at, client_query, decode, run_at, run_captured, servers,
    validating, validating_under,
};

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
        other => unreachable!("a query upstream, not {other:?}"),
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
            step @ (Step::Reply(_) | Step::Refresh(..)) => {
                unreachable!("a prewarm does not reply: {step:?}")
            }
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
        Warmth::Unaskable
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

/// D96: an entry is asked again `MARGIN` seconds before it expires if its prefetch point is later: a TTL of 5 s, of
/// which the default 10% leaves no second, would lapse before a refresh that comes at its last second landed.
#[test]
fn a_short_lived_entry_is_asked_again_a_margin_before_it_expires() {
    let response = captured("a");
    let query = query("a", 7);
    let config = Config {
        min_ttl: 0,
        max_ttl: 5,
        ..Config::default()
    };
    let pipeline = caching_with(config).with_prewarm(query.questions.clone());
    let warm = &pipeline.warmed()[0];
    assert_eq!(pipeline.warm_until(warm, 0), None);
    let _ = play(&pipeline, upstream_of(&pipeline, warm, 0), 0, |_| {
        Some(response.clone())
    });
    assert_eq!(pipeline.warm_until(warm, 1), Some(3));
    assert!(matches!(pipeline.prewarm(warm, 2), Warmth::Fresh(3)));
    assert!(matches!(pipeline.prewarm(warm, 3), Warmth::Upstream(_)));
    // An entry that lives less than the margin is asked at once, for the caller to hold back.
    assert_eq!(pipeline.warm_until(warm, 4), Some(3));
}

/// D96, D117: prewarm spends a share of the validation allowance of its own, so that it never sheds a client, and a
/// share spent is [`Warmth::Shed`], to be asked again.
#[test]
fn prewarm_spends_a_share_of_its_own_and_sheds_none_of_the_clients() {
    let validator = Validator::new(TrustAnchors::root(), Limits::default());
    // Two units for prewarm's address, in a table far larger than the addresses using it.
    let share = Budgets::with_key(
        Budget {
            per_second: 1,
            burst: 2,
            table: 1 << 16,
        },
        &[7; 16],
    )
    .expect("a share");
    let pipeline = validating_under(
        Validating::new(validator, std::sync::Arc::new(captured_at)).sharing(share),
    )
    .with_prewarm([a_of("cloudflare.com")]);
    let warm = &pipeline.warmed()[0];
    assert!(matches!(pipeline.prewarm(warm, 0), Warmth::Upstream(_)));
    assert!(matches!(pipeline.prewarm(warm, 0), Warmth::Upstream(_)));
    assert!(matches!(pipeline.prewarm(warm, 0), Warmth::Shed));
    // A client, from another address, is not shed.
    let query = client_query("cloudflare.com.", RecordType::A, Flags::NONE, true);
    let done = run_captured(&pipeline, &query, 0, &Captures::new());
    assert!(
        !done.requests.is_empty(),
        "the client's question went upstream"
    );
}

/// D96, D77: a prewarm whose answer is bogus stores nothing, as a refresh does: it is not a kept answer. One a client
/// stored is not one either, whatever its end: [`Pipeline::warm_until`] says so.
#[test]
fn a_bogus_answer_is_not_a_kept_one() {
    let pipeline = validating().with_prewarm([a_of("dnssec-failed.org")]);
    let warm = &pipeline.warmed()[1];
    assert!(warm.dnssec());
    let captures = Captures::new();
    let _ = play(&pipeline, upstream_of(&pipeline, warm, 0), 0, |request| {
        captures.answer(request).map(<[u8]>::to_vec)
    });
    assert_eq!(pipeline.warm_until(warm, 1), None);
    // A client's query stores the bogus answer for 60 s.
    let query = client_query("dnssec-failed.org.", RecordType::A, Flags::NONE, true);
    let _ = run_captured(&pipeline, &query, 1, &captures);
    assert_eq!(pipeline.warm_until(warm, 2), None);
    // Due before it expires, as any other (D96).
    assert!(matches!(pipeline.prewarm(warm, 2), Warmth::Fresh(59)));
}
