//! `dedensd` resolving from the root (D195) on the Internet of a captured resolution (D189): its recurse stage
//! answers the capture's question (RFC 1034 §5.3.3), priming the root's servers alongside (RFC 8109 §3), and the
//! resolutions of a hundred clients asking it at once send each query once (RFC 5452 §5), even of a silent server,
//! past which one more is shed (D195).

use std::cell::RefCell;
use std::collections::{BTreeMap, BTreeSet};
use std::net::{IpAddr, SocketAddr};
use std::rc::Rc;
use std::sync::Arc;
use std::time::Duration;

use dedens_cache::{Cache, Config};
use dedens_proto::edns::{EdnsOption, InfoCode};
use dedens_proto::rdata::RData;
use dedens_proto::{Message, Name, Question, Rcode, RecordType, Transport};
use dedens_resolver::{Caches, DEFAULT_CAPACITY, InfraCache, Limits, Minimisation, RrsetCache};
use dedens_roots::RootHints;
use dedens_server::{Pipeline, Recurse, Stage};
use dedens_sim::client::Carrier;
use dedens_sim::seed::{self, Seed};
use dedens_sim::stub::Outcome;
use dedens_sim::topology::{Topology, World};
use dedens_sim::trace::{Event, What};
use dedens_sim::upstream::{Answers, Verdict};
use dedens_testkit::recursion::Resolution;
use futures_util::future::join_all;

use crate::util::{SECOND, SEEDS};

/// The clients asking the same question at once: as many as wait on one query in flight, the one sending it
/// apart (`WAITERS`, D195).
const CLIENTS: usize = 100;

/// The step of the simulation: the latencies of its links are tens of milliseconds.
const TICK: Duration = Duration::from_millis(10);

/// The capture: `google.com A`, unsigned, from priming to the answer.
fn capture() -> Resolution {
    Resolution::read("unsigned")
}

/// A cache stage, one shard (D133), then a recurse stage whose caches are steered to the servers `capture`
/// followed, its questions not minimised as the capture's were not (D198).
fn pipeline(capture: &Resolution) -> Pipeline {
    let config = Config {
        shards: 1,
        ..Config::default()
    };
    let caches = Caches {
        rrsets: RrsetCache::new(DEFAULT_CAPACITY, config.clone()).expect("a valid config"),
        infra: InfraCache::new(InfraCache::DEFAULT_CAPACITY, 1).expect("a valid size"),
        roots: RootHints::bundled().clone(),
        tlds: None,
    };
    steer(&caches, capture);
    Pipeline::new(vec![
        Stage::Cache(Arc::new(Cache::new(config).expect("valid settings"))),
        Stage::Recurse(Recurse::new(Arc::new(caches)).with_minimisation(Minimisation::Off)),
    ])
}

/// Marks lame, for each zone `capture` asked, every address it shows but the first server it asked there: the
/// resolver then draws the server whose responses the capture followed, the others being no host of the run.
fn steer(caches: &Caches, capture: &Resolution) {
    let mut known: BTreeSet<IpAddr> = (caches.roots.servers().iter())
        .flat_map(dedens_roots::Server::addresses)
        .collect();
    for exchange in &capture.exchanges {
        let response = dedens_testkit::message(&exchange.response);
        known.extend(
            (response.answer.iter().chain(&response.additional)).filter_map(|r| match r.data() {
                RData::A(v4) => Some(IpAddr::from(v4)),
                RData::Aaaa(v6) => Some(IpAddr::from(v6)),
                _ => None,
            }),
        );
    }
    let mut followed: Vec<(&Name<'static>, IpAddr)> = Vec::new();
    for e in &capture.exchanges {
        if !followed.iter().any(|(zone, _)| *zone == &e.zone) {
            followed.push((&e.zone, e.server));
        }
    }
    for (zone, server) in followed {
        for &address in known.iter().filter(|&&a| a != server) {
            // The resolver's clock starts at 0 with the run.
            caches.infra.lame(SocketAddr::new(address, 53), zone, 0);
        }
    }
}

/// A world of the capture's servers and `dedensd` resolving from the root.
fn world(seed: Seed) -> World {
    let capture = capture();
    Topology::new()
        .resolution(&capture)
        .resolver(move |_| pipeline(&capture))
        .dedensd()
        .tick(TICK)
        .build(seed)
}

/// The queries each authoritative server answered, by server, question and whether over TCP.
fn served_each(events: &[Event]) -> BTreeMap<(IpAddr, String, u16, bool), usize> {
    let mut served = BTreeMap::new();
    for event in events {
        if let What::Served {
            question,
            transport,
        } = &event.what
        {
            let tcp = *transport == Transport::Tcp;
            let key = (event.host, question.name.to_string(), question.qtype.0, tcp);
            *served.entry(key).or_default() += 1;
        }
    }
    served
}

/// The capture's question.
fn question() -> Question<'static> {
    let capture = capture();
    Question::new(capture.name, capture.rtype)
}

#[test]
fn rfc1034_5_3_3_dedensd_resolves_the_capture_from_the_root() {
    seed::each(SEEDS, |seed| {
        let mut world = world(seed);
        world.client(async move |stub| {
            let answer = stub.expect(question(), Carrier::Udp).await?;
            assert_eq!(answer.message.rcode(), Rcode::NOERROR);
            assert!(!answer.message.answer.is_empty(), "{answer:?}");
            // The priming goes on after the reply, which does not wait for it: the run ends once it has, each message
            // taking up to turmoil's 100 ms, far below the first timeout of a server.
            tokio::time::sleep(SECOND).await;
            Ok(())
        });
        let events = world.run().expect("the run passes its checks");
        // RFC 8109 §3: the root's servers asked for once, alongside.
        let primed = served_each(&events)
            .into_iter()
            .filter(|((_, name, qtype, _), _)| name == "." && *qtype == RecordType::NS.0)
            .map(|(_, count)| count)
            .sum::<usize>();
        assert_eq!(primed, 1, "{events:#?}");
    });
}

/// The resolutions of a thread that wait on one query in flight, the one sending it apart (`WAITERS`, D195).
const WAITERS: usize = 100;

/// The extended error of `message`, if any.
fn ede(message: &Message<'_>) -> Option<InfoCode> {
    (message.edns.iter())
        .flat_map(|edns| &edns.options)
        .find_map(|option| match option {
            EdnsOption::Ede(ede) => Some(ede.code),
            _ => None,
        })
}

/// The root server the capture asked silent, one resolution sends its query, `WAITERS` wait on it, and one more is
/// shed: SERVFAIL Not Ready at once. Each client gets its reply within `Limits::time` (D195).
#[test]
fn d195_past_the_waiters_on_a_silent_server_a_resolution_is_shed() {
    seed::each(SEEDS, |seed| {
        let capture = capture();
        let root = capture.exchanges.first().expect("an exchange").server;
        let heard = Rc::new(RefCell::new(Vec::new()));
        let silent = {
            let heard = Rc::clone(&heard);
            Answers::new().faulty(move |question, _| {
                heard
                    .borrow_mut()
                    .push((tokio::time::Instant::now(), question.clone()));
                Verdict::Drop
            })
        };
        let mut world = Topology::new()
            .authoritative_at(root, silent)
            .resolution(&capture)
            .resolver(move |_| pipeline(&capture))
            .dedensd()
            .tick(TICK)
            .build(seed);
        let replies = Rc::new(RefCell::new(Vec::new()));
        let got = Rc::clone(&replies);
        world.client(async move |stub| {
            let asked = (0..WAITERS + 2).map(|_| stub.ask(question(), Carrier::Udp));
            for outcome in join_all(asked).await {
                let Outcome::Answered(answer) = outcome? else {
                    return Err("no reply".into());
                };
                got.borrow_mut().push(answer);
            }
            Ok(())
        });
        world.run().expect("the run passes its checks");
        // The client's question, asked of the silent server once until that query timed out; the root's servers
        // primed besides. Past it, resolutions with no other server ask it again (D196).
        let heard = heard.borrow();
        let first = (heard.iter())
            .find(|(_, asked)| *asked == question())
            .map(|&(at, _)| at)
            .expect("the question asked");
        let sent = (heard.iter())
            .filter(|(at, asked)| *asked == question() && *at < first + InfraCache::UNKNOWN_TIMEOUT)
            .count();
        assert_eq!(sent, 1, "{heard:#?}");
        let replies = replies.borrow();
        assert_eq!(replies.len(), WAITERS + 2);
        let shed = (replies.iter())
            .filter(|answer| ede(&answer.message) == Some(InfoCode::NOT_READY))
            .count();
        assert_eq!(shed, 1, "{replies:#?}");
        // Each message takes up to turmoil's 100 ms each way.
        let bound = Limits::default().time + 2 * Duration::from_millis(100);
        assert!(
            replies.iter().all(|answer| answer.elapsed <= bound),
            "{replies:#?}"
        );
    });
}

#[test]
fn rfc5452_5_a_hundred_identical_questions_send_each_query_once() {
    seed::each(SEEDS, |seed| {
        let mut world = world(seed);
        world.client(async move |stub| {
            let asked = (0..CLIENTS).map(|_| stub.expect(question(), Carrier::Udp));
            for answer in join_all(asked).await {
                assert_eq!(answer?.message.rcode(), Rcode::NOERROR);
            }
            Ok(())
        });
        let events = world.run().expect("the run passes its checks");
        let served = served_each(&events);
        assert!(!served.is_empty());
        assert!(
            served.values().all(|&count| count == 1),
            "a query sent twice: {served:#?}"
        );
    });
}
