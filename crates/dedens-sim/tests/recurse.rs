//! `dedensd` resolving from the root (D195) on the Internet of a captured resolution (D189): its recurse stage
//! answers the capture's question (RFC 1034 §5.3.3), priming the root's servers alongside (RFC 8109 §3), and the
//! resolutions of a hundred clients asking it at once send each query once (RFC 5452 §5).

use std::collections::{BTreeMap, HashSet};
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use dedens_cache::{Cache, Config};
use dedens_proto::rdata::RData;
use dedens_proto::{Name, Question, Rcode, RecordType, Transport};
use dedens_resolver::{Caches, DEFAULT_CAPACITY, InfraCache, RrsetCache};
use dedens_roots::RootHints;
use dedens_server::{Pipeline, Recurse, Stage};
use dedens_sim::client::Carrier;
use dedens_sim::seed::{self, Seed};
use dedens_sim::topology::{Topology, World};
use dedens_sim::trace::{Event, What};
use dedens_testkit::recursion::Resolution;
use futures_util::future::join_all;

use crate::util::SEEDS;

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
/// followed.
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
        Stage::Recurse(Recurse::new(Arc::new(caches))),
    ])
}

/// Marks lame, for each zone `capture` asked, every address it shows but the first server it asked there: the
/// resolver then draws the server whose responses the capture followed, the others being no host of the run.
fn steer(caches: &Caches, capture: &Resolution) {
    let mut known: HashSet<IpAddr> = (caches.roots.servers().iter())
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
fn served(events: &[Event]) -> BTreeMap<(IpAddr, String, u16, bool), usize> {
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
            Ok(())
        });
        let events = world.run().expect("the run passes its checks");
        // RFC 8109 §3: the root's servers asked for once, alongside.
        let primed = served(&events)
            .into_iter()
            .filter(|((_, name, qtype, _), _)| name == "." && *qtype == RecordType::NS.0)
            .map(|(_, count)| count)
            .sum::<usize>();
        assert_eq!(primed, 1, "{events:#?}");
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
        let served = served(&events);
        assert!(!served.is_empty());
        assert!(
            served.values().all(|&count| count == 1),
            "a query sent twice: {served:#?}"
        );
    });
}
