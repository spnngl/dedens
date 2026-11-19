//! `dedensd` resolving from the root (D195) on the Internet of every captured resolution (D189), asked each
//! capture's question in turn: the oracle's answer (D133) whatever the servers do wrong, each question within the
//! queries a resolution may send (D191), SERVFAIL before the client's timer when a delegation is lame (RFC 4697
//! §2.1), and the same again after a restart, which empties the caches and primes anew (RFC 8109 §3). D196.

use std::cell::RefCell;
use std::collections::{BTreeMap, BTreeSet, HashSet};
use std::net::{IpAddr, SocketAddr};
use std::num::NonZeroU64;
use std::rc::Rc;
use std::sync::Arc;
use std::time::Duration;

use dedens_cache::{Cache, Config};
use dedens_proto::rdata::RData;
use dedens_proto::{Name, Question, Rcode, RecordType};
use dedens_resolver::{Caches, DEFAULT_CAPACITY, InfraCache, Limits, Minimisation, RrsetCache};
use dedens_roots::RootHints;
use dedens_server::{Pipeline, Recurse, Stage};
use dedens_sim::client::Carrier;
use dedens_sim::fault::{Fault, Server};
use dedens_sim::seed::{self, Rng, Seed};
use dedens_sim::stub::{Outcome, Stub};
use dedens_sim::topology::{Topology, World};
use dedens_sim::upstream::{Answers, Conduct, Verdict};
use dedens_testkit::recursion::Resolution;

use crate::util::{SECOND, TIMEOUT};

/// The seeds of `just check`, two of D133's five within the family's budget (D164): 1 and 42 failed a first draft
/// (a silent server never asked again, a referral to servers no capture asked). `DEDENS_SIM_SEED` and
/// `DEDENS_SIM_RUNS` replace them.
const SEEDS: &[u64] = &[1, 42];

/// The step of the simulation: the latencies of its links are tens of milliseconds.
const TICK: Duration = Duration::from_millis(10);

/// The least and the most a message takes. Turmoil's 0 to 100 ms spreads a round trip past the RTO the infra cache
/// derives from its samples (D194), from 50 ms, and live servers timed out (D196).
const LATENCY: (Duration, Duration) = (Duration::from_millis(20), Duration::from_millis(30));

/// One UDP response in `LOSS` a server loses (D196).
const LOSS: NonZeroU64 = NonZeroU64::new(10).expect("not zero");

/// The queries the root's servers were asked for their own names: priming, paid by no client (D195).
fn priming(question: &Question<'_>) -> bool {
    question.name.is_root() && question.qtype == RecordType::NS
}

/// Every captured resolution.
fn captures() -> Vec<Resolution> {
    Resolution::all()
        .into_iter()
        .map(|(_, resolution)| resolution)
        .collect()
}

/// The questions of `captures`, in their order.
fn questions(captures: &[Resolution]) -> Vec<Question<'static>> {
    (captures.iter())
        .map(|capture| Question::new(capture.name.clone(), capture.rtype))
        .collect()
}

/// Each zone and the servers it was asked at.
type Zones = Vec<(Name<'static>, BTreeSet<IpAddr>)>;

/// The zones of `captures`, in the order first asked, each asked of one server of each family
/// (testdata/recursion/README.md).
fn zones(captures: &[Resolution]) -> Zones {
    let mut zones: Zones = Vec::new();
    for exchange in captures.iter().flat_map(|capture| &capture.exchanges) {
        match zones.iter_mut().find(|(zone, _)| *zone == exchange.zone) {
            Some((_, servers)) => {
                servers.insert(exchange.server);
            }
            None => zones.push((exchange.zone.clone(), BTreeSet::from([exchange.server]))),
        }
    }
    zones
}

/// A cache stage, one shard (D133), then a recurse stage whose caches are steered to the servers `zones` holds, its
/// questions not minimised as the captures' were not (D198).
fn pipeline(zones: &Zones, captures: &[Resolution]) -> Pipeline {
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
    steer(&caches, zones, captures);
    Pipeline::new(vec![
        Stage::Cache(Arc::new(Cache::new(config).expect("valid settings"))),
        Stage::Recurse(Recurse::new(Arc::new(caches)).with_minimisation(Minimisation::Off)),
    ])
}

/// Has the resolver skip every address the root's hints and `captures` show but the servers of `zones`, as it skips
/// a server timed out `TIMEOUT_LIMIT` times in a row (D194) until its probe: each timeout doubles the server's from
/// the first, until the probe is `MAX_TIMEOUT` on, the run's length. The resolver draws among the hosts of the run
/// alone, the others being none. Marked lame instead, they would be asked once the zone's hosts are, as lame servers
/// are when no other is left (RFC 4697 §2.2.1).
fn steer(caches: &Caches, zones: &Zones, captures: &[Resolution]) {
    let mut known: HashSet<IpAddr> = (caches.roots.servers().iter())
        .flat_map(dedens_roots::Server::addresses)
        .collect();
    for exchange in captures.iter().flat_map(|capture| &capture.exchanges) {
        let response = dedens_testkit::message(&exchange.response);
        known.extend(
            (response.answer.iter().chain(&response.additional)).filter_map(|r| match r.data() {
                RData::A(v4) => Some(IpAddr::from(v4)),
                RData::Aaaa(v6) => Some(IpAddr::from(v6)),
                _ => None,
            }),
        );
    }
    let hosted = |address: &IpAddr| zones.iter().any(|(_, servers)| servers.contains(address));
    for &address in known.iter().filter(|address| !hosted(address)) {
        let mut sent = InfraCache::UNKNOWN_TIMEOUT;
        while sent < InfraCache::MAX_TIMEOUT {
            // The resolver's clock starts at 0 with the run, and again with a restart.
            (caches.infra).timeout(SocketAddr::new(address, 53), sent, 0);
            sent *= 2;
        }
    }
}

/// What a server does wrong.
#[derive(Debug, Clone, Copy)]
enum Broken {
    /// Changes each response as the conduct says.
    Conducts(Conduct),
    /// Never answers.
    Silent,
}

/// The questions the servers heard, in order, each counted once whether answered or not, with the server.
type Heard = Rc<RefCell<Vec<(IpAddr, Question<'static>)>>>;

/// A world of every capture's servers, `broken` misbehaving and each losing one UDP response in `loss` if any, and
/// `dedensd` resolving from the root, with what the servers heard. Each server of a zone answers every question the
/// zone was asked with the response first captured: servers of one zone may refer to different servers of a child
/// (Akamai's do), and the capture asked those of the first referral.
fn world(
    seed: Seed,
    broken: &BTreeMap<IpAddr, Broken>,
    loss: Option<NonZeroU64>,
) -> (World, Heard) {
    let captures = captures();
    let zones = zones(&captures);
    let heard: Heard = Rc::default();
    let mut topology = Topology::new();
    for capture in &captures {
        topology = topology.resolution(capture);
    }
    let servers: BTreeSet<IpAddr> = (zones.iter())
        .flat_map(|(_, servers)| servers.iter().copied())
        .collect();
    for server in servers {
        let held = (captures.iter())
            .flat_map(|capture| &capture.exchanges)
            .filter(|exchange| {
                zones
                    .iter()
                    .any(|(zone, at)| *zone == exchange.zone && at.contains(&server))
            });
        let answers = Answers::default().exchanges(held);
        let (answers, silent) = match broken.get(&server) {
            Some(Broken::Conducts(conduct)) => (answers.conduct(*conduct), false),
            Some(Broken::Silent) => (answers, true),
            None => (answers, false),
        };
        let answers = match loss {
            Some(one_in) => answers.lossy(one_in),
            None => answers,
        };
        let heard = Rc::clone(&heard);
        let answers = answers.faulty(move |question, _: &mut Rng| {
            heard.borrow_mut().push((server, question.clone()));
            if silent {
                Verdict::Drop
            } else {
                Verdict::Answer
            }
        });
        topology = topology.authoritative_at(server, answers);
    }
    let world = topology
        .resolver(move |_| pipeline(&zones, &captures))
        .dedensd()
        .latency(LATENCY.0, LATENCY.1)
        .tick(TICK)
        .build(seed);
    (world, heard)
}

/// The queries of `heard` a client pays for: all but priming.
fn paid(heard: &[(IpAddr, Question<'static>)]) -> usize {
    heard
        .iter()
        .filter(|(_, question)| !priming(question))
        .count()
}

/// Asks each of `questions` in turn: the oracle's answer, or for those of `lame` SERVFAIL within the client's timer
/// (RFC 4697 §2.1), each within the queries a resolution may send (D191). The queries each cost, priming included.
async fn round(
    stub: &mut Stub,
    questions: &[Question<'static>],
    lame: &[Question<'static>],
    heard: &Heard,
) -> turmoil::Result<Vec<usize>> {
    let mut costs = Vec::with_capacity(questions.len());
    for question in questions {
        let before = heard.borrow().len();
        // The resolver does not ask for RRSIG records alone (D195).
        stub.rules.accept = if question.qtype == RecordType::RRSIG {
            vec![Rcode::NOTIMP]
        } else {
            Vec::new()
        };
        if lame.contains(question) {
            let Outcome::Answered(answer) = stub.ask(question.clone(), Carrier::Udp).await? else {
                return Err(format!("{question:?}: no response").into());
            };
            assert_eq!(answer.message.rcode(), Rcode::SERVFAIL, "{question:?}");
            assert!(answer.elapsed < TIMEOUT, "{question:?}: {answer:?}");
        } else {
            stub.expect(question.clone(), Carrier::Udp).await?;
        }
        let heard = &heard.borrow()[before..];
        let sent = paid(heard);
        assert!(
            sent <= Limits::default().queries,
            "{question:?}: {sent} queries, {heard:?}"
        );
        costs.push(heard.len());
    }
    Ok(costs)
}

/// Asks each capture's question in turn of the servers, `broken` misbehaving and each losing one UDP response
/// in `loss` if any.
fn resolves_each(seed: Seed, broken: &BTreeMap<IpAddr, Broken>, loss: Option<NonZeroU64>) {
    let (mut world, heard) = world(seed, broken, loss);
    world.client(async move |mut stub| {
        round(&mut stub, &questions(&captures()), &[], &heard).await?;
        Ok(())
    });
    world.run().expect("the run passes its checks");
}

/// The server of one family, the seed picking which, of each zone that has one of each, every one `broken`: the
/// zones keep a server that answers.
///
/// A zone whose servers the capture looked up (netmeister.org's) has its IPv6 one broken: the capture holds the
/// addresses of one of the zone's three names, the lookups of the others are refused, and when that name is drawn
/// last its AAAA is past the lookups a delegation may send (D191). The resolver asks its IPv4 server first then,
/// the A looked up before the AAAA.
fn one_of_each_broken(seed: Seed, broken: Broken) -> BTreeMap<IpAddr, Broken> {
    let captures = captures();
    let looked_up: BTreeSet<IpAddr> = (captures.iter().flat_map(|capture| &capture.exchanges))
        .filter(|exchange| matches!(exchange.rtype, RecordType::A | RecordType::AAAA))
        .flat_map(|exchange| dedens_testkit::message(&exchange.response).answer)
        .filter_map(|record| match record.data() {
            RData::A(v4) => Some(IpAddr::from(v4)),
            RData::Aaaa(v6) => Some(IpAddr::from(v6)),
            _ => None,
        })
        .collect();
    let v4 = Rng::new(seed, PICKS).below(2) == 0;
    (zones(&captures).into_iter())
        .filter(|(_, servers)| servers.len() > 1)
        .flat_map(|(_, servers)| {
            assert_eq!(servers.len(), 2, "one server of each family: {servers:?}");
            let v4 = v4 && !servers.is_subset(&looked_up);
            servers
                .into_iter()
                .filter(move |server| server.is_ipv4() == v4)
        })
        .map(|server| (server, broken))
        .collect()
}

/// The stream of the seed the tests pick from before the world is built, apart from the world's.
const PICKS: u64 = 1 << 61;

#[test]
fn rfc1034_5_3_3_each_capture_resolves_from_the_root() {
    seed::each(SEEDS, |seed| resolves_each(seed, &BTreeMap::new(), None));
}

#[test]
fn rfc1035_4_2_1_each_capture_resolves_when_responses_are_lost() {
    seed::each(SEEDS, |seed| {
        resolves_each(seed, &BTreeMap::new(), Some(LOSS));
    });
}

/// RFC 1035 §7.2: a server that does not answer is left for another of the zone.
#[test]
fn rfc1035_7_2_each_capture_resolves_when_a_server_of_each_zone_is_silent() {
    seed::each(SEEDS, |seed| {
        resolves_each(seed, &one_of_each_broken(seed, Broken::Silent), None);
    });
}

/// RFC 7766 §5: a truncated response is asked again over TCP.
#[test]
fn rfc7766_5_each_capture_resolves_when_a_server_of_each_zone_truncates() {
    seed::each(SEEDS, |seed| {
        let broken = one_of_each_broken(seed, Broken::Conducts(Conduct::Truncates));
        resolves_each(seed, &broken, None);
    });
}

/// RFC 6891 §7: a server that answers FORMERR to EDNS is asked again without.
#[test]
fn rfc6891_7_each_capture_resolves_when_a_server_of_each_zone_has_no_edns() {
    seed::each(SEEDS, |seed| {
        let broken = one_of_each_broken(seed, Broken::Conducts(Conduct::NoEdns));
        resolves_each(seed, &broken, None);
    });
}

/// D184, D190: a server that loses the case of `0x20` is asked again over TCP.
#[test]
fn draft_vixie_dnsext_dns0x20_5_each_capture_resolves_when_a_server_of_each_zone_folds_case() {
    seed::each(SEEDS, |seed| {
        let broken = one_of_each_broken(seed, Broken::Conducts(Conduct::FoldsCase));
        resolves_each(seed, &broken, None);
    });
}

/// Every server of a zone, the seed picking which of those whose servers serve no other, refuses: the questions
/// whose captures asked them end in SERVFAIL before the client's timer, the others resolve.
#[test]
fn rfc4697_2_1_a_lame_delegation_fails_before_the_clients_timer() {
    let captures = captures();
    let zones = zones(&captures);
    let alone: Vec<&BTreeSet<IpAddr>> = (zones.iter())
        .filter(|(zone, servers)| {
            !zone.is_root()
                && (zones.iter())
                    .all(|(other, theirs)| other == zone || theirs.is_disjoint(servers))
        })
        .map(|(_, servers)| servers)
        .collect();
    seed::each(SEEDS, |seed| {
        let pick = Rng::new(seed, PICKS).below(u64::try_from(alone.len()).expect("few zones"));
        let lame = alone[usize::try_from(pick).expect("below the zones' count")];
        let broken = (lame.iter())
            .map(|&server| (server, Broken::Conducts(Conduct::Refuses)))
            .collect();
        let failing: Vec<Question<'static>> = (captures.iter())
            // The resolver does not ask for RRSIG records alone (D195).
            .filter(|capture| capture.rtype != RecordType::RRSIG)
            .filter(|capture| {
                (capture.exchanges.iter()).any(|exchange| lame.contains(&exchange.server))
            })
            .map(|capture| Question::new(capture.name.clone(), capture.rtype))
            .collect();
        assert!(!failing.is_empty(), "{lame:?}");
        let (mut world, heard) = world(seed, &broken, None);
        let questions = questions(&captures);
        world.client(async move |mut stub| {
            round(&mut stub, &questions, &failing, &heard).await?;
            Ok(())
        });
        world.run().expect("the run passes its checks");
    });
}

/// The time a round of questions is given; the resolver restarts within a second after.
const ROUND: Duration = Duration::from_secs(5);

/// A resolver restarted between two rounds of questions has empty caches: it primes again (RFC 8109 §3) and asks
/// each question the first round asked again.
#[test]
fn rfc8109_3_a_restarted_resolver_primes_again_and_asks_anew() {
    seed::each(SEEDS, |seed| {
        let (mut world, heard) = world(seed, &BTreeMap::new(), None);
        let at = world.pick(ROUND, ROUND + SECOND);
        world.fault(at, Fault::Bounce(Server::Resolver));
        world.client(async move |mut stub| {
            let questions = questions(&captures());
            let begun = tokio::time::Instant::now();
            let first = round(&mut stub, &questions, &[], &heard).await?;
            assert!(begun.elapsed() < ROUND, "{:?}", begun.elapsed());
            tokio::time::sleep_until(begun + ROUND + 2 * SECOND).await;
            let restarted = heard.borrow().len();
            let second = round(&mut stub, &questions, &[], &heard).await?;
            let primed = heard.borrow()[restarted..]
                .iter()
                .filter(|(_, question)| priming(question))
                .count();
            assert!(primed > 0, "no priming after the restart");
            let asked = |costs: &[usize]| costs.iter().map(|&cost| cost > 0).collect::<Vec<_>>();
            assert_eq!(asked(&first), asked(&second), "{questions:?}");
            Ok(())
        });
        world.run().expect("the run passes its checks");
    });
}
