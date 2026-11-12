//! A resolver and its clients when the network splits and heals (D41, D43, D45, D27): the upstream servers cut off
//! one after another, a cut that loses only the queries or only the responses, held packets that arrive late, a
//! client cut off from the resolver. The last test has the seed cut and heal links between random hosts.
//!
//! `tests/baseline.rs` has the first use of each fault (one upstream cut, a one-way cut, hold and release, the stale
//! answer of one cut upstream): the tests here have two upstream servers, and say what the trace shows.

use std::net::{IpAddr, SocketAddr};
use std::num::NonZeroU8;
use std::time::Duration;

use dedens_cache::Config;
use dedens_net::exchange::Failure;
use dedens_proto::{Rcode, RecordType};
use dedens_server::Forward;
use dedens_sim::client::Carrier;
use dedens_sim::fault::{Fault, Node};
use dedens_sim::resolver::pipeline_forwarding;
use dedens_sim::seed::{self, Seed};
use dedens_sim::stub::{Answer, Outcome, question};
use dedens_sim::topology::{Topology, World};
use dedens_sim::trace::{Event, What};
use tokio::time::Instant;

use crate::util::{SECOND, SEEDS, answers_and_txt, served_by};

/// Fewer seeds for the scenarios in which a query runs through its timeouts: each costs the most wall time, and the
/// module keeps to its budget.
const FEW: &[u64] = &[0, 7];

/// How long the resolver waits for each try of a query to an upstream server, and how many tries it makes: two
/// seconds for each server, so that two cut off ones end a query before the stub's own five-second timeout.
const FORWARD_TIMEOUT: Duration = SECOND;
const FORWARD_TRIES: u8 = 2;
const PER_SERVER: Duration = Duration::from_secs(2);

/// A world of two upstream servers, the resolver forwarding with the timeout and tries above to a cache of
/// `config`.
fn world(seed: Seed, config: &Config) -> World {
    let config = config.clone();
    Topology::new()
        .upstream(answers_and_txt())
        .upstream(answers_and_txt())
        .resolver(move |upstreams| {
            let forward = Forward::new(upstreams.iter().cloned())
                .expect("an upstream server to forward to")
                .with_timeout(FORWARD_TIMEOUT)
                .with_tries(NonZeroU8::new(FORWARD_TRIES).expect("tries are not zero"));
            pipeline_forwarding(config.clone(), forward)
        })
        .build(seed)
}

/// A cache whose entries live a second, and that answers stale after 200 ms.
fn short_lived() -> Config {
    Config {
        min_ttl: 1,
        max_ttl: 1,
        stale_answer_after_ms: 200,
        ..Config::default()
    }
}

const UP0: Node = Node::Upstream(0);
const UP1: Node = Node::Upstream(1);

/// What a client got of its query, as an error if it got no response.
fn answered(outcome: Outcome) -> Result<Answer, String> {
    match outcome {
        Outcome::Answered(answer) => Ok(answer),
        other => Err(format!("no answer: {other:?}")),
    }
}

/// The upstream servers the resolver sent a UDP query to, in order, one for each server it tried.
fn tried_over_udp(events: &[Event]) -> Vec<SocketAddr> {
    events
        .iter()
        .filter_map(|event| match event.what {
            What::Forwarded {
                server,
                transport: dedens_proto::Transport::Udp,
            } => Some(server),
            _ => None,
        })
        .collect()
}

/// The queries the resolver sent to `server`, tries included.
fn sent_to(events: &[Event], resolver: IpAddr, server: SocketAddr) -> usize {
    events
        .iter()
        .filter(|event| {
            event.host == resolver
                && matches!(event.what, What::Sent { server: s, .. } if s == server)
        })
        .count()
}

/// The queries for `name` the upstream server at `host` answered.
fn served_for(events: &[Event], host: IpAddr, name: &str) -> usize {
    let name = name.parse().expect("a name");
    events
        .iter()
        .filter(|event| {
            event.host == host
                && matches!(&event.what, What::Served { question, .. } if question.name == name)
        })
        .count()
}

fn replied(events: &[Event]) -> usize {
    events
        .iter()
        .filter(|event| matches!(event.what, What::Replied { .. }))
        .count()
}

/// How the queries of the clients ended.
fn ends(events: &[Event]) -> Vec<&What> {
    events
        .iter()
        .map(|event| &event.what)
        .filter(|what| {
            matches!(
                what,
                What::Answered { .. } | What::Failed { .. } | What::Errored { .. }
            )
        })
        .collect()
}

#[test]
fn the_second_upstream_answers_when_the_first_is_cut_off() {
    seed::each(SEEDS, |seed| {
        let mut world = world(seed, &Config::default());
        world.fault(Duration::ZERO, Fault::Partition(Node::Resolver, UP0));
        let (resolver, upstreams) = (world.resolver.ip(), world.upstreams.clone());
        world.client(async move |stub| {
            let answer = stub
                .expect(question("example.com", RecordType::A), Carrier::Udp)
                .await?;
            assert_eq!(answer.message.answer.len(), 2);
            // The resolver gave up on the first server after its timeout for each try, then asked the second.
            assert!(answer.elapsed >= PER_SERVER, "{:?}", answer.elapsed);
            assert!(answer.elapsed < PER_SERVER + SECOND, "{:?}", answer.elapsed);
            Ok(())
        });
        let events = world.run().expect("the run passes its checks");
        // D41: the servers in the order given.
        assert_eq!(tried_over_udp(&events), upstreams, "{events:#?}");
        assert_eq!(
            sent_to(&events, resolver, upstreams[0]),
            usize::from(FORWARD_TRIES),
            "{events:#?}"
        );
        assert_eq!(served_by(&events, upstreams[0].ip()), 0, "{events:#?}");
        assert_eq!(served_by(&events, upstreams[1].ip()), 1, "{events:#?}");
    });
}

#[test]
fn with_every_upstream_cut_off_the_query_ends_in_servfail_within_the_forward_timeouts() {
    seed::each(FEW, |seed| {
        let mut world = world(seed, &Config::default());
        world.fault(Duration::ZERO, Fault::Partition(Node::Resolver, UP0));
        world.fault(Duration::ZERO, Fault::Partition(Node::Resolver, UP1));
        let upstreams = world.upstreams.clone();
        world.client(async move |stub| {
            let ask = question("example.com", RecordType::A);
            let first = answered(stub.ask(ask.clone(), Carrier::Udp).await?)?;
            assert_eq!(first.message.rcode(), Rcode::SERVFAIL);
            assert_eq!(first.message.answer, Vec::new());
            // Each server had its timeout for each try, one after the other, and no more.
            assert!(first.elapsed >= 2 * PER_SERVER, "{:?}", first.elapsed);
            assert!(
                first.elapsed < 2 * PER_SERVER + SECOND,
                "{:?}",
                first.elapsed
            );
            // D43: the failure is held, so that the same question is answered at once, no server asked.
            let second = answered(stub.ask(ask, Carrier::Udp).await?)?;
            assert_eq!(second.message.rcode(), Rcode::SERVFAIL);
            assert!(second.elapsed < SECOND, "{:?}", second.elapsed);
            Ok(())
        });
        let events = world.run().expect("the run passes its checks");
        assert_eq!(tried_over_udp(&events), upstreams, "{events:#?}");
        assert_eq!(served_by(&events, upstreams[0].ip()), 0, "{events:#?}");
        assert_eq!(served_by(&events, upstreams[1].ip()), 0, "{events:#?}");
    });
}

#[test]
fn with_every_upstream_cut_off_a_cached_name_is_answered_stale_and_another_is_not() {
    seed::each(FEW, |seed| {
        let mut world = world(seed, &short_lived());
        world.fault(SECOND / 2, Fault::Partition(Node::Resolver, UP0));
        world.fault(SECOND / 2, Fault::Partition(Node::Resolver, UP1));
        world.client(async move |stub| {
            let fresh = answered(
                stub.ask(question("example.com", RecordType::A), Carrier::Udp)
                    .await?,
            )?;
            assert!(!fresh.stale);
            // The entry has expired, and no server can be asked again.
            tokio::time::sleep(SECOND).await;
            let stale = answered(
                stub.ask(question("example.com", RecordType::A), Carrier::Udp)
                    .await?,
            )?;
            // RFC 8767 §5: EDE 3 on the copy, which the resolver's timer sent long before the stub's timeout.
            assert!(stale.stale, "{stale:?}");
            assert_eq!(stale.message.answer.len(), 2);
            assert!(stale.elapsed < SECOND, "{:?}", stale.elapsed);
            // A name never cached has no stale copy to answer with: SERVFAIL, after the servers' timeouts.
            let other = answered(
                stub.ask(question("google.com", RecordType::TXT), Carrier::Udp)
                    .await?,
            )?;
            assert!(!other.stale);
            assert_eq!(other.message.rcode(), Rcode::SERVFAIL);
            assert!(other.elapsed >= 2 * PER_SERVER, "{:?}", other.elapsed);
            Ok(())
        });
        world.run().expect("the run passes its checks");
    });
}

/// One client asks `example.com A` once, with the first upstream server cut as `cut` says, the second reachable.
fn cut_first_upstream(seed: Seed, cut: Fault) -> (Vec<Event>, IpAddr, Vec<SocketAddr>) {
    let mut world = world(seed, &Config::default());
    world.fault(Duration::ZERO, cut);
    world.client(async move |stub| {
        let answer = stub
            .expect(question("example.com", RecordType::A), Carrier::Udp)
            .await?;
        assert!(answer.elapsed >= PER_SERVER, "{:?}", answer.elapsed);
        Ok(())
    });
    let (resolver, upstreams) = (world.resolver.ip(), world.upstreams.clone());
    let events = world.run().expect("the run passes its checks");
    (events, resolver, upstreams)
}

#[test]
fn a_cut_of_the_queries_and_a_cut_of_the_responses_end_the_same_and_differ_in_the_trace() {
    seed::each(FEW, |seed| {
        let (queries_lost, resolver, upstreams) = cut_first_upstream(
            seed,
            Fault::PartitionOneWay {
                from: Node::Resolver,
                to: UP0,
            },
        );
        let (responses_lost, _, _) = cut_first_upstream(
            seed,
            Fault::PartitionOneWay {
                from: UP0,
                to: Node::Resolver,
            },
        );
        // The client sees one thing: the second server's records, after the first one's timeouts.
        assert_eq!(ends(&queries_lost), ends(&responses_lost));
        assert_eq!(tried_over_udp(&queries_lost), upstreams);
        assert_eq!(tried_over_udp(&responses_lost), upstreams);
        for events in [&queries_lost, &responses_lost] {
            assert_eq!(
                sent_to(events, resolver, upstreams[0]),
                usize::from(FORWARD_TRIES),
                "{events:#?}"
            );
            assert_eq!(served_by(events, upstreams[1].ip()), 1, "{events:#?}");
        }
        // The queries that never arrived were not served, the ones whose responses were lost were.
        assert_eq!(served_by(&queries_lost, upstreams[0].ip()), 0);
        assert_eq!(
            served_by(&responses_lost, upstreams[0].ip()),
            usize::from(FORWARD_TRIES)
        );
    });
}

#[test]
fn the_first_upstream_is_asked_again_when_its_link_is_repaired() {
    seed::each(FEW, |seed| {
        let mut world = world(seed, &short_lived());
        world.fault(Duration::ZERO, Fault::Partition(Node::Resolver, UP0));
        // After the first query ends, and after its entry expires.
        let heal = world.pick(Duration::from_millis(3200), Duration::from_millis(3700));
        world.fault(heal, Fault::Repair(Node::Resolver, UP0));
        let upstreams = world.upstreams.clone();
        world.client(async move |stub| {
            let begun = Instant::now();
            // Answered by the second server, after the first one's timeouts.
            stub.expect(question("example.com", RecordType::A), Carrier::Udp)
                .await?;
            // Healed and expired (an entry lives a second): the next query goes to the first server again, and it
            // answers.
            tokio::time::sleep_until(begun + heal + Duration::from_millis(50)).await;
            let again = stub
                .expect(question("example.com", RecordType::A), Carrier::Udp)
                .await?;
            assert!(again.elapsed < SECOND, "{:?}", again.elapsed);
            Ok(())
        });
        let events = world.run().expect("the run passes its checks");
        assert_eq!(
            tried_over_udp(&events),
            [upstreams[0], upstreams[1], upstreams[0]],
            "{events:#?}"
        );
        assert_eq!(served_by(&events, upstreams[0].ip()), 1, "{events:#?}");
        assert_eq!(served_by(&events, upstreams[1].ip()), 1, "{events:#?}");
    });
}

#[test]
fn queries_held_on_the_upstream_link_do_not_answer_a_later_query() {
    seed::each(FEW, |seed| {
        let mut world = world(seed, &Config::default());
        world.fault(Duration::ZERO, Fault::Hold(Node::Resolver, UP0));
        let release = world.pick(5 * SECOND / 2, 3 * SECOND);
        world.fault(release, Fault::Release(Node::Resolver, UP0));
        let upstreams = world.upstreams.clone();
        world.client(async move |stub| {
            let begun = Instant::now();
            // The first server's two tries are held; the second server answers.
            stub.expect(question("example.com", RecordType::A), Carrier::Udp)
                .await?;
            // A different question, 100 ms before the release: it is held too, with the first query's two tries
            // behind it. Their responses reach the resolver after the exchanges of the first query have ended,
            // along with the genuine one of this query, and the stub's own checks fail the run if the resolver
            // took a response for another question.
            tokio::time::sleep_until(begun + release - Duration::from_millis(100)).await;
            let answer = stub
                .expect(question("google.com", RecordType::TXT), Carrier::Udp)
                .await?;
            assert!(answer.message.answer.len() > 1);
            assert!(answer.elapsed < SECOND, "{:?}", answer.elapsed);
            Ok(())
        });
        let events = world.run().expect("the run passes its checks");
        assert_eq!(
            tried_over_udp(&events),
            [upstreams[0], upstreams[1], upstreams[0]],
            "{events:#?}"
        );
        // The first server answered the first query's two held tries and the second question (over UDP, then TCP
        // for the truncated answer); the second server answered the first query once.
        assert_eq!(
            served_for(&events, upstreams[0].ip(), "example.com"),
            2,
            "{events:#?}"
        );
        assert!(
            served_for(&events, upstreams[0].ip(), "google.com") >= 1,
            "{events:#?}"
        );
        assert_eq!(
            served_for(&events, upstreams[1].ip(), "example.com"),
            1,
            "{events:#?}"
        );
        assert_eq!(served_by(&events, upstreams[1].ip()), 1, "{events:#?}");
    });
}

#[test]
fn responses_held_on_the_client_link_do_not_answer_a_later_query() {
    seed::each(FEW, |seed| {
        let client = IpAddr::from([10, 7, 0, 1]);
        let mut world = world(seed, &Config::default());
        world.fault(
            Duration::ZERO,
            Fault::Hold(Node::Host(client), Node::Resolver),
        );
        let release = world.pick(5 * SECOND / 2, 3 * SECOND);
        world.fault(release, Fault::Release(Node::Host(client), Node::Resolver));
        world.client_at(client, async move |mut stub| {
            // One try of a second each: two queries held, and given up on.
            stub.options.timeout = SECOND;
            stub.options.tries = NonZeroU8::MIN;
            for (name, qtype) in [
                ("example.com", RecordType::A),
                ("google.com", RecordType::TXT),
            ] {
                let outcome = stub.ask(question(name, qtype), Carrier::Udp).await?;
                assert!(
                    matches!(outcome, Outcome::Failed(Failure::TimedOut { sends: 1 })),
                    "{outcome:?}"
                );
            }
            // The same question as the first, held with the others until the release: it takes only its own
            // response, and the two the resolver sent to the closed exchanges go nowhere.
            stub.options.timeout = 5 * SECOND;
            let answer = stub
                .expect(question("example.com", RecordType::A), Carrier::Udp)
                .await?;
            assert_eq!(answer.message.answer.len(), 2);
            // The resolver's replies to the others, and the TCP query behind the truncated one, go on a while.
            tokio::time::sleep(SECOND).await;
            Ok(())
        });
        let events = world.run().expect("the run passes its checks");
        // The resolver replied to all three, in time; the client counted the two it gave up on as failures and took
        // one answer.
        assert_eq!(replied(&events), 3, "{events:#?}");
        let ends = ends(&events);
        assert_eq!(ends.len(), 3, "{events:#?}");
        assert_eq!(
            ends.iter()
                .filter(|what| matches!(what, What::Answered { .. }))
                .count(),
            1,
            "{events:#?}"
        );
    });
}

#[test]
fn a_client_cut_off_from_the_resolver_times_out_while_the_resolver_serves_another() {
    seed::each(FEW, |seed| {
        let (cut, free) = (IpAddr::from([10, 7, 0, 1]), IpAddr::from([10, 7, 0, 2]));
        let mut world = world(seed, &Config::default());
        world.fault(
            Duration::ZERO,
            Fault::Partition(Node::Host(cut), Node::Resolver),
        );
        world.client_at(cut, async move |mut stub| {
            stub.options.timeout = SECOND;
            stub.options.tries = NonZeroU8::new(2).ok_or("two is not zero")?;
            let outcome = stub
                .ask(question("example.com", RecordType::A), Carrier::Udp)
                .await?;
            assert!(
                matches!(outcome, Outcome::Failed(Failure::TimedOut { sends: 2 })),
                "{outcome:?}"
            );
            Ok(())
        });
        world.client_at(free, async move |stub| {
            for (name, qtype) in [
                ("example.com", RecordType::A),
                ("google.com", RecordType::TXT),
                ("example.com", RecordType::A),
            ] {
                let answer = stub.expect(question(name, qtype), Carrier::Udp).await?;
                assert!(answer.elapsed < PER_SERVER, "{:?}", answer.elapsed);
                tokio::time::sleep(SECOND).await;
            }
            Ok(())
        });
        let events = world.run().expect("the run passes its checks");
        // None of the cut client's queries reached the resolver: it replied to the other one's three.
        assert_eq!(replied(&events), 3, "{events:#?}");
        assert!(
            events
                .iter()
                .any(|e| e.host == cut && matches!(e.what, What::Failed { .. })),
            "{events:#?}"
        );
    });
}

/// The hosts the seed cuts links between, in the world of two upstream servers and two clients.
const HOSTS: [Node; 5] = [Node::Resolver, UP0, UP1, Node::Client(0), Node::Client(1)];

/// How the seed cuts a link between `a` and `b`, and the fault that heals it: both ways, either way alone, or
/// held.
fn cut_and_heal(a: Node, b: Node, how: usize) -> (Fault, Fault) {
    match how {
        0 => (Fault::Partition(a, b), Fault::Repair(a, b)),
        1 => (
            Fault::PartitionOneWay { from: a, to: b },
            Fault::RepairOneWay { from: a, to: b },
        ),
        2 => (
            Fault::PartitionOneWay { from: b, to: a },
            Fault::RepairOneWay { from: b, to: a },
        ),
        _ => (Fault::Hold(a, b), Fault::Release(a, b)),
    }
}

/// The property of the family: whatever links the seed cuts and heals, between whichever hosts and whenever, while
/// two clients ask a stream of queries, each ends by its deadline in what an upstream server holds, a stale copy of
/// it, SERVFAIL or a failure (the stub's checks), and once every link is healed and the failures' holds have
/// ended, a query is answered with the records.
#[test]
fn whatever_links_the_seed_cuts_queries_end_well_and_the_healed_network_answers() {
    seed::each(&[0, 1, 7], |seed| {
        // Holds of at most two seconds, so that the last query below is not met by one.
        let config = Config {
            min_ttl: 1,
            max_ttl: 2,
            failure_min: 1,
            failure_max: 2,
            stale_recheck: 1,
            stale_answer_after_ms: 200,
            ..Config::default()
        };
        let mut world = world(seed, &config);
        for _ in 0..=world.choose(4) {
            let a = world.choose(HOSTS.len());
            let b = (a + 1 + world.choose(HOSTS.len() - 1)) % HOSTS.len();
            let start = world.pick(Duration::ZERO, 3 * SECOND / 2);
            let end = start + world.pick(SECOND / 2, 2 * SECOND);
            let how = world.choose(4);
            let (cut, heal) = cut_and_heal(HOSTS[a], HOSTS[b], how);
            world.fault(start, cut);
            world.fault(end, heal);
        }
        let queries = [
            ("example.com", RecordType::A),
            ("google.com", RecordType::TXT),
        ];
        for _ in 0..2 {
            let plan: Vec<(Duration, usize)> = (0..5)
                .map(|_| {
                    (
                        world.pick(Duration::ZERO, Duration::from_millis(600)),
                        world.choose(queries.len()),
                    )
                })
                .collect();
            world.client(async move |mut stub| {
                let begun = Instant::now();
                stub.options.timeout = SECOND;
                stub.options.tries = NonZeroU8::MIN;
                for (gap, which) in plan {
                    tokio::time::sleep(gap).await;
                    let (name, qtype) = queries[which];
                    stub.ask(question(name, qtype), Carrier::Udp).await?;
                }
                // Every link was healed by the fourth second, and the failures that came of the cuts are held two seconds more at most.
                tokio::time::sleep_until(begun + 7 * SECOND).await;
                let (name, qtype) = queries[0];
                let answer = stub.expect(question(name, qtype), Carrier::Udp).await?;
                assert_eq!(answer.message.answer.len(), 2);
                Ok(())
            });
        }
        world.run().expect("the run passes its checks");
    });
}
