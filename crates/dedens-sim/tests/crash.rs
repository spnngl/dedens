//! A host that crashes or restarts in the middle of an exchange costs a try, never a hang or a wrong answer
//! (D27, D31, D41, D45, D133).
//!
//! `baseline.rs` crashes the resolver before the first query and has a crashed host in its seven-way property;
//! here the host goes down while queries are in flight, on each of the three hosts, over UDP and TCP.

use std::net::{IpAddr, SocketAddr};
use std::time::Duration;

use dedens_net::client::ClientError;
use dedens_net::exchange::Failure;
use dedens_net::tcp::TcpError;
use dedens_proto::{Rcode, RecordType};
use dedens_sim::client::Carrier;
use dedens_sim::fault::{Fault, Node, Server};
use dedens_sim::seed::{self, Seed};
use dedens_sim::stub::{Outcome, question};
use dedens_sim::topology::{Topology, World};
use dedens_sim::trace::{self, Event, What};
use dedens_sim::upstream::{Answers, Verdict};

use crate::util::{SECOND, SEEDS, answers_and_txt, served_by};

/// Seeds for the scripts that run over both carriers or wait out the client's tries.
const FEW: &[u64] = &[0, 7];

const MS: Duration = Duration::from_millis(1);

/// [`answers_and_txt`], answering each query after a second: a query it got is in flight for that long.
fn slow() -> Answers {
    answers_and_txt().faulty(|_, _| Verdict::Delay(SECOND))
}

/// The queries of the scripts: one of each of the two captures.
const QUESTIONS: [(&str, RecordType); 2] = [
    ("example.com", RecordType::A),
    ("google.com", RecordType::TXT),
];

/// Two clients, each asking one of [`QUESTIONS`] over `carrier` and expecting records.
fn clients_expecting_records(world: &mut World, carrier: Carrier) {
    for (name, qtype) in QUESTIONS {
        world.client(async move |stub| {
            let answer = stub.expect(question(name, qtype), carrier).await?;
            assert_eq!(answer.message.rcode(), Rcode::NOERROR);
            assert!(!answer.message.answer.is_empty(), "{answer:?}");
            Ok(())
        });
    }
}

/// Every message of the link takes 10 ms. A host restarting at the very instant a peer connects to it refuses the
/// connection, which the client does not retry; the scripts that restart a host under a TCP connection keep clear
/// of that instant with a link that never takes less. A datagram in transit when its destination restarts reaches the
/// new host: the scripts that restart a host under a query in flight make the link fast enough for the query to
/// have arrived before the restart.
fn steady(world: &mut World, a: Node, b: Node) {
    let at = Duration::ZERO;
    let ten = 10 * MS;
    world.fault(
        at,
        Fault::Latency {
            a,
            b,
            min: ten,
            max: ten,
        },
    );
}

/// How many events `what` picks from `host`.
fn count(events: &[Event], host: IpAddr, what: impl Fn(&What) -> bool) -> usize {
    events
        .iter()
        .filter(|event| event.host == host && what(&event.what))
        .count()
}

/// How many times the resolver forwarded a query to `server`.
fn forwarded_to(events: &[Event], resolver: IpAddr, server: SocketAddr) -> usize {
    count(
        events,
        resolver,
        |what| matches!(what, What::Forwarded { server: to, .. } if *to == server),
    )
}

/// Where `fault` is in the trace, or `None` if the run has no such fault. The trace's order, not the times: an
/// event at the instant of a fault may come before or after it, and `World::run` makes a fault at the first step at
/// or past its time.
fn position(events: &[Event], fault: Fault) -> Option<usize> {
    let fault = What::Fault(fault);
    events.iter().position(|event| event.what == fault)
}

/// How many queries the clients asked, and how many ended.
fn asked_and_ended(events: &[Event]) -> (usize, usize) {
    let asked = events
        .iter()
        .filter(|event| matches!(event.what, What::Asked { .. }))
        .count();
    let ended = events
        .iter()
        .filter(|event| {
            matches!(
                event.what,
                What::Answered { .. } | What::Failed { .. } | What::Errored { .. }
            )
        })
        .count();
    (asked, ended)
}

/// With two upstream servers, the first crashing under queries in flight (UDP exchanges the resolver retries, TCP
/// connections it never hears from again), the forward stage asks the second (D41) and the client gets records.
#[test]
fn a_crashed_upstream_is_left_for_the_next() {
    for carrier in [Carrier::Udp, Carrier::Tcp] {
        seed::each(FEW, |seed| {
            let mut world = Topology::new()
                .upstream(slow())
                .upstream(answers_and_txt())
                .build(seed);
            let at = world.pick(100 * MS, 900 * MS);
            world.fault(at, Fault::Crash(Server::Upstream(0)));
            let (resolver, first, second) =
                (world.resolver.ip(), world.upstreams[0], world.upstreams[1]);
            clients_expecting_records(&mut world, carrier);
            let events = world.run().expect("the run passes its checks");
            // The answer it was holding never left the crashed host.
            assert_eq!(served_by(&events, first.ip()), 0, "{events:#?}");
            assert!(forwarded_to(&events, resolver, second) >= 2, "{events:#?}");
        });
    }
}

/// One upstream server that crashes and comes back: the resolver's second send of the query (D45: two tries
/// of 3 s each) reaches it, and the client needs no second try of its own.
#[test]
fn a_bounced_upstream_answers_the_second_send_of_the_resolver() {
    seed::each(SEEDS, |seed| {
        let mut world = Topology::new().upstream(slow()).build(seed);
        let crash = world.pick(100 * MS, 800 * MS);
        let back = crash + world.pick(100 * MS, 500 * MS);
        world.fault(crash, Fault::Crash(Server::Upstream(0)));
        world.fault(back, Fault::Bounce(Server::Upstream(0)));
        let (resolver, upstream) = (world.resolver.ip(), world.upstreams[0].ip());
        world.client(async move |stub| {
            let answer = stub
                .expect(question("example.com", RecordType::A), Carrier::Udp)
                .await?;
            assert!(answer.elapsed < 5 * SECOND, "{answer:?}");
            Ok(())
        });
        let events = world.run().expect("the run passes its checks");
        // The query of the crashed host is lost; the one after the bounce is answered.
        assert_eq!(served_by(&events, upstream), 1, "{events:#?}");
        assert_eq!(
            count(&events, resolver, |what| matches!(
                what,
                What::Sent { sends: 2, .. }
            )),
            1,
            "{events:#?}"
        );
    });
}

/// The only upstream server stays down: the resolver gives up on it and answers SERVFAIL, in its two tries
/// (D45), not at the client's deadline.
#[test]
fn an_upstream_that_stays_down_ends_in_servfail() {
    seed::each(SEEDS, |seed| {
        let mut world = Topology::new().upstream(slow()).build(seed);
        let at = world.pick(100 * MS, 900 * MS);
        world.fault(at, Fault::Crash(Server::Upstream(0)));
        world.client(async move |stub| {
            let outcome = stub
                .ask(question("example.com", RecordType::A), Carrier::Udp)
                .await?;
            let Outcome::Answered(answer) = outcome else {
                return Err(format!("no answer: {outcome:?}").into());
            };
            assert_eq!(answer.message.rcode(), Rcode::SERVFAIL);
            assert!(answer.elapsed < 8 * SECOND, "{answer:?}");
            Ok(())
        });
        world.run().expect("the run passes its checks");
    });
}

/// An upstream server that restarts while the resolver waits on a TCP connection: the connection closes, the
/// resolver opens a new one (D27) and the same exchange is answered, no new try spent.
#[test]
fn a_bounced_upstream_gets_one_new_connection() {
    seed::each(SEEDS, |seed| {
        let mut world = Topology::new().upstream(slow()).build(seed);
        steady(&mut world, Node::Resolver, Node::Upstream(0));
        let at = world.pick(100 * MS, 800 * MS);
        world.fault(at, Fault::Bounce(Server::Upstream(0)));
        let (resolver, upstream) = (world.resolver.ip(), world.upstreams[0]);
        clients_expecting_records(&mut world, Carrier::Tcp);
        let events = world.run().expect("the run passes its checks");
        // One exchange each, and no second send.
        assert_eq!(forwarded_to(&events, resolver, upstream), 2, "{events:#?}");
        assert_eq!(
            count(&events, resolver, |what| matches!(
                what,
                What::Sent { sends, .. } if *sends > 1
            )),
            0,
            "{events:#?}"
        );
        assert_eq!(served_by(&events, upstream.ip()), 2, "{events:#?}");
    });
}

/// A server that closes the connection twice, the new one included, fails the exchange (D31): the resolver
/// asks the next server when there is one, and answers SERVFAIL when there is not.
#[test]
fn a_second_close_fails_the_exchange() {
    for backup in [false, true] {
        seed::each(SEEDS, |seed| {
            let mut topology = Topology::new().upstream(slow());
            if backup {
                topology = topology.upstream(answers_and_txt());
            }
            let mut world = topology.build(seed);
            steady(&mut world, Node::Resolver, Node::Upstream(0));
            // It restarts every 300 ms for two seconds: no connection lives the second it takes to be answered, and
            // the new one of the exchange is one of them.
            let first = world.pick(100 * MS, 400 * MS);
            for step in 0..7 {
                world.fault(first + step * 300 * MS, Fault::Bounce(Server::Upstream(0)));
            }
            let (resolver, upstreams) = (world.resolver.ip(), world.upstreams.clone());
            world.client(async move |stub| {
                let begun = tokio::time::Instant::now();
                let outcome = stub
                    .ask(question("example.com", RecordType::A), Carrier::Tcp)
                    .await?;
                let Outcome::Answered(answer) = outcome else {
                    return Err(format!("no answer: {outcome:?}").into());
                };
                assert!(answer.elapsed < 4 * SECOND, "{answer:?}");
                let rcode = if backup {
                    Rcode::NOERROR
                } else {
                    Rcode::SERVFAIL
                };
                assert_eq!(answer.message.rcode(), rcode, "{answer:?}");
                // The restarts go on to the last, which a backup's early answer would leave unmade.
                tokio::time::sleep_until(begun + first + 6 * 300 * MS).await;
                Ok(())
            });
            let events = world.run().expect("the run passes its checks");
            assert_eq!(
                forwarded_to(&events, resolver, upstreams[0]),
                1,
                "{events:#?}"
            );
            assert_eq!(served_by(&events, upstreams[0].ip()), 0, "{events:#?}");
            if backup {
                assert_eq!(
                    forwarded_to(&events, resolver, upstreams[1]),
                    1,
                    "{events:#?}"
                );
            }
        });
    }
}

/// The resolver restarts with a UDP query in flight: the query dies with it, the client's second try is
/// answered by the new resolver, and the response the upstream server sent the old one goes nowhere.
#[test]
fn a_bounced_resolver_answers_the_clients_second_try() {
    seed::each(SEEDS, |seed| {
        let mut world = Topology::new().upstream(slow()).build(seed);
        // The default links take up to 100 ms: a query still on its way at the bounce (seed 8662461762334067750:
        // sent at 5 ms, bounced at 104 ms, arrived at 105 ms) reaches the new resolver, which answers it at once.
        steady(&mut world, Node::Client(0), Node::Resolver);
        let at = world.pick(100 * MS, 800 * MS);
        world.fault(at, Fault::Bounce(Server::Resolver));
        let upstream = world.upstreams[0].ip();
        world.client(async move |stub| {
            let answer = stub
                .expect(question("example.com", RecordType::A), Carrier::Udp)
                .await?;
            // Nothing answers before the second try (5 s): not the response the upstream sent the old resolver.
            assert!(answer.elapsed >= 5 * SECOND, "{answer:?}");
            Ok(())
        });
        let events = world.run().expect("the run passes its checks");
        assert_eq!(served_by(&events, upstream), 2, "{events:#?}");
    });
}

/// The resolver restarts with a TCP query in flight: the connection closes, the client opens a new one (D27) and
/// is answered, long before a timeout.
#[test]
fn a_bounced_resolver_gets_one_new_connection() {
    seed::each(SEEDS, |seed| {
        let mut world = Topology::new().upstream(slow()).build(seed);
        steady(&mut world, Node::Client(0), Node::Resolver);
        let at = world.pick(100 * MS, 800 * MS);
        world.fault(at, Fault::Bounce(Server::Resolver));
        world.client(async move |stub| {
            let answer = stub
                .expect(question("example.com", RecordType::A), Carrier::Tcp)
                .await?;
            assert!(answer.elapsed < 3 * SECOND, "{answer:?}");
            Ok(())
        });
        world.run().expect("the run passes its checks");
    });
}

/// A restarted resolver has an empty cache: what it held it asks for again, and keeps again.
#[test]
fn a_bounced_resolver_fills_its_cache_again() {
    seed::each(SEEDS, |seed| {
        let mut world = Topology::new().upstream(answers_and_txt()).build(seed);
        world.fault(3 * SECOND, Fault::Bounce(Server::Resolver));
        let (resolver, upstream) = (world.resolver.ip(), world.upstreams[0].ip());
        world.client(async move |stub| {
            // Asked, kept, answered from the cache, then the bounce at 3 s, then the same again.
            for pause in [SECOND, 2 * SECOND, SECOND, SECOND] {
                stub.expect(question("example.com", RecordType::A), Carrier::Udp)
                    .await?;
                tokio::time::sleep(pause).await;
            }
            Ok(())
        });
        let events = world.run().expect("the run passes its checks");
        assert_eq!(served_by(&events, upstream), 2, "{events:#?}");
        let stored: Vec<_> = events
            .iter()
            .filter(|event| event.host == resolver)
            .filter_map(|event| match event.what {
                What::Stored { entries, .. } => Some(entries),
                _ => None,
            })
            .collect();
        assert_eq!(stored, [1, 1], "{events:#?}");
    });
}

/// The resolver crashes under a query and stays down: the client gets nothing, tries three times and gives up,
/// and the resolver does nothing more.
#[test]
fn a_crashed_resolver_goes_silent() {
    for carrier in [Carrier::Udp, Carrier::Tcp] {
        seed::each(FEW, |seed| {
            let mut world = Topology::new().upstream(slow()).build(seed);
            let at = world.pick(100 * MS, 800 * MS);
            world.fault(at, Fault::Crash(Server::Resolver));
            let resolver = world.resolver.ip();
            world.client(async move |stub| {
                let outcome = stub
                    .ask(question("example.com", RecordType::A), carrier)
                    .await?;
                match (carrier, &outcome) {
                    (Carrier::Udp, Outcome::Failed(Failure::TimedOut { sends: 3 })) => {}
                    // The stalled query closed the connection, and the host is down: the new one never opens, and
                    // the pool's idle timeout ends the exchange (D27).
                    (Carrier::Tcp, Outcome::Io(ClientError::Tcp(TcpError::Connect(error))))
                        if error.kind() == std::io::ErrorKind::TimedOut => {}
                    _ => return Err(format!("{carrier:?}: {outcome:?}").into()),
                }
                Ok(())
            });
            let events = world.run().expect("the run passes its checks");
            let crash = position(&events, Fault::Crash(Server::Resolver))
                .expect("the crash under the query");
            assert!(
                events[crash..].iter().all(|event| event.host != resolver),
                "{events:#?}"
            );
        });
    }
}

/// A query's answer, the way the stream below needs it: whether the clients got records.
fn got_records(what: &What) -> bool {
    matches!(
        what,
        What::Answered {
            rcode: Rcode::NOERROR,
            answers: 1..,
            ..
        }
    )
}

/// The seed picks a host, a moment and whether it comes back, and a stream of queries over UDP or TCP runs
/// through it; the stub's checks pass, and each query:
///
/// - ends: an answer, or the failure of a client that tried;
/// - finds the crashed host silent while it is down;
/// - is answered with records when it starts after the host is back, or when the other upstream server is up;
/// - never finds a cache the restart should have emptied.
#[test]
fn whatever_the_seed_crashes_queries_end_well() {
    seed::each(SEEDS, |seed| {
        let mut world = Topology::new()
            .upstream(answers_and_txt().faulty(|_, rng| {
                if rng.below(2) == 0 {
                    Verdict::Delay(SECOND)
                } else {
                    Verdict::Answer
                }
            }))
            .upstream(answers_and_txt())
            .duration(600 * SECOND)
            .build(seed);
        let resolver = world.resolver.ip();
        let (server, host) = match world.choose(3) {
            0 => (Server::Resolver, resolver),
            1 => (Server::Upstream(0), world.upstreams[0].ip()),
            _ => (Server::Upstream(1), world.upstreams[1].ip()),
        };
        let at = world.pick(Duration::ZERO, 6 * SECOND);
        let back = (world.choose(2) == 0).then(|| at + world.pick(500 * MS, 4 * SECOND));
        world.fault(at, Fault::Crash(server));
        if let Some(back) = back {
            world.fault(back, Fault::Bounce(server));
        }
        let carrier = if world.choose(2) == 0 {
            Carrier::Udp
        } else {
            Carrier::Tcp
        };
        let pause = world.pick(100 * MS, 3 * SECOND);
        let last = back.unwrap_or(at);
        world.client(async move |stub| {
            // The client starts after the run does: `begun + last` is past `last`.
            let begun = tokio::time::Instant::now();
            for (name, qtype) in QUESTIONS.into_iter().cycle().take(6) {
                stub.ask(question(name, qtype), carrier).await?;
                tokio::time::sleep(pause).await;
            }
            // A last query after the last fault, which the run then always makes.
            tokio::time::sleep_until(begun + last).await;
            stub.ask(question(QUESTIONS[0].0, QUESTIONS[0].1), carrier)
                .await?;
            Ok(())
        });
        let events = world.run().expect("the run passes its checks");
        let (asked, ended) = asked_and_ended(&events);
        assert_eq!((asked, ended), (7, 7), "{events:#?}");
        // The crashed host does nothing while it is down; what it sent before may still land, on another host.
        let crash = position(&events, Fault::Crash(server));
        let bounce = position(&events, Fault::Bounce(server));
        let down = |index: usize| {
            crash.is_some_and(|crash| index > crash) && bounce.is_none_or(|bounce| index < bounce)
        };
        assert!(
            events
                .iter()
                .enumerate()
                .all(|(index, event)| event.host != host || !down(index)),
            "{events:#?}"
        );
        let asks: Vec<_> = events
            .iter()
            .filter(|event| matches!(event.what, What::Asked { .. }))
            .collect();
        let ends: Vec<_> = events
            .iter()
            .enumerate()
            .filter(|(_, event)| {
                matches!(
                    event.what,
                    What::Answered { .. } | What::Failed { .. } | What::Errored { .. }
                )
            })
            .collect();
        for (ask, (_, end)) in asks.iter().zip(&ends) {
            // With the resolver and one upstream server up, the stream gets records, late at worst.
            let up =
                server != Server::Resolver || back.is_some_and(|back| ask.at >= back + 100 * MS);
            assert!(!up || got_records(&end.what), "{ask:?} {end:?} {events:#?}");
        }
        if server == Server::Resolver {
            // What a dead resolver sent is on the wire for 100 ms, no more.
            assert!(
                ends.iter().all(|(index, end)| {
                    !matches!(end.what, What::Answered { .. })
                        || end.at <= at + 100 * MS
                        || bounce.is_some_and(|bounce| *index > bounce)
                }),
                "{events:#?}"
            );
            // The cache died with it: the first thing it keeps afterwards is the first entry.
            let first = events
                .iter()
                .enumerate()
                .filter(|(_, event)| event.host == resolver)
                .find_map(|(index, event)| match event.what {
                    What::Stored { entries, .. } if bounce.is_some_and(|bounce| index > bounce) => {
                        Some(entries)
                    }
                    _ => None,
                });
            assert!(first.is_none_or(|entries| entries == 1), "{events:#?}");
        }
    });
}

/// The digest of the trace of a run where each host of the topology goes down under UDP queries in flight, at times
/// the seed picks.
fn digest(seed: Seed) -> u64 {
    let mut world = Topology::new()
        .upstream(slow())
        .upstream(answers_and_txt())
        .build(seed);
    let upstream = world.pick(100 * MS, 900 * MS);
    let resolver = world.pick(100 * MS, 900 * MS);
    world.fault(upstream, Fault::Crash(Server::Upstream(0)));
    world.fault(resolver, Fault::Bounce(Server::Resolver));
    clients_expecting_records(&mut world, Carrier::Udp);
    trace::digest(&world.run().expect("the run passes its checks"))
}

#[test]
fn one_seed_gives_one_trace_in_two_processes() {
    let runs = std::cell::Cell::new(0);
    seed::in_two_processes(
        module_path!(),
        "one_seed_gives_one_trace_in_two_processes",
        FEW,
        |seed| {
            runs.set(runs.get() + 1);
            digest(seed)
        },
    );
    // The helper runs the scenario, in this process or the child's.
    assert!(runs.get() > 0);
}
