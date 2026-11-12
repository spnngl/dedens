//! `dedensd`'s own serving loop of UDP and TCP on the resolver host, behind the `Io` seam (D182): the scenarios of
//! the families that concern the server, run again against it under loss, reordering, partitions and restarts, and
//! what the driver of D133 leaves out: queries pipelined on one connection, answered as each can be (RFC 7766
//! §6.2.1.1).
//!
//! The loop records none of the resolver's `Replied`, `Forwarded` and `Stored`: the scenarios count what the clients
//! got, what the resolver sent (`Sent`, its client's) and what the upstream servers answered.
//!
//! The last tests: the property, where the seed picks the faults, and the replay of one of its runs in two processes.

use std::net::IpAddr;
use std::num::NonZeroU8;
use std::time::Duration;

use dedens_cache::Config;
use dedens_net::exchange::Failure;
use dedens_proto::{Message, Rcode, RecordType, Transport};
use dedens_server::Forward;
use dedens_sim::client::Carrier;
use dedens_sim::fault::{Fault, Node, Server};
use dedens_sim::framing;
use dedens_sim::resolver::pipeline_forwarding;
use dedens_sim::seed::{self, Seed};
use dedens_sim::stub::{Outcome, question};
use dedens_sim::topology::{Topology, World};
use dedens_sim::trace::{self, Event, What};
use dedens_sim::upstream::{Answers, Verdict};

use crate::util::{FORWARD_TRIES, SECOND, SEEDS, TRIES, answers_and_txt, served, served_by};

/// Fewer seeds for the scenarios in which a query runs through its timeouts: each costs the most wall time.
const FEW: &[u64] = &[0, 7];

const MS: Duration = Duration::from_millis(1);

/// [`answers_and_txt`], answering `example.com A` after a second: a query for it is in flight for that long.
fn slow_a() -> Answers {
    answers_and_txt().faulty(|ask, _| {
        if ask.qtype == RecordType::A {
            Verdict::Delay(SECOND)
        } else {
            Verdict::Answer
        }
    })
}

/// A world of `upstreams` servers holding [`answers_and_txt`], served by `dedensd`.
fn world(seed: Seed, upstreams: usize) -> World {
    (0..upstreams)
        .fold(Topology::new(), |topology, _| {
            topology.upstream(answers_and_txt())
        })
        .dedensd()
        .build(seed)
}

/// How many of `events` `what` picks.
fn count(events: &[Event], what: impl Fn(&Event) -> bool) -> usize {
    events.iter().filter(|event| what(event)).count()
}

/// The queries the resolver at `resolver` sent upstream, tries included.
fn sent_by(events: &[Event], resolver: IpAddr) -> usize {
    count(events, |event| {
        event.host == resolver && matches!(event.what, What::Sent { .. })
    })
}

/// How the clients' queries ended.
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

/// `tests/baseline.rs`: a query over UDP and one over TCP get the records, and the same question again comes from
/// the cache: the upstream server asked once for each question, twice for the TXT one truncated over UDP.
#[test]
fn udp_and_tcp_answers_and_the_cache() {
    seed::each(SEEDS, |seed| {
        for carrier in [Carrier::Udp, Carrier::Tcp] {
            let mut world = world(seed, 1);
            world.client(async move |stub| {
                for _ in 0..2 {
                    let answer = stub
                        .expect(question("example.com", RecordType::A), carrier)
                        .await?;
                    assert_eq!(answer.transport, Transport::from(carrier));
                    assert_eq!(answer.message.answer.len(), 2);
                }
                // Truncated over UDP upstream, asked again over TCP (D65).
                let answer = stub
                    .expect(question("google.com", RecordType::TXT), carrier)
                    .await?;
                assert!(answer.message.answer.len() > 1);
                Ok(())
            });
            let events = world.run().expect("the run passes its checks");
            // Over TCP, the resolver asks over TCP (D65): the TXT answer is whole at once.
            let asked = match carrier {
                Carrier::Udp => 3,
                _ => 2,
            };
            assert_eq!(served(&events), asked, "{carrier:?}: {events:#?}");
        }
    });
}

/// `tests/partition.rs`: with the first upstream server cut off, its tries time out and the second answers (D41).
#[test]
fn the_second_upstream_answers_when_the_first_is_cut_off() {
    seed::each(SEEDS, |seed| {
        let mut world = Topology::new()
            .upstream(answers_and_txt())
            .upstream(answers_and_txt())
            .resolver(|upstreams| {
                let forward = Forward::new(upstreams.iter().cloned())
                    .expect("an upstream server to forward to")
                    .with_timeout(SECOND)
                    .with_tries(NonZeroU8::new(2).expect("tries are not zero"));
                pipeline_forwarding(Config::default(), forward)
            })
            .dedensd()
            .build(seed);
        world.fault(
            Duration::ZERO,
            Fault::Partition(Node::Resolver, Node::Upstream(0)),
        );
        let (resolver, upstreams) = (world.resolver.ip(), world.upstreams.clone());
        world.client(async move |stub| {
            let answer = stub
                .expect(question("example.com", RecordType::A), Carrier::Udp)
                .await?;
            assert_eq!(answer.message.answer.len(), 2);
            assert!(answer.elapsed >= 2 * SECOND, "{:?}", answer.elapsed);
            assert!(answer.elapsed < 3 * SECOND, "{:?}", answer.elapsed);
            Ok(())
        });
        let events = world.run().expect("the run passes its checks");
        assert_eq!(sent_by(&events, resolver), 3, "{events:#?}");
        assert_eq!(served_by(&events, upstreams[0].ip()), 0, "{events:#?}");
        assert_eq!(served_by(&events, upstreams[1].ip()), 1, "{events:#?}");
    });
}

/// `tests/partition.rs`: with every upstream server cut off, the forward stage gives up (D45) and the client gets
/// SERVFAIL, which the cache then holds (D43).
#[test]
fn with_every_upstream_cut_off_the_query_ends_in_servfail() {
    seed::each(FEW, |seed| {
        let mut world = world(seed, 1);
        world.fault(
            Duration::ZERO,
            Fault::Partition(Node::Resolver, Node::Upstream(0)),
        );
        world.client(async move |stub| {
            for _ in 0..2 {
                let outcome = stub
                    .ask(question("example.com", RecordType::A), Carrier::Udp)
                    .await?;
                let Outcome::Answered(answer) = outcome else {
                    return Err(format!("no answer: {outcome:?}").into());
                };
                assert_eq!(answer.message.rcode(), Rcode::SERVFAIL);
            }
            Ok(())
        });
        let events = world.run().expect("the run passes its checks");
        assert_eq!(served(&events), 0, "{events:#?}");
    });
}

/// `tests/loss.rs`: a client cut off from the resolver times out after its tries, while another is served.
#[test]
fn a_client_cut_off_from_the_resolver_times_out_while_another_is_served() {
    seed::each(FEW, |seed| {
        let mut world = world(seed, 1);
        world.fault(
            Duration::ZERO,
            Fault::Partition(Node::Client(0), Node::Resolver),
        );
        world.client(async move |stub| {
            let outcome = stub
                .ask(question("example.com", RecordType::A), Carrier::Udp)
                .await?;
            assert!(
                matches!(outcome, Outcome::Failed(Failure::TimedOut { sends }) if u32::from(sends) == TRIES),
                "{outcome:?}"
            );
            Ok(())
        });
        world.client(async move |stub| {
            stub.expect(question("example.com", RecordType::A), Carrier::Udp)
                .await?;
            Ok(())
        });
        world.run().expect("the run passes its checks");
    });
}

/// `tests/crash.rs`: the resolver restarts with a UDP query in flight; the client's second try is answered by the
/// new one, its cache empty.
#[test]
fn a_bounced_resolver_answers_the_clients_second_try() {
    seed::each(SEEDS, |seed| {
        let mut world = Topology::new().upstream(slow_a()).dedensd().build(seed);
        let at = world.pick(100 * MS, 800 * MS);
        world.fault(at, Fault::Bounce(Server::Resolver));
        let upstream = world.upstreams[0].ip();
        world.client(async move |stub| {
            let answer = stub
                .expect(question("example.com", RecordType::A), Carrier::Udp)
                .await?;
            assert!(answer.elapsed >= 5 * SECOND, "{answer:?}");
            Ok(())
        });
        let events = world.run().expect("the run passes its checks");
        assert_eq!(served_by(&events, upstream), 2, "{events:#?}");
    });
}

/// `tests/crash.rs`: the resolver restarts with a TCP query in flight; the connection closes, the client opens a new
/// one (D27) and is answered long before a timeout.
#[test]
fn a_bounced_resolver_gets_one_new_connection() {
    seed::each(SEEDS, |seed| {
        let mut world = Topology::new().upstream(slow_a()).dedensd().build(seed);
        // A host restarting at the instant a peer connects refuses it, which the client does not retry.
        world.fault(
            Duration::ZERO,
            Fault::Latency {
                a: Node::Client(0),
                b: Node::Resolver,
                min: 10 * MS,
                max: 10 * MS,
            },
        );
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

/// Not in the driver, which answers a connection's queries in turn: two queries pipelined on one connection are
/// answered as each can be (RFC 7766 §6.2.1.1), the slow one last.
#[test]
fn pipelined_queries_on_one_connection_are_answered_out_of_order() {
    seed::each(SEEDS, |seed| {
        let mut world = Topology::new().upstream(slow_a()).dedensd().build(seed);
        let resolver = world.resolver;
        world.client(async move |_| {
            let mut stream = turmoil::net::TcpStream::connect(resolver).await?;
            for (id, (name, qtype)) in [
                (1, ("example.com", RecordType::A)),
                (2, ("google.com", RecordType::TXT)),
            ] {
                let mut wire = vec![0; 512];
                let len = Message::query(id, question(name, qtype)).encode(&mut wire)?;
                wire.truncate(len);
                framing::write(&mut stream, &wire).await?;
            }
            let mut ids = Vec::new();
            for _ in 0..2 {
                let wire = framing::read(&mut stream).await?;
                let response = Message::decode(&wire)?.message.into_owned();
                assert_eq!(response.rcode(), Rcode::NOERROR);
                ids.push(response.header.id);
            }
            assert_eq!(ids, [2, 1]);
            Ok(())
        });
        world.run().expect("the run passes its checks");
    });
}

/// The loss rates, and the longest delays, a link may get: below the forward stage's 3 s and the stub's 5 s, and
/// above.
const RATES: [f64; 3] = [0.0, 0.1, 0.25];
const DELAYS_MS: [u64; 4] = [0, 200, 2_000, 4_000];

/// A run in which two clients ask three questions each, over UDP or TCP as the seed picks; the seed picks the loss
/// and the delay of each link, and a host that goes down and comes back. Returns the events and the address of the
/// resolver.
fn faulty(seed: Seed) -> (Vec<Event>, IpAddr) {
    let mut world = Topology::new()
        .upstream(answers_and_txt())
        .upstream(answers_and_txt())
        .duration(10 * 60 * SECOND)
        .dedensd()
        .build(seed);
    for link in [
        (Node::Client(0), Node::Resolver),
        (Node::Client(1), Node::Resolver),
        (Node::Resolver, Node::Upstream(0)),
        (Node::Resolver, Node::Upstream(1)),
    ] {
        let rate = RATES[world.choose(RATES.len())];
        let max = Duration::from_millis(DELAYS_MS[world.choose(DELAYS_MS.len())]);
        world.fault(
            Duration::ZERO,
            Fault::Loss {
                a: link.0,
                b: link.1,
                rate,
            },
        );
        world.fault(
            Duration::ZERO,
            Fault::Latency {
                a: link.0,
                b: link.1,
                min: Duration::ZERO,
                max,
            },
        );
    }
    let server = match world.choose(3) {
        0 => Server::Resolver,
        n => Server::Upstream(n - 1),
    };
    let down = world.pick(Duration::ZERO, 4 * SECOND);
    let up = down + world.pick(500 * MS, 4 * SECOND);
    world.fault(down, Fault::Crash(server));
    world.fault(up, Fault::Bounce(server));
    let resolver = world.resolver.ip();
    for _ in 0..2 {
        let carrier = if world.choose(2) == 0 {
            Carrier::Udp
        } else {
            Carrier::Tcp
        };
        world.client(async move |stub| {
            // The client starts after the run does: `begun + up` is past the bounce.
            let begun = tokio::time::Instant::now();
            for (name, qtype) in [
                ("example.com", RecordType::A),
                ("google.com", RecordType::TXT),
            ] {
                stub.ask(question(name, qtype), carrier).await?;
            }
            tokio::time::sleep_until(begun + up).await;
            stub.ask(question("example.com", RecordType::A), carrier)
                .await?;
            Ok(())
        });
    }
    (world.run().expect("the run passes its checks"), resolver)
}

/// The property of the family: whatever the seed does to the links and the hosts, each query ends by its deadline
/// (the checks of the stub) in the data of a server, SERVFAIL or a failure of the exchange, and the resolver tried
/// each server no more than the forward stage's tries and the TCP retry after TC.
#[test]
fn whatever_the_seed_breaks_dedensd_serves_queries_to_their_end() {
    seed::each(FEW, |seed| {
        let (events, resolver) = faulty(seed);
        let asked = count(&events, |event| matches!(event.what, What::Asked { .. }));
        assert_eq!(asked, 6, "{events:#?}");
        assert_eq!(ends(&events).len(), asked, "{events:#?}");
        for event in &events {
            if let What::Sent { sends, .. } = event.what {
                // Each exchange's tries, and one send more for the fallback to TCP after TC.
                let tries = if event.host == resolver {
                    FORWARD_TRIES
                } else {
                    TRIES
                };
                assert!(u32::from(sends) <= tries + 1, "{events:#?}");
            }
        }
    });
}

/// One seed gives one trace in two processes (D133), with `dedensd`'s loop on the resolver host.
#[test]
fn a_faulty_run_replays_in_two_processes() {
    let runs = std::cell::Cell::new(0);
    seed::in_two_processes(
        module_path!(),
        "a_faulty_run_replays_in_two_processes",
        &[0],
        |seed| {
            runs.set(runs.get() + 1);
            trace::digest(&faulty(seed).0)
        },
    );
    assert!(runs.get() > 0);
}
