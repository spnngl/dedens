//! Loss, delay and reordering on the links of a run (D27, D31, D41, D45): what a query does when its datagrams are
//! lost, late or out of order, at the stub's link to the resolver and at the resolver's to an upstream server.
//!
//! Left to other tests, which this family cites rather than repeats:
//!
//! - The EDNS fallback is off in `dedensd` (`edns_fallback = false`, D46), so no scenario here loses a response to
//!   it; the sans-IO exchange has its own (`crates/dedens-net/tests/rfc6891.rs`, `rfc8906.rs`).
//! - What the exchange does with a late response, a changed query and a spare ID, one message at a time:
//!   `crates/dedens-net/tests/rfc1035.rs` (`a_late_response_to_an_earlier_try_is_taken`), `rfc5452.rs`
//!   (`a_changed_query_goes_with_a_spare_id`) and `rfc7766.rs`.
//! - Queries pipelined on one TCP connection are the compio layer's (`crates/dedens-net/tests/tcp.rs`); the
//!   driver here serves a connection's queries in order, one at a time.
//!
//! The sim client opens a socket for each exchange and reads no UDP once an exchange moved to TCP, so a late datagram
//! after a TC response never reaches the exchange; the effect of a late response on the exchange is checked in the
//! counts of queries sent and answered.
//!
//! A try is spent by a timeout alone (D31): the stub's tries are 5 s each, three of them (D27), the forward stage's
//! 3 s each, two of them (D45), so a forward stage that gives up (6 s) answers SERVFAIL after the stub's first try
//! (5 s) ran out, and the stub takes that late response as it takes any to an earlier try.
//!
//! The last tests: the property, where the seed picks the loss and the delay of each link, and the replay of one of
//! its runs in two processes.

use std::collections::BTreeSet;
use std::net::IpAddr;
use std::time::Duration;

use dedens_net::client::ClientError;
use dedens_net::exchange::{Exchange, Failure, Options, Progress, SPARE_IDS};
use dedens_net::tcp::TcpError;
use dedens_proto::{Message, Question, Rcode, RecordType, Transport};
use dedens_sim::client::Carrier;
use dedens_sim::fault::{Fault, Node};
use dedens_sim::seed::{self, Seed};
use dedens_sim::stub::{Outcome, question};
use dedens_sim::topology::{Topology, World};
use dedens_sim::trace::{self, Event, What};
use dedens_sim::upstream::{Answers, Behaviour, Verdict};
use turmoil::net::UdpSocket;

/// The seeds of `just check`; `DEDENS_SIM_SEED` and `DEDENS_SIM_RUNS` replace them.
const SEEDS: &[u64] = &[0, 1, 7, 42, 2026];

/// Fewer seeds for the scenarios in which a query runs through all its timeouts: each costs the most wall time.
const FEW: &[u64] = &[0, 7];

/// One seed for the scenarios that run for minutes of simulated time, the costliest of all.
const ONE: &[u64] = &[0];

const SECOND: Duration = Duration::from_secs(1);

/// How long the stub waits for a response to each try, and how many tries it makes (D27).
const TIMEOUT: Duration = Duration::from_secs(5);
const TRIES: u32 = 3;

/// How long a forward stage waits for a response to each try, and how many tries it makes of one server (D45).
const FORWARD_TIMEOUT: Duration = Duration::from_secs(3);
const FORWARD_TRIES: u32 = 2;

/// The link between the one client and the resolver, and the one between the resolver and the upstream server.
const STUB_LINK: (Node, Node) = (Node::Client(0), Node::Resolver);
const UPSTREAM_LINK: (Node, Node) = (Node::Resolver, Node::Upstream(0));

/// A server that holds `example.com A` and `google.com TXT` (truncated over UDP).
fn answers() -> Answers {
    Answers::new()
        .captured("a")
        .truncating("truncated", "txt_large")
}

/// `fault` on `link`, as each way.
fn loss(link: (Node, Node), rate: f64) -> Fault {
    Fault::Loss {
        a: link.0,
        b: link.1,
        rate,
    }
}

/// Each message of `link` takes the same time to arrive.
fn delay(link: (Node, Node), time: Duration) -> Fault {
    Fault::Latency {
        a: link.0,
        b: link.1,
        min: time,
        max: time,
    }
}

/// The events of a run, and the address of its resolver.
struct Run {
    events: Vec<Event>,
    resolver: IpAddr,
}

/// How the query of the run's one client went.
#[derive(Debug)]
struct Query {
    /// Queries it sent: one for each try, and one more for the fallback to TCP.
    sends: u32,
    /// From the query to its end.
    took: Duration,
    /// How it ended.
    end: What,
}

impl Run {
    fn count(&self, what: impl Fn(&What) -> bool) -> usize {
        self.events.iter().filter(|event| what(&event.what)).count()
    }

    /// Responses an upstream server sent.
    fn served(&self) -> usize {
        self.count(|what| matches!(what, What::Served { .. }))
    }

    /// Responses an upstream server sent over `transport`.
    fn served_over(&self, over: Transport) -> usize {
        self.count(|what| matches!(what, What::Served { transport, .. } if *transport == over))
    }

    /// Replies the resolver sent: one for each query that reached it.
    fn replied(&self) -> usize {
        self.count(|what| matches!(what, What::Replied { .. }))
    }

    /// Times the resolver started asking an upstream server.
    fn forwarded(&self) -> usize {
        self.count(|what| matches!(what, What::Forwarded { .. }))
    }

    /// The transports of the queries the resolver sent, in order, with their count in their exchange.
    fn sent_by_the_resolver(&self) -> Vec<(u32, Transport)> {
        self.events
            .iter()
            .filter(|event| event.host == self.resolver)
            .filter_map(|event| match event.what {
                What::Sent {
                    sends, transport, ..
                } => Some((u32::from(sends), transport)),
                _ => None,
            })
            .collect()
    }

    /// The most queries one exchange of the resolver sent.
    fn forward_tries(&self) -> u32 {
        self.sent_by_the_resolver()
            .iter()
            .map(|(sends, _)| *sends)
            .max()
            .unwrap_or(0)
    }

    /// The query of the one client.
    fn query(&self) -> Query {
        let asked = self
            .events
            .iter()
            .find(|event| matches!(event.what, What::Asked { .. }))
            .expect("the client asked");
        let end = self
            .events
            .iter()
            .find(|event| {
                event.host == asked.host
                    && matches!(
                        event.what,
                        What::Answered { .. } | What::Failed { .. } | What::Errored { .. }
                    )
            })
            .expect("the query ended");
        let sends = self
            .events
            .iter()
            .filter(|event| event.host == asked.host && matches!(event.what, What::Sent { .. }))
            .count();
        Query {
            sends: u32::try_from(sends).expect("a few"),
            took: end.at.saturating_sub(asked.at),
            end: end.what.clone(),
        }
    }
}

/// One client asks `ask` over UDP, once, and waits `after` more; the server holds `answers`, and `setup` adds what
/// goes wrong.
fn ask_once(
    seed: Seed,
    answers: Answers,
    ask: Question<'static>,
    after: Duration,
    setup: impl FnOnce(&mut World),
) -> Run {
    let mut world = Topology::new().upstream(answers).build(seed);
    setup(&mut world);
    let resolver = world.resolver.ip();
    world.client(async move |stub| {
        stub.ask(ask, Carrier::Udp).await?;
        tokio::time::sleep(after).await;
        Ok(())
    });
    let events = world.run().expect("the run passes its checks");
    Run { events, resolver }
}

/// [`ask_once`] for `example.com A`, which has two records.
fn ask_a(seed: Seed, after: Duration, setup: impl FnOnce(&mut World)) -> Run {
    let ask = question("example.com", RecordType::A);
    ask_once(seed, answers(), ask, after, setup)
}

fn is_records(what: &What) -> bool {
    matches!(
        what,
        What::Answered {
            rcode: Rcode::NOERROR,
            answers: 2,
            ..
        }
    )
}

fn is_servfail(what: &What) -> bool {
    matches!(
        what,
        What::Answered {
            rcode: Rcode::SERVFAIL,
            answers: 0,
            ..
        }
    )
}

/// Asserts that `query` took from `from` up to a second more: the network adds a few tenths at most.
fn assert_took(query: &Query, from: Duration) {
    assert!(
        query.took >= from && query.took < from + SECOND,
        "took {:?}, expected {from:?} and a little: {query:?}",
        query.took
    );
}

#[test]
fn a_lost_query_or_response_costs_one_try() {
    seed::each(ONE, |seed| {
        for lost in [0, 1, TRIES] {
            // The datagrams to the resolver, then the ones back, are lost for the first `lost` tries.
            for (from, to) in [STUB_LINK, (STUB_LINK.1, STUB_LINK.0)] {
                let run = ask_a(seed, Duration::ZERO, |world| {
                    world.fault(Duration::ZERO, Fault::PartitionOneWay { from, to });
                    world.fault(TIMEOUT * lost, Fault::RepairOneWay { from, to });
                });
                let query = run.query();
                let queries_lost = from == STUB_LINK.0;
                let reached = if queries_lost {
                    TRIES.saturating_sub(lost).min(1)
                } else {
                    (lost + 1).min(TRIES)
                };
                if lost < TRIES {
                    assert!(is_records(&query.end), "{lost} {query:?}");
                    // Only the timeouts spent tries: the one that got through ends it.
                    assert_eq!(query.sends, lost + 1, "{query:?}");
                    assert_took(&query, TIMEOUT * lost);
                } else {
                    assert!(
                        matches!(
                            query.end,
                            What::Failed {
                                failure: Failure::TimedOut { sends: 3 },
                                ..
                            }
                        ),
                        "{query:?}"
                    );
                    assert_took(&query, TIMEOUT * TRIES);
                }
                assert_eq!(run.replied(), reached as usize, "{lost} {query:?}");
                // The resolver asked the server once: its cache answered the tries that came again.
                assert_eq!(run.served(), usize::from(reached > 0), "{lost} {query:?}");
                assert_eq!(
                    run.forwarded(),
                    usize::from(reached > 0),
                    "{lost} {query:?}"
                );
            }
        }
    });
}

#[test]
fn a_lossy_stub_link_ends_in_the_records_or_a_timeout_after_every_try() {
    seed::each(FEW, |seed| {
        for rate in [0.1, 0.25, 0.5] {
            let run = ask_a(seed, Duration::ZERO, |world| {
                world.fault(Duration::ZERO, loss(STUB_LINK, rate));
            });
            let query = run.query();
            if is_records(&query.end) {
                assert!(query.sends <= TRIES, "{rate} {query:?}");
                assert_took(&query, TIMEOUT * (query.sends - 1));
                // The response that arrived answers a query that arrived.
                assert!(
                    (1..=query.sends as usize).contains(&run.replied()),
                    "{rate} {query:?}"
                );
            } else {
                assert!(
                    matches!(
                        query.end,
                        What::Failed {
                            failure: Failure::TimedOut { sends: 3 },
                            ..
                        }
                    ),
                    "{rate} {query:?}"
                );
                assert_eq!(query.sends, TRIES, "{rate} {query:?}");
                assert_took(&query, TIMEOUT * TRIES);
            }
            // However many tries came, the server was asked at most once: the cache kept its answer.
            assert!(run.served() <= 1, "{rate} {query:?}");
        }
    });
}

#[test]
fn a_lossy_upstream_link_ends_in_the_records_or_the_resolvers_servfail() {
    seed::each(FEW, |seed| {
        for rate in [0.1, 0.25, 0.5] {
            let run = ask_a(seed, Duration::ZERO, |world| {
                world.fault(Duration::ZERO, loss(UPSTREAM_LINK, rate));
            });
            let query = run.query();
            // The stub's link is sound: it always gets an answer, never the silence of a failure (D41).
            assert!(
                is_records(&query.end) || is_servfail(&query.end),
                "{rate} {query:?}"
            );
            if is_servfail(&query.end) {
                // SERVFAIL when the forward stage spent its tries: two of 3 s.
                assert_took(&query, FORWARD_TIMEOUT * FORWARD_TRIES);
            } else {
                assert!(
                    query.took < FORWARD_TIMEOUT * FORWARD_TRIES + SECOND,
                    "{query:?}"
                );
            }
            assert!(run.forward_tries() <= FORWARD_TRIES, "{rate} {query:?}");
        }
    });
}

#[test]
fn a_dead_upstream_link_ends_in_servfail_when_the_forward_stage_gives_up() {
    seed::each(FEW, |seed| {
        let run = ask_a(seed, Duration::ZERO, |world| {
            world.fault(
                Duration::ZERO,
                Fault::Partition(UPSTREAM_LINK.0, UPSTREAM_LINK.1),
            );
        });
        let query = run.query();
        assert!(is_servfail(&query.end), "{query:?}");
        // The stub's first try ran out at 5 s and its second went out; the response to the first, at 6 s, ends it.
        assert_eq!(query.sends, 2, "{query:?}");
        assert_took(&query, FORWARD_TIMEOUT * FORWARD_TRIES);
        assert_eq!(run.forward_tries(), FORWARD_TRIES, "{query:?}");
        assert_eq!(run.served(), 0, "{query:?}");
    });
}

#[test]
fn a_stub_that_waits_on_tcp_past_the_forward_stage_gets_servfail() {
    seed::each(FEW, |seed| {
        // The server takes the connection and never answers: the resolver asks over TCP as the stub did.
        let mut world = Topology::new()
            .upstream(answers().tcp(Behaviour::Silent))
            .build(seed);
        world.client(async move |stub| {
            // The resolver's 6 s outlast the stub's try of 5 s: its second try answers.
            let outcome = stub
                .ask(question("example.com", RecordType::A), Carrier::Tcp)
                .await?;
            let Outcome::Answered(answer) = outcome else {
                return Err(format!("no answer: {outcome:?}").into());
            };
            assert_eq!(answer.message.rcode(), Rcode::SERVFAIL);
            assert!(
                answer.elapsed >= FORWARD_TIMEOUT * FORWARD_TRIES,
                "{answer:?}"
            );
            Ok(())
        });
        world.run().expect("the run passes its checks");
    });
}

#[test]
fn a_response_later_than_the_try_timeout_still_ends_the_stub_exchange() {
    seed::each(ONE, |seed| {
        // Each message takes `one_way` on the stub link: a round trip of twice that. The queries go out at 0, 5 and
        // 10 s; the response to the first ends the exchange when it arrives, which the table gives.
        for (one_way, sends) in [(1, 1), (3, 2), (6, 3)] {
            let one_way = SECOND * one_way;
            let run = ask_a(seed, Duration::ZERO, |world| {
                world.fault(Duration::ZERO, delay(STUB_LINK, one_way));
            });
            let query = run.query();
            assert!(is_records(&query.end), "{one_way:?} {query:?}");
            assert_eq!(query.sends, sends, "{one_way:?} {query:?}");
            assert_took(&query, 2 * one_way);
        }
    });
}

#[test]
fn a_response_later_than_every_try_is_lost() {
    seed::each(ONE, |seed| {
        // A round trip of 16 s: after the third try's 15 s. The late responses arrive while the client is waiting still.
        let one_way = 8 * SECOND;
        let run = ask_a(seed, 8 * SECOND, |world| {
            world.fault(Duration::ZERO, delay(STUB_LINK, one_way));
        });
        let query = run.query();
        assert!(
            matches!(
                query.end,
                What::Failed {
                    failure: Failure::TimedOut { sends: 3 },
                    ..
                }
            ),
            "{query:?}"
        );
        assert_took(&query, TIMEOUT * TRIES);
    });
}

#[test]
fn a_response_later_than_the_forward_timeout_still_ends_the_forward_exchange() {
    seed::each(FEW, |seed| {
        // Each message takes `one_way` between the resolver and the server. The forward stage sends again after 3 s.
        for (one_way, forward_tries) in [(1, 1), (2, 2)] {
            let one_way = SECOND * one_way;
            let run = ask_a(seed, Duration::ZERO, |world| {
                world.fault(Duration::ZERO, delay(UPSTREAM_LINK, one_way));
            });
            let query = run.query();
            assert!(is_records(&query.end), "{one_way:?} {query:?}");
            assert_eq!(run.forward_tries(), forward_tries, "{one_way:?} {query:?}");
            // The stub never ran out of time, and the resolver's second try had not reached the server.
            assert_eq!(query.sends, 1, "{one_way:?} {query:?}");
            assert_eq!(run.served(), 1, "{one_way:?} {query:?}");
            assert_took(&query, 2 * one_way);
        }
    });
}

#[test]
fn a_response_later_than_the_forward_stage_is_lost_and_servfail_stands() {
    seed::each(ONE, |seed| {
        // A round trip of 8 s: the forward stage gave up at 6 s. The late responses arrive after the client is done.
        let run = ask_a(seed, 10 * SECOND, |world| {
            world.fault(Duration::ZERO, delay(UPSTREAM_LINK, 4 * SECOND));
        });
        let query = run.query();
        assert!(is_servfail(&query.end), "{query:?}");
        assert_took(&query, FORWARD_TIMEOUT * FORWARD_TRIES);
        assert_eq!(run.forward_tries(), FORWARD_TRIES, "{query:?}");
        // What arrived late was not kept: the cache stored the SERVFAIL of the first pass, and no more.
        assert_eq!(
            run.count(|what| matches!(what, What::Stored { .. })),
            1,
            "{:#?}",
            run.events
        );
    });
}

#[test]
fn a_late_response_to_the_first_try_does_not_send_a_changed_query_again() {
    seed::each(SEEDS, |seed| {
        // The server's first response is held 3.5 s, past the forward stage's 3 s: the second try goes out, and its
        // response, truncated, has the exchange ask again over TCP, which the server answers after a second. The
        // first response arrives during that, and nothing comes of it: one query over TCP, no more.
        let calls = std::cell::Cell::new(0);
        let server = answers().faulty(move |_, _| {
            calls.set(calls.get() + 1);
            match calls.get() {
                1 => Verdict::Delay(SECOND * 7 / 2),
                3 => Verdict::Delay(SECOND),
                _ => Verdict::Answer,
            }
        });
        let run = ask_once(
            seed,
            server,
            question("google.com", RecordType::TXT),
            SECOND,
            |_| {},
        );
        let query = run.query();
        assert!(
            matches!(&query.end, What::Answered { rcode: Rcode::NOERROR, answers, .. } if *answers > 1),
            "{query:?}"
        );
        assert_eq!(
            run.sent_by_the_resolver(),
            [
                (1, Transport::Udp),
                (2, Transport::Udp),
                (3, Transport::Tcp)
            ],
            "{query:?}"
        );
        assert_eq!(run.served_over(Transport::Tcp), 1, "{query:?}");
        assert_eq!(run.served_over(Transport::Udp), 2, "{query:?}");
        assert_eq!(query.sends, 1, "{query:?}");
    });
}

#[test]
fn a_truncated_response_whose_tcp_retry_is_lost_fails_after_the_tries_without_hanging() {
    seed::each(ONE, |seed| {
        // The server is asked directly: TC over UDP, then the query over TCP, which it never answers. The fallback is
        // a send, not a try (D31): the TCP query is sent on each of the three timeouts.
        let mut world = Topology::new()
            .upstream(answers().tcp(Behaviour::Silent))
            .build(seed);
        let server = world.upstreams[0];
        let resolver = world.resolver.ip();
        world.client(async move |stub| {
            let query = Message::query(0, question("google.com", RecordType::TXT));
            let outcome = stub.ask_query(query, server, Carrier::Udp).await?;
            assert!(
                matches!(outcome, Outcome::Failed(Failure::TimedOut { sends: 4 })),
                "{outcome:?}"
            );
            Ok(())
        });
        let events = world.run().expect("the run passes its checks");
        let run = Run { events, resolver };
        assert_took(&run.query(), TIMEOUT * TRIES);
    });
}

#[test]
fn a_truncated_response_whose_tcp_connection_closes_fails_at_once() {
    seed::each(FEW, |seed| {
        // A server that closes each connection as it is made: the client tries a second, then gives up (D27).
        let mut world = Topology::new()
            .upstream(answers().tcp(Behaviour::Close(0)))
            .build(seed);
        let server = world.upstreams[0];
        let resolver = world.resolver.ip();
        world.client(async move |stub| {
            let query = Message::query(0, question("google.com", RecordType::TXT));
            let outcome = stub.ask_query(query, server, Carrier::Udp).await?;
            assert!(
                matches!(outcome, Outcome::Io(ClientError::Tcp(TcpError::Closed))),
                "{outcome:?}"
            );
            Ok(())
        });
        let events = world.run().expect("the run passes its checks");
        let run = Run { events, resolver };
        assert!(run.query().took < SECOND, "{:?}", run.query());
    });
}

#[test]
fn an_upstream_that_truncates_and_loses_the_tcp_retry_ends_in_servfail() {
    seed::each(FEW, |seed| {
        let run = ask_once(
            seed,
            answers().tcp(Behaviour::Silent),
            question("google.com", RecordType::TXT),
            Duration::ZERO,
            |_| {},
        );
        let query = run.query();
        assert!(
            matches!(
                &query.end,
                What::Answered {
                    rcode: Rcode::SERVFAIL,
                    answers: 0,
                    ..
                }
            ),
            "{query:?}"
        );
        // The stub's second try went out at 5 s, and the response to the first came at 6 s: UDP, TCP, TCP.
        assert_took(&query, FORWARD_TIMEOUT * FORWARD_TRIES);
        assert_eq!(run.forward_tries(), 3, "{query:?}");
    });
}

/// The question `google.com TXT`, and the order of the answers' arrival, makes the third query the first back.
#[test]
fn responses_in_another_order_end_the_exchange_of_their_own_query() {
    seed::each(SEEDS, |seed| {
        // Those of `example.com A` wait a second at the server: the TXT response, sent last, comes first.
        let server = answers().faulty(|ask, _| {
            if ask.qtype == RecordType::A {
                Verdict::Delay(SECOND)
            } else {
                Verdict::Answer
            }
        });
        let mut world = Topology::new().upstream(server).build(seed);
        world.fault(
            Duration::ZERO,
            Fault::Latency {
                a: STUB_LINK.0,
                b: STUB_LINK.1,
                min: Duration::ZERO,
                max: Duration::from_millis(300),
            },
        );
        let resolver = world.resolver;
        world.client(async move |_| {
            // Three exchanges on one socket, two of them for one question with their own IDs, as a pool shares one.
            let asks = [
                question("example.com", RecordType::A),
                question("example.com", RecordType::A),
                question("google.com", RecordType::TXT),
            ];
            let socket = UdpSocket::bind("0.0.0.0:0").await?;
            let mut exchanges = Vec::new();
            for (id, ask) in (1..).zip(&asks) {
                let query = Message::query(id, ask.clone());
                let exchange = Exchange::start(
                    query,
                    resolver,
                    Options::default(),
                    [0; SPARE_IDS],
                    tokio::time::Instant::now().into_std(),
                )?;
                socket.send_to(exchange.wire(), resolver).await?;
                exchanges.push(Some(exchange));
            }
            let mut order = Vec::new();
            let mut buffer = vec![0; usize::from(u16::MAX)];
            while exchanges.iter().any(Option::is_some) {
                let (len, from) =
                    tokio::time::timeout(5 * SECOND, socket.recv_from(&mut buffer)).await??;
                let wire = buffer.get(..len).unwrap_or_default().to_vec();
                let mut ended = Vec::new();
                for (index, slot) in exchanges.iter_mut().enumerate() {
                    let Some(exchange) = slot.take() else {
                        continue;
                    };
                    let now = tokio::time::Instant::now().into_std();
                    match exchange.receive(from, Transport::Udp, wire.clone(), now) {
                        Progress::Wait(exchange) => *slot = Some(exchange),
                        Progress::Done(Ok(response)) => ended.push((index, response)),
                        other => return Err(format!("{other:?}").into()),
                    }
                }
                // Each datagram answers the one query with its ID and question, and no other.
                let [(index, response)] = ended.as_slice() else {
                    return Err(format!("{} exchanges took it", ended.len()).into());
                };
                let got = Message::decode(&response.wire)?.message.into_owned();
                assert_eq!(got.questions, [asks[*index].clone()]);
                assert_eq!(usize::from(got.header.id), index + 1);
                order.push(*index);
            }
            // The response to the last query came first, so the queries were answered out of order.
            assert_eq!(order.first(), Some(&2), "{order:?}");
            assert_eq!(order.iter().collect::<BTreeSet<_>>().len(), 3, "{order:?}");
            Ok(())
        });
        world.run().expect("the run passes its checks");
    });
}

#[test]
fn several_tcp_connections_at_once_each_get_their_own_answer() {
    seed::each(SEEDS, |seed| {
        let mut world = Topology::new().upstream(answers()).build(seed);
        let asks = [
            ("example.com", RecordType::A, 2),
            ("google.com", RecordType::TXT, 0),
            ("example.com", RecordType::A, 2),
        ];
        for (index, (name, qtype, records)) in asks.into_iter().enumerate() {
            world.fault(
                Duration::ZERO,
                Fault::Latency {
                    a: Node::Client(index),
                    b: Node::Resolver,
                    min: Duration::ZERO,
                    max: Duration::from_millis(400),
                },
            );
            world.client(async move |stub| {
                // `expect` checks it is a response to this question, and not a failure.
                let answer = stub.expect(question(name, qtype), Carrier::Tcp).await?;
                assert_eq!(answer.transport, Transport::Tcp);
                if records > 0 {
                    assert_eq!(answer.message.answer.len(), records);
                } else {
                    assert!(answer.message.answer.len() > 1);
                }
                Ok(())
            });
        }
        world.fault(
            Duration::ZERO,
            Fault::Latency {
                a: UPSTREAM_LINK.0,
                b: UPSTREAM_LINK.1,
                min: Duration::ZERO,
                max: Duration::from_millis(400),
            },
        );
        let events = world.run().expect("the run passes its checks");
        let hosts: BTreeSet<_> = events
            .iter()
            .filter(|event| matches!(event.what, What::Answered { .. }))
            .map(|event| event.host)
            .collect();
        assert_eq!(hosts.len(), 3, "{events:#?}");
    });
}

#[test]
fn an_answer_in_the_cache_serves_the_queries_a_lossy_network_repeats_without_the_server() {
    seed::each(ONE, |seed| {
        let mut world = Topology::new().upstream(answers()).build(seed);
        // The links turn lossy after the first answer, which a sound network got.
        for link in [STUB_LINK, UPSTREAM_LINK] {
            world.fault(SECOND / 2, loss(link, 0.5));
        }
        let resolver = world.resolver.ip();
        world.client(async move |stub| {
            stub.expect(question("example.com", RecordType::A), Carrier::Udp)
                .await?;
            tokio::time::sleep(SECOND).await;
            // The cache keeps it for at least a minute (`min_ttl`): the later queries, 15 s each at the most, fit.
            for _ in 0..3 {
                let outcome = stub
                    .ask(question("example.com", RecordType::A), Carrier::Udp)
                    .await?;
                match outcome {
                    Outcome::Answered(answer) => assert_eq!(answer.message.answer.len(), 2),
                    Outcome::Failed(Failure::TimedOut { sends: 3 }) => {}
                    other => return Err(format!("{other:?}").into()),
                }
            }
            Ok(())
        });
        let run = Run {
            events: world.run().expect("the run passes its checks"),
            resolver,
        };
        // One question went to the server, once, and one response went into the cache.
        assert_eq!(run.forwarded(), 1, "{:#?}", run.events);
        assert_eq!(run.served(), 1, "{:#?}", run.events);
        assert_eq!(
            run.count(|what| matches!(what, What::Stored { .. })),
            1,
            "{:#?}",
            run.events
        );
        // Each query that reached the resolver was replied to from it, the first aside.
        let answered = run.count(|what| matches!(what, What::Answered { .. }));
        assert!(run.replied() >= answered, "{:#?}", run.events);
    });
}

/// The loss rates, and the longest delays, a link may get: below the forward stage's 3 s and the stub's 5 s, and
/// above.
const RATES: [f64; 4] = [0.0, 0.1, 0.25, 0.5];
const DELAYS_MS: [u64; 5] = [0, 200, 2_000, 4_000, 7_000];

/// A run in which two clients each ask three questions, over UDP or TCP as the seed picks, and the seed picks the
/// loss and the delay of each link: the stub's links and the resolver's to the server. Returns the events and the
/// address of the resolver.
fn lossy(seed: Seed) -> Run {
    // The links are lossy and slow as the oracle's bounds and the duration of the run allow.
    let mut world = Topology::new()
        .upstream(answers())
        .duration(15 * 60 * SECOND)
        .build(seed);
    for link in [
        (Node::Client(0), Node::Resolver),
        (Node::Client(1), Node::Resolver),
        UPSTREAM_LINK,
    ] {
        let rate = RATES[world.choose(RATES.len())];
        let max = Duration::from_millis(DELAYS_MS[world.choose(DELAYS_MS.len())]);
        world.fault(Duration::ZERO, loss(link, rate));
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
    let resolver = world.resolver.ip();
    for _ in 0..2 {
        let carrier = if world.choose(2) == 0 {
            Carrier::Udp
        } else {
            Carrier::Tcp
        };
        world.client(async move |stub| {
            for (name, qtype) in [
                ("example.com", RecordType::A),
                ("google.com", RecordType::TXT),
                ("example.com", RecordType::A),
            ] {
                stub.ask(question(name, qtype), carrier).await?;
            }
            Ok(())
        });
    }
    let events = world.run().expect("the run passes its checks");
    Run { events, resolver }
}

/// The property of the family: whatever the seed does to the links, each query ends by its deadline (the checks of
/// the stub) in the data of the server, SERVFAIL or a failure of the exchange; no more than its tries were spent;
/// the resolver asked the server no more than its tries; and a response of the server came only for a query the
/// resolver sent.
#[test]
fn whatever_the_links_lose_and_delay_queries_end_well() {
    seed::each(FEW, |seed| {
        let run = lossy(seed);
        let events = &run.events;
        let asked = run.count(|what| matches!(what, What::Asked { .. }));
        let ended = run.count(|what| {
            matches!(
                what,
                What::Answered { .. } | What::Failed { .. } | What::Errored { .. }
            )
        });
        assert_eq!(asked, 6, "{events:#?}");
        assert_eq!(asked, ended, "{events:#?}");
        for event in events {
            if let What::Failed { failure, .. } = &event.what {
                // Every try ran out; a fallback to TCP is one send more.
                assert!(
                    matches!(failure, Failure::TimedOut { sends } if u32::from(*sends) >= TRIES),
                    "{events:#?}"
                );
            }
            // The forward stage tries a server twice, and asks again over TCP after TC.
            if event.host == run.resolver
                && let What::Sent { sends, .. } = event.what
            {
                assert!(u32::from(sends) <= FORWARD_TRIES + 1, "{events:#?}");
            }
        }
        let sent = run.sent_by_the_resolver().len();
        assert!(run.served() <= sent, "{events:#?}");
    });
}

/// One seed gives one trace in two processes (D133), the family's own scenario: lossy and slow links, the cache, TC.
#[test]
fn a_lossy_run_replays_in_two_processes() {
    let runs = std::cell::Cell::new(0);
    seed::in_two_processes("a_lossy_run_replays_in_two_processes", ONE, |seed| {
        runs.set(runs.get() + 1);
        trace::digest(&lossy(seed).events)
    });
    assert!(runs.get() > 0);
}
