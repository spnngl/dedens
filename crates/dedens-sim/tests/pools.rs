//! The client's pools on the simulated network, as `dedens-net` runs them (D134): the real `UdpPool` and `TcpPool`
//! behind `Client`, with the seeded faults of the other families. What the sans-IO exchange cannot show: how many
//! connections a pool opens (D27), the inbox of a query (D108), errors of a socket, and DNS over TLS through
//! rustls over the simulated stream.
//!
//! Each scenario has the client host speak to a server host on its own, with no stub and no oracle.

use std::cell::Cell;
use std::net::{IpAddr, SocketAddr};
use std::time::Duration;

use compio::rustls::pki_types::{CertificateDer, ServerName};
use dedens_net::client::{ClientError, Server};
use dedens_net::exchange::{Failure, Options};
use dedens_net::tcp::TcpError;
use dedens_net::tls::Trust;
use dedens_proto::{Message, Rcode, RecordType, Transport};
use dedens_sim::attacker::{Attacker, Injection, Reaction};
use dedens_sim::client::Carrier;
use dedens_sim::dot::{NAME, certificates};
use dedens_sim::fault::{Fault, Node, Server as Host};
use dedens_sim::seed::{self};
use dedens_sim::stub::question;
use dedens_sim::topology::{Topology, World};
use dedens_sim::trace::{self, Event, What};
use dedens_sim::upstream::{Answers, Behaviour, Verdict};

use crate::util::{SECOND, SEEDS, answers, served};

/// Seeds for the scenarios with TLS: a handshake is the slowest thing the simulation does.
const FEW: &[u64] = &[0, 7];

/// Seeds for the scenarios that last many simulated seconds and draw nothing from the seed but the network's.
const ONE: &[u64] = &[0];

const MS: Duration = Duration::from_millis(1);

fn ask() -> Message<'static> {
    Message::query(0, question("example.com", RecordType::A))
}

/// The server at `addr`, its certificate to hold [`NAME`].
fn named(addr: SocketAddr) -> Server {
    Server {
        addr,
        name: Some(ServerName::try_from(NAME).expect("a server name")),
        doh: None,
        docpath: Vec::new(),
    }
}

/// Three queries over DNS over TLS (RFC 7858) from one client, one after the other: the run's trace and the
/// connections the server accepted.
fn dot(seed: seed::Seed) -> (Vec<Event>, usize) {
    let (ca, presented) = certificates(0);
    let dot = answers();
    let connections = dot.connections();
    // The resolver host of every run needs an upstream to forward to; nothing asks it here.
    let mut world = Topology::new().upstream(answers()).build(seed);
    let server = world.dot_server(dot, presented);
    world.client_direct(async move |client| {
        let client = client.trusting(Trust::Roots(vec![ca]));
        for _ in 0..3 {
            let response = client
                .exchange(ask(), named(server), Carrier::Tls, &Options::default())
                .await?;
            assert_eq!(response.transport, Transport::Tls);
            let decoded = Message::decode(&response.wire)?;
            assert_eq!(decoded.message.rcode(), Rcode::NOERROR);
            assert!(!decoded.message.answer.is_empty(), "{decoded:?}");
        }
        Ok(())
    });
    let events = world.run().expect("the run passes its checks");
    (events, connections.get())
}

/// DNS over TLS goes through rustls over the simulated stream: the handshake completes, the queries of one client
/// share the connection, and each gets its records.
#[test]
fn dot_queries_share_one_connection() {
    seed::each(FEW, |seed| {
        let (events, connections) = dot(seed);
        assert_eq!(connections, 1, "{events:#?}");
        assert_eq!(served(&events), 3, "{events:#?}");
    });
}

/// A world with a DNS-over-TLS server answering from `dot`: the world, the authority to trust and the server.
fn dot_world(seed: seed::Seed, dot: Answers) -> (World, CertificateDer<'static>, SocketAddr) {
    let (ca, presented) = certificates(0);
    // The resolver host of every run needs an upstream to forward to; nothing asks it here.
    let mut world = Topology::new().upstream(answers()).build(seed);
    let server = world.dot_server(dot, presented);
    (world, ca, server)
}

/// A DNS-over-TLS server closes a connection after `limit` queries as one over TCP does
/// (`a_tcp_connection_serves_queries_until_the_server_closes_it`): `ceil(queries / limit)` connections.
#[test]
fn a_tls_connection_serves_queries_until_the_server_closes_it() {
    for limit in [1, 2] {
        seed::each(FEW, |seed| {
            let dot = answers().tcp(Behaviour::Close(limit));
            let connections = dot.connections();
            let (mut world, ca, server) = dot_world(seed, dot);
            world.client_direct(async move |client| {
                let client = client.trusting(Trust::Roots(vec![ca]));
                for _ in 0..4 {
                    let response = client
                        .exchange(ask(), named(server), Carrier::Tls, &Options::default())
                        .await?;
                    assert_eq!(response.transport, Transport::Tls);
                }
                Ok(())
            });
            world.run().expect("the run passes its checks");
            assert_eq!(connections.get(), 4_usize.div_ceil(limit), "limit {limit}");
        });
    }
}

/// A DNS-over-TLS server delays its responses as `faulty` says, and serves the queries of a connection pipelined
/// (RFC 7858 §3.3), as one over TCP does: four asked together on one connection all come within one delay.
#[test]
fn a_tls_server_delays_its_responses_without_holding_the_others() {
    const DELAY: Duration = Duration::from_millis(300);
    seed::each(FEW, |seed| {
        let dot = answers().faulty(|_, _| Verdict::Delay(DELAY));
        let connections = dot.connections();
        let (mut world, ca, server) = dot_world(seed, dot);
        world.client_direct(async move |client| {
            let client = client.trusting(Trust::Roots(vec![ca]));
            // The handshake first, so that the four below take the delay alone.
            client
                .exchange(ask(), named(server), Carrier::Tls, &Options::default())
                .await?;
            let start = tokio::time::Instant::now();
            let mut tasks = tokio::task::JoinSet::new();
            for _ in 0..4 {
                let client = client.clone();
                tasks.spawn_local(async move {
                    client
                        .exchange(ask(), named(server), Carrier::Tls, &Options::default())
                        .await
                });
            }
            while let Some(done) = tasks.join_next().await {
                done??;
            }
            let took = start.elapsed();
            assert!((DELAY..2 * DELAY).contains(&took), "{took:?}");
            Ok(())
        });
        world.run().expect("the run passes its checks");
        assert_eq!(connections.get(), 1);
    });
}

/// A DNS-over-TLS server that drops each response (`silent`) stalls a connection as one over TCP does
/// (`a_stalled_connection_is_dropped_after_a_try`): each try times out on a connection of its own.
#[test]
fn a_silent_tls_server_stalls_each_connection() {
    stalls(|| answers().silent());
}

/// As [`a_silent_tls_server_stalls_each_connection`], a server that reads the queries and never answers
/// ([`Behaviour::Silent`]).
#[test]
fn a_tls_server_that_never_answers_stalls_each_connection() {
    stalls(|| answers().tcp(Behaviour::Silent));
}

/// Asks the DNS-over-TLS server answering from `dot()`, which never answers: each try times out on a connection of its
/// own, the one before dropped as stalled (D108). Each seed builds its answers: clones would share their count of
/// connections over the seeds of `DEDENS_SIM_RUNS`.
fn stalls(dot: fn() -> Answers) {
    seed::each(ONE, |seed| {
        let dot = dot();
        let connections = dot.connections();
        let (mut world, ca, server) = dot_world(seed, dot);
        world.client_direct(async move |client| {
            let client = client.trusting(Trust::Roots(vec![ca]));
            let got = client
                .exchange(ask(), named(server), Carrier::Tls, &Options::default())
                .await;
            let Err(ClientError::Exchange(Failure::TimedOut { sends: 3 })) = got else {
                return Err(format!("{got:?}").into());
            };
            Ok(())
        });
        let events = world.run().expect("the run passes its checks");
        assert_eq!(connections.get(), 3, "{events:#?}");
    });
}

/// One seed gives one trace in two processes (D133) over TLS too: the certificates are fixed, and rustls' own draws
/// (randoms, key shares) change bytes on the wire, not their lengths nor when they arrive.
#[test]
fn a_dot_run_replays_in_two_processes() {
    let runs = Cell::new(0);
    seed::in_two_processes(
        module_path!(),
        "a_dot_run_replays_in_two_processes",
        FEW,
        |seed| {
            runs.set(runs.get() + 1);
            trace::digest(&dot(seed).0)
        },
    );
    assert!(runs.get() > 0);
}

/// A server certificate the client does not trust ends the exchange with a failed handshake, not a hang or an answer.
#[test]
fn dot_with_an_unknown_authority_is_refused() {
    seed::each(FEW, |seed| {
        let (_, presented) = certificates(0);
        let (other, _) = certificates(1);
        let mut world = Topology::new().upstream(answers()).build(seed);
        let server = world.dot_server(answers(), presented);
        world.client_direct(async move |client| {
            let client = client.trusting(Trust::Roots(vec![other]));
            let got = client
                .exchange(ask(), named(server), Carrier::Tls, &Options::default())
                .await;
            assert!(
                matches!(got, Err(ClientError::Tcp(TcpError::Handshake(_)))),
                "{got:?}"
            );
            Ok(())
        });
        world.run().expect("the run passes its checks");
    });
}

/// One TCP connection takes the queries of a client one after the other (D27): a server that closes after `limit`
/// queries sees `ceil(queries / limit)` connections, each query answered, whether the client noticed the close
/// before its next query or sent it into the closed connection and tried again on a new one.
#[test]
fn a_tcp_connection_serves_queries_until_the_server_closes_it() {
    for limit in [1, 2, 4] {
        seed::each(SEEDS, |seed| {
            let answers = answers().tcp(Behaviour::Close(limit));
            let connections = answers.connections();
            let mut world = Topology::new().upstream(answers).build(seed);
            let server = world.upstreams[0];
            world.client_direct(async move |client| {
                for _ in 0..4 {
                    let response = client
                        .exchange(ask(), server, Carrier::Tcp, &Options::default())
                        .await?;
                    assert_eq!(response.transport, Transport::Tcp);
                }
                Ok(())
            });
            world.run().expect("the run passes its checks");
            assert_eq!(connections.get(), 4_usize.div_ceil(limit), "limit {limit}");
        });
    }
}

/// Queries asked together go on one connection, pipelined, each answered by its ID (RFC 7766 §6.2.1, D27).
#[test]
fn queries_asked_together_share_a_connection() {
    seed::each(SEEDS, |seed| {
        let answers = answers().faulty(|_, _| Verdict::Delay(20 * MS));
        let connections = answers.connections();
        let mut world = Topology::new().upstream(answers).build(seed);
        let server = world.upstreams[0];
        world.client_direct(async move |client| {
            let mut tasks = tokio::task::JoinSet::new();
            for _ in 0..8 {
                let client = client.clone();
                tasks.spawn_local(async move {
                    client
                        .exchange(ask(), server, Carrier::Tcp, &Options::default())
                        .await
                });
            }
            while let Some(done) = tasks.join_next().await {
                let response = done??;
                assert_eq!(response.transport, Transport::Tcp);
            }
            Ok(())
        });
        world.run().expect("the run passes its checks");
        assert_eq!(connections.get(), 1);
    });
}

/// A server that crashes under a pooled connection: the next query finds it dead and ends in the pool's error when
/// connecting again gives up, at the idle timeout (10 s), not in a hang (D27: one retry, on a new connection).
#[test]
fn a_dead_server_ends_a_pooled_connection_query_in_an_error() {
    seed::each(FEW, |seed| {
        let mut world = Topology::new().upstream(answers()).build(seed);
        let server = world.upstreams[0];
        world.fault(2 * SECOND, Fault::Crash(Host::Upstream(0)));
        world.client_direct(async move |client| {
            let options = Options::default();
            client
                .exchange(ask(), server, Carrier::Tcp, &options)
                .await?;
            tokio::time::sleep(3 * SECOND).await;
            let start = tokio::time::Instant::now();
            let got = client.exchange(ask(), server, Carrier::Tcp, &options).await;
            let took = start.elapsed();
            let Err(ClientError::Tcp(TcpError::Connect(error))) = &got else {
                return Err(format!("{got:?}").into());
            };
            assert_eq!(error.kind(), std::io::ErrorKind::TimedOut, "{got:?}");
            assert!(took <= 11 * SECOND, "{took:?}");
            Ok(())
        });
        world.run().expect("the run passes its checks");
    });
}

/// A connection idle for less than the idle timeout (10 s, RFC 7766 §6.2.3) takes the next query; one idle for
/// longer was closed, and the next query opens another. On the simulated clock.
///
/// One seed: the scenario draws nothing, and a simulated second costs real time (turmoil steps by the millisecond).
#[test]
fn an_idle_connection_closes_after_the_idle_timeout() {
    seed::each(ONE, |seed| {
        let answers = answers();
        let connections = answers.connections();
        let counted = answers.connections();
        let mut world = Topology::new().upstream(answers).build(seed);
        let server = world.upstreams[0];
        world.client_direct(async move |client| {
            for (pause, opened) in [(Duration::ZERO, 1), (9 * SECOND, 1), (11 * SECOND, 2)] {
                tokio::time::sleep(pause).await;
                client
                    .exchange(ask(), server, Carrier::Tcp, &Options::default())
                    .await?;
                assert_eq!(counted.get(), opened, "after {pause:?}");
            }
            Ok(())
        });
        world.run().expect("the run passes its checks");
        assert_eq!(connections.get(), 2);
    });
}

/// A server that reads queries and never answers: each try times out, and the connection, from which nothing was
/// read since the query went, is dropped as stalled (D108), so the next try opens another.
#[test]
fn a_stalled_connection_is_dropped_after_a_try() {
    seed::each(ONE, |seed| {
        let answers = answers().tcp(Behaviour::Silent);
        let connections = answers.connections();
        let mut world = Topology::new().upstream(answers).build(seed);
        let server = world.upstreams[0];
        world.client_direct(async move |client| {
            let got = client
                .exchange(ask(), server, Carrier::Tcp, &Options::default())
                .await;
            let Err(ClientError::Exchange(Failure::TimedOut { sends: 3 })) = got else {
                return Err(format!("{got:?}").into());
            };
            Ok(())
        });
        let events = world.run().expect("the run passes its checks");
        assert_eq!(connections.get(), 3, "{events:#?}");
    });
}

/// Datagrams with a query's ID that fill its inbox (four, D108) crowd out the answer behind them: the try ends
/// at its timeout and the next one has a new ID and its own inbox. A flood of three leaves room.
#[test]
fn a_flood_of_datagrams_with_the_id_fills_the_inbox_of_the_query() {
    for (flood, answered) in [(3, true), (5, false)] {
        seed::each(FEW, |seed| {
            // The answer goes out right behind the flood, which the attacker sends at once, and the link takes
            // all of them the same time: they arrive together, and the answer last. The pool's receiving task
            // drains them all into the inbox before the query's task runs again, as turmoil schedules them: a
            // change of tokio's scheduling could let the query take some first and make room.
            let answers = answers()
                .faulty(|_, _| Verdict::Delay(Duration::ZERO))
                .attacked_by(Attacker::new(move |seen| {
                    // The ID and nothing else a response has: no question, not decodable as an answer.
                    let junk = seen.query.get(..2).unwrap_or_default().to_vec();
                    Reaction::beside(
                        (0..flood)
                            .map(|_| Injection {
                                after: Duration::ZERO,
                                wire: junk.clone(),
                            })
                            .collect(),
                    )
                }));
            let mut world = Topology::new().upstream(answers).build(seed);
            let server = world.upstreams[0];
            world.fault(
                Duration::ZERO,
                Fault::Latency {
                    a: Node::Client(0),
                    b: Node::Upstream(0),
                    min: 10 * MS,
                    max: 10 * MS,
                },
            );
            world.client_direct(async move |client| {
                let got = client
                    .exchange(ask(), server, Carrier::Udp, &Options::default())
                    .await;
                match (got, answered) {
                    (Ok(response), true) => assert_eq!(response.transport, Transport::Udp),
                    (Err(ClientError::Exchange(Failure::TimedOut { .. })), false) => {}
                    (got, _) => return Err(format!("flood {flood}: {got:?}").into()),
                }
                Ok(())
            });
            world.run().expect("the run passes its checks");
        });
    }
}

/// An error of the socket on receiving costs a try: the client sends again. One on sending, the network
/// unreachable, ends the exchange: sending again does no better (D50). It leaves the pool working.
#[test]
fn a_socket_error_costs_a_try() {
    seed::each(SEEDS, |seed| {
        let mut world = Topology::new().upstream(answers()).build(seed);
        let server = world.upstreams[0];
        world.client_direct(async move |client| {
            client.glitches().fail_sends(1);
            let refused = client
                .exchange(ask(), server, Carrier::Udp, &Options::default())
                .await;
            assert!(matches!(refused, Err(ClientError::Udp(_))), "{refused:?}");
            let sent = client
                .exchange(ask(), server, Carrier::Udp, &Options::default())
                .await?;
            assert_eq!(sent.transport, Transport::Udp);
            client.glitches().fail_receives(1);
            let received = client
                .exchange(ask(), server, Carrier::Udp, &Options::default())
                .await?;
            assert_eq!(received.transport, Transport::Udp);
            Ok(())
        });
        let events = world.run().expect("the run passes its checks");
        let sends = events
            .iter()
            .filter_map(|event| match event.what {
                What::Sent { sends, .. } => Some(sends),
                _ => None,
            })
            .collect::<Vec<_>>();
        // The failed send's try, then the next exchange's, then the third's two: the receive error cost a try.
        assert_eq!(sends, [1, 1, 1, 2], "{events:#?}");
    });
}

/// A client that drops its pools lets their connections go at once, its tasks cancelled with them, not at the idle
/// timeout (10 s): the server sees the connection end.
#[test]
fn a_dropped_client_closes_its_connections() {
    seed::each(ONE, |seed| {
        let answers = answers();
        let ended = answers.ended();
        let mut world = Topology::new().upstream(answers).build(seed);
        let server = world.upstreams[0];
        world.client_direct(async move |client| {
            client
                .exchange(ask(), server, Carrier::Tcp, &Options::default())
                .await?;
            assert_eq!(ended.get(), 0);
            drop(client);
            tokio::time::sleep(SECOND).await;
            assert_eq!(ended.get(), 1);
            Ok(())
        });
        world.run().expect("the run passes its checks");
    });
}

/// The same over DNS over TLS: the server counts the connection's end as a TCP server does.
#[test]
fn a_dropped_client_closes_its_tls_connections() {
    seed::each(ONE, |seed| {
        let (ca, presented) = certificates(0);
        let dot = answers();
        let ended = dot.ended();
        let mut world = Topology::new().upstream(answers()).build(seed);
        let server = world.dot_server(dot, presented);
        world.client_direct(async move |client| {
            let client = client.trusting(Trust::Roots(vec![ca]));
            client
                .exchange(ask(), named(server), Carrier::Tls, &Options::default())
                .await?;
            assert_eq!(ended.get(), 0);
            drop(client);
            tokio::time::sleep(SECOND).await;
            assert_eq!(ended.get(), 1);
            Ok(())
        });
        world.run().expect("the run passes its checks");
    });
}

/// Each client host is a host of its own, its IDs drawn from a stream of its own: two clients asking once each send
/// two IDs.
#[test]
fn two_clients_are_two_hosts_drawing_their_own_ids() {
    seed::each(FEW, |seed| {
        let mut world = Topology::new().upstream(answers()).build(seed);
        let server = world.upstreams[0];
        for _ in 0..2 {
            world.client_direct(async move |client| {
                client
                    .exchange(ask(), server, Carrier::Udp, &Options::default())
                    .await?;
                Ok(())
            });
        }
        let events = world.run().expect("the run passes its checks");
        let sent: Vec<(IpAddr, u16)> = events
            .iter()
            .filter_map(|event| match event.what {
                What::Sent { id, .. } => Some((event.host, id)),
                _ => None,
            })
            .collect();
        let [(one, first), (other, second)] = sent.as_slice() else {
            panic!("{events:#?}");
        };
        assert_ne!(one, other);
        assert_ne!(first, second, "{events:#?}");
    });
}

/// Each DNS-over-TLS server is a host of its own, at its own address.
#[test]
fn two_dot_servers_are_two_hosts() {
    seed::each(ONE, |seed| {
        let mut world = Topology::new().upstream(answers()).build(seed);
        let one = world.dot_server(answers(), certificates(0).1);
        let other = world.dot_server(answers(), certificates(0).1);
        assert_ne!(one, other);
    });
}
