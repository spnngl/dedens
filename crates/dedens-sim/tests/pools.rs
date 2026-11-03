//! The client's pools on the simulated network, as `dedens-net` runs them (D134): the real `UdpPool` and `TcpPool`
//! behind `Client`, with the seeded faults of the other families. What the sans-IO exchange cannot show: how many
//! connections a pool opens (D27), the inbox of a query (D108), errors of a socket, and DNS over TLS through
//! rustls over the simulated stream.
//!
//! Each scenario has the client host speak to a server host on its own, with no stub and no oracle.

use std::cell::Cell;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use compio::rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName};
use dedens_net::client::{ClientError, Server};
use dedens_net::exchange::{Failure, Options};
use dedens_net::tcp::TcpError;
use dedens_net::tls::{Presented, Trust};
use dedens_proto::{Message, Rcode, RecordType, Transport};
use dedens_sim::attacker::{Attacker, Injection, Reaction};
use dedens_sim::client::Carrier;
use dedens_sim::fault::{Fault, Node, Server as Host};
use dedens_sim::seed::{self};
use dedens_sim::stub::question;
use dedens_sim::topology::Topology;
use dedens_sim::trace::{self, Event, What};
use dedens_sim::upstream::{Answers, Behaviour, Verdict};
use rcgen::{BasicConstraints, CertificateParams, CertifiedIssuer, IsCa, KeyPair};

const SEEDS: &[u64] = &[0, 1, 7, 42, 2026];

/// Seeds for the scenarios with TLS: a handshake is the slowest thing the simulation does.
const FEW: &[u64] = &[0, 7];

/// Seeds for the scenarios that last many simulated seconds and draw nothing from the seed but the network's.
const ONE: &[u64] = &[0];

const MS: Duration = Duration::from_millis(1);

const SECOND: Duration = Duration::from_secs(1);

/// The name the server's certificate holds.
const NAME: &str = "dns.example";

/// An upstream server holding `example.com A`.
fn upstream() -> Answers {
    Answers::new().captured("a")
}

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

/// The Ed25519 key of the 32 bytes `seed`, in PKCS #8 (RFC 8410 §7): the same on every run.
fn key(seed: u8) -> KeyPair {
    /// The PKCS #8 encoding of an Ed25519 private key up to its 32 bytes.
    const PREFIX: [u8; 16] = [
        0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x04, 0x22, 0x04,
        0x20,
    ];
    let mut der = PREFIX.to_vec();
    der.extend_from_slice(&[seed; 32]);
    KeyPair::from_pkcs8_der_and_sign_algo(&PrivatePkcs8KeyDer::from(der), &rcgen::PKCS_ED25519)
        .expect("an Ed25519 key")
}

/// The certificate authority `authority`, and the server certificate it signed: the authority to trust and what the
/// server presents. The same bytes on every run (fixed keys, Ed25519's signatures, rcgen's fixed validity and its
/// serial numbers from the keys), so that a run over TLS replays from its seed.
fn certificates(authority: u8) -> (CertificateDer<'static>, Arc<Presented>) {
    let mut params = CertificateParams::new(Vec::<String>::new()).expect("CA parameters");
    params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    let ca = CertifiedIssuer::self_signed(params, key(authority)).expect("a CA");
    let key = key(authority.wrapping_add(128));
    let server = CertificateParams::new(vec![NAME.to_owned()])
        .expect("server parameters")
        .signed_by(&key, &ca)
        .expect("a server certificate");
    let presented = Presented::new(
        vec![server.der().clone()],
        PrivateKeyDer::Pkcs8(key.serialize_der().into()),
    )
    .expect("a certificate rustls signs with");
    (ca.der().clone(), Arc::new(presented))
}

/// Three queries over DNS over TLS (RFC 7858) from one client, one after the other: the run's trace and the
/// connections the server accepted.
fn dot(seed: seed::Seed) -> (Vec<Event>, usize) {
    let (ca, presented) = certificates(0);
    let answers = upstream();
    let connections = answers.connections();
    // The resolver host of every run needs an upstream to forward to; nothing asks it here.
    let mut world = Topology::new().upstream(upstream()).build(seed);
    let server = world.dot_server(answers, presented);
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
        let replies = events
            .iter()
            .filter(|event| matches!(event.what, What::Served { .. }))
            .count();
        assert_eq!(replies, 3, "{events:#?}");
    });
}

/// One seed gives one trace in two processes (D133) over TLS too: the certificates are fixed, and rustls' own draws
/// (randoms, key shares) change bytes on the wire, not their lengths nor when they arrive.
#[test]
fn a_dot_run_replays_in_two_processes() {
    let runs = Cell::new(0);
    seed::in_two_processes("a_dot_run_replays_in_two_processes", FEW, |seed| {
        runs.set(runs.get() + 1);
        trace::digest(&dot(seed).0)
    });
    assert!(runs.get() > 0);
}

/// A server certificate the client does not trust ends the exchange with a failed handshake, not a hang or an answer.
#[test]
fn dot_with_an_unknown_authority_is_refused() {
    seed::each(FEW, |seed| {
        let (_, presented) = certificates(0);
        let (other, _) = certificates(1);
        let mut world = Topology::new().upstream(upstream()).build(seed);
        let server = world.dot_server(upstream(), presented);
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
            let answers = upstream().tcp(Behaviour::Close(limit));
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
        let answers = upstream().faulty(|_, _| Verdict::Delay(20 * MS));
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
        let mut world = Topology::new().upstream(upstream()).build(seed);
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
        let answers = upstream();
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
            let answers = upstream()
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

/// An error of the socket on receiving costs a try: the client sends again. One on sending ends the exchange, as the
/// failure is local (D46), and leaves the pool working.
#[test]
fn a_socket_error_costs_a_try() {
    seed::each(SEEDS, |seed| {
        let mut world = Topology::new().upstream(upstream()).build(seed);
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
