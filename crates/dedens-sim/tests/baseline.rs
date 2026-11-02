//! What the client, the resolver's pipeline and its cache do together (D27, D41, D43), first over a perfect
//! network, then with each fault and the attacker the harness offers used once (D133): every later family starts
//! from these. The last test has the seed pick the faults.

use std::cell::RefCell;
use std::net::SocketAddr;
use std::rc::Rc;
use std::time::{Duration, UNIX_EPOCH};

use dedens_cache::Config;
use dedens_net::client::ClientError;
use dedens_net::exchange::{Failure, Options};
use dedens_net::tcp::TcpError;
use dedens_proto::edns::EdnsOption;
use dedens_proto::{Message, Rcode, RecordType, Transport};
use dedens_sim::attacker::{Attacker, Injection};
use dedens_sim::client::{Carrier, Client};
use dedens_sim::fault::{Fault, Node, Server};
use dedens_sim::resolver::pipeline_with;
use dedens_sim::seed::{self, Rng, Seed};
use dedens_sim::stub::{Outcome, question};
use dedens_sim::topology::{Topology, World};
use dedens_sim::trace::{Event, Trace, What};
use dedens_sim::upstream::Answers;

/// The seeds of `just check`; `DEDENS_SIM_SEED` and `DEDENS_SIM_RUNS` replace them.
const SEEDS: &[u64] = &[0, 1, 7, 42, 2026];

/// One client asks `example.com A` `asks` times over `carrier`, through a resolver with one upstream server.
fn run(seed: Seed, carrier: Carrier, asks: usize) -> Vec<Event> {
    let answers = Answers::new()
        .captured("a")
        .truncating("truncated", "txt_large");
    let mut world = Topology::new().upstream(answers).build(seed);
    world.client(async move |stub| {
        for _ in 0..asks {
            let outcome = stub
                .ask(question("example.com", RecordType::A), carrier)
                .await?;
            let Outcome::Answered(answer) = outcome else {
                return Err(format!("no answer: {outcome:?}").into());
            };
            assert_eq!(answer.transport, Transport::from(carrier));
            // The captured response holds two A records.
            assert_eq!(answer.message.answer.len(), 2);
        }
        Ok(())
    });
    world.run().expect("the run passes its checks")
}

fn served(events: &[Event]) -> usize {
    events
        .iter()
        .filter(|event| matches!(event.what, What::Served { .. }))
        .count()
}

#[test]
fn udp_answer() {
    seed::each(SEEDS, |seed| {
        let events = run(seed, Carrier::Udp, 1);
        assert_eq!(served(&events), 1, "{events:#?}");
    });
}

#[test]
fn tcp_answer() {
    seed::each(SEEDS, |seed| {
        let events = run(seed, Carrier::Tcp, 1);
        assert_eq!(served(&events), 1, "{events:#?}");
    });
}

#[test]
fn second_query_comes_from_the_cache() {
    seed::each(SEEDS, |seed| {
        for carrier in [Carrier::Udp, Carrier::Tcp] {
            let events = run(seed, carrier, 2);
            assert_eq!(served(&events), 1, "{carrier:?}: {events:#?}");
            // The answer went into the cache once, and the second query was replied from it.
            let stored = events
                .iter()
                .filter(|e| matches!(e.what, What::Stored { .. }))
                .count();
            assert_eq!(stored, 1, "{carrier:?}: {events:#?}");
            let replied = events
                .iter()
                .filter(|e| matches!(e.what, What::Replied { .. }))
                .count();
            assert_eq!(replied, 2, "{carrier:?}: {events:#?}");
        }
    });
}

#[test]
fn resolver_asks_again_over_tcp_when_the_upstream_truncates() {
    seed::each(SEEDS, |seed| {
        let mut world = Topology::new()
            .upstream(Answers::new().truncating("truncated", "txt_large"))
            .build(seed);
        world.client(async move |stub| {
            let outcome = stub
                .ask(question("google.com", RecordType::TXT), Carrier::Udp)
                .await?;
            let Outcome::Answered(answer) = outcome else {
                return Err(format!("no answer: {outcome:?}").into());
            };
            // The stub's EDNS size holds the whole response: it comes over UDP.
            assert_eq!(answer.transport, Transport::Udp);
            assert!(answer.message.answer.len() > 1);
            Ok(())
        });
        let events = world.run().expect("the run passes its checks");
        assert!(
            events.iter().any(|event| matches!(
                event.what,
                What::Served {
                    transport: Transport::Tcp,
                    ..
                }
            )),
            "{events:#?}"
        );
    });
}

#[test]
fn an_upstream_that_refuses_ends_in_servfail() {
    seed::each(SEEDS, |seed| {
        // The upstream server holds nothing: it answers REFUSED.
        let mut world = Topology::new().upstream(Answers::new()).build(seed);
        world.client(async move |stub| {
            let outcome = stub
                .ask(question("example.com", RecordType::A), Carrier::Udp)
                .await?;
            let Outcome::Answered(answer) = outcome else {
                return Err(format!("no answer: {outcome:?}").into());
            };
            assert_eq!(answer.message.rcode(), Rcode::SERVFAIL);
            assert_eq!(answer.message.answer, Vec::new());
            Ok(())
        });
        world.run().expect("the run passes its checks");
    });
}

#[test]
fn an_upstream_that_is_out_of_reach_ends_in_servfail_or_a_failure() {
    seed::each(SEEDS, |seed| {
        let events = ask_once(seed, a(), |world| {
            world.fault(Duration::ZERO, Fault::Partition(LINK.0, LINK.1));
        });
        let ends = ends(&events);
        assert_eq!(ends.len(), 1, "{events:#?}");
        assert!(
            matches!(
                ends[0],
                What::Answered {
                    rcode: Rcode::SERVFAIL,
                    answers: 0,
                    ..
                } | What::Failed {
                    failure: Failure::TimedOut { .. },
                    ..
                }
            ),
            "{events:#?}"
        );
        // Nothing the resolver sent arrived.
        assert_eq!(served(&events), 0, "{events:#?}");
    });
}

#[test]
fn seeds_shape_the_run() {
    assert_ne!(run(Seed(0), Carrier::Udp, 2), run(Seed(1), Carrier::Udp, 2));
}

#[test]
fn a_seed_replays_to_the_same_trace() {
    seed::each(SEEDS, |seed| {
        assert_eq!(run(seed, Carrier::Udp, 2), run(seed, Carrier::Udp, 2));
    });
}

/// The link between the resolver and the upstream server.
const LINK: (Node, Node) = (Node::Resolver, Node::Upstream(0));

const SECOND: Duration = Duration::from_secs(1);

/// One client asks `example.com A` over UDP, once, with one upstream server holding `answers`; `setup` adds what
/// goes wrong.
fn ask_once(seed: Seed, answers: Answers, setup: impl FnOnce(&mut World)) -> Vec<Event> {
    let mut world = Topology::new().upstream(answers).build(seed);
    setup(&mut world);
    world.client(async move |stub| {
        stub.ask(question("example.com", RecordType::A), Carrier::Udp)
            .await?;
        // Whatever else the network and the hosts do goes on a while.
        tokio::time::sleep(SECOND).await;
        Ok(())
    });
    world.run().expect("the run passes its checks")
}

fn a() -> Answers {
    Answers::new().captured("a")
}

/// Whether a client got the two records of the captured response.
fn got_the_records(events: &[Event]) -> bool {
    events.iter().any(|event| {
        matches!(
            &event.what,
            What::Answered {
                rcode: Rcode::NOERROR,
                answers: 2,
                ..
            }
        )
    })
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

/// The most sends any exchange of the run made: how often a query was tried.
fn most_sends(events: &[Event]) -> u16 {
    events
        .iter()
        .filter_map(|event| match event.what {
            What::Sent { sends, .. } => Some(sends),
            _ => None,
        })
        .max()
        .unwrap_or(0)
}

#[test]
fn a_lossy_link_ends_in_the_records_or_a_failure_the_resolver_names() {
    seed::each(SEEDS, |seed| {
        let events = ask_once(seed, a(), |world| {
            world.fault(
                Duration::ZERO,
                Fault::Loss {
                    a: LINK.0,
                    b: LINK.1,
                    rate: 0.5,
                },
            );
        });
        let ends = ends(&events);
        assert_eq!(ends.len(), 1, "{events:#?}");
        // The loss is between the resolver and the server: the stub's own link is fine, so the resolver answers,
        // the records when a try got through, SERVFAIL when none did.
        assert!(
            matches!(
                ends[0],
                What::Answered {
                    rcode: Rcode::NOERROR,
                    answers: 2,
                    ..
                } | What::Answered {
                    rcode: Rcode::SERVFAIL,
                    answers: 0,
                    ..
                }
            ),
            "{events:#?}"
        );
    });
}

#[test]
fn slow_links_reorder_but_the_answer_is_the_same() {
    seed::each(SEEDS, |seed| {
        let events = ask_once(seed, a(), |world| {
            world.fault(
                Duration::ZERO,
                Fault::Latency {
                    a: LINK.0,
                    b: LINK.1,
                    min: Duration::from_millis(10),
                    max: Duration::from_millis(500),
                },
            );
        });
        assert!(got_the_records(&events), "{events:#?}");
    });
}

#[test]
fn the_resolver_asks_again_when_a_partition_ends() {
    seed::each(SEEDS, |seed| {
        let events = ask_once(seed, a(), |world| {
            world.fault(Duration::ZERO, Fault::Partition(LINK.0, LINK.1));
            let end = world.pick(SECOND, 2 * SECOND);
            world.fault(end, Fault::Repair(LINK.0, LINK.1));
        });
        assert!(got_the_records(&events), "{events:#?}");
    });
}

#[test]
fn answers_that_do_not_come_back_are_asked_for_again() {
    seed::each(SEEDS, |seed| {
        let events = ask_once(seed, a(), |world| {
            world.fault(
                Duration::ZERO,
                Fault::PartitionOneWay {
                    from: LINK.1,
                    to: LINK.0,
                },
            );
            let end = world.pick(SECOND, 2 * SECOND);
            world.fault(
                end,
                Fault::RepairOneWay {
                    from: LINK.1,
                    to: LINK.0,
                },
            );
        });
        // The first answer was lost: the server served the query twice.
        assert!(served(&events) >= 2, "{events:#?}");
        assert!(got_the_records(&events), "{events:#?}");
    });
}

#[test]
fn a_held_query_arrives_when_released() {
    seed::each(SEEDS, |seed| {
        let events = ask_once(seed, a(), |world| {
            world.fault(Duration::ZERO, Fault::Hold(LINK.0, LINK.1));
            let release = world.pick(Duration::from_millis(200), SECOND);
            world.fault(release, Fault::Release(LINK.0, LINK.1));
        });
        assert!(got_the_records(&events), "{events:#?}");
    });
}

#[test]
fn a_resolver_that_restarts_answers_the_second_try() {
    seed::each(SEEDS, |seed| {
        let events = ask_once(seed, a(), |world| {
            // Before the stub's first query, which is 5 ms into the run.
            let crash = world.pick(Duration::ZERO, Duration::from_millis(4));
            let bounce = crash + world.pick(SECOND, 2 * SECOND);
            world.fault(crash, Fault::Crash(Server::Resolver));
            world.fault(bounce, Fault::Bounce(Server::Resolver));
        });
        // The stub's second try, after 5 s, finds it back, with an empty cache.
        assert!(got_the_records(&events), "{events:#?}");
        assert_eq!(most_sends(&events), 2, "{events:#?}");
    });
}

#[test]
fn forged_and_late_datagrams_from_the_server_do_not_change_the_answer() {
    seed::each(SEEDS, |seed| {
        let attacker = Attacker::new(|seen| {
            let Some(genuine) = seen.genuine else {
                return Vec::new();
            };
            // The right address and port, the wrong ID, other data.
            let mut forged = genuine.to_vec();
            if let Some(id) = forged.first_mut() {
                *id = id.wrapping_add(1);
            }
            if let Some(last) = forged.last_mut() {
                *last ^= 0xff;
            }
            vec![
                Injection {
                    after: Duration::ZERO,
                    wire: forged,
                },
                // The genuine answer again, after the exchange ended.
                Injection {
                    after: Duration::from_millis(300),
                    wire: genuine.to_vec(),
                },
            ]
        });
        let events = ask_once(seed, a().attacked_by(attacker), |_| {});
        let injected = events
            .iter()
            .filter(|event| matches!(event.what, What::Injected { .. }))
            .count();
        assert_eq!(injected, 2, "{events:#?}");
        assert!(got_the_records(&events), "{events:#?}");
    });
}

#[test]
fn the_run_starts_at_its_epoch() {
    seed::each(SEEDS, |seed| {
        let epoch = Duration::from_secs(1_700_000_000);
        let mut world = Topology::new()
            .upstream(a())
            .epoch(UNIX_EPOCH + epoch)
            .build(seed);
        world.client(async move |_| {
            let now = turmoil::since_epoch().ok_or("outside a simulation")?;
            assert!(now >= epoch && now < epoch + SECOND, "{now:?}");
            Ok(())
        });
        world.run().expect("the run passes its checks");
    });
}

#[test]
fn a_small_edns_size_has_the_stub_ask_again_over_tcp() {
    seed::each(SEEDS, |seed| {
        let mut world = Topology::new()
            .upstream(Answers::new().truncating("truncated", "txt_large"))
            .build(seed);
        world.client(async move |mut stub| {
            stub.payload = Some(512);
            let outcome = stub
                .ask(question("google.com", RecordType::TXT), Carrier::Udp)
                .await?;
            let Outcome::Answered(answer) = outcome else {
                return Err(format!("no answer: {outcome:?}").into());
            };
            // The resolver truncates for the stub as the upstream server did for it.
            assert_eq!(answer.transport, Transport::Tcp);
            assert!(answer.message.answer.len() > 1);
            Ok(())
        });
        world.run().expect("the run passes its checks");
    });
}

/// The property of the family: whatever the seed does to the network and the hosts, each query ends by its
/// deadline in what an upstream server holds, SERVFAIL, or a failure (the checks of the stub), and the run
/// passes.
#[test]
fn whatever_the_seed_breaks_queries_end_well() {
    seed::each(SEEDS, |seed| {
        let answers = Answers::new()
            .captured("a")
            .truncating("truncated", "txt_large");
        let mut world = Topology::new().upstream(answers).build(seed);
        let start = world.pick(Duration::ZERO, 2 * SECOND);
        let end = start + world.pick(SECOND, 6 * SECOND);
        let (from, to) = LINK;
        let (down, up) = match world.choose(7) {
            0 => (
                Fault::Loss {
                    a: from,
                    b: to,
                    rate: 0.02,
                },
                Fault::Loss {
                    a: from,
                    b: to,
                    rate: 0.0,
                },
            ),
            1 => (
                Fault::Latency {
                    a: from,
                    b: to,
                    min: Duration::ZERO,
                    max: 2 * SECOND,
                },
                Fault::Latency {
                    a: from,
                    b: to,
                    min: Duration::ZERO,
                    max: Duration::ZERO,
                },
            ),
            2 => (Fault::Partition(from, to), Fault::Repair(from, to)),
            3 => (
                Fault::PartitionOneWay { from: to, to: from },
                Fault::RepairOneWay { from: to, to: from },
            ),
            4 => (Fault::Hold(from, to), Fault::Release(from, to)),
            5 => (
                Fault::Crash(Server::Resolver),
                Fault::Bounce(Server::Resolver),
            ),
            _ => (
                Fault::Crash(Server::Upstream(0)),
                Fault::Bounce(Server::Upstream(0)),
            ),
        };
        world.fault(start, down);
        world.fault(end, up);
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
        world.run().expect("the run passes its checks");
    });
}

/// The cookies in the queries the upstream server gets, in order: the client cookie, and whether it came with a
/// server cookie.
fn cookies_seen(seed: Seed, server_cookie: Option<[u8; 8]>) -> Vec<Option<(Vec<u8>, bool)>> {
    let queries = Rc::new(RefCell::new(Vec::new()));
    let record = Rc::clone(&queries);
    let attacker = Attacker::new(move |seen| {
        let query = Message::decode(seen.query).expect("a query");
        let cookie = query
            .message
            .edns
            .iter()
            .flat_map(|edns| &edns.options)
            .find_map(|option| match option {
                EdnsOption::Cookie(cookie) => Some(*cookie),
                _ => None,
            });
        record
            .borrow_mut()
            .push(cookie.map(|cookie| (cookie.client().to_vec(), cookie.server().is_some())));
        Vec::new()
    });
    let mut answers = Answers::new()
        .captured("a")
        .truncating("truncated", "txt_large")
        .attacked_by(attacker);
    if let Some(cookie) = server_cookie {
        answers = answers.cookies(cookie);
    }
    let mut world = Topology::new().upstream(answers).build(seed);
    world.client(async move |stub| {
        for (name, qtype) in [
            ("example.com", RecordType::A),
            ("google.com", RecordType::TXT),
        ] {
            stub.ask(question(name, qtype), Carrier::Udp).await?;
        }
        Ok(())
    });
    world.run().expect("the run passes its checks");
    queries.take()
}

#[test]
fn the_resolver_sends_a_client_cookie_of_the_seed_and_returns_the_servers() {
    let first = cookies_seen(Seed(1), Some([7; 8]));
    // The first query has the client cookie alone; the server answers with its own, which the next one carries.
    assert!(
        matches!(first.as_slice(), [Some((_, false)), Some((_, true)), ..]),
        "{first:?}"
    );
    assert_eq!(
        first[0].as_ref().map(|c| &c.0),
        first[1].as_ref().map(|c| &c.0)
    );
    assert_eq!(first, cookies_seen(Seed(1), Some([7; 8])));
    assert_ne!(first[0], cookies_seen(Seed(2), Some([7; 8]))[0]);
    // A server that sets no cookie of its own has none returned.
    let without = cookies_seen(Seed(1), None);
    assert!(
        without
            .iter()
            .all(|cookie| matches!(cookie, Some((_, false)))),
        "{without:?}"
    );
}

#[test]
fn the_cache_follows_the_clock() {
    seed::each(SEEDS, |seed| {
        let ttl = 5;
        let mut world = Topology::new()
            .upstream(a())
            .resolver(move |upstreams| {
                let config = Config {
                    min_ttl: 1,
                    max_ttl: ttl,
                    ..Config::default()
                };
                pipeline_with(config, upstreams)
            })
            .build(seed);
        world.client(async move |stub| {
            for pause in [SECOND, Duration::from_secs(u64::from(ttl) + 1)] {
                stub.ask(question("example.com", RecordType::A), Carrier::Udp)
                    .await?;
                tokio::time::sleep(pause).await;
            }
            stub.ask(question("example.com", RecordType::A), Carrier::Udp)
                .await?;
            Ok(())
        });
        let events = world.run().expect("the run passes its checks");
        // The first and the third ask reach the server: the entry of the first had expired for the third.
        assert_eq!(served(&events), 2, "{events:#?}");
    });
}

#[test]
fn two_clients_share_the_cache_and_ask_with_their_own_ids() {
    seed::each(SEEDS, |seed| {
        let mut world = Topology::new().upstream(a()).build(seed);
        for _ in 0..2 {
            world.client(async move |stub| {
                stub.ask(question("example.com", RecordType::A), Carrier::Udp)
                    .await?;
                Ok(())
            });
        }
        let events = world.run().expect("the run passes its checks");
        let hosts: std::collections::BTreeSet<_> = events
            .iter()
            .filter(|event| matches!(event.what, What::Answered { .. }))
            .map(|event| event.host)
            .collect();
        assert_eq!(hosts.len(), 2, "{events:#?}");
        let ids: std::collections::BTreeSet<_> = events
            .iter()
            .filter_map(|event| match event.what {
                What::Sent { id, .. } if hosts.contains(&event.host) => Some((event.host, id)),
                _ => None,
            })
            .collect();
        assert_eq!(ids.len(), 2, "{events:#?}");
        assert!(served(&events) <= 2, "{events:#?}");
    });
}

#[test]
fn a_crashed_resolver_leaves_a_tcp_query_to_time_out() {
    seed::each(SEEDS, |seed| {
        let mut world = Topology::new().upstream(a()).build(seed);
        world.fault(Duration::ZERO, Fault::Crash(Server::Resolver));
        world.client(async move |stub| {
            // The first step of the run is the crash.
            tokio::time::sleep(Duration::from_millis(10)).await;
            let outcome = stub
                .ask(question("example.com", RecordType::A), Carrier::Tcp)
                .await?;
            assert!(
                matches!(outcome, Outcome::Failed(Failure::TimedOut { sends: 3 })),
                "{outcome:?}"
            );
            Ok(())
        });
        world.run().expect("the run passes its checks");
    });
}

#[test]
fn a_port_nobody_listens_on_refuses_the_connection() {
    seed::each(SEEDS, |seed| {
        let mut world = Topology::new().upstream(a()).build(seed);
        let resolver = world.resolver;
        world.client(async move |_| {
            let host = turmoil::lookup("client-0");
            let rng = Rc::new(RefCell::new(Rng::new(seed, 99)));
            let client = Client::new(rng, host, Trace::new());
            let query = Message::query(0, question("example.com", RecordType::A));
            let nobody = SocketAddr::new(resolver.ip(), 54);
            let got = client
                .exchange(query, nobody, Carrier::Tcp, &Options::default())
                .await;
            let Err(ClientError::Tcp(TcpError::Connect(error))) = got else {
                return Err(format!("{got:?}").into());
            };
            assert_eq!(error.kind(), std::io::ErrorKind::ConnectionRefused);
            Ok(())
        });
        world.run().expect("the run passes its checks");
    });
}

#[test]
fn a_cache_answers_stale_when_the_server_is_out_of_reach() {
    seed::each(SEEDS, |seed| {
        let mut world = Topology::new()
            .upstream(a())
            .resolver(|upstreams| {
                let config = Config {
                    min_ttl: 1,
                    max_ttl: 2,
                    stale_answer_after_ms: 200,
                    ..Config::default()
                };
                pipeline_with(config, upstreams)
            })
            .build(seed);
        world.fault(SECOND, Fault::Partition(LINK.0, LINK.1));
        world.client(async move |stub| {
            let first = stub
                .ask(question("example.com", RecordType::A), Carrier::Udp)
                .await?;
            let Outcome::Answered(first) = first else {
                return Err(format!("{first:?}").into());
            };
            assert!(!first.stale);
            // The entry has expired, and the server cannot be asked again.
            tokio::time::sleep(3 * SECOND).await;
            let second = stub
                .ask(question("example.com", RecordType::A), Carrier::Udp)
                .await?;
            let Outcome::Answered(second) = second else {
                return Err(format!("{second:?}").into());
            };
            assert!(second.stale, "{second:?}");
            assert_eq!(second.message.answer.len(), 2);
            // The resolver's timer (D45) sent it, well before the stub's own timeout.
            assert!(second.elapsed < SECOND, "{:?}", second.elapsed);
            Ok(())
        });
        let events = world.run().expect("the run passes its checks");
        assert!(
            events
                .iter()
                .any(|event| matches!(event.what, What::Replied { stale: true, .. })),
            "{events:#?}"
        );
    });
}

#[test]
fn a_client_at_an_address_of_its_choice_asks_from_there() {
    seed::each(SEEDS, |seed| {
        let ip = std::net::IpAddr::from([10, 1, 2, 3]);
        let mut world = Topology::new().upstream(a()).build(seed);
        world.client_at(ip, async move |stub| {
            stub.ask(question("example.com", RecordType::A), Carrier::Udp)
                .await?;
            Ok(())
        });
        let events = world.run().expect("the run passes its checks");
        assert!(
            events
                .iter()
                .any(|event| event.host == ip && matches!(event.what, What::Answered { .. })),
            "{events:#?}"
        );
    });
}

#[test]
fn expect_wants_the_data_where_the_path_is_up() {
    seed::each(SEEDS, |seed| {
        let mut world = Topology::new().upstream(a()).build(seed);
        world.client(async move |stub| {
            let answer = stub
                .expect(question("example.com", RecordType::A), Carrier::Udp)
                .await?;
            assert_eq!(answer.message.answer.len(), 2);
            Ok(())
        });
        world.run().expect("the run passes its checks");
    });
}

#[test]
fn expect_fails_on_the_servfail_that_ask_allows() {
    seed::each(SEEDS, |seed| {
        // The server holds nothing, so the resolver's answer is SERVFAIL: `ask` accepts it, `expect` does not.
        let mut world = Topology::new().upstream(Answers::new()).build(seed);
        world.client(async move |stub| {
            let ask = question("example.com", RecordType::A);
            assert!(stub.ask(ask.clone(), Carrier::Udp).await.is_ok());
            assert!(stub.expect(ask, Carrier::Udp).await.is_err());
            Ok(())
        });
        world.run().expect("the run passes its checks");
    });
}

#[test]
fn a_server_that_refuses_the_connection_is_skipped_for_the_next() {
    seed::each(SEEDS, |seed| {
        // The resolver forwards a query that came over TCP over TCP, first to a port nobody listens on: the error is
        // the network's, not the query's, so the question goes on to the next server and is not abandoned (D46).
        let mut world = Topology::new()
            .upstream(a())
            .resolver(|upstreams| {
                let nobody = SocketAddr::new(upstreams[0].ip(), 54);
                pipeline_with(Config::default(), &[nobody, upstreams[0]])
            })
            .build(seed);
        world.client(async move |stub| {
            let outcome = stub
                .ask(question("example.com", RecordType::A), Carrier::Tcp)
                .await?;
            let Outcome::Answered(answer) = outcome else {
                return Err(format!("no answer: {outcome:?}").into());
            };
            assert_eq!(answer.message.answer.len(), 2);
            Ok(())
        });
        world.run().expect("the run passes its checks");
    });
}
