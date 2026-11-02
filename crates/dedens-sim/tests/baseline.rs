//! What the client, the resolver's pipeline and its cache do together (D27, D41, D43), first over a perfect
//! network, then with each fault and the attacker the harness offers used once (D133): every later family starts
//! from these. The last test has the seed pick the faults.

use std::time::{Duration, UNIX_EPOCH};

use dedens_net::exchange::Failure;
use dedens_proto::{Rcode, RecordType, Transport};
use dedens_sim::attacker::{Attacker, Injection};
use dedens_sim::client::Carrier;
use dedens_sim::fault::{Fault, Node, Server};
use dedens_sim::seed::{self, Seed};
use dedens_sim::stub::{Outcome, question};
use dedens_sim::topology::{Topology, World};
use dedens_sim::trace::{Event, What};
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
            let Outcome::Answered(answer) = stub
                .ask(question("example.com", RecordType::A), carrier)
                .await?
            else {
                return Err("no answer".into());
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
fn no_upstream_answer_ends_in_servfail_or_failure() {
    seed::each(SEEDS, |seed| {
        // The upstream server holds nothing: it never answers.
        let mut world = Topology::new().upstream(Answers::new()).build(seed);
        world.client(async move |stub| {
            match stub
                .ask(question("example.com", RecordType::A), Carrier::Udp)
                .await?
            {
                Outcome::Answered(answer) => {
                    assert_eq!(answer.message.rcode(), dedens_proto::Rcode::SERVFAIL);
                }
                Outcome::Failed(Failure::TimedOut { .. }) => {}
                Outcome::Failed(other) => return Err(format!("{other}").into()),
            }
            Ok(())
        });
        world.run().expect("the run passes its checks");
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

fn ended(events: &[Event]) -> bool {
    events
        .iter()
        .any(|event| matches!(event.what, What::Answered { .. } | What::Failed { .. }))
}

#[test]
fn a_lossy_link_ends_in_an_answer_or_a_failure() {
    seed::each(SEEDS, |seed| {
        let events = ask_once(seed, a(), |world| {
            world.fault(
                Duration::ZERO,
                Fault::Loss {
                    a: LINK.0,
                    b: LINK.1,
                    rate: 0.01,
                },
            );
        });
        assert!(ended(&events), "{events:#?}");
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
            let crash = world.pick(Duration::ZERO, Duration::from_millis(50));
            let bounce = crash + world.pick(SECOND, 2 * SECOND);
            world.fault(crash, Fault::Crash(Server::Resolver));
            world.fault(bounce, Fault::Bounce(Server::Resolver));
        });
        // The stub's second try, after 5 s, finds it back, with an empty cache.
        assert!(got_the_records(&events), "{events:#?}");
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

#[test]
fn queries_carry_a_client_cookie_of_the_seed() {
    let cookies = |seed| {
        let seen = std::rc::Rc::new(std::cell::RefCell::new(Vec::new()));
        let record = std::rc::Rc::clone(&seen);
        let attacker = Attacker::new(move |seen| {
            let query = dedens_proto::Message::decode(seen.query).expect("a query");
            let cookie = query
                .message
                .edns
                .iter()
                .flat_map(|edns| &edns.options)
                .find_map(|option| match option {
                    dedens_proto::edns::EdnsOption::Cookie(cookie) => Some(*cookie),
                    _ => None,
                });
            record
                .borrow_mut()
                .push(cookie.map(|cookie| cookie.client()));
            Vec::new()
        });
        ask_once(seed, a().attacked_by(attacker), |_| {});
        seen.take()
    };
    let first = cookies(Seed(1));
    assert!(matches!(first.as_slice(), [Some(_), ..]), "{first:?}");
    assert_eq!(first, cookies(Seed(1)));
    assert_ne!(first, cookies(Seed(2)));
}
