//! Forged and duplicated responses on the resolver's path to an upstream server (D26, D31, D68, D111, D114): an
//! attacker on the server's host sends the resolver datagrams that look like the server's answer, and copies of
//! the real one. Whatever it sends, the clients get the server's data and the cache holds nothing the server did
//! not say.
//!
//! The attacker is off-path as RFC 5452 models it: it sees each query, so knows its ID, but cannot spoof the
//! source address (turmoil shares the server's socket with it) and never sends a response that matches the query
//! in everything the resolver checks: ID, QR, opcode, question and cookie. Such a response is the one the defences
//! cannot tell from the server's: a guess of the ID is the odds of RFC 5452 §7, and an exchange that has not
//! yet seen a server cookie takes a response with none (RFC 7873 §5.3). Each forgery here breaks one of the checks,
//! and carries data the oracle refuses (`6.6.6.6`).
//!
//! Left to other tests, which this family cites rather than repeats:
//!
//! - Each check on one message at a time: `crates/dedens-net/tests/exchange.rs`
//!   (`a_forged_formerr_without_a_question_causes_no_downgrade`, `a_changed_query_goes_with_a_spare_id`,
//!   `a_wrong_client_cookie_is_dropped`, `an_exchange_with_only_wrong_cookies_fails_as_forged`,
//!   `a_missing_cookie_is_dropped_once_the_server_sent_one`, `a_late_response_to_an_earlier_try_is_taken`), and in
//!   `crates/dedens-server/tests/stages.rs` the core's own check of QR, opcode and question (D111).
//! - What the socket does with a datagram nobody waits for: `crates/dedens-net/tests/udp.rs`
//!   (`a_query_waits_for_its_id`).
//! - One forgery in a race and one late copy over the run: `baseline.rs`.
//!
//! The sim client opens a socket for each exchange and closes it when the exchange ends, so a duplicate that comes
//! after lands on a port nobody reads.
//!
//! The last tests: the property, where the seed picks the attacker's rate, flaws, timing and duplicates during a
//! stream of queries, and the replay of one of its runs in two processes.

use std::cell::{Cell, RefCell};
use std::net::{IpAddr, Ipv4Addr};
use std::time::Duration;

use dedens_net::exchange::Failure;
use dedens_proto::edns::{Cookie, Edns, EdnsOption};
use dedens_proto::rdata::RData;
use dedens_proto::{Class, Flags, Message, Opcode, Rcode, Record, RecordType, Transport, Ttl};
use dedens_sim::attacker::{Attacker, Injection, Reaction};
use dedens_sim::client::Carrier;
use dedens_sim::fault::{Fault, Node};
use dedens_sim::seed::{self, Rng, Seed};
use dedens_sim::stub::{Outcome, question};
use dedens_sim::topology::Topology;
use dedens_sim::trace::{self, Event, What};
use dedens_sim::upstream::Answers;

use crate::util::{
    FORWARD_TIMEOUT, FORWARD_TRIES, SECOND, SEEDS, TIMEOUT, TRIES, answers, forwarded, served,
    served_over,
};

/// Fewer seeds for the scenarios in which a query runs through its timeouts: each costs the most wall time.
const FEW: &[u64] = &[0, 7];

/// The link between the resolver and the upstream server.
const LINK: (Node, Node) = (Node::Resolver, Node::Upstream(0));

/// The streams of the attacker's draws: no host of a run has them (the resolver's is 0, a client's its number).
const ATTACKER: u64 = 1 << 32;

/// The server cookie of the servers that have one.
const SERVER_COOKIE: [u8; 8] = [7; 8];

/// The address the forged answers carry: no server holds it.
const POISON: Ipv4Addr = Ipv4Addr::new(6, 6, 6, 6);

/// What is wrong with a forgery besides its data: the one check of the resolver it fails.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Flaw {
    /// A guessed ID, the other fields right (RFC 5452 §9.1).
    Id,
    /// The right ID, another question.
    Question,
    /// The right ID, QR clear: a query.
    Query,
    /// The right ID, another opcode.
    Opcode,
    /// The right ID, a client cookie that is not the query's (RFC 7873 §5.3).
    ClientCookie,
    /// The right ID, no cookie, to an exchange that has seen the server's (RFC 7873 §5.3).
    NoCookie,
}

/// The flaws any query allows.
const PLAIN: [Flaw; 4] = [Flaw::Id, Flaw::Question, Flaw::Query, Flaw::Opcode];

fn decode(wire: &[u8]) -> Message<'static> {
    Message::decode(wire)
        .expect("a message")
        .message
        .into_owned()
}

fn encode(message: &Message<'_>) -> Vec<u8> {
    let mut out = vec![0; 4096];
    let len = message.encode(&mut out).expect("a message that encodes");
    out.truncate(len);
    out
}

/// The cookie a message carries.
fn cookie_of(message: &Message<'_>) -> Option<Cookie> {
    message
        .edns
        .iter()
        .flat_map(|edns| &edns.options)
        .find_map(|option| match option {
            EdnsOption::Cookie(cookie) => Some(*cookie),
            _ => None,
        })
}

/// A forgery of `genuine`, the answer to `query`, with the flaw `flaw`: the one answer record is `POISON` for the
/// name asked. `guess` is the ID of [`Flaw::Id`], moved when it is the real one.
fn forge(genuine: &[u8], query: &Message<'_>, flaw: Flaw, guess: u16) -> Vec<u8> {
    let mut message = decode(genuine);
    let asked = message.questions.first().expect("a question").clone();
    message.header.flags = message.header.flags.without(Flags::TC);
    message.header.rcode = Rcode::NOERROR;
    message.answer = vec![Record::new(
        asked.name.clone(),
        Class::IN,
        Ttl::new(3600).expect("a TTL"),
        &RData::A(POISON),
    )];
    message.authority.clear();
    message.additional.clear();
    let edns = message.edns.get_or_insert_with(Edns::default);
    edns.options
        .retain(|option| !matches!(option, EdnsOption::Cookie(_)));
    match flaw {
        Flaw::Id => {
            let real = message.header.id;
            message.header.id = if guess == real {
                guess.wrapping_add(1)
            } else {
                guess
            };
        }
        Flaw::Question => message.questions = vec![question("example.net", asked.qtype)],
        Flaw::Query => message.header.flags = message.header.flags.without(Flags::QR),
        Flaw::Opcode => message.header.opcode = Opcode::NOTIFY,
        Flaw::ClientCookie => {
            let wrong = cookie_of(query).map_or([0xaa; 8], |cookie| cookie.client().map(|b| !b));
            let cookie = Cookie::new(wrong, Some(&[0x55; 8])).expect("a cookie");
            edns.options.push(EdnsOption::Cookie(cookie));
        }
        Flaw::NoCookie => {}
    }
    encode(&message)
}

/// The events of a run, and the address of its resolver.
struct Run {
    events: Vec<Event>,
    resolver: IpAddr,
}

impl Run {
    fn count(&self, what: impl Fn(&What) -> bool) -> usize {
        self.events.iter().filter(|event| what(&event.what)).count()
    }

    /// Times the resolver's cache changed with an upstream response.
    fn stored(&self) -> usize {
        self.count(|what| matches!(what, What::Stored { .. }))
    }

    /// Datagrams the attacker sent.
    fn injected(&self) -> usize {
        self.count(|what| matches!(what, What::Injected { .. }))
    }

    /// Replies the resolver sent.
    fn replied(&self) -> usize {
        self.count(|what| matches!(what, What::Replied { .. }))
    }

    fn asked(&self) -> usize {
        self.count(|what| matches!(what, What::Asked { .. }))
    }

    /// Queries the clients saw end in a response.
    fn answered(&self) -> usize {
        self.count(|what| matches!(what, What::Answered { .. }))
    }

    fn ended(&self) -> usize {
        self.count(|what| {
            matches!(
                what,
                What::Answered { .. } | What::Failed { .. } | What::Errored { .. }
            )
        })
    }

    /// The queries the resolver sent the server: the transport, and the count of its exchange.
    fn sent_by_the_resolver(&self) -> Vec<(u16, Transport)> {
        self.events
            .iter()
            .filter(|event| event.host == self.resolver)
            .filter_map(|event| match event.what {
                What::Sent {
                    sends, transport, ..
                } => Some((sends, transport)),
                _ => None,
            })
            .collect()
    }
}

/// A server that holds `example.com A`, `gmail.com MX` and `google.com TXT` (truncated over UDP), in that order.
fn answers_mx_and_txt() -> Answers {
    answers()
        .captured("mx")
        .truncating("truncated", "txt_large")
}

/// Whether a message answers with `POISON`.
fn holds_poison(message: &Message<'_>) -> bool {
    message
        .answer
        .iter()
        .any(|record| matches!(record.data(), RData::A(address) if address == POISON))
}

/// `n` bounded draws of `rng` in `0..bound`, as an index.
fn below(rng: &mut Rng, bound: usize) -> usize {
    let bound = u64::try_from(bound).expect("a small bound");
    usize::try_from(rng.below(bound)).expect("below the bound")
}

/// One client asks `example.com A` and another, `later`, asks it again, of a server that holds `answers`: the first
/// query goes to the server, the second comes from the cache. Both must get the two records, not the poison.
fn two_clients(seed: Seed, answers: Answers, later: Duration) -> Run {
    let mut world = Topology::new().upstream(answers).build(seed);
    let resolver = world.resolver.ip();
    for wait in [Duration::ZERO, later] {
        world.client(async move |stub| {
            tokio::time::sleep(wait).await;
            let answer = stub
                .expect(question("example.com", RecordType::A), Carrier::Udp)
                .await?;
            // The oracle checked the data; the poison is what a failing check would let in.
            assert_eq!(answer.message.answer.len(), 2, "{answer:?}");
            assert!(!holds_poison(&answer.message), "{answer:?}");
            Ok(())
        });
    }
    let events = world.run().expect("the run passes its checks");
    Run { events, resolver }
}

/// An attacker that races each answer with `FLOOD` datagrams over the first 30 ms, as the seed draws them: mostly
/// guessed IDs, the rest with the real ID and another flaw.
const FLOOD: usize = 200;

fn flood(seed: Seed) -> Attacker {
    let rng = RefCell::new(Rng::new(seed, ATTACKER));
    Attacker::new(move |seen| {
        let Some(genuine) = seen.genuine else {
            return Reaction::beside(Vec::new());
        };
        let query = decode(seen.query);
        let mut rng = rng.borrow_mut();
        let mut injections = Vec::new();
        for _ in 0..FLOOD {
            let flaw = match rng.below(8) {
                0 => Flaw::Question,
                1 => Flaw::Query,
                2 => Flaw::Opcode,
                _ => Flaw::Id,
            };
            injections.push(Injection {
                after: Duration::from_micros(rng.below(30_000)),
                wire: forge(genuine, &query, flaw, rng.next_u16()),
            });
        }
        Reaction::beside(injections)
    })
}

#[test]
fn a_flood_of_forgeries_racing_the_real_answer_leaves_the_cache_with_the_real_one() {
    seed::each(SEEDS, |seed| {
        let answers = answers_mx_and_txt().attacked_by(flood(seed));
        let run = two_clients(seed, answers, 2 * SECOND);
        let events = &run.events;
        // The flood went out once, for the one query to the server, and the server answered once.
        assert_eq!(run.injected(), FLOOD, "{events:#?}");
        assert_eq!(served(&run.events), 1, "{events:#?}");
        // One answer was stored: the server's. The other client's query came from the cache.
        assert_eq!(run.stored(), 1, "{events:#?}");
        assert_eq!(forwarded(&run.events), 1, "{events:#?}");
        assert_eq!(run.replied(), 2, "{events:#?}");
        assert_eq!(run.answered(), 2, "{events:#?}");
        // The resolver took no forgery for a reason to ask again.
        assert_eq!(
            run.sent_by_the_resolver(),
            [(1, Transport::Udp)],
            "{events:#?}"
        );
    });
}

#[test]
fn forgeries_in_the_servers_place_end_in_servfail_and_none_is_stored() {
    seed::each(FEW, |seed| {
        // The attacker answers in the server's place, with what it drew: no genuine answer goes out.
        let rng = RefCell::new(Rng::new(seed, ATTACKER));
        let attacker = Attacker::new(move |seen| {
            let Some(genuine) = seen.genuine else {
                return Reaction::instead(Vec::new());
            };
            let query = decode(seen.query);
            let mut rng = rng.borrow_mut();
            let injections = (0..FLOOD)
                .map(|n| Injection {
                    after: Duration::from_millis(u64::try_from(n * 30).expect("small")),
                    wire: forge(genuine, &query, PLAIN[n % PLAIN.len()], rng.next_u16()),
                })
                .collect();
            Reaction::instead(injections)
        });
        let mut world = Topology::new()
            .upstream(answers_mx_and_txt().attacked_by(attacker))
            .build(seed);
        let resolver = world.resolver.ip();
        world.client(async move |stub| {
            let outcome = stub
                .ask(question("example.com", RecordType::A), Carrier::Udp)
                .await?;
            let Outcome::Answered(answer) = outcome else {
                return Err(format!("no answer: {outcome:?}").into());
            };
            assert_eq!(answer.message.rcode(), Rcode::SERVFAIL, "{answer:?}");
            assert!(answer.message.answer.is_empty(), "{answer:?}");
            // The forward stage's tries ran out with only forgeries heard.
            assert!(
                answer.elapsed >= FORWARD_TIMEOUT * FORWARD_TRIES
                    && answer.elapsed < FORWARD_TIMEOUT * FORWARD_TRIES + SECOND,
                "{answer:?}"
            );
            // What the cache answers now is the failure it holds (RFC 9520 §3.2), at once, not a forgery.
            let outcome = stub
                .ask(question("example.com", RecordType::A), Carrier::Udp)
                .await?;
            let Outcome::Answered(again) = outcome else {
                return Err(format!("no answer: {outcome:?}").into());
            };
            assert_eq!(again.message.rcode(), Rcode::SERVFAIL, "{again:?}");
            assert!(again.elapsed < SECOND, "{again:?}");
            Ok(())
        });
        let events = world.run().expect("the run passes its checks");
        let run = Run { events, resolver };
        assert_eq!(served(&run.events), 0, "{:#?}", run.events);
        // The cache holds the failure (D43, RFC 9520 §3.2) and nothing of the forgeries: that one entry is all it
        // stored.
        assert_eq!(run.stored(), 1, "{:#?}", run.events);
        assert!(run.injected() >= FLOOD, "{:#?}", run.events);
        let most = run.sent_by_the_resolver().iter().map(|(n, _)| *n).max();
        assert_eq!(most, Some(u16::try_from(FORWARD_TRIES).expect("two")));
    });
}

/// The times, after the query, at which an attacker repeats the real answer: with it, a moment after, and long
/// after the exchange ended.
const COPIES: [Duration; 7] = [
    Duration::ZERO,
    Duration::from_millis(1),
    Duration::from_millis(3),
    Duration::from_millis(10),
    Duration::from_millis(50),
    Duration::from_millis(300),
    Duration::from_secs(2),
];

fn copies() -> Attacker {
    Attacker::new(|seen| {
        Reaction::beside(
            seen.genuine
                .into_iter()
                .flat_map(|genuine| {
                    COPIES.map(|after| Injection {
                        after,
                        wire: genuine.to_vec(),
                    })
                })
                .collect(),
        )
    })
}

#[test]
fn a_duplicated_response_is_one_answer_stored_once() {
    seed::each(SEEDS, |seed| {
        let mut world = Topology::new()
            .upstream(answers_mx_and_txt().attacked_by(copies()))
            .build(seed);
        let resolver = world.resolver.ip();
        world.client(async move |stub| {
            // A, TXT (TC over UDP, then TCP), then A again, after the copies and from the cache.
            for (name, qtype) in [
                ("example.com", RecordType::A),
                ("google.com", RecordType::TXT),
            ] {
                stub.expect(question(name, qtype), Carrier::Udp).await?;
            }
            tokio::time::sleep(3 * SECOND).await;
            stub.expect(question("example.com", RecordType::A), Carrier::Udp)
                .await?;
            Ok(())
        });
        let events = world.run().expect("the run passes its checks");
        let run = Run { events, resolver };
        let events = &run.events;
        // Each query ended once, with one reply.
        assert_eq!(run.asked(), 3, "{events:#?}");
        assert_eq!(run.answered(), 3, "{events:#?}");
        assert_eq!(run.replied(), 3, "{events:#?}");
        // The server answered the A over UDP, and the TXT over UDP (TC) and TCP: the copies are the attacker's.
        assert_eq!(served_over(&run.events, Transport::Udp), 2, "{events:#?}");
        assert_eq!(served_over(&run.events, Transport::Tcp), 1, "{events:#?}");
        assert_eq!(run.injected(), 2 * COPIES.len(), "{events:#?}");
        // Two answers stored, one for each question that went to the server; the copies added nothing, and none
        // counted as a response to a retry: each exchange sent once, the TCP one after the UDP query's TC.
        assert_eq!(run.stored(), 2, "{events:#?}");
        assert_eq!(forwarded(&run.events), 2, "{events:#?}");
        assert_eq!(
            run.sent_by_the_resolver(),
            [
                (1, Transport::Udp),
                (1, Transport::Udp),
                (2, Transport::Tcp)
            ],
            "{events:#?}"
        );
    });
}

/// An attacker that lets the first query through and answers each later one in the server's place with forgeries
/// that have the real ID and question, and no cookie or a wrong client cookie.
fn without_the_cookie() -> Attacker {
    let first = Cell::new(true);
    Attacker::new(move |seen| {
        let Some(genuine) = seen.genuine else {
            return Reaction::instead(Vec::new());
        };
        if first.replace(false) {
            return Reaction::beside(Vec::new());
        }
        let query = decode(seen.query);
        let injections = [
            (Duration::ZERO, Flaw::NoCookie),
            (Duration::ZERO, Flaw::ClientCookie),
            (Duration::from_millis(20), Flaw::NoCookie),
            (Duration::from_millis(500), Flaw::ClientCookie),
        ]
        .into_iter()
        .map(|(after, flaw)| Injection {
            after,
            wire: forge(genuine, &query, flaw, 0),
        })
        .collect();
        Reaction::instead(injections)
    })
}

#[test]
fn forged_responses_without_the_servers_cookie_end_an_exchange_as_forged() {
    seed::each(FEW, |seed| {
        let answers = answers_mx_and_txt()
            .cookies(SERVER_COOKIE)
            .attacked_by(without_the_cookie());
        let mut world = Topology::new().upstream(answers).build(seed);
        let server = world.upstreams[0];
        world.client(async move |stub| {
            // The server sets its cookie in the first answer; the client's exchanges go with it from then on.
            let query = Message::query(0, question("example.com", RecordType::A));
            let first = stub.ask_query(query, server, Carrier::Udp).await?;
            assert!(matches!(first, Outcome::Answered(_)), "{first:?}");
            // Every answer that comes now has the real ID and question, and no server cookie: none ends the exchange.
            let started = tokio::time::Instant::now();
            let query = Message::query(0, question("example.com", RecordType::A));
            let second = stub.ask_query(query, server, Carrier::Udp).await?;
            assert!(
                matches!(second, Outcome::Failed(Failure::Forged { sends: 3 })),
                "{second:?}"
            );
            let took = started.elapsed();
            assert!(
                took >= TIMEOUT * TRIES && took < TIMEOUT * TRIES + SECOND,
                "{took:?}"
            );
            Ok(())
        });
        let resolver = world.resolver.ip();
        let events = world.run().expect("the run passes its checks");
        let run = Run { events, resolver };
        assert_eq!(served(&run.events), 1, "{:#?}", run.events);
        assert_eq!(run.answered(), 1, "{:#?}", run.events);
        assert_eq!(
            run.injected(),
            4 * usize::try_from(TRIES).expect("three"),
            "{:#?}",
            run.events
        );
    });
}

#[test]
fn a_resolver_that_hears_only_forgeries_after_the_servers_cookie_answers_servfail() {
    seed::each(FEW, |seed| {
        let answers = answers_mx_and_txt()
            .cookies(SERVER_COOKIE)
            .attacked_by(without_the_cookie());
        let mut world = Topology::new().upstream(answers).build(seed);
        let resolver = world.resolver.ip();
        world.client(async move |stub| {
            stub.expect(question("example.com", RecordType::A), Carrier::Udp)
                .await?;
            // Another question, so the cache cannot answer: the resolver's exchange hears forgeries alone.
            let outcome = stub
                .ask(question("gmail.com", RecordType::MX), Carrier::Udp)
                .await?;
            let Outcome::Answered(answer) = outcome else {
                return Err(format!("no answer: {outcome:?}").into());
            };
            assert_eq!(answer.message.rcode(), Rcode::SERVFAIL, "{answer:?}");
            assert!(answer.message.answer.is_empty(), "{answer:?}");
            assert!(
                answer.elapsed >= FORWARD_TIMEOUT * FORWARD_TRIES
                    && answer.elapsed < FORWARD_TIMEOUT * FORWARD_TRIES + SECOND,
                "{answer:?}"
            );
            Ok(())
        });
        let events = world.run().expect("the run passes its checks");
        let run = Run { events, resolver };
        // Only the first answer came from the server: the cache stored it, and the failure it holds (RFC 9520 §3.2).
        assert_eq!(served(&run.events), 1, "{:#?}", run.events);
        assert_eq!(run.stored(), 2, "{:#?}", run.events);
        assert!(run.injected() >= 4, "{:#?}", run.events);
    });
}

/// The questions each client of the property asks: a repeat among them, which the cache answers.
const QUESTIONS: [(&str, RecordType); 4] = [
    ("example.com", RecordType::A),
    ("gmail.com", RecordType::MX),
    ("google.com", RecordType::TXT),
    ("example.com", RecordType::A),
];

/// An attacker that draws for each query to the server how many forgeries it sends, of which flaws, when, and
/// whether it repeats the real answer or silences it.
///
/// The cookie flaws come only when the query carries what they break: a client cookie, and a server cookie for
/// [`Flaw::NoCookie`].
fn drawing(rng: Rng) -> Attacker {
    let rng = RefCell::new(rng);
    Attacker::new(move |seen| {
        let Some(genuine) = seen.genuine else {
            return Reaction::beside(Vec::new());
        };
        let query = decode(seen.query);
        let mut flaws = PLAIN.to_vec();
        if let Some(cookie) = cookie_of(&query) {
            flaws.push(Flaw::ClientCookie);
            if cookie.server().is_some() {
                flaws.push(Flaw::NoCookie);
            }
        }
        let mut rng = rng.borrow_mut();
        let silenced = rng.below(5) == 0;
        // The forgeries of a silenced server go on as long as the forward stage listens.
        let spread = if silenced { 7_000 } else { 400 };
        let mut injections = Vec::new();
        for _ in 0..rng.below(41) {
            let flaw = flaws[below(&mut rng, flaws.len())];
            injections.push(Injection {
                after: Duration::from_millis(rng.below(spread)),
                wire: forge(genuine, &query, flaw, rng.next_u16()),
            });
        }
        if silenced {
            return Reaction::instead(injections);
        }
        for _ in 0..rng.below(4) {
            injections.push(Injection {
                after: Duration::from_millis(rng.below(spread)),
                wire: genuine.to_vec(),
            });
        }
        Reaction::beside(injections)
    })
}

/// The loss rates and the longest delays the link to the server may get.
const RATES: [f64; 3] = [0.0, 0.05, 0.2];
const DELAYS_MS: [u64; 4] = [0, 50, 300, 2_000];

/// A run in which two clients ask `QUESTIONS` over UDP while an attacker on the server's host sends what the seed
/// draws, the server has a cookie or not as the seed says, and the link to the server loses and delays as it picks.
fn attacked(seed: Seed) -> Run {
    let mut rng = Rng::new(seed, ATTACKER);
    let mut answers = answers_mx_and_txt();
    if rng.below(2) == 0 {
        answers = answers.cookies(SERVER_COOKIE);
    }
    let mut world = Topology::new()
        .upstream(answers.attacked_by(drawing(rng)))
        .duration(10 * 60 * SECOND)
        .build(seed);
    let rate = RATES[world.choose(RATES.len())];
    let max = Duration::from_millis(DELAYS_MS[world.choose(DELAYS_MS.len())]);
    world.fault(
        Duration::ZERO,
        Fault::Loss {
            a: LINK.0,
            b: LINK.1,
            rate,
        },
    );
    world.fault(
        Duration::ZERO,
        Fault::Latency {
            a: LINK.0,
            b: LINK.1,
            min: Duration::ZERO,
            max,
        },
    );
    let resolver = world.resolver.ip();
    for _ in 0..2 {
        let wait = world.pick(Duration::ZERO, 3 * SECOND);
        world.client(async move |stub| {
            tokio::time::sleep(wait).await;
            for (name, qtype) in QUESTIONS {
                stub.ask(question(name, qtype), Carrier::Udp).await?;
            }
            Ok(())
        });
    }
    let events = world.run().expect("the run passes its checks");
    Run { events, resolver }
}

/// The property of the family: whatever the attacker draws (how many forgeries, which flaw, when, and copies of
/// the real answer), each query ends by its deadline in the data of the server, SERVFAIL or a failure, which
/// the stub's checks and the oracle hold; and the cache stores an answer only for one the server gave.
#[test]
fn whatever_the_attacker_forges_the_clients_get_the_servers_data() {
    seed::each(SEEDS, |seed| {
        let run = attacked(seed);
        let events = &run.events;
        assert_eq!(run.asked(), 2 * QUESTIONS.len(), "{events:#?}");
        assert_eq!(run.ended(), run.asked(), "{events:#?}");
        // Each change of the cache has a cause: an answer of the server, or the SERVFAIL the resolver holds (RFC 9520 §3.2).
        let servfails = run.count(|what| {
            matches!(
                what,
                What::Answered {
                    rcode: Rcode::SERVFAIL,
                    ..
                }
            )
        });
        assert!(
            run.stored() <= served(&run.events) + servfails,
            "{events:#?}"
        );
        // The attacker did attack: this run is no check of nothing.
        assert!(run.injected() > 0, "{events:#?}");
    });
}

/// One seed gives one trace in two processes (D133), the family's own scenario: the attacker's draws and the cache.
#[test]
fn an_attacked_run_replays_in_two_processes() {
    let runs = Cell::new(0);
    seed::in_two_processes(
        module_path!(),
        "an_attacked_run_replays_in_two_processes",
        FEW,
        |seed| {
            runs.set(runs.get() + 1);
            trace::digest(&attacked(seed).events)
        },
    );
    assert!(runs.get() > 0);
}
