//! What the limits of the resolver hold back, with many clients in a few networks on one resolver (D91, D113, D117):
//! a network over its response rate, a valid and a forged Server Cookie, a network over its share of validation, a
//! denied network. The clients each limit names are held back; the others of their kind are not.
//!
//! Left to other tests, which this family cites rather than repeats:
//!
//! - The bucket, the slip count and the refill, a query at a time: `access.rs` (`a_burst_passes_then_the_rate_limits`,
//!   `the_bucket_refills_per_second`, `one_in_slip_is_answered`) and `budget.rs` of `dedens-server`.
//! - The cookie of a reply, valid, forged, stale or of another address, and the slip as BADCOOKIE: RFC 7873 §5.2 to
//!   §5.4 and RFC 9018 in `crates/dedens-server/tests/access.rs`.
//! - A share of validation spent by one client, its neighbour in the /24, a proven client and an exempt source:
//!   `crates/dedens-server/tests/dnssec.rs` (`a_client_over_its_share_cannot_shed_another_client`,
//!   `a_proven_client_is_not_shed_by_the_unproven_ones_of_its_network`, `an_exempt_source_has_no_share`).
//! - The access lists, one query at a time: `crates/dedens-server/src/access.rs` and the pipeline's tests.
//!
//! What is new here is the clients together, through the real client's reactions: a TC reply is asked again over
//! TCP, a BADCOOKIE with a fresh cookie is asked again with it, a dropped query is asked again five seconds later,
//! when the bucket has refilled.
//!
//! The resolver's clock is whole seconds of the run, and every client asks within the first second, so a network's
//! queries meet its bucket together: the stub's first try, then each retry five seconds after. The model of the
//! property is that bucket, wave by wave. The rate is one query a second, so each retry finds a bucket whole.
//!
//! The buckets of the limit and the shares are slots of a table hashed with a key that changes with each process
//! (D133): the tables here have a million slots for at most four networks, so that two networks share one with a
//! chance of a few in a million, and the replay test runs the scenario in two processes.
//!
//! The last tests: the property, where the seed picks the networks, their clients and the limits, and the replay of
//! a run in two processes.

use std::cell::RefCell;
use std::collections::BTreeMap;
use std::net::{IpAddr, Ipv4Addr};
use std::rc::Rc;
use std::time::{Duration, UNIX_EPOCH};

use dedens_dnssec::{Limits as ValidatorLimits, TrustAnchors, Validator};
use dedens_net::exchange::Failure;
use dedens_proto::edns::{EdnsOption, InfoCode};
use dedens_proto::{Flags, Message, Rcode, RecordType, Transport};
use dedens_server::{
    Access, Budget, Budgets, Cookies, Denial, Network, Pipeline, Rate, RateLimit, RateLimitConfig,
    Secret, Secrets, Server, Validating,
};
use dedens_sim::client::Carrier;
use dedens_sim::fault::{Fault, Node};
use dedens_sim::resolver::{pipeline, pipeline_validating, wall_clock};
use dedens_sim::seed::{self, Rng, Seed};
use dedens_sim::stub::{Outcome, question};
use dedens_sim::topology::{Topology, World};
use dedens_sim::trace::{self, Event, What};
use dedens_sim::upstream::Answers;

use crate::util::{SECOND, SEEDS, answers, forwarded};

/// Fewer seeds for the scenarios that run through the stub's timeouts or validate.
const FEW: &[u64] = &[0, 7];

/// Three seeds for the property, whose runs go through the stub's timeouts.
const THREE: &[u64] = &[0, 7, 42];

/// One seed for the scenario that runs twice in two processes.
const ONE: &[u64] = &[0];

/// How long the stub waits for each try, and how many tries it makes (D27).
const STUB_TIMEOUT: Duration = Duration::from_secs(5);
const STUB_TRIES: u16 = 3;

/// Buckets of the rate limit and the shares: a million, so that the networks of a run do not share one.
const TABLE: usize = 1 << 20;

/// Four /24 networks of documentation and shared addresses, none in the 192.168.0.0/16 the other hosts take.
const NETS: [[u8; 3]; 4] = [[198, 51, 100], [203, 0, 113], [192, 0, 2], [100, 64, 0]];

/// The address `n` of the network `prefix`.
fn host(prefix: [u8; 3], n: u8) -> IpAddr {
    let [a, b, c] = prefix;
    IpAddr::V4(Ipv4Addr::new(a, b, c, n))
}

/// The network `prefix`/24.
fn network(prefix: [u8; 3]) -> Network {
    let [a, b, c] = prefix;
    format!("{a}.{b}.{c}.0/24")
        .parse()
        .expect("a network of IPv4")
}

/// The secret of the resolver's cookies, and another a forger may hold.
fn secrets(byte: u8) -> Secrets {
    Secrets::new(Secret::new([byte; 16]), vec![])
}

/// What the resolver of a run limits: a bucket of `burst` queries and one more a second for each /24, `slip`, the
/// cookies, the networks `allowed` and what happens to the rest.
#[derive(Clone)]
struct Limits {
    burst: u32,
    slip: u8,
    cookies: bool,
    access: Option<(Vec<Network>, Denial)>,
}

impl Limits {
    fn open(burst: u32, slip: u8) -> Self {
        Self {
            burst,
            slip,
            cookies: false,
            access: None,
        }
    }

    const fn with_cookies(mut self) -> Self {
        self.cookies = true;
        self
    }

    fn allowing(mut self, allowed: &[[u8; 3]], denial: Denial) -> Self {
        self.access = Some((allowed.iter().copied().map(network).collect(), denial));
        self
    }

    fn pipeline(&self, upstreams: &[Server]) -> Pipeline {
        let rate = Rate {
            prefix: 24,
            per_second: 1,
            burst: self.burst,
        };
        let limit = RateLimit::new(RateLimitConfig {
            ipv4: rate,
            slip: self.slip,
            table: TABLE,
            ..RateLimitConfig::default()
        })
        .expect("a limit in bounds");
        let mut pipeline = pipeline(upstreams).with_rate_limit(limit);
        if self.cookies {
            pipeline = pipeline.with_cookies(Cookies::new(secrets(7), wall_clock()));
        }
        if let Some((allowed, denial)) = &self.access {
            pipeline = pipeline.with_access(Access::new(allowed.iter().copied(), [], *denial));
        }
        pipeline
    }

    /// A world with this resolver and the server of `answers`.
    fn world(&self, seed: Seed) -> World {
        let limits = self.clone();
        Topology::new()
            .upstream(answers())
            .resolver(move |upstreams| limits.pipeline(upstreams))
            .build(seed)
    }
}

/// How a client's query ended.
#[derive(Debug, Clone, PartialEq)]
enum How {
    Answered(Rcode, Transport),
    Failed(Failure),
    Errored,
}

/// How a client's query ended, the queries it took and the retry it waited for: each is 5 s of the stub's.
#[derive(Debug, Clone, PartialEq)]
struct Fate {
    how: How,
    sends: u16,
    wave: u64,
}

impl Fate {
    const fn answered(rcode: Rcode, transport: Transport, sends: u16, wave: u64) -> Self {
        Self {
            how: How::Answered(rcode, transport),
            sends,
            wave,
        }
    }

    /// A query answered with the data over UDP, `sends` queries after `wave` timeouts.
    const fn direct(sends: u16, wave: u64) -> Self {
        Self::answered(Rcode::NOERROR, Transport::Udp, sends, wave)
    }

    /// A query that ran through its tries.
    const fn lost() -> Self {
        Self {
            how: How::Failed(Failure::TimedOut { sends: STUB_TRIES }),
            sends: STUB_TRIES,
            wave: STUB_TRIES as u64,
        }
    }
}

/// The fates of the queries the hosts of `of` made, one for each query, in the order they ended.
fn fates(events: &[Event], of: impl Fn(IpAddr) -> bool) -> Vec<Fate> {
    let mut open: BTreeMap<IpAddr, (Duration, u16)> = BTreeMap::new();
    let mut fates = Vec::new();
    for event in events.iter().filter(|event| of(event.host)) {
        let how = match &event.what {
            What::Asked { .. } => {
                open.insert(event.host, (event.at, 0));
                continue;
            }
            What::Sent { .. } => {
                if let Some((_, sends)) = open.get_mut(&event.host) {
                    *sends += 1;
                }
                continue;
            }
            What::Answered {
                rcode, transport, ..
            } => How::Answered(*rcode, *transport),
            What::Failed { failure, .. } => How::Failed(failure.clone()),
            What::Errored { .. } => How::Errored,
            _ => continue,
        };
        if let Some((asked, sends)) = open.remove(&event.host) {
            let took = event.at.saturating_sub(asked);
            fates.push(Fate {
                how,
                sends,
                wave: u64::try_from(took.as_millis() / STUB_TIMEOUT.as_millis())
                    .unwrap_or(u64::MAX),
            });
        }
    }
    fates
}

/// The fates of the hosts of the network `prefix`.
fn fates_of(events: &[Event], prefix: [u8; 3]) -> Vec<Fate> {
    fates(events, |host| match host {
        IpAddr::V4(host) => host.octets().first_chunk() == Some(&prefix),
        IpAddr::V6(_) => false,
    })
}

/// `got` is `want` in some order.
#[track_caller]
fn assert_same(got: &[Fate], want: &[Fate], events: &[Event]) {
    let mut left = want.to_vec();
    for fate in got {
        let at = left.iter().position(|wanted| wanted == fate);
        assert!(
            at.is_some(),
            "{fate:?} is not wanted: got {got:?}, want {want:?}\n{events:#?}"
        );
        if let Some(at) = at {
            left.swap_remove(at);
        }
    }
    assert!(left.is_empty(), "got {got:?}, want {want:?}\n{events:#?}");
}

/// `fate` `count` times.
fn times(count: usize, fate: &Fate) -> Vec<Fate> {
    vec![fate.clone(); count]
}

/// `parts` one after the other.
fn all(parts: &[Vec<Fate>]) -> Vec<Fate> {
    parts.concat()
}

/// A network of `clients` clients, each asking `example.com A` once over `carrier`.
#[derive(Debug, Clone, Copy)]
struct Subnet {
    prefix: [u8; 3],
    clients: u8,
    carrier: Carrier,
}

impl Subnet {
    const fn udp(prefix: [u8; 3], clients: u8) -> Self {
        Self {
            prefix,
            clients,
            carrier: Carrier::Udp,
        }
    }

    const fn tcp(prefix: [u8; 3], clients: u8) -> Self {
        Self {
            prefix,
            clients,
            carrier: Carrier::Tcp,
        }
    }
}

/// Adds the clients of `subnet`, which all ask at once, with Client Cookies if `cookies`; a REFUSED is allowed.
fn add(world: &mut World, subnet: Subnet, cookies: bool) {
    for n in 1..=subnet.clients {
        let carrier = subnet.carrier;
        world.client_at(host(subnet.prefix, n), async move |mut stub| {
            stub.options.cookies = cookies;
            stub.rules.accept = vec![Rcode::REFUSED];
            let outcome = stub
                .ask(question("example.com", RecordType::A), carrier)
                .await?;
            // D91: a refusal is REFUSED with EDE 18, and never truncated.
            if let Outcome::Answered(answer) = outcome
                && answer.message.rcode() == Rcode::REFUSED
            {
                assert_eq!(error(&answer.message), Some(InfoCode::PROHIBITED));
                assert!(!answer.message.header.flags.contains(Flags::TC));
            }
            Ok(())
        });
    }
}

/// The error code of a reply.
fn error(reply: &Message<'_>) -> Option<InfoCode> {
    reply
        .edns
        .as_ref()?
        .options
        .iter()
        .find_map(|option| match option {
            EdnsOption::Ede(ede) => Some(ede.code),
            _ => None,
        })
}

/// D113: a network over its rate, whose reply to one query in `slip` is a truncated one, and whose clients ask again
/// over TCP, which is not limited; a network within its rate and one that asks over TCP see no change.
#[test]
fn a_network_over_its_rate_asks_again_over_tcp_and_the_others_are_answered() {
    seed::each(SEEDS, |seed| {
        let mut world = Limits::open(3, 1).world(seed);
        let over = Subnet::udp(NETS[0], 6);
        let within = Subnet::udp(NETS[1], 3);
        let tcp = Subnet::tcp(NETS[2], 6);
        for subnet in [over, within, tcp] {
            add(&mut world, subnet, false);
        }
        let events = world.run().expect("the run passes its checks");
        // The bucket holds 3: the others are all slipped, answered over TCP by the queries after the UDP one.
        assert_same(
            &fates_of(&events, over.prefix),
            &all(&[
                times(3, &Fate::direct(1, 0)),
                times(3, &Fate::answered(Rcode::NOERROR, Transport::Tcp, 2, 0)),
            ]),
            &events,
        );
        assert_same(
            &fates_of(&events, within.prefix),
            &times(3, &Fate::direct(1, 0)),
            &events,
        );
        assert_same(
            &fates_of(&events, tcp.prefix),
            &times(6, &Fate::answered(Rcode::NOERROR, Transport::Tcp, 1, 0)),
            &events,
        );
    });
}

/// D113: with `slip` 2 one query in two over the rate is truncated and the other dropped, so that its client waits
/// for its retry, five seconds on, when the bucket is whole again; the count of drops goes on across the waves.
#[test]
fn one_in_slip_is_truncated_and_the_rest_wait_for_the_refill() {
    seed::each(FEW, |seed| {
        let mut world = Limits::open(2, 2).world(seed);
        let subnet = Subnet::udp(NETS[0], 8);
        add(&mut world, subnet, false);
        let events = world.run().expect("the run passes its checks");
        // The bucket holds 2; of the 6 over it, 3 are dropped (the 1st, 3rd and 5th) and 3 slipped. The 3 dropped
        // ask again at 5 s: 2 pass, the 3rd is over, the 7th limited query of the network and the count is odd
        // again, so it is dropped; it asks again at 10 s and passes.
        assert_same(
            &fates_of(&events, subnet.prefix),
            &all(&[
                times(2, &Fate::direct(1, 0)),
                times(3, &Fate::answered(Rcode::NOERROR, Transport::Tcp, 2, 0)),
                times(2, &Fate::direct(2, 1)),
                times(1, &Fate::direct(3, 2)),
            ]),
            &events,
        );
    });
}

/// D113, RFC 7873 §5.4: a client with cookies that is slipped gets BADCOOKIE with a fresh Server Cookie, asks again
/// with it at once and is answered over UDP: no TCP connection is made for it, and no wait.
#[test]
fn a_slip_of_a_client_with_cookies_is_a_fresh_cookie_and_not_a_truncation() {
    seed::each(SEEDS, |seed| {
        let mut world = Limits::open(3, 1).with_cookies().world(seed);
        let subnet = Subnet::udp(NETS[0], 6);
        add(&mut world, subnet, true);
        let events = world.run().expect("the run passes its checks");
        assert_same(
            &fates_of(&events, subnet.prefix),
            &all(&[times(3, &Fate::direct(1, 0)), times(3, &Fate::direct(2, 0))]),
            &events,
        );
        let tcp = events.iter().any(|event| {
            matches!(
                event.what,
                What::Sent {
                    transport: Transport::Tcp,
                    ..
                }
            )
        });
        assert!(!tcp, "{events:#?}");
    });
}

/// RFC 7873 §5.2.5, RFC 9018 §4: a query with the Server Cookie the resolver made for its address passes the limit,
/// in the second its network's bucket is empty; a query with none, a cookie made under another secret or one made
/// for another address does not, and waits for the refill. With no slip the limited are dropped, so that a pass is
/// seen as no wait.
#[test]
fn a_valid_server_cookie_passes_the_limit_and_a_forged_one_does_not() {
    seed::each(FEW, |seed| {
        let limits = Limits::open(1, 0).with_cookies();
        let mut world = limits.world(seed);
        let [a, b, c] = [NETS[0], NETS[1], NETS[2]];
        let late = SECOND / 2;
        let resolver = world.resolver;
        let client = [1, 2, 3, 4, 5, 6, 7, 8];
        let first = host(a, 1);
        // A: the first query spends the bucket and brings the cookie; the second, with it, passes; a third client
        // that has none waits.
        world.client_at(first, async move |stub| {
            for _ in 0..2 {
                stub.expect(question("example.com", RecordType::A), Carrier::Udp)
                    .await?;
                tokio::time::sleep(late).await;
            }
            Ok(())
        });
        world.client_at(host(a, 2), async move |mut stub| {
            stub.options.cookies = false;
            tokio::time::sleep(late).await;
            stub.expect(question("example.com", RecordType::A), Carrier::Udp)
                .await?;
            Ok(())
        });
        // B and C: the second client's cookie is one a forger makes, under another secret, or one the resolver made
        // for A's client. The cookies are made when the client asks: they carry the time of the run.
        for (prefix, secret, from) in [(b, 9, host(b, 2)), (c, 7, first)] {
            world.client_at(host(prefix, 1), async move |stub| {
                stub.expect(question("example.com", RecordType::A), Carrier::Udp)
                    .await?;
                Ok(())
            });
            world.client_at(host(prefix, 2), async move |stub| {
                tokio::time::sleep(late).await;
                let cookie = Cookies::new(secrets(secret), wall_clock()).issue(client, from);
                let mut query = Message::query(0, question("example.com", RecordType::A));
                if let Some(edns) = query.edns.as_mut() {
                    edns.options.push(EdnsOption::Cookie(cookie));
                }
                stub.ask_query(query, resolver, Carrier::Udp).await?;
                Ok(())
            });
        }
        let events = world.run().expect("the run passes its checks");
        assert_same(
            &fates_of(&events, a),
            &all(&[times(2, &Fate::direct(1, 0)), times(1, &Fate::direct(2, 1))]),
            &events,
        );
        for prefix in [b, c] {
            assert_same(
                &fates_of(&events, prefix),
                &all(&[times(1, &Fate::direct(1, 0)), times(1, &Fate::direct(2, 1))]),
                &events,
            );
        }
    });
}

/// D91, D113: a denied network is refused, REFUSED with EDE 18 over UDP and TCP; over UDP its refusals count
/// against the rate and the ones over it are dropped, never truncated, so that its clients wait for the refill; an
/// allowed network is answered, and nothing of the denied one reaches the upstream server.
#[test]
fn a_denied_network_is_refused_and_an_allowed_one_answered() {
    seed::each(FEW, |seed| {
        let allowed = Subnet::udp(NETS[0], 3);
        let denied = Subnet::udp(NETS[1], 5);
        let tcp = Subnet::tcp(NETS[2], 2);
        let limits = Limits::open(3, 1).allowing(&[allowed.prefix], Denial::Refuse);
        let mut world = limits.world(seed);
        for subnet in [allowed, denied, tcp] {
            add(&mut world, subnet, false);
        }
        let events = world.run().expect("the run passes its checks");
        assert_same(
            &fates_of(&events, allowed.prefix),
            &times(3, &Fate::direct(1, 0)),
            &events,
        );
        // 3 refused at once; 2 dropped over the rate, however `slip` is, and refused 5 s on.
        assert_same(
            &fates_of(&events, denied.prefix),
            &all(&[
                times(3, &Fate::answered(Rcode::REFUSED, Transport::Udp, 1, 0)),
                times(2, &Fate::answered(Rcode::REFUSED, Transport::Udp, 2, 1)),
            ]),
            &events,
        );
        assert_same(
            &fates_of(&events, tcp.prefix),
            &times(2, &Fate::answered(Rcode::REFUSED, Transport::Tcp, 1, 0)),
            &events,
        );
        assert!(forwarded(&events) <= 3, "{events:#?}");
    });
}

/// D91: a denied network is dropped: its UDP queries get nothing, its TCP connections are closed as they open; an
/// allowed network is answered, and nothing of the denied one reaches the upstream server.
#[test]
fn a_network_denied_by_dropping_gets_nothing() {
    seed::each(FEW, |seed| {
        let allowed = Subnet::udp(NETS[0], 2);
        let denied = Subnet::udp(NETS[1], 2);
        let tcp = Subnet::tcp(NETS[2], 2);
        let limits = Limits::open(3, 1).allowing(&[allowed.prefix], Denial::Drop);
        let mut world = limits.world(seed);
        for subnet in [allowed, denied, tcp] {
            add(&mut world, subnet, false);
        }
        let events = world.run().expect("the run passes its checks");
        assert_same(
            &fates_of(&events, allowed.prefix),
            &times(2, &Fate::direct(1, 0)),
            &events,
        );
        assert_same(
            &fates_of(&events, denied.prefix),
            &times(2, &Fate::lost()),
            &events,
        );
        assert_same(
            &fates_of(&events, tcp.prefix),
            &times(
                2,
                &Fate {
                    how: How::Errored,
                    sends: 1,
                    wave: 0,
                },
            ),
            &events,
        );
        assert!(forwarded(&events) <= 2, "{events:#?}");
    });
}

/// What a client of `ask_cold` came to, for each name it asked.
type Report = Rc<RefCell<Vec<Validated>>>;

/// The names of captured zones that validate, each cold the first time it is asked.
const COLD: [&str; 5] = [
    "nlnetlabs.nl",
    "cloudflare.com",
    "fedoraproject.org",
    "ed25519.nl",
    "debian.org",
];

/// A world with a validating resolver at the time of the captures of `dedens-dnssec`, with no key cache, so that
/// each name costs a validation from the root, and each client network a share of `share` units, refilled
/// `SHARE_REFILL` a second. The links of the resolver take no time, so that what a run asks is within one second of
/// its clock.
fn validating_world(seed: Seed, share: u32) -> World {
    let dir = dedens_testkit::path("dnssec");
    let mut world = Topology::new()
        .upstream(Answers::new().directory(&dir))
        .epoch(UNIX_EPOCH + Duration::from_secs(dedens_testkit::dnssec::captured_at().into()))
        .resolver(move |upstreams| {
            let limits = ValidatorLimits {
                key_cache: 0,
                ..ValidatorLimits::default()
            };
            let validator = Validator::new(TrustAnchors::root(), limits);
            let shares = Budgets::new(Budget {
                per_second: SHARE_REFILL,
                burst: share,
                table: TABLE,
            })
            .expect("a share in bounds");
            let validating = Validating::new(validator, wall_clock()).sharing(shares);
            pipeline_validating(upstreams, validating)
        })
        .build(seed);
    world.fault(
        Duration::ZERO,
        Fault::Latency {
            a: Node::Resolver,
            b: Node::Upstream(0),
            min: Duration::ZERO,
            max: Duration::ZERO,
        },
    );
    world
}

/// How a cold validation ended for its client.
#[derive(Debug, Clone, Copy, PartialEq)]
enum Validated {
    /// NOERROR with the data and AD.
    Yes,
    /// SERVFAIL with EDE 14: shed by the share, not failed.
    Shed,
}

/// Adds a client at `ip` that waits `after`, asks each of `names` for A over `carrier` and notes what came of it in
/// the report it returns.
fn ask_cold(
    world: &mut World,
    ip: IpAddr,
    (carrier, after): (Carrier, Duration),
    names: &'static [&'static str],
) -> Report {
    world.fault(
        Duration::ZERO,
        Fault::Latency {
            a: Node::Host(ip),
            b: Node::Resolver,
            min: Duration::ZERO,
            max: Duration::ZERO,
        },
    );
    let report = Report::default();
    let notes = Rc::clone(&report);
    world.client_at(ip, async move |mut stub| {
        stub.rules.dnssec = true;
        stub.rules.authentic = true;
        tokio::time::sleep(after).await;
        for name in names {
            let outcome = stub.ask(question(name, RecordType::A), carrier).await?;
            let Outcome::Answered(answer) = outcome else {
                return Err(format!("{name} got no answer: {outcome:?}").into());
            };
            let message = &answer.message;
            notes.borrow_mut().push(
                if message.rcode() == Rcode::NOERROR && message.header.flags.contains(Flags::AD) {
                    Validated::Yes
                } else {
                    assert_eq!(message.rcode(), Rcode::SERVFAIL, "{message:?}");
                    assert_eq!(error(message), Some(InfoCode::NOT_READY), "{message:?}");
                    Validated::Shed
                },
            );
        }
        Ok(())
    });
    report
}

/// The share of units of one network in the scenarios, which two cold validations spend, and the units it refills a
/// second: the three seconds a later query waits repay it.
const SHARE: u32 = 30;
const SHARE_REFILL: u32 = 10;

/// D117: a network that asks for more cold validations than its share is shed with SERVFAIL and EDE 14, and so is
/// its neighbour in the /24, whose names stay uncached; a client of another network, and one of the same /24 over
/// TCP, which proves its address and has a share of its own, are still validated; once the share is repaid the
/// network is validated again.
#[test]
fn a_network_over_its_share_of_validation_is_shed_and_the_others_are_not() {
    seed::each(FEW, |seed| {
        let mut world = validating_world(seed, SHARE);
        let (udp, half) = (Carrier::Udp, SECOND / 2);
        let greedy = ask_cold(
            &mut world,
            host(NETS[0], 1),
            (udp, Duration::ZERO),
            &COLD[..3],
        );
        let neighbour = ask_cold(&mut world, host(NETS[0], 2), (udp, half), &COLD[3..4]);
        let proven = ask_cold(
            &mut world,
            host(NETS[0], 3),
            (Carrier::Tcp, half),
            &COLD[4..],
        );
        let other = ask_cold(
            &mut world,
            host(NETS[1], 1),
            (udp, half + half / 5),
            &COLD[3..4],
        );
        // The share refills a unit a second, and a shed query was never held.
        let later = ask_cold(&mut world, host(NETS[0], 4), (udp, 3 * SECOND), &COLD[2..3]);
        world.run().expect("the run passes its checks");
        let (yes, shed) = (Validated::Yes, Validated::Shed);
        assert_eq!(*greedy.borrow(), [yes, yes, shed]);
        assert_eq!(*neighbour.borrow(), [shed]);
        assert_eq!(*proven.borrow(), [yes]);
        assert_eq!(*other.borrow(), [yes]);
        assert_eq!(*later.borrow(), [yes]);
    });
}

/// The property of the shares: a network that asks the five cold names one after the other, over UDP or TCP, is
/// validated for the first and shed with EDE 14 for some of the others; each of the one to three other networks,
/// whose single client asks one cold name when the seed says, is validated, however the greedy one was shed. D117.
#[test]
fn whatever_the_seed_picks_a_network_is_shed_alone() {
    seed::each(THREE, |seed| {
        let mut rng = Rng::new(seed, SCENE);
        let mut pick = |bound: usize| {
            let bound = u64::try_from(bound).unwrap_or(u64::MAX);
            usize::try_from(rng.below(bound)).unwrap_or_default()
        };
        let carrier = if pick(2) == 0 {
            Carrier::Udp
        } else {
            Carrier::Tcp
        };
        let mut world = validating_world(seed, SHARE);
        let greedy = ask_cold(
            &mut world,
            host(NETS[0], 1),
            (carrier, Duration::ZERO),
            &COLD,
        );
        let others: Vec<_> = NETS[1..=1 + pick(3)]
            .iter()
            .map(|prefix| {
                let name = pick(COLD.len());
                let after = Duration::from_millis(100 * u64::try_from(pick(15)).unwrap_or(0));
                ask_cold(
                    &mut world,
                    host(*prefix, 1),
                    (Carrier::Udp, after),
                    &COLD[name..=name],
                )
            })
            .collect();
        world.run().expect("the run passes its checks");
        let greedy = greedy.borrow();
        // A name that costs little can still be admitted with what the share has left, so that no order is wanted.
        assert_eq!(greedy.first(), Some(&Validated::Yes), "{greedy:?}");
        assert!(greedy.contains(&Validated::Shed), "{greedy:?}");
        for other in others {
            assert_eq!(*other.borrow(), [Validated::Yes]);
        }
    });
}

/// The stream of the seed the property draws its scene from: no host's, which are 0 and up and `u64::MAX` and down.
const SCENE: u64 = 1 << 62;

/// What the property's run is made of: the resolver's limits, whether the stubs ask with cookies, and the networks,
/// each with whether the access list allows it.
struct Scene {
    limits: Limits,
    client_cookies: bool,
    subnets: Vec<(Subnet, bool)>,
}

/// What the resolver does with the queries of a network.
#[derive(Debug, Clone, Copy, PartialEq)]
enum Standing {
    Allowed,
    Refused,
    Dropped,
}

impl Scene {
    /// The scene of `seed`: two to four networks of one to six clients, over UDP or TCP, a bucket of one to four
    /// queries, a slip of 0 to 3, cookies on the resolver and on the clients or not, and an access list that denies
    /// some networks by REFUSED or by dropping, or none.
    fn picked(seed: Seed) -> Self {
        let mut rng = Rng::new(seed, SCENE);
        let mut pick = |bound: usize| {
            let bound = u64::try_from(bound).unwrap_or(u64::MAX);
            usize::try_from(rng.below(bound)).unwrap_or_default()
        };
        let networks = 2 + pick(3);
        let mut limits = Limits::open(
            u32::try_from(1 + pick(4)).unwrap_or(1),
            u8::try_from(pick(4)).unwrap_or(0),
        );
        if pick(2) == 0 {
            limits = limits.with_cookies();
        }
        let client_cookies = pick(2) == 0;
        let guarded = pick(2) == 0;
        let denial = if pick(2) == 0 {
            Denial::Refuse
        } else {
            Denial::Drop
        };
        let mut subnets = Vec::new();
        for prefix in NETS.into_iter().take(networks) {
            let clients = u8::try_from(1 + pick(6)).unwrap_or(1);
            let carrier = if pick(4) == 0 {
                Carrier::Tcp
            } else {
                Carrier::Udp
            };
            let allowed = !guarded || pick(3) != 0;
            subnets.push((
                Subnet {
                    prefix,
                    clients,
                    carrier,
                },
                allowed,
            ));
        }
        if guarded {
            let list: Vec<_> = subnets
                .iter()
                .filter(|(_, allowed)| *allowed)
                .map(|(subnet, _)| subnet.prefix)
                .collect();
            limits = limits.allowing(&list, denial);
        }
        Self {
            limits,
            client_cookies,
            subnets,
        }
    }

    fn run(&self, seed: Seed) -> Vec<Event> {
        let mut world = self.limits.world(seed);
        for (subnet, _) in &self.subnets {
            add(&mut world, *subnet, self.client_cookies);
        }
        world.run().expect("the run passes its checks")
    }

    fn standing(&self, allowed: bool) -> Standing {
        match (&self.limits.access, allowed) {
            (None, _) | (Some(_), true) => Standing::Allowed,
            (Some((_, Denial::Drop)), false) => Standing::Dropped,
            (Some(_), false) => Standing::Refused,
        }
    }

    /// What D91 and D113 make of the queries of `subnet`, each client asking once.
    fn expected(&self, subnet: Subnet, allowed: bool) -> Vec<Fate> {
        let clients = usize::from(subnet.clients);
        let standing = self.standing(allowed);
        let (burst, slip) = (self.limits.burst, self.limits.slip);
        match (subnet.carrier, standing) {
            (Carrier::Udp, Standing::Dropped) => times(clients, &Fate::lost()),
            (Carrier::Udp, Standing::Refused) => {
                bucket(clients, (burst, 0), (Rcode::REFUSED, None))
            }
            (Carrier::Udp, Standing::Allowed) => {
                // A slip is a fresh cookie when both sides have them, a truncation to ask again over TCP if not.
                let slipped = if self.limits.cookies && self.client_cookies {
                    Transport::Udp
                } else {
                    Transport::Tcp
                };
                bucket(clients, (burst, slip), (Rcode::NOERROR, Some(slipped)))
            }
            (Carrier::Tcp, Standing::Dropped) => times(
                clients,
                &Fate {
                    how: How::Errored,
                    sends: 1,
                    wave: 0,
                },
            ),
            (Carrier::Tcp, Standing::Refused) => times(
                clients,
                &Fate::answered(Rcode::REFUSED, Transport::Tcp, 1, 0),
            ),
            (Carrier::Tcp, Standing::Allowed) => times(
                clients,
                &Fate::answered(Rcode::NOERROR, Transport::Tcp, 1, 0),
            ),
            (Carrier::Tls, _) => unreachable!("the limits scenarios speak UDP and TCP"),
        }
    }
}

/// What a bucket of `burst` queries and a `slip` makes of the queries of `clients` clients that ask at once and
/// again five seconds on, up to the tries: it passes `burst` of the queries of each wave with `pass`, and of the rest
/// one in `slip` ends as `slipped` says, a query more over the transport, and the others are dropped. The count of
/// the slip goes on across the waves, and the bucket is whole again at each, a second of the rate being 5 s of
/// refill. D113.
fn bucket(
    clients: usize,
    (burst, slip): (u32, u8),
    (pass, slipped): (Rcode, Option<Transport>),
) -> Vec<Fate> {
    let (burst, slip) = (
        usize::try_from(burst).unwrap_or(usize::MAX),
        usize::from(slip),
    );
    let mut fates = Vec::new();
    let (mut pending, mut since) = (clients, 0);
    for wave in 0..u64::from(STUB_TRIES) {
        let tries = u16::try_from(wave + 1).unwrap_or(u16::MAX);
        let passed = pending.min(burst);
        fates.extend(times(
            passed,
            &Fate::answered(pass, Transport::Udp, tries, wave),
        ));
        let mut waiting = 0;
        for _ in passed..pending {
            since += 1;
            match slipped {
                Some(transport) if slip != 0 && since >= slip => {
                    since = 0;
                    fates.push(Fate::answered(Rcode::NOERROR, transport, tries + 1, wave));
                }
                _ => waiting += 1,
            }
        }
        pending = waiting;
    }
    fates.extend(times(pending, &Fate::lost()));
    fates
}

/// The property of the family: whatever the seed picks of the networks, their clients and the limits, each client
/// of a network that is allowed and within its bucket ends with its answer at once; each over it ends as D113 says,
/// slipped to TCP or to a fresh cookie, or answered after the refill, or without an answer when the tries run out;
/// each of a denied network as D91 says; and none of a network is held back by another's.
#[test]
fn whatever_the_seed_picks_each_network_ends_as_the_limits_say() {
    seed::each(THREE, |seed| {
        let scene = Scene::picked(seed);
        let events = scene.run(seed);
        for (subnet, allowed) in &scene.subnets {
            assert_same(
                &fates_of(&events, subnet.prefix),
                &scene.expected(*subnet, *allowed),
                &events,
            );
        }
        // A denied network reaches no upstream server: with none allowed the resolver asks nothing.
        if scene.subnets.iter().all(|(_, allowed)| !allowed) && scene.limits.access.is_some() {
            assert_eq!(forwarded(&events), 0, "{events:#?}");
        }
    });
}

/// One seed gives one trace in two processes (D133), with every limit at once: a rate and a slip, cookies, an access
/// list, and clients over UDP and TCP.
#[test]
fn a_limited_run_replays_in_two_processes() {
    let runs = std::cell::Cell::new(0);
    seed::in_two_processes(
        module_path!(),
        "a_limited_run_replays_in_two_processes",
        ONE,
        |seed| {
            runs.set(runs.get() + 1);
            let scene = Scene {
                limits: Limits::open(2, 2)
                    .with_cookies()
                    .allowing(&[NETS[0], NETS[1]], Denial::Refuse),
                client_cookies: true,
                subnets: vec![
                    (Subnet::udp(NETS[0], 5), true),
                    (Subnet::tcp(NETS[1], 2), true),
                    (Subnet::udp(NETS[2], 4), false),
                ],
            };
            trace::digest(&scene.run(seed))
        },
    );
    assert!(runs.get() > 0);
}
