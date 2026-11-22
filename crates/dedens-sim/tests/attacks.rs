//! The attacks on recursive resolvers that have a name, run against `dedensd` resolving from the root on the
//! simulated Internet of the captured resolutions (D189, D196), each from captured responses changed as the attack
//! changes them, each held under a number: the queries sent for one client question, the cache entries poisoned
//! (none), the time to the answer. The bounds are the decisions': D190 (the socket per query), D191 (the
//! resolution's limits), D192 (the scrubber), D193 (the ranks of the cache), D197 (the validation), D199 (the failure
//! hold), D117 (the budget of a client network); a bound found wrong goes back to its decision.
//!
//! The attacker is the off-path one of RFC 5452 §1 and the forged family (`forged.rs`), or the zone's own server:
//!
//! - Kaminsky, "Black Ops 2008: It's The End Of The Cache As We Know It": a flood of forged answers for random
//!   names in the zone, each with a random ID and case, glue for the zone's server in them. The attacker is given
//!   the port of the query, which RFC 5452 §4.2 has it guess, and still guesses ID (§9.2) and case
//!   (draft-vixie-dnsext-dns0x20).
//! - `NXNSAttack` (Afek, Bremler-Barr, Shister, USENIX Security 2020, CVE-2020-12662 and kin): a referral of a
//!   thousand server names without an address, in a zone that denies them.
//! - `TsuNAME` (Moura et al., IMC 2021, CVE-2021-3023 and kin): two zones whose servers are named in each other. The
//!   failure hold of RFC 9520 §3.2 (D199) stops the next resolution.
//! - CAMP and iDNS (Afek et al., "Amplification by chaining", 2023): a chain of CNAME records and one of
//!   referrals, each link a query, and a client network that spends its budget on them (D117).
//! - `KeyTrap` (CVE-2023-50387): signatures that fail, many. What a validation does is bounded by its budget (D75,
//!   D77, D197). The NSEC3 iterations (CVE-2023-50868) are not here: no capture is secure with more than 0
//!   iterations (`ws`'s 10 are an opt-out span, insecure by itself), so no run isolates the limit's verdict, and a
//!   changed record has no signature. `MaxIterations` is held by `crates/dedens-dnssec/tests/denial.rs` and
//!   `validator.rs` (`nsec3_iterations_above_the_limit_are_insecure`), on captured proofs (D74).
//! - `MaginotDNS` (Li et al., USENIX Security 2023): a referral's glue for servers named outside
//!   the zone of the answer.
//! - `TuDoor` (Li et al., IEEE S&P 2024): datagrams that are no message, with the query's ID, port and address.
//! - The ghost domain (Jiang et al., NDSS 2012): a delegation that the parent revoked, kept alive by the child's
//!   answers.
//!
//! RFC 9199 §3 is the operators' side of the same bounds: a resolver under stress retries and answers from its cache
//! (C4, C5), so the queries one question may cost are bounded (the numbers asserted) and a cached delegation lives as
//! long as the parent's and the child's TTLs say, never longer (C6, the ghost domain).
//!
//! The simulation cannot read a validation's cost, signature checks and hashes: the scenarios of the validator
//! judge by its verdict, and by the budget it is given (`crates/dedens-resolver/tests/validation.rs` counts).

use std::cell::{Cell, RefCell};
use std::collections::BTreeSet;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::rc::Rc;
use std::sync::Arc;
use std::time::Duration;

use dedens_cache::{Cache, Config};
use dedens_dnssec::crypto::Verifications;
use dedens_dnssec::{TrustAnchors, Validator};
use dedens_net::exchange::Options;
use dedens_proto::edns::{EdnsOption, InfoCode};
use dedens_proto::rdata::{Dnskey, RData, Soa};
use dedens_proto::{
    Class, Flags, Message, Name, Question, Rcode, Record, RecordType, Transport, Ttl,
};
use dedens_resolver::{Caches, DEFAULT_CAPACITY, InfraCache, Limits, Minimisation, RrsetCache};
use dedens_roots::RootHints;
use dedens_server::{Budget, Budgets, Pipeline, Recurse, Stage, Validating};
use dedens_sim::attacker::{Attacker, Injection, Reaction};
use dedens_sim::client::{Carrier, Client};
use dedens_sim::seed::{self, Rng, Seed};
use dedens_sim::stub::{Outcome, question};
use dedens_sim::topology::{Topology, World};
use dedens_sim::trace::{Event, What};
use dedens_sim::upstream::{Answers, Verdict};
use dedens_testkit::recursion::Resolution;
use dedens_testkit::{dns, message};

use crate::recursion::{TICK, Zones, steer, zones};
use crate::util::{SECOND, TABLE_KEY};

/// The seeds of `just check`: two of D133's five, the family's budget being two seconds (D164).
const SEEDS: &[u64] = &[1, 42];

/// The stream of the attacker's draws: no host of a run has it (the resolver's is 0, a client's its number).
const ATTACKER: u64 = 1 << 32;

/// The address no server holds, which a forgery carries.
const POISON: Ipv4Addr = Ipv4Addr::new(6, 6, 6, 6);

/// The least and the most a message takes: a round trip within the 50 ms the infra cache's timer starts from (D194),
/// where `recursion`'s 20 to 30 ms may exceed it and time a server out, which the scenarios asking one server
/// again and again cannot have.
const LAG: (Duration, Duration) = (Duration::from_millis(15), Duration::from_millis(20));

/// The second at which the cache is read after a run: the entries of a run are fresh then, their TTLs being the
/// minutes and the days of the captures.
const NOW: u32 = 1;

/// Forgeries per query of the Kaminsky flood: with the query's answer and the one of the ID, fewer than the 64
/// datagrams a simulated socket queues (turmoil's `udp_capacity`), so that none is lost before the exchange reads it.
const FLOOD: usize = 60;

/// The names a Kaminsky attacker draws, one a question.
const DRAWS: usize = 10;

/// The response a server of a zone makes to a question: `zone` is the zone the server was captured answering for.
type Derive = dyn Fn(&Name<'static>, &Question<'static>) -> Option<Message<'static>>;

/// The attacker on the servers of a zone, if there is one.
type Aim = dyn Fn(&Name<'static>) -> Option<Attacker>;

/// What a scenario changes of the Internet of its captures, and of the resolver.
struct Plot {
    captures: Vec<Resolution>,
    /// What the servers answer beside the captures: the capture changed as the attack changes it.
    derive: Option<Rc<Derive>>,
    aim: Option<Rc<Aim>>,
    limits: Limits,
    /// The share of a client network (D117), if the resolver has one.
    share: Option<Budget>,
    /// The clock and the limits of the validator, if the resolver validates (D197).
    validate: Option<(u64, dedens_dnssec::Limits)>,
    /// Whether a cache stage answers before the recurse stage: its failure hold (D199) is the same rule.
    cached: bool,
    /// How long the run lasts, if more than the simulation's default.
    duration: Option<Duration>,
    /// The settings of the resolver's caches.
    config: Config,
}

impl Plot {
    fn new(captures: Vec<Resolution>) -> Self {
        Self {
            captures,
            derive: None,
            aim: None,
            limits: Limits::default(),
            share: None,
            validate: None,
            cached: false,
            duration: None,
            config: Config::default(),
        }
    }

    fn deriving(
        mut self,
        derive: impl Fn(&Name<'static>, &Question<'static>) -> Option<Message<'static>> + 'static,
    ) -> Self {
        self.derive = Some(Rc::new(derive));
        self
    }

    fn attacked(mut self, aim: impl Fn(&Name<'static>) -> Option<Attacker> + 'static) -> Self {
        self.aim = Some(Rc::new(aim));
        self
    }
}

/// The questions the servers heard, in order, with the server and the time.
type Heard = Rc<RefCell<Vec<(IpAddr, Question<'static>, Duration)>>>;

/// The caches of the resolver of the run, as it started last.
type Held = Rc<RefCell<Option<Arc<Caches>>>>;

/// A world of the plot, with what its servers heard and the caches of its resolver.
struct Lab {
    world: World,
    heard: Heard,
    caches: Held,
}

/// The questions heard that a client pays for: the priming (`. NS`) is paid by none (D195).
fn paid(heard: &Heard) -> Vec<(IpAddr, Question<'static>, Duration)> {
    (heard.borrow().iter())
        .filter(|(_, question, _)| !(question.name.is_root() && question.qtype == RecordType::NS))
        .cloned()
        .collect()
}

fn pipeline(plot: &Plot, zones: &Zones, held: &Held) -> Pipeline {
    let config = Config {
        shards: 1,
        ..plot.config.clone()
    };
    let caches = Caches {
        rrsets: RrsetCache::new(DEFAULT_CAPACITY, config.clone()).expect("a valid config"),
        infra: InfraCache::new(InfraCache::DEFAULT_CAPACITY, 1).expect("a valid size"),
        roots: RootHints::bundled().clone(),
        tlds: None,
    };
    steer(&caches, zones, &plot.captures);
    let caches = Arc::new(caches);
    *held.borrow_mut() = Some(Arc::clone(&caches));
    let mut recurse = Recurse::new(caches)
        .with_minimisation(Minimisation::Off)
        .with_limits(plot.limits);
    if let Some(share) = plot.share {
        recurse = recurse.with_share(Budgets::with_key(share, &TABLE_KEY).expect("a valid share"));
    }
    if let Some((at, limits)) = &plot.validate {
        let at = *at;
        let validator = Validator::new(TrustAnchors::root(), limits.clone());
        recurse = recurse.validating(Validating::new(validator, Arc::new(move || at)));
    }
    let mut stages = Vec::new();
    if plot.cached {
        stages.push(Stage::Cache(Arc::new(
            Cache::new(config).expect("valid settings"),
        )));
    }
    stages.push(Stage::Recurse(recurse));
    Pipeline::new(stages)
}

/// The world of `plot`: each captured server at its address, answering what its zone was asked and what the plot
/// derives, `dedensd` resolving from the root.
fn lab(seed: Seed, plot: Plot) -> Lab {
    let zones = zones(&plot.captures);
    let heard: Heard = Rc::default();
    let held: Held = Rc::default();
    let mut topology = Topology::new();
    if let Some(duration) = plot.duration {
        topology = topology.duration(duration);
    }
    for capture in &plot.captures {
        topology = topology.resolution(capture);
    }
    let servers: BTreeSet<IpAddr> = (zones.iter())
        .flat_map(|(_, servers)| servers.iter().copied())
        .collect();
    for server in servers {
        let (zone, _) = (zones.iter())
            .find(|(_, at)| at.contains(&server))
            .expect("a zone");
        let held_here = (plot.captures.iter())
            .flat_map(|capture| &capture.exchanges)
            .filter(|exchange| {
                zones
                    .iter()
                    .any(|(zone, at)| *zone == exchange.zone && at.contains(&server))
            });
        let mut answers = Answers::default().exchanges(held_here);
        if let Some(derive) = &plot.derive {
            let (derive, zone) = (Rc::clone(derive), zone.clone());
            answers = answers
                .derived(move |question| derive(&zone, question).map(|message| encode(&message)));
        }
        if let Some(attacker) = plot.aim.as_ref().and_then(|aim| aim(zone)) {
            answers = answers.attacked_by(attacker);
        }
        let heard = Rc::clone(&heard);
        answers = answers.faulty(move |question, _: &mut Rng| {
            let at = turmoil::sim_elapsed().unwrap_or_default();
            heard.borrow_mut().push((server, question.clone(), at));
            Verdict::Answer
        });
        topology = topology.authoritative_at(server, answers);
    }
    let plot = Rc::new(plot);
    let (shared, kept) = (Rc::clone(&plot), Rc::clone(&held));
    let world = topology
        .resolver(move |_| pipeline(&shared, &zones, &kept))
        .dedensd()
        .latency(LAG.0, LAG.1)
        .tick(TICK)
        .build(seed);
    Lab {
        world,
        heard,
        caches: held,
    }
}

fn encode(message: &Message<'_>) -> Vec<u8> {
    let mut out = vec![0; 65_535];
    let len = message.encode(&mut out).expect("a message that encodes");
    out.truncate(len);
    out
}

fn decode(wire: &[u8]) -> Message<'static> {
    Message::decode(wire)
        .expect("a message")
        .message
        .into_owned()
}

/// The response of the capture's server of `zone` to the capture's own question.
fn captured(capture: &Resolution, zone: &Name<'_>) -> Message<'static> {
    answer_of(capture, zone, &capture.name, capture.rtype)
}

/// The response of the capture's server of `zone` to `name` and `rtype`.
fn answer_of(
    capture: &Resolution,
    zone: &Name<'_>,
    name: &Name<'_>,
    rtype: RecordType,
) -> Message<'static> {
    let exchange = (capture.exchanges.iter())
        .find(|exchange| {
            exchange.zone == *zone && exchange.name == *name && exchange.rtype == rtype
        })
        .expect("an exchange of the zone");
    message(&exchange.response)
}

/// `message` with every record living `secs`.
fn living(mut message: Message<'static>, secs: u32) -> Message<'static> {
    let ttl = Ttl::new(secs).expect("a TTL");
    let records = (message.answer.iter_mut())
        .chain(&mut message.authority)
        .chain(&mut message.additional);
    for record in records {
        record.ttl = ttl;
    }
    message
}

/// The server of the zone of the captures that the attacks aim at: Google's.
const LEAF: Ipv4Addr = Ipv4Addr::new(216, 239, 32, 10);

/// `response`, answering `question`.
fn to(mut response: Message<'static>, question: &Question<'static>) -> Message<'static> {
    response.questions = vec![question.clone()];
    response
}

/// A referral of `owner` to the server `server`, with no glue, on the model of `template`, a captured one.
fn referral(
    template: Message<'static>,
    question: &Question<'static>,
    owner: &Name<'static>,
    servers: &[Name<'static>],
) -> Message<'static> {
    let ns = (template.authority.iter())
        .find(|record| record.rtype() == RecordType::NS)
        .expect("an NS record")
        .clone();
    let mut response = to(template, question);
    response.authority = (servers.iter())
        .map(|server| Record::new(owner.clone(), ns.class, ns.ttl, &RData::Ns(server.clone())))
        .collect();
    response.additional.clear();
    response
}

/// The queries of a client of the resolver: `question` over UDP, the message and how long it took.
async fn ask(
    client: &Client,
    resolver: SocketAddr,
    question: &Question<'static>,
) -> turmoil::Result<(Message<'static>, Duration)> {
    let start = tokio::time::Instant::now();
    let response = client
        .exchange(
            Message::query(0, question.clone()),
            resolver,
            Carrier::Udp,
            &Options::default(),
        )
        .await?;
    Ok((decode(&response.wire), start.elapsed()))
}

/// Whether `name` is one a scenario's attacker draws: a label `prefix` and a number, in `zone`.
fn drawn(name: &Name<'_>, prefix: u8, zone: &Name<'_>) -> bool {
    name.is_within(zone)
        && name.label_count() == zone.label_count() + 1
        && name.labels().next().is_some_and(|label| {
            label
                .first()
                .is_some_and(|byte| byte.eq_ignore_ascii_case(&prefix))
        })
}

/// Whether the cache holds `POISON` for `owner` and `rtype`.
fn poisoned(caches: &Caches, owner: &Name<'_>, rtype: RecordType) -> bool {
    caches
        .rrsets
        .get(owner, rtype, Class::IN, NOW)
        .is_some_and(|held| {
            held.rrset
                .rdatas()
                .iter()
                .any(|rdata| matches!(rdata.data(), RData::A(address) if address == POISON))
        })
}

/// The extended error of `message`, if any.
fn ede(message: &Message<'_>) -> Option<InfoCode> {
    (message.edns.iter())
        .flat_map(|edns| &edns.options)
        .find_map(|option| match option {
            EdnsOption::Ede(ede) => Some(ede.code),
            _ => None,
        })
}

/// What a run left.
struct Ran {
    events: Vec<Event>,
    heard: Heard,
    caches: Arc<Caches>,
}

impl Lab {
    /// Runs the world to its end, failing the test if a client or the oracle does.
    fn run(self) -> Ran {
        let events = self.world.run().expect("the run passes its checks");
        let caches = self
            .caches
            .borrow()
            .clone()
            .expect("a resolver that started");
        Ran {
            events,
            heard: self.heard,
            caches,
        }
    }
}

/// How many datagrams the attackers sent in the run.
fn injected(events: &[Event]) -> usize {
    (events.iter())
        .filter(|event| matches!(event.what, What::Injected { .. }))
        .count()
}

/// The servers a capture asked for `zone`.
fn servers_of(capture: &Resolution, zone: &Name<'_>) -> BTreeSet<IpAddr> {
    (capture.exchanges.iter())
        .filter(|exchange| exchange.zone == *zone)
        .map(|exchange| exchange.server)
        .collect()
}

/// The name `name` with each letter in a case drawn from `rng`: what an attacker that reads no query guesses of
/// `0x20` (draft-vixie-dnsext-dns0x20).
fn guess_case(name: &Name<'_>, rng: &mut Rng) -> Name<'static> {
    let labels: Vec<Vec<u8>> = (name.labels())
        .map(|label| {
            (label.iter())
                .map(|byte| {
                    if rng.below(2) == 0 {
                        byte.to_ascii_lowercase()
                    } else {
                        byte.to_ascii_uppercase()
                    }
                })
                .collect()
        })
        .collect();
    Name::from_labels(labels.iter().map(Vec::as_slice)).expect("a name")
}

/// What a forgery of Kaminsky's gets right of the query, of what it must match (RFC 5452 §9.1, `0x20`).
#[derive(Clone, Copy, PartialEq, Eq)]
enum Guess {
    /// Neither: a random ID and a random case.
    Neither,
    /// The case, which `0x20` hides, not the ID: only the ID check drops it.
    Case,
    /// The ID, not the case: only the case check drops it, and the exchange asks again over TCP (D190).
    Id,
}

/// The forgery of Kaminsky's: `genuine`'s question, its ID and its case as `guess` says (what is not right is
/// guessed), the poison as its answer and as the glue of the zone's server.
fn kaminsky(genuine: &[u8], guess: Guess, rng: &mut Rng) -> Vec<u8> {
    let mut message = decode(genuine);
    let asked = message.questions.first().expect("a question").clone();
    let name = match guess {
        Guess::Neither => guess_case(&asked.name, rng),
        Guess::Case => asked.name.clone(),
        Guess::Id => flip_case(&asked.name),
    };
    if guess != Guess::Id {
        // Never the ID of the query: a wrong guess is the point.
        let right = message.header.id;
        message.header.id = std::iter::repeat_with(|| rng.next_u16())
            .find(|id| *id != right)
            .expect("an ID that is not the query's");
    }
    message.header.flags = (message.header.flags.with(Flags::AA)).without(Flags::TC);
    message.header.rcode = Rcode::NOERROR;
    message.questions = vec![Question::new(name.clone(), asked.qtype)];
    let ttl = Ttl::new(86_400).expect("a TTL");
    let server = dns("ns1.google.com.");
    message.answer = vec![Record::new(name, Class::IN, ttl, &RData::A(POISON))];
    let ns = RData::Ns(server.clone());
    message.authority = vec![Record::new(dns("google.com."), Class::IN, ttl, &ns)];
    message.additional = vec![Record::new(server, Class::IN, ttl, &RData::A(POISON))];
    encode(&message)
}

/// The name `name` with the case of its first letter flipped: not the case it was sent in.
fn flip_case(name: &Name<'_>) -> Name<'static> {
    let mut flipped = false;
    let labels: Vec<Vec<u8>> = (name.labels())
        .map(|label| {
            (label.iter())
                .map(|byte| {
                    if !flipped && byte.is_ascii_alphabetic() {
                        flipped = true;
                        byte ^ 0x20
                    } else {
                        *byte
                    }
                })
                .collect()
        })
        .collect();
    Name::from_labels(labels.iter().map(Vec::as_slice)).expect("a name")
}

/// Whether the attacker also guesses the ID of the query: it does for the odd names of the draws (`k1`, `k3`...).
fn lucky(query: &[u8]) -> bool {
    let asked = decode(query).questions.first().expect("a question").clone();
    asked
        .name
        .labels()
        .next()
        .and_then(|label| label.last())
        .is_some_and(|digit| (digit - b'0') % 2 == 1)
}

/// The attacker of Kaminsky's on the servers of a zone, which has silenced them: `FLOOD` forgeries a query, of a
/// random ID with the case of the query or not, and for the odd names one of the query's ID in another case, all
/// before the real answer, which it sends itself last. Each forgery reaches the exchange waiting for the answer, the
/// port of the query being given it (RFC 5452 §4.2 has it guess it: stronger than the attack).
fn flood(rng: Rc<RefCell<Rng>>) -> Attacker {
    Attacker::new(move |seen| {
        let Some(genuine) = seen.genuine else {
            return Reaction::beside(Vec::new());
        };
        let mut rng = rng.borrow_mut();
        let mut injections: Vec<Injection> = (0..FLOOD)
            .map(|i| Injection {
                after: Duration::ZERO,
                wire: kaminsky(
                    genuine,
                    if i % 2 == 0 {
                        Guess::Neither
                    } else {
                        Guess::Case
                    },
                    &mut rng,
                ),
            })
            .collect();
        if lucky(seen.query) {
            injections.push(Injection {
                after: Duration::ZERO,
                wire: kaminsky(genuine, Guess::Id, &mut rng),
            });
        }
        injections.push(Injection {
            after: TICK,
            wire: genuine.to_vec(),
        });
        Reaction::instead(injections)
    })
}

#[test]
fn rfc5452_9_2_a_kaminsky_flood_of_guessed_ids_and_cases_poisons_nothing() {
    seed::each(SEEDS, |seed| {
        let nx = Resolution::read("nxdomain-unsigned");
        let leaf = dns("google.com.");
        let leaf_servers = servers_of(&nx, &leaf);
        let rng = Rc::new(RefCell::new(Rng::new(seed, ATTACKER)));
        let plot = Plot::new(vec![Resolution::read("unsigned"), nx.clone()])
            .deriving({
                let leaf = leaf.clone();
                move |zone, question| {
                    drawn(&question.name, b'k', &leaf).then(|| to(captured(&nx, zone), question))
                }
            })
            .attacked({
                let leaf = leaf.clone();
                move |zone| (*zone == leaf).then(|| flood(Rc::clone(&rng)))
            });
        let mut lab = lab(seed, plot);
        let slowest = Rc::new(Cell::new(Duration::ZERO));
        let (resolver, slow) = (lab.world.resolver, Rc::clone(&slowest));
        lab.world.client_direct(async move |client| {
            for i in 0..DRAWS {
                let name = format!("k{i}.google.com");
                let (answer, elapsed) =
                    ask(&client, resolver, &question(&name, RecordType::A)).await?;
                assert_eq!(answer.rcode(), Rcode::NXDOMAIN, "{name}: {answer:?}");
                assert!(answer.answer.is_empty(), "{name}: {answer:?}");
                slow.set(slow.get().max(elapsed));
            }
            Ok(())
        });
        let Ran {
            events,
            heard,
            caches,
        } = lab.run();
        for i in 0..DRAWS {
            let name = dns(&format!("k{i}.google.com."));
            assert!(!poisoned(&caches, &name, RecordType::A), "{name}");
        }
        assert!(!poisoned(&caches, &dns("ns1.google.com."), RecordType::A));
        assert!(
            caches
                .rrsets
                .get(&leaf, RecordType::NS, Class::IN, NOW)
                .is_some()
        );
        // The walk from the root once, then a query a name to the zone's servers, which the attacker silences: they
        // are counted where the resolver sends them. The flood costs no query, but for the odd names, which have the
        // exchange ask again over TCP, the one defence left to a forgery with the ID (D190).
        let walk = (paid(&heard).iter())
            .filter(|(server, _, _)| !leaf_servers.contains(server))
            .count();
        assert_eq!(walk, 2, "the walk to the zone");
        let sent: Vec<(Transport, u16)> = (events.iter())
            .filter_map(|event| match &event.what {
                What::Sent {
                    server,
                    transport,
                    sends,
                    ..
                } if leaf_servers.contains(&server.ip()) => Some((*transport, *sends)),
                _ => None,
            })
            .collect();
        let udp = sent.iter().filter(|(t, _)| *t == Transport::Udp).count();
        let tcp = sent.iter().filter(|(t, _)| *t == Transport::Tcp).count();
        // Forgeries and the answer read by each exchange: what the flood did to the waiting exchanges.
        let arrived = (events.iter())
            .filter(|event| {
                matches!(&event.what, What::Arrived { from } if leaf_servers.contains(&from.ip()))
            })
            .count();
        println!(
            "kaminsky seed {}: {udp} UDP and {tcp} TCP queries for {DRAWS} questions, {} forgeries sent, {arrived} datagrams read, slowest {:?}",
            seed.0,
            injected(&events),
            slowest.get()
        );
        assert_eq!(udp, DRAWS, "one try each: the answer came in time");
        assert!(sent.iter().all(|(_, sends)| *sends <= 2), "{sent:?}");
        assert_eq!(tcp, DRAWS / 2, "the odd names, whose forgery had the ID");
        assert_eq!(injected(&events), DRAWS * (FLOOD + 1) + DRAWS / 2);
        // The forgeries reached the exchanges: every datagram sent was read, but for the answers of the odd names,
        // which the exchange no longer waited for over UDP.
        assert_eq!(arrived, injected(&events) - DRAWS / 2);
        assert!(
            slowest.get() < Duration::from_millis(500),
            "{:?}",
            slowest.get()
        );
    });
}

/// Servers named in the referral of the `NXNSAttack`: the attacker's zone, which has none of them.
const NAMES: usize = 1000;

#[test]
fn nxnsattack_a_referral_of_a_thousand_servers_without_address_costs_the_targets_limit() {
    // D191: an address lookup for each server of a delegation, up to `Limits::targets`; the scrubber keeps 20 names
    // of the thousand (D192), the resolution 13 servers, and the lookups' queries count in the question's.
    seed::each(SEEDS, |seed| {
        let (unsigned, nx) = (
            Resolution::read("unsigned"),
            Resolution::read("nxdomain-nsec3"),
        );
        let (com, nl, google) = (dns("com."), dns("nl."), dns("google.com."));
        let victim = dns("dedens-nxdomain.nl.");
        let servers: Vec<Name<'static>> = (0..NAMES)
            .map(|i| dns(&format!("ns{i}.dedens-nxdomain.nl.")))
            .collect();
        let denying = servers_of(&nx, &nl);
        let (template, denial) = (unsigned.clone(), nx.clone());
        let plot = Plot::new(vec![unsigned, nx]).deriving(move |zone, question| {
            if *zone == com && question.name.is_within(&google) {
                return Some(referral(
                    captured(&template, zone),
                    question,
                    &google,
                    &servers,
                ));
            }
            let above = zone.is_root() || *zone == nl;
            (above && question.name.is_within(&victim))
                .then(|| to(captured(&denial, zone), question))
        });
        let mut lab = lab(seed, plot);
        let slowest = Rc::new(Cell::new(Duration::ZERO));
        let (resolver, slow) = (lab.world.resolver, Rc::clone(&slowest));
        lab.world.client_direct(async move |client| {
            let (answer, elapsed) =
                ask(&client, resolver, &question("google.com", RecordType::A)).await?;
            assert_eq!(answer.rcode(), Rcode::SERVFAIL, "{answer:?}");
            slow.set(elapsed);
            Ok(())
        });
        let Ran { heard, .. } = lab.run();
        let paid = paid(&heard);
        let victim = dns("dedens-nxdomain.nl.");
        let lookups = (paid.iter())
            .filter(|(server, q, _)| denying.contains(server) && q.name.is_within(&victim))
            .count();
        println!(
            "nxns seed {}: {} queries ({lookups} for the names), {:?}",
            seed.0,
            paid.len(),
            slowest.get()
        );
        // The numbers of D191's defaults, written out: a limit changed must change them here too. 5 lookups
        // (`Limits::targets`, Unbound's `MAX_TARGET_NX`), the walk of 4 queries, none of the 32 of `queries`, and
        // the 4.5 s of `time` not reached.
        assert_eq!(lookups, 5, "lookups");
        assert_eq!(paid.len(), 9, "queries");
        assert!(
            slowest.get() <= Duration::from_millis(4500),
            "{:?}",
            slowest.get()
        );
    });
}

#[test]
fn rfc9520_3_tsuname_servers_named_in_each_others_zones_end_once_and_are_held() {
    // Moura et al. 2021: google.com's server is ns1.example.com, example.com's ns1.google.com, and no glue says
    // where either is. One resolution ends (D191: a lookup for a name whose zone waits on the stack ends at once);
    // the next of the question, within the hold of RFC 9520 §3.2, sends nothing (D199).
    seed::each(SEEDS, |seed| {
        let unsigned = Resolution::read("unsigned");
        let (com, google, example) = (dns("com."), dns("google.com."), dns("example.com."));
        let (template, ring) = (unsigned.clone(), unsigned.clone());
        let (to_example, to_google) = (vec![dns("ns1.example.com.")], vec![dns("ns1.google.com.")]);
        let plot = Plot::new(vec![unsigned]).deriving(move |zone, question| {
            let inside = |apex: &Name<'_>| question.name.is_within(apex);
            if *zone == com && inside(&google) {
                return Some(referral(
                    captured(&template, zone),
                    question,
                    &google,
                    &to_example,
                ));
            }
            if *zone == com && inside(&example) {
                return Some(referral(
                    captured(&template, zone),
                    question,
                    &example,
                    &to_google,
                ));
            }
            (zone.is_root() && inside(&com)).then(|| to(captured(&ring, zone), question))
        });
        let mut lab = lab(seed, plot);
        let (resolver, heard) = (lab.world.resolver, Rc::clone(&lab.heard));
        let counts = Rc::new(RefCell::new(Vec::new()));
        let seen = Rc::clone(&counts);
        lab.world.client_direct(async move |client| {
            let asked = question("google.com", RecordType::A);
            for pause in [Duration::ZERO, SECOND, 2 * SECOND, 8 * SECOND] {
                tokio::time::sleep(pause).await;
                let (answer, elapsed) = ask(&client, resolver, &asked).await?;
                assert_eq!(answer.rcode(), Rcode::SERVFAIL, "{answer:?}");
                assert_eq!(ede(&answer), Some(InfoCode::NO_REACHABLE_AUTHORITY));
                seen.borrow_mut().push((paid(&heard).len(), elapsed));
            }
            Ok(())
        });
        lab.run();
        let counts = counts.borrow();
        println!("tsuname seed {}: (queries so far, time) {counts:?}", seed.0);
        // The walk to the zone, the two zones' servers asked for once each, and the end of the loop: 5 queries.
        assert_eq!(counts[0].0, 5, "{counts:?}");
        // Held: no query, an answer within the clients' own round trip.
        assert_eq!(counts[1].0, counts[0].0, "{counts:?}");
        assert_eq!(counts[2].0, counts[0].0, "{counts:?}");
        assert!(counts[2].1 < Duration::from_millis(100), "{counts:?}");
        // The hold ends at 5 s (`failure_min`): asked again, the walk is the same, not longer.
        assert!(counts[3].0 > counts[0].0, "{counts:?}");
        assert!(counts[3].0 <= 2 * counts[0].0, "{counts:?}");
    });
}

/// The number in the label of a name the chain attacks draw: `c12` is 12.
fn numbered(name: &Name<'_>) -> Option<usize> {
    let label = name.labels().next()?;
    std::str::from_utf8(label.get(1..)?).ok()?.parse().ok()
}

/// The answer of `zone`'s server to a name of the CNAME chain, `c0`, `c1`, ...: a record to the next, with no end.
fn chained(
    unsigned: &Resolution,
    leaf: &Name<'static>,
) -> impl Fn(&Name<'static>, &Question<'static>) -> Option<Message<'static>> + 'static {
    let (unsigned, leaf) = (unsigned.clone(), leaf.clone());
    move |zone, question| {
        if *zone != leaf {
            // The servers above answer the walk to the zone for any name in it, as they did for the capture's.
            return question
                .name
                .is_within(&leaf)
                .then(|| to(captured(&unsigned, zone), question));
        }
        if !drawn(&question.name, b'c', &leaf) {
            return None;
        }
        let next = dns(&format!("c{}.google.com.", numbered(&question.name)? + 1));
        let mut response = to(captured(&unsigned, zone), question);
        response.authority.clear();
        response.additional.clear();
        let ttl = Ttl::new(300).expect("a TTL");
        let link = Record::new(question.name.clone(), Class::IN, ttl, &RData::Cname(next));
        response.answer = vec![link];
        Some(response)
    }
}

#[test]
fn camp_a_chain_of_cname_records_without_end_stops_at_the_restarts_limit() {
    // Each link is a query to the zone's server (D191: restarts 11); the walk to the zone is paid once. The attack
    // of CAMP: one client question, as many upstream queries as the chain is long.
    seed::each(SEEDS, |seed| {
        let unsigned = Resolution::read("unsigned");
        let leaf = dns("google.com.");
        let leaf_servers = servers_of(&unsigned, &leaf);
        let plot = Plot::new(vec![unsigned.clone()]).deriving(chained(&unsigned, &leaf));
        let mut lab = lab(seed, plot);
        let resolver = lab.world.resolver;
        let took = Rc::new(Cell::new(Duration::ZERO));
        let slot = Rc::clone(&took);
        lab.world.client_direct(async move |client| {
            let (answer, elapsed) =
                ask(&client, resolver, &question("c0.google.com", RecordType::A)).await?;
            assert_eq!(answer.rcode(), Rcode::SERVFAIL, "{answer:?}");
            slot.set(elapsed);
            Ok(())
        });
        let Ran { heard, .. } = lab.run();
        let paid = paid(&heard);
        let at_leaf = (paid.iter())
            .filter(|(server, _, _)| leaf_servers.contains(server))
            .count();
        println!(
            "camp cname seed {}: {} queries ({at_leaf} to the zone), {:?}",
            seed.0,
            paid.len(),
            took.get()
        );
        // The first name and 11 restarts (`Limits::restarts`, Unbound's `max-query-restarts` 11, plus its first
        // query) at the zone, 2 queries for the walk: 14 of the 32 of `queries`.
        assert_eq!(at_leaf, 12, "queries to the zone");
        assert_eq!(paid.len(), 14, "queries");
        assert!(
            took.get() <= Duration::from_millis(4500),
            "{:?}",
            took.get()
        );
    });
}

/// The labels of the name that the referral chain asks for, below the zone.
const DEPTH: usize = 60;

#[test]
fn idns_a_chain_of_referrals_each_one_label_deeper_stops_at_the_referrals_limit() {
    // iDNS: the zone's server refers the question to a zone one label closer to the name, whose server is itself,
    // and again, for as many labels as the name has. Each referral is a query (D191: referrals 30, queries 32).
    // A second leg lifts the referrals' limit so that the queries' alone stops the chain.
    let default = Limits::default();
    let lifted = Limits {
        referrals: 1000,
        ..default
    };
    for (limits, at_leaf_is, paid_is) in [(default, 29, 31), (lifted, 30, 32)] {
        seed::each(SEEDS, |seed| {
            let unsigned = Resolution::read("unsigned");
            let (com, leaf) = (dns("com."), dns("google.com."));
            let leaf_servers = servers_of(&unsigned, &leaf);
            let referrals = Cell::new(0);
            let template = unsigned.clone();
            let mut plot = Plot::new(vec![unsigned]).deriving({
                let leaf = leaf.clone();
                move |zone, question| {
                    let deep = leaf.label_count() + DEPTH;
                    if *zone != leaf {
                        return question
                            .name
                            .is_within(&leaf)
                            .then(|| to(captured(&template, zone), question));
                    }
                    if question.name.label_count() < deep {
                        return None;
                    }
                    referrals.set(referrals.get() + 1);
                    let labels: Vec<&[u8]> = question.name.labels().collect();
                    let below = (leaf.label_count() + referrals.get()).min(deep);
                    let owner = Name::from_labels(labels[labels.len() - below..].iter().copied())
                        .expect("a name");
                    let server =
                        Name::from_labels(std::iter::once(&b"ns"[..]).chain(owner.labels()))
                            .expect("a name");
                    let mut response = referral(
                        captured(&template, &com),
                        question,
                        &owner,
                        std::slice::from_ref(&server),
                    );
                    let ttl = response.authority[0].ttl;
                    response.additional =
                        vec![Record::new(server, Class::IN, ttl, &RData::A(LEAF))];
                    Some(response)
                }
            });
            plot.limits = limits;
            let mut lab = lab(seed, plot);
            let resolver = lab.world.resolver;
            let took = Rc::new(Cell::new(Duration::ZERO));
            let slot = Rc::clone(&took);
            lab.world.client_direct(async move |client| {
                let name = format!("{}google.com", "l.".repeat(DEPTH));
                let (answer, elapsed) =
                    ask(&client, resolver, &question(&name, RecordType::A)).await?;
                assert_eq!(answer.rcode(), Rcode::SERVFAIL, "{answer:?}");
                slot.set(elapsed);
                Ok(())
            });
            let Ran { heard, .. } = lab.run();
            let paid = paid(&heard);
            let at_leaf = (paid.iter())
                .filter(|(server, _, _)| leaf_servers.contains(server))
                .count();
            println!(
                "idns seed {}: {} queries ({at_leaf} to the zone), {:?}",
                seed.0,
                paid.len(),
                took.get()
            );
            // By default 29 queries to the zone at the 30 referrals of `Limits::referrals` (the first question is no
            // referral to follow), 2 for the walk: 31 of the 32 of `queries`, which the referrals' limit reaches first;
            // lifted, the 32 of `queries`: 30 to the zone.
            assert_eq!(at_leaf, at_leaf_is, "queries to the zone");
            assert_eq!(paid.len(), paid_is, "queries");
            assert!(
                took.get() <= Duration::from_millis(4500),
                "{:?}",
                took.get()
            );
        });
    }
}

/// What a network may spend a second, and at once, in the scenario of the budget (D117).
const SHARE: Budget = Budget {
    per_second: 1,
    burst: 40,
    table: 1 << 10,
};

/// A client of another /24 than the attacker of the budget scenario, asking after it has spent its burst: the time
/// its answer took.
fn other_network(lab: &mut Lab) -> Rc<Cell<Duration>> {
    let served = Rc::new(Cell::new(Duration::MAX));
    let slot = Rc::clone(&served);
    lab.world.client_at(
        IpAddr::V4(Ipv4Addr::new(203, 0, 113, 9)),
        async move |stub| {
            tokio::time::sleep(5 * SECOND).await;
            let answer = stub
                .expect(question("google.com", RecordType::A), Carrier::Udp)
                .await?;
            slot.set(answer.elapsed);
            Ok(())
        },
    );
    served
}

/// The lab of the budget scenario: chains of CNAME records under `leaf`, a budget of `SHARE` for each network.
fn lab_of_the_budget(seed: Seed, unsigned: &Resolution, leaf: &Name<'static>) -> Lab {
    let mut plot = Plot::new(vec![unsigned.clone()]).deriving(chained(unsigned, leaf));
    plot.share = Some(SHARE);
    lab(seed, plot)
}

#[test]
fn camp_a_network_over_its_budget_is_refused_and_the_others_are_served() {
    // D117: each query the resolver sends costs the asking network a unit. One network asks one chain after the
    // other: past its burst it is refused (SERVFAIL, EDE 14) and nothing is sent for it; another /24 is served.
    const ASKS: usize = 8;
    seed::each(SEEDS, |seed| {
        let unsigned = Resolution::read("unsigned");
        let leaf = dns("google.com.");
        let mut lab = lab_of_the_budget(seed, &unsigned, &leaf);
        let refused = Rc::new(Cell::new(0));
        let counted = Rc::clone(&refused);
        lab.world.client_at(
            IpAddr::V4(Ipv4Addr::new(198, 51, 100, 7)),
            async move |stub| {
                for k in 0..ASKS {
                    let asked = question(&format!("c{}.google.com", k * 100), RecordType::A);
                    let Outcome::Answered(answer) = stub.ask(asked, Carrier::Udp).await? else {
                        return Err("no answer".into());
                    };
                    assert_eq!(
                        answer.message.rcode(),
                        Rcode::SERVFAIL,
                        "{:?}",
                        answer.message
                    );
                    if ede(&answer.message) == Some(InfoCode::NOT_READY) {
                        counted.set(counted.get() + 1);
                    }
                }
                Ok(())
            },
        );
        let served = other_network(&mut lab);
        let Ran { heard, .. } = lab.run();
        // The same run without the attacker: what the other network is served in.
        let mut alone = lab_of_the_budget(seed, &unsigned, &leaf);
        let unattacked = other_network(&mut alone);
        alone.run();
        let mine = |name: &Name<'_>| drawn(name, b'c', &leaf);
        let mine: Vec<_> = paid(&heard)
            .into_iter()
            .filter(|(_, q, _)| mine(&q.name))
            .collect();
        let last = mine.iter().map(|(_, _, at)| *at).max().unwrap_or_default();
        println!(
            "camp budget seed {}: {} queries for {ASKS} questions, {} refused, the other served in {:?} ({:?} alone)",
            seed.0,
            mine.len(),
            refused.get(),
            served.get(),
            unattacked.get()
        );
        let seconds = usize::try_from(last.as_secs()).expect("a few seconds");
        let allowed = usize::try_from(SHARE.burst).expect("a count")
            + seconds * usize::try_from(SHARE.per_second).expect("a count")
            + 1;
        assert!(
            mine.len() <= allowed,
            "{} queries, {allowed} allowed",
            mine.len()
        );
        // 41 queries are paid: the burst of 40 and the one the bucket's refill gives; a chain costs about 13, so 3 are
        // answered and the other 5 of the 8 questions are refused.
        assert_eq!(refused.get(), 5, "refused");
        // The attacker's refusals cost the other network nothing: it is served no slower than with no attacker (faster in fact,
        // the attacker's walks having warmed the cache).
        assert!(
            served.get() <= unattacked.get(),
            "{:?} served, {:?} alone",
            served.get(),
            unattacked.get()
        );
    });
}

/// The keys of the tag of a zone's key that the `KeyTrap` adds to its set.
const KEYS: usize = 60;

/// `message` with `KEYS` keys more for each key of its set, each of the same tag and none that verifies (swapping two
/// bytes two apart keeps the tag, RFC 4034 Appendix B).
fn colliding(mut message: Message<'static>) -> Message<'static> {
    let mut added = Vec::new();
    for record in &message.answer {
        let RData::Dnskey(key) = record.data() else {
            continue;
        };
        for at in 0..KEYS {
            let mut public = key.public_key().to_vec();
            public.swap(at, at + 2);
            let key = Dnskey::new(key.flags(), key.algorithm(), &public).expect("a key");
            let rdata = RData::Dnskey(key);
            added.push(Record::new(
                record.name.clone(),
                record.class,
                record.ttl,
                &rdata,
            ));
        }
    }
    message.answer.extend(added);
    message
}

/// What a client of a validating resolver got, and what the run held.
struct Validated {
    message: Message<'static>,
    paid: usize,
    events: Vec<Event>,
}

/// One run of `plot`, validating at `at` with `limits`, a client asking the capture's own question.
fn validated(seed: Seed, mut plot: Plot, (at, limits): (u64, dedens_dnssec::Limits)) -> Validated {
    let capture = plot.captures[0].clone();
    plot.validate = Some((at, limits));
    let mut lab = lab(seed, plot);
    let slot = Rc::new(RefCell::new(None));
    let kept = Rc::clone(&slot);
    lab.world.client(async move |mut stub| {
        stub.rules.dnssec = true;
        stub.rules.authentic = true;
        let asked = Question::new(capture.name.clone(), capture.rtype);
        let Outcome::Answered(answer) = stub.ask(asked, Carrier::Udp).await? else {
            return Err("no answer".into());
        };
        *kept.borrow_mut() = Some(answer.message);
        Ok(())
    });
    let Ran { heard, events, .. } = lab.run();
    let message = slot.borrow_mut().take().expect("an answer");
    let paid = paid(&heard).len();
    Validated {
        message,
        paid,
        events,
    }
}

/// `plot` with the DNSKEY set of sidn.nl that `capture` holds made a `KeyTrap`'s by `colliding`.
fn keytrapped(plot: Plot, capture: &Resolution) -> Plot {
    let template = capture.clone();
    let (sidn, dnskeys) = (
        dns("sidn.nl."),
        Question::new(dns("sidn.nl."), RecordType::DNSKEY),
    );
    plot.deriving(move |zone, question| {
        let held =
            *zone == sidn && question.qtype == RecordType::DNSKEY && question.name == dnskeys.name;
        held.then(|| {
            to(
                colliding(answer_of(&template, zone, &question.name, question.qtype)),
                question,
            )
        })
    })
}

#[test]
fn keytrap_sixty_keys_of_one_tag_are_checked_within_the_validation_budget() {
    // CVE-2023-50387: the DNSKEY set of sidn.nl holds `KEYS` keys more for each key, of its tag, none that verifies.
    // The validator refuses the set at its digest check (D77) before any signature check: the verdict is bogus, and
    // costs no budget (D75, D197); the keys are asked once and the answer is SERVFAIL.
    seed::each(SEEDS, |seed| {
        let capture = Resolution::read("signed-nl");
        let at = capture.captured_at;
        let dnskeys = Question::new(dns("sidn.nl."), RecordType::DNSKEY);
        let limits = dedens_dnssec::Limits::default();
        let clean = validated(seed, Plot::new(vec![capture.clone()]), (at, limits.clone()));
        assert_eq!(clean.message.rcode(), Rcode::NOERROR, "{:?}", clean.message);
        assert!(
            clean.message.header.flags.contains(Flags::AD),
            "{:?}",
            clean.message
        );
        {
            let run = validated(
                seed,
                keytrapped(Plot::new(vec![capture.clone()]), &capture),
                (at, limits),
            );
            // Over UDP the set is cut (TC) and asked again over TCP: one query, two transports.
            let keys = (run.events.iter())
                .filter(|event| {
                    matches!(&event.what, What::Served { question, transport: Transport::Udp } if *question == dnskeys)
                })
                .count();
            assert_eq!(run.message.rcode(), Rcode::SERVFAIL, "{:?}", run.message);
            assert_eq!(
                ede(&run.message),
                Some(InfoCode::DNSSEC_BOGUS),
                "{:?}",
                run.message
            );
            assert_eq!(keys, 1, "the keys are asked once");
            assert!(
                run.paid <= clean.paid + 1,
                "{} queries, {} clean",
                run.paid,
                clean.paid
            );
            println!(
                "keytrap seed {}: {} queries, {keys} for the keys, clean {}",
                seed.0, run.paid, clean.paid
            );
        }
    });
}

#[test]
fn keytrap_a_budget_too_small_for_the_walk_is_indeterminate_not_bogus() {
    // The chain of trust to the keys of sidn.nl costs 4 signature checks and the answer's 2 more (the clean run is
    // secure at 6, indeterminate at 5: the budget says nothing of the data, D75). The trapped keys cost none: at the
    // walk's 4 the verdict is bogus, for the digest check of D77 refuses the set before any signature is checked,
    // and at 3 it is the walk that the budget stops. The queries stay within the clean run's plus one.
    seed::each(SEEDS, |seed| {
        let capture = Resolution::read("signed-nl");
        let at = capture.captured_at;
        let walk = |checks| dedens_dnssec::Limits {
            budget: dedens_dnssec::crypto::Budget::new(
                Verifications(checks),
                dedens_dnssec::crypto::Budget::DEFAULT_NSEC3_BLOCKS,
            ),
            ..dedens_dnssec::Limits::default()
        };
        let fresh = |checks| validated(seed, Plot::new(vec![capture.clone()]), (at, walk(checks)));
        let trap = |checks| {
            let plot = keytrapped(Plot::new(vec![capture.clone()]), &capture);
            validated(seed, plot, (at, walk(checks)))
        };
        let clean = fresh(64);
        let (secure, starved) = (fresh(6), fresh(5));
        assert_eq!(
            secure.message.rcode(),
            Rcode::NOERROR,
            "{:?}",
            secure.message
        );
        assert!(
            secure.message.header.flags.contains(Flags::AD),
            "{:?}",
            secure.message
        );
        assert_eq!(
            starved.message.rcode(),
            Rcode::SERVFAIL,
            "{:?}",
            starved.message
        );
        assert_eq!(ede(&starved.message), Some(InfoCode::DNSSEC_INDETERMINATE));
        let (bogus, indeterminate) = (trap(4), trap(3));
        assert_eq!(
            bogus.message.rcode(),
            Rcode::SERVFAIL,
            "{:?}",
            bogus.message
        );
        assert_eq!(ede(&bogus.message), Some(InfoCode::DNSSEC_BOGUS));
        assert_eq!(indeterminate.message.rcode(), Rcode::SERVFAIL);
        assert_eq!(
            ede(&indeterminate.message),
            Some(InfoCode::DNSSEC_INDETERMINATE)
        );
        for run in [&bogus, &indeterminate] {
            assert!(
                run.paid <= clean.paid + 1,
                "{} queries, {} clean",
                run.paid,
                clean.paid
            );
        }
        println!(
            "keytrap budget seed {}: trap with a budget of 4 {} queries bogus, of 3 {} queries indeterminate",
            seed.0, bogus.paid, indeterminate.paid
        );
    });
}

#[test]
fn maginotdns_glue_of_a_name_outside_the_zone_is_not_cached() {
    // Li et al., USENIX Security 2023: the server of org. refers netmeister.org to its servers, names of gandi.net, and
    // adds to the referral an address of each: the poison. The owner of the glue is outside the zone of the answer
    // (D192): the scrubber drops it, the servers' names are resolved from their own zone, and the cache keeps nothing
    // of the attacker's. Of the injections of the paper this one only the zone's bound stops: a chain of CNAME records
    // is cut at the zone's edge, a delegation of `org.` itself in an answer is not a referral, and an address that
    // answers nothing is not glue.
    seed::each(SEEDS, |seed| {
        let capture = Resolution::read("dname");
        let (zone, org, child) = (capture.name.clone(), dns("org."), dns("netmeister.org."));
        let child_servers = servers_of(&capture, &child);
        let referral = answer_of(&capture, &org, &zone, RecordType::A);
        let targets: Vec<Name<'static>> = (referral.authority.iter())
            .filter_map(|record| match record.data() {
                RData::Ns(server) => Some(server.into_owned()),
                _ => None,
            })
            .collect();
        assert!(
            !targets.is_empty() && targets.iter().all(|server| !server.is_within(&org)),
            "{targets:?}"
        );
        let plot =
            Plot::new(vec![capture]).deriving({
                let targets = targets.clone();
                move |at, question| {
                    if *at != org || question.name != zone || question.qtype != RecordType::A {
                        return None;
                    }
                    let mut response = to(referral.clone(), question);
                    let ttl = Ttl::new(86_400).expect("a TTL");
                    response.additional.extend(targets.iter().map(|server| {
                        Record::new(server.clone(), Class::IN, ttl, &RData::A(POISON))
                    }));
                    Some(response)
                }
            });
        let mut lab = lab(seed, plot);
        lab.world.client(async move |stub| {
            stub.expect(
                question("www.dname.dns.netmeister.org", RecordType::A),
                Carrier::Udp,
            )
            .await?;
            Ok(())
        });
        let Ran { heard, caches, .. } = lab.run();
        let at_child = (paid(&heard).iter())
            .filter(|(server, _, _)| child_servers.contains(server))
            .count();
        println!(
            "maginot seed {}: {at_child} queries to netmeister.org's servers",
            seed.0
        );
        assert!(at_child >= 1, "the answer came from the poison");
        for server in &targets {
            assert!(!poisoned(&caches, server, RecordType::A), "{server}");
        }
    });
}

/// The datagrams that are no message but have the ID and the question of `genuine`: it cut short at 30 places, counts
/// that lie, a name that points at itself, bytes with nothing in them. No more than the 64 a simulated socket queues.
fn malformed(genuine: &[u8]) -> Vec<Vec<u8>> {
    let mut datagrams: Vec<Vec<u8>> = (0..genuine.len())
        .step_by((genuine.len() / 30).max(1))
        .map(|n| genuine[..n].to_vec())
        .collect();
    for count in [4, 6, 8, 10] {
        let mut lying = genuine.to_vec();
        lying[count..count + 2].copy_from_slice(&[0xff, 0xff]);
        datagrams.push(lying);
    }
    let mut looping = genuine.to_vec();
    looping[12..14].copy_from_slice(&[0xc0, 12]);
    datagrams.push(looping);
    let mut empty = genuine[..2].to_vec();
    empty.extend([0xff; 30]);
    datagrams.push(empty);
    let mut long = genuine.to_vec();
    long.extend([0xde, 0xad, 0xbe, 0xef]);
    datagrams.push(long);
    datagrams
}

#[test]
fn tudoor_datagrams_that_are_no_message_on_the_query_port_with_its_id_do_not_end_the_exchange() {
    // Li et al., IEEE S&P 2024: a datagram from the server's address to the query's port, with the query's ID and
    // question, that does not parse. The attacker silences the server and sends its answer after them, so that the
    // exchange reads each. It goes on waiting (D190, D111: a datagram that is no answer to the query is no answer),
    // the real response is accepted and no query is asked again.
    seed::each(SEEDS, |seed| {
        let unsigned = Resolution::read("unsigned");
        let plot = Plot::new(vec![unsigned]).attacked(|_| {
            Some(Attacker::new(|seen| {
                let Some(genuine) = seen.genuine else {
                    return Reaction::beside(Vec::new());
                };
                let mut injections: Vec<Injection> = (malformed(genuine).into_iter())
                    .map(|wire| Injection {
                        after: Duration::ZERO,
                        wire,
                    })
                    .collect();
                injections.push(Injection {
                    after: TICK,
                    wire: genuine.to_vec(),
                });
                Reaction::instead(injections)
            }))
        });
        let mut lab = lab(seed, plot);
        let took = Rc::new(Cell::new(Duration::ZERO));
        let slot = Rc::clone(&took);
        lab.world.client(async move |stub| {
            let answer = stub
                .expect(question("google.com", RecordType::A), Carrier::Udp)
                .await?;
            slot.set(answer.elapsed);
            Ok(())
        });
        let Ran { events, .. } = lab.run();
        // The queries are counted where they are sent, the servers being silenced: the client's, the priming's and
        // the walk's to the root, .com's and google.com's, once each, over UDP, the answer within the 800 ms of a retry.
        let sent: Vec<(Transport, u16)> = (events.iter())
            .filter_map(|event| match &event.what {
                What::Sent {
                    transport, sends, ..
                } => Some((*transport, *sends)),
                _ => None,
            })
            .collect();
        let arrived = (events.iter())
            .filter(|event| matches!(event.what, What::Arrived { .. }))
            .count();
        println!(
            "tudoor seed {}: {} queries, {} datagrams sent, {arrived} read, {:?}",
            seed.0,
            sent.len(),
            injected(&events),
            took.get()
        );
        assert_eq!(sent, vec![(Transport::Udp, 1); 5]);
        // The exchanges read the unreadable datagrams, 30 and more each, then the answer: all but those of an
        // exchange the resolver gave up on before they came (the root's, asked twice at once) were read.
        assert!(arrived >= 3 * 30, "{arrived} datagrams read");
        assert!(arrived < injected(&events), "{arrived} datagrams read");
        assert!(took.get() < Duration::from_millis(500), "{:?}", took.get());
    });
}

/// The NS set and the glue a zone renews its delegation with for a day: those of `ghost`, or, for "ghost 2.0", one
/// server of another name, the parent never delegated to, at the zone's own address.
fn renewed(
    ghost: &Message<'static>,
    zone: &Name<'static>,
    new_names: bool,
) -> (Vec<Record<'static>>, Vec<Record<'static>>) {
    if !new_names {
        return (ghost.authority.clone(), ghost.additional.clone());
    }
    let server = dns("ns.renewed.google.com.");
    let day = Ttl::new(86_400).expect("a TTL");
    (
        vec![Record::new(
            zone.clone(),
            Class::IN,
            day,
            &RData::Ns(server.clone()),
        )],
        vec![Record::new(server, Class::IN, day, &RData::A(LEAF))],
    )
}

#[test]
fn ghost_domain_a_delegation_the_parent_revoked_is_gone_at_its_ns_ttl() {
    // Jiang et al., NDSS 2012: google.com's NS set at .com lives 20 s; at 15 s .com revokes the delegation
    // (NXDOMAIN). The zone's server answers each query with the NS set at 86 400 s and glue to match: asked for the
    // NS set at 12 s it would renew the delegation for a day (D193: a set replacing an unexpired one lives no longer
    // than it had left, glue pinned). Asked for the address at 25 s, the answer is the parent's, NXDOMAIN, and the
    // zone's servers were not asked after the 20 s. The second run is the renewal of "ghost 2.0": the NS set the zone
    // renews names a server the parent never delegated to (`ns.renewed`, at the zone's own address), which the cache
    // may use no longer than the delegation it replaced. The cache's floor on TTLs (60 s) is off, for the run to be
    // short.
    const NS_TTL: u32 = 20;
    seed::each(SEEDS, |seed| {
        let unsigned = Resolution::read("unsigned");
        for new_names in [false, true] {
            let (com, google) = (dns("com."), dns("google.com."));
            let google_servers = servers_of(&unsigned, &google);
            let revoked = Duration::from_secs(15);
            let parent = living(captured(&unsigned, &com), NS_TTL);
            let ghost = living(parent.clone(), 86_400);
            let (renewal, glue) = renewed(&ghost, &google, new_names);
            let leaf = captured(&unsigned, &google);
            let plot = {
                let (com, google) = (com.clone(), google.clone());
                let mut plot = Plot::new(vec![unsigned.clone()]).deriving(move |zone, question| {
                    if !question.name.is_within(&google) {
                        return None;
                    }
                    if *zone == com {
                        let mut response = to(parent.clone(), question);
                        if turmoil::sim_elapsed().unwrap_or_default() >= revoked {
                            response.header.rcode = Rcode::NXDOMAIN;
                            response.header.flags = response.header.flags.with(Flags::AA);
                            response.authority = vec![Record::new(
                                com.clone(),
                                Class::IN,
                                Ttl::new(5).expect("a TTL"),
                                &RData::Soa(Soa {
                                    mname: dns("a.gtld-servers.net."),
                                    rname: dns("nstld.verisign-grs.com."),
                                    serial: 1,
                                    refresh: 1800,
                                    retry: 900,
                                    expire: 604_800,
                                    minimum: 5,
                                }),
                            )];
                            response.additional.clear();
                        }
                        return Some(response);
                    }
                    if *zone == google {
                        let mut response = to(living(leaf.clone(), 2), question);
                        if question.qtype == RecordType::NS {
                            response.answer = renewal.clone();
                            response.authority.clear();
                        } else {
                            response.authority = renewal.clone();
                        }
                        response.additional = glue.clone();
                        return Some(response);
                    }
                    None
                });
                plot.duration = Some(Duration::from_secs(60));
                plot.config.min_ttl = 0;
                plot
            };
            let mut lab = lab(seed, plot);
            let resolver = lab.world.resolver;
            let rcodes = Rc::new(RefCell::new(Vec::new()));
            let slot = Rc::clone(&rcodes);
            lab.world.client_direct(async move |client| {
                for (pause, rtype) in [
                    (0, RecordType::A),
                    (12, RecordType::NS),
                    (13, RecordType::A),
                ] {
                    tokio::time::sleep(Duration::from_secs(pause)).await;
                    let (answer, _) =
                        ask(&client, resolver, &question("google.com", rtype)).await?;
                    slot.borrow_mut().push(answer.rcode());
                }
                Ok(())
            });
            let Ran { heard, .. } = lab.run();
            let late = (paid(&heard).iter())
                .filter(|(server, _, at)| {
                    google_servers.contains(server) && *at > Duration::from_secs(u64::from(NS_TTL))
                })
                .count();
            println!(
                "ghost seed {} (new names {new_names}): {:?}, {late} queries to the zone after its NS TTL",
                seed.0,
                rcodes.borrow()
            );
            assert_eq!(
                *rcodes.borrow(),
                [Rcode::NOERROR, Rcode::NOERROR, Rcode::NXDOMAIN]
            );
            assert_eq!(late, 0);
        }
    });
}
