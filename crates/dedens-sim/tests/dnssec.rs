//! Family 05, DNSSEC: the validating resolver (D77) of the run, over the captured signed zones of
//! `testdata/dnssec`, with the clock of the run set at the time of the capture (`captured_at`)
//! so that their signatures are valid, and a few runs set later.
//!
//! The upstream server answers each question the captures hold: the client's, and the DS, DNSKEY and denial
//! questions of the validator, which are upstream queries like any other (D77). What the sans-IO tests settle is
//! left to them: the verdict of each capture and its extended error (`crates/dedens-dnssec/tests/validator.rs`,
//! `crates/dedens-server/tests/dnssec.rs`, RFC 4035 §3.2.3, §5), and the accounts of the allowance and the shares
//! on a clock the test drives (`crates/dedens-server/tests/dnssec.rs` too). Here the questions and the answers go
//! over the simulated network, and what is checked is that the verdicts, the cache and the limits hold when those
//! packets are lost, late, or never come, and as the time of the run moves.
//!
//! No capture has AD set by its server, so that "AD is ours alone" (D114) shows as the verdicts that are not secure
//! having no AD, and as the oracle's rule that an answer carries AD exactly when the test says the zone is secure.
//! A forgery on the wire is the business of family 04; here the forged data are the captures that fail
//! validation: `bogus_signature`, `bogus_expired`, `bogus_no_key` and `bogus_sigexpired`.

use std::cell::{Cell, RefCell};
use std::collections::{BTreeSet, HashSet};
use std::num::NonZeroU8;
use std::path::PathBuf;
use std::rc::Rc;
use std::time::{Duration, UNIX_EPOCH};

use dedens_cache::Config;
use dedens_dnssec::{Limits, TrustAnchors, Validator};
use dedens_proto::edns::{EdnsOption, InfoCode};
use dedens_proto::{Flags, Message, Name, Question, Rcode, RecordType};
use dedens_server::{Allowance, Budget, Budgets, Forward, Validating};
use dedens_sim::client::Carrier;
use dedens_sim::fault::{Fault, Node};
use dedens_sim::resolver::{pipeline_forwarding, pipeline_validating, wall_clock};
use dedens_sim::seed::{self, Seed};
use dedens_sim::stub::{Answer, CheckError, Outcome, Stub, question};
use dedens_sim::topology::{Topology, World};
use dedens_sim::trace::{self, Event, What};
use dedens_sim::upstream::{Answers, Verdict};

use crate::util::{SEEDS, served};
/// For the scenarios that take a world for each case.
const FEW: &[u64] = &[0, 7];
/// For the scenarios whose point is not the seed.
const ONE: &[u64] = &[0];
/// For each shed scenario, the seed that failed it: its links take no time where the shed query starts, so the server
/// answers the query before at that instant, which `Run::served_for` counted for the shed query when it went by time.
/// One seed each: these runs are the family's longest, and with seed 0 and each other's seed the module took 3.2 s
/// of its 2 s (D164).
const ALLOWANCE_SHED: &[u64] = &[954_528_015_640_862_262];
const SHARE_SHED: &[u64] = &[721_027_006_700_900_320];

/// What a zone's answer is, with no fault: the verdict of the validator, which sets AD for the first only (D114).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Expect {
    /// A chain of trust to the root: AD.
    Secure,
    /// A proven absence of DS above it, or an algorithm the validator does not know: the answer, without AD.
    Insecure,
    /// SERVFAIL with this extended error (D77).
    Bogus(InfoCode),
}

/// A name the captures answer, and what the validator makes of it.
#[derive(Debug, Clone, Copy)]
struct Zone {
    name: &'static str,
    qtype: RecordType,
    expect: Expect,
}

const fn zone(name: &'static str, expect: Expect) -> Zone {
    Zone {
        name,
        qtype: RecordType::A,
        expect,
    }
}

/// The signed zones and their kinds of proof: one algorithm each, a denial by NSEC and by NSEC3, an unsigned zone
/// below a signed one, an algorithm the validator lacks, and the four captures that fail validation.
const ZONES: &[Zone] = &[
    zone("cloudflare.com", Expect::Secure),
    zone("nlnetlabs.nl", Expect::Secure),
    zone("fedoraproject.org", Expect::Secure),
    zone("ed25519.nl", Expect::Secure),
    zone("debian.org", Expect::Secure),
    zone("nonexistent.nlnetlabs.nl", Expect::Secure),
    zone("nonexistent.debian.org", Expect::Secure),
    zone("www.icann.org", Expect::Secure),
    zone("google.com", Expect::Insecure),
    zone("ed448.nl", Expect::Insecure),
    zone("www.ripe.net", Expect::Insecure),
    zone("dnssec-failed.org", Expect::Bogus(InfoCode::DNSKEY_MISSING)),
    zone("rhybar.cz", Expect::Bogus(InfoCode::DNSKEY_MISSING)),
    zone(
        "sigfail.verteiltesysteme.net",
        Expect::Bogus(InfoCode::DNSSEC_BOGUS),
    ),
    zone(
        "sigexpired.bad-dnssec.wb.sidnlabs.nl",
        Expect::Bogus(InfoCode::SIGNATURE_EXPIRED),
    ),
];

/// The zone of [`ZONES`] called `name`.
fn zone_of(name: &str) -> Zone {
    *ZONES
        .iter()
        .find(|zone| zone.name == name)
        .expect("a zone of the table")
}

/// The costliest capture: a DS for each of the 34 labels of a name below `ip6.arpa`, 41 questions to the server.
const COSTLY: &str = "b.8.6.0.0.0.1.c.0.0.0.0.0.0.0.0.2.2.0.0.8.e.2.0.c.7.6.0.1.0.0.2.ip6.arpa";

fn testdata() -> PathBuf {
    dedens_testkit::path("dnssec")
}

/// The Unix time the captures were taken at, when their signatures are valid.
fn captured_at() -> Duration {
    Duration::from_secs(dedens_testkit::dnssec::captured_at().into())
}

thread_local! {
    /// The captures, read once by thread: 186 files to decode.
    static CAPTURES: Answers = Answers::new().directory(&testdata());
}

fn captures() -> Answers {
    CAPTURES.with(Clone::clone)
}

/// The validator of a world: the root's keys, and the limits of the default.
fn validating() -> Validating {
    validating_with(Limits::default())
}

fn validating_with(limits: Limits) -> Validating {
    Validating::new(Validator::new(TrustAnchors::root(), limits), wall_clock())
}

/// A world answering from `answers`, its clock `after` the capture, for a run of `duration`, where `validating`
/// is the resolver's stage.
fn world(
    seed: Seed,
    answers: Answers,
    after: Duration,
    duration: Duration,
    validating: Validating,
) -> World {
    Topology::new()
        .upstream(answers)
        .epoch(UNIX_EPOCH + captured_at() + after)
        .duration(duration)
        .resolver(move |upstreams| pipeline_validating(upstreams, validating.clone()))
        .build(seed)
}

/// [`world_now`] where a bogus verdict is kept for `bogus_ttl` seconds in place of 60: a run of seconds, not of
/// minutes, as the simulation's cost is the time it simulates. The default is the sans-IO test's
/// (`dedens-server/tests/dnssec.rs`, `bogus_data_is_cached_for_sixty_seconds`).
fn world_keeping_bogus(seed: Seed, bogus_ttl: u32) -> World {
    let validating = validating();
    Topology::new()
        .upstream(captures())
        .epoch(UNIX_EPOCH + captured_at())
        .resolver(move |upstreams| {
            let forward = Forward::new(upstreams.iter().cloned())
                .expect("an upstream server to forward to")
                .validating(validating.clone());
            let config = Config {
                bogus_ttl,
                ..Config::default()
            };
            pipeline_forwarding(config, forward)
        })
        .build(seed)
}

/// A world at the time of the capture, for a run of two minutes.
fn world_now(seed: Seed, answers: Answers) -> World {
    world(
        seed,
        answers,
        Duration::ZERO,
        Duration::from_secs(120),
        validating(),
    )
}

/// The first extended error of a response, if it has one.
fn ede(message: &Message<'_>) -> Option<InfoCode> {
    message
        .edns
        .iter()
        .flat_map(|edns| &edns.options)
        .find_map(|option| match option {
            EdnsOption::Ede(ede) => Some(ede.code),
            _ => None,
        })
}

/// What a client saw of a verdict.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Seen {
    Secure,
    Insecure,
    Servfail(Option<InfoCode>),
}

fn seen(message: &Message<'_>) -> Seen {
    if message.rcode() == Rcode::SERVFAIL {
        Seen::Servfail(ede(message))
    } else if message.header.flags.contains(Flags::AD) {
        Seen::Secure
    } else {
        Seen::Insecure
    }
}

impl Expect {
    fn seen(self) -> Seen {
        match self {
            Self::Secure => Seen::Secure,
            Self::Insecure => Seen::Insecure,
            Self::Bogus(code) => Seen::Servfail(Some(code)),
        }
    }
}

/// A stub that waits for the longest validation of a lossy network, and asks with DO.
fn asks(stub: &mut Stub) {
    stub.options.timeout = Duration::from_secs(120);
    stub.options.tries = NonZeroU8::MIN;
    stub.rules.dnssec = true;
}

/// Asks `zone` over `carrier`, and expects AD for a secure zone only: the answer, or what else ended the query.
async fn ask(stub: &mut Stub, zone: &Zone, carrier: Carrier) -> Result<Answer, String> {
    stub.rules.authentic = zone.expect == Expect::Secure;
    answer(
        stub.ask(question(zone.name, zone.qtype), carrier).await,
        zone.name,
    )
}

fn answer(outcome: Result<Outcome, CheckError>, name: &str) -> Result<Answer, String> {
    match outcome {
        Ok(Outcome::Answered(answer)) => Ok(answer),
        Ok(other) => Err(format!("{name}: no response: {other:?}")),
        Err(error) => Err(format!("{name}: {error}")),
    }
}

/// The run's events, with what the scenarios ask of them.
struct Run(Vec<Event>);

impl Run {
    /// The distinct questions the upstream server answered.
    fn questions(&self) -> BTreeSet<String> {
        self.0
            .iter()
            .filter_map(|event| match &event.what {
                What::Served { question, .. } => Some(format!("{question:?}")),
                _ => None,
            })
            .collect()
    }

    /// Responses to questions of `qtype` the upstream server sent.
    fn served_of(&self, qtype: RecordType) -> usize {
        self.0
            .iter()
            .filter(|event| matches!(&event.what, What::Served { question, .. } if question.qtype == qtype))
            .count()
    }

    /// Where in the trace a client asked `name`, and where those queries ended: places, not times, as a link
    /// may take no time, and then a response the server sent for the query before shares its instant with the
    /// next query's start.
    fn exchanges(&self, name: &str) -> Vec<(usize, usize)> {
        let name: Name<'static> = name.parse().expect("a domain name");
        let events = || self.0.iter().enumerate();
        let starts = events().filter_map(|(place, event)| match &event.what {
            What::Asked { question, .. } if question.name == name => Some(place),
            _ => None,
        });
        let ends = events().filter_map(|(place, event)| match &event.what {
            What::Answered { question, .. }
            | What::Failed { question, .. }
            | What::Errored { question, .. }
                if question.name == name =>
            {
                Some(place)
            }
            _ => None,
        });
        let exchanges: Vec<_> = starts.zip(ends).collect();
        assert!(
            exchanges.iter().all(|(start, end)| start < end),
            "{exchanges:?}"
        );
        exchanges
    }

    /// Responses the upstream server sent, the client's questions included, while a client's `nth` query for
    /// `name` was open.
    fn served_for(&self, name: &str, nth: usize) -> usize {
        let (from, to) = self.exchanges(name)[nth];
        served(&self.0[from..to])
    }
}

// ---------------------------------------------------------------------------------------------------------------
// 1. The secure chain, and the cache.

/// Every zone of the table, half over UDP and half over TCP: AD on the secure ones and on those only (D114); the
/// insecure ones answer without it, and the bogus ones are SERVFAIL with the extended error the validator gave
/// them, no answer and no AD (D77). The oracle checks the records are the server's.
///
/// The verdicts of each capture are those of `crates/dedens-dnssec/tests/validator.rs`; the point here is that they
/// hold on the wire, with the questions of the chain answered by the simulated server.
#[test]
fn a_verdict_reaches_the_client_as_ad_for_a_secure_zone_and_for_it_alone() {
    seed::each(SEEDS, |seed| {
        let mut world = world_now(seed, captures());
        world.client(async move |mut stub| {
            asks(&mut stub);
            for (carrier, group) in [(Carrier::Udp, 0), (Carrier::Tcp, 1)] {
                for zone in ZONES.iter().skip(group).step_by(2) {
                    let got = ask(&mut stub, zone, carrier).await?;
                    assert_eq!(seen(&got.message), zone.expect.seen(), "{}", zone.name);
                    let ad = got.message.header.flags.contains(Flags::AD);
                    assert_eq!(ad, zone.expect == Expect::Secure, "{}", zone.name);
                    if let Expect::Bogus(_) = zone.expect {
                        assert!(got.message.answer.is_empty(), "{}", zone.name);
                    }
                }
            }
            Ok(())
        });
        world.run().expect("the run passes its checks");
    });
}

/// A secure answer is stored whole, with its AD: asked again it comes from the cache with no question to the
/// server, none of the chain either (D77); a client without DO then gets the records without AD for the cost of
/// its own question alone, the chain being in the key cache (D86).
#[test]
fn a_secure_answer_is_served_again_from_the_cache_without_asking_the_chain() {
    seed::each(SEEDS, |seed| {
        let mut world = world_now(seed, captures());
        world.client(async move |mut stub| {
            asks(&mut stub);
            let zone = zone_of("cloudflare.com");
            let first = ask(&mut stub, &zone, Carrier::Udp).await?;
            assert_eq!(seen(&first.message), Seen::Secure);
            tokio::time::sleep(Duration::from_secs(1)).await;
            let again = ask(&mut stub, &zone, Carrier::Udp).await?;
            assert_eq!(seen(&again.message), Seen::Secure);
            // The TTLs ran down by a second; the rest is the same.
            let rdata = |message: &Message<'_>| {
                message
                    .answer
                    .iter()
                    .map(|record| format!("{:?}", record.rdata))
                    .collect::<Vec<_>>()
            };
            assert_eq!(rdata(&again.message), rdata(&first.message));
            tokio::time::sleep(Duration::from_secs(1)).await;
            stub.rules.dnssec = false;
            stub.rules.authentic = false;
            let plain = stub
                .ask(question(zone.name, zone.qtype), Carrier::Udp)
                .await;
            assert_eq!(seen(&answer(plain, zone.name)?.message), Seen::Insecure);
            Ok(())
        });
        let run = Run(world.run().expect("the run passes its checks"));
        assert!(
            run.served_of(RecordType::DS) >= 1 && run.served_of(RecordType::DNSKEY) >= 1,
            "the first ask makes the validator ask DS and DNSKEY questions"
        );
        let first = run.served_for("cloudflare.com", 0);
        assert!(first >= 4, "the first ask costs the chain: {first}");
        assert_eq!(
            run.served_for("cloudflare.com", 1),
            0,
            "the second ask is a cache hit"
        );
        assert_eq!(
            run.served_for("cloudflare.com", 2),
            1,
            "a client without DO costs its own question"
        );
    });
}

// ---------------------------------------------------------------------------------------------------------------
// 2. Loss on the questions of the chain.

/// An upstream server that loses the responses `lose` says.
fn dropping(lose: impl Fn(&Question<'static>) -> bool + 'static) -> Answers {
    captures().faulty(move |question, _| {
        if lose(question) {
            Verdict::Drop
        } else {
            Verdict::Answer
        }
    })
}

/// An upstream server that loses the first response to each question of these types.
fn losing_first(types: &'static [RecordType]) -> Answers {
    let seen = Rc::new(RefCell::new(HashSet::new()));
    captures().faulty(move |question, _| {
        if types.contains(&question.qtype) && seen.borrow_mut().insert(format!("{question:?}")) {
            Verdict::Drop
        } else {
            Verdict::Answer
        }
    })
}
/// A world with a client for each of `names`, asking at once over UDP what the validator makes of them: a lost
/// response costs seconds of simulated time, which is what a run costs, and the clients wait together.
fn all_ask(seed: Seed, answers: Answers, names: &[&str], expect: fn(Zone) -> Seen) -> Run {
    let mut world = world_now(seed, answers);
    for name in names {
        let zone = zone_of(name);
        world.client(async move |mut stub| {
            asks(&mut stub);
            let got = ask(&mut stub, &zone, Carrier::Udp).await?;
            assert_eq!(seen(&got.message), expect(zone), "{}", zone.name);
            Ok(())
        });
    }
    Run(world.run().expect("the run passes its checks"))
}

/// The first response to each question of `types` lost: the resolver asks again after its timeout, and the
/// verdicts are those of the run with no loss, the questions answered the same (a lost response is not an answer:
/// it makes no insecure zone and no bogus one).
fn lost_first(types: &'static [RecordType]) {
    const NAMES: [&str; 3] = [
        "cloudflare.com",
        "google.com",
        "sigfail.verteiltesysteme.net",
    ];
    seed::each(ONE, |seed| {
        let clean = all_ask(seed, captures(), &NAMES, |zone| zone.expect.seen());
        let lossy = all_ask(seed, losing_first(types), &NAMES, |zone| zone.expect.seen());
        assert_eq!(
            lossy.questions(),
            clean.questions(),
            "{types:?}: the same questions, answered"
        );
        let waited = lossy.0.last().map_or(Duration::ZERO, |event| event.at);
        assert!(
            waited >= Duration::from_secs(3),
            "{types:?}: the resolver waited for the lost responses: {waited:?}"
        );
    });
}

#[test]
fn a_lost_ds_response_is_asked_again_and_the_verdict_stands() {
    lost_first(&[RecordType::DS]);
}

#[test]
fn a_lost_dnskey_response_is_asked_again_and_the_verdict_stands() {
    lost_first(&[RecordType::DNSKEY]);
}

#[test]
fn a_lost_ds_and_dnskey_response_is_asked_again_and_the_verdict_stands() {
    lost_first(&[RecordType::DS, RecordType::DNSKEY]);
}

/// What the server never answers.
#[derive(Debug, Clone, Copy)]
enum Silence {
    Ds,
    Dnskey,
    /// The DS of the zones asked, which proves a zone unsigned or links it to its parent.
    ZoneDs,
}

/// Questions of the chain the server never answers: SERVFAIL with an extended error, never the answer without AD
/// that an absent DS would make an insecure one (RFC 4035 §5.2, D77: unanswered is indeterminate, not insecure).
/// Of a signed zone, of an unsigned one (the DS that would prove it so is the response lost), of one the validator
/// cannot check, and of a denial.
#[test]
fn a_chain_question_nobody_answers_ends_in_servfail_with_an_ede_never_insecure() {
    const NAMES: [&str; 4] = [
        "cloudflare.com",
        "google.com",
        "ed448.nl",
        "nonexistent.nlnetlabs.nl",
    ];
    seed::each(ONE, |seed| {
        for silence in [Silence::Ds, Silence::Dnskey, Silence::ZoneDs] {
            let zones: Vec<Name<'static>> = NAMES
                .iter()
                .map(|name| name.parse().expect("a name"))
                .collect();
            let answers = dropping(move |question| match silence {
                Silence::Ds => question.qtype == RecordType::DS,
                Silence::Dnskey => question.qtype == RecordType::DNSKEY,
                Silence::ZoneDs => {
                    question.qtype == RecordType::DS && zones.contains(&question.name)
                }
            });
            // A SERVFAIL is judged as a bare one: no AD, no answer.
            all_ask(seed, answers, &NAMES, |_| {
                Seen::Servfail(Some(InfoCode::NO_REACHABLE_AUTHORITY))
            });
        }
    });
}

// ---------------------------------------------------------------------------------------------------------------
// 3. Forged or broken data.

/// The four captures that fail validation: SERVFAIL with the validator's extended error and an empty answer, as
/// the sans-IO tests have them (`dedens-server/tests/dnssec.rs`,
/// `a_bogus_answer_is_servfail_with_an_extended_error`), over either transport, and the records the client may not
/// have do not come in the authority or additional sections either (the oracle's bare SERVFAIL).
#[test]
fn a_bogus_answer_is_servfail_with_the_validators_ede_over_either_transport() {
    seed::each(SEEDS, |seed| {
        let mut world = world_now(seed, captures());
        world.client(async move |mut stub| {
            asks(&mut stub);
            for zone in ZONES
                .iter()
                .filter(|zone| matches!(zone.expect, Expect::Bogus(_)))
            {
                for carrier in [Carrier::Udp, Carrier::Tcp] {
                    let got = ask(&mut stub, zone, carrier).await?;
                    assert_eq!(seen(&got.message), zone.expect.seen(), "{}", zone.name);
                    assert!(got.message.answer.is_empty(), "{}", zone.name);
                }
            }
            Ok(())
        });
        world.run().expect("the run passes its checks");
    });
}

/// A bogus verdict is kept for `Config::bogus_ttl` (D77; 5 s here, 60 by default), and no longer: a client asking
/// again inside it gets the same SERVFAIL and extended error with no question to the server; past it the
/// validator asks again.
#[test]
fn a_bogus_verdict_is_kept_for_the_bogus_ttl_and_no_longer() {
    seed::each(FEW, |seed| {
        let mut world = world_keeping_bogus(seed, 5);
        world.client(async move |mut stub| {
            asks(&mut stub);
            let zone = zone_of("dnssec-failed.org");
            let mut codes = Vec::new();
            for wait in [0, 3, 4] {
                tokio::time::sleep(Duration::from_secs(wait)).await;
                codes.push(seen(&ask(&mut stub, &zone, Carrier::Udp).await?.message));
            }
            assert_eq!(codes, [zone.expect.seen(); 3]);
            Ok(())
        });
        let run = Run(world.run().expect("the run passes its checks"));
        assert!(
            run.served_for("dnssec-failed.org", 0) > 1,
            "the first ask validates"
        );
        assert_eq!(
            run.served_for("dnssec-failed.org", 1),
            0,
            "inside the TTL it is the cache's"
        );
        assert!(
            run.served_for("dnssec-failed.org", 2) > 1,
            "past the TTL it validates again"
        );
    });
}

/// A bogus verdict is never served stale (D77): with the server gone, after its TTL (5 s here), the client gets a
/// SERVFAIL with no records and not the Stale Answer of an expired copy; inside its TTL it still gets the verdict.
#[test]
fn a_bogus_verdict_is_never_served_stale() {
    seed::each(FEW, |seed| {
        let mut world = world_keeping_bogus(seed, 5);
        world.fault(
            Duration::from_secs(1),
            Fault::Partition(Node::Resolver, Node::Upstream(0)),
        );
        world.client(async move |mut stub| {
            asks(&mut stub);
            let zone = zone_of("sigfail.verteiltesysteme.net");
            let first = ask(&mut stub, &zone, Carrier::Udp).await?;
            assert_eq!(seen(&first.message), zone.expect.seen());
            tokio::time::sleep(Duration::from_secs(2)).await;
            let kept = ask(&mut stub, &zone, Carrier::Udp).await?;
            assert_eq!(
                seen(&kept.message),
                zone.expect.seen(),
                "inside the TTL, with the server gone"
            );
            tokio::time::sleep(Duration::from_secs(6)).await;
            let gone = ask(&mut stub, &zone, Carrier::Udp).await?;
            assert!(matches!(seen(&gone.message), Seen::Servfail(_)));
            assert!(gone.message.answer.is_empty() && !gone.stale);
            assert_ne!(ede(&gone.message), Some(InfoCode::STALE_ANSWER));
            Ok(())
        });
        let events = world.run().expect("the run passes its checks");
        assert!(
            !events
                .iter()
                .any(|event| matches!(event.what, What::Replied { stale: true, .. })),
            "no stale reply"
        );
    });
}

// ---------------------------------------------------------------------------------------------------------------
// 4. The start date.

/// The start of the run after the signatures expired, the captures unchanged: the zones turn bogus, signature
/// expired, and nothing else changes. A secure zone turns SERVFAIL, never insecure; as the date moves, a zone that
/// is SERVFAIL stays so, with the same extended error. The unsigned zone fails too, with the first signatures to
/// end, those of the root's keys.
#[test]
fn a_start_date_past_the_signatures_turns_the_captures_bogus_and_nothing_else_changes() {
    const DAYS: [u64; 6] = [0, 1, 7, 14, 30, 3650];
    let zones = [
        zone_of("cloudflare.com"),
        zone_of("nlnetlabs.nl"),
        zone_of("google.com"),
    ];
    seed::each(FEW, |seed| {
        let mut verdicts: Vec<Vec<Seen>> = Vec::new();
        for days in DAYS {
            let mut world = world(
                seed,
                captures(),
                Duration::from_secs(days * 86_400),
                Duration::from_secs(120),
                validating(),
            );
            let got = Rc::new(RefCell::new(Vec::new()));
            let into = Rc::clone(&got);
            world.client(async move |mut stub| {
                asks(&mut stub);
                for zone in zones {
                    // Whatever the verdict, the oracle checks the response is the server's or a bare SERVFAIL.
                    let got = ask(&mut stub, &zone, Carrier::Udp).await?;
                    into.borrow_mut().push(seen(&got.message));
                }
                Ok(())
            });
            world.run().expect("the run passes its checks");
            verdicts.push(got.take());
        }
        let expired = Seen::Servfail(Some(InfoCode::SIGNATURE_EXPIRED));
        let intact: Vec<Seen> = zones.iter().map(|zone| zone.expect.seen()).collect();
        assert_eq!(verdicts[0], intact, "at the capture time");
        assert_eq!(verdicts[DAYS.len() - 1], [expired; 3], "ten years after");
        for (day, now) in verdicts.iter().enumerate() {
            for (at, got) in now.iter().enumerate() {
                assert!(
                    *got == intact[at] || *got == expired,
                    "after {} days {}: {got:?}, neither its verdict nor expired",
                    DAYS[day],
                    zones[at].name
                );
                if day > 0 && verdicts[day - 1][at] == expired {
                    assert_eq!(*got, expired, "{} stays failed", zones[at].name);
                }
            }
        }
    });
}

// ---------------------------------------------------------------------------------------------------------------
// 5. The cost of a validation.

/// The zone that makes the validator ask the most, a 34-label name in `ip6.arpa` (a DS for each label), under the
/// limits of the default: it validates, within the 64 questions of a query (D75) and the 256 units of its allowance
/// (D106), and no question is asked twice over a transport.
#[test]
fn the_costliest_zone_is_validated_within_the_limits_of_a_query() {
    seed::each(ONE, |seed| {
        let mut world = world_now(seed, captures());
        world.client(async move |mut stub| {
            asks(&mut stub);
            stub.rules.authentic = true;
            let got = answer(
                stub.ask(question(COSTLY, RecordType::PTR), Carrier::Udp)
                    .await,
                COSTLY,
            )?;
            assert_eq!(seen(&got.message), Seen::Secure);
            Ok(())
        });
        let run = Run(world.run().expect("the run passes its checks"));
        let asked = run.served_for(COSTLY, 0);
        assert!(
            (30..=65).contains(&asked),
            "the validator asked {asked} questions"
        );
        let mut questions: Vec<String> = run
            .0
            .iter()
            .filter_map(|event| match &event.what {
                What::Served {
                    question,
                    transport,
                    ..
                } => Some(format!("{question:?} {transport:?}")),
                _ => None,
            })
            .collect();
        let all = questions.len();
        questions.sort();
        questions.dedup();
        assert_eq!(questions.len(), all, "no question asked twice");
    });
}

/// A query that would cost more than its allowance of a query, 256 units by default, ends without a verdict:
/// SERVFAIL with the extended error DNSSEC Indeterminate, the validator asking no more where the allowance ends
/// (D106). The allowance here is 20 units, which the costliest zone spends in its first questions. The end is no
/// verdict and is not stored (D77): the failure hold of RFC 9520 (D43) answers an ask right after it with a bare
/// SERVFAIL and no question to the server, and one past the hold is validated again, to the same end; another zone
/// is answered throughout.
#[test]
fn a_query_past_its_allowance_has_no_verdict_and_stops_asking() {
    const PER_QUERY: u32 = 20;
    seed::each(ONE, |seed| {
        let allowing = validating().allowing(Allowance {
            per_query: PER_QUERY,
            ..Allowance::default()
        });
        let mut world = world(
            seed,
            captures(),
            Duration::ZERO,
            Duration::from_secs(120),
            allowing,
        );
        world.client(async move |mut stub| {
            asks(&mut stub);
            let indeterminate = Seen::Servfail(Some(InfoCode::DNSSEC_INDETERMINATE));
            for (wait, expected) in [
                (0, Some(indeterminate)),
                (1, None),
                (10, Some(indeterminate)),
            ] {
                tokio::time::sleep(Duration::from_secs(wait)).await;
                let got = answer(
                    stub.ask(question(COSTLY, RecordType::PTR), Carrier::Udp)
                        .await,
                    COSTLY,
                )?;
                match expected {
                    Some(seen_now) => assert_eq!(seen(&got.message), seen_now),
                    None => assert!(matches!(seen(&got.message), Seen::Servfail(_))),
                }
            }
            let cheap = zone_of("google.com");
            let got = ask(&mut stub, &cheap, Carrier::Udp).await?;
            assert_eq!(seen(&got.message), cheap.expect.seen());
            Ok(())
        });
        let run = Run(world.run().expect("the run passes its checks"));
        for nth in [0, 2] {
            let asked = run.served_for(COSTLY, nth);
            assert!(
                (1..=PER_QUERY as usize + 2).contains(&asked),
                "ask {nth}: {asked} questions for an allowance of {PER_QUERY} units"
            );
        }
        assert_eq!(run.served_for(COSTLY, 1), 0, "the hold asks nothing");
    });
}

/// The names a greedy client asks, each a cold validation: the key cache is off in these worlds so that none is
/// cheaper for the ones before it.
const COLD: [&str; 6] = [
    "cloudflare.com",
    "nlnetlabs.nl",
    "fedoraproject.org",
    "ed25519.nl",
    "debian.org",
    "www.icann.org",
];

/// A validation with no key cache, so that each cold name costs its chain, under the allowance and the shares
/// given.
fn spending(allowance: Allowance, share: Budget) -> Validating {
    validating_with(Limits {
        key_cache: 0,
        ..Limits::default()
    })
    .allowing(allowance)
    .sharing(Budgets::new(share).expect("a share in bounds"))
}

/// Asks cold names until one is shed, which is SERVFAIL with Not Ready (D106, D117): how many were answered first.
async fn until_shed(stub: &mut Stub) -> Result<usize, String> {
    for (answered, name) in COLD.iter().enumerate() {
        let zone = zone_of(name);
        let got = ask(stub, &zone, Carrier::Udp).await?;
        match seen(&got.message) {
            Seen::Secure => {}
            Seen::Servfail(Some(InfoCode::NOT_READY)) => return Ok(answered),
            other => return Err(format!("{name}: {other:?}")),
        }
    }
    Err("no query was shed".to_owned())
}

/// The allowance of all clients spent: the query that would ask more is shed with SERVFAIL and Not Ready (D106), and
/// asks nothing while the allowance is in debt; one the cache has still gets its answer, whose cost is none; the
/// allowance refills with time.
#[test]
fn a_query_past_the_allowance_is_shed_and_the_cache_is_still_answered() {
    seed::each(ALLOWANCE_SHED, |seed| {
        let spending = spending(
            Allowance {
                per_second: 1,
                burst: 25,
                ..Allowance::default()
            },
            Budget {
                per_second: 1_000,
                burst: 2_000,
                table: 1 << 20,
            },
        );
        let mut world = world(
            seed,
            captures(),
            Duration::ZERO,
            Duration::from_secs(120),
            spending,
        );
        world.client(async move |mut stub| {
            asks(&mut stub);
            let answered = until_shed(&mut stub).await?;
            assert!(answered >= 1, "the first query finds the allowance whole");
            let shed = zone_of("ed448.nl");
            let got = ask(&mut stub, &shed, Carrier::Udp).await?;
            assert_eq!(
                seen(&got.message),
                Seen::Servfail(Some(InfoCode::NOT_READY)),
                "still in debt"
            );
            let cached = zone_of(COLD[0]);
            let got = ask(&mut stub, &cached, Carrier::Udp).await?;
            assert_eq!(
                seen(&got.message),
                Seen::Secure,
                "a cache hit costs nothing"
            );
            // Debt is at most the burst: 25 units, refilled by one a second.
            tokio::time::sleep(Duration::from_secs(30)).await;
            let got = ask(&mut stub, &shed, Carrier::Udp).await?;
            assert_eq!(
                seen(&got.message),
                shed.expect.seen(),
                "the allowance refilled"
            );
            Ok(())
        });
        let run = Run(world.run().expect("the run passes its checks"));
        assert_eq!(
            run.served_for("ed448.nl", 0),
            0,
            "the shed query asked nothing"
        );
        assert!(
            run.served_for("ed448.nl", 1) > 1,
            "the refilled one validates"
        );
        assert_eq!(run.served_for(COLD[0], 1), 0, "the cache hit asked nothing");
    });
}

/// A client that spends its share, a /24 of IPv4 (D117), is shed: Not Ready, nothing asked for it; a client of the
/// same network is shed with it, a client of another is answered, and the share refills. The clients take turns, so
/// that the questions the server answers are each one client's.
#[test]
fn a_client_over_its_share_is_shed_with_its_network_and_the_others_are_answered() {
    const GREEDY: &str = "198.51.100.7";
    const NEIGHBOUR: &str = "198.51.100.200";
    const OTHER: &str = "203.0.113.9";
    seed::each(SHARE_SHED, |seed| {
        let spending = spending(
            Allowance::default(),
            Budget {
                per_second: 1,
                burst: 25,
                // Large, so that no two of the networks hash to one slot (D133).
                table: 1 << 20,
            },
        );
        let mut world = world(
            seed,
            captures(),
            Duration::ZERO,
            Duration::from_secs(120),
            spending,
        );
        world.client_at(
            GREEDY.parse().expect("an address"),
            async move |mut stub| {
                asks(&mut stub);
                let answered = until_shed(&mut stub).await?;
                assert!(answered >= 1, "the first query finds the share whole");
                let shed = zone_of("ed448.nl");
                let got = ask(&mut stub, &shed, Carrier::Udp).await?;
                assert_eq!(
                    seen(&got.message),
                    Seen::Servfail(Some(InfoCode::NOT_READY)),
                    "still in debt"
                );
                let cached = zone_of(COLD[0]);
                let got = ask(&mut stub, &cached, Carrier::Udp).await?;
                assert_eq!(
                    seen(&got.message),
                    Seen::Secure,
                    "a cache hit costs nothing"
                );
                tokio::time::sleep(Duration::from_secs(40)).await;
                let got = ask(&mut stub, &shed, Carrier::Udp).await?;
                assert_eq!(seen(&got.message), shed.expect.seen(), "the share refilled");
                Ok(())
            },
        );
        world.client_at(
            NEIGHBOUR.parse().expect("an address"),
            async move |mut stub| {
                asks(&mut stub);
                tokio::time::sleep(Duration::from_secs(2)).await;
                let zone = zone_of("www.ripe.net");
                let got = ask(&mut stub, &zone, Carrier::Udp).await?;
                assert_eq!(
                    seen(&got.message),
                    Seen::Servfail(Some(InfoCode::NOT_READY)),
                    "the network's share"
                );
                Ok(())
            },
        );
        world.client_at(OTHER.parse().expect("an address"), async move |mut stub| {
            asks(&mut stub);
            tokio::time::sleep(Duration::from_secs(3)).await;
            let zone = zone_of("nonexistent.debian.org");
            let got = ask(&mut stub, &zone, Carrier::Udp).await?;
            assert_eq!(
                seen(&got.message),
                Seen::Secure,
                "another network has a share of its own"
            );
            Ok(())
        });
        let run = Run(world.run().expect("the run passes its checks"));
        assert_eq!(
            run.served_for("ed448.nl", 0),
            0,
            "the shed query asked nothing"
        );
        assert!(
            run.served_for("ed448.nl", 1) > 1,
            "the refilled one validates"
        );
        assert!(
            run.served_for("www.ripe.net", 0) <= 1,
            "the neighbour's query was shed with at most its own question asked"
        );
        assert!(
            run.served_for("nonexistent.debian.org", 0) > 1,
            "the other's was validated"
        );
    });
}

// ---------------------------------------------------------------------------------------------------------------
// 6. The seed picks the weather.

/// The zones whose verdict a lossy network may delay or fail, not change: the costliest takes longer than a
/// scenario of minutes waits for.
const LIGHT: &[&str] = &[
    "cloudflare.com",
    "nlnetlabs.nl",
    "debian.org",
    "nonexistent.nlnetlabs.nl",
    "google.com",
    "ed448.nl",
    "dnssec-failed.org",
    "sigfail.verteiltesysteme.net",
    "sigexpired.bad-dnssec.wb.sidnlabs.nl",
];

/// Percent of the DS and DNSKEY responses lost, and of those left that are late, and by how much at most.
#[derive(Debug, Clone, Copy, Default)]
struct Weather {
    loss: u64,
    slow: u64,
    delay_ms: u64,
}

const LOSS: [u64; 4] = [0, 10, 30, 60];
const SLOW: [u64; 3] = [0, 30, 100];
const DELAYS_MS: [u64; 5] = [0, 200, 2_000, 4_000, 7_000];

/// An upstream server whose responses to the validator's questions suffer the weather, which a scenario sets
/// after the world is built, from the seed.
fn weathered(weather: Rc<Cell<Weather>>) -> Answers {
    captures().faulty(move |question, rng| {
        let weather = weather.get();
        if !matches!(question.qtype, RecordType::DS | RecordType::DNSKEY) {
            Verdict::Answer
        } else if rng.below(100) < weather.loss {
            Verdict::Drop
        } else if weather.delay_ms > 0 && rng.below(100) < weather.slow {
            Verdict::Delay(Duration::from_millis(1 + rng.below(weather.delay_ms)))
        } else {
            Verdict::Answer
        }
    })
}

/// The run of the property: two clients, each over a transport the seed picks, ask three names the seed picks (all
/// different: a second ask of a name that failed meets the failure hold, a SERVFAIL with no extended error), while
/// the DS and DNSKEY responses are lost and late as the seed says. Each answer is the verdict of the table, or a
/// SERVFAIL saying there is none (DNSSEC Indeterminate or No Reachable Authority): a lost response is an unanswered
/// question, never a verdict other than the zone's, no insecure signed zone, no bogus one that validates, no secure
/// one called bogus.
fn weather_run(seed: Seed) -> Vec<Event> {
    let weather = Rc::new(Cell::new(Weather::default()));
    let mut world = world(
        seed,
        weathered(Rc::clone(&weather)),
        Duration::ZERO,
        Duration::from_mins(30),
        validating(),
    );
    weather.set(Weather {
        loss: LOSS[world.choose(LOSS.len())],
        slow: SLOW[world.choose(SLOW.len())],
        delay_ms: DELAYS_MS[world.choose(DELAYS_MS.len())],
    });
    let mut names = LIGHT.to_vec();
    for _ in 0..2 {
        let carrier = [Carrier::Udp, Carrier::Tcp][world.choose(2)];
        let mine: Vec<&str> = (0..3)
            .map(|_| names.swap_remove(world.choose(names.len())))
            .collect();
        world.client(async move |mut stub| {
            asks(&mut stub);
            for name in mine {
                let zone = zone_of(name);
                let got = ask(&mut stub, &zone, carrier).await?;
                match seen(&got.message) {
                    Seen::Servfail(None) => {
                        return Err(format!("{name}: SERVFAIL without an extended error").into());
                    }
                    // A lost or late response leaves the question unanswered: no verdict.
                    Seen::Servfail(Some(
                        InfoCode::DNSSEC_INDETERMINATE | InfoCode::NO_REACHABLE_AUTHORITY,
                    )) => {}
                    verdict if zone.expect.seen() == verdict => {}
                    verdict => {
                        return Err(format!("{name}: {verdict:?}, not {:?}", zone.expect).into());
                    }
                }
            }
            Ok(())
        });
    }
    world.run().expect("the run passes its checks")
}

/// Whatever the weather on the validator's questions, each answer is its zone's verdict or a SERVFAIL of no verdict,
/// over UDP and TCP, with the oracle's checks of every response (AD only where the zone is secure,
/// the records the server's).
#[test]
fn whatever_the_validators_questions_suffer_the_verdict_stands_or_servfails() {
    seed::each(FEW, |seed| {
        weather_run(seed);
    });
}

/// One seed gives one trace in two processes, with the validator's maps and the budgets of the allowance and the
/// shares, whose hashers are seeded by the process (D133).
#[test]
fn a_validating_run_replays_in_two_processes() {
    let runs = Cell::new(0);
    seed::in_two_processes(
        module_path!(),
        "a_validating_run_replays_in_two_processes",
        ONE,
        |seed| {
            runs.set(runs.get() + 1);
            trace::digest(&weather_run(seed))
        },
    );
    assert!(runs.get() > 0);
}
