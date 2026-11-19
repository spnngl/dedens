//! The iteration of a resolution on the captured resolutions of `testdata/recursion/` (D188), each server answering
//! as captured through `Authorities`, the harness acting as the transport: RFC 1034 §5.3.3 (from the closest
//! delegation down the referrals, across CNAMEs), §4.3.2 (referrals down only, whatever the AA bit), RFC 2308 §5
//! (no denial without its SOA), RFC 5452 §9.1 (a response to another question is not read), RFC 6672 §2.2 (a DNAME
//! making a name too long), RFC 6895 §3 (questions not resolved), RFC 8914 §4 (the extended error of a failure),
//! RFC 9471 §2 (glue within the zone asked), and each bound of `Limits` (D191).

use std::cell::RefCell;
use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use dedens_cache::{Checked, Config};
use dedens_proto::edns::InfoCode;
use dedens_proto::rdata::{Opaque, RData};
use dedens_proto::{Class, Flags, Message, Name, Question, Rcode, Record, RecordType};
use dedens_resolver::{
    Caches, DEFAULT_CAPACITY, Failure, InfraCache, Limit, Limits, Marks, Next, Outcome, Query,
    Rank, Reply, Resolution, Rrset, RrsetCache, Unsupported,
};
use dedens_roots::{RootHints, Tlds};
use dedens_testkit::recursion::{self, Authorities, Exchange};

use crate::infra_cache::Seeded;

/// A question sent: the zone asked, the name and the type.
type Sent = (Name<'static>, Name<'static>, RecordType);

/// The seed of the draws: of a server per zone, which the steering makes, and of the server names looked up, for
/// which it falls on the names the captures looked up.
const SEED: u64 = 0;

/// Empty caches; the TLD hints when `tlds`.
fn caches(tlds: bool) -> Arc<Caches> {
    Arc::new(Caches {
        rrsets: RrsetCache::new(DEFAULT_CAPACITY, Config::default()).expect("a valid config"),
        infra: InfraCache::new(InfraCache::DEFAULT_CAPACITY, 64).expect("a valid size"),
        roots: RootHints::bundled().clone(),
        tlds: tlds.then(|| Tlds::bundled().clone()),
    })
}

/// The time of the capture, so that every TTL it holds is fresh.
fn at(capture: &recursion::Resolution) -> Duration {
    Duration::from_secs(capture.captured_at)
}

/// The server of each zone whose responses the capture followed: the first asked, IPv4 when both families answer.
fn followed(capture: &recursion::Resolution) -> HashMap<&Name<'static>, IpAddr> {
    let mut first = HashMap::new();
    for e in &capture.exchanges {
        first.entry(&e.zone).or_insert(e.server);
    }
    first
}

/// Marks lame, for each zone the capture asked, every address it shows but the server it followed: the draw then
/// falls on that server.
fn steer(caches: &Caches, capture: &recursion::Resolution) {
    let mut known: HashSet<IpAddr> = caches
        .roots
        .servers()
        .iter()
        .flat_map(dedens_roots::Server::addresses)
        .collect();
    for exchange in &capture.exchanges {
        let response = dedens_testkit::message(&exchange.response);
        let records = response.answer.iter().chain(&response.additional);
        known.extend(records.filter_map(|r| address(r)));
    }
    let now = secs(at(capture));
    for (zone, server) in followed(capture) {
        for &address in known.iter().filter(|&&a| a != server) {
            caches.infra.lame(SocketAddr::new(address, 53), zone, now);
        }
    }
}

fn address(record: &Record<'_>) -> Option<IpAddr> {
    match record.data() {
        RData::A(v4) => Some(v4.into()),
        RData::Aaaa(v6) => Some(v6.into()),
        _ => None,
    }
}

fn secs(now: Duration) -> u32 {
    u32::try_from(now.as_secs()).expect("a capture time within u32")
}

/// How the transport ends an exchange.
enum Answered {
    Response(Message<'static>),
    Timeout,
    ServerError,
    LocalError,
}

/// The authoritative servers and the network: what comes of a query.
type Server<'a> = dyn Fn(&Query) -> Answered + 'a;

/// Runs `resolution` to its end at `now`, each query answered by `server`; the outcome, and the questions sent.
fn run(resolution: &mut Resolution, server: &Server<'_>, now: Duration) -> (Outcome, Vec<Sent>) {
    seeded(resolution, server, now, SEED)
}

/// [`run`], drawing from `seed`.
fn seeded(
    resolution: &mut Resolution,
    server: &Server<'_>,
    now: Duration,
    seed: u64,
) -> (Outcome, Vec<Sent>) {
    let mut rng = Seeded(seed);
    let mut sent = Vec::new();
    loop {
        let query = match resolution.step(now, &mut rng) {
            Next::Done(outcome) => {
                let outcome = outcome.clone();
                assert_eq!(resolution.sent(), sent.len());
                return (outcome, sent);
            }
            Next::Send(query) => query.clone(),
        };
        let question = &query.question;
        sent.push((query.zone.clone(), question.name.clone(), question.qtype));
        // Far past any bound the tests set: a resolution that would never end fails at once.
        assert!(sent.len() <= 1000, "no end in sight");
        let answered = server(&query);
        resolution.receive(reply(&answered), now);
    }
}

/// The reply the transport hands over.
fn reply(answered: &Answered) -> Reply<'_> {
    match answered {
        Answered::Response(message) => Reply::Response {
            message,
            seen: Marks::default(),
        },
        Answered::Timeout => Reply::Timeout,
        Answered::ServerError => Reply::ServerError,
        Answered::LocalError => Reply::LocalError,
    }
}

/// A resolution of `capture`'s question.
fn start(capture: &recursion::Resolution, caches: &Arc<Caches>, limits: Limits) -> Resolution {
    let question = Question::new(capture.name.clone(), capture.rtype);
    Resolution::start(question, Arc::clone(caches), at(capture), limits).expect("an IN question")
}

/// Starts `capture`'s question on `caches`, steered to its servers, under `limits`, and runs it.
fn resolve(
    capture: &recursion::Resolution,
    caches: &Arc<Caches>,
    limits: Limits,
) -> (Outcome, Vec<Sent>) {
    changed(capture, caches, limits, &|_, _| {})
}

/// Changes the response a server of a zone gives.
type Change<'a> = dyn Fn(&Name<'_>, &mut Message<'static>) + 'a;

/// [`resolve`], each captured response passed through `change` with the zone of the server giving it.
fn changed(
    capture: &recursion::Resolution,
    caches: &Arc<Caches>,
    limits: Limits,
    change: &Change<'_>,
) -> (Outcome, Vec<Sent>) {
    steer(caches, capture);
    let authorities = Authorities::new([capture]);
    let server = |query: &Query| {
        let mut response = captured(&authorities, query);
        change(&query.zone, &mut response);
        Answered::Response(response)
    };
    run(&mut start(capture, caches, limits), &server, at(capture))
}

/// Whether `zone` is the zone written `text`.
fn is(zone: &Name<'_>, text: &str) -> bool {
    zone.to_string() == text
}

fn name(text: &str) -> Name<'static> {
    text.parse().expect("a name")
}

/// The response of `capture` to `name` from a server of `zone`.
fn response(capture: &recursion::Resolution, zone: &str, name: &str) -> Message<'static> {
    let exchange = (capture.exchanges.iter())
        .find(|e| is(&e.zone, zone) && is(&e.name, name))
        .expect("a captured exchange");
    dedens_testkit::message(&exchange.response)
}

/// `response` as the answer to `question`.
fn to(mut response: Message<'static>, question: &Question<'static>) -> Message<'static> {
    response.questions = vec![question.clone()];
    response
}

/// The response `authorities` captured to `query`, over TCP after a truncated one, as the transport has it.
fn captured(authorities: &Authorities, query: &Query) -> Message<'static> {
    let wire = Message::query(0, query.question.clone())
        .to_vec()
        .expect("a query encodes");
    let udp = authorities.answer(query.server.ip(), recursion::Transport::Udp, &wire);
    let response = dedens_testkit::message(&udp);
    if !response.header.flags.contains(Flags::TC) {
        return response;
    }
    let tcp = authorities.answer(query.server.ip(), recursion::Transport::Tcp, &wire);
    dedens_testkit::message(&tcp)
}

/// The questions the resolution sends of those the capture asked: not the priming, DS and DNSKEY queries of its
/// validation, each asked of one server where the capture asked one per address family or transport, and a
/// server's AAAA not once its A was found.
fn expected(capture: &recursion::Resolution) -> Vec<Sent> {
    let mut sent: Vec<Sent> = Vec::new();
    let mut found: Vec<&Name<'static>> = Vec::new();
    for e in &capture.exchanges {
        let asked = (&e.name, e.rtype) == (&capture.name, capture.rtype);
        let validation = matches!(e.rtype, RecordType::DS | RecordType::DNSKEY)
            || (e.name.is_root() && e.rtype == RecordType::NS);
        if (validation && !asked) || (e.rtype == RecordType::AAAA && found.contains(&&e.name)) {
            continue;
        }
        if e.rtype == RecordType::A && !answer(e).is_empty() {
            found.push(&e.name);
        }
        let one = (e.zone.clone(), e.name.clone(), e.rtype);
        if sent.last() != Some(&one) {
            sent.push(one);
        }
    }
    sent
}

/// The `RRsets` of the answer section of `exchange`'s response.
fn answer(exchange: &Exchange) -> Vec<Rrset> {
    Rrset::group(&dedens_testkit::message(&exchange.response).answer)
}

/// A referral to `child` built on `template`, a captured one, answering `question`: one server per address of
/// `addresses`, `ns<i>.<child>`, with its glue.
fn referral(
    template: &Message<'static>,
    question: &Question<'static>,
    child: &Name<'static>,
    addresses: &[Ipv4Addr],
) -> Message<'static> {
    let ns = (template.authority.iter())
        .find(|r| r.rtype() == RecordType::NS)
        .expect("an NS record");
    let glue = (template.additional.iter())
        .find(|r| r.rtype() == RecordType::A)
        .expect("an A record");
    let mut response = to(template.clone(), question);
    response.authority.clear();
    response.additional.clear();
    for (i, &address) in addresses.iter().enumerate() {
        let server = name(&format!("ns{i}.{child}"));
        let data = RData::Ns(server.clone());
        response
            .authority
            .push(Record::new(child.clone(), ns.class, ns.ttl, &data));
        let data = RData::A(address);
        response
            .additional
            .push(Record::new(server, glue.class, glue.ttl, &data));
    }
    response
}

/// The zone one label below `zone` on the way to `name`.
fn below(zone: &Name<'_>, name: &Name<'_>) -> Name<'static> {
    let skip = name.label_count() - zone.label_count() - 1;
    Name::from_labels(name.labels().skip(skip)).expect("a name")
}

#[test]
fn rfc1034_5_3_3_each_capture_resolves_asking_what_it_asked() {
    for (id, capture) in recursion::Resolution::all() {
        let (outcome, sent) = resolve(&capture, &caches(false), Limits::default());
        assert_eq!(sent, expected(&capture), "{id}");
        let followed = followed(&capture);
        let last = (capture.exchanges.iter().rev())
            .find(|e| e.rtype == capture.rtype && followed.get(&e.zone) == Some(&e.server))
            .expect("an exchange");
        match outcome {
            Outcome::Answer { data, .. } => {
                let captured = answer(last)
                    .into_iter()
                    .find(|set| set.rtype() == capture.rtype);
                assert_eq!(Some(&*data.rrset), captured.as_ref(), "{id}");
            }
            Outcome::NxDomain { soa, .. } => {
                assert!(id.starts_with("nxdomain"), "{id}");
                assert_eq!(soa.rrset.rtype(), RecordType::SOA, "{id}");
            }
            Outcome::NoData { soa, .. } => {
                assert!(id.starts_with("nodata"), "{id}");
                assert_eq!(soa.rrset.rtype(), RecordType::SOA, "{id}");
            }
            Outcome::YxDomain { .. } => panic!("{id}: {outcome:?}"),
            Outcome::Failed(failure) => panic!("{id}: {failure}"),
        }
    }
}

#[test]
fn rfc1034_5_3_3_the_cache_answers_again() {
    for (id, capture) in recursion::Resolution::all() {
        if id == "dname" {
            continue; // d193_an_address_pinned_to_glue_is_asked_again
        }
        let caches = caches(false);
        let (first, sent) = resolve(&capture, &caches, Limits::default());
        let (again, resent) = resolve(&capture, &caches, Limits::default());
        match first {
            // Positive answers come from the cache whole, chain included.
            Outcome::Answer { .. } => {
                // The cache counts its TTLs down from the least of the RRset's.
                let rrsets = |outcome: &Outcome| match outcome {
                    Outcome::Answer { chain, data } => {
                        let sets = chain.iter().chain([data]);
                        sets.map(|held| Rrset::clone(&held.rrset))
                            .collect::<Vec<_>>()
                    }
                    _ => Vec::new(),
                };
                assert_eq!(rrsets(&again), rrsets(&first), "{id}");
                assert_eq!(resent, [], "{id}");
            }
            // A denial is not cached yet (step 12): asked again, from the closest delegation cached.
            _ => assert!(resent.len() < sent.len(), "{id}: {resent:?}"),
        }
    }
}

#[test]
fn d193_an_address_pinned_to_glue_is_asked_again() {
    // panix.netmeister.org, a server of dns.netmeister.org, came as glue before as the answer: the answer keeps
    // the glue's rank, which answers no client, so the chain comes from the cache and the address from its zone.
    let capture = recursion::Resolution::read("dname");
    let caches = caches(false);
    let _ = resolve(&capture, &caches, Limits::default());
    let (_, resent) = resolve(&capture, &caches, Limits::default());
    let first = resent
        .first()
        .map(|(zone, name, _)| (zone.to_string(), name.to_string()));
    let pinned = (
        "netmeister.org.".to_owned(),
        "panix.netmeister.org.".to_owned(),
    );
    assert_eq!(first, Some(pinned));
}

#[test]
fn d191_tld_hints_start_below_the_root() {
    let capture = recursion::Resolution::read("unsigned");
    let (_, from_root) = resolve(&capture, &caches(false), Limits::default());
    let (outcome, sent) = resolve(&capture, &caches(true), Limits::default());
    assert!(matches!(outcome, Outcome::Answer { .. }), "{outcome:?}");
    assert_eq!(sent.first().map(|s| s.0.to_string()), Some("com.".into()));
    assert_eq!(sent.len() + 1, from_root.len());
}

#[test]
fn rfc6895_3_meta_types_and_other_classes_are_not_resolved() {
    let caches = caches(false);
    let start = |name: &str, rtype, class| {
        let question = Question {
            name: self::name(name),
            qtype: rtype,
            qclass: class,
        };
        Resolution::start(
            question,
            Arc::clone(&caches),
            Duration::ZERO,
            Limits::default(),
        )
        .err()
    };
    let any = RecordType::from(255);
    assert_eq!(
        start("example.com.", any, Class::IN),
        Some(Unsupported::Type(any))
    );
    assert_eq!(
        start("example.com.", RecordType::OPT, Class::IN),
        Some(Unsupported::Type(RecordType::OPT))
    );
    assert_eq!(
        start("version.bind.", RecordType::TXT, Class::CH),
        Some(Unsupported::Class(Class::CH))
    );
    assert_eq!(start("example.com.", RecordType::A, Class::IN), None);
}

/// The outcome of `id` under `limits`, and the queries sent.
pub(crate) fn limited(id: &str, limits: Limits) -> (Outcome, usize) {
    let capture = recursion::Resolution::read(id);
    let (outcome, sent) = resolve(&capture, &caches(false), limits);
    (outcome, sent.len())
}

#[test]
fn d191_queries_bound() {
    let limits = Limits {
        queries: 2,
        ..Limits::default()
    };
    let (outcome, sent) = limited("unsigned", limits);
    assert_eq!(outcome, Outcome::Failed(Failure::Limit(Limit::Queries)));
    assert_eq!(sent, 2);
}

#[test]
fn d191_referrals_bound() {
    let limits = Limits {
        referrals: 1,
        ..Limits::default()
    };
    let (outcome, sent) = limited("unsigned", limits);
    assert_eq!(outcome, Outcome::Failed(Failure::Limit(Limit::Referrals)));
    assert_eq!(sent, 2);
}

/// Resolves a name 40 labels below google.com, each zone from google.com down referring to the next one down with
/// two servers, `lame` making the first asked of each zone below google.com lame.
fn deep(lame: bool) -> (Outcome, Vec<Sent>) {
    let capture = recursion::Resolution::read("unsigned");
    let template = response(&capture, "com.", "google.com.");
    let deep = name(&format!("{}google.com.", "x.".repeat(40)));
    let caches = caches(false);
    steer(&caches, &capture);
    let authorities = Authorities::new([&capture]);
    let up = response(&capture, ".", "google.com.");
    let asked: RefCell<HashSet<Name<'static>>> = RefCell::new(HashSet::new());
    let google = name("google.com.");
    let server = |query: &Query| {
        let zone = &query.zone;
        let question = &query.question;
        if zone.is_root() || is(zone, "com.") {
            let renamed = Query {
                question: Question::new(capture.name.clone(), capture.rtype),
                ..query.clone()
            };
            return Answered::Response(to(captured(&authorities, &renamed), question));
        }
        if lame && *zone != google && asked.borrow_mut().insert(zone.clone()) {
            // The root's referral to com: up, from a server of a zone below.
            return Answered::Response(to(up.clone(), question));
        }
        let child = below(zone, &question.name);
        let addresses = [Ipv4Addr::new(192, 0, 2, 1), Ipv4Addr::new(192, 0, 2, 2)];
        Answered::Response(referral(&template, question, &child, &addresses))
    };
    let question = Question::new(deep, RecordType::A);
    let mut resolution =
        Resolution::start(question, caches, at(&capture), Limits::default()).expect("IN");
    run(&mut resolution, &server, at(&capture))
}

#[test]
fn d191_referrals_default_bound() {
    // The root's referral, com's, then one per zone from google.com down: the 31st is past the bound.
    let (outcome, sent) = deep(false);
    assert_eq!(outcome, Outcome::Failed(Failure::Limit(Limit::Referrals)));
    assert_eq!(sent.len(), Limits::default().referrals + 1);
}

#[test]
fn d191_queries_default_bound() {
    // Two queries per zone below google.com, the first lame: the 33rd query is past the bound, at the 17th
    // referral.
    let (outcome, sent) = deep(true);
    assert_eq!(outcome, Outcome::Failed(Failure::Limit(Limit::Queries)));
    assert_eq!(sent.len(), Limits::default().queries);
}

#[test]
fn d191_restarts_bound() {
    // www.microsoft.com goes through two CNAMEs.
    let (outcome, _) = limited("cname", Limits::default());
    let Outcome::Answer { chain, .. } = outcome else {
        panic!("{outcome:?}");
    };
    let restarts = |restarts| {
        let limits = Limits {
            restarts,
            ..Limits::default()
        };
        limited("cname", limits).0
    };
    assert!(matches!(restarts(chain.len()), Outcome::Answer { .. }));
    assert_eq!(
        restarts(chain.len() - 1),
        Outcome::Failed(Failure::Limit(Limit::Restarts))
    );
}

#[test]
fn d191_restarts_default_bound_counts_the_cnames_of_a_response() {
    // microsoft.com answers www.microsoft.com with a chain of `hops` CNAMEs within it, then the address.
    let capture = recursion::Resolution::read("cname");
    let chain = |hops: usize| {
        let change = |zone: &Name<'_>, response: &mut Message<'static>| {
            if !is(zone, "microsoft.com.") {
                return;
            }
            let cname = response.answer.first().expect("a CNAME").clone();
            let mut owner = cname.name.clone();
            response.answer.clear();
            for i in 1..=hops {
                let target = name(&format!("c{i}.microsoft.com."));
                let data = RData::Cname(target.clone());
                response
                    .answer
                    .push(Record::new(owner, cname.class, cname.ttl, &data));
                owner = target;
            }
            let data = RData::A(Ipv4Addr::new(192, 0, 2, 1));
            response
                .answer
                .push(Record::new(owner, cname.class, cname.ttl, &data));
        };
        changed(&capture, &caches(false), Limits::default(), &change).0
    };
    let restarts = Limits::default().restarts;
    let Outcome::Answer { chain: kept, .. } = chain(restarts) else {
        panic!("{:?}", chain(restarts));
    };
    assert_eq!(kept.len(), restarts);
    assert_eq!(
        chain(restarts + 1),
        Outcome::Failed(Failure::Limit(Limit::Restarts))
    );
}

#[test]
fn d191_depth_bound() {
    // netmeister.org's servers are named under gandi.net, without glue in org.
    let limits = Limits {
        depth: 0,
        ..Limits::default()
    };
    let (outcome, sent) = limited("glueless", limits);
    assert_eq!(outcome, Outcome::Failed(Failure::Limit(Limit::Depth)));
    assert_eq!(sent, 2);
}

#[test]
fn d191_targets_bound() {
    let limits = Limits {
        targets: 0,
        ..Limits::default()
    };
    let (outcome, sent) = limited("glueless", limits);
    assert_eq!(outcome, Outcome::Failed(Failure::Limit(Limit::Targets)));
    assert_eq!(sent, 2);
}

/// Runs the question of `unsigned` under `limits`, every exchange ending as `answered` makes it.
fn unreached(limits: Limits, answered: fn() -> Answered) -> (Outcome, usize) {
    let capture = recursion::Resolution::read("unsigned");
    let mut resolution = start(&capture, &caches(false), limits);
    let (outcome, sent) = run(&mut resolution, &|_| answered(), at(&capture));
    (outcome, sent.len())
}

/// Runs the question of `unsigned` with every query timing out, under `limits`.
pub(crate) fn unanswered(limits: Limits) -> (Outcome, usize) {
    unreached(limits, || Answered::Timeout)
}

#[test]
fn d191_servers_bound() {
    // The root hints give 26 addresses.
    let (outcome, sent) = unanswered(Limits::default());
    assert_eq!(outcome, Outcome::Failed(Failure::Limit(Limit::Servers)));
    assert_eq!(sent, Limits::default().servers);
}

#[test]
fn rfc8914_4_no_server_answering_is_no_reachable_authority() {
    let limits = Limits {
        servers: 100,
        ..Limits::default()
    };
    let roots: usize = (RootHints::bundled().servers().iter())
        .map(|s| s.addresses().count())
        .sum();
    let (outcome, sent) = unanswered(limits);
    assert_eq!(outcome, Outcome::Failed(Failure::Unreachable));
    assert_eq!(
        Failure::Unreachable.info_code(),
        InfoCode::NO_REACHABLE_AUTHORITY
    );
    assert_eq!(sent, roots);
    // Exchanges failing, on the network or here, are a network error.
    for answered in [|| Answered::ServerError, || Answered::LocalError] {
        let (outcome, sent) = unreached(limits, answered);
        assert_eq!(outcome, Outcome::Failed(Failure::Network));
        assert_eq!(sent, roots);
    }
    assert_eq!(Failure::Network.info_code(), InfoCode::NETWORK_ERROR);
    assert_eq!(Failure::Unusable.info_code(), InfoCode::OTHER);
}

#[test]
fn d191_a_delegation_fails_on_what_its_own_servers_did() {
    // The root answers; com's servers all time out: no server of com answered.
    let capture = recursion::Resolution::read("unsigned");
    let caches = caches(false);
    steer(&caches, &capture);
    let authorities = Authorities::new([&capture]);
    let server = |query: &Query| {
        if is(&query.zone, "com.") {
            Answered::Timeout
        } else {
            Answered::Response(captured(&authorities, query))
        }
    };
    let limits = Limits {
        servers: 100,
        ..Limits::default()
    };
    let (outcome, _) = run(&mut start(&capture, &caches, limits), &server, at(&capture));
    assert_eq!(outcome, Outcome::Failed(Failure::Unreachable));
}

#[test]
fn d191_time_bound() {
    let capture = recursion::Resolution::read("unsigned");
    let limits = Limits::default();
    let mut resolution = start(&capture, &caches(false), limits);
    let (outcome, sent) = run(
        &mut resolution,
        &|_| Answered::Timeout,
        at(&capture) + limits.time,
    );
    assert_eq!(outcome, Outcome::Failed(Failure::Limit(Limit::Time)));
    assert_eq!(sent, []);
}

#[test]
fn d191_time_runs_out_mid_resolution() {
    // Each query times out after its timeout: the last one is given the time left, then the resolution ends.
    let capture = recursion::Resolution::read("unsigned");
    let limits = Limits::default();
    let mut resolution = start(&capture, &caches(false), limits);
    let mut rng = Seeded(SEED);
    let mut now = at(&capture);
    let mut waited = Vec::new();
    let outcome = loop {
        let timeout = match resolution.step(now, &mut rng) {
            Next::Done(outcome) => break outcome.clone(),
            Next::Send(query) => query.timeout,
        };
        waited.push(timeout);
        assert!(waited.len() <= 1000, "no end in sight");
        now += timeout;
        resolution.receive(Reply::Timeout, now);
    };
    assert_eq!(outcome, Outcome::Failed(Failure::Limit(Limit::Time)));
    assert_eq!(waited.iter().sum::<Duration>(), limits.time);
    assert!(
        waited.len() > 1 && waited.len() < limits.servers,
        "{waited:?}"
    );
}

/// Resolves `unsigned`'s question with com's referral to google.com naming `servers` servers without glue, their
/// names given by `named`, each lookup answered by `lookup` given the zone asked; drawing from `seed`.
fn glueless(
    names: &[Name<'static>],
    limits: Limits,
    seed: u64,
    lookup: &dyn Fn(&Query) -> Message<'static>,
) -> (Outcome, Vec<Sent>) {
    let capture = recursion::Resolution::read("unsigned");
    let caches = caches(false);
    steer(&caches, &capture);
    let authorities = Authorities::new([&capture]);
    let mut to_google = response(&capture, "com.", "google.com.");
    let ns = (to_google.authority.iter())
        .find(|r| r.rtype() == RecordType::NS)
        .expect("an NS record")
        .clone();
    to_google.authority = (names.iter())
        .map(|server| {
            Record::new(
                ns.name.clone(),
                ns.class,
                ns.ttl,
                &RData::Ns(server.clone()),
            )
        })
        .collect();
    to_google.additional.clear();
    let server = |query: &Query| {
        let question = &query.question;
        if question.name == capture.name {
            if is(&query.zone, "com.") {
                return Answered::Response(to(to_google.clone(), question));
            }
            return Answered::Response(captured(&authorities, query));
        }
        Answered::Response(lookup(query))
    };
    seeded(
        &mut start(&capture, &caches, limits),
        &server,
        at(&capture),
        seed,
    )
}

/// `count` server names in a zone that does not exist: the root refers to nl, whose servers deny the name.
fn nxns(count: usize, limits: Limits) -> (Outcome, Vec<Sent>) {
    let nx = recursion::Resolution::read("nxdomain-nsec3");
    let to_nl = response(&nx, ".", "dedens-nxdomain.nl.");
    let denied = response(&nx, "nl.", "dedens-nxdomain.nl.");
    let names: Vec<Name<'static>> = (0..count)
        .map(|i| name(&format!("ns{i}.dedens-nxdomain.nl.")))
        .collect();
    let lookup = |query: &Query| {
        let response = if query.zone.is_root() {
            &to_nl
        } else {
            &denied
        };
        to(response.clone(), &query.question)
    };
    glueless(&names, limits, SEED, &lookup)
}

/// The names looked up of `sent`, in order, with their types.
fn looked_up(sent: &[Sent]) -> Vec<(String, RecordType)> {
    let client = name("google.com.");
    (sent.iter())
        .filter(|(_, name, _)| *name != client)
        .map(|(_, name, rtype)| (name.to_string(), *rtype))
        .collect()
}

#[test]
fn d191_targets_default_bound_on_names_in_a_zone_that_does_not_exist() {
    // NXNSAttack (CVE-2020-12662): 20 server names without an address. Five are looked up, A only since each is
    // denied: the root's referral to nl and nl's denial for the first, nl's denial for the next four.
    let (outcome, sent) = nxns(20, Limits::default());
    assert_eq!(outcome, Outcome::Failed(Failure::Limit(Limit::Targets)));
    assert_eq!(sent.len(), 2 + 2 + 4, "{sent:?}");
    let names: HashSet<String> = looked_up(&sent).into_iter().map(|(name, _)| name).collect();
    assert_eq!(names.len(), Limits::default().targets);
    assert!(sent.iter().all(|s| s.2 == RecordType::A), "{sent:?}");
}

#[test]
fn d191_a_referral_keeps_as_many_server_names_as_servers_asked() {
    // Of the 20 server names, the first 13 are kept, each looked up once.
    let limits = Limits {
        targets: 100,
        ..Limits::default()
    };
    let (outcome, sent) = nxns(20, limits);
    assert_eq!(outcome, Outcome::Failed(Failure::Unreachable));
    let names: HashSet<String> = looked_up(&sent).into_iter().map(|(name, _)| name).collect();
    assert_eq!(names.len(), limits.servers);
    assert_eq!(sent.len(), 2 + 1 + limits.servers, "{sent:?}");
}

#[test]
fn d191_a_referral_caches_as_many_server_names_as_servers_asked() {
    // com's referral to google.com names 16 more servers after its four: the NS `RRset` cached holds 13.
    let capture = recursion::Resolution::read("unsigned");
    let change = |zone: &Name<'_>, response: &mut Message<'static>| {
        let ns = (response.authority.iter())
            .find(|r| r.rtype() == RecordType::NS)
            .cloned();
        if let (true, Some(ns)) = (is(zone, "com."), ns) {
            response.authority.extend((5..=20).map(|i| {
                let server = name(&format!("ns{i}.google.com."));
                Record::new(ns.name.clone(), ns.class, ns.ttl, &RData::Ns(server))
            }));
        }
    };
    let caches = caches(false);
    let (outcome, _) = changed(&capture, &caches, Limits::default(), &change);
    assert!(matches!(outcome, Outcome::Answer { .. }), "{outcome:?}");
    let now = secs(at(&capture));
    let ns = (caches
        .rrsets
        .get(&name("google.com."), RecordType::NS, Class::IN, now))
    .expect("google.com's NS cached");
    assert_eq!(ns.rrset.rdatas().len(), Limits::default().servers);
}

/// google.com's four servers, named in google.com, which com's referral gives without glue: reachable only through
/// google.com, com's referral leading back to it.
fn looping(seed: u64) -> (Outcome, Vec<Sent>) {
    let capture = recursion::Resolution::read("unsigned");
    let to_google = response(&capture, "com.", "google.com.");
    let names: Vec<Name<'static>> = (1..=4)
        .map(|i| name(&format!("ns{i}.google.com.")))
        .collect();
    let lookup = |query: &Query| {
        let mut referral = to(to_google.clone(), &query.question);
        referral.additional.clear();
        referral
    };
    glueless(&names, Limits::default(), seed, &lookup)
}

#[test]
fn d191_a_lookup_leading_back_to_a_zone_waiting_on_it_ends_at_once() {
    // Each server name is asked once of com, A only: com's referral back to google.com ends its lookup.
    let (outcome, sent) = looping(SEED);
    assert_eq!(outcome, Outcome::Failed(Failure::Unreachable));
    let mut names = looked_up(&sent);
    names.sort();
    let each = |i| (format!("ns{i}.google.com."), RecordType::A);
    assert_eq!(names, (1..=4).map(each).collect::<Vec<_>>());
    assert!(sent.iter().skip(2).all(|s| is(&s.0, "com.")), "{sent:?}");
}

#[test]
fn d191_server_names_are_looked_up_in_random_order() {
    let orders: HashSet<Vec<(String, RecordType)>> =
        (0..8).map(|seed| looked_up(&looping(seed).1)).collect();
    assert!(orders.len() > 1, "{orders:?}");
}

#[test]
fn rfc5452_9_1_a_response_to_another_question_is_not_read() {
    // google.com's servers answer another question, or with the QR bit clear.
    let capture = recursion::Resolution::read("unsigned");
    let changes: [&Change<'_>; 2] = [
        &|zone, response| {
            if is(zone, "google.com.") {
                response.questions = vec![Question::new(name("example.com."), RecordType::A)];
            }
        },
        &|zone, response| {
            if is(zone, "google.com.") {
                response.header.flags = response.header.flags.without(Flags::QR);
            }
        },
    ];
    for change in changes {
        let (outcome, _) = changed(&capture, &caches(false), Limits::default(), change);
        assert_eq!(outcome, Outcome::Failed(Failure::Unusable));
    }
}

#[test]
fn rfc1034_4_3_2_a_referral_not_down_is_lame() {
    // The servers of com, then of google.com, answer with the root's referral to com, as lame servers could.
    let capture = recursion::Resolution::read("unsigned");
    let to_com = response(&capture, ".", "google.com.");
    let lame = |lame: &'static str| {
        let change = |zone: &Name<'_>, response: &mut Message<'static>| {
            if is(zone, lame) {
                let questions = std::mem::take(&mut response.questions);
                *response = to_com.clone();
                response.questions = questions;
            }
        };
        let (outcome, sent) = changed(&capture, &caches(false), Limits::default(), &change);
        let asked = sent.iter().filter(|s| is(&s.0, lame)).count();
        (outcome, asked, sent.len())
    };
    // Each server of com is lame, up to the bound on servers asked.
    let servers = Limits::default().servers;
    let failed = Outcome::Failed(Failure::Limit(Limit::Servers));
    assert_eq!(lame("com."), (failed, servers, servers + 1));
    // Each of google.com's eight addresses is lame: none answers.
    assert_eq!(
        lame("google.com."),
        (Outcome::Failed(Failure::Unusable), 8, 10)
    );
}

#[test]
fn d191_a_referral_with_the_aa_bit_is_a_referral() {
    // The root's referral to com with the AA bit set, as servers set it: told before the AA bit, as by Unbound.
    let capture = recursion::Resolution::read("signed-com");
    let change = |zone: &Name<'_>, response: &mut Message<'static>| {
        if zone.is_root() {
            response.header.flags = response.header.flags.with(Flags::AA);
        }
    };
    let (outcome, sent) = changed(&capture, &caches(false), Limits::default(), &change);
    assert!(matches!(outcome, Outcome::Answer { .. }), "{outcome:?}");
    assert_eq!(sent, expected(&capture));
}

#[test]
fn d191_a_referral_of_another_class_is_not_followed() {
    // The root's referral to com, its NS records of class CH.
    let capture = recursion::Resolution::read("unsigned");
    let change = |zone: &Name<'_>, response: &mut Message<'static>| {
        if zone.is_root() {
            for record in &mut response.authority {
                if record.rtype() == RecordType::NS {
                    record.class = Class::CH;
                }
            }
        }
    };
    let (outcome, sent) = changed(&capture, &caches(false), Limits::default(), &change);
    assert!(matches!(outcome, Outcome::Failed(_)), "{outcome:?}");
    assert!(sent.iter().all(|s| s.0.is_root()), "{sent:?}");
}

#[test]
fn d191_a_referral_read_whatever_the_order_of_its_records() {
    // The root's referral to com, its authority section reversed: com's DS before its NS.
    let capture = recursion::Resolution::read("signed-com");
    let change = |zone: &Name<'_>, response: &mut Message<'static>| {
        if zone.is_root() {
            response.authority.reverse();
        }
    };
    let (outcome, sent) = changed(&capture, &caches(false), Limits::default(), &change);
    assert!(matches!(outcome, Outcome::Answer { .. }), "{outcome:?}");
    assert_eq!(sent, expected(&capture));
}

#[test]
fn d191_an_address_given_twice_is_asked_once() {
    // com's referral gives each server of google.com the address of the one followed; it times out.
    let capture = recursion::Resolution::read("unsigned");
    let google = name("google.com.");
    let IpAddr::V4(followed) = followed(&capture)[&google] else {
        panic!("google.com followed over IPv4");
    };
    let caches = caches(false);
    let authorities = Authorities::new([&capture]);
    steer(&caches, &capture);
    let server = |query: &Query| {
        if query.zone == google {
            return Answered::Timeout;
        }
        let mut response = captured(&authorities, query);
        if is(&query.zone, "com.") {
            response.additional.retain(|r| r.rtype() == RecordType::A);
            for record in &mut response.additional {
                *record = Record::new(
                    record.name.clone(),
                    record.class,
                    record.ttl,
                    &RData::A(followed),
                );
            }
        }
        Answered::Response(response)
    };
    let (outcome, sent) = run(
        &mut start(&capture, &caches, Limits::default()),
        &server,
        at(&capture),
    );
    assert_eq!(outcome, Outcome::Failed(Failure::Unreachable));
    assert_eq!(sent.iter().filter(|s| s.0 == google).count(), 1, "{sent:?}");
}

#[test]
fn d191_an_address_looked_up_after_it_was_asked_is_not_asked_again() {
    // `glueless`, gandi.net giving each server of netmeister.org ns-143-b.gandi.net's addresses, which time out:
    // each is asked once, though every name looked up gives it again.
    let capture = recursion::Resolution::read("glueless");
    let caches = caches(false);
    steer(&caches, &capture);
    let authorities = Authorities::new([&capture]);
    let server = |query: &Query| {
        if is(&query.zone, "netmeister.org.") {
            return Answered::Timeout;
        }
        if !query.question.name.is_within(&name("gandi.net.")) {
            return Answered::Response(captured(&authorities, query));
        }
        let renamed = Query {
            question: Question::new(name("ns-143-b.gandi.net."), query.question.qtype),
            ..query.clone()
        };
        let mut response = to(captured(&authorities, &renamed), &query.question);
        for record in &mut response.answer {
            record.name = query.question.name.clone();
        }
        Answered::Response(response)
    };
    let (_, sent) = run(
        &mut start(&capture, &caches, Limits::default()),
        &server,
        at(&capture),
    );
    // Its IPv4 and its IPv6 address.
    let asked = sent.iter().filter(|s| is(&s.0, "netmeister.org.")).count();
    assert_eq!(asked, 2, "{sent:?}");
}

#[test]
fn rfc9471_2_glue_out_of_the_zone_asked_is_not_used() {
    // org's referral to netmeister.org given ns-143-b.gandi.net's address, as gandi.net gives it: not org's to give.
    let capture = recursion::Resolution::read("glueless");
    let gandi = response(&capture, "gandi.net.", "ns-143-b.gandi.net.");
    let change = |zone: &Name<'_>, response: &mut Message<'static>| {
        if is(zone, "org.") && response.referral().is_some() {
            response.additional.extend(gandi.answer.iter().cloned());
        }
    };
    let (outcome, sent) = changed(&capture, &caches(false), Limits::default(), &change);
    assert!(matches!(outcome, Outcome::Answer { .. }), "{outcome:?}");
    assert_eq!(sent, expected(&capture));
}

/// `glueless`, gandi.net's servers not answering the A lookup of ns-143-b.gandi.net, under `limits`.
fn without_ipv4(limits: Limits) -> (Outcome, Vec<Sent>) {
    let capture = recursion::Resolution::read("glueless");
    let caches = caches(false);
    steer(&caches, &capture);
    let authorities = Authorities::new([&capture]);
    let server = |query: &Query| {
        if is(&query.zone, "gandi.net.") && query.question.qtype == RecordType::A {
            return Answered::Timeout;
        }
        Answered::Response(captured(&authorities, query))
    };
    run(&mut start(&capture, &caches, limits), &server, at(&capture))
}

#[test]
fn rfc1034_5_3_3_a_server_without_ipv4_reached_over_ipv6() {
    // gandi.net has no A record for ns-143-b.gandi.net: its AAAA one is looked up and asked.
    let (outcome, sent) = without_ipv4(Limits::default());
    assert!(matches!(outcome, Outcome::Answer { .. }), "{outcome:?}");
    let aaaa = ("ns-143-b.gandi.net.".to_owned(), RecordType::AAAA);
    assert!(
        sent.iter().any(|s| (s.1.to_string(), s.2) == aaaa),
        "{sent:?}"
    );
}

#[test]
fn d191_targets_bound_counts_aaaa_lookups() {
    // The A lookup of ns-143-b.gandi.net gives no address: its AAAA lookup is past a bound of one.
    let limits = Limits {
        targets: 1,
        servers: 100,
        queries: 100,
        ..Limits::default()
    };
    let (outcome, _) = without_ipv4(limits);
    assert_eq!(outcome, Outcome::Failed(Failure::Limit(Limit::Targets)));
}

#[test]
fn d191_targets_bound_counts_each_name_looked_up() {
    // netmeister.org's servers are lame: the name of a server after the first is past the bound.
    let capture = recursion::Resolution::read("glueless");
    let limits = Limits {
        targets: 1,
        ..Limits::default()
    };
    let change = |zone: &Name<'_>, response: &mut Message<'static>| {
        if is(zone, "netmeister.org.") {
            response.header.flags = response.header.flags.without(Flags::AA);
        }
    };
    let (outcome, _) = changed(&capture, &caches(false), limits, &change);
    assert_eq!(outcome, Outcome::Failed(Failure::Limit(Limit::Targets)));
}

#[test]
fn rfc2308_5_a_denial_without_the_soa_of_the_zone_asked_is_not_taken() {
    // google.com's denial holds com's SOA, not its own: no server of google.com gives a usable answer.
    let capture = recursion::Resolution::read("nodata-unsigned");
    let com = (capture.exchanges.iter())
        .find(|e| is(&e.zone, "com."))
        .map(|e| e.zone.clone())
        .expect("com's exchange");
    let change = |zone: &Name<'_>, response: &mut Message<'static>| {
        if is(zone, "google.com.") {
            for record in &mut response.authority {
                record.name = com.clone();
            }
        }
    };
    let (outcome, _) = changed(&capture, &caches(false), Limits::default(), &change);
    assert_eq!(outcome, Outcome::Failed(Failure::Unusable));
}

#[test]
fn rfc6672_2_2_a_dname_making_a_name_too_long_is_yxdomain() {
    // dns.netmeister.org answers YXDOMAIN with its DNAME, after one sideways and one out of the zone asked, to a
    // name under it: YXDOMAIN when the synthesis is longer than 255 bytes, wrong otherwise.
    let capture = recursion::Resolution::read("dname");
    let at_dname = response(
        &capture,
        "dns.netmeister.org.",
        "www.dname.dns.netmeister.org.",
    );
    let captured_dname = (at_dname.answer.iter())
        .find(|r| r.rtype() == RecordType::DNAME)
        .expect("a DNAME");
    // Its target, netmeister.org, made longer than its owner: the synthesis lengthens a name by 77 - 26 = 51 bytes.
    let target = name(&format!("{}.netmeister.org.", "t".repeat(60)));
    let mut buf = [0; 255];
    let wire = target.to_wire(&mut buf);
    let data = RData::Opaque(Opaque::new(RecordType::DNAME, wire).expect("a DNAME target"));
    let dname =
        |owner: Name<'static>| Record::new(owner, captured_dname.class, captured_dname.ttl, &data);
    let real = dname(captured_dname.name.clone());
    assert_eq!((real.name.wire_len(), target.wire_len()), (26, 77));
    let answer = vec![
        dname(name("other.dns.netmeister.org.")),
        dname(name("netmeister.org.")),
        real.clone(),
    ];
    let resolve = |length: usize| {
        // `length` bytes of wire: labels "a", and one "bb" when the length is odd.
        let filler = length - real.name.wire_len();
        let mut labels = ["a"].repeat(filler / 2);
        if filler % 2 == 1 {
            labels[0] = "bb";
        }
        let long = name(&format!("{}.{}", labels.join("."), real.name));
        assert_eq!(long.wire_len(), length);
        let caches = caches(false);
        steer(&caches, &capture);
        let authorities = Authorities::new([&capture]);
        let server = |query: &Query| {
            if query.question.name != long {
                return Answered::Response(captured(&authorities, query));
            }
            let renamed = Query {
                question: Question::new(capture.name.clone(), capture.rtype),
                ..query.clone()
            };
            let mut response = to(captured(&authorities, &renamed), &query.question);
            if is(&query.zone, "dns.netmeister.org.") {
                response.answer.clone_from(&answer);
                response.set_rcode(Rcode::YXDOMAIN).expect("a 4-bit rcode");
            }
            Answered::Response(response)
        };
        let question = Question::new(long.clone(), RecordType::A);
        let mut resolution =
            Resolution::start(question, caches, at(&capture), Limits::default()).expect("IN");
        run(&mut resolution, &server, at(&capture)).0
    };
    // 205 + 51 = 256 bytes: too long, said by the DNAME of the zone asked above the name.
    let Outcome::YxDomain { chain } = resolve(205) else {
        panic!("{:?}", resolve(205));
    };
    let owners: Vec<&Name<'static>> = chain.iter().map(|held| held.rrset.owner()).collect();
    assert_eq!(owners, [&real.name]);
    // 204 + 51 = 255 bytes: the synthesis fits, YXDOMAIN is wrong.
    assert_eq!(resolve(204), Outcome::Failed(Failure::Unusable));
}

#[test]
fn rfc1034_4_3_2_a_chain_cut_short_is_followed_from_its_end() {
    // netmeister.org answers www.netmeister.org with its CNAME to panix.netmeister.org, without the address.
    let capture = recursion::Resolution::read("dname");
    let change = |zone: &Name<'_>, response: &mut Message<'static>| {
        if is(zone, "netmeister.org.") {
            response
                .answer
                .retain(|r| is(&r.name, "www.netmeister.org."));
        }
    };
    let (_, sent) = changed(&capture, &caches(false), Limits::default(), &change);
    let panix = ("panix.netmeister.org.".to_owned(), RecordType::A);
    assert!(
        sent.iter().any(|s| (s.1.to_string(), s.2) == panix),
        "{sent:?}"
    );
}

#[test]
fn d193_the_cname_owning_the_name_asked_ranks_authoritative() {
    let (outcome, _) = limited("cname", Limits::default());
    let Outcome::Answer { chain, .. } = outcome else {
        panic!("{outcome:?}");
    };
    let ranks: Vec<Rank> = chain.iter().map(|held| held.rank).collect();
    assert_eq!(ranks.first(), Some(&Rank::AnswerAuthoritative), "{ranks:?}");
}

/// What the infrastructure cache holds of the root server first asked for `unsigned`'s question, after its
/// exchange ends as `answered` makes it.
struct After {
    /// The timeout of the first query.
    first: Duration,
    /// The server's timeout after; `None` when it is not asked again.
    timeout: Option<Duration>,
    /// Whether it is lame for the root: a server not heard is chosen over it.
    lame: bool,
}

fn after(answered: &dyn Fn(&Query, Message<'static>) -> Answered) -> After {
    let capture = recursion::Resolution::read("unsigned");
    let caches = caches(false);
    steer(&caches, &capture);
    let authorities = Authorities::new([&capture]);
    let mut resolution = start(&capture, &caches, Limits::default());
    let mut rng = Seeded(SEED);
    let now = at(&capture);
    let query = match resolution.step(now, &mut rng) {
        Next::Send(query) => Some(query.clone()),
        Next::Done(_) => None,
    };
    let query = query.expect("a query");
    let answered = answered(&query, captured(&authorities, &query));
    resolution.receive(reply(&answered), now);
    let select = |servers: &[SocketAddr], rng: &mut Seeded| {
        let remaining = Duration::from_secs(10);
        caches
            .infra
            .select(servers, &query.zone, remaining, secs(now), rng)
    };
    let unheard = SocketAddr::new(Ipv4Addr::new(192, 0, 2, 1).into(), 53);
    After {
        first: query.timeout,
        timeout: select(&[query.server], &mut rng).map(|choice| choice.timeout),
        lame: select(&[query.server, unheard], &mut rng).map(|choice| choice.server)
            == Some(unheard),
    }
}

#[test]
fn d191_only_a_usable_response_credits_the_server() {
    let unchanged = |answered: &dyn Fn(&Query, Message<'static>) -> Answered| {
        let after = after(answered);
        after.timeout == Some(after.first)
    };
    let backed_off = |answered: &dyn Fn(&Query, Message<'static>) -> Answered| {
        let after = after(answered);
        after.timeout.is_some_and(|timeout| timeout > after.first)
    };
    let rcode = |rcode| {
        move |_: &Query, mut response: Message<'static>| {
            response.set_rcode(rcode).expect("a 4-bit rcode");
            Answered::Response(response)
        }
    };
    // A referral credits its round trip.
    assert!(!unchanged(&|_, response| Answered::Response(response)));
    // A local error is not the server's; a response to another question says nothing of it.
    assert!(unchanged(&|_, _| Answered::LocalError));
    assert!(unchanged(&|_, response| {
        Answered::Response(to(
            response,
            &Question::new(name("example.com."), RecordType::A),
        ))
    }));
    // Timeouts, server errors, REFUSED and SERVFAIL back it off.
    assert!(backed_off(&|_, _| Answered::Timeout));
    assert!(backed_off(&|_, _| Answered::ServerError));
    assert!(backed_off(&rcode(Rcode::REFUSED)));
    assert!(backed_off(&rcode(Rcode::SERVFAIL)));
    // A lame server is asked for the zone only when all are.
    let lame = after(&|_, mut response| {
        response.authority.clear();
        Answered::Response(response)
    });
    assert!(lame.lame);
}

#[test]
fn d193_ns_learned_through_a_cached_delegation_stored_as_of_the_start() {
    // A resolution started two seconds before it runs: google.com's NS, learned from com's servers, is stored as
    // of its start when the cache gave com's delegation, as of now when the root's referral did.
    let capture = recursion::Resolution::read("unsigned");
    let start = at(&capture);
    let later = start + Duration::from_secs(2);
    let ns_ttl = |caches: &Arc<Caches>| {
        steer(caches, &capture);
        let mut resolution = self::start(&capture, caches, Limits::default());
        let authorities = Authorities::new([&capture]);
        let server = |query: &Query| Answered::Response(captured(&authorities, query));
        let (outcome, _) = run(&mut resolution, &server, later);
        assert!(matches!(outcome, Outcome::Answer { .. }), "{outcome:?}");
        let held = caches
            .rrsets
            .get(&capture.name, RecordType::NS, Class::IN, secs(later));
        held.map(|held| held.ttl.get())
            .expect("google.com's NS cached")
    };
    let fresh = ns_ttl(&caches(false));
    let cached = caches(false);
    let com = response(&capture, ".", "google.com.");
    let sections = [
        (&com.authority, Rank::AuthorityNonAuthoritative),
        (&com.additional, Rank::AdditionalNonAuthoritative),
    ];
    for (section, rank) in sections {
        for set in Rrset::group(section) {
            let stored = cached
                .rrsets
                .insert(set, rank, Checked::Unchecked, secs(start));
            assert!(stored.is_ok(), "{stored:?}");
        }
    }
    let stale = ns_ttl(&cached);
    assert_eq!(stale + 2, fresh);
}
