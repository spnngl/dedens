//! The iteration of a resolution on the captured resolutions of `testdata/recursion/` (D188), each server answering
//! as captured through `Authorities`, the harness acting as the transport: RFC 1034 §5.3.3 (from the closest
//! delegation down the referrals, across CNAMEs), §4.3.2 (referrals down only, whatever the AA bit), RFC 2308 §5
//! (no denial without its SOA), RFC 4035 §3.1.4.1 (a DS asked of the parent), RFC 5452 §5 (a reply shared by the
//! resolutions waiting on one query judges its server once), §9.1 (a response to another
//! question is not read), RFC 6672 §2.2 (a DNAME making a name too long), RFC 6895 §3 (questions not resolved),
//! RFC 8914 §4 (the extended error of a failure), RFC 9471 §2 (glue within the zone asked), and each bound of
//! `Limits` (D191).

use std::cell::{Cell, RefCell};
use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use dedens_cache::{Checked, Config};
use dedens_proto::edns::InfoCode;
use dedens_proto::rdata::{Opaque, RData};
use dedens_proto::{Class, Flags, Message, Name, Question, Rcode, Record, RecordType, Ttl};
use dedens_resolver::{
    Caches, DEFAULT_CAPACITY, Failure, InfraCache, Limit, Limits, Marks, Minimisation, Next, Query,
    Rank, Reply, Resolution, Resolved, Rrset, RrsetCache, Unsupported,
};
use dedens_roots::{RootHints, Tlds};
use dedens_testkit::recursion::{self, Authorities, Exchange};

use crate::seeded::Seeded;

/// A question sent: the zone asked, the name and the type.
pub(crate) type Sent = (Name<'static>, Name<'static>, RecordType);

/// The seed of the draws: of a server per zone, which the steering makes, and of the server names looked up, for
/// which it falls on the names the captures looked up.
const SEED: u64 = 0;

/// Empty caches; the TLD hints when `tlds`.
pub(crate) fn caches(tlds: bool) -> Arc<Caches> {
    configured(tlds, Config::default())
}

/// [`caches`], the `RRset` cache's under `config`.
pub(crate) fn configured(tlds: bool, config: Config) -> Arc<Caches> {
    Arc::new(Caches {
        rrsets: RrsetCache::new(DEFAULT_CAPACITY, config).expect("a valid config"),
        infra: InfraCache::new(InfraCache::DEFAULT_CAPACITY, 64).expect("a valid size"),
        roots: RootHints::bundled().clone(),
        tlds: tlds.then(|| Tlds::bundled().clone()),
    })
}

/// The time of the capture, so that every TTL it holds is fresh.
pub(crate) fn at(capture: &recursion::Resolution) -> Duration {
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
pub(crate) fn steer(caches: &Caches, capture: &recursion::Resolution) {
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

/// The round-trip time the transport reports for every response.
const RTT: Duration = Duration::from_millis(20);

fn secs(now: Duration) -> u32 {
    u32::try_from(now.as_secs()).expect("a capture time within u32")
}

/// How the transport ends an exchange.
pub(crate) enum Answered {
    Response(Message<'static>),
    /// A response over TCP, the query moved there from UDP.
    Moved(Message<'static>),
    Undecodable,
    Timeout,
    ServerError,
    LocalError,
}

/// The authoritative servers and the network: what comes of a query.
pub(crate) type Server<'a> = dyn Fn(&Query) -> Answered + 'a;

/// Runs `resolution` to its end at `now`, each query answered by `server`; the outcome, and the questions sent.
pub(crate) fn run(
    resolution: &mut Resolution,
    server: &Server<'_>,
    now: Duration,
) -> (Resolved, Vec<Sent>) {
    seeded(resolution, server, now, SEED)
}

/// [`run`], drawing from `seed`.
fn seeded(
    resolution: &mut Resolution,
    server: &Server<'_>,
    now: Duration,
    seed: u64,
) -> (Resolved, Vec<Sent>) {
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
            rtt: Some(RTT),
        },
        Answered::Moved(message) => Reply::Response {
            message,
            seen: Marks::default(),
            rtt: None,
        },
        Answered::Undecodable => Reply::Undecodable,
        Answered::Timeout => Reply::Timeout,
        Answered::ServerError => Reply::ServerError,
        Answered::LocalError => Reply::LocalError,
    }
}

/// A resolution of `capture`'s question.
pub(crate) fn start(
    capture: &recursion::Resolution,
    caches: &Arc<Caches>,
    limits: Limits,
) -> Resolution {
    let question = Question::new(capture.name.clone(), capture.rtype);
    Resolution::start(
        question,
        Arc::clone(caches),
        at(capture),
        limits,
        Minimisation::Off,
    )
    .expect("an IN question")
}

/// Starts `capture`'s question on `caches`, steered to its servers, under `limits`, and runs it.
pub(crate) fn resolve(
    capture: &recursion::Resolution,
    caches: &Arc<Caches>,
    limits: Limits,
) -> (Resolved, Vec<Sent>) {
    changed(capture, caches, limits, &|_, _| {})
}

/// Changes the response a server of a zone gives.
pub(crate) type Change<'a> = dyn Fn(&Name<'_>, &mut Message<'static>) + 'a;

/// [`resolve`], each captured response passed through `change` with the zone of the server giving it.
pub(crate) fn changed(
    capture: &recursion::Resolution,
    caches: &Arc<Caches>,
    limits: Limits,
    change: &Change<'_>,
) -> (Resolved, Vec<Sent>) {
    served(capture, caches, &mut start(capture, caches, limits), change)
}

/// Runs `resolution` on `caches`, steered to `capture`'s servers, each captured response passed through `change`.
pub(crate) fn served(
    capture: &recursion::Resolution,
    caches: &Arc<Caches>,
    resolution: &mut Resolution,
    change: &Change<'_>,
) -> (Resolved, Vec<Sent>) {
    steer(caches, capture);
    let authorities = Authorities::new([capture]);
    let server = |query: &Query| {
        let mut response = captured(&authorities, query);
        change(&query.zone, &mut response);
        Answered::Response(response)
    };
    run(resolution, &server, at(capture))
}

/// Whether `zone` is the zone written `text`.
pub(crate) fn is(zone: &Name<'_>, text: &str) -> bool {
    zone.to_string() == text
}

pub(crate) fn name(text: &str) -> Name<'static> {
    text.parse().expect("a name")
}

/// The response of `capture` to `name` from a server of `zone`.
pub(crate) fn response(
    capture: &recursion::Resolution,
    zone: &str,
    name: &str,
) -> Message<'static> {
    let exchange = (capture.exchanges.iter())
        .find(|e| is(&e.zone, zone) && is(&e.name, name))
        .expect("a captured exchange");
    dedens_testkit::message(&exchange.response)
}

/// `response` as the answer to `question`.
pub(crate) fn to(mut response: Message<'static>, question: &Question<'static>) -> Message<'static> {
    response.questions = vec![question.clone()];
    response
}

/// The response `authorities` captured to `query`, over TCP after a truncated one, as the transport has it.
pub(crate) fn captured(authorities: &Authorities, query: &Query) -> Message<'static> {
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
    for (id, capture) in resolvable() {
        let (outcome, sent) = resolve(&capture, &caches(false), Limits::default());
        assert_eq!(sent, expected(&capture), "{id}");
        let followed = followed(&capture);
        let last = (capture.exchanges.iter().rev())
            .find(|e| e.rtype == capture.rtype && followed.get(&e.zone) == Some(&e.server))
            .expect("an exchange");
        match outcome {
            Resolved::Answer { data, .. } => {
                let captured = answer(last)
                    .into_iter()
                    .find(|set| set.rtype() == capture.rtype);
                assert_eq!(Some(&*data.rrset), captured.as_ref(), "{id}");
            }
            Resolved::NxDomain { soa, .. } => {
                assert!(id.starts_with("nxdomain"), "{id}");
                assert_eq!(soa.rrset.rtype(), RecordType::SOA, "{id}");
            }
            Resolved::NoData { soa, .. } => {
                assert!(id.starts_with("nodata"), "{id}");
                assert_eq!(soa.rrset.rtype(), RecordType::SOA, "{id}");
            }
            Resolved::YxDomain { .. } => panic!("{id}: {outcome:?}"),
            Resolved::Failed(failure) => panic!("{id}: {failure}"),
        }
    }
}

#[test]
fn rfc1034_5_3_3_the_cache_answers_again() {
    for (id, capture) in resolvable() {
        if id == "dname" {
            continue; // d193_an_address_pinned_to_glue_is_asked_again
        }
        let caches = caches(false);
        let (first, sent) = resolve(&capture, &caches, Limits::default());
        let (again, resent) = resolve(&capture, &caches, Limits::default());
        match first {
            // Positive answers come from the cache whole, chain included.
            Resolved::Answer { .. } => {
                // The cache counts its TTLs down from the least of the RRset's.
                let rrsets = |outcome: &Resolved| match outcome {
                    Resolved::Answer { chain, data, .. } => {
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
    // the glue's rank, which answers no client, so the address is asked of its zone. The CNAME the DNAME
    // synthesized is not cached (RFC 6672 §3.4), so the name is asked first; the rest of the chain is cached.
    let capture = recursion::Resolution::read("dname");
    let caches = caches(false);
    let _ = resolve(&capture, &caches, Limits::default());
    let cname = |owner: &str| {
        let now = secs(at(&capture));
        (caches
            .rrsets
            .get(&name(owner), RecordType::CNAME, Class::IN, now))
        .is_some()
    };
    assert!(!cname("www.dname.dns.netmeister.org."));
    assert!(
        cname("www.dns.netmeister.org."),
        "the CNAME the DNAME leads to"
    );
    let (_, resent) = resolve(&capture, &caches, Limits::default());
    let resent: Vec<_> = (resent.iter().take(2))
        .map(|(zone, name, _)| (zone.to_string(), name.to_string()))
        .collect();
    let asked = |zone: &str, name: &str| (zone.to_owned(), name.to_owned());
    let expected = [
        asked("dns.netmeister.org.", "www.dname.dns.netmeister.org."),
        asked("netmeister.org.", "panix.netmeister.org."),
    ];
    assert_eq!(resent, expected);
}

#[test]
fn rfc1034_5_3_3_a_zone_cached_is_asked_of_its_own_name() {
    // google.com's SRV, a NODATA not cached (recursive step 12), asked again: of the google.com servers the first
    // resolution cached, not com's.
    let capture = recursion::Resolution::read("nodata-unsigned");
    let caches = caches(false);
    let _ = resolve(&capture, &caches, Limits::default());
    let (outcome, sent) = resolve(&capture, &caches, Limits::default());
    assert!(matches!(outcome, Resolved::NoData { .. }), "{outcome:?}");
    let google = name("google.com.");
    assert_eq!(sent, vec![(google.clone(), google, RecordType::SRV)]);
}

#[test]
fn d191_tld_hints_start_below_the_root() {
    let capture = recursion::Resolution::read("unsigned");
    let (_, from_root) = resolve(&capture, &caches(false), Limits::default());
    let (outcome, sent) = resolve(&capture, &caches(true), Limits::default());
    assert!(matches!(outcome, Resolved::Answer { .. }), "{outcome:?}");
    assert_eq!(sent.first().map(|s| s.0.to_string()), Some("com.".into()));
    assert_eq!(sent.len() + 1, from_root.len());
}

/// The DS of the name `capture` asked, asked after it on the same `caches`, each response passed through `change`.
fn ds_after(capture: &recursion::Resolution, change: &Change<'_>) -> (Resolved, Vec<Sent>) {
    let caches = caches(false);
    let (outcome, _) = resolve(capture, &caches, Limits::default());
    assert!(matches!(outcome, Resolved::Answer { .. }), "{outcome:?}");
    let question = Question::new(capture.name.clone(), RecordType::DS);
    let mut resolution = Resolution::start(
        question,
        Arc::clone(&caches),
        at(capture),
        Limits::default(),
        Minimisation::Off,
    )
    .expect("an IN question");
    served(capture, &caches, &mut resolution, change)
}

#[test]
fn rfc4035_3_1_4_1_a_ds_is_asked_of_the_parent() {
    // example.com's servers are cached; its DS is com's to give, as the capture asked it.
    let capture = recursion::Resolution::read("signed-com");
    let (outcome, sent) = ds_after(&capture, &|_, _| {});
    let Resolved::Answer { data, .. } = outcome else {
        panic!("{outcome:?}");
    };
    assert_eq!(data.rrset.rtype(), RecordType::DS);
    assert_eq!(
        sent,
        vec![(name("com."), name("example.com."), RecordType::DS)]
    );
}

#[test]
fn d191_a_ds_referred_to_the_child_is_not_followed() {
    // com's servers answer example.com's DS with the referral to it they give for its A, without its DS: the
    // child's servers have none to give.
    let capture = recursion::Resolution::read("signed-com");
    let mut referral = response(&capture, "com.", "example.com.");
    referral.authority.retain(|r| r.rtype() == RecordType::NS);
    let change = |zone: &Name<'_>, response: &mut Message<'static>| {
        if is(zone, "com.") {
            let asked = response.questions.first().expect("a question").clone();
            *response = to(referral.clone(), &asked);
        }
    };
    let (outcome, sent) = ds_after(&capture, &change);
    assert!(matches!(outcome, Resolved::Failed(_)), "{outcome:?}");
    assert!(sent.iter().all(|(zone, ..)| is(zone, "com.")), "{sent:?}");
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
            Minimisation::Off,
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
    // An RRSIG is part of the RRset it covers (D176), never an answer of its own.
    let rrsig = recursion::Resolution::read("rrsig");
    assert_eq!(
        start(&rrsig.name.to_string(), rrsig.rtype, Class::IN),
        Some(Unsupported::Type(RecordType::RRSIG))
    );
}

/// The captures a resolution takes: all but the RRSIG question's, refused at the start
/// (`rfc6895_3_meta_types_and_other_classes_are_not_resolved`).
pub(crate) fn resolvable() -> Vec<(String, recursion::Resolution)> {
    let mut all = recursion::Resolution::all();
    all.retain(|(_, capture)| capture.rtype != RecordType::RRSIG);
    all
}

/// The outcome of `id` under `limits`, and the queries sent.
pub(crate) fn limited(id: &str, limits: Limits) -> (Resolved, usize) {
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
    assert_eq!(outcome, Resolved::Failed(Failure::Limit(Limit::Queries)));
    assert_eq!(sent, 2);
}

#[test]
fn d191_referrals_bound() {
    let limits = Limits {
        referrals: 1,
        ..Limits::default()
    };
    let (outcome, sent) = limited("unsigned", limits);
    assert_eq!(outcome, Resolved::Failed(Failure::Limit(Limit::Referrals)));
    assert_eq!(sent, 2);
}

/// Resolves a name 40 labels below google.com, each zone from google.com down referring to the next one down with
/// two servers, `lame` making the first asked of each zone below google.com lame.
fn deep(lame: bool) -> (Resolved, Vec<Sent>) {
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
    let mut resolution = Resolution::start(
        question,
        caches,
        at(&capture),
        Limits::default(),
        Minimisation::Off,
    )
    .expect("IN");
    run(&mut resolution, &server, at(&capture))
}

#[test]
fn d191_referrals_default_bound() {
    // The root's referral, com's, then one per zone from google.com down: the 31st is past the bound.
    let (outcome, sent) = deep(false);
    assert_eq!(outcome, Resolved::Failed(Failure::Limit(Limit::Referrals)));
    assert_eq!(sent.len(), Limits::default().referrals + 1);
}

#[test]
fn d191_queries_default_bound() {
    // Two queries per zone below google.com, the first lame: the 33rd query is past the bound, at the 17th
    // referral.
    let (outcome, sent) = deep(true);
    assert_eq!(outcome, Resolved::Failed(Failure::Limit(Limit::Queries)));
    assert_eq!(sent.len(), Limits::default().queries);
}

#[test]
fn d191_restarts_bound() {
    // www.microsoft.com goes through two CNAMEs.
    let (outcome, _) = limited("cname", Limits::default());
    let Resolved::Answer { chain, .. } = outcome else {
        panic!("{outcome:?}");
    };
    let restarts = |restarts| {
        let limits = Limits {
            restarts,
            ..Limits::default()
        };
        limited("cname", limits).0
    };
    assert!(matches!(restarts(chain.len()), Resolved::Answer { .. }));
    assert_eq!(
        restarts(chain.len() - 1),
        Resolved::Failed(Failure::Limit(Limit::Restarts))
    );
}

#[test]
fn d191_restarts_bound_counts_a_dname_and_its_cname_once() {
    // www.dname.dns.netmeister.org goes through a DNAME, the CNAME synthesized from it, then CNAMEs: one hop per
    // CNAME, the DNAME's included.
    let (outcome, _) = limited("dname", Limits::default());
    let Resolved::Answer { chain, .. } = outcome else {
        panic!("{outcome:?}")
    };
    let cnames = (chain.iter())
        .filter(|held| held.rrset.rtype() == RecordType::CNAME)
        .count();
    assert!(
        chain
            .iter()
            .any(|held| held.rrset.rtype() == RecordType::DNAME),
        "{chain:?}"
    );
    let restarts = |restarts| {
        let limits = Limits {
            restarts,
            ..Limits::default()
        };
        limited("dname", limits).0
    };
    assert!(matches!(restarts(cnames), Resolved::Answer { .. }));
    assert_eq!(
        restarts(cnames - 1),
        Resolved::Failed(Failure::Limit(Limit::Restarts))
    );
}

#[test]
fn d191_restarts_default_bound_counts_the_cnames_of_a_response() {
    // microsoft.com answers www.microsoft.com with a chain of `hops` CNAMEs within it, then the address, and each
    // name of the chain with the rest of it: the scrubber keeps 11 hops of a response, the next is asked again.
    let capture = recursion::Resolution::read("cname");
    let chain = |hops: usize| {
        let change = |zone: &Name<'_>, response: &mut Message<'static>| {
            if !is(zone, "microsoft.com.") {
                return;
            }
            let asked = response.questions.first().expect("a question").clone();
            *response = to(
                self::response(&capture, "microsoft.com.", "www.microsoft.com."),
                &asked,
            );
            let cname = response.answer.first().expect("a CNAME").clone();
            let names: Vec<Name<'static>> = std::iter::once(cname.name.clone())
                .chain((1..=hops).map(|i| name(&format!("c{i}.microsoft.com."))))
                .collect();
            let from = (names.iter().position(|n| *n == asked.name)).expect("a name of the chain");
            let record = |owner: &Name<'static>, data| {
                Record::new(owner.clone(), cname.class, cname.ttl, &data)
            };
            response.answer = (names[from..].windows(2))
                .map(|pair| record(&pair[0], RData::Cname(pair[1].clone())))
                .collect();
            let last = names.last().expect("the chain's end");
            (response.answer).push(record(last, RData::A(Ipv4Addr::new(192, 0, 2, 1))));
        };
        changed(&capture, &caches(false), Limits::default(), &change).0
    };
    let restarts = Limits::default().restarts;
    let Resolved::Answer { chain: kept, .. } = chain(restarts) else {
        panic!("{:?}", chain(restarts));
    };
    let owners: Vec<String> = kept
        .iter()
        .map(|held| held.rrset.owner().to_string())
        .collect();
    let names = (1..restarts).map(|i| format!("c{i}.microsoft.com."));
    let expected: Vec<String> = std::iter::once("www.microsoft.com.".to_owned())
        .chain(names)
        .collect();
    assert_eq!(owners, expected);
    assert_eq!(
        chain(restarts + 1),
        Resolved::Failed(Failure::Limit(Limit::Restarts))
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
    assert_eq!(outcome, Resolved::Failed(Failure::Limit(Limit::Depth)));
    assert_eq!(sent, 2);
}

#[test]
fn d191_targets_bound() {
    let limits = Limits {
        targets: 0,
        ..Limits::default()
    };
    let (outcome, sent) = limited("glueless", limits);
    assert_eq!(outcome, Resolved::Failed(Failure::Limit(Limit::Targets)));
    assert_eq!(sent, 2);
}

/// Runs the question of `unsigned` under `limits`, every exchange ending as `answered` makes it.
fn unreached(limits: Limits, answered: fn() -> Answered) -> (Resolved, usize) {
    let capture = recursion::Resolution::read("unsigned");
    let mut resolution = start(&capture, &caches(false), limits);
    let (outcome, sent) = run(&mut resolution, &|_| answered(), at(&capture));
    (outcome, sent.len())
}

/// Runs the question of `unsigned` with every query timing out, under `limits`.
pub(crate) fn unanswered(limits: Limits) -> (Resolved, usize) {
    unreached(limits, || Answered::Timeout)
}

#[test]
fn d191_servers_bound() {
    // The root hints give 26 addresses.
    let (outcome, sent) = unanswered(Limits::default());
    assert_eq!(outcome, Resolved::Failed(Failure::Limit(Limit::Servers)));
    assert_eq!(sent, Limits::default().servers);
}

/// A server timed out and asked again counts against `Limits::servers`, as a server first asked does (D196).
#[test]
fn d196_a_server_asked_again_counts_against_the_servers_bound() {
    // The root hints give 26 addresses, each timing out: one more is a server asked again.
    let servers = 27;
    let (outcome, sent) = unanswered(Limits {
        servers,
        ..Limits::default()
    });
    assert_eq!(outcome, Resolved::Failed(Failure::Limit(Limit::Servers)));
    assert_eq!(sent, servers);
}

/// Resolves `unsigned`'s question with com's referral to google.com naming `glued` servers with an IPv4 glue each,
/// the first an IPv6 one too, and ns.example.net without glue, whose lookup gives one IPv4 address; every server of
/// google.com fails, a server error, which is not asked again as a timeout is (D196).
fn spent(glued: usize) -> (Resolved, Vec<Sent>) {
    let capture = recursion::Resolution::read("unsigned");
    let google = name("google.com.");
    let unglued = name("ns.example.net.");
    let caches = caches(false);
    steer(&caches, &capture);
    let authorities = Authorities::new([&capture]);
    let template = response(&capture, "com.", "google.com.");
    let question = Question::new(capture.name.clone(), capture.rtype);
    let addresses: Vec<Ipv4Addr> = (1..=glued)
        .map(|i| Ipv4Addr::new(192, 0, 2, u8::try_from(i).expect("a byte")))
        .collect();
    let mut to_google = referral(&template, &question, &google, &addresses);
    let ns = to_google.authority[0].clone();
    let glue = to_google.additional[0].clone();
    let v6 = RData::Aaaa(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1));
    (to_google.additional).push(Record::new(glue.name.clone(), glue.class, glue.ttl, &v6));
    let data = RData::Ns(unglued.clone());
    (to_google.authority).push(Record::new(ns.name.clone(), ns.class, ns.ttl, &data));
    let mut found = template.clone();
    found.header.flags = found.header.flags.with(Flags::AA);
    found.authority.clear();
    found.additional.clear();
    let address = RData::A(Ipv4Addr::new(192, 0, 2, 100));
    found.answer = vec![Record::new(unglued.clone(), glue.class, glue.ttl, &address)];
    let server = |query: &Query| {
        let question = &query.question;
        if query.zone == google {
            Answered::ServerError
        } else if question.name == unglued && question.qtype == RecordType::A {
            Answered::Response(to(found.clone(), question))
        } else if is(&query.zone, "com.") {
            Answered::Response(to(to_google.clone(), question))
        } else {
            Answered::Response(captured(&authorities, query))
        }
    };
    let mut resolution = start(&capture, &caches, Limits::default());
    run(&mut resolution, &server, at(&capture))
}

#[test]
fn d191_servers_bound_stops_lookups() {
    // 13 glued addresses fail: the unglued name is not looked up.
    let servers = Limits::default().servers;
    let google = name("google.com.");
    let (outcome, sent) = spent(servers - 1);
    assert_eq!(outcome, Resolved::Failed(Failure::Limit(Limit::Servers)));
    assert_eq!(looked_up(&sent), [], "{sent:?}");
    assert_eq!(sent.iter().filter(|s| s.0 == google).count(), servers);
    // 12, then the address looked up: its AAAA is not looked up.
    let (outcome, sent) = spent(servers - 2);
    assert_eq!(outcome, Resolved::Failed(Failure::Limit(Limit::Servers)));
    let lookup = ("ns.example.net.".to_owned(), RecordType::A);
    assert_eq!(looked_up(&sent), [lookup], "{sent:?}");
    assert_eq!(sent.iter().filter(|s| s.0 == google).count(), servers);
}

#[test]
fn rfc8914_4_no_server_answering_is_no_reachable_authority() {
    let limits = Limits {
        queries: 1000,
        servers: 1000,
        ..Limits::default()
    };
    let roots: usize = (RootHints::bundled().servers().iter())
        .map(|s| s.addresses().count())
        .sum();
    // Each asked until the infra cache skips it (D196).
    let (outcome, sent) = unanswered(limits);
    assert_eq!(outcome, Resolved::Failed(Failure::Unreachable));
    assert_eq!(
        Failure::Unreachable.info_code(),
        InfoCode::NO_REACHABLE_AUTHORITY
    );
    assert_eq!(sent, roots * usize::from(InfraCache::TIMEOUT_LIMIT));
    // Exchanges failing, on the network or here, are a network error.
    for answered in [|| Answered::ServerError, || Answered::LocalError] {
        let (outcome, sent) = unreached(limits, answered);
        assert_eq!(outcome, Resolved::Failed(Failure::Network));
        assert_eq!(sent, roots);
    }
    // Responses that do not decode are servers answering: no network error.
    let (outcome, _) = unreached(limits, || Answered::Undecodable);
    assert_eq!(outcome, Resolved::Failed(Failure::Unusable));
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
        queries: 1000,
        servers: 1000,
        ..Limits::default()
    };
    let (outcome, _) = run(&mut start(&capture, &caches, limits), &server, at(&capture));
    assert_eq!(outcome, Resolved::Failed(Failure::Unreachable));
}

#[test]
fn rfc1035_7_2_a_server_timing_out_is_asked_again_before_a_name_is_looked_up() {
    // D196: microsoft.com's one glued server times out once; it is asked again, and its servers without glue are
    // not looked up.
    let capture = recursion::Resolution::read("truncated");
    let caches = caches(false);
    steer(&caches, &capture);
    let authorities = Authorities::new([&capture]);
    let microsoft = name("microsoft.com.");
    let lost = Cell::new(false);
    let asked = RefCell::new(Vec::new());
    let server = |query: &Query| {
        if query.zone == microsoft {
            asked.borrow_mut().push(query.server);
            if !lost.replace(true) {
                return Answered::Timeout;
            }
        }
        Answered::Response(captured(&authorities, query))
    };
    let limits = Limits::default();
    let (outcome, sent) = run(&mut start(&capture, &caches, limits), &server, at(&capture));
    assert!(matches!(outcome, Resolved::Answer { .. }), "{outcome:?}");
    assert!(sent.iter().all(|s| s.1 == microsoft), "{sent:?}");
    let asked = asked.into_inner();
    assert_eq!(asked.len(), 2, "{asked:?}");
    assert_eq!(asked[0], asked[1]);
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
    assert_eq!(outcome, Resolved::Failed(Failure::Limit(Limit::Time)));
    assert_eq!(sent, []);
}

/// A query moved to TCP that times out there leaves the server's time over UDP as it was: the next query to it
/// waits as long, where a timeout over UDP doubles the wait (RFC 6298 §5.5), and the next server is asked.
#[test]
fn d197_a_tcp_timeout_does_not_back_off_the_server() {
    let capture = recursion::Resolution::read("unsigned");
    let now = at(&capture);
    let waits = [Reply::Timeout, Reply::TcpTimeout].map(|reply| {
        let caches = caches(false);
        let mut resolution = start(&capture, &caches, Limits::default());
        let mut rng = Seeded(SEED);
        let Next::Send(query) = resolution.step(now, &mut rng) else {
            panic!("a query");
        };
        let query = query.clone();
        resolution.receive(reply, now + query.timeout);
        let Next::Send(next) = resolution.step(now + query.timeout, &mut rng) else {
            panic!("a query");
        };
        assert_ne!(next.server, query.server);
        let again = caches.infra.select(
            &[query.server],
            &query.zone,
            Duration::MAX,
            secs(now + query.timeout),
            &mut rng,
        );
        (query.timeout, again.expect("a server").timeout)
    });
    let [(sent, udp), (tcp_sent, tcp)] = waits;
    assert_eq!((udp, tcp), (sent * 2, tcp_sent));
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
    assert_eq!(outcome, Resolved::Failed(Failure::Limit(Limit::Time)));
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
) -> (Resolved, Vec<Sent>) {
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
fn nxns(count: usize, limits: Limits) -> (Resolved, Vec<Sent>) {
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
    assert_eq!(outcome, Resolved::Failed(Failure::Limit(Limit::Targets)));
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
    assert_eq!(outcome, Resolved::Failed(Failure::Unreachable));
    let names: HashSet<String> = looked_up(&sent).into_iter().map(|(name, _)| name).collect();
    assert_eq!(names.len(), limits.servers);
    assert_eq!(sent.len(), 2 + 1 + limits.servers, "{sent:?}");
}

/// google.com's four servers, named in google.com, which com's referral gives without glue: reachable only through
/// google.com, com's referral leading back to it.
fn looping(seed: u64) -> (Resolved, Vec<Sent>) {
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
    assert_eq!(outcome, Resolved::Failed(Failure::Unreachable));
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
        assert_eq!(outcome, Resolved::Failed(Failure::Unusable));
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
    let failed = Resolved::Failed(Failure::Limit(Limit::Servers));
    assert_eq!(lame("com."), (failed, servers, servers + 1));
    // Each of google.com's eight addresses is lame: none answers.
    assert_eq!(
        lame("google.com."),
        (Resolved::Failed(Failure::Unusable), 8, 10)
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
    assert!(matches!(outcome, Resolved::Answer { .. }), "{outcome:?}");
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
    assert!(matches!(outcome, Resolved::Failed(_)), "{outcome:?}");
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
    assert!(matches!(outcome, Resolved::Answer { .. }), "{outcome:?}");
    assert_eq!(sent, expected(&capture));
}

#[test]
fn d191_an_address_given_twice_is_asked_once() {
    // com's referral gives each server of google.com the address of the one followed; it fails (a timeout would
    // have it asked again, D196).
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
            return Answered::ServerError;
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
    assert_eq!(outcome, Resolved::Failed(Failure::Network));
    assert_eq!(sent.iter().filter(|s| s.0 == google).count(), 1, "{sent:?}");
}

/// An address of each range a resolution does not ask by default (D191): loopback, "this network", private,
/// shared, link-local, IETF protocol assignments, benchmarking, multicast, reserved, broadcast, site-local, every
/// IPv4-mapped one (a public one too), IPv4-compatible ones, and a NAT64 or 6to4 one embedding a non-global IPv4,
/// 10.1.2.3 among them, which misread in the wrong byte order or segments (2.3.10.1, 2.3.0.0) is global.
const LOCAL: [IpAddr; 32] = [
    IpAddr::V4(Ipv4Addr::new(127, 0, 0, 53)),
    IpAddr::V4(Ipv4Addr::new(0, 1, 2, 3)),
    IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
    IpAddr::V4(Ipv4Addr::new(172, 31, 0, 1)),
    IpAddr::V4(Ipv4Addr::new(192, 168, 0, 1)),
    IpAddr::V4(Ipv4Addr::new(100, 127, 0, 1)),
    IpAddr::V4(Ipv4Addr::new(169, 254, 0, 1)),
    IpAddr::V4(Ipv4Addr::new(192, 0, 0, 9)),
    IpAddr::V4(Ipv4Addr::new(224, 0, 0, 251)),
    IpAddr::V4(Ipv4Addr::new(240, 0, 0, 1)),
    IpAddr::V4(Ipv4Addr::BROADCAST),
    IpAddr::V4(Ipv4Addr::new(198, 18, 0, 1)),
    IpAddr::V4(Ipv4Addr::new(198, 19, 255, 1)),
    IpAddr::V6(Ipv6Addr::LOCALHOST),
    IpAddr::V6(Ipv6Addr::UNSPECIFIED),
    IpAddr::V6(Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 1)),
    IpAddr::V6(Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 1)),
    IpAddr::V6(Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 0, 0xfb)),
    IpAddr::V6(Ipv4Addr::LOCALHOST.to_ipv6_mapped()),
    IpAddr::V6(Ipv4Addr::new(192, 168, 0, 1).to_ipv6_mapped()),
    IpAddr::V6(Ipv4Addr::new(100, 64, 0, 1).to_ipv6_mapped()),
    IpAddr::V6(Ipv4Addr::new(224, 0, 0, 1).to_ipv6_mapped()),
    IpAddr::V6(Ipv4Addr::new(192, 0, 2, 1).to_ipv6_mapped()),
    IpAddr::V6(Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0xc000, 0x201)),
    IpAddr::V6(Ipv6Addr::new(0xfec0, 0, 0, 0, 0, 0, 0, 1)),
    IpAddr::V6(Ipv6Addr::new(0x64, 0xff9b, 0, 0, 0, 0, 0x7f00, 1)),
    IpAddr::V6(Ipv6Addr::new(0x64, 0xff9b, 0, 0, 0, 0, 0xa00, 1)),
    IpAddr::V6(Ipv6Addr::new(0x64, 0xff9b, 0, 0, 0, 0, 0xa01, 0x203)),
    IpAddr::V6(Ipv6Addr::new(0x64, 0xff9b, 1, 0, 0, 0, 0xc000, 0x201)),
    IpAddr::V6(Ipv6Addr::new(0x2002, 0x7f00, 1, 0, 0, 0, 0, 1)),
    IpAddr::V6(Ipv6Addr::new(0x2002, 0xa00, 1, 0, 0, 0, 0, 1)),
    IpAddr::V6(Ipv6Addr::new(0x2002, 0xa01, 0x203, 0, 0, 0, 0, 1)),
];

/// `unsigned`, com's referral to google.com giving its servers the addresses of [`LOCAL`] as glue, which fail:
/// the outcome under `limits`, `ask` for [`Resolution::asking_local_addresses`], and the addresses of google.com
/// asked.
fn local(limits: Limits, ask: bool) -> (Resolved, Vec<IpAddr>) {
    let capture = recursion::Resolution::read("unsigned");
    let google = name("google.com.");
    let caches = caches(false);
    let authorities = Authorities::new([&capture]);
    steer(&caches, &capture);
    let asked = RefCell::new(Vec::new());
    let server = |query: &Query| {
        if query.zone == google {
            asked.borrow_mut().push(query.server.ip());
            return Answered::ServerError;
        }
        let mut response = captured(&authorities, query);
        if is(&query.zone, "com.") {
            glued(&mut response, &LOCAL);
        }
        Answered::Response(response)
    };
    let mut resolution = start(&capture, &caches, limits).asking_local_addresses(ask);
    let (outcome, _) = run(&mut resolution, &server, at(&capture));
    (outcome, asked.into_inner())
}

/// `referral` with `addresses` for glue in place of its own, given to its servers in turn.
fn glued(referral: &mut Message<'static>, addresses: &[IpAddr]) {
    let glue = referral.additional[0].clone();
    let servers: Vec<Name<'static>> = (referral.authority.iter())
        .filter_map(|r| match r.data() {
            RData::Ns(server) => Some(server.into_owned()),
            _ => None,
        })
        .collect();
    referral.additional = (addresses.iter().zip(servers.iter().cycle()))
        .map(|(&address, server)| {
            let data = match address {
                IpAddr::V4(v4) => RData::A(v4),
                IpAddr::V6(v6) => RData::Aaaa(v6),
            };
            Record::new(server.clone(), glue.class, glue.ttl, &data)
        })
        .collect();
}

#[test]
fn d191_a_server_at_a_local_address_is_not_asked() {
    let (outcome, asked) = local(Limits::default(), false);
    assert_eq!(outcome, Resolved::Failed(Failure::Unreachable));
    assert_eq!(asked, Vec::<IpAddr>::new());
}

#[test]
fn d191_a_server_at_a_local_address_is_asked_when_set() {
    let limits = Limits {
        servers: LOCAL.len(),
        queries: LOCAL.len() + 8,
        ..Limits::default()
    };
    let (outcome, asked) = local(limits, true);
    assert_eq!(outcome, Resolved::Failed(Failure::Network));
    let asked: HashSet<IpAddr> = asked.into_iter().collect();
    assert_eq!(asked, HashSet::from(LOCAL));
}

#[test]
fn d191_an_address_just_outside_the_local_ranges_is_asked() {
    // The neighbours of the ranges' edges: 172.32/12's first, 100.128/10's, 192.0.1.0, 198.17/16's last and
    // 198.20/16's first, fbff::, ::1:0:0 above the IPv4-compatible, 64:ff9b:2:: past the local-use NAT64; and the
    // NAT64 and 6to4 addresses embedding a global IPv4 (192.0.2.1, and 8.0.0.10, which misread in the wrong byte
    // order, 0.10.8.0, is "this network").
    let outside = [
        IpAddr::V4(Ipv4Addr::new(198, 17, 255, 1)),
        IpAddr::V4(Ipv4Addr::new(198, 20, 0, 1)),
        IpAddr::V6(Ipv6Addr::new(0, 0, 0, 0, 0, 1, 0, 1)),
        IpAddr::V6(Ipv6Addr::new(0x64, 0xff9b, 2, 0, 0, 0, 0, 1)),
        IpAddr::V6(Ipv6Addr::new(0x64, 0xff9b, 0, 0, 0, 0, 0xc000, 0x201)),
        IpAddr::V6(Ipv6Addr::new(0x2002, 0xc000, 0x201, 0, 0, 0, 0, 1)),
        IpAddr::V6(Ipv6Addr::new(0x64, 0xff9b, 0, 0, 0, 0, 0x800, 0xa)),
        IpAddr::V6(Ipv6Addr::new(0x2002, 0x800, 0xa, 0, 0, 0, 0, 1)),
        IpAddr::V4(Ipv4Addr::new(172, 32, 0, 1)),
        IpAddr::V4(Ipv4Addr::new(100, 128, 0, 1)),
        IpAddr::V4(Ipv4Addr::new(100, 63, 255, 1)),
        IpAddr::V4(Ipv4Addr::new(192, 0, 1, 1)),
        IpAddr::V4(Ipv4Addr::new(223, 255, 255, 1)),
        IpAddr::V6(Ipv6Addr::new(0xfbff, 0, 0, 0, 0, 0, 0, 1)),
    ];
    let capture = recursion::Resolution::read("unsigned");
    let google = name("google.com.");
    let caches = caches(false);
    let authorities = Authorities::new([&capture]);
    steer(&caches, &capture);
    let asked = RefCell::new(HashSet::new());
    let server = |query: &Query| {
        if query.zone == google {
            asked.borrow_mut().insert(query.server.ip());
            return Answered::ServerError;
        }
        let mut response = captured(&authorities, query);
        if is(&query.zone, "com.") {
            glued(&mut response, &outside);
        }
        Answered::Response(response)
    };
    let limits = Limits {
        servers: outside.len(),
        queries: outside.len() + 8,
        ..Limits::default()
    };
    run(&mut start(&capture, &caches, limits), &server, at(&capture));
    assert_eq!(asked.into_inner(), HashSet::from(outside));
}

#[test]
fn d191_an_address_looked_up_after_it_was_asked_is_not_asked_again() {
    // `glueless`, gandi.net giving each server of netmeister.org ns-143-b.gandi.net's addresses, which fail (a
    // timeout would have them asked again, D196): each is asked once, though every name looked up gives it again.
    let capture = recursion::Resolution::read("glueless");
    let caches = caches(false);
    steer(&caches, &capture);
    let authorities = Authorities::new([&capture]);
    let server = |query: &Query| {
        if is(&query.zone, "netmeister.org.") {
            return Answered::ServerError;
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
    assert!(matches!(outcome, Resolved::Answer { .. }), "{outcome:?}");
    assert_eq!(sent, expected(&capture));
}

#[test]
fn rfc1034_5_3_3_a_server_without_glue_is_looked_up_beside_one_with() {
    // org's referral to netmeister.org naming ns-143-b.gandi.net, and panix.netmeister.org with its glue (as
    // netmeister.org gives it in `dname`), which does not answer: only ns-143-b.gandi.net's own address may stand
    // for it, so it is looked up and asked.
    let capture = recursion::Resolution::read("glueless");
    let panix = (recursion::Resolution::read("dname").exchanges.iter())
        .flat_map(|exchange| dedens_testkit::message(&exchange.response).additional)
        .find(|r| r.rtype() == RecordType::A && is(&r.name, "panix.netmeister.org."))
        .expect("panix.netmeister.org's glue");
    let silent = address(&panix).expect("an address");
    let caches = caches(false);
    steer(&caches, &capture);
    let authorities = Authorities::new([&capture]);
    let server = |query: &Query| {
        if query.server.ip() == silent {
            return Answered::Timeout;
        }
        let mut response = captured(&authorities, query);
        if is(&query.zone, "org.") && response.referral().is_some() {
            let ns = (response.authority.iter())
                .find(|r| r.rtype() == RecordType::NS)
                .expect("an NS record")
                .clone();
            let gandi = name("ns-143-b.gandi.net.");
            response.authority.retain(|r| r.rtype() != RecordType::NS);
            for server in [gandi, panix.name.clone()] {
                let data = RData::Ns(server);
                (response.authority).push(Record::new(ns.name.clone(), ns.class, ns.ttl, &data));
            }
            response.additional.push(panix.clone());
        }
        Answered::Response(response)
    };
    let (outcome, sent) = run(
        &mut start(&capture, &caches, Limits::default()),
        &server,
        at(&capture),
    );
    assert!(matches!(outcome, Resolved::Answer { .. }), "{outcome:?}");
    let lookup = ("ns-143-b.gandi.net.".to_owned(), RecordType::A);
    assert!(
        sent.iter().any(|s| (s.1.to_string(), s.2) == lookup),
        "{sent:?}"
    );
}

/// `glueless`, gandi.net's servers not answering the A lookup of ns-143-b.gandi.net, under `limits`.
fn without_ipv4(limits: Limits) -> (Resolved, Vec<Sent>) {
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
    assert!(matches!(outcome, Resolved::Answer { .. }), "{outcome:?}");
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
    assert_eq!(outcome, Resolved::Failed(Failure::Limit(Limit::Targets)));
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
    assert_eq!(outcome, Resolved::Failed(Failure::Limit(Limit::Targets)));
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
    assert_eq!(outcome, Resolved::Failed(Failure::Unusable));
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
        let mut resolution = Resolution::start(
            question,
            caches,
            at(&capture),
            Limits::default(),
            Minimisation::Off,
        )
        .expect("IN");
        run(&mut resolution, &server, at(&capture)).0
    };
    // 205 + 51 = 256 bytes: too long, said by the DNAME of the zone asked above the name.
    let Resolved::YxDomain { chain } = resolve(205) else {
        panic!("{:?}", resolve(205));
    };
    let owners: Vec<&Name<'static>> = chain.iter().map(|held| held.rrset.owner()).collect();
    assert_eq!(owners, [&real.name]);
    // 204 + 51 = 255 bytes: the synthesis fits, YXDOMAIN is wrong.
    assert_eq!(resolve(204), Resolved::Failed(Failure::Unusable));
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
    let Resolved::Answer { chain, .. } = outcome else {
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
    /// Whether it is lame for the root: a server not heard is chosen over it, draw after draw.
    lame: bool,
    /// Whether it is chosen for com, over a server not heard, with the timeout of a server not heard.
    elsewhere: bool,
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
    let com = caches.infra.select(
        &[query.server],
        &name("com."),
        Duration::from_secs(10),
        secs(now),
        &mut rng,
    );
    After {
        first: query.timeout,
        timeout: select(&[query.server], &mut rng).map(|choice| choice.timeout),
        lame: (0..16).all(|_| {
            select(&[query.server, unheard], &mut rng).map(|choice| choice.server) == Some(unheard)
        }),
        elsewhere: com.is_some_and(|choice| choice.timeout == query.timeout),
    }
}

/// The timeout a server is given after one response in `rtt`.
fn credited(rtt: Duration) -> Option<Duration> {
    let infra = InfraCache::new(InfraCache::DEFAULT_CAPACITY, 1).expect("a valid size");
    let server = SocketAddr::new(Ipv4Addr::new(192, 0, 2, 1).into(), 53);
    infra.reply(server, rtt, Marks::default(), 0);
    let root = Name::root();
    let choice = infra.select(
        &[server],
        &root,
        Duration::from_secs(10),
        0,
        &mut Seeded(SEED),
    );
    choice.map(|choice| choice.timeout)
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
    // A referral credits the round trip the transport measured (D190), whatever the time since the query was
    // given.
    assert_ne!(credited(RTT), credited(Duration::ZERO));
    assert_eq!(
        after(&|_, response| Answered::Response(response)).timeout,
        credited(RTT)
    );
    // A response over TCP after a move there is a response, whose time is not its UDP time: none credited.
    assert!(unchanged(&|_, response| Answered::Moved(response)));
    // A local error is not the server's; a response to another question says nothing of it.
    assert!(unchanged(&|_, _| Answered::LocalError));
    assert!(unchanged(&|_, response| {
        Answered::Response(to(
            response,
            &Question::new(name("example.com."), RecordType::A),
        ))
    }));
    // Timeouts and server errors back it off.
    assert!(backed_off(&|_, _| Answered::Timeout));
    assert!(backed_off(&|_, _| Answered::ServerError));
    // An undecodable response, REFUSED and SERVFAIL leave it as it was, for this zone and the others, as Unbound's
    // `THROWAWAY`: three of them cannot shut a server out (D191).
    for answered in [
        &(|_: &Query, _| Answered::Undecodable) as &dyn Fn(&Query, Message<'static>) -> Answered,
        &rcode(Rcode::REFUSED),
        &rcode(Rcode::SERVFAIL),
    ] {
        let after = after(answered);
        assert_eq!(after.timeout, Some(after.first));
        assert!(after.elsewhere);
    }
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
        assert!(matches!(outcome, Resolved::Answer { .. }), "{outcome:?}");
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

#[test]
fn d191_a_cached_delegation_with_no_address_to_ask_is_skipped() {
    // The cache holds google.com's NS with glue at local addresses only, as a zone could have made it: the closest
    // delegation is the root's, not that one, and no local address is asked.
    let capture = recursion::Resolution::read("unsigned");
    let caches = caches(false);
    let mut referral = response(&capture, "com.", "google.com.");
    glued(&mut referral, &LOCAL);
    let sections = [
        (&referral.authority, Rank::AuthorityNonAuthoritative),
        (&referral.additional, Rank::AdditionalNonAuthoritative),
    ];
    for (section, rank) in sections {
        for set in Rrset::group(section) {
            let stored = (caches.rrsets).insert(set, rank, Checked::Unchecked, secs(at(&capture)));
            assert!(stored.is_ok(), "{stored:?}");
        }
    }
    steer(&caches, &capture);
    let authorities = Authorities::new([&capture]);
    let asked = RefCell::new(Vec::new());
    let server = |query: &Query| {
        asked.borrow_mut().push(query.server.ip());
        Answered::Response(captured(&authorities, query))
    };
    let (outcome, sent) = run(
        &mut start(&capture, &caches, Limits::default()),
        &server,
        at(&capture),
    );
    assert!(matches!(outcome, Resolved::Answer { .. }), "{outcome:?}");
    assert_eq!(sent.first().map(|s| &s.0), Some(&Name::root()), "{sent:?}");
    assert!(asked.into_inner().iter().all(|a| !LOCAL.contains(a)));
}

#[test]
fn d191_a_cached_delegation_with_no_address_is_skipped_whatever_the_switch() {
    // The cache holds google.com's NS without the addresses of its servers (the glue expired first, or came not at
    // all): with local addresses asked or not, the closest delegation is the root's, not a zone to look up from
    // itself.
    let capture = recursion::Resolution::read("unsigned");
    for ask in [false, true] {
        let caches = caches(false);
        let referral = response(&capture, "com.", "google.com.");
        for set in Rrset::group(&referral.authority) {
            let rank = Rank::AuthorityNonAuthoritative;
            let stored = (caches.rrsets).insert(set, rank, Checked::Unchecked, secs(at(&capture)));
            assert!(stored.is_ok(), "{stored:?}");
        }
        steer(&caches, &capture);
        let authorities = Authorities::new([&capture]);
        let server = |query: &Query| Answered::Response(captured(&authorities, query));
        let mut resolution =
            start(&capture, &caches, Limits::default()).asking_local_addresses(ask);
        let (outcome, sent) = run(&mut resolution, &server, at(&capture));
        assert!(
            matches!(outcome, Resolved::Answer { .. }),
            "{ask}: {outcome:?}"
        );
        assert_eq!(
            sent.first().map(|s| &s.0),
            Some(&Name::root()),
            "{ask}: {sent:?}"
        );
    }
}

#[test]
fn rfc5452_5_a_reply_shared_does_not_judge_the_server_again() {
    // The same query of two resolutions, sent once: the one that waited on it takes the reply without timing the
    // server out a second time (D195).
    let capture = recursion::Resolution::read("unsigned");
    let caches = caches(false);
    let now = at(&capture);
    let mut rng = Seeded(SEED);
    let mut waiter = start(&capture, &caches, Limits::default());
    let Next::Send(first) = waiter.step(now, &mut rng) else {
        panic!("a query")
    };
    let first = first.server;
    waiter.receive_shared(Reply::Timeout, now);
    assert_eq!(caches.infra.len(), 0);
    // It took the timeout all the same: the next query goes to another server.
    let Next::Send(next) = waiter.step(now, &mut rng) else {
        panic!("a query")
    };
    assert_ne!(next.server, first);
    // A response shared credits no server either.
    let referral = response(&capture, ".", &capture.name.to_string());
    let shared = Reply::Response {
        message: &referral,
        seen: Marks::default(),
        rtt: Some(RTT),
    };
    waiter.receive_shared(shared, now);
    assert_eq!(caches.infra.len(), 0);
    let mut sender = start(&capture, &caches, Limits::default());
    assert!(matches!(sender.step(now, &mut rng), Next::Send(_)));
    sender.receive(Reply::Timeout, now);
    assert_eq!(caches.infra.len(), 1);
}

#[test]
fn d195_a_timeout_cut_short_by_the_resolution_s_end_does_not_judge_the_server() {
    // With 10 ms left, the query waits 10 ms, not its server's timeout: its silence is not the server's, whether an
    // ICMP error came meanwhile (`Unreachable`) or not.
    let capture = recursion::Resolution::read("unsigned");
    let limits = Limits::default();
    let mut rng = Seeded(SEED);
    for reply in [Reply::Timeout, Reply::Unreachable] {
        let caches = caches(false);
        let mut resolution = start(&capture, &caches, limits);
        let now = at(&capture) + limits.time.saturating_sub(Duration::from_millis(10));
        let Next::Send(query) = resolution.step(now, &mut rng) else {
            panic!("a query")
        };
        assert_eq!(query.timeout, query.left);
        let timeout = query.timeout;
        resolution.receive(reply, now + timeout);
        assert_eq!(caches.infra.len(), 0, "{reply:?}");
        // With time left, the same timeout is the server's.
        let mut resolution = start(&capture, &caches, limits);
        let Next::Send(query) = resolution.step(at(&capture), &mut rng) else {
            panic!("a query")
        };
        assert!(query.timeout < query.left, "{query:?}");
        let timeout = query.timeout;
        resolution.receive(reply, at(&capture) + timeout);
        assert_eq!(caches.infra.len(), 1, "{reply:?}");
    }
}

#[test]
fn d193_the_authority_section_of_an_answer_does_not_answer_a_question() {
    // `nodata-signed`: sidn.nl's servers deny its SRV with the NSEC at sidn.nl in the authority section, held
    // authority authoritative. A later NSEC question for sidn.nl is asked again, not answered with it: only an
    // answer section answers (RFC 2181 §5.4.1; Unbound's `dns_cache_lookup` serves no authority or additional
    // section).
    let capture = recursion::Resolution::read("nodata-signed");
    let caches = caches(false);
    let (outcome, _) = resolve(&capture, &caches, Limits::default());
    assert!(matches!(outcome, Resolved::NoData { .. }), "{outcome:?}");
    let now = secs(at(&capture));
    let held = caches
        .rrsets
        .get(&capture.name, RecordType::NSEC, Class::IN, now)
        .expect("the NSEC of the denial is kept");
    assert_eq!(held.rank, Rank::AuthorityAuthoritative);
    let question = Question::new(capture.name.clone(), RecordType::NSEC);
    let mut resolution = Resolution::start(
        question,
        Arc::clone(&caches),
        at(&capture),
        Limits::default(),
        Minimisation::Off,
    )
    .expect("an IN question");
    let next = resolution.step(at(&capture), &mut Seeded(SEED));
    assert!(matches!(next, Next::Send(_)), "{next:?}");
}

/// google.com's one server, `ns1.google.com`, named without glue by com's referral; com answers its A with
/// `192.0.2.53` (TTL 0, so that only the resolution's own memory holds it) and its AAAA with the referral back to
/// google.com, which ends that lookup as a loop (D191). The server times out once, then answers `google.com` with a
/// CNAME to `www.google.com`, which it answers: the resolution goes on at the same cut, naming the server again.
fn memoised(aaaa: impl Fn(&Query) -> Message<'static>) -> Resolved {
    let capture = recursion::Resolution::read("unsigned");
    let caches = caches(false);
    steer(&caches, &capture);
    let authorities = Authorities::new([&capture]);
    let ns1 = name("ns1.google.com.");
    let www = name("www.google.com.");
    let address = Ipv4Addr::new(192, 0, 2, 53);
    let mut to_google = response(&capture, "com.", "google.com.");
    let ns = (to_google.authority.iter())
        .find(|r| r.rtype() == RecordType::NS)
        .expect("an NS record")
        .clone();
    to_google.authority = vec![Record::new(
        ns.name.clone(),
        ns.class,
        ns.ttl,
        &RData::Ns(ns1.clone()),
    )];
    to_google.additional.clear();
    let answer = answered(&capture);
    let template = (answer.answer.iter())
        .find(|r| r.rtype() == RecordType::A)
        .expect("an A record")
        .clone();
    let a = |owner: &Name<'static>, ttl| {
        let mut response = answer.clone();
        response.answer = vec![Record::new(
            owner.clone(),
            template.class,
            ttl,
            &RData::A(address),
        )];
        response
    };
    let timed_out = Cell::new(false);
    let server = |query: &Query| {
        let question = &query.question;
        if query.server.ip() == IpAddr::from(address) {
            if question.name == capture.name && !timed_out.replace(true) {
                return Answered::Timeout;
            }
            if question.name == capture.name {
                let mut response = a(&capture.name, template.ttl);
                let cname = RData::Cname(www.clone());
                response.answer = vec![Record::new(
                    capture.name.clone(),
                    template.class,
                    template.ttl,
                    &cname,
                )];
                return Answered::Response(to(response, question));
            }
            return Answered::Response(to(a(&www, template.ttl), question));
        }
        if question.name == ns1 && is(&query.zone, "com.") {
            if question.qtype == RecordType::A {
                return Answered::Response(to(a(&ns1, Ttl::from_wire(0)), question));
            }
            return Answered::Response(to(aaaa(query), question));
        }
        if (question.name == capture.name || question.name == www) && is(&query.zone, "com.") {
            return Answered::Response(to(to_google.clone(), question));
        }
        Answered::Response(captured(&authorities, query))
    };
    let mut resolution = start(&capture, &caches, Limits::default());
    seeded(&mut resolution, &server, at(&capture), SEED).0
}

#[test]
fn d191_an_address_found_is_kept_when_the_aaaa_lookup_loops() {
    // The A lookup of ns1.google.com found its address; the AAAA one led back to google.com, which waited on it. The
    // loop notes no AAAA address, not the loss of the A found: the CNAME's target is asked of the same server.
    let capture = recursion::Resolution::read("unsigned");
    let to_google = response(&capture, "com.", "google.com.");
    let outcome = memoised(|_| {
        let mut referral = to_google.clone();
        referral.additional.clear();
        referral
    });
    assert!(matches!(outcome, Resolved::Answer { .. }), "{outcome:?}");
}

/// A referral to `child` naming `server`, without glue, answering `question`: com's referral to google.com, the NS
/// and the glue changed.
fn glueless_referral(
    template: &Message<'static>,
    question: &Question<'static>,
    child: &str,
    server: &str,
) -> Message<'static> {
    let ns = (template.authority.iter())
        .find(|r| r.rtype() == RecordType::NS)
        .expect("an NS record");
    let data = RData::Ns(name(server));
    let mut response = to(template.clone(), question);
    response.authority = vec![Record::new(name(child), ns.class, ns.ttl, &data)];
    response.additional.clear();
    response
}

/// google.com's servers named `ns.alpha.org.` and `ns.beta.net.`, without glue. The first is reached through a
/// referral to org naming the second, which is reached through one to net naming `ns.gamma.de.`, which the root
/// answers: with a depth bound of 2 that last lookup is past the bound inside the first lookup, and within it when
/// the second is looked up from google.com's servers. `seed` draws which is looked up first.
fn deeply(seed: u64) -> Resolved {
    let capture = recursion::Resolution::read("unsigned");
    let to_google = response(&capture, "com.", "google.com.");
    let real = (capture.exchanges.iter())
        .find_map(|e| match e.server {
            IpAddr::V4(v4) if is(&e.zone, "google.com.") && e.rtype == RecordType::A => Some(v4),
            _ => None,
        })
        .expect("a server of google.com");
    let answer = answered(&capture);
    let template = (answer.answer.iter())
        .find(|r| r.rtype() == RecordType::A)
        .expect("an A record")
        .clone();
    let direct = |question: &Question<'static>, address: Ipv4Addr| {
        let mut response = answer.clone();
        let data = RData::A(address);
        response.answer = vec![Record::new(
            question.name.clone(),
            template.class,
            template.ttl,
            &data,
        )];
        to(response, question)
    };
    let lookup = |query: &Query| {
        let question = &query.question;
        let (zone, asked) = (query.zone.to_string(), question.name.to_string());
        if question.qtype != RecordType::A {
            return to(answer.clone(), question);
        }
        match (zone.as_str(), asked.as_str()) {
            (".", "ns.alpha.org.") => {
                glueless_referral(&to_google, question, "org.", "ns.beta.net.")
            }
            (".", "ns.beta.net.") => {
                glueless_referral(&to_google, question, "net.", "ns.gamma.de.")
            }
            ("org.", "ns.alpha.org.") | ("net.", "ns.beta.net.") => direct(question, real),
            _ => direct(question, Ipv4Addr::new(192, 0, 2, 7)),
        }
    };
    let names = [name("ns.alpha.org."), name("ns.beta.net.")];
    // The AAAA lookups, unanswered, cost queries.
    let limits = Limits {
        depth: 2,
        queries: 200,
        ..Limits::default()
    };
    glueless(&names, limits, seed, &lookup).0
}

#[test]
fn d191_a_lookup_past_the_depth_bound_is_not_taken_for_no_address() {
    // Looked up inside another lookup, `ns.beta.net.` fails the depth bound; looked up from google.com's servers
    // next, within it, it resolves: the failure is not a name with no address.
    for seed in 0..8 {
        let outcome = deeply(seed);
        assert!(
            matches!(outcome, Resolved::Answer { .. }),
            "seed {seed}: {outcome:?}"
        );
    }
}

/// google.com's captured answer to its A question.
fn answered(capture: &recursion::Resolution) -> Message<'static> {
    let exchange = (capture.exchanges.iter())
        .find(|e| is(&e.zone, "google.com.") && e.rtype == RecordType::A && e.name == capture.name)
        .expect("google.com's A answer");
    dedens_testkit::message(&exchange.response)
}

#[test]
fn d191_a_delegation_takes_no_more_addresses_than_unbound_does() {
    // com's referral names one server without glue, whose lookup gives 300 addresses (a response can hold some
    // thousands), all failing: with the servers bound out of the way, 100 are asked, Unbound's `delegpt_max_addr`.
    let capture = recursion::Resolution::read("unsigned");
    let google = name("google.com.");
    let unglued = name("ns.example.net.");
    let caches = caches(false);
    steer(&caches, &capture);
    let authorities = Authorities::new([&capture]);
    let template = response(&capture, "com.", "google.com.");
    let question = Question::new(capture.name.clone(), capture.rtype);
    let mut to_google = referral(&template, &question, &google, &[Ipv4Addr::UNSPECIFIED]);
    to_google.additional.clear();
    let ns = to_google.authority[0].clone();
    to_google.authority = vec![Record::new(
        ns.name.clone(),
        ns.class,
        ns.ttl,
        &RData::Ns(unglued.clone()),
    )];
    let mut found = answered(&capture);
    let class = found.answer[0].class;
    let ttl = found.answer[0].ttl;
    found.answer = (0..300_u32)
        .map(|i| {
            let address = Ipv4Addr::from(u32::from(Ipv4Addr::new(203, 0, 0, 0)) + i);
            Record::new(unglued.clone(), class, ttl, &RData::A(address))
        })
        .collect();
    let asked = RefCell::new(HashSet::new());
    let server = |query: &Query| {
        let question = &query.question;
        if query.zone == google {
            asked.borrow_mut().insert(query.server.ip());
            Answered::ServerError
        } else if question.name == unglued && question.qtype == RecordType::A {
            Answered::Response(to(found.clone(), question))
        } else if is(&query.zone, "com.") {
            Answered::Response(to(to_google.clone(), question))
        } else {
            Answered::Response(captured(&authorities, query))
        }
    };
    let limits = Limits {
        servers: 1000,
        queries: 1000,
        ..Limits::default()
    };
    let (outcome, _) = run(&mut start(&capture, &caches, limits), &server, at(&capture));
    assert_eq!(outcome, Resolved::Failed(Failure::Network));
    assert_eq!(asked.borrow().len(), 100);
}
