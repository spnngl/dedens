//! The recurse stage (D195) on the captured resolutions of `testdata/recursion/` (D188), each server answering as
//! captured through `Authorities`, the harness acting as the transport: RFC 1034 §5.3.3 (each capture resolved
//! through the pipeline, the cache stage answering it again), RFC 8109 §3 (priming), RFC 6303 §3 and §4, RFC 8375 §4,
//! RFC 9462 §6.4 and RFC 6761 §6.3, §6.4 (the zones served locally), RFC 5452 §5 (a resolution on shared replies),
//! D117 (the client's network pays each query), and validation (D197): RFC 4035 §5 (AD on a secure answer, SERVFAIL
//! with the extended error of RFC 8914 §4 on a bogus one), §3.2.2 (none for a query with CD, which gets the data
//! as held: AD when secure, by RFC 6840 §5.8, bogus data by §5.9), and D77 (the allowance bounds it).

use std::collections::HashSet;
use std::convert::Infallible;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use dedens_cache::{Cache, Config};
use dedens_dnssec::{TrustAnchors, Validator};
use dedens_proto::edns::{EdnsOption, InfoCode};
use dedens_proto::rdata::RData;
use dedens_proto::{Class, Flags, Message, Name, Rcode, RecordType, Transport};
use dedens_resolver::{
    Caches, DEFAULT_CAPACITY, InfraCache, Marks, Minimisation, Query, Reply, Resolved, RrsetCache,
};
use dedens_roots::RootHints;
use dedens_server::{
    Allowance, Budget, Budgets, Pipeline, Recurse, Resolving, Stage, Step, Turn, Validating,
};
use dedens_testkit::recursion::{self, Authorities};
use rand_core::{TryCryptoRng, TryRng};

use crate::util::{client_query, decode};

/// `SplitMix64` from a fixed seed, so that a draw replays: a CSPRNG by marker only, for tests.
struct Seeded(u64);

impl TryRng for Seeded {
    type Error = Infallible;

    fn try_next_u32(&mut self) -> Result<u32, Infallible> {
        Ok(u32::try_from(self.try_next_u64()? >> 32).unwrap_or_default())
    }

    fn try_next_u64(&mut self) -> Result<u64, Infallible> {
        self.0 = self.0.wrapping_add(0x9e37_79b9_7f4a_7c15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
        Ok(z ^ (z >> 31))
    }

    fn try_fill_bytes(&mut self, dst: &mut [u8]) -> Result<(), Infallible> {
        for chunk in dst.chunks_mut(8) {
            let word = self.try_next_u64()?.to_le_bytes();
            chunk.copy_from_slice(&word[..chunk.len()]);
        }
        Ok(())
    }
}

impl TryCryptoRng for Seeded {}

/// Empty caches under `config`, without the TLD hints: a resolution starts at the root, as the captures did.
fn caches(config: Config) -> Arc<Caches> {
    Arc::new(Caches {
        rrsets: RrsetCache::new(DEFAULT_CAPACITY, config).expect("a valid config"),
        infra: InfraCache::new(InfraCache::DEFAULT_CAPACITY, 64).expect("a valid size"),
        roots: RootHints::bundled().clone(),
        tlds: None,
    })
}

/// A cache stage under `config`, then `recurse`.
fn pipeline(config: Config, recurse: Recurse) -> Pipeline {
    Pipeline::new(vec![
        Stage::Cache(Arc::new(Cache::new(config).expect("valid settings"))),
        Stage::Recurse(recurse),
    ])
}

/// The recurse stage on `caches`, its questions not minimised: the captures are of an iterator asking the full name
/// (D198).
fn unminimised(caches: Arc<Caches>) -> Recurse {
    Recurse::new(caches).with_minimisation(Minimisation::Off)
}

/// The second of the capture, so that every TTL it holds is fresh.
fn at(capture: &recursion::Resolution) -> u32 {
    u32::try_from(capture.captured_at).expect("a capture time within u32")
}

/// Marks lame, for each zone `capture` asked, every address it shows but the first server it asked there: the draw
/// then falls on the server whose responses the capture followed.
fn steer(caches: &Caches, capture: &recursion::Resolution) {
    let mut known: HashSet<IpAddr> = (caches.roots.servers().iter())
        .flat_map(dedens_roots::Server::addresses)
        .collect();
    for exchange in &capture.exchanges {
        let response = dedens_testkit::message(&exchange.response);
        known.extend(
            (response.answer.iter().chain(&response.additional)).filter_map(|r| match r.data() {
                RData::A(v4) => Some(IpAddr::from(v4)),
                RData::Aaaa(v6) => Some(IpAddr::from(v6)),
                _ => None,
            }),
        );
    }
    let mut followed: Vec<(&Name<'static>, IpAddr)> = Vec::new();
    for e in &capture.exchanges {
        if !followed.iter().any(|(zone, _)| *zone == &e.zone) {
            followed.push((&e.zone, e.server));
        }
    }
    for (zone, server) in followed {
        for &address in known.iter().filter(|&&a| a != server) {
            caches
                .infra
                .lame(SocketAddr::new(address, 53), zone, at(capture));
        }
    }
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

/// Steps `resolving` at `now` to its end, each query answered from `authorities`; the queries sent.
fn drive(resolving: &mut Resolving, authorities: &Authorities, now: u32) -> usize {
    drive_as(resolving, authorities, now, Resolving::receive)
}

/// [`drive`], each reply handed over by `receive`. Each query is stepped to twice, as a driver may: the client pays
/// for it once (D117).
fn drive_as(
    resolving: &mut Resolving,
    authorities: &Authorities,
    now: u32,
    receive: impl Fn(&mut Resolving, Reply<'_>, Duration),
) -> usize {
    let now = Duration::from_secs(now.into());
    let mut rng = Seeded(0);
    let mut sent = 0;
    while let Turn::Send(query) = resolving.step(now, &mut rng) {
        let query = query.clone();
        let again = match resolving.step(now, &mut rng) {
            Turn::Send(again) => Some(again.clone()),
            Turn::Done => None,
        };
        assert_eq!(
            again,
            Some(query.clone()),
            "the same query again, paid for already"
        );
        let response = captured(authorities, &query);
        sent += 1;
        assert!(sent <= 1000, "no end in sight");
        let reply = Reply::Response {
            message: &response,
            seen: Marks::default(),
            rtt: Duration::from_millis(20),
        };
        receive(resolving, reply, now);
    }
    sent
}

/// The reply of `pipeline` at `now` to `query` from `from`, the resolution answered from `authorities`, and the
/// queries it sent: `None` when nothing was resolved.
fn ask(
    pipeline: &Pipeline,
    (query, from): (&[u8], IpAddr),
    authorities: &Authorities,
    now: u32,
) -> (Option<Vec<u8>>, Option<usize>) {
    let mut out = vec![0; 65535];
    match pipeline.query(query, Transport::Udp, from, now, &mut out) {
        Step::Reply(len) => (Some(out[..len].to_vec()), None),
        Step::Drop => (None, None),
        Step::Resolve(mut resolving) => {
            let sent = drive(&mut resolving, authorities, now);
            match pipeline.resolved(&resolving, now, &mut out) {
                Step::Reply(len) => (Some(out[..len].to_vec()), Some(sent)),
                Step::Drop => (None, Some(sent)),
                step => unreachable!("a reply, not {step:?}"),
            }
        }
        step => unreachable!("no forward stage: {step:?}"),
    }
}

/// The query of `capture`'s question, RD set, DO clear.
fn question(capture: &recursion::Resolution) -> Vec<u8> {
    client_query(&capture.name.to_string(), capture.rtype, Flags::NONE, false)
}

/// The extended error of `reply`, if any.
fn ede(reply: &Message<'_>) -> Option<InfoCode> {
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

const CLIENT: IpAddr = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 7));

#[test]
fn rfc1034_5_3_3_each_capture_resolves_through_the_pipeline_and_the_cache_answers_again() {
    for (id, capture) in recursion::Resolution::all() {
        if capture.rtype == RecordType::RRSIG {
            continue; // d195_a_type_not_resolved_is_not_implemented
        }
        let caches = caches(Config::default());
        steer(&caches, &capture);
        let pipeline = pipeline(Config::default(), unminimised(Arc::clone(&caches)));
        let authorities = Authorities::new([&capture]);
        let query = question(&capture);
        let now = at(&capture);
        let (reply, sent) = ask(&pipeline, (&query, CLIENT), &authorities, now);
        let reply = decode(reply.as_deref().expect("a reply"));
        assert!(sent > Some(0), "{id}");
        let rcode = if id.starts_with("nxdomain") {
            Rcode::NXDOMAIN
        } else {
            Rcode::NOERROR
        };
        assert_eq!(reply.header.rcode, rcode, "{id}");
        assert!(reply.header.flags.contains(Flags::RA), "{id}");
        assert!(!reply.header.flags.contains(Flags::AA), "{id}");
        let answered = reply.answer.iter().any(|r| r.rtype() == capture.rtype);
        let denied = id.starts_with("nxdomain") || id.starts_with("nodata");
        assert_eq!(answered, !denied, "{id}: {reply:?}");
        if denied {
            assert!(
                reply.authority.iter().any(|r| r.rtype() == RecordType::SOA),
                "{id}"
            );
        }
        // The cache stage answers again: nothing is resolved.
        let (again, resent) = ask(&pipeline, (&query, CLIENT), &authorities, now + 1);
        assert_eq!(resent, None, "{id}");
        let again = decode(again.as_deref().expect("a reply"));
        assert_eq!(again.header.rcode, rcode, "{id}");
        assert_eq!(again.answer.len(), reply.answer.len(), "{id}");
    }
}

#[test]
fn d124_an_answer_is_served_within_the_cache_lifetime() {
    let capture = recursion::Resolution::read("signed-com");
    let config = Config {
        max_ttl: 60,
        ..Config::default()
    };
    let caches = caches(config.clone());
    steer(&caches, &capture);
    let pipeline = pipeline(config, unminimised(Arc::clone(&caches)));
    let authorities = Authorities::new([&capture]);
    let (reply, _) = ask(
        &pipeline,
        (&question(&capture), CLIENT),
        &authorities,
        at(&capture),
    );
    let reply = decode(reply.as_deref().expect("a reply"));
    assert_ne!(reply.answer, []);
    // The capture's TTLs are over a minute: the cache's lifetime bounds them.
    let captured = capture.exchanges.last().expect("an exchange");
    let captured = dedens_testkit::message(&captured.response);
    assert!(captured.answer.iter().all(|r| r.ttl.get() > 60));
    assert!(reply.answer.iter().all(|r| r.ttl.get() <= 60), "{reply:?}");
}

#[test]
fn d124_an_answer_from_the_rrset_cache_is_served_its_time_left_not_the_floor() {
    let capture = recursion::Resolution::read("signed-com");
    let caches = caches(Config::default());
    steer(&caches, &capture);
    let authorities = Authorities::new([&capture]);
    let query = question(&capture);
    let now = at(&capture);
    let first = pipeline(Config::default(), unminimised(Arc::clone(&caches)));
    let (reply, _) = ask(&first, (&query, CLIENT), &authorities, now);
    assert_ne!(decode(reply.as_deref().expect("a reply")).answer, []);
    let held = (caches
        .rrsets
        .get(&capture.name, capture.rtype, Class::IN, now))
    .expect("the answer cached");
    let floor = Config::default().min_ttl;
    assert!(held.ttl.get() > floor);
    // Three seconds left, under the floor; a new response cache, so that the `RRset` cache answers.
    let later = now + held.ttl.get() - 3;
    let second = pipeline(Config::default(), unminimised(Arc::clone(&caches)));
    let (reply, sent) = ask(&second, (&query, CLIENT), &authorities, later);
    assert_eq!(sent, Some(0));
    let reply = decode(reply.as_deref().expect("a reply"));
    let ttls: Vec<u32> = reply.answer.iter().map(|r| r.ttl.get()).collect();
    assert_eq!(ttls, [3, 3], "{reply:?}");
}

#[test]
fn rfc4035_3_2_1_signatures_go_to_a_client_asking_with_do() {
    let capture = recursion::Resolution::read("signed-com");
    let caches = caches(Config::default());
    steer(&caches, &capture);
    let pipeline = pipeline(Config::default(), unminimised(Arc::clone(&caches)));
    let authorities = Authorities::new([&capture]);
    let query = client_query("example.com.", RecordType::A, Flags::NONE, true);
    let (reply, _) = ask(&pipeline, (&query, CLIENT), &authorities, at(&capture));
    let reply = decode(reply.as_deref().expect("a reply"));
    let types: Vec<_> = reply
        .answer
        .iter()
        .map(dedens_proto::Record::rtype)
        .collect();
    // The A RRset of the capture, two records, then its signature.
    assert_eq!(types, [RecordType::A, RecordType::A, RecordType::RRSIG]);
}

#[test]
fn rfc8109_3_priming_asks_the_root_ns_once_until_it_expires() {
    let capture = recursion::Resolution::read("priming");
    let caches = caches(Config::default());
    steer(&caches, &capture);
    let pipeline = pipeline(Config::default(), unminimised(Arc::clone(&caches)));
    let authorities = Authorities::new([&capture]);
    let now = at(&capture);
    let secs = Duration::from_secs(now.into());
    let mut priming = pipeline
        .prime(secs)
        .expect("the cache is empty: priming is due");
    assert!(priming.is_priming());
    assert_eq!(priming.question().name, Name::root());
    assert_eq!(priming.question().qtype, RecordType::NS);
    // One at a time, whichever thread starts it.
    assert!(pipeline.prime(secs).is_none());
    assert!(priming.resolved().is_none());
    assert_eq!(drive(&mut priming, &authorities, now), 1);
    // What it resolved to, which the server logs.
    assert!(matches!(priming.resolved(), Some(Resolved::Answer { .. })));
    let mut out = vec![0; 512];
    assert!(matches!(
        pipeline.resolved(&priming, now, &mut out),
        Step::Drop
    ));
    drop(priming);
    let root = Name::root();
    let ns =
        (caches.rrsets.get(&root, RecordType::NS, Class::IN, now)).expect("the root NS cached");
    // Fresh, it is not asked again; expired, it is.
    assert!(pipeline.prime(secs).is_none());
    let expired = secs + Duration::from_secs(u64::from(ns.ttl.get()) + 1);
    assert!(pipeline.prime(expired).is_some());
}

#[test]
fn rfc5452_5_a_resolution_on_shared_replies_resolves_and_judges_no_server() {
    let capture = recursion::Resolution::read("unsigned");
    let caches = caches(Config::default());
    steer(&caches, &capture);
    // The lame marks of the steering alone.
    let known = caches.infra.len();
    let pipeline = pipeline(Config::default(), unminimised(Arc::clone(&caches)));
    let authorities = Authorities::new([&capture]);
    let now = at(&capture);
    let mut out = vec![0; 65535];
    let Step::Resolve(mut resolving) =
        pipeline.query(&question(&capture), Transport::Udp, CLIENT, now, &mut out)
    else {
        panic!("a resolution")
    };
    assert!(!resolving.is_priming());
    assert!(drive_as(&mut resolving, &authorities, now, Resolving::receive_shared) > 0);
    let Step::Reply(len) = pipeline.resolved(&resolving, now, &mut out) else {
        panic!("a reply")
    };
    assert_eq!(decode(&out[..len]).header.rcode, Rcode::NOERROR);
    assert_eq!(caches.infra.len(), known);
}

#[test]
fn rfc8109_3_a_priming_given_up_lets_the_next_start() {
    let pipeline = pipeline(Config::default(), unminimised(caches(Config::default())));
    let priming = pipeline.prime(Duration::ZERO).expect("due");
    drop(priming);
    assert!(pipeline.prime(Duration::ZERO).is_some());
}

/// The reply of `pipeline` to `name` `rtype`, which a zone served locally answers: no query is sent.
fn local(pipeline: &Pipeline, name: &str, rtype: RecordType) -> Message<'static> {
    let query = client_query(name, rtype, Flags::NONE, false);
    let (reply, sent) = ask(pipeline, (&query, CLIENT), &Authorities::default(), 0);
    assert_eq!(sent, None, "{name} {rtype}");
    let reply = decode(reply.as_deref().expect("a reply")).into_owned();
    assert!(reply.header.flags.contains(Flags::AA), "{name} {rtype}");
    reply
}

fn soa(message: &Message<'_>) -> Option<Name<'static>> {
    (message.authority.iter().chain(&message.answer))
        .find(|r| r.rtype() == RecordType::SOA)
        .map(|r| r.name.clone().into_owned())
}

#[test]
fn rfc6303_3_a_reverse_zone_of_private_addresses_is_served_empty() {
    let pipeline = pipeline(Config::default(), unminimised(caches(Config::default())));
    let zone: Name<'static> = "10.in-addr.arpa.".parse().expect("a name");
    // Below the apex: NXDOMAIN, the zone's SOA to cache it with.
    let below = local(&pipeline, "1.2.3.10.in-addr.arpa.", RecordType::PTR);
    assert_eq!(below.header.rcode, Rcode::NXDOMAIN);
    assert_eq!(soa(&below), Some(zone.clone()));
    // At the apex: its SOA and NS, NODATA for any other type.
    let apex = local(&pipeline, "10.in-addr.arpa.", RecordType::SOA);
    assert_eq!(apex.header.rcode, Rcode::NOERROR);
    let [soa_record] = apex.answer.as_slice() else {
        panic!("one SOA: {apex:?}")
    };
    let RData::Soa(data) = soa_record.data() else {
        panic!("a SOA")
    };
    assert_eq!(
        (data.mname.clone(), data.rname.to_string()),
        (zone.clone(), "nobody.invalid.".to_owned())
    );
    assert_eq!(
        (
            data.serial,
            data.refresh,
            data.retry,
            data.expire,
            data.minimum
        ),
        (1, 3600, 1200, 604_800, 10800)
    );
    assert_eq!(soa_record.ttl.get(), 10800);
    let ns = local(&pipeline, "10.in-addr.arpa.", RecordType::NS);
    assert_eq!(ns.answer.len(), 1);
    assert_eq!(ns.answer[0].data(), RData::Ns(zone.clone()));
    let nodata = local(&pipeline, "10.in-addr.arpa.", RecordType::TXT);
    assert_eq!(
        (nodata.header.rcode, nodata.answer.len()),
        (Rcode::NOERROR, 0)
    );
    assert_eq!(soa(&nodata), Some(zone));
    // Every zone of §4, the IPv6 ones too.
    for name in [
        "1.0.0.127.in-addr.arpa.",
        "5.31.172.in-addr.arpa.",
        "1.1.168.192.in-addr.arpa.",
        "1.254.169.in-addr.arpa.",
        "1.2.0.192.in-addr.arpa.",
        "1.100.51.198.in-addr.arpa.",
        "1.113.0.203.in-addr.arpa.",
        "1.0.0.0.in-addr.arpa.",
        "255.255.255.255.in-addr.arpa.",
        "1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.ip6.arpa.",
        "0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.ip6.arpa.",
        "1.d.f.ip6.arpa.",
        "1.8.e.f.ip6.arpa.",
        "1.9.e.f.ip6.arpa.",
        "1.a.e.f.ip6.arpa.",
        "1.b.e.f.ip6.arpa.",
        "1.8.b.d.0.1.0.0.2.ip6.arpa.",
    ] {
        let reply = local(&pipeline, name, RecordType::PTR);
        assert!(soa(&reply).is_some(), "{name}");
    }
}

#[test]
fn rfc6303_3_a_zone_turned_off_is_resolved() {
    let zone: Name<'static> = "10.in-addr.arpa.".parse().expect("a name");
    let served = unminimised(caches(Config::default()));
    assert!(served.local_zones().any(|local| *local == zone));
    let recurse = served.resolving(&zone).expect("a zone served locally");
    // Listed no more, so that a reload turning it off flushes the cache stage.
    assert!(!recurse.local_zones().any(|local| *local == zone));
    let invalid: Name<'static> = "invalid.".parse().expect("a name");
    assert!(recurse.local_zones().any(|local| *local == invalid));
    let pipeline = pipeline(Config::default(), recurse);
    let query = client_query(
        "1.2.3.10.in-addr.arpa.",
        RecordType::PTR,
        Flags::NONE,
        false,
    );
    let mut out = vec![0; 65535];
    let step = pipeline.query(&query, Transport::Udp, CLIENT, 0, &mut out);
    assert!(matches!(step, Step::Resolve(_)), "{step:?}");
    // A zone not served locally cannot be turned off.
    let other: Name<'static> = "example.com.".parse().expect("a name");
    let error = unminimised(caches(Config::default()))
        .resolving(&other)
        .expect_err("not served locally");
    assert_eq!(error.0, other);
}

#[test]
fn rfc8375_4_home_arpa_is_served_empty_but_its_ds() {
    let pipeline = pipeline(Config::default(), unminimised(caches(Config::default())));
    let below = local(&pipeline, "printer.home.arpa.", RecordType::A);
    assert_eq!(below.header.rcode, Rcode::NXDOMAIN);
    assert_eq!(soa(&below), Some("home.arpa.".parse().expect("a name")));
    // Its apex alone has an SOA and NS records; the SOA answered is not in the authority section too.
    let apex = local(&pipeline, "home.arpa.", RecordType::SOA);
    assert_eq!((apex.answer.len(), apex.authority.len()), (1, 0));
    for rtype in [RecordType::SOA, RecordType::NS] {
        let below = local(&pipeline, "printer.home.arpa.", rtype);
        assert_eq!(
            (below.header.rcode, below.answer.len()),
            (Rcode::NXDOMAIN, 0)
        );
    }
    // Its DS proves it insecure: it is resolved (RFC 8375 §4 item 4.B).
    let query = client_query("home.arpa.", RecordType::DS, Flags::NONE, true);
    let mut out = vec![0; 65535];
    let step = pipeline.query(&query, Transport::Udp, CLIENT, 0, &mut out);
    assert!(matches!(step, Step::Resolve(_)), "{step:?}");
}

#[test]
fn rfc9462_6_4_resolver_arpa_has_no_data() {
    let pipeline = pipeline(Config::default(), unminimised(caches(Config::default())));
    for (name, rtype) in [
        ("resolver.arpa.", RecordType::SVCB),
        ("_dns.resolver.arpa.", RecordType::SVCB),
        ("_dns.resolver.arpa.", RecordType::SOA),
        ("_dns.resolver.arpa.", RecordType::NS),
    ] {
        let reply = local(&pipeline, name, rtype);
        assert_eq!(
            (reply.header.rcode, reply.answer.len()),
            (Rcode::NOERROR, 0),
            "{name}"
        );
    }
}

#[test]
fn rfc6761_6_3_localhost_is_the_loopback() {
    let pipeline = pipeline(Config::default(), unminimised(caches(Config::default())));
    let a = local(&pipeline, "www.localhost.", RecordType::A);
    assert_eq!(a.answer[0].data(), RData::A(Ipv4Addr::LOCALHOST));
    let aaaa = local(&pipeline, "localhost.", RecordType::AAAA);
    assert_eq!(
        aaaa.answer[0].data(),
        RData::Aaaa(std::net::Ipv6Addr::LOCALHOST)
    );
    let mx = local(&pipeline, "localhost.", RecordType::MX);
    assert_eq!((mx.header.rcode, mx.answer.len()), (Rcode::NOERROR, 0));
    // Its DS too: no query goes out for it (item 4), as for any name below.
    let ds = local(&pipeline, "localhost.", RecordType::DS);
    assert_eq!((ds.header.rcode, ds.answer.len()), (Rcode::NOERROR, 0));
    assert_eq!(soa(&ds), Some("localhost.".parse().expect("a name")));
}

/// The local zones are class IN's: a question of another class is the stage's, which resolves none (REFUSED).
#[test]
fn d195_the_local_zones_answer_class_in_only() {
    let pipeline = pipeline(Config::default(), unminimised(caches(Config::default())));
    for name in ["localhost.", "10.in-addr.arpa.", "host.invalid."] {
        let mut question =
            dedens_proto::Question::new(name.parse().expect("a name"), RecordType::A);
        question.qclass = Class::CH;
        let mut query = Message::query(7, question);
        query.header.flags = Flags::RD;
        let query = crate::util::wire(&query);
        let (reply, sent) = ask(&pipeline, (&query, CLIENT), &Authorities::default(), 0);
        assert!(matches!(sent, None | Some(0)), "{name}");
        let reply = decode(reply.as_deref().expect("a reply"));
        assert_eq!(reply.header.rcode, Rcode::REFUSED, "{name}");
        assert!(!reply.header.flags.contains(Flags::AA), "{name}");
    }
}

#[test]
fn rfc6761_6_4_invalid_does_not_exist() {
    let pipeline = pipeline(Config::default(), unminimised(caches(Config::default())));
    let invalid: Name<'static> = "invalid.".parse().expect("a name");
    for (name, rtype) in [
        ("host.invalid.", RecordType::A),
        ("invalid.", RecordType::DS),
    ] {
        let reply = local(&pipeline, name, rtype);
        assert_eq!(reply.header.rcode, Rcode::NXDOMAIN, "{name}");
        // A SOA to cache the NXDOMAIN by (RFC 2308 §5).
        assert_eq!(soa(&reply), Some(invalid.clone()), "{name}");
    }
}

#[test]
fn d117_a_network_out_of_queries_gets_servfail_not_ready() {
    let capture = recursion::Resolution::read("signed-com");
    let caches = caches(Config::default());
    steer(&caches, &capture);
    let share = Budgets::new(Budget {
        per_second: 1,
        burst: 2,
        table: 1,
    })
    .expect("a budget");
    let recurse = unminimised(Arc::clone(&caches)).with_share(share);
    let pipeline = pipeline(Config::default(), recurse);
    let authorities = Authorities::new([&capture]);
    let (reply, sent) = ask(
        &pipeline,
        (&question(&capture), CLIENT),
        &authorities,
        at(&capture),
    );
    // Root, com and example.com: the third is not paid for.
    assert_eq!(sent, Some(2));
    let reply = decode(reply.as_deref().expect("a reply"));
    assert_eq!(reply.header.rcode, Rcode::SERVFAIL);
    assert_eq!(ede(&reply), Some(InfoCode::NOT_READY));
}

/// The stage hands its client share, for a reload with the same budget to keep its buckets (D195).
#[test]
fn d195_the_stage_hands_its_client_share() {
    let caches = caches(Config::default());
    assert!(unminimised(Arc::clone(&caches)).share().is_none());
    let share = Arc::new(
        Budgets::new(Budget {
            per_second: 1,
            burst: 1,
            table: 1,
        })
        .expect("a budget"),
    );
    let recurse = unminimised(caches).with_share(Arc::clone(&share));
    assert!(
        recurse
            .share()
            .is_some_and(|held| Arc::ptr_eq(held, &share))
    );
}

/// A resolution shed for the waiters on its query (`Resolving::shed`) gives its unit back: nothing was sent.
#[test]
fn d195_a_resolution_shed_gets_servfail_not_ready_and_pays_nothing() {
    let capture = recursion::Resolution::read("signed-com");
    let caches = caches(Config::default());
    steer(&caches, &capture);
    let share = Budgets::new(Budget {
        per_second: 1,
        burst: 1,
        table: 1,
    })
    .expect("a budget");
    let recurse = unminimised(Arc::clone(&caches)).with_share(share);
    let pipeline = pipeline(Config::default(), recurse);
    let now = at(&capture);
    let mut out = vec![0; 65535];
    for _ in 0..2 {
        let Step::Resolve(mut resolving) =
            pipeline.query(&question(&capture), Transport::Udp, CLIENT, now, &mut out)
        else {
            panic!("a resolution")
        };
        let mut rng = Seeded(0);
        // The one unit of the burst pays the first query each time.
        assert!(matches!(
            resolving.step(Duration::from_secs(now.into()), &mut rng),
            Turn::Send(_)
        ));
        resolving.shed();
        assert_eq!(
            resolving.step(Duration::from_secs(now.into()), &mut rng),
            Turn::Done
        );
        let Step::Reply(len) = pipeline.resolved(&resolving, now, &mut out) else {
            panic!("a reply")
        };
        let reply = decode(&out[..len]);
        assert_eq!(reply.header.rcode, Rcode::SERVFAIL);
        assert_eq!(ede(&reply), Some(InfoCode::NOT_READY));
    }
}

#[test]
fn d195_a_type_not_resolved_is_not_implemented() {
    let pipeline = pipeline(Config::default(), unminimised(caches(Config::default())));
    let query = client_query("sidn.nl.", RecordType::RRSIG, Flags::NONE, false);
    let (reply, sent) = ask(&pipeline, (&query, CLIENT), &Authorities::default(), 0);
    assert_eq!(sent, Some(0));
    assert_eq!(decode(&reply.expect("a reply")).header.rcode, Rcode::NOTIMP);
}

#[test]
fn rfc1034_4_3_1_without_rd_the_recurse_stage_refuses() {
    let pipeline = pipeline(Config::default(), unminimised(caches(Config::default())));
    let mut query = client_query("example.com.", RecordType::A, Flags::NONE, false);
    query[2] &= !Flags::RD.bits().to_be_bytes()[0];
    let (reply, _) = ask(&pipeline, (&query, CLIENT), &Authorities::default(), 0);
    let reply = decode(reply.as_deref().expect("a reply"));
    assert_eq!(reply.header.rcode, Rcode::REFUSED);
    assert_eq!(ede(&reply), Some(InfoCode::NOT_AUTHORITATIVE));
}

#[test]
fn rfc8482_any_over_udp_is_truncated() {
    let pipeline = pipeline(Config::default(), unminimised(caches(Config::default())));
    let query = client_query("example.com.", RecordType::ANY, Flags::NONE, false);
    let (reply, _) = ask(&pipeline, (&query, CLIENT), &Authorities::default(), 0);
    let reply = decode(reply.as_deref().expect("a reply"));
    assert!(reply.header.flags.contains(Flags::TC));
}

/// The recurse stage on `caches`, validating from the root's anchors at the time of `capture` under `allowance`.
fn validating(
    caches: &Arc<Caches>,
    capture: &recursion::Resolution,
    allowance: Allowance,
) -> Recurse {
    let validator = Validator::new(TrustAnchors::root(), dedens_dnssec::Limits::default());
    let at = capture.captured_at;
    let validating = Validating::new(validator, Arc::new(move || at)).allowing(allowance);
    unminimised(Arc::clone(caches)).validating(validating)
}

/// The reply of a validating pipeline to `query`, `capture` served by `authorities`, and the queries it sent.
fn validated(
    capture: &recursion::Resolution,
    authorities: &Authorities,
    query: &[u8],
    allowance: Allowance,
) -> (Message<'static>, Option<usize>) {
    let caches = caches(Config::default());
    steer(&caches, capture);
    let pipeline = pipeline(Config::default(), validating(&caches, capture, allowance));
    let (reply, sent) = ask(&pipeline, (query, CLIENT), authorities, at(capture));
    (
        decode(reply.as_deref().expect("a reply")).into_owned(),
        sent,
    )
}

/// `capture` with the signatures of its answers to `name` and `rtype` taken out.
fn stripped(
    mut capture: recursion::Resolution,
    name: &str,
    rtype: RecordType,
) -> recursion::Resolution {
    for exchange in &mut capture.exchanges {
        if exchange.name.to_string() == name && exchange.rtype == rtype {
            let mut response = dedens_testkit::message(&exchange.response);
            response.answer.retain(|r| r.rtype() != RecordType::RRSIG);
            exchange.response = response.to_vec().expect("a response encodes");
        }
    }
    capture
}

#[test]
fn rfc4035_5_each_capture_validated_is_secure_with_ad_or_insecure_without() {
    for (id, capture) in recursion::Resolution::all() {
        if capture.rtype == RecordType::RRSIG {
            continue; // d195_a_type_not_resolved_is_not_implemented
        }
        let caches = caches(Config::default());
        steer(&caches, &capture);
        let pipeline = pipeline(
            Config::default(),
            validating(&caches, &capture, Allowance::default()),
        );
        let authorities = Authorities::new([&capture]);
        let query = client_query(&capture.name.to_string(), capture.rtype, Flags::NONE, true);
        let now = at(&capture);
        let (reply, _) = ask(&pipeline, (&query, CLIENT), &authorities, now);
        let reply = decode(reply.as_deref().expect("a reply"));
        assert_ne!(reply.header.rcode, Rcode::SERVFAIL, "{id}: {reply:?}");
        let unsigned = [
            "cname",
            "cname-to-signed",
            "unsigned",
            "truncated",
            "wildcard-optout",
        ]
        .contains(&id.as_str())
            || id.ends_with("-unsigned");
        assert_eq!(reply.header.flags.contains(Flags::AD), !unsigned, "{id}");
        // The cache stage answers again as it was judged.
        let (again, resent) = ask(&pipeline, (&query, CLIENT), &authorities, now + 1);
        assert_eq!(resent, None, "{id}");
        let again = decode(again.as_deref().expect("a reply"));
        assert_eq!(again.header.flags.contains(Flags::AD), !unsigned, "{id}");
    }
}

#[test]
fn rfc4035_5_a_bogus_answer_gets_servfail_with_its_extended_error() {
    let capture = stripped(
        recursion::Resolution::read("signed-nl"),
        "sidn.nl.",
        RecordType::A,
    );
    let authorities = Authorities::new([&capture]);
    let query = client_query("sidn.nl.", RecordType::A, Flags::NONE, true);
    let caches = caches(Config::default());
    steer(&caches, &capture);
    let pipeline = pipeline(
        Config::default(),
        validating(&caches, &capture, Allowance::default()),
    );
    // The `RRset` cache holds the verdict: asked again, the stage sends nothing and answers the same.
    for (later, sent) in [(0, true), (1, false)] {
        let (reply, resent) = ask(
            &pipeline,
            (&query, CLIENT),
            &authorities,
            at(&capture) + later,
        );
        assert_eq!(resent.is_some_and(|n| n > 0), sent, "{later}");
        let reply = decode(reply.as_deref().expect("a reply"));
        assert_eq!(reply.header.rcode, Rcode::SERVFAIL);
        assert_eq!(ede(&reply), Some(InfoCode::RRSIGS_MISSING));
        assert_eq!(reply.answer, []);
    }
}

#[test]
fn rfc4035_3_2_2_a_query_with_cd_is_not_validated() {
    let capture = stripped(
        recursion::Resolution::read("signed-nl"),
        "sidn.nl.",
        RecordType::A,
    );
    let authorities = Authorities::new([&capture]);
    let query = client_query("sidn.nl.", RecordType::A, Flags::CD, true);
    let (reply, _) = validated(&capture, &authorities, &query, Allowance::default());
    assert_eq!(reply.header.rcode, Rcode::NOERROR);
    assert!(!reply.header.flags.contains(Flags::AD));
    assert!(
        reply.answer.iter().any(|r| r.rtype() == RecordType::A),
        "{reply:?}"
    );
}

#[test]
fn d77_a_validation_past_the_allowance_gets_servfail_not_ready() {
    let capture = recursion::Resolution::read("signed-nl");
    let authorities = Authorities::new([&capture]);
    let query = client_query("sidn.nl.", RecordType::A, Flags::NONE, true);
    let allowance = Allowance {
        per_second: 1,
        burst: 1,
        per_query: 256,
    };
    let (reply, sent) = validated(&capture, &authorities, &query, allowance);
    assert_eq!(reply.header.rcode, Rcode::SERVFAIL);
    assert_eq!(ede(&reply), Some(InfoCode::NOT_READY));
    // Shed at its first validator question, as the allowance runs dry, not at the end of its 8 queries.
    assert!(sent.is_some_and(|sent| sent < 8), "{sent:?}");
}

#[test]
fn d77_a_validation_past_its_query_allowance_is_indeterminate() {
    let capture = recursion::Resolution::read("signed-nl");
    let authorities = Authorities::new([&capture]);
    let query = client_query("sidn.nl.", RecordType::A, Flags::NONE, true);
    // The validation of `sidn.nl A` costs 8 units by its last query (its questions and verifications so far,
    // D106's `work`), and sends 8 queries in all: past `per_query` it stops at once.
    for (per_query, secure, queries) in [(2, false, 4), (7, false, 7), (8, true, 8)] {
        let allowance = Allowance {
            per_query,
            ..Allowance::default()
        };
        let (reply, sent) = validated(&capture, &authorities, &query, allowance);
        assert_eq!(sent, Some(queries), "{per_query}");
        if secure {
            assert_eq!(reply.header.rcode, Rcode::NOERROR, "{per_query}");
            assert!(reply.header.flags.contains(Flags::AD), "{per_query}");
        } else {
            assert_eq!(reply.header.rcode, Rcode::SERVFAIL, "{per_query}");
            let code = Some(InfoCode::DNSSEC_INDETERMINATE);
            assert_eq!(ede(&reply), code, "{per_query}");
        }
    }
}

#[test]
fn rfc6840_5_8_a_query_with_cd_gets_ad_for_data_held_secure() {
    // RFC 4035 §3.2.3: AD when every RRset is authentic, which the `RRset` cache holds from the first query.
    let capture = recursion::Resolution::read("signed-nl");
    let authorities = Authorities::new([&capture]);
    let caches = caches(Config::default());
    steer(&caches, &capture);
    let pipeline = pipeline(
        Config::default(),
        validating(&caches, &capture, Allowance::default()),
    );
    for flags in [Flags::NONE, Flags::CD] {
        let query = client_query("sidn.nl.", RecordType::A, flags, true);
        let (reply, _) = ask(&pipeline, (&query, CLIENT), &authorities, at(&capture));
        let reply = decode(reply.as_deref().expect("a reply"));
        assert_eq!(reply.header.rcode, Rcode::NOERROR, "{flags:?}");
        assert!(reply.header.flags.contains(Flags::AD), "{flags:?}");
    }
}

#[test]
fn rfc6840_5_9_a_query_with_cd_gets_the_data_held_bogus() {
    let capture = stripped(
        recursion::Resolution::read("signed-nl"),
        "sidn.nl.",
        RecordType::A,
    );
    let authorities = Authorities::new([&capture]);
    let caches = caches(Config::default());
    steer(&caches, &capture);
    let pipeline = pipeline(
        Config::default(),
        validating(&caches, &capture, Allowance::default()),
    );
    let checked = client_query("sidn.nl.", RecordType::A, Flags::NONE, true);
    let (bogus, _) = ask(&pipeline, (&checked, CLIENT), &authorities, at(&capture));
    let bogus = decode(bogus.as_deref().expect("a reply"));
    assert_eq!(bogus.header.rcode, Rcode::SERVFAIL);
    // The bogus data the `RRset` cache holds, without AD, and no query sent.
    let unchecked = client_query("sidn.nl.", RecordType::A, Flags::CD, true);
    let (reply, sent) = ask(&pipeline, (&unchecked, CLIENT), &authorities, at(&capture));
    assert_eq!(sent, Some(0));
    let reply = decode(reply.as_deref().expect("a reply"));
    assert_eq!(reply.header.rcode, Rcode::NOERROR);
    assert!(!reply.header.flags.contains(Flags::AD));
    assert!(
        reply.answer.iter().any(|r| r.rtype() == RecordType::A),
        "{reply:?}"
    );
}

#[test]
fn d197_the_stage_tells_its_validation() {
    let capture = recursion::Resolution::read("signed-nl");
    let caches = caches(Config::default());
    assert!(unminimised(Arc::clone(&caches)).validation().is_none());
    let validator = Validator::new(TrustAnchors::root(), dedens_dnssec::Limits::default());
    let at = capture.captured_at;
    let validating = Validating::new(validator, Arc::new(move || at)).tagged("anchors");
    let stage = unminimised(caches).validating(validating);
    assert_eq!(stage.validation().map(Validating::tag), Some("anchors"));
    assert_eq!(stage.validation_tag(), Some("anchors"));
}

/// D186: a validating recurse stage parks no query: one the allowance refuses is given up at once, its share's
/// unit given back, and counted shed.
#[cfg(feature = "metrics")]
#[test]
fn d197_a_query_the_allowance_refuses_is_counted_shed() {
    let recorder = metrics_util::debugging::DebuggingRecorder::new();
    let snapshotter = recorder.snapshotter();
    let capture = recursion::Resolution::read("signed-nl");
    let authorities = Authorities::new([&capture]);
    let caches = caches(Config::default());
    let allowance = Allowance {
        burst: 0,
        ..Allowance::default()
    };
    let recurse =
        metrics::with_local_recorder(&recorder, || validating(&caches, &capture, allowance));
    let pipeline = pipeline(Config::default(), recurse);
    let query = client_query("sidn.nl.", RecordType::A, Flags::NONE, true);
    let (reply, sent) = ask(&pipeline, (&query, CLIENT), &authorities, at(&capture));
    assert_eq!(sent, Some(0));
    assert_eq!(
        ede(&decode(reply.as_deref().expect("a reply"))),
        Some(InfoCode::NOT_READY)
    );
    assert_eq!(
        crate::metrics::counted(&snapshotter, "dedens_validations_total", "verdict"),
        [("shed".to_owned(), 1)]
    );
}
