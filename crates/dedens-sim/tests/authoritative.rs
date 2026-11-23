//! `dedensd` resolving from the root (D195) on an Internet whose authoritative servers are `dedensd` too, each an
//! authoritative stage (D208) serving the root zone of RFC 1034 §6.1 and the zone `ISI.EDU.` of RFC 1035 §5.3, at the
//! addresses the root zone gives its servers: the resolver follows the root's referral to them and answers a name of
//! `ISI.EDU.` (RFC 1034 §5.3.3).

use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;

use dedens_cache::{Cache, Config};
use dedens_proto::rdata::RData;
use dedens_proto::{
    Flags, Header, MAX_MESSAGE_LEN, Message, Name, Question, Rcode, RecordType, Ttl,
};
use dedens_resolver::{Caches, DEFAULT_CAPACITY, InfraCache, RrsetCache};
use dedens_roots::RootHints;
use dedens_server::{Authoritative, Pipeline, Recurse, Stage};
use dedens_sim::client::Carrier;
use dedens_sim::oracle::Expected;
use dedens_sim::seed::{self, Seed};
use dedens_sim::topology::{Topology, World};
use dedens_zone::{Dnssec, Limits, Source, Zone};

use crate::util::SEEDS;

/// The step of the simulation: the latencies of its links are tens of milliseconds.
const TICK: Duration = Duration::from_millis(10);

/// The addresses of the root's servers in RFC 1034 §6.1, A.ISI.EDU, C.ISI.EDU and SRI-NIC.ARPA: each a host, as
/// the referral to `EDU.` names two of them.
const SERVERS: [[u8; 4]; 4] = [
    [26, 3, 0, 103],
    [10, 0, 0, 52],
    [26, 0, 0, 73],
    [10, 0, 0, 51],
];

/// The root hints of RFC 1034 §6.1's root zone: its NS records and their addresses.
const HINTS: &str = ". 3600000 NS A.ISI.EDU.
. 3600000 NS C.ISI.EDU.
. 3600000 NS SRI-NIC.ARPA.
A.ISI.EDU. 3600000 A 26.3.0.103
C.ISI.EDU. 3600000 A 10.0.0.52
SRI-NIC.ARPA. 3600000 A 26.0.0.73
SRI-NIC.ARPA. 3600000 A 10.0.0.51
";

/// The zone of `apex` in `testdata/zones/{file}`, its `$INCLUDE` the mailboxes of RFC 1035 §5.3.
fn zone(apex: &str, file: &str) -> Arc<Zone> {
    let zones = dedens_testkit::path("zones");
    let text = std::fs::read(zones.join(file)).expect("the zone file");
    let source = Source {
        name: file,
        text: &text,
        // dedensd's default (D208).
        default_ttl: Some(Ttl::from_wire(3600)),
    };
    let mut include = |_: &str| {
        std::fs::read(zones.join("rfc1035_isi_mailboxes.zone")).map_err(|e| e.to_string())
    };
    let apex: Name<'static> = apex.parse().expect("a name");
    let loaded = Zone::load(apex, source, &mut include, &Limits::default());
    Arc::new(loaded.expect("the zone loads").zone)
}

/// A cache stage, one shard (D133), then a recurse stage from the hints of [`HINTS`], asking the servers at private
/// addresses the run gives them (D191).
fn resolver() -> Pipeline {
    let config = Config {
        shards: 1,
        ..Config::default()
    };
    let caches = Caches {
        rrsets: RrsetCache::new(DEFAULT_CAPACITY, config.clone()).expect("a valid config"),
        infra: InfraCache::new(InfraCache::DEFAULT_CAPACITY, 1).expect("a valid size"),
        roots: RootHints::read(HINTS.as_bytes()).expect("valid hints"),
        tlds: None,
    };
    Pipeline::new(vec![
        Stage::Cache(Arc::new(Cache::new(config).expect("valid settings"))),
        Stage::Recurse(Recurse::new(Arc::new(caches)).asking_local_addresses(true)),
    ])
}

/// The question the client asks: a name of `ISI.EDU.`, two addresses (RFC 1035 §5.3).
fn question() -> Question<'static> {
    Question::new("VENERA.ISI.EDU.".parse().expect("a name"), RecordType::A)
}

/// What `zone` answers to `question`, as its servers send it.
fn answered(zone: &Zone, question: &Question<'static>) -> Expected {
    let answer = zone.answer(question);
    let mut message = Message {
        header: Header {
            flags: Flags::QR,
            ..Header::default()
        },
        questions: vec![question.clone()],
        ..Message::default()
    };
    answer.fill(zone, &mut message, MAX_MESSAGE_LEN, Dnssec::Without);
    Expected::of(&message.into_owned())
}

/// A world of the root's servers, each `dedensd` serving the root and `ISI.EDU.`, and `dedensd` resolving.
fn world(seed: Seed) -> World {
    let zones = [
        zone(".", "rfc1034_root.zone"),
        zone("ISI.EDU.", "rfc1035_isi.zone"),
    ];
    let mut topology = Topology::new().expecting(answered(&zones[1], &question()));
    for address in SERVERS {
        let zones = zones.clone();
        topology = topology.dedensd_at(IpAddr::from(address), move || {
            let stage = Authoritative::new(zones.iter().cloned()).expect("two zones");
            Pipeline::new(vec![Stage::Authoritative(stage)])
        });
    }
    topology
        .resolver(|_| resolver())
        .dedensd()
        .tick(TICK)
        .build(seed)
}

#[test]
fn rfc1034_5_3_3_dedensd_resolves_through_dedensd_authoritative_servers() {
    seed::each(SEEDS, |seed| {
        let mut world = world(seed);
        world.client(async move |stub| {
            let answer = stub.expect(question(), Carrier::Udp).await?;
            assert_eq!(answer.message.rcode(), Rcode::NOERROR);
            let mut addresses: Vec<String> = (answer.message.answer.iter())
                .filter_map(|record| match record.data() {
                    RData::A(address) => Some(address.to_string()),
                    _ => None,
                })
                .collect();
            addresses.sort();
            assert_eq!(addresses, ["10.1.0.52", "128.9.0.32"], "{answer:?}");
            Ok(())
        });
        world.run().expect("the run passes its checks");
    });
}
