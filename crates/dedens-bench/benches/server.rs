//! The server's paths (D23, D43), as `dedensd` runs them for each datagram: a hit, `Pipeline::query` reading a
//! query and answering it from the cache stage, and a miss, the query sent upstream and its response stored and
//! answered; a plugin answering with records it holds (D54); and an authoritative stage answering from its zones
//! (D208), without keys and with them, its query unsigned and signed (D211). The allocation counts show the hit
//! and plugin paths allocate nothing.

use std::hint::black_box;
use std::net::{Ipv4Addr, SocketAddr};
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::sync::Arc;

use dedens_bench::CASES;
use dedens_cache::{Cache, Checked, Config};
use dedens_proto::edns::{Edns, EdnsFlags};
use dedens_proto::rdata::RData;
use dedens_proto::{Class, Message, Name, Query, Question, Record, RecordType, Transport, Ttl};
use dedens_server::{Answer, Authoritative, Forward, Pipeline, Plugin, Records, Stage, Step};
use dedens_testkit::{captured, query};
use dedens_tsig::{Algorithm, Key, Keyring, sign_request};
use dedens_zone::{Limits, Source, Zone};
use divan::Bencher;

#[global_allocator]
static ALLOC: divan::AllocProfiler = divan::AllocProfiler::system();

fn main() {
    divan::main();
}

/// A caching forwarder, its cache empty.
fn forwarding() -> Pipeline {
    let server = SocketAddr::from(([192, 0, 2, 53], 53));
    Pipeline::new(vec![
        Stage::Cache(Arc::new(
            Cache::new(Config::default()).expect("the default config is valid"),
        )),
        Stage::Forward(Forward::new([server]).expect("a server")),
    ])
}

/// A pipeline whose cache holds `response`, the answer to `query`, stored at time 0.
fn caching(query: &[u8], response: &[u8]) -> Pipeline {
    let pipeline = forwarding();
    let mut out = vec![0; 65535];
    let Step::Upstream(upstream) = pipeline.query(
        query,
        Transport::Udp,
        Ipv4Addr::LOCALHOST.into(),
        0,
        &mut out,
    ) else {
        unreachable!("an empty cache sends the query upstream");
    };
    let step = pipeline.receive(upstream, Some(response), 0, &mut out);
    assert!(matches!(step, Step::Reply(_)), "{step:?}");
    pipeline
}

/// A query missing the cache, sent upstream, then the response stored and the reply made from it.
#[divan::bench(args = CASES)]
fn miss(bencher: Bencher<'_, '_>, case: &str) {
    let response = captured(case);
    let query = query(case, 7).to_vec().expect("a query fits");
    let mut out = vec![0; 1232];
    bencher
        .with_inputs(forwarding)
        .bench_local_refs(|pipeline| {
            let Step::Upstream(upstream) = pipeline.query(
                black_box(&query),
                Transport::Udp,
                Ipv4Addr::LOCALHOST.into(),
                0,
                &mut out,
            ) else {
                unreachable!("an empty cache sends the query upstream");
            };
            black_box(upstream.request());
            let step = pipeline.receive(upstream, Some(black_box(&response)), 0, &mut out);
            assert!(matches!(step, Step::Reply(_)));
        });
}

/// A query answered from the cache: read, looked up, copied and patched into a 1232-byte buffer.
#[divan::bench(args = CASES)]
fn hit(bencher: Bencher<'_, '_>, case: &str) {
    let response = captured(case);
    let query = query(case, 7).to_vec().expect("a query fits");
    let pipeline = caching(&query, &response);
    let mut out = vec![0; 1232];
    bencher.bench_local(|| {
        let step = pipeline.query(
            black_box(&query),
            Transport::Udp,
            Ipv4Addr::LOCALHOST.into(),
            0,
            &mut out,
        );
        assert!(matches!(step, Step::Reply(_)));
    });
}

/// `hit` under the `catch_unwind` that `dedensd` puts around the step of each datagram (D121): the landing pad costs
/// nothing until a panic, and nothing is allocated.
#[divan::bench(args = CASES)]
fn hit_guarded(bencher: Bencher<'_, '_>, case: &str) {
    let response = captured(case);
    let query = query(case, 7).to_vec().expect("a query fits");
    let pipeline = caching(&query, &response);
    let mut out = vec![0; 1232];
    bencher.bench_local(|| {
        let step = catch_unwind(AssertUnwindSafe(|| {
            pipeline.query(
                black_box(&query),
                Transport::Udp,
                Ipv4Addr::LOCALHOST.into(),
                0,
                &mut out,
            )
        }));
        assert!(matches!(step, Ok(Step::Reply(_))));
    });
}

/// A query for the captured response `response` with DO set, then `response` stored in the cache of a forwarder as
/// `checked`, the verdict of a validating stage (D77), and a hit on it: the hit path of a validating forwarder, whose
/// stage only differs from the plain one when the cache misses.
fn dnssec_hit(bencher: Bencher<'_, '_>, case: &str, checked: Checked) {
    let response = captured(case);
    let mut query = query(case, 7);
    query.edns = Some(Edns {
        flags: EdnsFlags::DO,
        ..Edns::default()
    });
    let query = query.to_vec().expect("a query fits");
    let pipeline = forwarding();
    let Some(Stage::Cache(cache)) = pipeline.stages().first() else {
        unreachable!("the cache comes first");
    };
    cache
        .insert_checked(
            &Query::read(&query).expect("a query"),
            &Message::decode(&response).expect("decodes"),
            0,
            checked,
            0,
        )
        .expect("cacheable");
    let mut out = vec![0; 1232];
    bencher.bench_local(|| {
        let step = pipeline.query(
            black_box(&query),
            Transport::Udp,
            Ipv4Addr::LOCALHOST.into(),
            0,
            &mut out,
        );
        assert!(matches!(step, Step::Reply(_)));
    });
}

/// `hit` for a client with DO, the response stored without a verdict: what `hit_secure` is compared with.
#[divan::bench(args = CASES)]
fn hit_dnssec_ok(bencher: Bencher<'_, '_>, case: &str) {
    dnssec_hit(bencher, case, Checked::Unchecked);
}

/// `hit` for a client with DO, the response stored as validated secure: the AD bit set from the verdict (D77).
#[divan::bench(args = CASES)]
fn hit_secure(bencher: Bencher<'_, '_>, case: &str) {
    dnssec_hit(bencher, case, Checked::Secure);
}

/// Answers every query with the records of the captured response's answer section, as a hosts plugin would.
#[derive(Debug)]
struct Fixed(Records);

impl Plugin for Fixed {
    fn answer(&self, _: &Query<'_>) -> Option<Answer<'_>> {
        Some(Answer {
            rcode: dedens_proto::Rcode::NOERROR,
            records: Some(&self.0),
            authoritative: true,
            error: None,
        })
    }
}

/// A query answered by a plugin: read, then its records copied after the question.
#[divan::bench]
fn plugin(bencher: Bencher<'_, '_>) {
    let name: dedens_proto::Name<'static> = "host.example.".parse().expect("a name");
    let records: Vec<_> = (1..=2)
        .map(|i| {
            Record::new(
                name.clone(),
                Class::IN,
                Ttl::from_wire(3600),
                &RData::A([192, 0, 2, i].into()),
            )
        })
        .collect();
    let pipeline = Pipeline::new(vec![Stage::Plugin(Box::new(Fixed(
        Records::new(&name, &records).expect("the records fit"),
    )))]);
    let mut query = Message::query(7, Question::new(name, RecordType::A));
    query.edns = Some(Edns::default());
    let query = query.to_vec().expect("a query fits");
    let mut out = vec![0; 1232];
    bencher.bench_local(|| {
        let step = pipeline.query(
            black_box(&query),
            Transport::Udp,
            Ipv4Addr::LOCALHOST.into(),
            0,
            &mut out,
        );
        assert!(matches!(step, Step::Reply(_)));
    });
}

/// The zone of `origin` in `testdata/{file}`, its `$INCLUDE` the mailboxes of RFC 1035 §5.3, records without a TTL
/// at dedensd's 3600 seconds (D208).
fn zone(origin: &str, file: &str) -> Arc<Zone> {
    let text = std::fs::read(dedens_testkit::path(file)).expect("the zone file");
    let source = Source {
        name: file,
        text: &text,
        default_ttl: Some(Ttl::from_wire(3600)),
    };
    let mut include = |_: &str| {
        std::fs::read(dedens_testkit::path("zones/rfc1035_isi_mailboxes.zone"))
            .map_err(|e| e.to_string())
    };
    let origin: Name<'static> = origin.parse().expect("a name");
    let loaded = Zone::load(origin, source, &mut include, &Limits::default());
    Arc::new(loaded.expect("the zone loads").zone)
}

/// The questions of `authoritative`: data (two addresses), data with additional records (two MX and their four
/// addresses), a name not there (NXDOMAIN with the SOA), and a referral of the captured root zone to `com.` (13 name
/// servers, their glue).
const AUTHORITATIVE: [(&str, RecordType); 4] = [
    ("VENERA.ISI.EDU.", RecordType::A),
    ("ISI.EDU.", RecordType::MX),
    ("NOTHERE.ISI.EDU.", RecordType::A),
    ("www.example.com.", RecordType::A),
];

/// The time the keyed benches' requests are signed and verified at.
const NOW: u64 = 1_750_000_000;

/// A pipeline of an authoritative stage serving the captured root zone and `ISI.EDU.` of RFC 1035 §5.3, verifying
/// requests with one key if `keyed` (D211).
fn serving(keyed: Option<&Key>) -> Pipeline {
    let zones = [
        zone(".", "authoritative/zones/root.zone"),
        zone("ISI.EDU.", "zones/rfc1035_isi.zone"),
    ];
    let pipeline = Pipeline::new(vec![Stage::Authoritative(
        Authoritative::new(zones).expect("two zones"),
    )]);
    match keyed {
        Some(key) => pipeline.with_keys(
            Keyring::new([key.clone()]).expect("one key"),
            Arc::new(|| NOW),
        ),
        None => pipeline,
    }
}

/// The key the keyed benches sign with.
fn key() -> Key {
    let name = "transfer.".parse().expect("a name");
    Key::new(name, Algorithm::HmacSha256, vec![7; 32]).expect("a key")
}

/// A query with EDNS for `name`, signed with `key` at `NOW` if there is one.
fn authoritative_query(name: &str, qtype: RecordType, key: Option<&Key>) -> Vec<u8> {
    let mut query = Message::query(7, Question::new(name.parse().expect("a name"), qtype));
    query.edns = Some(Edns::default());
    let mut wire = query.to_vec().expect("a query fits");
    if let Some(key) = key {
        sign_request(key, &mut wire, NOW).expect("room for the TSIG");
    }
    wire
}

/// Answers `query` from `pipeline` into a 1232-byte buffer.
fn answer(bencher: Bencher<'_, '_>, pipeline: &Pipeline, query: &[u8]) {
    let mut out = vec![0; 1232];
    bencher.bench_local(|| {
        let step = pipeline.query(
            black_box(query),
            Transport::Udp,
            Ipv4Addr::LOCALHOST.into(),
            0,
            &mut out,
        );
        assert!(matches!(step, Step::Reply(_)));
    });
}

/// A query answered by an authoritative stage serving the captured root zone and `ISI.EDU.` of RFC 1035 §5.3: read,
/// its zone found, the answer filled and encoded into a 1232-byte buffer (D208).
#[divan::bench(args = AUTHORITATIVE)]
fn authoritative(bencher: Bencher<'_, '_>, (name, qtype): (&str, RecordType)) {
    answer(
        bencher,
        &serving(None),
        &authoritative_query(name, qtype, None),
    );
}

/// `authoritative` with keys ([`Pipeline::with_keys`]) and an unsigned query: what a server with keys costs each
/// query that carries no TSIG (D211).
#[divan::bench(args = AUTHORITATIVE)]
fn authoritative_with_keys(bencher: Bencher<'_, '_>, (name, qtype): (&str, RecordType)) {
    let key = key();
    answer(
        bencher,
        &serving(Some(&key)),
        &authoritative_query(name, qtype, None),
    );
}

/// `authoritative` with keys and a query signed with one: the TSIG verified and the reply signed (D211).
#[divan::bench(args = AUTHORITATIVE)]
fn authoritative_signed(bencher: Bencher<'_, '_>, (name, qtype): (&str, RecordType)) {
    let key = key();
    answer(
        bencher,
        &serving(Some(&key)),
        &authoritative_query(name, qtype, Some(&key)),
    );
}
