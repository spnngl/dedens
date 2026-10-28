//! The server's paths (D23, D43), as `dedensd` runs them for each datagram: a hit, `Pipeline::query` reading a
//! query and answering it from the cache stage, and a miss, the query sent upstream and its response stored and
//! answered; and a plugin answering with records it holds (D54). The allocation counts show the hit and plugin
//! paths allocate nothing.

use std::hint::black_box;
use std::net::SocketAddr;
use std::sync::Arc;

use dedens_bench::{CASES, wire};
use dedens_cache::{Cache, Config};
use dedens_proto::{Class, Edns, Message, Query, Question, RData, Record, RecordType, Ttl};
use dedens_server::{Answer, Forward, Pipeline, Plugin, Records, Stage, Step, Transport};
use divan::Bencher;

#[global_allocator]
static ALLOC: divan::AllocProfiler = divan::AllocProfiler::system();

fn main() {
    divan::main();
}

/// A query for the captured response `response`, with EDNS as most clients send it.
fn query_for(response: &[u8]) -> Vec<u8> {
    let message = Message::decode(response).expect("decodes").message;
    let mut query = Message::query(7, message.questions[0].clone());
    query.edns = Some(Edns::default());
    query.to_vec().expect("a query fits")
}

/// A caching forwarder, its cache empty.
fn forwarding() -> Pipeline {
    let server = SocketAddr::from(([192, 0, 2, 53], 53));
    Pipeline::new(vec![
        Stage::Cache(Arc::new(
            Cache::new(Config::default()).expect("the default config is valid"),
        )),
        Stage::Forward(Forward::new(&[server]).expect("a server")),
    ])
}

/// A pipeline whose cache holds `response`, the answer to `query`, stored at time 0.
fn caching(query: &[u8], response: &[u8]) -> Pipeline {
    let pipeline = forwarding();
    let mut out = vec![0; 65535];
    let Step::Upstream(upstream) = pipeline.query(query, Transport::Udp, 0, &mut out) else {
        unreachable!("an empty cache sends the query upstream");
    };
    let step = pipeline.receive(upstream, Some(response), 0, &mut out);
    assert!(matches!(step, Step::Reply(_)), "{step:?}");
    pipeline
}

/// A query missing the cache, sent upstream, then the response stored and the reply made from it.
#[divan::bench(args = CASES)]
fn miss(bencher: Bencher<'_, '_>, case: &str) {
    let response = wire(case);
    let query = query_for(&response);
    let mut out = vec![0; 1232];
    bencher
        .with_inputs(forwarding)
        .bench_local_refs(|pipeline| {
            let Step::Upstream(upstream) =
                pipeline.query(black_box(&query), Transport::Udp, 0, &mut out)
            else {
                unreachable!("an empty cache sends the query upstream");
            };
            let step = pipeline.receive(upstream, Some(black_box(&response)), 0, &mut out);
            assert!(matches!(step, Step::Reply(_)));
        });
}

/// A query answered from the cache: read, looked up, copied and patched into a 1232-byte buffer.
#[divan::bench(args = CASES)]
fn hit(bencher: Bencher<'_, '_>, case: &str) {
    let response = wire(case);
    let query = query_for(&response);
    let pipeline = caching(&query, &response);
    let mut out = vec![0; 1232];
    bencher.bench_local(|| {
        let step = pipeline.query(black_box(&query), Transport::Udp, 0, &mut out);
        assert!(matches!(step, Step::Reply(_)));
    });
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
        let step = pipeline.query(black_box(&query), Transport::Udp, 0, &mut out);
        assert!(matches!(step, Step::Reply(_)));
    });
}
