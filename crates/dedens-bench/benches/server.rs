//! The server's hit path (D23, D43): `Pipeline::query` reading a query and answering it from the cache stage, as
//! `dedensd` does for each datagram. The allocation counts show the path allocates nothing.

use std::hint::black_box;
use std::net::SocketAddr;

use dedens_bench::{CASES, wire};
use dedens_cache::{Cache, Config};
use dedens_proto::{Edns, Message};
use dedens_server::{Forward, Pipeline, Stage, Step, Transport};
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

/// A pipeline whose cache holds `response`, the answer to `query`, stored at time 0.
fn caching(query: &[u8], response: &[u8]) -> Pipeline {
    let server = SocketAddr::from(([192, 0, 2, 53], 53));
    let pipeline = Pipeline::new(vec![
        Stage::Cache(Cache::new(Config::default()).expect("the default config is valid")),
        Stage::Forward(Forward::new(&[server]).expect("a server")),
    ]);
    let mut out = vec![0; 65535];
    let Step::Upstream(upstream) = pipeline.query(query, Transport::Udp, 0, &mut out) else {
        unreachable!("an empty cache sends the query upstream");
    };
    let step = pipeline.receive(upstream, Some(response), 0, &mut out);
    assert!(matches!(step, Step::Reply(_)), "{step:?}");
    pipeline
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
