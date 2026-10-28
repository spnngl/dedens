//! The cache hit path: look up, copy and patch into the caller's buffer.
//!
//! `hit` serves real responses on one thread; `hit_hot` has every thread ask one name (one shard lock), and
//! `hit_spread` spreads them over many names, as real traffic does. `insert` is the cost of storing a response.

use std::hint::black_box;
use std::net::Ipv4Addr;
use std::sync::atomic::{AtomicUsize, Ordering};

use dedens_bench::{CASES, wire};
use dedens_cache::{Cache, Config, Key, Lookup, StalePolicy};
use dedens_proto::{Class, Flags, Message, Name, Query, Question, RData, Record, RecordType, Ttl};
use divan::Bencher;

fn main() {
    divan::main();
}

const THREADS: &[usize] = &[1, 4, 8];

/// Names in `hit_spread`.
const SPREAD: usize = 10_000;

fn cache() -> Cache {
    Cache::new(Config::default()).expect("the default config is valid")
}

/// The query a captured response answers.
fn query_for(response: &[u8]) -> Vec<u8> {
    let message = Message::decode(response).expect("decodes").message;
    let question = message.questions[0].clone();
    Message::query(7, question).to_vec().expect("a query fits")
}

fn key(query: &[u8]) -> Key {
    Key::of(&Query::read(query).expect("a valid query")).expect("a question")
}

fn hit_once(cache: &Cache, query: &[u8], out: &mut [u8]) -> usize {
    let query = Query::read(black_box(query)).expect("a valid query");
    match cache.lookup(&query, 10, StalePolicy::Never, out) {
        Lookup::Hit(hit) => hit.len,
        other => unreachable!("expected a hit, got {other:?}"),
    }
}

#[divan::bench(args = CASES)]
fn hit(bencher: Bencher<'_, '_>, case: &str) {
    let response = wire(case);
    let query = query_for(&response);
    let cache = cache();
    if cache.insert(&key(&query), &response, 0).is_err() {
        // Not cacheable (TC, NXDOMAIN without SOA...): nothing to time.
        return;
    }
    let mut out = vec![0; 65_535];
    bencher.bench_local(|| hit_once(&cache, &query, &mut out));
}

#[divan::bench(args = CASES)]
fn insert(bencher: Bencher<'_, '_>, case: &str) {
    let response = wire(case);
    let query = query_for(&response);
    let key = key(&query);
    let cache = cache();
    bencher.bench_local(|| cache.insert(&key, black_box(&response), 0).is_ok());
}

fn synthetic(name: &str) -> (Vec<u8>, Vec<u8>) {
    let owner = Name::from_labels(name.split('.').map(str::as_bytes)).expect("a valid name");
    let question = Question::new(owner.clone(), RecordType::A);
    let query = Message::query(7, question.clone()).to_vec().expect("fits");
    let mut response = Message::query(7, question);
    response.header.flags = Flags::QR.with(Flags::RD).with(Flags::RA);
    response.answer = vec![Record::new(
        owner,
        Class::IN,
        Ttl::new(3600).expect("valid"),
        &RData::A(Ipv4Addr::new(192, 0, 2, 1)),
    )];
    (query, response.to_vec().expect("fits"))
}

#[divan::bench(threads = THREADS)]
fn hit_hot(bencher: Bencher<'_, '_>) {
    let cache = cache();
    let (query, response) = synthetic("www.example.com");
    cache.insert(&key(&query), &response, 0).expect("cacheable");
    bencher.bench(|| hit_once(&cache, &query, &mut [0; 512]));
}

#[divan::bench(threads = THREADS)]
fn hit_spread(bencher: Bencher<'_, '_>) {
    let cache = cache();
    let queries: Vec<Vec<u8>> = (0..SPREAD)
        .map(|i| {
            let (query, response) = synthetic(&format!("host{i}.example.com"));
            cache.insert(&key(&query), &response, 0).expect("cacheable");
            query
        })
        .collect();
    let next = AtomicUsize::new(0);
    bencher.bench(|| {
        let i = next.fetch_add(7919, Ordering::Relaxed) % SPREAD;
        hit_once(&cache, &queries[i], &mut [0; 512])
    });
}
