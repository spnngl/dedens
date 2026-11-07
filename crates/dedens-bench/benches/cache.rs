//! The cache hit path: look up, copy and patch into the caller's buffer.
//!
//! `hit` serves real responses on one thread; `hit_hot` has every thread ask one name (one shard lock), and
//! `hit_spread` spreads them over many names, as real traffic does. `insert` is the cost of storing a response
//! already decoded, as a forwarder has it; `insert_evicting_hot` is one that must evict from a full shard whose
//! entries all have the most hits (D116); `insert_under_hits` one that waits behind threads hitting its shard
//! (D137).
//!
//! Features `metrics` (counters on, no recorder) and `recorder` (counters on and recorded) measure the cache's
//! counters (D30).

use std::cell::Cell;
use std::hash::{BuildHasher, RandomState};
use std::hint::black_box;
use std::net::Ipv4Addr;
use std::sync::atomic::{AtomicBool, Ordering};

use dedens_bench::{CASES, wire};
use dedens_cache::{Cache, Config, Lookup, StalePolicy};
use dedens_proto::rdata::RData;
use dedens_proto::{Class, Flags, Message, Name, Query, Question, Record, RecordType, Ttl};
use divan::Bencher;

#[global_allocator]
static ALLOC: divan::AllocProfiler = divan::AllocProfiler::system();

fn main() {
    #[cfg(feature = "recorder")]
    metrics_util::debugging::DebuggingRecorder::new()
        .install()
        .expect("no recorder installed yet");
    divan::main();
}

const THREADS: &[usize] = &[1, 4, 8];

/// Threads hitting in `insert_under_hits`.
const HITTERS: usize = 7;

/// Names in `hit_spread`.
const SPREAD: usize = 10_000;

thread_local! {
    /// The next name a thread of `hit_spread` asks: each thread walks the names from its own random start, sharing
    /// no counter with the others.
    static NEXT: Cell<usize> = Cell::new(
        usize::try_from(RandomState::new().hash_one(0) % 10_000).unwrap_or_default(),
    );
}

fn cache() -> Cache {
    Cache::new(Config::default()).expect("the default config is valid")
}

/// The query a captured response answers.
fn query_for(response: &[u8]) -> Vec<u8> {
    let message = Message::decode(response).expect("decodes").message;
    let question = message.questions[0].clone();
    Message::query(7, question).to_vec().expect("a query fits")
}

/// Stores `response` at time 0, the answer to `query`.
fn insert_at_0(cache: &Cache, query: &[u8], response: &[u8]) -> bool {
    let query = Query::read(query).expect("a valid query");
    let decoded = Message::decode(response).expect("decodes");
    cache.insert(&query, &decoded, 0, 0).is_ok()
}

/// Looks `query` up at time 0, when it was stored: every record has TTL 1 or more, so it is fresh.
fn hit_once(cache: &Cache, query: &[u8], out: &mut [u8]) -> usize {
    let query = Query::read(black_box(query)).expect("a valid query");
    match cache.lookup(&query, 0, StalePolicy::Never, out) {
        Lookup::Hit(hit) => hit.len,
        other => unreachable!("expected a hit, got {other:?}"),
    }
}

#[divan::bench(args = CASES)]
fn hit(bencher: Bencher<'_, '_>, case: &str) {
    let response = wire(case);
    let query = query_for(&response);
    let cache = cache();
    if !insert_at_0(&cache, &query, &response) {
        // Not cacheable (TC, NXDOMAIN without SOA...): nothing to time.
        return;
    }
    let mut out = vec![0; 65_535];
    bencher.bench_local(|| hit_once(&cache, &query, &mut out));
}

/// A hit larger than the client's buffer (512 bytes, no EDNS): answered truncated, as the root DNSKEY set is.
/// Its time is compared to `hit` of the same case, which copies the response whole.
#[divan::bench]
fn hit_truncated(bencher: Bencher<'_, '_>) {
    let response = wire("txt_large");
    let query = query_for(&response);
    let cache = cache();
    assert!(insert_at_0(&cache, &query, &response), "cacheable");
    let mut out = out();
    bencher.bench_local(|| {
        let query = Query::read(black_box(&query)).expect("a valid query");
        match cache.lookup(&query, 0, StalePolicy::Never, &mut out) {
            Lookup::Hit(hit) => {
                assert!(hit.truncated, "too large for 512 bytes");
                hit.len
            }
            other => unreachable!("expected a hit, got {other:?}"),
        }
    });
}

#[divan::bench(args = CASES)]
fn insert(bencher: Bencher<'_, '_>, case: &str) {
    let response = wire(case);
    let decoded = Message::decode(&response).expect("decodes");
    let query = query_for(&response);
    let query = Query::read(&query).expect("a valid query");
    let cache = cache();
    bencher.bench_local(|| cache.insert(&query, black_box(&decoded), 0, 0).is_ok());
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

/// A buffer for one response, made outside the timed loop.
fn out() -> Vec<u8> {
    vec![0; 512]
}

#[divan::bench(threads = THREADS)]
fn hit_hot(bencher: Bencher<'_, '_>) {
    let cache = cache();
    let (query, response) = synthetic("www.example.com");
    assert!(insert_at_0(&cache, &query, &response), "cacheable");
    bencher
        .with_inputs(out)
        .bench_refs(|out| hit_once(&cache, &query, out));
}

/// One insert into a full shard whose every entry sits in main with the most hits: evicting one takes passing over
/// entries again and again (E8, D116). Each sample is a new cache, built outside the timing; the slowest of them
/// tells, not the median.
#[divan::bench(sample_count = 300, sample_size = 1)]
fn insert_evicting_hot(bencher: Bencher<'_, '_>) {
    let store = |cache: &Cache, i: usize| {
        let (query, response) = synthetic(&format!("host{i}.example.com"));
        assert!(insert_at_0(cache, &query, &response), "cacheable");
        query
    };
    // Entries evicted meanwhile answer with a miss: nothing to count for them.
    let hit_all = |cache: &Cache, queries: &[Vec<u8>], times: usize| {
        let mut out = out();
        for query in queries {
            let query = Query::read(query).expect("a valid query");
            for _ in 0..times {
                black_box(cache.lookup(&query, 0, StalePolicy::Never, &mut out));
            }
        }
    };
    bencher
        .with_inputs(|| {
            let cache = Cache::new(Config {
                capacity: 1 << 20,
                shards: 1,
                ..Config::default()
            })
            .expect("a valid config");
            // Fill the shard, hit each entry once, and insert one more: every entry moves from small to main.
            let mut queries = vec![];
            while cache.len() == queries.len() {
                queries.push(store(&cache, queries.len()));
            }
            hit_all(&cache, &queries, 1);
            let next = store(&cache, queries.len());
            queries.push(next);
            // The most hits, for the entries still stored.
            hit_all(&cache, &queries, 3);
            let (query, response) = synthetic("new.example.com");
            (cache, query, response)
        })
        // The cache goes out with the result: dropping it is not the insert.
        .bench_values(|(cache, query, response)| {
            let stored = insert_at_0(&cache, &query, &response);
            (cache, stored)
        });
}

/// A store of one name into the only shard while `HITTERS` threads hit another name of it: how long a writer waits
/// behind readers of the same lock (D137), where `hit_hot` times the readers. They hit until the timing ends.
#[divan::bench(sample_count = 300)]
fn insert_under_hits(bencher: Bencher<'_, '_>) {
    let cache = Cache::new(Config {
        shards: 1,
        ..Config::default()
    })
    .expect("a valid config");
    let (hot, response) = synthetic("www.example.com");
    assert!(insert_at_0(&cache, &hot, &response), "cacheable");
    let (stored, response) = synthetic("other.example.com");
    let decoded = Message::decode(&response).expect("decodes");
    let stored = Query::read(&stored).expect("a valid query");
    let done = AtomicBool::new(false);
    std::thread::scope(|scope| {
        for _ in 0..HITTERS {
            scope.spawn(|| {
                let mut out = out();
                while !done.load(Ordering::Relaxed) {
                    hit_once(&cache, &hot, &mut out);
                }
            });
        }
        bencher.bench_local(|| cache.insert(&stored, black_box(&decoded), 0, 0).is_ok());
        done.store(true, Ordering::Relaxed);
    });
}

#[divan::bench(threads = THREADS)]
fn hit_spread(bencher: Bencher<'_, '_>) {
    let cache = cache();
    let queries: Vec<Vec<u8>> = (0..SPREAD)
        .map(|i| {
            let (query, response) = synthetic(&format!("host{i}.example.com"));
            assert!(insert_at_0(&cache, &query, &response), "cacheable");
            query
        })
        .collect();
    let next = || {
        NEXT.with(|next| {
            let i = next.get();
            next.set((i + 7919) % SPREAD);
            i
        })
    };
    bencher
        .with_inputs(|| (next(), out()))
        .bench_refs(|(i, out)| hit_once(&cache, &queries[*i], out));
}
