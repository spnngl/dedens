//! The hit ratio of one cache shard under a workload, for tuning the eviction (E8, D116): how many rotations of hot
//! entries of main one eviction may make (`MAX_ROTATIONS` in `crates/dedens-cache/src/shard.rs`, changed by editing it
//! and running again).
//!
//! `cargo run --release -p dedens-bench --example hit_ratio` draws names from Zipf distributions (exponents 0.7,
//! 0.9 and 1.1, over twenty times as many names as the cache holds entries, shards of 1000 and 10000 entries): each
//! request looks the name up and, on a miss, stores a response of one address. The ratio is counted over the last
//! two thirds of the requests. The names are synthetic: `--trace FILE --entries N` reads one name per line of a
//! capture instead, for a cache of `N` entries.

#![expect(
    clippy::cast_precision_loss,
    reason = "counts and ranks far below 2^52, in a tool printing four digits"
)]

use std::fs;
use std::net::Ipv4Addr;

use dedens_cache::{Cache, Config, Lookup, StalePolicy};
use dedens_proto::{Class, Flags, Message, Name, Query, Question, RData, Record, RecordType, Ttl};

/// Requests per entry of the cache.
const REQUESTS_PER_ENTRY: usize = 100;
/// Names per entry of the cache in the synthetic workloads.
const NAMES_PER_ENTRY: usize = 20;

fn question(name: &str) -> Question<'static> {
    let owner = Name::from_labels(name.split('.').map(str::as_bytes)).expect("a valid name");
    Question::new(owner, RecordType::A)
}

fn query_of(name: &str) -> Vec<u8> {
    Message::query(7, question(name)).to_vec().expect("fits")
}

/// A response of one address, the same size for every name.
fn response_of(name: &str) -> Vec<u8> {
    let question = question(name);
    let owner = question.name.clone();
    let mut response = Message::query(7, question);
    response.header.flags = Flags::QR.with(Flags::RD).with(Flags::RA);
    response.answer = vec![Record::new(
        owner,
        Class::IN,
        Ttl::new(3600).expect("valid"),
        &RData::A(Ipv4Addr::new(192, 0, 2, 1)),
    )];
    response.to_vec().expect("fits")
}

/// Asks the cache for `name`, storing the answer on a miss; whether it was a hit.
fn request(cache: &Cache, name: &str, query: &[u8], out: &mut [u8]) -> bool {
    let read = Query::read(query).expect("a valid query");
    if matches!(
        cache.lookup(&read, 0, StalePolicy::Never, out),
        Lookup::Hit(_)
    ) {
        return true;
    }
    let wire = response_of(name);
    let decoded = Message::decode(&wire).expect("decodes");
    cache.insert(&read, &decoded, 0, 0).expect("cacheable");
    false
}

/// Bytes one entry takes in the cache, as the cache counts them.
fn entry_cost(name: &str) -> usize {
    let probe = Cache::new(Config::default()).expect("valid");
    let (query, wire) = (query_of(name), response_of(name));
    let read = Query::read(&query).expect("valid");
    let decoded = Message::decode(&wire).expect("decodes");
    probe.insert(&read, &decoded, 0, 0).expect("cacheable");
    probe.used()
}

/// The hit ratio over the last two thirds of `requests`, names indexed into `names`, by a cache of `entries`.
fn ratio(
    entries: usize,
    names: &[String],
    requests: impl Iterator<Item = usize>,
    total: usize,
) -> f64 {
    let cache = Cache::new(Config {
        capacity: entries * entry_cost(&names[0]),
        shards: 1,
        ..Config::default()
    })
    .expect("a valid config");
    let queries: Vec<Vec<u8>> = names.iter().map(|name| query_of(name)).collect();
    let mut out = vec![0; 512];
    let (mut hits, mut counted) = (0_usize, 0_usize);
    for (i, name) in requests.enumerate() {
        let hit = request(&cache, &names[name], &queries[name], &mut out);
        if i >= total / 3 {
            counted += 1;
            hits += usize::from(hit);
        }
    }
    hits as f64 / counted as f64
}

/// A deterministic stream of numbers in `0..1`.
struct Uniform(u64);

impl Uniform {
    fn next(&mut self) -> f64 {
        // SplitMix64.
        self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^= z >> 31;
        (z >> 11) as f64 / (1_u64 << 53) as f64
    }
}

fn zipf(entries: usize, exponent: f64) -> f64 {
    let names: Vec<String> = (0..NAMES_PER_ENTRY * entries)
        .map(|i| format!("n{i}.example.com"))
        .collect();
    // Cumulative weights of the ranks: a draw is the first rank whose sum reaches it.
    let mut sum = 0.0;
    let cumulative: Vec<f64> = (1..=names.len())
        .map(|rank| {
            sum += (rank as f64).powf(-exponent);
            sum
        })
        .collect();
    let total = REQUESTS_PER_ENTRY * entries;
    let last = names.len() - 1;
    let mut uniform = Uniform(entries as u64);
    let draws = (0..total).map(move |_| {
        let target = uniform.next() * sum;
        cumulative.partition_point(|&c| c < target).min(last)
    });
    ratio(entries, &names, draws, total)
}

fn trace(path: &str, entries: usize) -> f64 {
    let text = fs::read_to_string(path).expect("a readable trace");
    let mut names: Vec<String> = vec![];
    let mut index = std::collections::HashMap::new();
    let requests: Vec<usize> = text
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .map(|line| {
            let line = line.trim_end_matches('.');
            *index.entry(line.to_owned()).or_insert_with(|| {
                names.push(line.to_owned());
                names.len() - 1
            })
        })
        .collect();
    let total = requests.len();
    ratio(entries, &names, requests.into_iter(), total)
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let value = |flag: &str| {
        args.iter()
            .position(|arg| arg == flag)
            .and_then(|at| args.get(at + 1))
    };
    if let Some(path) = value("--trace") {
        let entries = value("--entries")
            .and_then(|n| n.parse().ok())
            .expect("--entries N with --trace");
        println!(
            "trace {path} entries={entries} hit={:.4}",
            trace(path, entries)
        );
        return;
    }
    println!("entry cost={}", entry_cost("n0.example.com"));
    for entries in [1_000, 10_000] {
        for exponent in [0.7, 0.9, 1.1] {
            println!(
                "zipf={exponent} entries={entries} hit={:.4}",
                zipf(entries, exponent)
            );
        }
    }
}
