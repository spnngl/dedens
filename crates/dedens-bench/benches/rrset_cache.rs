//! The resolver's `RRset` cache (D193): `insert` stores a captured `RRset` into an empty cache, `replace` over the
//! other data of its key held at a lesser rank, `evict` into a full cache, evicting; `hit` looks one up; `group`
//! groups the records of a large response: a whole zone, or up to 2048 A records.
//!
//! The `RRsets`: `a`, the two A records of `example.com.`; `ns`, its two NS records; `root_ns`, the 13 NS records of
//! `com.` from a root server's referral. `insert` takes the `RRset` already grouped, as the resolver has it. The
//! zones of `group` are the examples of RFC 4035 Appendix A and RFC 5155 Appendix A, as if one response held them.

use std::hint::black_box;

use dedens_cache::{Checked, Config};
use dedens_proto::{Record, Section};
use dedens_resolver::{Rank, Rrset, RrsetCache};
use dedens_testkit::{captured, dns, message, zone};
use divan::Bencher;

#[global_allocator]
static ALLOC: divan::AllocProfiler = divan::AllocProfiler::system();

fn main() {
    divan::main();
}

const RRSETS: &[&str] = &["a", "ns", "root_ns"];

const ZONES: &[&str] = &["rfc4035_appendix_a.zone", "rfc5155_appendix_a.zone"];

/// The records of the `RRset` named `name` in [`RRSETS`].
fn records(name: &str) -> Vec<Record<'static>> {
    let (case, section) = match name {
        "a" => ("a", Section::Answer),
        "ns" => ("ns", Section::Answer),
        _ => ("referral_root", Section::Authority),
    };
    let message = message(&captured(case));
    match section {
        Section::Answer => message.answer,
        Section::Authority | Section::Additional => message.authority,
    }
}

/// The `RRset` named `name` in [`RRSETS`].
fn rrset(name: &str) -> Rrset {
    Rrset::group(&records(name)).remove(0)
}

/// The `RRset` named `name` in [`RRSETS`] but its first record: other data of the same key.
fn fewer(name: &str) -> Rrset {
    Rrset::group(&records(name)[1..]).remove(0)
}

/// One shard: the cost of an insert, not of the shards' allocation.
fn cache(capacity: usize) -> RrsetCache {
    let config = Config {
        shards: 1,
        ..Config::default()
    };
    RrsetCache::new(capacity, config).expect("a valid config")
}

#[divan::bench(args = RRSETS)]
fn insert(bencher: Bencher<'_, '_>, name: &str) {
    let rrset = rrset(name);
    bencher
        .with_inputs(|| (cache(1 << 20), rrset.clone()))
        .bench_local_values(|(cache, rrset)| {
            let inserted = cache.insert(rrset, Rank::AnswerNonAuthoritative, Checked::Unchecked, 0);
            // The cache is returned so that dropping it is not measured.
            (cache, inserted)
        });
}

#[divan::bench(args = RRSETS)]
fn replace(bencher: Bencher<'_, '_>, name: &str) {
    let (rrset, fewer) = (rrset(name), fewer(name));
    bencher
        .with_inputs(|| {
            let cache = cache(1 << 20);
            cache
                .insert(
                    fewer.clone(),
                    Rank::AdditionalAuthoritative,
                    Checked::Unchecked,
                    0,
                )
                .expect("stored");
            (cache, rrset.clone())
        })
        .bench_local_values(|(cache, rrset)| {
            let inserted = cache.insert(rrset, Rank::AnswerNonAuthoritative, Checked::Unchecked, 1);
            (cache, inserted)
        });
}

/// `a`, owned by `i.example.com.`: as many keys as wanted.
fn renamed(records: &[Record<'static>], i: usize) -> Rrset {
    let owner = dns(&format!("{i}.example.com."));
    let records: Vec<Record<'static>> = records
        .iter()
        .map(|r| Record {
            name: owner.clone(),
            ..r.clone()
        })
        .collect();
    Rrset::group(&records).remove(0)
}

#[divan::bench]
fn evict(bencher: Bencher<'_, '_>) {
    const CAPACITY: usize = 256 << 10;
    let records = records("a");
    let cache = cache(CAPACITY);
    let mut i = 0;
    // Full before measuring.
    while cache.used() < CAPACITY - (4 << 10) || i < 4096 {
        cache
            .insert(
                renamed(&records, i),
                Rank::AnswerNonAuthoritative,
                Checked::Unchecked,
                0,
            )
            .expect("stored");
        i += 1;
    }
    bencher
        .with_inputs(|| {
            i += 1;
            renamed(&records, i)
        })
        .bench_local_values(|rrset| {
            cache.insert(rrset, Rank::AnswerNonAuthoritative, Checked::Unchecked, 0)
        });
}

#[divan::bench(args = RRSETS)]
fn hit(bencher: Bencher<'_, '_>, name: &str) {
    let rrset = rrset(name);
    let cache = cache(1 << 20);
    let (owner, rtype, class) = (rrset.owner().clone(), rrset.rtype(), rrset.class());
    cache
        .insert(rrset, Rank::AnswerNonAuthoritative, Checked::Unchecked, 0)
        .expect("stored");
    bencher.bench(|| cache.get(black_box(&owner), rtype, class, 0));
}

#[divan::bench(args = ZONES)]
fn group(bencher: Bencher<'_, '_>, file: &str) {
    let records = zone(file);
    bencher.bench(|| Rrset::group(black_box(&records)));
}

/// `n` A records of distinct owners `i.example.com.`, from the captured `a`: up to the 2048 of a 64 KiB response.
fn many(n: usize) -> Vec<Record<'static>> {
    let record = records("a").remove(0);
    (0..n)
        .map(|i| Record {
            name: dns(&format!("{i}.example.com.")),
            ..record.clone()
        })
        .collect()
}

#[divan::bench(args = [16, 128, 2048])]
fn group_many(bencher: Bencher<'_, '_>, n: usize) {
    let records = many(n);
    bencher.bench(|| Rrset::group(black_box(&records)));
}
