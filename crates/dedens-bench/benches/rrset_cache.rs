//! The resolver's `RRset` cache (D193): `insert` stores a captured `RRset` into an empty cache, `hit` looks one up.
//!
//! The `RRsets`: `a`, the two A records of `example.com.`; `ns`, its two NS records; `root_ns`, the 13 NS records of
//! `com.` from a root server's referral. `insert` takes the `RRset` already grouped, as the resolver has it.

use std::hint::black_box;

use dedens_cache::{Checked, Config};
use dedens_proto::Section;
use dedens_resolver::{Rank, Rrset, RrsetCache};
use dedens_testkit::{captured, message};
use divan::Bencher;

#[global_allocator]
static ALLOC: divan::AllocProfiler = divan::AllocProfiler::system();

fn main() {
    divan::main();
}

const RRSETS: &[&str] = &["a", "ns", "root_ns"];

/// The `RRset` named `name` in [`RRSETS`].
fn rrset(name: &str) -> Rrset {
    let (case, section) = match name {
        "a" => ("a", Section::Answer),
        "ns" => ("ns", Section::Answer),
        _ => ("referral_root", Section::Authority),
    };
    let message = message(&captured(case));
    let records = match section {
        Section::Answer => &message.answer,
        Section::Authority | Section::Additional => &message.authority,
    };
    Rrset::group(records).remove(0)
}

/// One shard: the cost of an insert, not of the shards' allocation.
fn cache() -> RrsetCache {
    let config = Config {
        shards: 1,
        ..Config::default()
    };
    RrsetCache::new(1 << 20, config).expect("a valid config")
}

#[divan::bench(args = RRSETS)]
fn insert(bencher: Bencher<'_, '_>, name: &str) {
    let rrset = rrset(name);
    bencher
        .with_inputs(|| (cache(), rrset.clone()))
        .bench_local_values(|(cache, rrset)| {
            let hit = cache.insert(rrset, Rank::AnswerNonAuthoritative, Checked::Unchecked, 0);
            // The cache is returned so that dropping it is not measured.
            (cache, hit)
        });
}

#[divan::bench(args = RRSETS)]
fn hit(bencher: Bencher<'_, '_>, name: &str) {
    let rrset = rrset(name);
    let cache = cache();
    let (owner, rtype, class) = (rrset.owner().clone(), rrset.rtype(), rrset.class());
    cache
        .insert(rrset, Rank::AnswerNonAuthoritative, Checked::Unchecked, 0)
        .expect("stored");
    bencher.bench(|| cache.get(black_box(&owner), rtype, class, 0));
}
