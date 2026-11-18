//! The bytes the `RRset` cache requests from the allocator and has not returned stay within 1.05 times its capacity
//! whatever it stores (D116, D193): [`Rrset`]'s cost is each allocation an entry owns, to the byte. As in `dedens-cache`'s
//! `tests/memory.rs`, the count is taken between operations, and this binary holds one test: the allocator counts
//! every thread.

use std::alloc::System;
use std::sync::Arc;

use dedens_cache::{Checked, Config, Cost};
use dedens_proto::{Message, Record};
use dedens_resolver::{Rank, Rrset, RrsetCache};
use dedens_testkit::{captured, dns, dnssec, message};
use stats_alloc::{INSTRUMENTED_SYSTEM, Region, StatsAlloc};

#[global_allocator]
static ALLOC: &StatsAlloc<System> = &INSTRUMENTED_SYSTEM;

const CAPACITY: usize = 1 << 20;

/// The `RRsets` of `records` with their owner names moved under `zone{i}.`, so each `i` makes new keys.
fn renamed(records: &[Record<'static>], i: usize) -> Vec<Rrset> {
    let records: Vec<Record<'static>> = records
        .iter()
        .map(|r| Record {
            name: dns(&format!("{}zone{i}.", r.name)),
            ..r.clone()
        })
        .collect();
    Rrset::group(&records)
}

#[test]
fn the_memory_held_stays_within_the_capacity() {
    // A referral from the root: 13 NS records, then an A and an AAAA `RRset` for each server.
    let referral: Message<'static> = message(&captured("referral_root"));
    // The cost of an `RRset` is what the cache's `Arc` of it allocates: unsigned, and signed.
    let signed = dnssec::response("alg13_a");
    for set in [&referral.authority, &referral.additional, &signed.answer]
        .into_iter()
        .flat_map(|records| Rrset::group(records))
    {
        let region = Region::new(ALLOC);
        let held = Arc::new(set.clone());
        assert_eq!(region.change().bytes_allocated, set.cost(), "{set:?}");
        drop(held);
    }
    let region = Region::new(ALLOC);
    let cache = RrsetCache::new(
        CAPACITY,
        Config {
            shards: 4,
            ..Config::default()
        },
    )
    .expect("a valid config");
    let mut most = 0;
    let mut stored = 0;
    for i in 0..4000 {
        for (records, rank) in [
            (&referral.authority, Rank::AuthorityNonAuthoritative),
            (&referral.additional, Rank::AdditionalNonAuthoritative),
        ] {
            for set in renamed(records, i) {
                let owner = set.owner().clone();
                let (rtype, class) = (set.rtype(), set.class());
                cache
                    .insert(set, rank, Checked::Unchecked, 0)
                    .expect("stored");
                stored += 1;
                if i % 3 == 0 {
                    let _ = cache.get(&owner, rtype, class, 0);
                }
            }
        }
        if i % 16 == 0 {
            let stats = region.change();
            most = most.max(stats.bytes_allocated - stats.bytes_deallocated);
        }
    }
    assert!(cache.used() <= CAPACITY, "used {} bytes", cache.used());
    assert!(cache.len() < stored, "{} entries of {stored}", cache.len());
    let held = most * 1000 / CAPACITY;
    println!(
        "{held} thousandths of the capacity, {} entries at the end",
        cache.len()
    );
    assert!(held <= 1050, "{held} thousandths of the capacity");
}
