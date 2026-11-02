//! The bytes a cache requests from the allocator and has not returned stay within 1.05 times `Config::capacity`,
//! whatever it stores and for as long as it churns: the slab, the index, the queues and the ghosts count in the budget
//! as well as the responses (D116, L12). That is not the memory of the process: the allocator rounds sizes up, and
//! the workloads here do not reach each table's worst moment of growth, which a unit test of `SLOT_COST` holds.
//!
//! The count is taken between operations: the tables of a shard grow by moving to a larger one, which briefly holds
//! both, and the transient buffers of an insert are gone by then. One test per file: the allocator counts every
//! thread.

mod common;

use std::alloc::System;

use common::{T0, a, query, response};
use dedens_cache::{Cache, Config, StalePolicy};
use dedens_proto::{Message, Query, Rcode, RecordType};
use stats_alloc::{INSTRUMENTED_SYSTEM, Region, StatsAlloc};

#[global_allocator]
static ALLOC: &StatsAlloc<System> = &INSTRUMENTED_SYSTEM;

const CAPACITY: usize = 1 << 20;

/// What a workload does for its `i`th name.
type Operation = fn(&Cache, usize);

fn name(i: usize) -> String {
    format!("host{i}.example")
}

/// Stores a response of `records` addresses for name `i`, and asks for it once in three, so that those go to the
/// main queue as popular names do.
fn insert_of(cache: &Cache, i: usize, records: u8) {
    let name = name(i);
    let asked = query(1, &name, RecordType::A);
    let answer = (0..records).map(|r| a(&name, 600, r)).collect();
    let wire = response(&name, RecordType::A, Rcode::NOERROR, answer, vec![]);
    let decoded = Message::decode(&wire).expect("a response that decodes");
    let asked = Query::read(&asked).expect("a valid query");
    // Over `Config::max_entry_bytes` for some: answered, not stored.
    let _ = cache.insert(&asked, &decoded, T0, 0);
    if i.is_multiple_of(3) {
        let mut out = vec![0; 8192];
        let _ = cache.lookup(&asked, T0, StalePolicy::Never, &mut out);
    }
}

/// A pseudo-random number below `n`, the same for the same `i`.
fn random(i: usize, n: u64) -> u8 {
    let x = (u64::try_from(i).expect("a count") + 1).wrapping_mul(0x9E37_79B9_7F4A_7C15);
    u8::try_from((x >> 33) % n).expect("below 256")
}

/// Runs `operation` for each of `count` names on a new cache and returns the most bytes held between two of them,
/// in thousandths of the capacity, and the entries it ends with.
fn most_held(count: usize, operation: Operation) -> (usize, usize) {
    let region = Region::new(ALLOC);
    let cache = Cache::new(Config {
        capacity: CAPACITY,
        shards: 4,
        ..Config::default()
    })
    .expect("a valid config");
    let mut most = 0;
    for i in 0..count {
        operation(&cache, i);
        if i.is_multiple_of(64) {
            let stats = region.change();
            most = most.max(stats.bytes_allocated - stats.bytes_deallocated);
        }
    }
    assert!(cache.used() <= CAPACITY, "used {} bytes", cache.used());
    (most * 1000 / CAPACITY, cache.len())
}

/// A response of a hundred or more addresses, the large ones of the workloads.
fn large(cache: &Cache, i: usize) {
    insert_of(cache, i, 100 + random(i, 150));
}

fn fail(cache: &Cache, i: usize) {
    let asked = query(1, &name(i), RecordType::A);
    let _ = cache.fail(&common::key_of(&asked), T0);
}

#[test]
fn the_memory_held_stays_within_the_capacity() {
    let workloads: [(&str, usize, Operation); 5] = [
        ("small responses", 40_000, |cache, i| insert_of(cache, i, 1)),
        ("responses of every size", 15_000, |cache, i| {
            insert_of(cache, i, 1 + random(i, 255));
        }),
        ("small, then large responses", 16_000, |cache, i| {
            let records = if i < 10_000 { 1 } else { 100 + random(i, 150) };
            insert_of(cache, i, records);
        }),
        ("failures", 40_000, fail),
        ("failures, then large responses", 26_000, |cache, i| {
            if i < 20_000 {
                fail(cache, i);
            } else {
                large(cache, i);
            }
        }),
    ];
    let mut over = vec![];
    for (what, count, operation) in workloads {
        let (held, entries) = most_held(count, operation);
        println!("{what}: {held} thousandths of the capacity, {entries} entries at the end");
        if held > 1050 {
            over.push(what);
        }
        if what == "failures, then large responses" {
            // The slots the failures took are given back: as many large entries as on a cache that saw no failure.
            let (_, fresh) = most_held(6_000, |cache, i| large(cache, 20_000 + i));
            assert!(
                entries * 10 >= fresh * 8,
                "{entries} entries, {fresh} on a fresh cache"
            );
        }
    }
    assert!(over.is_empty(), "over 1.05 times the capacity: {over:?}");
}
