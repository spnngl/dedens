//! A hit allocates nothing, even one cut to fit a small buffer (D116). One test per file: the allocator counts
//! every thread, and a second test's allocations would show in the first's.

mod common;

use std::alloc::System;

use common::{T0, a, insert, query, response};
use dedens_cache::{Cache, Config, Lookup, StalePolicy};
use dedens_proto::{Query, Rcode, RecordType};
use stats_alloc::{INSTRUMENTED_SYSTEM, Region, StatsAlloc};

#[global_allocator]
static ALLOC: &StatsAlloc<System> = &INSTRUMENTED_SYSTEM;

#[test]
fn a_truncated_hit_allocates_nothing() {
    let cache = Cache::new(Config::default()).unwrap();
    let q = query(1, "www.example", RecordType::A);
    let answer = (0..60).map(|i| a("www.example", 60, i)).collect();
    insert(
        &cache,
        &q,
        &response("www.example", RecordType::A, Rcode::NOERROR, answer, vec![]),
        T0,
    )
    .unwrap();
    let asked = Query::read(&q).unwrap();
    let mut out = [0; 512];
    let region = Region::new(ALLOC);
    for _ in 0..100 {
        let Lookup::Hit(hit) = cache.lookup(&asked, T0, StalePolicy::Never, &mut out) else {
            panic!("a hit");
        };
        assert!(hit.truncated, "too large for 512 bytes");
    }
    let stats = region.change();
    assert_eq!(stats.allocations, 0, "{stats:?}");
}
