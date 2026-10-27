//! RFC 9520 §3: caching resolution failures.

mod common;

use common::{T0, a, key_of, lookup, query, response, small_cache};
use dedens_cache::{Lookup, StalePolicy};
use dedens_proto::{Rcode, RecordType};

const NEVER: StalePolicy = StalePolicy::Never;

#[test]
fn a_failure_holds_the_key() {
    let cache = small_cache();
    let q = query(1, "down.example", RecordType::A);
    assert_eq!(cache.fail(&key_of(&q), T0), 5);
    assert_eq!(lookup(&cache, &q, T0, NEVER).0, Lookup::Failed);
    assert_eq!(lookup(&cache, &q, T0 + 4, NEVER).0, Lookup::Failed);
    assert_eq!(lookup(&cache, &q, T0 + 5, NEVER).0, Lookup::Miss);
}

/// §3.2: back off exponentially on repeated failures, holding at most 5 minutes.
#[test]
fn holds_double_up_to_five_minutes() {
    let cache = small_cache();
    let key = key_of(&query(1, "down.example", RecordType::A));
    let holds: Vec<u32> = (0..9).map(|i| cache.fail(&key, T0 + i * 1000)).collect();
    assert_eq!(holds, [5, 10, 20, 40, 80, 160, 300, 300, 300]);
}

#[test]
fn an_answer_ends_the_hold() {
    let cache = small_cache();
    let q = query(1, "down.example", RecordType::A);
    let key = key_of(&q);
    for _ in 0..6 {
        let _ = cache.fail(&key, T0);
    }
    let r = response(
        "down.example",
        RecordType::A,
        Rcode::NOERROR,
        vec![a("down.example", 60, 1)],
        vec![],
    );
    cache.insert(&key, &r, T0).unwrap();
    assert!(matches!(lookup(&cache, &q, T0, NEVER).0, Lookup::Hit(_)));
    // Counted from one again: the first hold, raised to the RFC 8767 recheck time as stale data now exists.
    assert_eq!(cache.fail(&key, T0 + 1000), 30);
}
