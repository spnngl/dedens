//! RFC 9520 §3: caching resolution failures.

mod common;

use common::{T0, a, insert, key_of, lookup, query, response, small_cache};
use dedens_cache::{Cache, Key, Lookup, StalePolicy};
use dedens_proto::{Rcode, RecordType};

const NEVER: StalePolicy = StalePolicy::Never;

fn down() -> Key {
    key_of(&query(1, "down.example", RecordType::A))
}

/// Fails `key` `times` in a row, each as the previous hold ends; returns the holds and when the last one ends.
fn fail_in_a_row(cache: &Cache, key: &Key, times: usize) -> (Vec<u32>, u32) {
    let mut now = T0;
    let holds = (0..times)
        .map(|_| {
            let hold = cache.fail(key, now);
            now += hold;
            hold
        })
        .collect();
    (holds, now)
}

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
    let (holds, _) = fail_in_a_row(&cache, &down(), 9);
    assert_eq!(holds, [5, 10, 20, 40, 80, 160, 300, 300, 300]);
}

/// A failure reported during a hold, by a resolution started before it, neither counts nor extends the hold.
#[test]
fn a_failure_during_the_hold_is_not_counted() {
    let cache = small_cache();
    let key = down();
    assert_eq!(cache.fail(&key, T0), 5);
    assert_eq!(cache.fail(&key, T0 + 2), 3);
    assert_eq!(cache.fail(&key, T0 + 4), 1);
    assert_eq!(cache.fail(&key, T0 + 5), 10);
}

/// Failures stop being in a row once the key has resolved, or not been tried, for longer than the longest hold.
#[test]
fn failures_long_apart_start_over() {
    let cache = small_cache();
    let key = down();
    let (_, end) = fail_in_a_row(&cache, &key, 4);
    let longest = cache.config().failure_max;
    assert_eq!(cache.fail(&key, end + longest), 80);
    assert_eq!(cache.fail(&key, end + 80 + longest + longest + 1), 5);
}

/// A hold set before the clock went back lasts no longer than the longest hold from now.
#[test]
fn a_clock_going_back_does_not_extend_a_hold() {
    let cache = small_cache();
    let q = query(1, "down.example", RecordType::A);
    let key = key_of(&q);
    let _ = cache.fail(&key, T0 + 10_000);
    assert_eq!(lookup(&cache, &q, T0, NEVER).0, Lookup::Miss);
    // Still in a row: the second failure.
    assert_eq!(cache.fail(&key, T0), 10);
    assert_eq!(lookup(&cache, &q, T0, NEVER).0, Lookup::Failed);
}

#[test]
fn an_answer_ends_the_hold() {
    let cache = small_cache();
    let q = query(1, "down.example", RecordType::A);
    let key = key_of(&q);
    let (_, now) = fail_in_a_row(&cache, &key, 6);
    let _ = cache.fail(&key, now);
    let r = response(
        "down.example",
        RecordType::A,
        Rcode::NOERROR,
        vec![a("down.example", 60, 1)],
        vec![],
    );
    insert(&cache, &q, &r, now).unwrap();
    assert!(matches!(lookup(&cache, &q, now, NEVER).0, Lookup::Hit(_)));
    // Counted from one again: the first hold, raised to the RFC 8767 recheck time as stale data now exists.
    assert_eq!(cache.fail(&key, now + 60), 30);
}

/// The RFC 8767 recheck time holds only while the stale data may still be served.
#[test]
fn the_recheck_time_ends_with_the_stale_data() {
    let q = query(1, "down.example", RecordType::A);
    let key = key_of(&q);
    let r = response(
        "down.example",
        RecordType::A,
        Rcode::NOERROR,
        vec![a("down.example", 60, 1)],
        vec![],
    );
    for (late, hold) in [(0, 30), (1, 5)] {
        let cache = small_cache();
        insert(&cache, &q, &r, T0).unwrap();
        let stale_until = T0 + 60 + cache.config().max_stale;
        assert_eq!(cache.fail(&key, stale_until - 1 + late), hold);
    }
}
