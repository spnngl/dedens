//! Serial number arithmetic: RFC 1982 §3 (addition, comparison), §4 (corollaries), §5 (examples) and §7 (the SOA
//! serial is 32 bits, `SERIAL_BITS` = 32).
//!
//! The examples of §5 use 2 and 8 bits; the same pairs are tried here at 32, where the largest increment is
//! 2^31 - 1 and the pairs with no order are 2^31 apart.

use core::cmp::Ordering;

use dedens_proto::Serial;
use proptest::prelude::*;

const HALF: u32 = 1 << 31;

/// §2: a serial is an unsigned 32-bit number, written in decimal.
#[test]
fn s2_a_serial_is_its_number() {
    for n in [0, 1, 2_026_112_201, u32::MAX] {
        let serial = Serial::new(n);
        assert_eq!(serial.get(), n);
        assert_eq!(u32::from(serial), n);
        assert_eq!(serial.to_string(), n.to_string());
        assert_eq!(Serial::from(n), serial);
    }
}

/// §5.2 at 32 bits: `255+1 == 0` is `MAX+1 == 0`; `100+100 > 100` and `(100+100)+100 < 100` use a step of 100/256 of
/// the circle.
#[test]
fn s5_2_examples_at_32_bits() {
    assert_eq!(Serial::new(u32::MAX).checked_add(1), Some(Serial::new(0)));
    assert!(Serial::new(1) > Serial::new(0));
    assert!(Serial::new(0) > Serial::new(u32::MAX));
    // 100, 200 and 44 of the 8-bit circle: a step of 100/256 of it, three times.
    let step = 1_677_721_600;
    let a = Serial::new(step);
    let b = a.checked_add(step).expect("below 2^31");
    let c = b.checked_add(step).expect("below 2^31");
    assert!(b > a, "100+100 > 100");
    assert!(
        c < a,
        "(100+100)+100 < 100: incrementing can make a serial smaller"
    );
    assert!(Serial::new(u32::MAX) > b, "255 > 200");
}

/// §3.2: the pairs of values 2^31 apart are not equal, and neither is greater.
#[test]
fn s3_2_a_pair_half_the_circle_apart_has_no_order() {
    for s in [0, 1, 2, HALF - 1, HALF, u32::MAX] {
        let (a, b) = (Serial::new(s), Serial::new(s.wrapping_add(HALF)));
        assert_ne!(a, b);
        assert_eq!(a.partial_cmp(&b), None);
        assert_eq!([a < b, a > b, a <= b, a >= b], [false; 4]);
        assert_eq!(a.since(b), None);
    }
}

/// §3.1: the increment is 0 to 2^31 - 1; any other is undefined.
#[test]
fn s3_1_the_largest_increment_is_2_pow_31_minus_1() {
    assert_eq!(Serial::new(5).checked_add(0), Some(Serial::new(5)));
    assert_eq!(
        Serial::new(5).checked_add(HALF - 1),
        Some(Serial::new(5 + HALF - 1))
    );
    assert_eq!(Serial::new(5).checked_add(HALF), None);
    assert_eq!(Serial::new(5).checked_add(u32::MAX), None);
}

/// `since` is the signed distance, across the wrap.
#[test]
fn since_counts_across_the_wrap() {
    assert_eq!(Serial::new(2).since(Serial::new(u32::MAX - 1)), Some(4));
    assert_eq!(Serial::new(u32::MAX - 1).since(Serial::new(2)), Some(-4));
    assert_eq!(Serial::new(7).since(Serial::new(7)), Some(0));
    assert_eq!(Serial::new(HALF - 1).since(Serial::new(0)), Some(i32::MAX));
    assert_eq!(
        Serial::new(HALF + 1).since(Serial::new(0)),
        Some(i32::MIN + 1)
    );
}

proptest! {
    /// §3.2: where the order is defined, `a < b` exactly when `b > a`, and never both ways.
    #[test]
    fn s3_2_the_order_is_antisymmetric(a in any::<u32>(), b in any::<u32>()) {
        let (a, b) = (Serial::new(a), Serial::new(b));
        prop_assert_eq!(a.partial_cmp(&b), b.partial_cmp(&a).map(Ordering::reverse));
        prop_assert_eq!(a.partial_cmp(&b) == Some(Ordering::Equal), a == b);
    }

    /// §4.1: `(s + n) > s` for `n` in 1..=2^31 - 1, and `s + 0 == s`.
    #[test]
    fn s4_1_adding_makes_a_serial_greater(s in any::<u32>(), n in 1..HALF) {
        let s = Serial::new(s);
        let sum = s.checked_add(n).expect("in range");
        prop_assert!(sum > s);
        prop_assert_eq!(sum.since(s), Some(i32::try_from(n).expect("below 2^31")));
        prop_assert_eq!(s.checked_add(0), Some(s));
    }

    /// §4.4: two increments whose sum is still in range are one increment.
    #[test]
    fn s4_4_increments_whose_sum_is_in_range_add_up(s in any::<u32>(), n in 1..HALF / 2, m in 1..HALF / 2) {
        let s = Serial::new(s);
        let twice = s.checked_add(n).and_then(|t| t.checked_add(m));
        prop_assert_eq!(twice, s.checked_add(n + m));
        prop_assert!(twice > Some(s));
    }
}
