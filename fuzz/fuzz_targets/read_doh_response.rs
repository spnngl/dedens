//! Arbitrary bytes as the HTTP response of a `DoH` server must never panic, and its `Age` and `Date` may only lower
//! the TTLs.

#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| dedens_fuzz::read_doh_response(data));
