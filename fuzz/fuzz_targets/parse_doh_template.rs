//! Arbitrary text read as a `DoH` URI Template must never panic, and what reads must read back from its display.

#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| dedens_fuzz::parse_doh_template(data));
