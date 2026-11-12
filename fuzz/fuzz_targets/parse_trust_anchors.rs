//! Arbitrary bytes as a trust anchor file must never panic, and what reads anchors every owner it holds.

#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| dedens_fuzz::parse_trust_anchors(data));
