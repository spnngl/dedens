//! Arbitrary bytes as the HTTP side of Oblivious `DoH` (RFC 9230 §4; D79) must never panic: the `cache-control` of
//! a target's configurations, the requests a target classifies, and the responses a client reads.

#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| dedens_fuzz::read_odoh_http(data));
