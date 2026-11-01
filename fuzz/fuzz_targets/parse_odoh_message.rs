//! Arbitrary bytes as `ObliviousDoHMessage` and `ObliviousDoHMessagePlaintext` (RFC 9230 §6.1) must never panic,
//! and what parses must re-encode to the same bytes.

#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| dedens_fuzz::parse_odoh_message(data));
