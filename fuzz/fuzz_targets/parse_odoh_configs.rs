//! Arbitrary bytes as `ObliviousDoHConfigs` (RFC 9230 §5) must never panic, and what parses must re-encode to a list
//! that parses to the same configs.

#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| dedens_fuzz::parse_odoh_configs(data));
