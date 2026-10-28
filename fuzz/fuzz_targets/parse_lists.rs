//! Arbitrary text as a hosts file and a blocklist must never panic, and the plugins' replies must decode.

#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| dedens_fuzz::parse_lists(data));
