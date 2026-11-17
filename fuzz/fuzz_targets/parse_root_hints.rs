//! Arbitrary bytes as root hints must never panic, and hints read must have an address.

#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| dedens_fuzz::parse_root_hints(data));
