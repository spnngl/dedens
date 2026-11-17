//! Arbitrary bytes as IANA's TLD list must never panic, and each TLD read must be found by its name.

#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| dedens_fuzz::parse_tlds_json(data));
