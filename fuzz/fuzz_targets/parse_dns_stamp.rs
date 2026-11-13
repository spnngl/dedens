//! Arbitrary text read as a DNS stamp must never panic, and what reads must write back as it was.

#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| dedens_fuzz::parse_dns_stamp(data));
