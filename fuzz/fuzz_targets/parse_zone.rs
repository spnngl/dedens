//! Arbitrary bytes as a zone file must never panic, and its records must survive a text round trip.

#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| dedens_fuzz::parse_zone(data));
