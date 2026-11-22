//! A zone file and a question: every answer the zone gives is whole and its reply encodes and decodes, and never panics.

#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| dedens_fuzz::zone_answer(data));
