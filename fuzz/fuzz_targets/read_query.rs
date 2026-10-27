//! Arbitrary bytes into the query reader must never panic, and it must agree with the decoder.

#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| dedens_fuzz::read_query(data));
