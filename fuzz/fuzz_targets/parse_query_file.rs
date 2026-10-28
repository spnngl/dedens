//! Arbitrary bytes as a query file must never panic, and the queries it holds must encode.

#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| dedens_fuzz::parse_query_file(data));
