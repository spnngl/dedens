//! Arbitrary bytes as a query and as an upstream response: the server's replies must conform.

#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| dedens_fuzz::serve_query(data));
