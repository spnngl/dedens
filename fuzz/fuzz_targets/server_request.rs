//! Arbitrary bytes as the request of a `DoH` client must never panic, and the query a server reads must be one the
//! RFC allows.

#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| dedens_fuzz::server_request(data));
