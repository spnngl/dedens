//! Arbitrary bytes as a `/.well-known/core` payload (RFC 6690) must never panic, and the links a client takes from it
//! are paths on the server; the list `dedensd` writes for any path reads back to that path.

#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| dedens_fuzz::parse_link_format(data));
