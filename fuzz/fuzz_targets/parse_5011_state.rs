//! Arbitrary bytes as the state of a root key rollover followed by RFC 5011 must never panic, and a state that
//! reads trusts a key and reads back as written.

#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| dedens_fuzz::parse_5011_state(data));
