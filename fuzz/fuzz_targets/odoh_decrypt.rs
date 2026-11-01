//! Arbitrary bytes as an `ODoH` query and as a response (RFC 9230 §7, §8) through a fixed target key must never
//! panic, and a forged message must be refused.

#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| dedens_fuzz::odoh_decrypt(data));
