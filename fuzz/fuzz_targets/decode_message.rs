//! Arbitrary bytes into the message decoder must never panic, and what decodes must round-trip.

#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| dedens_fuzz::decode_message(data));
