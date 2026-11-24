//! Arbitrary bytes into the UPDATE reader must never panic, and what it accepts must be inside its zone.

#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| dedens_fuzz::update_message(data));
