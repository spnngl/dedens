//! Arbitrary bytes as a zone file must load into a whole zone or be refused with errors, and never panic.

#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| dedens_fuzz::load_zone(data));
