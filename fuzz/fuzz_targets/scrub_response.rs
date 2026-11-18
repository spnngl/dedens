//! Any response scrubbed as from any ancestor of its name must never panic, and keep nothing outside that zone.

#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| dedens_fuzz::scrub_response(data));
