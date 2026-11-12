//! Arbitrary text as a configuration file of `dedensd` must never panic its reading or the building of what it says.

#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| dedens_fuzz::read_config(data));
