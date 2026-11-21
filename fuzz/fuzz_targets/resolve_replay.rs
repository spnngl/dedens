//! A resolution answered with any response to each query it sends must end within its limits, and never panic.

#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| dedens_fuzz::resolve_replay(data));
