//! Arbitrary bytes as a response and as every answer its validation asks for, under the root anchors, must never
//! panic, ask past the limit or loop.

#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| dedens_fuzz::validate(data));
