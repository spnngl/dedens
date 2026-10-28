//! A message dedens and hickory-proto both read must agree in validity and survive each one's re-encoding.

#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| dedens_fuzz::differential_hickory(data));
