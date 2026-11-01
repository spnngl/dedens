//! Arbitrary NSEC and NSEC3 records and questions through the proofs of denial of existence must never panic,
//! and a proof lasts as long as one of its records.

#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| dedens_fuzz::denial(data));
