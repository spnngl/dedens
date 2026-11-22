//! Arbitrary bytes as a message of a TSIG exchange must be answered, never panic (RFC 8945 §5).

#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| dedens_fuzz::tsig_verify(data));
