//! Arbitrary bytes as keys, signatures and digests, and the keys of a message against its signatures, must never
//! panic, and the answers must agree with `supported` and `supported_digest`.

#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| dedens_fuzz::dnssec_crypto(data));
