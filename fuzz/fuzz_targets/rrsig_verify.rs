//! The `RRsets`, RRSIGs, DNSKEYs and DS records of a message through `rrsig::verify_any` and `trusted_keys` must
//! never panic, and an RRSIG alone never makes data insecure.

#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| dedens_fuzz::rrsig_verify(data));
