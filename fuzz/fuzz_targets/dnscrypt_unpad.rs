//! A DNS message padded to an arbitrary length (draft "Padding For Client Queries Over UDP") is read back by the
//! resolver as it was sent.

#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| dedens_fuzz::dnscrypt_unpad(data));
