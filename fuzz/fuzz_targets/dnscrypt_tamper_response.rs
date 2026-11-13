//! An authentic response with one bit of the packet changed (draft "Negative Cases", "Tampered ciphertext") is
//! refused by the client.

#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| dedens_fuzz::dnscrypt_tamper_response(data));
