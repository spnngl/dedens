//! An authentic query with one bit of the packet changed (draft "Negative Cases", "Tampered ciphertext") is refused
//! by the resolver.

#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| dedens_fuzz::dnscrypt_tamper_query(data));
