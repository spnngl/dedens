//! The control field of a response of arbitrary bytes (draft "Response Control Field") never panics, and the
//! tickets the resolver issues read back as they were made.

#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| dedens_fuzz::dnscrypt_control(data));
