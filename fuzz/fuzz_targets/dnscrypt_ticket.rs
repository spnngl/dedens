//! A resumed query of arbitrary bytes (draft "Resumption Tickets") is refused, the fuzzer holding no ticket key; the
//! client's own is read, and not with one bit changed.

#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| dedens_fuzz::dnscrypt_ticket(data));
