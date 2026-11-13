//! Arbitrary bytes as a `DNSCrypt` query and as a response (draft "Client Queries Over UDP", "Resolver Responses
//! Over UDP") through fixed keys must never panic, and a packet of ours with a changed byte must be refused.

#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| dedens_fuzz::dnscrypt_decrypt(data));
