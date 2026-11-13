//! Arbitrary bytes as a resolver's DNS response, encrypted for UDP and for TCP (draft "Resolver Responses Over UDP",
//! "Resolver Responses Over TCP"), must never panic and must fit the carrier.

#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| dedens_fuzz::dnscrypt_encrypt_response(data));
