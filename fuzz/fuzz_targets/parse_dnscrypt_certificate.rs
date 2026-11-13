//! Arbitrary bytes as a `DNSCrypt` certificate and as a DNS message with certificates in TXT records (draft
//! "Certificates") must never panic, and a certificate that is made reads back as it was.

#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| dedens_fuzz::parse_dnscrypt_certificate(data));
