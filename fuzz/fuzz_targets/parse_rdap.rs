//! Arbitrary bytes as an RDAP answer to `+tld` must never panic its reading nor its printing.

#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| dedens_fuzz::parse_rdap(data));
