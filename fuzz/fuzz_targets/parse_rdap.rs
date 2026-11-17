//! Arbitrary bytes as an RDAP bootstrap file or answer to `+tld` and `+rdap` must never panic their reading nor the printing.

#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| dedens_fuzz::parse_rdap(data));
