//! Responses off the wire, their `RRsets` stored in the resolver's `RRset` cache: what is stored is found again.

#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| dedens_fuzz::rrset_cache_insert(data));
