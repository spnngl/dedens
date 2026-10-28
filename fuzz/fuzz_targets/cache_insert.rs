//! Arbitrary bytes, decoded, stored in the cache and served again: what is served must be a conforming answer.

#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| dedens_fuzz::cache_insert(data));
