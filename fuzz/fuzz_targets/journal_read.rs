//! Arbitrary bytes as a journal file must read into whole, consecutive changesets, and never panic.

#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| dedens_fuzz::journal_read(data));
