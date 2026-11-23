//! Arbitrary bytes as a zone transfer's request and responses must never panic, and what they bring is the zone
//! asked for or its changes from the serial asked (D210).

#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| dedens_fuzz::transfer_stream(data));
