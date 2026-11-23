//! Arbitrary bytes as a signed zone transfer's request and responses must never panic, and a stream that is
//! accepted is the zone asked for or its changes, verified message by message (D210).

#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| dedens_fuzz::transfer_signed(data));
