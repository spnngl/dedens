//! Arbitrary CoAP datagrams through the codec and a client exchange must never panic, and what is read is written
//! back as a message that reads the same.

#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| dedens_fuzz::parse_coap(data));
