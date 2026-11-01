//! A client CoAP exchange against a model of the `dedensd` listener, driven by the input: retransmission, duplicates,
//! changing bodies and block-wise transfers must never panic, and a body is never put together of blocks of two
//! versions.

#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| dedens_fuzz::coap_doc(data));
