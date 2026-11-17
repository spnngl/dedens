//! Arbitrary bytes as IANA's root-anchors.xml, as its .p7s and as ICANN's CA bundle must never panic, and a
//! signature that holds yields the anchors of the captured XML.

#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| dedens_fuzz::parse_root_anchors(data));
