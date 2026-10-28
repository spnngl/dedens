//! Arbitrary text as `/etc/resolv.conf` must never panic, and the search candidates of its words must stay bounded.

#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| dedens_fuzz::parse_resolv_conf(data));
