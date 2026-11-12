//! Arbitrary bytes as the arguments of `dedens`, NUL between two, must never panic its command line's reading.

#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| dedens_fuzz::parse_command_line(data));
