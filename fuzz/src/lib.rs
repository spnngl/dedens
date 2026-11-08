//! Fuzz entry points: one function per parser of outside data, each fed arbitrary bytes and required never
//! to panic, in modules by the crate they test.
//!
//! `cargo-fuzz` (nightly) reaches them through the shims in `fuzz_targets/`; `cargo test --lib` (stable,
//! `just fuzz-smoke`) replays the captured responses plus mutated variants through [`TARGETS`].

#![forbid(unsafe_code)]
#![expect(
    clippy::panic,
    reason = "a fuzz target, and the smoke test replaying it, report a bug by panicking"
)]

mod coap;
mod dnssec;
mod net;
mod odoh;
mod plugins;
mod proto;
mod server;
#[cfg(test)]
mod smoke;

pub use coap::{coap_doc, parse_coap, parse_link_format};
pub use dnssec::{denial, dnssec_crypto, rrsig_verify, validate};
pub use net::{parse_doh_template, parse_resolv_conf, read_doh_response, server_request};
pub use odoh::{odoh_decrypt, parse_odoh_configs, parse_odoh_message, read_odoh_http};
pub use plugins::parse_lists;
pub use proto::{
    decode_message, differential_hickory, parse_name, parse_query_file, parse_zone, read_query,
};
pub use server::{cache_insert, parse_network, serve_query};

/// A fuzz entry point.
pub type Entry = fn(&[u8]);

/// Every target by name; `fuzz_targets/<name>.rs` and this list stay in step (checked by the smoke test).
pub const TARGETS: &[(&str, Entry)] = &[
    ("decode_message", decode_message),
    ("read_query", read_query),
    ("parse_zone", parse_zone),
    ("cache_insert", cache_insert),
    ("serve_query", serve_query),
    ("parse_name", parse_name),
    ("parse_network", parse_network),
    ("differential_hickory", differential_hickory),
    ("parse_query_file", parse_query_file),
    ("parse_resolv_conf", parse_resolv_conf),
    ("parse_lists", parse_lists),
    ("parse_doh_template", parse_doh_template),
    ("server_request", server_request),
    ("read_doh_response", read_doh_response),
    ("dnssec_crypto", dnssec_crypto),
    ("parse_odoh_configs", parse_odoh_configs),
    ("parse_odoh_message", parse_odoh_message),
    ("odoh_decrypt", odoh_decrypt),
    ("read_odoh_http", read_odoh_http),
    ("rrsig_verify", rrsig_verify),
    ("denial", denial),
    ("validate", validate),
    ("parse_coap", parse_coap),
    ("coap_doc", coap_doc),
    ("parse_link_format", parse_link_format),
];
