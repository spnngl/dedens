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

mod cli;
mod coap;
mod daemon;
mod dnscrypt;
mod dnssec;
mod net;
mod odoh;
mod plugins;
mod proto;
mod resolver;
mod roots;
mod server;
#[cfg(test)]
mod smoke;
mod zone;

pub use cli::{parse_command_line, parse_rdap};
pub use coap::{coap_doc, parse_coap, parse_link_format};
pub use daemon::read_config;
pub use dnscrypt::{
    dnscrypt_control, dnscrypt_decrypt, dnscrypt_encrypt_response, dnscrypt_tamper_query,
    dnscrypt_tamper_response, dnscrypt_ticket, dnscrypt_unpad, parse_dnscrypt_certificate,
};
pub use dnssec::{
    denial, dnssec_crypto, parse_5011_state, parse_root_anchors, parse_trust_anchors, rrsig_verify,
    validate,
};
pub use net::{
    parse_dns_stamp, parse_doh_template, parse_resolv_conf, read_doh_response, server_request,
};
pub use odoh::{odoh_decrypt, parse_odoh_configs, parse_odoh_message, read_odoh_http};
pub use plugins::parse_lists;
pub use proto::{
    decode_message, differential_hickory, parse_name, parse_query_file, parse_zone, read_query,
};
pub use resolver::{resolve_replay, rrset_cache_insert, scrub_response};
pub use roots::{parse_root_hints, parse_tlds_json};
pub use server::{cache_insert, parse_network, serve_query};
pub use zone::load_zone;

/// A fuzz entry point.
pub type Entry = fn(&[u8]);

/// Every target, one name each: [`TARGETS`] lists them for `fuzz_targets/` and `[[bin]]` to agree with, and the smoke
/// test, `survives::<name>`, replays the seeds through each on its own thread, so a slow target is seen by name.
macro_rules! targets {
    ($($name:ident),* $(,)?) => {
        /// Every target by name; `fuzz_targets/<name>.rs` and this list stay in step (checked by the smoke test).
        pub const TARGETS: &[(&str, Entry)] = &[$((stringify!($name), $name)),*];

        #[cfg(test)]
        mod survives {
            $(#[test]
            fn $name() {
                crate::smoke::survives(stringify!($name), crate::$name);
            })*
        }
    };
}

targets! {
    decode_message,
    read_query,
    parse_zone,
    load_zone,
    cache_insert,
    serve_query,
    parse_name,
    parse_network,
    differential_hickory,
    parse_query_file,
    parse_resolv_conf,
    parse_lists,
    parse_doh_template,
    parse_dns_stamp,
    server_request,
    read_doh_response,
    dnssec_crypto,
    parse_odoh_configs,
    parse_odoh_message,
    odoh_decrypt,
    read_odoh_http,
    parse_dnscrypt_certificate,
    dnscrypt_decrypt,
    dnscrypt_encrypt_response,
    dnscrypt_unpad,
    dnscrypt_tamper_query,
    dnscrypt_tamper_response,
    dnscrypt_ticket,
    dnscrypt_control,
    rrsig_verify,
    denial,
    validate,
    parse_trust_anchors,
    parse_root_anchors,
    parse_5011_state,
    parse_coap,
    coap_doc,
    parse_link_format,
    parse_command_line,
    parse_rdap,
    read_config,
    parse_root_hints,
    parse_tlds_json,
    rrset_cache_insert,
    scrub_response,
    resolve_replay,
}
