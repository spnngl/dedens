//! DNS transports (UDP, TCP, TLS, QUIC, HTTP/3, CoAP) on the compio runtime, over sans-IO cores.
//!
//! The only crate of the workspace that touches sockets and timers; `dedens-proto` stays free of I/O. Every module
//! but `dial`, which only the transports use, is public, as several items share a name (`Exchange`, `Options`,
//! `Response`; D160). The modules are of two kinds:
//!
//! - Sans-IO, fed bytes and time, with no socket, clock or randomness: `exchange` (one query, D26), `doh` (the
//!   messages of DNS over HTTPS, D82), `coap` (CoAP and the messages of DNS over CoAP, D80), `resolv_conf`.
//! - On compio: `udp`, `tcp`, `quic`, `http3`, `doc` (feature `doc`) the transports, `dial` the QUIC endpoints and
//!   connections, `client` the exchange run over the transports, `io` the seam of the UDP and TCP pools (D134), `tls`
//!   the TLS configurations, `odoh` (feature `odoh`, D79) Oblivious `DoH`: its requests, responses and target
//!   classifier are sans-IO, but its configurations are fetched over `http3` and kept by the clock, and its client
//!   draws the system's randomness.

#![forbid(unsafe_code)]
#![warn(clippy::print_stdout, clippy::print_stderr)]

/// A `tracing` debug event with the `tracing` feature; without it, nothing, its arguments not even compiled (D30).
macro_rules! debug {
    ($($event:tt)*) => {
        #[cfg(feature = "tracing")]
        tracing::debug!($($event)*);
    };
}

/// A `tracing` trace event, as [`debug!`].
macro_rules! trace {
    ($($event:tt)*) => {
        #[cfg(feature = "tracing")]
        tracing::trace!($($event)*);
    };
}

pub mod client;
pub mod coap;
mod dial;
#[cfg(feature = "doc")]
pub mod doc;
pub mod doh;
pub mod exchange;
pub mod http3;
pub mod io;
#[cfg(feature = "odoh")]
pub mod odoh;
pub mod quic;
pub mod resolv_conf;
pub mod tcp;
pub mod tls;
pub mod udp;
