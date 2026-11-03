//! DNS transports (UDP, TCP, TLS, QUIC, HTTPS over HTTP/3, CoAP) on the compio runtime, and the messages of DNS over
//! HTTPS and over CoAP.
//!
//! The only crate of the workspace that touches sockets and timers; `dedens-proto` stays free of I/O.

#![forbid(unsafe_code)]
#![warn(
    missing_docs,
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    clippy::print_stdout,
    clippy::print_stderr
)]

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
pub mod https;
pub mod io;
#[cfg(feature = "odoh")]
pub mod odoh;
pub mod quic;
pub mod resolv_conf;
pub mod tcp;
pub mod tls;
pub mod udp;
