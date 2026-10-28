//! DNS transports (UDP, TCP) on the compio runtime.
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

pub mod client;
pub mod exchange;
pub mod tcp;
pub mod udp;
