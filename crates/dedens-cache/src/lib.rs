//! DNS response cache for `dedensd`: shared by threads, sharded, sans-IO.
//!
//! A response is checked and encoded once at insert (no OPT, ID 0, question lowercased, one TTL for all
//! records) with the offsets of its TTL fields. A hit that fits the caller's buffer is copied there and its ID,
//! flags, question case and TTLs patched: no decode, no allocation. A hit too large for the buffer is decoded and
//! encoded again without the records that do not fit, outside the shard's lock. Time comes in as seconds from the
//! caller.
//!
//! RFCs: 2308 (negative caching), 8767 (serve-stale), 9520 (resolution failures), 2181 §5.2/§9, 4343, 6895 §3.1
//! (meta types are not cached), 7871 §7.3.1 (nor answers for a client subnet).

#![forbid(unsafe_code)]
#![warn(
    missing_docs,
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    clippy::print_stdout,
    clippy::print_stderr
)]

mod cache;
mod config;
mod key;
mod response;
mod shard;

pub use cache::{Cache, Freshness, Hit, Lookup, StalePolicy};
pub use config::{Config, ConfigError};
pub use key::Key;
pub use response::NotCached;
