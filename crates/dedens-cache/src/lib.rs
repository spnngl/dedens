//! DNS response cache for `dedensd`: shared by threads, sharded, sans-IO.
//!
//! A response is checked and encoded once at insert (no OPT, ID 0, one TTL for all records) with the offsets of its
//! TTL fields and of the cuts that keep the `RRsets` of its additional section whole. A hit is copied into the caller's buffer and its ID, flags, question case and TTLs patched: no decode, no
//! allocation, one too large for the buffer cut at a record boundary and TC set as RFC 2181 §9 asks (D116). Time
//! comes in as seconds from the caller.
//!
//! RFCs: 2308 (negative caching), 8767 (serve-stale), 9520 (resolution failures), 2181 §5.2/§9, 4343, 6895 §3.1
//! (meta types are not cached), 7871 §7.3.1 (nor answers for a client subnet), 4035 §3.2.2/§4.7 (the verdict a
//! validating caller kept with a response, [`Checked`]: the AD bit follows it, bad data is kept for
//! `Config::bogus_ttl`, insecure data for `Config::insecure_ttl` at most; D77, D93).
//!
//! Feature `metrics`: lookup, insert, prefetch and eviction counters through the `metrics` facade; without it
//! they compile away.

#![forbid(unsafe_code)]
#![warn(clippy::print_stdout, clippy::print_stderr)]

mod cache;
mod config;
mod key;
mod metrics;
mod response;
mod shard;

pub use cache::{Cache, Freshness, Hit, Lookup, StalePolicy};
pub use config::{Config, ConfigError};
pub use key::Key;
pub use response::{Checked, NotCached};
