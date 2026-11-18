//! The recursive resolver (RFC 1034 §5.3.3, RFC 1035 §7), sans-IO: time comes in as seconds from the caller.
//!
//! [`RrsetCache`] holds what resolution learned, `RRset` by `RRset` (RFC 2181 §5), each with its [`Rank`]: where it
//! was read, which decides whether later data replaces it (RFC 2181 §5.4.1), and the validator's verdict on it
//! (RFC 4035 §4.7). Its TTL rules are the response cache's `Config` (D124, D193).
//!
//! RFCs: 1034 §5.3.3, 1035 §3.2.1/§4.1, 2181 §5/§5.2/§5.4.1/§8, 4035 §4.7, 4343, 6895 §3.1.
//!
//! Feature `metrics`: lookup, insert and eviction counters through the `metrics` facade; without it they compile
//! away.

#![forbid(unsafe_code)]
#![warn(clippy::print_stdout, clippy::print_stderr)]

mod metrics;
mod rrset;
mod rrset_cache;

pub use rrset::Rrset;
pub use rrset_cache::{DEFAULT_CAPACITY, Hit, NotCached, Rank, RrsetCache};
