//! The integration tests of `dedens-resolver`, one binary (D162): a module per topic, with the RFC and section in
//! its docs and in the names of its tests. `memory.rs` is a binary of its own: it sets the process's
//! `#[global_allocator]`.

mod infra_cache;
mod iteration;
#[cfg(feature = "metrics")]
mod metrics;
mod rrset_cache;
mod scrub;
