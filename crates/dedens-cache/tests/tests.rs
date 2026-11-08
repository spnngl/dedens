//! The integration tests of `dedens-cache`, one binary (D162): a module per topic, with the RFC and section in its
//! docs and in the names of its tests. `allocations.rs` and `memory.rs` are binaries of their own: each sets the
//! process's `#[global_allocator]`.

mod cache;
mod checked;
#[cfg(feature = "metrics")]
mod metrics;
mod rfc;
mod util;
