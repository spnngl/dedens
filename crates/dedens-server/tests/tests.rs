//! The integration tests of `dedens-server`, one binary (D162): a module per topic, with the RFC and section in its
//! docs and in the names of its tests.

mod access;
mod dnssec;
#[cfg(feature = "metrics")]
mod metrics;
mod stages;
mod util;
mod wire;
