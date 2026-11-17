//! The integration tests of `dedens-dnssec`, one binary (D162): a module per topic, with the RFC and section in its
//! docs and in the names of its tests.

mod algorithms;
mod anchor;
mod denial;
mod rrsig;
#[cfg(feature = "fetch-anchors")]
mod signed_anchors;
mod util;
mod validator;
