//! The integration tests of `dedens`, one binary (D162): a module per topic, with the RFC and section in its
//! docs and in the names of its tests.

#[cfg(feature = "dnscrypt")]
mod dnscrypt;
mod files;
#[cfg(feature = "odoh")]
mod odoh;
mod options;
mod output;
mod providers;
mod trace;
mod transports;
mod util;
mod validate;
