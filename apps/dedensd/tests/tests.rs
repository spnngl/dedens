//! The integration tests of `dedensd`, one binary (D162): a module per topic, with the RFC and section in its docs
//! and in the names of its tests.

mod access;
#[cfg(feature = "doc")]
mod coap;
mod doh;
mod end_to_end;
mod flights;
mod listeners;
mod lists;
#[cfg(feature = "odoh")]
mod odoh;
#[cfg(unix)]
mod privileges;
mod quic;
#[cfg(unix)]
mod reload;
mod util;
