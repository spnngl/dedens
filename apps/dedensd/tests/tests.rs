//! The integration tests of `dedensd`, one binary (D162): a module per topic, with the RFC and section in its docs
//! and in the names of its tests.

mod access;
#[cfg(unix)]
mod authoritative;
#[cfg(feature = "doc")]
mod coap;
#[cfg(feature = "dnscrypt")]
mod dnscrypt;
mod doh;
mod end_to_end;
mod flights;
#[cfg(all(target_os = "linux", target_env = "musl"))]
mod huge_pages;
mod listeners;
mod lists;
#[cfg(feature = "odoh")]
mod odoh;
mod prewarm;
#[cfg(unix)]
mod privileges;
mod quic;
mod recurse;
#[cfg(unix)]
mod reload;
mod rfc6761;
#[cfg(unix)]
mod rfc9718;
#[cfg(unix)]
mod secondary;
#[cfg(unix)]
mod tlds;
mod util;
