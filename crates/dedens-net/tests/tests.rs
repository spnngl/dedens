//! The integration tests of `dedens-net`, one binary (D162): a module per topic, with the RFC and section in its
//! docs and in the names of its tests.

mod client;
mod coap;
mod doh;
mod exchange;
#[cfg(feature = "odoh")]
mod odoh;
mod quic;
mod tcp;
mod tls;
mod udp;
mod util;
