//! TSIG, transaction signatures for DNS messages (RFC 8945, D205): the keys, and signing and verifying on both sides
//! of a request, a response or a TCP stream of responses. Sans I/O: the caller holds the bytes and the clock.
//!
//! - [`Key`], [`Keyring`], [`Algorithm`]: a shared secret with its name and HMAC algorithm.
//! - Server: [`verify_request`] checks a request (RFC 8945 §5.2) and gives a [`Request`], whose
//!   [`ResponseSigner`] signs every message of the response; a [`Refusal`] says what to answer otherwise
//!   (§5.2, §5.3.2).
//! - Client: [`sign_request`] signs a request and gives the [`ResponseVerifier`] of its response (§5.4, §5.3.1).
//!
//! The record's data and finding it in a message are in `dedens-proto` ([`dedens_proto::Tsig`],
//! [`dedens_proto::find_tsig`]).

mod algorithm;
mod client;
mod digest;
mod key;
mod server;

pub use algorithm::{Algorithm, UnknownAlgorithm};
pub use client::{ResponseError, ResponseVerifier, Verified, sign_request};
pub use digest::SignError;
pub use key::{Key, KeyError, Keyring};
pub use server::{FormatError, NotAuth, Refusal, Request, ResponseSigner, verify_request};

/// The fudge this crate signs with, in seconds: how far a receiver's clock may differ (RFC 8945 §5.2.3; the value
/// RFC 8945 §10 recommends, as Knot and BIND use).
pub const FUDGE: u16 = 300;

/// The messages in a row without a TSIG that a client accepts in a response stream (RFC 8945 §5.3.1).
pub const MAX_UNSIGNED: usize = 99;
