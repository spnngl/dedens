//! CoAP (RFC 7252), the carrier of DNS over CoAP (RFC 9953), without I/O (D80).
//!
//! - [`Message`]: the message, read and written as bytes, with its [`Options`].
//! - [`block`]: the block-wise transfer option and the reassembly and slicing of bodies (RFC 7959).
//! - [`exchange`]: one request and its response over an unreliable transport: retransmission, separate
//!   responses, block-wise transfer. The client side.
//! - [`server`]: the CON messages a server has seen, to answer a duplicate without processing it again.
//! - [`dns`]: the `DoC` request and the `docpath` of an SVCB record, and the discovery of a `DoC` resource.
//! - [`link`]: the `CoRE` Link Format of that discovery (RFC 6690).
//!
//! Nothing here opens a socket, reads a clock or draws a random number.

pub mod block;
pub mod dns;
pub mod exchange;
pub mod link;
mod message;
pub mod server;

pub use message::{
    Code, MAX_OPTIONS, Message, OptionNumber, Options, ParseError, Token, TokenTooLong, Type,
    WriteError,
};
