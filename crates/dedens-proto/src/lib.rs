//! DNS wire format (RFC 1035 and its updates): messages, names and records, encoded and decoded without I/O.
//!
//! Every item cites the RFC section it implements; `docs/rfc/coverage.md` maps each RFC to its code and tests.

#![forbid(unsafe_code)]
#![warn(
    missing_docs,
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    clippy::print_stdout,
    clippy::print_stderr
)]

pub mod codes;
pub mod edns;
pub mod error;
pub mod header;
pub mod message;
pub mod name;
pub mod query;
pub mod question;
pub mod rdata;
pub mod record;
pub mod text;
pub mod transport;
pub mod wire;

#[cfg(kani)]
mod proofs;

pub use codes::{Class, DigestType, Nsec3HashAlgorithm, Opcode, Rcode, RecordType, SecAlgorithm};
pub use edns::{Edns, EdnsFlags, EdnsView};
pub use error::{DecodeError, DecodeErrorKind, EncodeError};
pub use header::{Flags, Header};
pub use message::{Decoded, Encoded, Message, Section, Violation};
pub use name::{Name, NameError};
pub use query::Query;
pub use question::Question;
pub use rdata::RData;
pub use record::{DecodedRecord, Record, Ttl, WireRdata};
pub use text::{TextError, TextErrorKind};
pub use transport::Transport;
