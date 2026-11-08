//! DNS wire format (RFC 1035 and its updates): messages, names and records, encoded and decoded without I/O.
//!
//! ```
//! use dedens_proto::rdata::RData;
//! use dedens_proto::{Message, Name, Question, RecordType};
//!
//! // A query for the A records of example.com.
//! let name: Name<'static> = "example.com.".parse()?;
//! let query = Message::query(0x2a, Question::new(name, RecordType::A)).to_vec()?;
//! assert_eq!(Message::decode(&query)?.message.questions.len(), 1);
//!
//! // The response 1.1.1.1 gave (`just capture`): borrowed from the bytes, the rules it breaks beside it.
//! let response = Message::decode(include_bytes!("../tests/testdata/a.bin"))?;
//! assert!(response.violations.is_empty());
//! for record in &response.message.answer {
//!     assert!(matches!(record.data(), RData::A(_)));
//!     println!("{record}"); // A zone-file line: owner, TTL, class, type, address.
//! }
//! # Ok::<(), Box<dyn std::error::Error>>(())
//! ```
//!
//! Each item an RFC defines cites its section; `docs/rfc/coverage.md` maps each RFC to its code and tests.
//!
//! # Presentation format
//!
//! Records as zone-file text (RFC 1035 §5.1). Written by `Display` on [`Name`], the codes, [`RData`] and
//! [`Record`]: one tab-separated line per record, absolute names, TTL in seconds, character-strings quoted, bytes
//! outside printable ASCII as `\DDD`. [`RData::generic`] and [`Record::generic`] write the generic form of
//! RFC 3597 §5 (`TYPE65280 \# 2 abcd`). Read by `FromStr` on the same types, and zone files by [`ZoneReader`].
//! Text is bytes (`&[u8]` underneath), since a quoted string may hold any byte; a known type written in the
//! generic form is read into its typed RDATA (RFC 3597 §5).
//!
//! [`RData`]: rdata::RData
//! [`RData::generic`]: rdata::RData::generic

#![forbid(unsafe_code)]
#![warn(clippy::print_stdout, clippy::print_stderr)]

pub mod edns;
pub mod rdata;

mod codes;
mod error;
mod header;
mod message;
mod name;
#[cfg(kani)]
mod proofs;
mod query;
mod question;
mod record;
mod text;
mod transport;
mod wire;

// One path per item (D160): `rdata` and `edns` are the namespaces a reader names; every other item is here.
pub use codes::{
    Class, DigestType, Nsec3HashAlgorithm, Opcode, Rcode, RecordType, SecAlgorithm, UnknownCode,
};
pub use error::{DecodeError, DecodeErrorKind, EncodeError};
pub use header::{Flags, HEADER_LEN, Header};
pub use message::{Decoded, Encoded, Message, Section, Violation, ttl_offsets};
pub use name::{Labels, MAX_LABEL_LEN, MAX_LABELS, MAX_NAME_LEN, Name, NameError};
pub use query::Query;
pub use question::Question;
pub use record::{DecodedRecord, GenericRecord, Record, Ttl, WireRdata};
pub use text::{
    Hex, TextError, TextErrorKind, ZoneEntry, ZoneReader, decode_base64url, decode_hex,
    encode_base64url,
};
pub use transport::Transport;
pub use wire::MAX_MESSAGE_LEN;
