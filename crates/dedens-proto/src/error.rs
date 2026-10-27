//! Errors of decoding and encoding.

/// A message that cannot be decoded: its structure is broken, so nothing can be recovered from this point.
///
/// Rule violations in an otherwise readable message are not errors; they are reported as
/// `Violation`s.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("{kind} at offset {offset}")]
pub struct DecodeError {
    /// Offset in the message where decoding failed.
    pub offset: usize,
    /// What is wrong.
    pub kind: DecodeErrorKind,
}

/// The reason of a [`DecodeError`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum DecodeErrorKind {
    /// The message, or the RDATA being read, ends before a field does.
    #[error("unexpected end of data")]
    UnexpectedEnd,
    /// A name is longer than 255 bytes in wire form (RFC 1035 §2.3.4).
    #[error("name longer than 255 bytes")]
    NameTooLong,
    /// A compression pointer does not point strictly before the name being read (RFC 1035 §4.1.4).
    #[error("compression pointer does not point backwards")]
    BadPointer,
    /// A label type reserved by RFC 6891 §5 (`0b01` or `0b10` in the two high bits).
    #[error("reserved label type")]
    ReservedLabelType,
    /// RDATA is shorter or longer than its fields.
    #[error("RDATA length does not match its content")]
    RdataLength,
    /// A field holds a value the RFC forbids.
    #[error("{0}")]
    Invalid(&'static str),
}

/// A message that cannot be encoded.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum EncodeError {
    /// The output buffer, or the 65535 bytes of a DNS message, is full.
    #[error("buffer full")]
    BufferFull,
    /// The response code needs an EDNS OPT record to carry its upper bits (RFC 6891 §6.1.3).
    #[error("response code above 15 needs EDNS")]
    RcodeNeedsEdns,
    /// The response code does not fit: 12 bits for a message (RFC 6891 §6.1.3), 4 bits for a header.
    #[error("response code out of range")]
    RcodeOutOfRange,
    /// The opcode does not fit in the header's four bits (RFC 1035 §4.1.1).
    #[error("opcode above 15")]
    OpcodeOutOfRange,
}
