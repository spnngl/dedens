//! What the plugins share: reading their line-based files, and the lowercase key of a name.

use core::str::SplitWhitespace;

use dedens_proto::name::MAX_NAME_LEN;
use dedens_proto::{Name, TextError, TextErrorKind};

/// A line of a plugin's input that it cannot read.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("line {line}: {kind}")]
pub struct LineError {
    /// The line, from 1.
    pub line: usize,
    /// What is wrong with it.
    pub kind: LineErrorKind,
}

/// What is wrong with a line.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum LineErrorKind {
    /// The first field is not an IPv4 or IPv6 address.
    #[error("`{0}` is not an IP address")]
    Address(String),
    /// An address without a name after it.
    #[error("an address without a name")]
    NoName,
    /// A field that is not a domain name.
    #[error("`{0}` is not a domain name: {1}")]
    Name(String, TextErrorKind),
    /// A name with more records than a message carries.
    #[error("`{0}` has more records than a message carries")]
    TooMany(String),
}

/// The fields of each line of `text` with any, from 1, with comments (`#` to the end of the line) left out.
pub(crate) fn lines(text: &str) -> impl Iterator<Item = (usize, SplitWhitespace<'_>)> {
    text.lines().enumerate().filter_map(|(index, line)| {
        let line = line.split_once('#').map_or(line, |(before, _)| before);
        let fields = line.split_whitespace();
        fields
            .clone()
            .next()
            .is_some()
            .then_some((index + 1, fields))
    })
}

/// `field`, a name relative to the root.
pub(crate) fn name(line: usize, field: &str) -> Result<Name<'static>, LineError> {
    field.parse().map_err(|error: TextError| LineError {
        line,
        kind: LineErrorKind::Name(field.to_owned(), error.kind),
    })
}

/// The wire form of `name` in lowercase: the key plugins look names up by, case-insensitively (RFC 4343 §3).
pub(crate) fn key<'b>(name: &Name<'_>, buf: &'b mut [u8; MAX_NAME_LEN]) -> &'b [u8] {
    let mut wire = [0; MAX_NAME_LEN];
    let wire = name.to_wire(&mut wire);
    let key = &mut buf[..wire.len()];
    key.copy_from_slice(wire);
    // Length bytes stay below 64, under `A`.
    key.make_ascii_lowercase();
    key
}
