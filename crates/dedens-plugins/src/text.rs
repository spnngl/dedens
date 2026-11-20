//! What the plugins share: reading their line-based files, and the lowercase key of a name.

use core::str::SplitWhitespace;

use dedens_proto::{MAX_NAME_LEN, Name, TextError, TextErrorKind};

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
    /// A name of one label in a plain list: it would block, or allow, a whole top-level domain (D118).
    #[error("`{0}` is one label, a whole top-level domain")]
    SingleLabel(String),
    /// A `*.name` in a list of names to ask for: a wildcard cannot be asked (D96).
    #[error("`{0}` is a wildcard, which cannot be asked")]
    Wildcard(String),
    /// A field after the one name a line holds.
    #[error("`{0}` after the name")]
    Extra(String),
    /// A name with more records than a message carries.
    #[error("`{0}` has more records than a message carries")]
    TooMany(String),
}

/// The fields of each line of `text` with any, from 1, with comments (`#` to the end of the line) and a leading
/// byte order mark (U+FEFF, as some Windows editors write) left out.
pub(crate) fn lines(text: &str) -> impl Iterator<Item = (usize, SplitWhitespace<'_>)> {
    let text = text.strip_prefix('\u{feff}').unwrap_or(text);
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

/// The wire form of a name in lowercase, the key plugins look names up by, case-insensitively (RFC 4343 §3): the
/// labels, each after its length byte, then the root's zero byte, 255 bytes at most. Only [`key`] makes one, so a
/// walk of the labels can rely on that form.
#[derive(Debug, Clone, Copy)]
pub(crate) struct Key<'b>(&'b [u8]);

impl<'b> Key<'b> {
    pub(crate) const fn as_bytes(self) -> &'b [u8] {
        self.0
    }
}

/// The [`Key`] of `name`, written to `buf`.
pub(crate) fn key<'b>(name: &Name<'_>, buf: &'b mut [u8; MAX_NAME_LEN]) -> Key<'b> {
    let key = name.copy_wire(buf);
    // Length bytes stay below 64, under `A`.
    key.make_ascii_lowercase();
    Key(key)
}

#[cfg(test)]
mod tests {
    use dedens_proto::{MAX_NAME_LEN, Message, Name};
    use dedens_testkit::captured;

    use super::key;

    fn key_of(name: &Name<'_>) -> Vec<u8> {
        key(name, &mut [0; MAX_NAME_LEN]).as_bytes().to_vec()
    }

    /// A key is the name's wire form in lowercase, a compressed one followed to its end.
    #[test]
    fn a_key_is_the_lowercase_wire_form() {
        let wire = captured("a");
        let decoded = Message::decode(&wire).expect("a message");
        let owner = &decoded.message.answer[0].name;
        assert_eq!(key_of(owner), b"\x07example\x03com\x00");
        let mixed: Name<'_> = "WwW.ExAmple.COM.".parse().expect("a name");
        assert_eq!(key_of(&mixed), b"\x03www\x07example\x03com\x00");
        assert_eq!(key_of(&Name::root()), b"\x00");
    }
}
