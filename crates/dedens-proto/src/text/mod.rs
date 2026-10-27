//! Presentation format (RFC 1035 §5.1): records as zone-file text, read and written.
//!
//! Written: `Display` on [`Name`], the codes, [`RData`] and [`Record`]: one tab-separated line per record,
//! absolute names, TTL in seconds, character-strings quoted, bytes outside printable ASCII as `\DDD`.
//! [`RData::generic`] and [`Record::generic`] write the form of RFC 3597 §5 (`TYPE65280 \# 2 abcd`).
//!
//! Zone files: [`ZoneReader`].
//!
//! Read: `FromStr` on the same types. Text is bytes (`&[u8]` underneath), since a quoted string may hold any
//! byte; a known type may be written in the generic form and is read into its typed RDATA (RFC 3597 §5).
//!
//! [`Name`]: crate::Name
//! [`RData`]: crate::RData
//! [`RData::generic`]: crate::RData::generic
//! [`Record`]: crate::Record
//! [`Record::generic`]: crate::Record::generic

pub(crate) mod encoding;
mod lexer;
mod zone;

use core::fmt;
use core::str::FromStr;

pub(crate) use lexer::{Lexer, Token};
use zone::Defaults;
pub use zone::{Entry, ZoneReader};

use crate::codes::{Class, RecordType};
use crate::error::DecodeErrorKind;
use crate::name::{Name, NameError};
use crate::rdata::{SvcParamsError, TxtError};
use crate::record::{Record, Ttl};

/// Text that does not hold a valid record, and where.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("line {line}, column {column}: {kind}")]
pub struct TextError {
    /// Line of the error, from 1.
    pub line: usize,
    /// Column of the error, in bytes from 1.
    pub column: usize,
    /// What is wrong.
    pub kind: TextErrorKind,
}

/// The reason of a [`TextError`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum TextErrorKind {
    /// A `(` without its `)`, or the reverse.
    #[error("unbalanced parenthesis")]
    UnbalancedParenthesis,
    /// A `"` without its closing one.
    #[error("unterminated quoted string")]
    UnterminatedQuote,
    /// A `\` that is neither followed by a non-digit nor by three digits up to 255.
    #[error("bad escape: \\ takes a non-digit or three digits up to 255")]
    BadEscape,
    /// The entry ends before this field.
    #[error("missing {0}")]
    Missing(&'static str),
    /// This field does not parse.
    #[error("invalid {0}")]
    Invalid(&'static str),
    /// Text after the last field of the record.
    #[error("unexpected text after the record")]
    Trailing,
    /// A name that does not end in a dot, or `@`, without an origin to complete it.
    #[error("relative name without an origin")]
    RelativeName,
    /// A name breaks the limits of RFC 1035 §2.3.4.
    #[error("{0}")]
    Name(NameError),
    /// TXT strings break RFC 1035 §3.3.14.
    #[error("{0}")]
    Txt(TxtError),
    /// SVCB parameters break RFC 9460.
    #[error("{0}")]
    SvcParams(SvcParamsError),
    /// A type without a text form here: its RDATA must be written `\# length hex` (RFC 3597 §5).
    #[error("this type has no text form here: write its RDATA as \\# length hex")]
    NeedsGeneric,
    /// The length of a generic RDATA does not match its hex bytes.
    #[error("\\# declares {declared} bytes, the hex holds {actual}")]
    GenericLength {
        /// The length written after `\#`.
        declared: usize,
        /// The bytes the hex holds.
        actual: usize,
    },
    /// Generic RDATA of a known type that is not valid for it.
    #[error("RDATA invalid for its type: {0}")]
    Rdata(DecodeErrorKind),
    /// A record without TTL, and no default for it.
    #[error("no TTL")]
    NoTtl,
    /// An entry that starts with a blank, before any owner name.
    #[error("no owner name to repeat")]
    NoOwner,
    /// A `$` entry other than `$ORIGIN`, `$INCLUDE` and `$TTL`.
    #[error("unknown directive: only $ORIGIN, $INCLUDE and $TTL")]
    UnknownDirective,
}

/// Cursor over the fields of one entry.
#[derive(Debug)]
pub(crate) struct Fields<'e, 't> {
    tokens: &'e [Token<'t>],
    origin: Option<&'e Name<'static>>,
    /// Where a missing field is reported: the end of the entry.
    end: (usize, usize),
}

impl<'e, 't> Fields<'e, 't> {
    pub(crate) fn new(tokens: &'e [Token<'t>], origin: Option<&'e Name<'static>>) -> Self {
        let end = tokens
            .last()
            .map_or((1, 1), |t| (t.line, t.column + t.raw.len()));
        Self {
            tokens,
            origin,
            end,
        }
    }

    /// An error at the end of the entry.
    pub(crate) const fn end_error(&self, kind: TextErrorKind) -> TextError {
        TextError {
            line: self.end.0,
            column: self.end.1,
            kind,
        }
    }

    /// The next token, if any.
    pub(crate) fn peek(&self) -> Option<&'e Token<'t>> {
        self.tokens.first()
    }

    /// The next token, or [`TextErrorKind::Missing`] naming `what`.
    pub(crate) fn next(&mut self, what: &'static str) -> Result<&'e Token<'t>, TextError> {
        let (first, rest) = self.tokens.split_first().ok_or(TextError {
            line: self.end.0,
            column: self.end.1,
            kind: TextErrorKind::Missing(what),
        })?;
        self.tokens = rest;
        Ok(first)
    }

    /// The next token, if any, consumed.
    pub(crate) fn next_opt(&mut self) -> Option<&'e Token<'t>> {
        let (first, rest) = self.tokens.split_first()?;
        self.tokens = rest;
        Some(first)
    }

    /// A domain name, relative to the origin unless it ends in a dot.
    pub(crate) fn name(&mut self, what: &'static str) -> Result<Name<'static>, TextError> {
        let token = self.next(what)?;
        Name::from_text(token.raw, self.origin).map_err(|kind| token.error(kind))
    }

    /// A decimal number: digits only.
    pub(crate) fn number<T: FromStr>(&mut self, what: &'static str) -> Result<T, TextError> {
        let token = self.next(what)?;
        number(token.raw).ok_or(token.error(TextErrorKind::Invalid(what)))
    }

    /// A number of seconds, plain or with units (`1h30m`).
    pub(crate) fn seconds(&mut self, what: &'static str) -> Result<u32, TextError> {
        let token = self.next(what)?;
        seconds(token.raw).ok_or(token.error(TextErrorKind::Invalid(what)))
    }

    /// A value parsed by its `FromStr`, such as an address.
    pub(crate) fn parse<T: FromStr>(&mut self, what: &'static str) -> Result<T, TextError> {
        let token = self.next(what)?;
        str::from_utf8(token.raw)
            .ok()
            .and_then(|s| s.parse().ok())
            .ok_or(token.error(TextErrorKind::Invalid(what)))
    }

    /// A character-string, quoted or not, escapes decoded; its length is not checked.
    pub(crate) fn text(&mut self, what: &'static str) -> Result<Vec<u8>, TextError> {
        let token = self.next(what)?;
        unescape(token.raw).map_err(|kind| token.error(kind))
    }

    /// Checks that no field is left.
    pub(crate) fn finish(&self) -> Result<(), TextError> {
        match self.tokens.first() {
            Some(token) => Err(token.error(TextErrorKind::Trailing)),
            None => Ok(()),
        }
    }
}

/// The fields of a record before its RDATA: `[TTL] [class] type` or `[class] [TTL] type` (RFC 1035 §5.1).
#[derive(Debug, Clone, Copy)]
pub(crate) struct Head {
    pub(crate) ttl: Option<u32>,
    pub(crate) class: Option<Class>,
    pub(crate) rtype: RecordType,
    /// Where the type is written, to report errors about the whole record.
    pub(crate) at: (usize, usize),
}

impl Head {
    /// Reads TTL, class and type. A TTL starts with a digit; class and type mnemonics are disjoint except `ANY`,
    /// a class only when a TTL or a type follows it.
    pub(crate) fn read(f: &mut Fields<'_, '_>) -> Result<Self, TextError> {
        let mut ttl = None;
        let mut class = None;
        loop {
            let token = f.next("record type")?;
            if token.raw.first().is_some_and(u8::is_ascii_digit) && ttl.is_none() {
                let secs = seconds(token.raw)
                    .filter(|&s| s <= Ttl::MAX.get())
                    .ok_or(token.error(TextErrorKind::Invalid("TTL")))?;
                ttl = Some(secs);
                continue;
            }
            let word = str::from_utf8(token.raw).unwrap_or_default();
            if class.is_none()
                && let Ok(c) = word.parse::<Class>()
                && (c != Class::ANY || f.peek().is_some_and(|next| starts_head(next.raw)))
            {
                class = Some(c);
                continue;
            }
            let rtype = word
                .parse()
                .map_err(|_| token.error(TextErrorKind::Invalid("record type")))?;
            return Ok(Self {
                ttl,
                class,
                rtype,
                at: (token.line, token.column),
            });
        }
    }
}

/// Reads a text holding exactly one record with its owner and TTL; names not ending in a dot are absolute and the
/// class defaults to IN.
pub(crate) fn one_record(text: &[u8]) -> Result<Record<'static>, TextError> {
    let mut lexer = Lexer::new(text);
    let mut tokens = Vec::new();
    let Some(blank) = lexer.entry(&mut tokens)? else {
        return Err(TextError {
            line: 1,
            column: 1,
            kind: TextErrorKind::Missing("record"),
        });
    };
    if let (true, Some(first)) = (blank, tokens.first()) {
        return Err(first.error(TextErrorKind::NoOwner));
    }
    let origin = Name::root();
    let mut f = Fields::new(&tokens, Some(&origin));
    let owner = f.name("owner name")?;
    let record = Defaults::default().record(owner, &mut f)?;
    if lexer.entry(&mut tokens)?.is_some()
        && let Some(first) = tokens.first()
    {
        return Err(first.error(TextErrorKind::Trailing));
    }
    Ok(record)
}

/// Writes RDATA in the generic form of RFC 3597 §5: `\# length hex`.
pub(crate) fn write_generic(f: &mut fmt::Formatter<'_>, data: &[u8]) -> fmt::Result {
    if data.is_empty() {
        f.write_str("\\# 0")
    } else {
        write!(f, "\\# {} {}", data.len(), encoding::Hex(data))
    }
}

/// Whether a token can be a TTL or a type, so that an `ANY` before it is a class.
fn starts_head(raw: &[u8]) -> bool {
    raw.first().is_some_and(u8::is_ascii_digit)
        || str::from_utf8(raw).is_ok_and(|w| w.parse::<RecordType>().is_ok())
}

/// A decimal number of digits only, no sign or blank.
pub(crate) fn number<T: FromStr>(raw: &[u8]) -> Option<T> {
    if raw.is_empty() || !raw.iter().all(u8::is_ascii_digit) {
        return None;
    }
    str::from_utf8(raw).ok()?.parse().ok()
}

/// Seconds, plain or as numbers each followed by a unit `w`, `d`, `h`, `m` or `s`, any case (BIND).
pub(crate) fn seconds(raw: &[u8]) -> Option<u32> {
    if let Some(plain) = number(raw) {
        return Some(plain);
    }
    let mut total: u32 = 0;
    let mut value: Option<u32> = None;
    for &b in raw {
        if b.is_ascii_digit() {
            let digit = u32::from(b - b'0');
            value = Some(value.unwrap_or(0).checked_mul(10)?.checked_add(digit)?);
            continue;
        }
        let unit = match b.to_ascii_lowercase() {
            b'w' => 604_800,
            b'd' => 86_400,
            b'h' => 3_600,
            b'm' => 60,
            b's' => 1,
            _ => return None,
        };
        total = total.checked_add(value.take()?.checked_mul(unit)?)?;
    }
    value.is_none().then_some(total)
}

/// Decodes a character-string (RFC 1035 §5.1, RFC 9460 appendix A): `"` groups and is dropped, `\X` is `X`,
/// `\DDD` is the byte of that decimal value.
pub(crate) fn unescape(raw: &[u8]) -> Result<Vec<u8>, TextErrorKind> {
    let mut out = Vec::with_capacity(raw.len());
    let mut i = 0;
    while let Some(&b) = raw.get(i) {
        i += 1;
        match b {
            b'"' => {}
            b'\\' => {
                let (byte, used) = escape(raw.get(i..).unwrap_or_default())?;
                out.push(byte);
                i += used;
            }
            _ => out.push(b),
        }
    }
    Ok(out)
}

/// The byte an escape stands for, `rest` being what follows the `\`, and how many bytes of `rest` it uses.
pub(crate) fn escape(rest: &[u8]) -> Result<(u8, usize), TextErrorKind> {
    match rest {
        [a, b, c, ..] if a.is_ascii_digit() => {
            if !(b.is_ascii_digit() && c.is_ascii_digit()) {
                return Err(TextErrorKind::BadEscape);
            }
            let value = u16::from(a - b'0') * 100 + u16::from(b - b'0') * 10 + u16::from(c - b'0');
            u8::try_from(value)
                .map(|byte| (byte, 3))
                .map_err(|_| TextErrorKind::BadEscape)
        }
        [a, ..] if !a.is_ascii_digit() => Ok((*a, 1)),
        _ => Err(TextErrorKind::BadEscape),
    }
}

/// Writes bytes as a quoted character-string: `"` and `\` escaped, bytes outside printable ASCII as `\DDD`.
pub(crate) struct Quoted<'b>(pub(crate) &'b [u8]);

impl fmt::Display for Quoted<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("\"")?;
        for &b in self.0 {
            match b {
                b'"' | b'\\' => write!(f, "\\{}", char::from(b))?,
                0x20..=0x7E => write!(f, "{}", char::from(b))?,
                _ => write!(f, "\\{b:03}")?,
            }
        }
        f.write_str("\"")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn character_strings_drop_quotes_and_decode_escapes() {
        assert_eq!(unescape(br#""a b\"\\\065\255""#).unwrap(), b"a b\"\\A\xff");
        assert_eq!(unescape(br"x\ y\.").unwrap(), b"x y.");
        assert_eq!(unescape(br"\256"), Err(TextErrorKind::BadEscape));
        assert_eq!(unescape(br"\12"), Err(TextErrorKind::BadEscape));
        assert_eq!(unescape(br"a\"), Err(TextErrorKind::BadEscape));
    }

    #[test]
    fn quoted_round_trips_every_byte() {
        let all: Vec<u8> = (0..=255).collect();
        let text = Quoted(&all).to_string();
        assert_eq!(unescape(text.as_bytes()).unwrap(), all);
    }

    #[test]
    fn seconds_take_bind_units() {
        assert_eq!(seconds(b"3600"), Some(3600));
        assert_eq!(seconds(b"1h30m"), Some(5400));
        assert_eq!(seconds(b"1W2d3H4m5S"), Some(788_645));
        assert_eq!(seconds(b"1h30"), None);
        assert_eq!(seconds(b"h"), None);
        assert_eq!(seconds(b"4294967296"), None);
        assert_eq!(seconds(b"7102w"), None);
    }

    #[test]
    fn numbers_are_digits_only() {
        assert_eq!(number::<u16>(b"65535"), Some(65535));
        assert_eq!(number::<u16>(b"65536"), None);
        assert_eq!(number::<u16>(b"+1"), None);
        assert_eq!(number::<u16>(b""), None);
    }
}
