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

/// Cursor over the fields of one entry, read from the lexer as they are asked for.
#[derive(Debug)]
pub(crate) struct Fields<'f, 't> {
    lexer: &'f mut Lexer<'t>,
    origin: Option<&'f Name<'static>>,
    /// The next token, read ahead by [`Fields::peek`], and the lexer as it was before it.
    peeked: Option<(Token<'t>, Lexer<'t>)>,
    /// Whether a quote may open after the first `=` of a token (see [`Lexer::token`]).
    pairs: bool,
}

impl<'f, 't> Fields<'f, 't> {
    pub(crate) const fn new(lexer: &'f mut Lexer<'t>, origin: Option<&'f Name<'static>>) -> Self {
        Self {
            lexer,
            origin,
            peeked: None,
            pairs: false,
        }
    }

    /// An error right after the last field read.
    pub(crate) fn end_error(&self, kind: TextErrorKind) -> TextError {
        let (line, column) = self
            .peeked
            .as_ref()
            .map_or(self.lexer.end(), |(_, before)| before.end());
        TextError { line, column, kind }
    }

    /// Reads the fields left as SVCB parameters, `key="value"` (RFC 9460 §2.1; see [`Lexer::token`]).
    pub(crate) fn quoted_pairs(&mut self) {
        self.pairs = true;
        // A token read ahead is read again, the new way.
        if let Some((_, before)) = self.peeked.take() {
            *self.lexer = before;
        }
    }

    /// The next token, if any, left for the next read.
    pub(crate) fn peek(&mut self) -> Result<Option<Token<'t>>, TextError> {
        if self.peeked.is_none() {
            let before = *self.lexer;
            self.peeked = self.lexer.token(self.pairs)?.map(|token| (token, before));
        }
        Ok(self.peeked.map(|(token, _)| token))
    }

    /// The next token, or [`TextErrorKind::Missing`] naming `what`.
    pub(crate) fn next(&mut self, what: &'static str) -> Result<Token<'t>, TextError> {
        self.next_opt()?
            .ok_or_else(|| self.end_error(TextErrorKind::Missing(what)))
    }

    /// The next token, if any.
    pub(crate) fn next_opt(&mut self) -> Result<Option<Token<'t>>, TextError> {
        match self.peeked.take() {
            Some((token, _)) => Ok(Some(token)),
            None => self.lexer.token(self.pairs),
        }
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
    pub(crate) fn finish(&mut self) -> Result<(), TextError> {
        match self.next_opt()? {
            Some(token) => Err(token.error(TextErrorKind::Trailing)),
            None => Ok(()),
        }
    }
}

/// The fields of a record before its RDATA: `[TTL] [class] type` or `[class] [TTL] type` (RFC 1035 §5.1).
#[derive(Debug, Clone, Copy)]
pub(crate) struct Head {
    pub(crate) ttl: Option<Ttl>,
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
                    .and_then(Ttl::new)
                    .ok_or(token.error(TextErrorKind::Invalid("TTL")))?;
                ttl = Some(secs);
                continue;
            }
            let word = str::from_utf8(token.raw).unwrap_or_default();
            if class.is_none()
                && let Ok(c) = word.parse::<Class>()
                && (c != Class::ANY || f.peek()?.is_some_and(|next| starts_head(next.raw)))
            {
                if !is_data_class(c) {
                    return Err(token.error(TextErrorKind::Invalid("class: a query or meta class")));
                }
                class = Some(c);
                continue;
            }
            let rtype = word
                .parse()
                .map_err(|_| token.error(TextErrorKind::Invalid("record type")))?;
            if !is_data_type(rtype) {
                return Err(
                    token.error(TextErrorKind::Invalid("record type: a query or meta type"))
                );
            }
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
    let Some(blank) = lexer.entry()? else {
        return Err(TextError {
            line: 1,
            column: 1,
            kind: TextErrorKind::Missing("record"),
        });
    };
    let origin = Name::root();
    let mut f = Fields::new(&mut lexer, Some(&origin));
    if blank {
        return Err(f.next("owner name")?.error(TextErrorKind::NoOwner));
    }
    let owner = f.name("owner name")?;
    let record = Defaults::default().record(owner, &mut f)?.record;
    if lexer.entry()?.is_some()
        && let Some(first) = lexer.token(false)?
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

/// Whether a record can have type `rtype`: not 0, OPT, a QTYPE or meta type of 128 to 255, or the reserved 65535
/// (RFC 6895 section 3.1).
fn is_data_type(rtype: RecordType) -> bool {
    rtype != RecordType::OPT && !matches!(u16::from(rtype), 0 | 128..=255 | 65535)
}

/// Whether a record can have class `class`: not 0, a QCLASS or meta class (128 to 255 with NONE and ANY, 57344 to
/// 65279), or the reserved 65535 (RFC 6895 section 3.2).
fn is_data_class(class: Class) -> bool {
    !matches!(u16::from(class), 0 | 128..=255 | 0xE000..=0xFEFF | 65535)
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

/// Decodes a character-string (RFC 1035 §5.1, RFC 9460 appendix A): quotes around it are dropped, `\X` is `X`,
/// `\DDD` is the byte of that decimal value. The lexer ends a quoted token at its closing quote, so any other `"`
/// is text.
pub(crate) fn unescape(raw: &[u8]) -> Result<Vec<u8>, TextErrorKind> {
    let mut out = Vec::with_capacity(raw.len());
    unescape_into(raw, &mut out)?;
    Ok(out)
}

/// [`unescape`], appending to `out`.
pub(crate) fn unescape_into(raw: &[u8], out: &mut Vec<u8>) -> Result<(), TextErrorKind> {
    let mut raw = raw
        .strip_prefix(b"\"")
        .and_then(|inner| inner.strip_suffix(b"\""))
        .unwrap_or(raw);
    // Plain runs are copied whole; most strings have no escape at all.
    while let Some(at) = raw.iter().position(|&b| b == b'\\') {
        let (plain, rest) = raw.split_at(at);
        out.extend_from_slice(plain);
        let rest = rest.get(1..).unwrap_or_default();
        let (byte, used) = escape(rest)?;
        out.push(byte);
        raw = rest.get(used..).unwrap_or_default();
    }
    out.extend_from_slice(raw);
    Ok(())
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
        assert_eq!(unescape(br#"a"b"#).unwrap(), b"a\"b");
        assert_eq!(unescape(br#""""#).unwrap(), b"");
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
