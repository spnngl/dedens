//! TXT: text strings (RFC 1035 §3.3.14, §3.3).

use core::fmt;
use std::borrow::Cow;

use super::MAX_RDATA_LEN;
use crate::error::{DecodeError, DecodeErrorKind, EncodeError};
use crate::text::{Fields, Quoted, TextError, TextErrorKind, unescape_into};
use crate::wire::{Reader, Writer};

/// A TXT RDATA: one or more `<character-string>`s, each up to 255 arbitrary bytes behind a length byte
/// (RFC 1035 §3.3).
///
/// Kept in wire form, borrowed from the message it was decoded from or owned; [`Txt::strings`] reads it.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Txt<'a>(Cow<'a, [u8]>);

/// Strings that cannot form a TXT RDATA (RFC 1035 §3.3, §3.3.14).
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum TxtError {
    /// No string.
    #[error("TXT needs at least one character string")]
    Empty,
    /// A string longer than 255 bytes.
    #[error("character string longer than 255 bytes")]
    StringTooLong,
    /// Strings and their length bytes over the 65535 bytes of an RDATA.
    #[error("TXT RDATA longer than 65535 bytes")]
    TooLong,
}

impl<'a> Txt<'a> {
    /// A TXT RDATA of `strings`, in order.
    ///
    /// # Errors
    ///
    /// [`TxtError`] when there is no string, one is longer than 255 bytes, or all take more than 65535 bytes.
    pub fn new<'s, I>(strings: I) -> Result<Txt<'static>, TxtError>
    where
        I: IntoIterator<Item = &'s [u8]>,
    {
        let mut wire = Vec::new();
        for s in strings {
            push_string(&mut wire, s)?;
        }
        if wire.is_empty() {
            return Err(TxtError::Empty);
        }
        Ok(Txt(Cow::Owned(wire)))
    }

    /// The strings, in order, without their length bytes.
    #[must_use]
    pub fn strings(&self) -> CharacterStrings<'_> {
        CharacterStrings(&self.0)
    }

    /// The same RDATA, owning its bytes.
    #[must_use]
    pub fn into_owned(self) -> Txt<'static> {
        Txt(Cow::Owned(self.0.into_owned()))
    }

    pub(super) fn decode(r: &mut Reader<'a>) -> Result<Self, DecodeError> {
        let mut check = *r;
        let wire = r.rest();
        if wire.is_empty() {
            return Err(r.error(DecodeErrorKind::Invalid("TXT without a character string")));
        }
        while !check.is_empty() {
            let len = usize::from(check.u8()?);
            check.bytes(len)?;
        }
        Ok(Self(Cow::Borrowed(wire)))
    }

    pub(super) fn encode(&self, w: &mut Writer<'_>) -> Result<(), EncodeError> {
        w.put_bytes(&self.0)
    }
}

/// Iterator over the character-strings of a [`Txt`] (RFC 1035 §3.3).
#[derive(Debug, Clone)]
pub struct CharacterStrings<'t>(&'t [u8]);

impl<'t> Iterator for CharacterStrings<'t> {
    type Item = &'t [u8];

    fn next(&mut self) -> Option<&'t [u8]> {
        let (&len, rest) = self.0.split_first()?;
        let (s, rest) = rest.split_at_checked(usize::from(len))?;
        self.0 = rest;
        Some(s)
    }
}

impl Txt<'static> {
    /// Reads one or more character-strings, quoted or not (RFC 1035 §5.1).
    pub(super) fn from_text(f: &mut Fields<'_, '_>) -> Result<Self, TextError> {
        let first = f.next("TXT string")?;
        // Escapes only shrink a string: one string never grows the buffer.
        let mut wire = Vec::with_capacity(first.raw.len() + 1);
        let mut token = Some(first);
        while let Some(at) = token {
            // Unescaped in place behind its length byte, set once the length is known.
            let len_at = wire.len();
            wire.push(0);
            unescape_into(at.raw, &mut wire).map_err(|kind| at.error(kind))?;
            let txt_error = |e| at.error(TextErrorKind::Txt(e));
            let len = u8::try_from(wire.len() - len_at - 1)
                .map_err(|_| txt_error(TxtError::StringTooLong))?;
            if wire.len() > MAX_RDATA_LEN {
                return Err(txt_error(TxtError::TooLong));
            }
            if let Some(byte) = wire.get_mut(len_at) {
                *byte = len;
            }
            token = f.next_opt()?;
        }
        Ok(Txt(Cow::Owned(wire)))
    }
}

/// Appends `s` behind its length byte to the RDATA `wire`.
fn push_string(wire: &mut Vec<u8>, s: &[u8]) -> Result<(), TxtError> {
    let len = u8::try_from(s.len()).map_err(|_| TxtError::StringTooLong)?;
    if wire.len() + 1 + s.len() > MAX_RDATA_LEN {
        return Err(TxtError::TooLong);
    }
    wire.push(len);
    wire.extend_from_slice(s);
    Ok(())
}

/// Each string quoted, separated by spaces.
impl fmt::Display for Txt<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for (i, s) in self.strings().enumerate() {
            if i > 0 {
                f.write_str(" ")?;
            }
            write!(f, "{}", Quoted(s))?;
        }
        Ok(())
    }
}
