//! TXT: text strings (RFC 1035 §3.3.14, §3.3).

use std::borrow::Cow;

use crate::error::{DecodeError, DecodeErrorKind, EncodeError};
use crate::wire::{Reader, Writer};

/// A TXT RDATA: one or more `<character-string>`s, each up to 255 arbitrary bytes behind a length byte
/// (RFC 1035 §3.3).
///
/// Kept in wire form, borrowed from the message it was decoded from or owned; [`Txt::strings`] reads it.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Txt<'a>(Cow<'a, [u8]>);

/// Strings that cannot form a TXT RDATA.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum TxtError {
    /// No string.
    #[error("TXT needs at least one character string")]
    Empty,
    /// A string longer than 255 bytes.
    #[error("character string longer than 255 bytes")]
    StringTooLong,
}

impl<'a> Txt<'a> {
    /// A TXT RDATA of `strings`, in order.
    ///
    /// # Errors
    ///
    /// [`TxtError`] when there is no string, or one is longer than 255 bytes.
    pub fn new<'s, I>(strings: I) -> Result<Txt<'static>, TxtError>
    where
        I: IntoIterator<Item = &'s [u8]>,
    {
        let mut wire = Vec::new();
        for s in strings {
            let len = u8::try_from(s.len()).map_err(|_| TxtError::StringTooLong)?;
            wire.push(len);
            wire.extend_from_slice(s);
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

/// Iterator over the strings of a [`Txt`].
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
