//! TXT: text strings (RFC 1035 §3.3.14, §3.3).

use crate::error::{DecodeError, DecodeErrorKind, EncodeError};
use crate::wire::{Reader, Writer};

/// A `<character-string>`: up to 255 arbitrary bytes behind a length byte (RFC 1035 §3.3).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct CharacterString(Box<[u8]>);

/// A character string longer than 255 bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("character string longer than 255 bytes")]
pub struct CharacterStringTooLong;

impl CharacterString {
    /// A character string holding `bytes`.
    ///
    /// # Errors
    ///
    /// [`CharacterStringTooLong`] when `bytes` is longer than 255 bytes.
    pub fn new(bytes: &[u8]) -> Result<Self, CharacterStringTooLong> {
        if bytes.len() > usize::from(u8::MAX) {
            return Err(CharacterStringTooLong);
        }
        Ok(Self(bytes.into()))
    }

    /// The bytes, without the length byte.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

/// A TXT RDATA is a sequence of one or more character strings.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Txt(Vec<CharacterString>);

/// A TXT RDATA with no string.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("TXT needs at least one character string")]
pub struct EmptyTxt;

impl Txt {
    /// A TXT RDATA of `strings`.
    ///
    /// # Errors
    ///
    /// [`EmptyTxt`] when `strings` is empty.
    pub fn new(strings: Vec<CharacterString>) -> Result<Self, EmptyTxt> {
        if strings.is_empty() {
            return Err(EmptyTxt);
        }
        Ok(Self(strings))
    }

    /// The strings, in order.
    #[must_use]
    pub fn strings(&self) -> &[CharacterString] {
        &self.0
    }

    pub(super) fn decode(r: &mut Reader<'_>) -> Result<Self, DecodeError> {
        let mut strings = Vec::new();
        while !r.is_empty() {
            let len = usize::from(r.u8()?);
            strings.push(CharacterString(r.bytes(len)?.into()));
        }
        Self::new(strings)
            .map_err(|_| r.error(DecodeErrorKind::Invalid("TXT without a character string")))
    }

    pub(super) fn encode(&self, w: &mut Writer<'_>) -> Result<(), EncodeError> {
        for s in &self.0 {
            let len = u8::try_from(s.0.len()).map_err(|_| EncodeError::BufferFull)?;
            w.put_u8(len)?;
            w.put_bytes(&s.0)?;
        }
        Ok(())
    }
}
