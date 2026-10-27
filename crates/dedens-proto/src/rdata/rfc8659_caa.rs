//! CAA: certification authority authorization (RFC 8659 §4).

use core::fmt;
use std::borrow::Cow;

use super::MAX_RDATA_LEN;
use crate::error::{DecodeError, DecodeErrorKind, EncodeError};
use crate::text::{Fields, Quoted, TextError, TextErrorKind};
use crate::wire::{Reader, Writer};

/// A CAA tag that is not 1 to 15 ASCII letters or digits (RFC 8659 §4.1.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum CaaError {
    /// A tag that is not 1 to 15 ASCII letters or digits.
    #[error("CAA tag must be 1 to 15 ASCII letters or digits")]
    InvalidTag,
    /// Flags, tag and value over the 65535 bytes of an RDATA.
    #[error("CAA RDATA longer than 65535 bytes")]
    TooLong,
}

/// A CAA property: flags, a tag such as `issue`, and a value.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Caa<'a> {
    flags: u8,
    tag: Cow<'a, [u8]>,
    value: Cow<'a, [u8]>,
}

impl<'a> Caa<'a> {
    /// Bit 0 of the flags: a CA that does not understand the property must not issue (RFC 8659 §4.1.1).
    pub const CRITICAL: u8 = 0x80;

    /// A CAA property, borrowing `tag` and `value`.
    ///
    /// # Errors
    ///
    /// [`CaaError`] when `tag` is not 1 to 15 ASCII letters or digits, or the value is too long for an RDATA.
    pub fn new(flags: u8, tag: &'a [u8], value: &'a [u8]) -> Result<Self, CaaError> {
        let valid = (1..=15).contains(&tag.len()) && tag.iter().all(u8::is_ascii_alphanumeric);
        if !valid {
            return Err(CaaError::InvalidTag);
        }
        if 2 + tag.len() + value.len() > MAX_RDATA_LEN {
            return Err(CaaError::TooLong);
        }
        Ok(Self {
            flags,
            tag: Cow::Borrowed(tag),
            value: Cow::Borrowed(value),
        })
    }

    /// The same property, owning its bytes.
    #[must_use]
    pub fn into_owned(self) -> Caa<'static> {
        Caa {
            flags: self.flags,
            tag: Cow::Owned(self.tag.into_owned()),
            value: Cow::Owned(self.value.into_owned()),
        }
    }

    /// The flags byte.
    #[must_use]
    pub const fn flags(&self) -> u8 {
        self.flags
    }

    /// Whether the critical flag is set.
    #[must_use]
    pub const fn is_critical(&self) -> bool {
        self.flags & Self::CRITICAL != 0
    }

    /// The tag, ASCII letters and digits.
    #[must_use]
    pub fn tag(&self) -> &[u8] {
        &self.tag
    }

    /// The value: the rest of the RDATA, any bytes.
    #[must_use]
    pub fn value(&self) -> &[u8] {
        &self.value
    }

    pub(super) fn decode(r: &mut Reader<'a>) -> Result<Self, DecodeError> {
        let flags = r.u8()?;
        let tag_len = usize::from(r.u8()?);
        let tag = r.bytes(tag_len)?;
        let value = r.rest();
        Self::new(flags, tag, value)
            .map_err(|_| r.error(DecodeErrorKind::Invalid("invalid CAA tag")))
    }

    pub(super) fn encode(&self, w: &mut Writer<'_>) -> Result<(), EncodeError> {
        let tag_len = u8::try_from(self.tag.len()).map_err(|_| EncodeError::BufferFull)?;
        w.put_u8(self.flags)?;
        w.put_u8(tag_len)?;
        w.put_bytes(&self.tag)?;
        w.put_bytes(&self.value)
    }
}

impl Caa<'static> {
    /// Reads `flags tag value`, the value a character-string of any length (RFC 8659 §4.1.1).
    pub(super) fn from_text(f: &mut Fields<'_, '_>) -> Result<Self, TextError> {
        let flags = f.number("CAA flags")?;
        let tag = f.next("CAA tag")?;
        let value = f.text("CAA value")?;
        Caa::new(flags, tag.raw, &value)
            .map(Caa::into_owned)
            .map_err(|e| {
                tag.error(TextErrorKind::Invalid(match e {
                    CaaError::InvalidTag => "CAA tag: 1 to 15 letters or digits, unquoted",
                    CaaError::TooLong => "CAA value: RDATA over 65535 bytes",
                }))
            })
    }
}

/// `flags tag "value"`.
impl fmt::Display for Caa<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let tag = str::from_utf8(&self.tag).unwrap_or_default();
        write!(f, "{} {tag} {}", self.flags, Quoted(&self.value))
    }
}
