//! MX: mail exchange (RFC 1035 §3.3.9).

use core::fmt;

use crate::error::{DecodeError, EncodeError};
use crate::name::Name;
use crate::text::{Fields, TextError};
use crate::wire::{Reader, Writer};

/// A mail exchange (RFC 1035 §3.3.9): lower preference is tried first.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Mx<'a> {
    /// Preference of this exchange.
    pub preference: u16,
    /// The host that accepts the mail.
    pub exchange: Name<'a>,
}

impl<'a> Mx<'a> {
    /// The same exchange, owning its name.
    #[must_use]
    pub fn into_owned(self) -> Mx<'static> {
        Mx {
            preference: self.preference,
            exchange: self.exchange.into_owned(),
        }
    }

    pub(super) fn decode(r: &mut Reader<'a>) -> Result<Self, DecodeError> {
        Ok(Self {
            preference: r.u16()?,
            exchange: Name::decode(r)?,
        })
    }

    pub(super) fn encode(&self, w: &mut Writer<'_>) -> Result<(), EncodeError> {
        w.put_u16(self.preference)?;
        w.put_name_compressed(&self.exchange)
    }
}

impl Mx<'static> {
    /// Reads `preference exchange`.
    pub(super) fn from_text(f: &mut Fields<'_, '_>) -> Result<Self, TextError> {
        Ok(Self {
            preference: f.number("MX preference")?,
            exchange: f.name("MX exchange")?,
        })
    }
}

/// `preference exchange`.
impl fmt::Display for Mx<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} {}", self.preference, self.exchange)
    }
}
