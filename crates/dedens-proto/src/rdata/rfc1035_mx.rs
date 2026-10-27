//! MX: mail exchange (RFC 1035 §3.3.9).

use crate::error::{DecodeError, EncodeError};
use crate::name::Name;
use crate::wire::{Reader, Writer};

/// A mail exchange: lower preference is tried first.
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
