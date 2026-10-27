//! MX: mail exchange (RFC 1035 §3.3.9).

use crate::error::{DecodeError, EncodeError};
use crate::name::Name;
use crate::wire::{Reader, Writer};

/// A mail exchange: lower preference is tried first.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Mx {
    /// Preference of this exchange.
    pub preference: u16,
    /// The host that accepts the mail.
    pub exchange: Name,
}

impl Mx {
    pub(super) fn decode(r: &mut Reader<'_>) -> Result<Self, DecodeError> {
        Ok(Self {
            preference: r.u16()?,
            exchange: Name::decode(r)?,
        })
    }

    pub(super) fn encode(&self, w: &mut Writer<'_>) -> Result<(), EncodeError> {
        w.put_u16(self.preference)?;
        self.exchange.encode(w)
    }
}
