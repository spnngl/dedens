//! SRV: service locator (RFC 2782).

use core::fmt;

use crate::error::{DecodeError, EncodeError};
use crate::name::Name;
use crate::text::{Fields, TextError};
use crate::wire::{Reader, Writer};

/// A service location: lower priority is tried first, weight shares load among equal priorities.
///
/// The target is not compressed when written (RFC 2782, RFC 3597 §4).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Srv<'a> {
    /// Priority of the target host.
    pub priority: u16,
    /// Relative weight among targets of the same priority.
    pub weight: u16,
    /// Port of the service.
    pub port: u16,
    /// Host providing the service; the root means the service is not available.
    pub target: Name<'a>,
}

impl<'a> Srv<'a> {
    /// The same service location, owning its name.
    #[must_use]
    pub fn into_owned(self) -> Srv<'static> {
        Srv {
            priority: self.priority,
            weight: self.weight,
            port: self.port,
            target: self.target.into_owned(),
        }
    }

    pub(super) fn decode(r: &mut Reader<'a>) -> Result<Self, DecodeError> {
        Ok(Self {
            priority: r.u16()?,
            weight: r.u16()?,
            port: r.u16()?,
            target: Name::decode(r)?,
        })
    }

    pub(super) fn encode(&self, w: &mut Writer<'_>) -> Result<(), EncodeError> {
        w.put_u16(self.priority)?;
        w.put_u16(self.weight)?;
        w.put_u16(self.port)?;
        self.target.encode(w)
    }
}

impl Srv<'static> {
    /// Reads `priority weight port target`.
    pub(super) fn from_text(f: &mut Fields<'_, '_>) -> Result<Self, TextError> {
        Ok(Self {
            priority: f.number("SRV priority")?,
            weight: f.number("SRV weight")?,
            port: f.number("SRV port")?,
            target: f.name("SRV target")?,
        })
    }
}

/// `priority weight port target`.
impl fmt::Display for Srv<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{} {} {} {}",
            self.priority, self.weight, self.port, self.target
        )
    }
}
