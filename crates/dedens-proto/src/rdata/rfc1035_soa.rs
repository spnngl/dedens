//! SOA: start of authority (RFC 1035 §3.3.13).

use crate::error::{DecodeError, EncodeError};
use crate::name::Name;
use crate::wire::{Reader, Writer};

/// Start of authority. The four intervals are seconds, `minimum` is the negative-caching TTL (RFC 2308 §4).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Soa {
    /// Primary name server of the zone (MNAME).
    pub mname: Name,
    /// Mailbox of the person responsible (RNAME).
    pub rname: Name,
    /// Version of the zone.
    pub serial: u32,
    /// Seconds before a secondary refreshes.
    pub refresh: u32,
    /// Seconds before a secondary retries a failed refresh.
    pub retry: u32,
    /// Seconds before a secondary stops answering.
    pub expire: u32,
    /// Negative-caching TTL.
    pub minimum: u32,
}

impl Soa {
    pub(super) fn decode(r: &mut Reader<'_>) -> Result<Self, DecodeError> {
        Ok(Self {
            mname: Name::decode(r)?,
            rname: Name::decode(r)?,
            serial: r.u32()?,
            refresh: r.u32()?,
            retry: r.u32()?,
            expire: r.u32()?,
            minimum: r.u32()?,
        })
    }

    pub(super) fn encode(&self, w: &mut Writer<'_>) -> Result<(), EncodeError> {
        w.put_name_compressed(&self.mname)?;
        w.put_name_compressed(&self.rname)?;
        for v in [
            self.serial,
            self.refresh,
            self.retry,
            self.expire,
            self.minimum,
        ] {
            w.put_u32(v)?;
        }
        Ok(())
    }
}
