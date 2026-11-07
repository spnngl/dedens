//! SOA: start of authority (RFC 1035 §3.3.13).

use core::fmt;

use crate::error::{DecodeError, EncodeError};
use crate::name::Name;
use crate::text::{Fields, TextError};
use crate::wire::{Reader, Writer};

/// Start of authority. The four intervals are seconds, `minimum` is the negative-caching TTL (RFC 2308 §4).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Soa<'a> {
    /// Primary name server of the zone (MNAME).
    pub mname: Name<'a>,
    /// Mailbox of the person responsible (RNAME).
    pub rname: Name<'a>,
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

impl<'a> Soa<'a> {
    /// The same SOA, owning its names.
    #[must_use]
    pub fn into_owned(self) -> Soa<'static> {
        Soa {
            mname: self.mname.into_owned(),
            rname: self.rname.into_owned(),
            serial: self.serial,
            refresh: self.refresh,
            retry: self.retry,
            expire: self.expire,
            minimum: self.minimum,
        }
    }

    pub(super) fn decode(r: &mut Reader<'a>) -> Result<Self, DecodeError> {
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

impl Soa<'static> {
    /// Reads `mname rname serial refresh retry expire minimum`; the four intervals may use units (`1h`).
    pub(super) fn from_text(f: &mut Fields<'_, '_>) -> Result<Self, TextError> {
        Ok(Self {
            mname: f.name("SOA MNAME")?,
            rname: f.name("SOA RNAME")?,
            serial: f.number("SOA serial")?,
            refresh: f.seconds("SOA refresh")?,
            retry: f.seconds("SOA retry")?,
            expire: f.seconds("SOA expire")?,
            minimum: f.seconds("SOA minimum")?,
        })
    }
}

/// `mname rname serial refresh retry expire minimum`, intervals in seconds.
impl fmt::Display for Soa<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{} {} {} {} {} {} {}",
            self.mname,
            self.rname,
            self.serial,
            self.refresh,
            self.retry,
            self.expire,
            self.minimum
        )
    }
}
