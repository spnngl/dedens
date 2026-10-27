//! Resource records (RFC 1035 §3.2.1, §4.1.3) and their TTL (RFC 2181 §8).

use crate::codes::{Class, RecordType};
use crate::error::{DecodeError, EncodeError};
use crate::name::Name;
use crate::rdata::{Opaque, RData};
use crate::wire::{Reader, Writer};

/// A time to live in seconds: 0 to 2^31 - 1 (RFC 2181 §8).
///
/// One exception: an OPT record kept among the records (D9) keeps its whole TTL field, which holds EDNS bits
/// (RFC 6891 §6.1.3).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Ttl(u32);

impl Ttl {
    /// Do not cache.
    pub const ZERO: Self = Self(0);
    /// The largest TTL, 2^31 - 1.
    pub const MAX: Self = Self(0x7FFF_FFFF);

    /// A TTL of `secs`, or `None` above [`Ttl::MAX`].
    #[must_use]
    pub const fn new(secs: u32) -> Option<Self> {
        if secs <= Self::MAX.0 {
            Some(Self(secs))
        } else {
            None
        }
    }

    /// The TTL of a wire value; one with the top bit set is treated as zero (RFC 2181 §8).
    #[must_use]
    pub const fn from_wire(secs: u32) -> Self {
        match Self::new(secs) {
            Some(ttl) => ttl,
            None => Self::ZERO,
        }
    }

    /// The TTL in seconds.
    #[must_use]
    pub const fn get(self) -> u32 {
        self.0
    }

    /// The TTL of a record of `rtype` with the wire value `secs`: an OPT record kept as a record (D9) holds EDNS
    /// bits there, not seconds, so it is kept whole.
    pub(crate) const fn of_record(rtype: RecordType, secs: u32) -> Self {
        if rtype.0 == RecordType::OPT.0 {
            Self(secs)
        } else {
            Self::from_wire(secs)
        }
    }
}

/// A resource record: owner name, class, TTL and data; the type is the data's.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Record<'a> {
    /// Owner name.
    pub name: Name<'a>,
    /// Class, almost always IN.
    pub class: Class,
    /// Time to live.
    pub ttl: Ttl,
    /// The data, which carries the type.
    pub data: RData<'a>,
}

/// The fixed fields of a record and its RDATA still unparsed, so the message decoder can take an OPT record
/// before its CLASS and TTL are read as such (RFC 6891 §6.1.2).
#[derive(Debug, Clone)]
pub(crate) struct RawRecord<'a> {
    pub(crate) name: Name<'a>,
    pub(crate) rtype: RecordType,
    pub(crate) class: Class,
    pub(crate) ttl: u32,
    pub(crate) rdata: Reader<'a>,
}

/// Parses the RDATA of a record of `rtype`; RDATA invalid for its type is kept opaque, with why (D9).
///
/// # Errors
///
/// [`DecodeError`] when the RDATA of a type that may hold compressed names is invalid.
pub(crate) fn decode_rdata(
    rtype: RecordType,
    rdata: Reader<'_>,
) -> Result<(RData<'_>, Option<DecodeError>), DecodeError> {
    let mut r = rdata;
    match RData::decode(rtype, &mut r) {
        Ok(data) => Ok((data, None)),
        Err(e) if RData::may_hold_compressed_names(rtype) => Err(e),
        Err(e) => {
            let mut bytes = rdata;
            Ok((RData::Opaque(Opaque::invalid(rtype, bytes.rest())), Some(e)))
        }
    }
}

/// A record and, when its RDATA was invalid for its type, why it was kept opaque (D9).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DecodedRecord<'a> {
    /// The record.
    pub record: Record<'a>,
    /// Why the RDATA could not be parsed; it is then [`RData::Opaque`] with the bytes as received.
    pub invalid_rdata: Option<DecodeError>,
}

impl<'a> Record<'a> {
    /// A record.
    #[must_use]
    pub const fn new(name: Name<'a>, class: Class, ttl: Ttl, data: RData<'a>) -> Self {
        Self {
            name,
            class,
            ttl,
            data,
        }
    }

    /// The record type.
    #[must_use]
    pub const fn rtype(&self) -> RecordType {
        self.data.rtype()
    }

    /// The same record, owning its bytes.
    #[must_use]
    pub fn into_owned(self) -> Record<'static> {
        Record {
            name: self.name.into_owned(),
            class: self.class,
            ttl: self.ttl,
            data: self.data.into_owned(),
        }
    }

    /// Reads the owner name and the fixed fields, and delimits the RDATA without parsing it.
    pub(crate) fn read_raw(r: &mut Reader<'a>) -> Result<RawRecord<'a>, DecodeError> {
        let name = Name::decode(r)?;
        // Type, class, TTL and RDLENGTH in one bounds check.
        let [t0, t1, c0, c1, l0, l1, l2, l3, d0, d1] = r.array()?;
        let rtype = RecordType(u16::from_be_bytes([t0, t1]));
        let class = Class(u16::from_be_bytes([c0, c1]));
        let ttl = u32::from_be_bytes([l0, l1, l2, l3]);
        let len = usize::from(u16::from_be_bytes([d0, d1]));
        let rdata = r.sub(len).map_err(|mut e| {
            e.kind = crate::error::DecodeErrorKind::RdataLength;
            e
        })?;
        Ok(RawRecord {
            name,
            rtype,
            class,
            ttl,
            rdata,
        })
    }

    /// Reads one record.
    ///
    /// RDATA that is well delimited but invalid for its type is kept as [`Opaque`] bytes and reported in
    /// [`DecodedRecord::invalid_rdata`], except for the types that may hold compressed names
    /// ([`RData::may_hold_compressed_names`]): their bytes mean nothing outside the message, so that is an error (D9).
    ///
    /// # Errors
    ///
    /// [`DecodeError`] when the name or the fixed fields are cut short, RDLENGTH overruns the message, or the RDATA
    /// of a type with compressible names is invalid.
    pub fn decode(r: &mut Reader<'a>) -> Result<DecodedRecord<'a>, DecodeError> {
        Self::from_raw(Self::read_raw(r)?)
    }

    pub(crate) fn from_raw(raw: RawRecord<'a>) -> Result<DecodedRecord<'a>, DecodeError> {
        let RawRecord {
            name,
            rtype,
            class,
            ttl,
            rdata,
        } = raw;
        let (data, invalid_rdata) = decode_rdata(rtype, rdata)?;
        let record = Self::new(name, class, Ttl::of_record(rtype, ttl), data);
        Ok(DecodedRecord {
            record,
            invalid_rdata,
        })
    }

    /// Writes the record, compressing its owner and the RDATA names of the RFC 1035 types (RFC 3597 §4).
    ///
    /// # Errors
    ///
    /// [`EncodeError::BufferFull`] when it does not fit.
    pub fn encode(&self, w: &mut Writer<'_>) -> Result<(), EncodeError> {
        w.put_name_compressed(&self.name)?;
        w.put_u16(self.rtype().0)?;
        w.put_u16(self.class.0)?;
        w.put_u32(self.ttl.get())?;
        let at = w.reserve_u16()?;
        self.data.encode(w)?;
        let len = u16::try_from(w.len() - at - 2).map_err(|_| EncodeError::BufferFull)?;
        w.patch_u16(at, len);
        Ok(())
    }
}
