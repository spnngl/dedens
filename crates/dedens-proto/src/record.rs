//! Resource records (RFC 1035 §3.2.1, §4.1.3), their TTL (RFC 2181 §8) and their RDATA as wire bytes (D28).

use core::fmt;
use core::hash::{Hash, Hasher};
use core::str::FromStr;

use zerocopy::network_endian::{U16, U32};
use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout, Unaligned};

use crate::codes::{Class, RecordType};
use crate::error::{DecodeError, DecodeErrorKind, EncodeError};
use crate::name::Name;
use crate::rdata::{Opaque, RData};
use crate::text::{self, TextError};
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

/// The RDATA of a record as wire bytes with its type (D28), read as [`RData`] on demand by [`WireRdata::data`].
///
/// Decoded RDATA was checked against its type, and stays in the message it came from: names in it may point
/// elsewhere in that message. Encoding copies the bytes, except for the types whose names may be compressed
/// (RFC 3597 §4), which are read and written again. Equality and hashing go through [`RData`], so names inside
/// RDATA compare ASCII case-insensitively (RFC 4343).
#[derive(Clone)]
pub struct WireRdata<'a>(Repr<'a>);

#[derive(Clone)]
enum Repr<'a> {
    /// `msg[start..end]`, checked when decoded.
    InMessage {
        msg: &'a [u8],
        start: u16,
        end: u16,
        rtype: RecordType,
    },
    /// Bytes without compression pointers.
    Owned { bytes: Box<[u8]>, rtype: RecordType },
}

impl<'a> WireRdata<'a> {
    /// The wire form of `data`.
    #[must_use]
    pub fn new(data: &RData<'_>) -> WireRdata<'static> {
        WireRdata(Repr::Owned {
            bytes: data.with_wire(|wire| Box::from(wire)),
            rtype: data.rtype(),
        })
    }

    /// RDATA of `rtype` already checked, without compression pointers.
    pub(crate) const fn from_checked(rtype: RecordType, bytes: Box<[u8]>) -> WireRdata<'static> {
        WireRdata(Repr::Owned { bytes, rtype })
    }

    /// Checks the RDATA of `rtype` delimited by `rdata` and keeps it in place; RDATA invalid for its type is kept,
    /// with why (D9).
    ///
    /// # Errors
    ///
    /// [`DecodeError`] when the RDATA of a type that may hold compressed names is invalid.
    pub(crate) fn decode(
        rtype: RecordType,
        rdata: Reader<'a>,
    ) -> Result<(Self, Option<DecodeError>), DecodeError> {
        let (data, invalid) = decode_rdata(rtype, rdata)?;
        let msg = rdata.message();
        let repr = match (u16::try_from(rdata.position()), u16::try_from(rdata.end())) {
            (Ok(start), Ok(end)) => Repr::InMessage {
                msg,
                start,
                end,
                rtype,
            },
            // Only past the 65535 bytes of a DNS message, in a larger buffer: copied out.
            _ => WireRdata::new(&data).0,
        };
        Ok((Self(repr), invalid))
    }

    /// The record type.
    #[must_use]
    pub const fn rtype(&self) -> RecordType {
        match &self.0 {
            Repr::InMessage { rtype, .. } | Repr::Owned { rtype, .. } => *rtype,
        }
    }

    /// The RDATA read as its type; RDATA invalid for its type is [`RData::Opaque`] (D9).
    #[must_use]
    pub fn data(&self) -> RData<'_> {
        let rtype = self.rtype();
        let r = self.reader();
        // Decoded RDATA was checked; bytes built from typed data hold no pointer. What still fails to read, such
        // as bytes given as opaque for a type with names, stays opaque.
        decode_rdata(rtype, r).map_or_else(
            |_| {
                let mut bytes = r;
                RData::Opaque(Opaque::invalid(rtype, bytes.rest()))
            },
            |(data, _)| data,
        )
    }

    /// The same RDATA, owning its bytes, with names uncompressed.
    #[must_use]
    pub fn into_owned(self) -> WireRdata<'static> {
        match self.0 {
            Repr::Owned { bytes, rtype } => WireRdata(Repr::Owned { bytes, rtype }),
            Repr::InMessage { rtype, .. } if RData::may_hold_compressed_names(rtype) => {
                WireRdata::new(&self.data())
            }
            Repr::InMessage {
                msg,
                start,
                end,
                rtype,
            } => WireRdata(Repr::Owned {
                bytes: Box::from(
                    msg.get(usize::from(start)..usize::from(end))
                        .unwrap_or_default(),
                ),
                rtype,
            }),
        }
    }

    /// A reader over the RDATA, inside its message when decoded.
    fn reader(&self) -> Reader<'_> {
        match &self.0 {
            Repr::InMessage {
                msg, start, end, ..
            } => Reader::range(msg, usize::from(*start), usize::from(*end)),
            Repr::Owned { bytes, .. } => Reader::new(bytes),
        }
    }

    /// Writes the RDATA, without its length: a copy, unless names in it may be compressed, in the message read
    /// (RFC 3597 §4) or the one written (the RFC 1035 types).
    pub(crate) fn encode(&self, w: &mut Writer<'_>) -> Result<(), EncodeError> {
        let rtype = self.rtype();
        let copy = match self.0 {
            Repr::InMessage { .. } => !RData::may_hold_compressed_names(rtype),
            Repr::Owned { .. } => !RData::compressed_on_write(rtype),
        };
        if copy {
            w.put_bytes(self.reader().rest())
        } else {
            self.data().encode(w)
        }
    }
}

impl From<&RData<'_>> for WireRdata<'static> {
    fn from(data: &RData<'_>) -> Self {
        Self::new(data)
    }
}

impl<'b> PartialEq<WireRdata<'b>> for WireRdata<'_> {
    fn eq(&self, other: &WireRdata<'b>) -> bool {
        self.data() == other.data()
    }
}

impl Eq for WireRdata<'_> {}

impl Hash for WireRdata<'_> {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.data().hash(state);
    }
}

/// As the [`RData`] it reads as.
impl fmt::Debug for WireRdata<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Debug::fmt(&self.data(), f)
    }
}

/// As the [`RData`] it reads as.
impl fmt::Display for WireRdata<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(&self.data(), f)
    }
}

/// A resource record: owner name, class, TTL and RDATA; the type is the RDATA's.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Record<'a> {
    /// Owner name.
    pub name: Name<'a>,
    /// Class, almost always IN.
    pub class: Class,
    /// Time to live.
    pub ttl: Ttl,
    /// The RDATA, which carries the type; [`Record::data`] reads it.
    pub rdata: WireRdata<'a>,
}

/// The fields after a record's owner name as they are on the wire (RFC 1035 §4.1.3), read and written in place.
#[derive(FromBytes, IntoBytes, KnownLayout, Immutable, Unaligned)]
#[repr(C)]
struct Fixed {
    rtype: U16,
    class: U16,
    ttl: U32,
    rdlength: U16,
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
    /// Why the RDATA could not be parsed; it then reads as [`RData::Opaque`] with the bytes as received.
    pub invalid_rdata: Option<DecodeError>,
}

impl<'a> Record<'a> {
    /// A record of typed data, stored as its wire form.
    #[must_use]
    pub fn new(name: Name<'a>, class: Class, ttl: Ttl, data: &RData<'_>) -> Self {
        Self {
            name,
            class,
            ttl,
            rdata: WireRdata::new(data),
        }
    }

    /// The record type.
    #[must_use]
    pub const fn rtype(&self) -> RecordType {
        self.rdata.rtype()
    }

    /// The RDATA read as its type; see [`WireRdata::data`].
    #[must_use]
    pub fn data(&self) -> RData<'_> {
        self.rdata.data()
    }

    /// The same record, owning its bytes.
    #[must_use]
    pub fn into_owned(self) -> Record<'static> {
        Record {
            name: self.name.into_owned(),
            class: self.class,
            ttl: self.ttl,
            rdata: self.rdata.into_owned(),
        }
    }

    /// Reads the owner name and the fixed fields, and delimits the RDATA without parsing it.
    pub(crate) fn read_raw(r: &mut Reader<'a>) -> Result<RawRecord<'a>, DecodeError> {
        let name = Name::decode(r)?;
        let fixed: &Fixed = r.fields()?;
        let rtype = RecordType(fixed.rtype.get());
        let class = Class(fixed.class.get());
        let ttl = fixed.ttl.get();
        let rdata = r.sub(usize::from(fixed.rdlength.get())).map_err(|mut e| {
            e.kind = DecodeErrorKind::RdataLength;
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

    /// The record read by [`Record::read_raw`].
    ///
    /// RDATA that is well delimited but invalid for its type is kept, reads as [`Opaque`] bytes, and is reported in
    /// [`DecodedRecord::invalid_rdata`], except for the types that may hold compressed names
    /// ([`RData::may_hold_compressed_names`]): their bytes mean nothing outside the message, so that is an error (D9).
    ///
    /// # Errors
    ///
    /// [`DecodeError`] when the RDATA of a type with compressible names is invalid.
    pub(crate) fn from_raw(raw: RawRecord<'a>) -> Result<DecodedRecord<'a>, DecodeError> {
        let RawRecord {
            name,
            rtype,
            class,
            ttl,
            rdata,
        } = raw;
        let (rdata, invalid_rdata) = WireRdata::decode(rtype, rdata)?;
        let record = Self {
            name,
            class,
            ttl: Ttl::of_record(rtype, ttl),
            rdata,
        };
        Ok(DecodedRecord {
            record,
            invalid_rdata,
        })
    }

    /// Writes the record, compressing its owner and the RDATA names of the RFC 1035 types (RFC 3597 §4), its owner
    /// a pointer to `owner` if given ([`Writer::put_owner`]); returns the offset to give the next record when it
    /// has the same owner.
    ///
    /// # Errors
    ///
    /// [`EncodeError::BufferFull`] when it does not fit; the writer is then left as it was.
    pub(crate) fn encode_after(
        &self,
        w: &mut Writer<'_>,
        owner: Option<u16>,
    ) -> Result<Option<u16>, EncodeError> {
        w.all_or_nothing(|w| {
            let owner = w.put_owner(&self.name, owner)?;
            let fixed = Fixed {
                rtype: self.rtype().0.into(),
                class: self.class.0.into(),
                ttl: self.ttl.get().into(),
                rdlength: U16::ZERO,
            };
            w.put_bytes(fixed.as_bytes())?;
            let at = w.len() - 2;
            self.rdata.encode(w)?;
            let len = u16::try_from(w.len() - at - 2).map_err(|_| EncodeError::BufferFull)?;
            w.patch_u16(at, len);
            Ok(owner)
        })
    }
}

impl Record<'_> {
    /// The record with its RDATA in the generic form of RFC 3597 §5, `\# length hex`.
    #[must_use]
    pub const fn generic(&self) -> GenericRecord<'_> {
        GenericRecord(self)
    }

    fn write_head(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}\t{}\t{}\t{}\t",
            self.name,
            self.ttl.get(),
            self.class,
            self.rtype()
        )
    }
}

/// One line: owner, TTL in seconds, class, type and RDATA, separated by tabs, names absolute (RFC 1035 §5.1).
impl fmt::Display for Record<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.write_head(f)?;
        write!(f, "{}", self.rdata)
    }
}

/// A record written with its RDATA in the generic form; from [`Record::generic`].
#[derive(Debug, Clone, Copy)]
pub struct GenericRecord<'r>(&'r Record<'r>);

impl fmt::Display for GenericRecord<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.write_head(f)?;
        write!(f, "{}", self.0.data().generic())
    }
}

/// Reads one record in presentation form: owner, TTL, optional class (IN by default), type and RDATA, TTL and
/// class in either order (RFC 1035 §5.1). Names not ending in a dot are absolute; `@` is the root. `\#` RDATA
/// that its type refuses is an error, where [`ZoneReader`](crate::text::ZoneReader) keeps it opaque with the reason.
impl FromStr for Record<'static> {
    type Err = TextError;

    fn from_str(s: &str) -> Result<Self, TextError> {
        text::one_record(s.as_bytes())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Names expanded from pointers can make RDATA outgrow 65535 bytes when the message sits in a larger buffer,
    /// as a zone transfer stream may: an error, not a panic (RFC 3597 §4).
    #[test]
    fn rdata_expanded_past_65535_bytes_is_an_error() {
        // After a header, a 255-byte name at offset 12: three labels of 63 bytes, one of 61, the root.
        let mut buf = vec![0; 12];
        for len in [63, 63, 63, 61] {
            buf.push(len);
            buf.extend(std::iter::repeat_n(b'a', usize::from(len)));
        }
        buf.push(0);
        let start = buf.len();
        // Root owner, SIG, IN, TTL 0, RDLENGTH 65535: 18 fixed bytes, the signer a pointer to the long name, the
        // rest.
        buf.extend([0, 0, 24, 0, 1, 0, 0, 0, 0, 0xFF, 0xFF]);
        buf.extend([0; 18]);
        buf.extend([0xC0, 12]);
        buf.resize(start + 11 + 65535, 0);
        let mut r = Reader::new(&buf);
        r.bytes(start).expect("the name");
        let err = Record::read_raw(&mut r)
            .and_then(Record::from_raw)
            .expect_err("too long once expanded");
        assert_eq!(err.kind, DecodeErrorKind::RdataLength);
    }
}
