//! RDATA of the supported record types (D11); every other type is kept [`Opaque`] (RFC 3597).
//!
//! One file per type, or per group of types sharing a format, named after the RFC that defines it.

mod rfc1035_a;
mod rfc1035_domain_name;
mod rfc1035_mx;
mod rfc1035_soa;
mod rfc1035_txt;
mod rfc2782_srv;
mod rfc3596_aaaa;
mod rfc3597_opaque;
mod rfc4034_dnskey;
mod rfc4034_ds;
mod rfc4034_nsec;
mod rfc4034_rrsig;
mod rfc5155_nsec3;
mod rfc8659_caa;
mod rfc9460_svcb;

use core::fmt;
use core::net::{Ipv4Addr, Ipv6Addr};

pub use rfc1035_mx::Mx;
pub use rfc1035_soa::Soa;
pub use rfc1035_txt::{CharacterStrings, Txt, TxtError};
pub use rfc2782_srv::Srv;
pub use rfc3597_opaque::Opaque;
pub use rfc4034_dnskey::{Dnskey, DnskeyError};
pub use rfc4034_ds::{Ds, DsError};
pub use rfc4034_nsec::{Nsec, TypeBitmap, TypeBitmapError};
pub use rfc4034_rrsig::{Rrsig, RrsigError};
pub use rfc5155_nsec3::{Nsec3, Nsec3Error, Nsec3Param};
pub use rfc8659_caa::{Caa, CaaError};
pub use rfc9460_svcb::{Params, SvcParam, SvcParamKey, SvcParams, SvcParamsError, Svcb};

use crate::codes::RecordType;
use crate::error::{DecodeError, DecodeErrorKind, EncodeError};
use crate::name::Name;
use crate::record::{WireRdata, decode_rdata};
use crate::text::{self, Fields, TextError, TextErrorKind, encoding};
use crate::wire::{Reader, Writer};

/// The most bytes an RDATA holds: RDLENGTH is 16 bits (RFC 1035 §3.2.1).
pub(crate) const MAX_RDATA_LEN: usize = 65535;

/// The data of a resource record, borrowed from the message it was decoded from or owned (D7a).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum RData<'a> {
    /// Host address (RFC 1035 §3.4.1).
    A(Ipv4Addr),
    /// IPv6 address (RFC 3596 §2.2).
    Aaaa(Ipv6Addr),
    /// Authoritative name server (RFC 1035 §3.3.11).
    Ns(Name<'a>),
    /// Canonical name (RFC 1035 §3.3.1).
    Cname(Name<'a>),
    /// Domain name pointer (RFC 1035 §3.3.12).
    Ptr(Name<'a>),
    /// Start of authority (RFC 1035 §3.3.13).
    Soa(Soa<'a>),
    /// Mail exchange (RFC 1035 §3.3.9).
    Mx(Mx<'a>),
    /// Text strings (RFC 1035 §3.3.14).
    Txt(Txt<'a>),
    /// Service locator (RFC 2782).
    Srv(Srv<'a>),
    /// Certification authority authorization (RFC 8659).
    Caa(Caa<'a>),
    /// Service binding (RFC 9460).
    Svcb(Svcb<'a>),
    /// Service binding for HTTPS (RFC 9460 §9); same format as [`RData::Svcb`].
    Https(Svcb<'a>),
    /// Delegation signer (RFC 4034 §5).
    Ds(Ds<'a>),
    /// Child copy of the delegation signer (RFC 7344 §3.1); same format as [`RData::Ds`].
    Cds(Ds<'a>),
    /// Public key of a zone (RFC 4034 §2).
    Dnskey(Dnskey<'a>),
    /// Child copy of the public key (RFC 7344 §3.2); same format as [`RData::Dnskey`].
    Cdnskey(Dnskey<'a>),
    /// Signature of an `RRset` (RFC 4034 §3).
    Rrsig(Rrsig<'a>),
    /// Next name and types of a name in a zone (RFC 4034 §4).
    Nsec(Nsec<'a>),
    /// Hashed denial of existence (RFC 5155 §3).
    Nsec3(Nsec3<'a>),
    /// Parameters of a zone's NSEC3 records (RFC 5155 §4).
    Nsec3Param(Nsec3Param<'a>),
    /// Any other type, or content invalid for its type (D9).
    Opaque(Opaque<'a>),
}

impl<'a> RData<'a> {
    /// The same data, owning its bytes.
    #[must_use]
    pub fn into_owned(self) -> RData<'static> {
        match self {
            Self::A(a) => RData::A(a),
            Self::Aaaa(a) => RData::Aaaa(a),
            Self::Ns(n) => RData::Ns(n.into_owned()),
            Self::Cname(n) => RData::Cname(n.into_owned()),
            Self::Ptr(n) => RData::Ptr(n.into_owned()),
            Self::Soa(soa) => RData::Soa(soa.into_owned()),
            Self::Mx(mx) => RData::Mx(mx.into_owned()),
            Self::Txt(txt) => RData::Txt(txt.into_owned()),
            Self::Srv(srv) => RData::Srv(srv.into_owned()),
            Self::Caa(caa) => RData::Caa(caa.into_owned()),
            Self::Svcb(svcb) => RData::Svcb(svcb.into_owned()),
            Self::Https(svcb) => RData::Https(svcb.into_owned()),
            Self::Ds(ds) => RData::Ds(ds.into_owned()),
            Self::Cds(ds) => RData::Cds(ds.into_owned()),
            Self::Dnskey(key) => RData::Dnskey(key.into_owned()),
            Self::Cdnskey(key) => RData::Cdnskey(key.into_owned()),
            Self::Rrsig(rrsig) => RData::Rrsig(rrsig.into_owned()),
            Self::Nsec(nsec) => RData::Nsec(nsec.into_owned()),
            Self::Nsec3(nsec3) => RData::Nsec3(nsec3.into_owned()),
            Self::Nsec3Param(param) => RData::Nsec3Param(param.into_owned()),
            Self::Opaque(o) => RData::Opaque(o.into_owned()),
        }
    }

    /// The record type this data belongs to.
    #[must_use]
    pub const fn rtype(&self) -> RecordType {
        match self {
            Self::A(_) => RecordType::A,
            Self::Aaaa(_) => RecordType::AAAA,
            Self::Ns(_) => RecordType::NS,
            Self::Cname(_) => RecordType::CNAME,
            Self::Ptr(_) => RecordType::PTR,
            Self::Soa(_) => RecordType::SOA,
            Self::Mx(_) => RecordType::MX,
            Self::Txt(_) => RecordType::TXT,
            Self::Srv(_) => RecordType::SRV,
            Self::Caa(_) => RecordType::CAA,
            Self::Svcb(_) => RecordType::SVCB,
            Self::Https(_) => RecordType::HTTPS,
            Self::Ds(_) => RecordType::DS,
            Self::Cds(_) => RecordType::CDS,
            Self::Dnskey(_) => RecordType::DNSKEY,
            Self::Cdnskey(_) => RecordType::CDNSKEY,
            Self::Rrsig(_) => RecordType::RRSIG,
            Self::Nsec(_) => RecordType::NSEC,
            Self::Nsec3(_) => RecordType::NSEC3,
            Self::Nsec3Param(_) => RecordType::NSEC3PARAM,
            Self::Opaque(o) => o.rtype(),
        }
    }

    /// Whether RDATA of `rtype` may hold compressed names, which receivers decompress (RFC 3597 §4): MUST for the
    /// types of RFC 1035, SHOULD for RP, AFSDB, RT, SIG, PX, NXT, NAPTR and SRV.
    ///
    /// Invalid RDATA of these types cannot be kept as opaque bytes, since pointers in it would be meaningless
    /// once the record leaves its message (D9).
    #[must_use]
    pub const fn may_hold_compressed_names(rtype: RecordType) -> bool {
        matches!(
            rtype,
            RecordType::NS
                | RecordType::CNAME
                | RecordType::SOA
                | RecordType::PTR
                | RecordType::MX
                | RecordType::SRV
        ) || Opaque::holds_names(rtype)
    }

    /// Whether the encoder compresses the names in RDATA of `rtype`: only in the types of RFC 1035 (RFC 3597 §4).
    pub(crate) const fn compressed_on_write(rtype: RecordType) -> bool {
        matches!(
            rtype,
            RecordType::NS | RecordType::CNAME | RecordType::SOA | RecordType::PTR | RecordType::MX
        )
    }

    /// Calls `f` with the uncompressed wire form of the RDATA.
    pub(crate) fn with_wire<R>(&self, f: impl FnOnce(&[u8]) -> R) -> R {
        // Most RDATA fits on the stack; larger RDATA is written again into a heap buffer 8 times larger each time,
        // so it costs a few times its size, not 64 KiB.
        let mut small = [0; 512];
        let mut w = Writer::uncompressed(&mut small);
        if self.encode(&mut w).is_ok() {
            return f(w.written());
        }
        let mut large = vec![0; 4096];
        loop {
            let mut w = Writer::uncompressed(&mut large);
            if self.encode(&mut w).is_ok() {
                return f(w.written());
            }
            assert!(
                large.len() < MAX_RDATA_LEN,
                "typed RDATA fits 65535 bytes by construction"
            );
            large.resize((large.len() * 8).min(MAX_RDATA_LEN), 0);
        }
    }

    /// Decodes the RDATA of `rtype` from `r`, a reader limited to RDLENGTH bytes; all of them must be used.
    ///
    /// # Errors
    ///
    /// [`DecodeError`] when the RDATA is shorter or longer than its fields, or a field is invalid.
    pub(crate) fn decode(rtype: RecordType, r: &mut Reader<'a>) -> Result<Self, DecodeError> {
        let data = Self::decode_fields(rtype, r).map_err(|mut e| {
            if e.kind == DecodeErrorKind::UnexpectedEnd {
                e.kind = DecodeErrorKind::RdataLength;
            }
            e
        })?;
        if r.is_empty() {
            Ok(data)
        } else {
            Err(r.error(DecodeErrorKind::RdataLength))
        }
    }

    fn decode_fields(rtype: RecordType, r: &mut Reader<'a>) -> Result<Self, DecodeError> {
        Ok(match rtype {
            RecordType::A => Self::A(rfc1035_a::decode(r)?),
            RecordType::AAAA => Self::Aaaa(rfc3596_aaaa::decode(r)?),
            RecordType::NS => Self::Ns(rfc1035_domain_name::decode(r)?),
            RecordType::CNAME => Self::Cname(rfc1035_domain_name::decode(r)?),
            RecordType::PTR => Self::Ptr(rfc1035_domain_name::decode(r)?),
            RecordType::SOA => Self::Soa(Soa::decode(r)?),
            RecordType::MX => Self::Mx(Mx::decode(r)?),
            RecordType::TXT => Self::Txt(Txt::decode(r)?),
            RecordType::SRV => Self::Srv(Srv::decode(r)?),
            RecordType::CAA => Self::Caa(Caa::decode(r)?),
            RecordType::SVCB => Self::Svcb(Svcb::decode(r)?),
            RecordType::HTTPS => Self::Https(Svcb::decode(r)?),
            RecordType::DS => Self::Ds(Ds::decode(r)?),
            RecordType::CDS => Self::Cds(Ds::decode(r)?),
            RecordType::DNSKEY => Self::Dnskey(Dnskey::decode(r)?),
            RecordType::CDNSKEY => Self::Cdnskey(Dnskey::decode(r)?),
            RecordType::RRSIG => Self::Rrsig(Rrsig::decode(r)?),
            RecordType::NSEC => Self::Nsec(Nsec::decode(r)?),
            RecordType::NSEC3 => Self::Nsec3(Nsec3::decode(r)?),
            RecordType::NSEC3PARAM => Self::Nsec3Param(Nsec3Param::decode(r)?),
            _ => Self::Opaque(Opaque::decode(rtype, r)?),
        })
    }

    /// Writes the RDATA, without its length.
    ///
    /// # Errors
    ///
    /// [`EncodeError::BufferFull`] when the buffer or the message is full.
    pub(crate) fn encode(&self, w: &mut Writer<'_>) -> Result<(), EncodeError> {
        match self {
            Self::A(a) => rfc1035_a::encode(*a, w),
            Self::Aaaa(a) => rfc3596_aaaa::encode(*a, w),
            Self::Ns(n) | Self::Cname(n) | Self::Ptr(n) => rfc1035_domain_name::encode(n, w),
            Self::Soa(soa) => soa.encode(w),
            Self::Mx(mx) => mx.encode(w),
            Self::Txt(txt) => txt.encode(w),
            Self::Srv(srv) => srv.encode(w),
            Self::Caa(caa) => caa.encode(w),
            Self::Svcb(svcb) | Self::Https(svcb) => svcb.encode(w),
            Self::Ds(ds) | Self::Cds(ds) => ds.encode(w),
            Self::Dnskey(key) | Self::Cdnskey(key) => key.encode(w),
            Self::Rrsig(rrsig) => rrsig.encode(w),
            Self::Nsec(nsec) => nsec.encode(w),
            Self::Nsec3(nsec3) => nsec3.encode(w),
            Self::Nsec3Param(param) => param.encode(w),
            Self::Opaque(o) => o.encode(w),
        }
    }
}

impl RData<'static> {
    /// Reads the RDATA of `rtype` from the rest of an entry: its own text form, or `\# length hex` for any type
    /// (RFC 3597 §5), checked as its type, into its wire form. With the RDATA, why `\#` bytes invalid for
    /// their type were kept opaque (D9).
    pub(crate) fn from_text(
        rtype: RecordType,
        f: &mut Fields<'_, '_>,
    ) -> Result<(WireRdata<'static>, Option<DecodeError>), TextError> {
        if f.peek()?.is_some_and(|t| t.raw == br"\#") {
            return Self::from_generic(rtype, f);
        }
        let data = match rtype {
            RecordType::A => Self::A(f.parse("IPv4 address")?),
            RecordType::AAAA => Self::Aaaa(f.parse("IPv6 address")?),
            RecordType::NS => Self::Ns(f.name("NS name")?),
            RecordType::CNAME => Self::Cname(f.name("CNAME target")?),
            RecordType::PTR => Self::Ptr(f.name("PTR name")?),
            RecordType::SOA => Self::Soa(Soa::from_text(f)?),
            RecordType::MX => Self::Mx(Mx::from_text(f)?),
            RecordType::TXT => Self::Txt(Txt::from_text(f)?),
            RecordType::SRV => Self::Srv(Srv::from_text(f)?),
            RecordType::CAA => Self::Caa(Caa::from_text(f)?),
            RecordType::SVCB => Self::Svcb(Svcb::from_text(f)?),
            RecordType::HTTPS => Self::Https(Svcb::from_text(f)?),
            RecordType::DS => Self::Ds(Ds::from_text(f)?),
            RecordType::CDS => Self::Cds(Ds::from_text(f)?),
            RecordType::DNSKEY => Self::Dnskey(Dnskey::from_text(f)?),
            RecordType::CDNSKEY => Self::Cdnskey(Dnskey::from_text(f)?),
            RecordType::RRSIG => Self::Rrsig(Rrsig::from_text(f)?),
            RecordType::NSEC => Self::Nsec(Nsec::from_text(f)?),
            RecordType::NSEC3 => Self::Nsec3(Nsec3::from_text(f)?),
            RecordType::NSEC3PARAM => Self::Nsec3Param(Nsec3Param::from_text(f)?),
            _ => {
                if let Some(opaque) = Opaque::from_text(rtype, f) {
                    Self::Opaque(opaque?)
                } else {
                    let kind = TextErrorKind::NeedsGeneric;
                    let at = f.peek()?;
                    return Err(at.map_or_else(|| f.end_error(kind), |t| t.error(kind)));
                }
            }
        };
        Ok((WireRdata::new(&data), None))
    }

    /// The generic bytes are the wire form, once checked.
    fn from_generic(
        rtype: RecordType,
        f: &mut Fields<'_, '_>,
    ) -> Result<(WireRdata<'static>, Option<DecodeError>), TextError> {
        let marker = f.next("\\#")?;
        let declared: usize = f.number("RDATA length")?;
        if declared > MAX_RDATA_LEN {
            return Err(marker.error(TextErrorKind::Invalid("\\# length, over 65535")));
        }
        let mut data = Vec::with_capacity(declared);
        while let Some(token) = f.next_opt()? {
            encoding::decode_hex(token.raw, &mut data)
                .ok_or(token.error(TextErrorKind::Invalid("hex RDATA")))?;
        }
        if data.len() != declared {
            return Err(marker.error(TextErrorKind::GenericLength {
                declared,
                actual: data.len(),
            }));
        }
        let invalid = |kind| marker.error(TextErrorKind::Rdata(kind));
        // Same rule as the wire (D9): RDATA invalid for its type is kept opaque, unless the type holds names.
        let (decoded, why) =
            decode_rdata(rtype, Reader::new(&data)).map_err(|e| invalid(e.kind))?;
        if Self::may_hold_compressed_names(rtype) {
            // A name read here may hold a pointer, which means nothing outside a message: refuse what does not
            // write back to the same bytes.
            let mut buf = vec![0; data.len()];
            let mut w = Writer::uncompressed(&mut buf);
            if decoded.encode(&mut w).is_err() || w.written() != data.as_slice() {
                return Err(invalid(DecodeErrorKind::Invalid(
                    "RDATA that does not write back the same",
                )));
            }
        }
        Ok((WireRdata::from_checked(rtype, data.into()), why))
    }
}

impl RData<'_> {
    /// The RDATA in the generic form of RFC 3597 §5, `\# length hex`, whatever its type.
    #[must_use]
    pub const fn generic(&self) -> Generic<'_> {
        Generic(self)
    }
}

/// The RDATA in its text form (RFC 1035 §5.1 and the RFC of its type); types without one in the generic form of
/// RFC 3597 §5.
impl fmt::Display for RData<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::A(a) => write!(f, "{a}"),
            Self::Aaaa(a) => write!(f, "{a}"),
            Self::Ns(n) | Self::Cname(n) | Self::Ptr(n) => write!(f, "{n}"),
            Self::Soa(soa) => write!(f, "{soa}"),
            Self::Mx(mx) => write!(f, "{mx}"),
            Self::Txt(txt) => write!(f, "{txt}"),
            Self::Srv(srv) => write!(f, "{srv}"),
            Self::Caa(caa) => write!(f, "{caa}"),
            Self::Svcb(svcb) | Self::Https(svcb) => write!(f, "{svcb}"),
            Self::Ds(ds) | Self::Cds(ds) => write!(f, "{ds}"),
            Self::Dnskey(key) | Self::Cdnskey(key) => write!(f, "{key}"),
            Self::Rrsig(rrsig) => write!(f, "{rrsig}"),
            Self::Nsec(nsec) => write!(f, "{nsec}"),
            Self::Nsec3(nsec3) => write!(f, "{nsec3}"),
            Self::Nsec3Param(param) => write!(f, "{param}"),
            Self::Opaque(o) => write!(f, "{o}"),
        }
    }
}

/// RDATA written in the generic form of RFC 3597 §5; from [`RData::generic`].
#[derive(Debug, Clone, Copy)]
pub struct Generic<'r>(&'r RData<'r>);

impl fmt::Display for Generic<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.with_wire(|wire| text::write_generic(f, wire))
    }
}
