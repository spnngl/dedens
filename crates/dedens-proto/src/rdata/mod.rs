//! RDATA of the supported record types (D11); every other type is kept [`Opaque`] (RFC 3597).
//!
//! One file per type, or per group of types sharing a format, named after the type (D159); the codecs of A, AAAA
//! and the one-name types are modules beside the table.

mod caa;
mod dnskey;
mod ds;
mod mx;
mod nsec;
mod nsec3;
mod opaque;
mod rrsig;
mod soa;
mod srv;
mod svcb;
mod txt;

use core::fmt;
use core::net::{Ipv4Addr, Ipv6Addr};

pub use caa::{Caa, CaaError};
pub use dnskey::{Dnskey, DnskeyError};
pub use ds::{Ds, DsError};
pub use mx::Mx;
pub use nsec::{Nsec, TypeBitmap, TypeBitmapError};
pub use nsec3::{Nsec3, Nsec3Error, Nsec3Param};
pub use opaque::Opaque;
pub use rrsig::{Rrsig, RrsigError};
pub use soa::Soa;
pub use srv::Srv;
pub use svcb::{Params, SvcParam, SvcParamKey, SvcParams, SvcParamsError, Svcb};
pub use txt::{CharacterStrings, Txt, TxtError};

use crate::codes::RecordType;
use crate::error::{DecodeError, DecodeErrorKind, EncodeError};
use crate::name::Name;
use crate::record::{WireRdata, decode_rdata};
use crate::text::{self, Fields, TextError, TextErrorKind, encoding};
use crate::wire::{Reader, Writer};

/// The most bytes an RDATA holds: RDLENGTH is 16 bits (RFC 1035 §3.2.1).
pub(crate) const MAX_RDATA_LEN: usize = 65535;

/// One line a typed RDATA, `Variant(payload) = RecordType constant, codec`, builds [`RData`] and every dispatch on it
/// (D139), so a type cannot be in one and missing from another. The codec is the payload type, or for A, AAAA, NS,
/// CNAME and PTR the module of the type: either gives `decode`, `encode`, `from_text` and `into_owned`. Types
/// outside the table are [`Opaque`].
macro_rules! rdata_types {
    ($($(#[$meta:meta])* $variant:ident($ty:ty) = $code:ident, $codec:ident;)*) => {
        /// The data of a resource record (RFC 1035 §3.2.1), borrowed from the message it was decoded from or owned
        /// (D7a).
        #[derive(Debug, Clone, PartialEq, Eq, Hash)]
        #[non_exhaustive]
        pub enum RData<'a> {
            $($(#[$meta])* $variant($ty),)*
            /// Any other type, or content invalid for its type (D9).
            Opaque(Opaque<'a>),
        }

        impl<'a> RData<'a> {
            /// The same data, owning its bytes.
            #[must_use]
            pub fn into_owned(self) -> RData<'static> {
                match self {
                    $(Self::$variant(x) => RData::$variant($codec::into_owned(x)),)*
                    Self::Opaque(o) => RData::Opaque(o.into_owned()),
                }
            }

            /// The record type this data belongs to.
            #[must_use]
            pub const fn rtype(&self) -> RecordType {
                match self {
                    $(Self::$variant(_) => RecordType::$code,)*
                    Self::Opaque(o) => o.rtype(),
                }
            }

            fn decode_fields(rtype: RecordType, r: &mut Reader<'a>) -> Result<Self, DecodeError> {
                match rtype {
                    $(RecordType::$code => $codec::decode(r).map(Self::$variant),)*
                    _ => Opaque::decode(rtype, r).map(Self::Opaque),
                }
            }

            /// Writes the RDATA, without its length.
            ///
            /// # Errors
            ///
            /// [`EncodeError::BufferFull`] when the buffer or the message is full.
            pub(crate) fn encode(&self, w: &mut Writer<'_>) -> Result<(), EncodeError> {
                match self {
                    $(Self::$variant(x) => $codec::encode(x, w),)*
                    Self::Opaque(o) => o.encode(w),
                }
            }
        }

        impl RData<'static> {
            /// Reads the RDATA of a type of the table from the rest of an entry, or `None` for any other.
            fn typed_from_text(
                rtype: RecordType,
                f: &mut Fields<'_, '_>,
            ) -> Result<Option<Self>, TextError> {
                Ok(Some(match rtype {
                    $(RecordType::$code => Self::$variant($codec::from_text(f)?),)*
                    _ => return Ok(None),
                }))
            }
        }

        /// The RDATA in its text form (RFC 1035 §5.1 and the RFC of its type); types without one in the generic
        /// form of RFC 3597 §5.
        impl fmt::Display for RData<'_> {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                match self {
                    $(Self::$variant(x) => write!(f, "{x}"),)*
                    Self::Opaque(o) => write!(f, "{o}"),
                }
            }
        }
    };
}

rdata_types! {
    /// Host address (RFC 1035 §3.4.1).
    A(Ipv4Addr) = A, a;
    /// IPv6 address (RFC 3596 §2.2).
    Aaaa(Ipv6Addr) = AAAA, aaaa;
    /// Authoritative name server (RFC 1035 §3.3.11).
    Ns(Name<'a>) = NS, domain_name;
    /// Canonical name (RFC 1035 §3.3.1).
    Cname(Name<'a>) = CNAME, domain_name;
    /// Domain name pointer (RFC 1035 §3.3.12).
    Ptr(Name<'a>) = PTR, domain_name;
    /// Start of authority (RFC 1035 §3.3.13).
    Soa(Soa<'a>) = SOA, Soa;
    /// Mail exchange (RFC 1035 §3.3.9).
    Mx(Mx<'a>) = MX, Mx;
    /// Text strings (RFC 1035 §3.3.14).
    Txt(Txt<'a>) = TXT, Txt;
    /// Service locator (RFC 2782).
    Srv(Srv<'a>) = SRV, Srv;
    /// Certification authority authorization (RFC 8659).
    Caa(Caa<'a>) = CAA, Caa;
    /// Service binding (RFC 9460).
    Svcb(Svcb<'a>) = SVCB, Svcb;
    /// Service binding for HTTPS (RFC 9460 §9); same format as [`RData::Svcb`].
    Https(Svcb<'a>) = HTTPS, Svcb;
    /// Delegation signer (RFC 4034 §5).
    Ds(Ds<'a>) = DS, Ds;
    /// Child copy of the delegation signer (RFC 7344 §3.1); same format as [`RData::Ds`].
    Cds(Ds<'a>) = CDS, Ds;
    /// Public key of a zone (RFC 4034 §2).
    Dnskey(Dnskey<'a>) = DNSKEY, Dnskey;
    /// Child copy of the public key (RFC 7344 §3.2); same format as [`RData::Dnskey`].
    Cdnskey(Dnskey<'a>) = CDNSKEY, Dnskey;
    /// Signature of an `RRset` (RFC 4034 §3).
    Rrsig(Rrsig<'a>) = RRSIG, Rrsig;
    /// Next name and types of a name in a zone (RFC 4034 §4).
    Nsec(Nsec<'a>) = NSEC, Nsec;
    /// Hashed denial of existence (RFC 5155 §3).
    Nsec3(Nsec3<'a>) = NSEC3, Nsec3;
    /// Parameters of a zone's NSEC3 records (RFC 5155 §4).
    Nsec3Param(Nsec3Param<'a>) = NSEC3PARAM, Nsec3Param;
}

/// A: an IPv4 address (RFC 1035 §3.4.1).
mod a {
    use super::{DecodeError, EncodeError, Fields, Ipv4Addr, Reader, TextError, Writer};

    pub(super) fn decode(r: &mut Reader<'_>) -> Result<Ipv4Addr, DecodeError> {
        Ok(Ipv4Addr::from(r.array::<4>()?))
    }

    #[expect(
        clippy::trivially_copy_pass_by_ref,
        reason = "the signature of every codec in the table (D139)"
    )]
    pub(super) fn encode(addr: &Ipv4Addr, w: &mut Writer<'_>) -> Result<(), EncodeError> {
        w.put_bytes(&addr.octets())
    }

    pub(super) fn from_text(f: &mut Fields<'_, '_>) -> Result<Ipv4Addr, TextError> {
        f.parse("IPv4 address")
    }

    pub(super) const fn into_owned(addr: Ipv4Addr) -> Ipv4Addr {
        addr
    }
}

/// AAAA: an IPv6 address (RFC 3596 §2.2).
mod aaaa {
    use super::{DecodeError, EncodeError, Fields, Ipv6Addr, Reader, TextError, Writer};

    pub(super) fn decode(r: &mut Reader<'_>) -> Result<Ipv6Addr, DecodeError> {
        Ok(Ipv6Addr::from(r.array::<16>()?))
    }

    pub(super) fn encode(addr: &Ipv6Addr, w: &mut Writer<'_>) -> Result<(), EncodeError> {
        w.put_bytes(&addr.octets())
    }

    pub(super) fn from_text(f: &mut Fields<'_, '_>) -> Result<Ipv6Addr, TextError> {
        f.parse("IPv6 address")
    }

    pub(super) const fn into_owned(addr: Ipv6Addr) -> Ipv6Addr {
        addr
    }
}

/// NS, CNAME and PTR: RDATA that is one domain name (RFC 1035 §3.3.1, §3.3.11, §3.3.12).
///
/// The name may be compressed (RFC 3597 §4).
mod domain_name {
    use super::{DecodeError, EncodeError, Fields, Name, Reader, TextError, Writer};

    pub(super) fn decode<'a>(r: &mut Reader<'a>) -> Result<Name<'a>, DecodeError> {
        Name::decode(r)
    }

    pub(super) fn encode(name: &Name<'_>, w: &mut Writer<'_>) -> Result<(), EncodeError> {
        w.put_name_compressed(name)
    }

    pub(super) fn from_text(f: &mut Fields<'_, '_>) -> Result<Name<'static>, TextError> {
        f.name("domain name")
    }

    pub(super) fn into_owned(name: Name<'_>) -> Name<'static> {
        name.into_owned()
    }
}

impl<'a> RData<'a> {
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
    ///
    /// Every typed RDATA fits [`MAX_RDATA_LEN`] bytes by construction (D125), so encoding into the largest buffer
    /// does not fail. If it does, whatever the error (a length, or an invariant reported as `BufferFull`), a type
    /// misses its bound: debug builds assert, release builds hand `f` no bytes.
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
            if large.len() == MAX_RDATA_LEN {
                debug_assert!(
                    false,
                    "typed RDATA does not encode in 65535 bytes: a type misses its bound (D125)"
                );
                return f(&[]);
            }
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
        let data = if let Some(data) = Self::typed_from_text(rtype, f)? {
            data
        } else if let Some(opaque) = Opaque::from_text(rtype, f) {
            Self::Opaque(opaque?)
        } else {
            let kind = TextErrorKind::NeedsGeneric;
            let at = f.peek()?;
            return Err(at.map_or_else(|| f.end_error(kind), |t| t.error(kind)));
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

/// RDATA written in the generic form of RFC 3597 §5; from [`RData::generic`].
#[derive(Debug, Clone, Copy)]
pub struct Generic<'r>(&'r RData<'r>);

impl fmt::Display for Generic<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.with_wire(|wire| text::write_generic(f, wire))
    }
}
