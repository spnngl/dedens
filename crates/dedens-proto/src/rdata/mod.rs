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
mod rfc8659_caa;
mod rfc9460_svcb;

use core::net::{Ipv4Addr, Ipv6Addr};

pub use rfc1035_mx::Mx;
pub use rfc1035_soa::Soa;
pub use rfc1035_txt::{CharacterString, CharacterStringTooLong, EmptyTxt, Txt};
pub use rfc2782_srv::Srv;
pub use rfc3597_opaque::Opaque;
pub use rfc8659_caa::{Caa, InvalidCaaTag};
pub use rfc9460_svcb::{SvcParam, SvcParamKey, SvcParams, SvcParamsError, Svcb};

use crate::codes::RecordType;
use crate::error::{DecodeError, DecodeErrorKind, EncodeError};
use crate::name::Name;
use crate::wire::{Reader, Writer};

/// The data of a resource record.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum RData {
    /// Host address (RFC 1035 §3.4.1).
    A(Ipv4Addr),
    /// IPv6 address (RFC 3596 §2.2).
    Aaaa(Ipv6Addr),
    /// Authoritative name server (RFC 1035 §3.3.11).
    Ns(Name),
    /// Canonical name (RFC 1035 §3.3.1).
    Cname(Name),
    /// Domain name pointer (RFC 1035 §3.3.12).
    Ptr(Name),
    /// Start of authority (RFC 1035 §3.3.13).
    Soa(Soa),
    /// Mail exchange (RFC 1035 §3.3.9).
    Mx(Mx),
    /// Text strings (RFC 1035 §3.3.14).
    Txt(Txt),
    /// Service locator (RFC 2782).
    Srv(Srv),
    /// Certification authority authorization (RFC 8659).
    Caa(Caa),
    /// Service binding (RFC 9460).
    Svcb(Svcb),
    /// Service binding for HTTPS (RFC 9460 §9); same format as [`RData::Svcb`].
    Https(Svcb),
    /// Any other type, or content invalid for its type (D9).
    Opaque(Opaque),
}

impl RData {
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
            Self::Opaque(o) => o.rtype,
        }
    }

    /// Whether RDATA of `rtype` may hold compressed names (RFC 3597 §4: only the types of RFC 1035).
    ///
    /// Invalid RDATA of these types cannot be kept as opaque bytes, since pointers in it would be meaningless
    /// once the record leaves its message (D9).
    #[must_use]
    pub const fn has_compressible_names(rtype: RecordType) -> bool {
        matches!(
            rtype,
            RecordType::NS | RecordType::CNAME | RecordType::SOA | RecordType::PTR | RecordType::MX
        )
    }

    /// Decodes the RDATA of `rtype` from `r`, a reader limited to RDLENGTH bytes; all of them must be used.
    ///
    /// # Errors
    ///
    /// [`DecodeError`] when the RDATA is shorter or longer than its fields, or a field is invalid.
    pub(crate) fn decode(rtype: RecordType, r: &mut Reader<'_>) -> Result<Self, DecodeError> {
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

    fn decode_fields(rtype: RecordType, r: &mut Reader<'_>) -> Result<Self, DecodeError> {
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
            _ => Self::Opaque(Opaque {
                rtype,
                data: r.rest().into(),
            }),
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
            Self::Opaque(o) => o.encode(w),
        }
    }
}
