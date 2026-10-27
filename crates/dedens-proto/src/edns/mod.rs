//! EDNS(0): the OPT pseudo-record and its options (RFC 6891).
//!
//! A [`Message`](crate::Message) holds the OPT record as an [`Edns`] value, not among its records (D8). One file per
//! typed option (D12); every other option, and an option whose content is invalid, stays [`EdnsOption::Unknown`].

mod rfc5001_nsid;
mod rfc7828_keepalive;
mod rfc7830_padding;
mod rfc7871_client_subnet;
mod rfc7873_cookie;
mod rfc8914_ede;

pub use rfc7871_client_subnet::{ClientSubnet, InvalidClientSubnet};
pub use rfc7873_cookie::{Cookie, InvalidServerCookie};
pub use rfc8914_ede::{ExtendedError, InfoCode};

use crate::codes::{RecordType, code_type};
use crate::error::{DecodeError, DecodeErrorKind, EncodeError};
use crate::wire::{Reader, Writer};

/// The UDP payload size to advertise by default: 1232 bytes avoids IP fragmentation (DNS Flag Day 2020, D10).
pub const DEFAULT_UDP_PAYLOAD: u16 = 1232;

/// Root owner, type, CLASS, TTL and RDLENGTH of an OPT record.
const OPT_FIXED_LEN: usize = 11;

/// Code and length of an option.
const OPTION_HEADER_LEN: usize = 4;

/// Mask of the 15 flag bits after DO in the OPT TTL (RFC 6891 §6.1.3).
const Z_MASK: u16 = 0x7FFF;

code_type! {
    /// EDNS option code (RFC 6891 §6.1.2, IANA registry).
    OptionCode(u16), "OPTION";
    /// Name server identifier (RFC 5001).
    NSID = 3, "NSID";
    /// Client subnet (RFC 7871).
    CLIENT_SUBNET = 8, "CLIENT-SUBNET";
    /// Cookie (RFC 7873).
    COOKIE = 10, "COOKIE";
    /// TCP keepalive (RFC 7828).
    KEEPALIVE = 11, "TCP-KEEPALIVE";
    /// Padding (RFC 7830).
    PADDING = 12, "PADDING";
    /// Extended DNS Error (RFC 8914).
    EDE = 15, "EDE";
}

/// One option of an OPT record.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum EdnsOption {
    /// Name server identifier: empty in a query (RFC 5001).
    Nsid(Box<[u8]>),
    /// Client subnet (RFC 7871).
    ClientSubnet(ClientSubnet),
    /// Cookie (RFC 7873).
    Cookie(Cookie),
    /// TCP keepalive: the idle timeout in 100 ms units, absent in a query (RFC 7828).
    Keepalive(Option<u16>),
    /// Padding of this many zero bytes (RFC 7830).
    Padding(u16),
    /// Extended DNS Error (RFC 8914).
    Ede(ExtendedError),
    /// An option without a typed variant, or whose content is invalid for its code (D9).
    Unknown {
        /// The option code.
        code: OptionCode,
        /// The option data as received.
        data: Box<[u8]>,
    },
}

impl EdnsOption {
    /// The option code.
    #[must_use]
    pub const fn code(&self) -> OptionCode {
        match self {
            Self::Nsid(_) => OptionCode::NSID,
            Self::ClientSubnet(_) => OptionCode::CLIENT_SUBNET,
            Self::Cookie(_) => OptionCode::COOKIE,
            Self::Keepalive(_) => OptionCode::KEEPALIVE,
            Self::Padding(_) => OptionCode::PADDING,
            Self::Ede(_) => OptionCode::EDE,
            Self::Unknown { code, .. } => *code,
        }
    }

    /// The length of the option data on the wire.
    fn data_len(&self) -> usize {
        match self {
            Self::Nsid(id) => id.len(),
            Self::ClientSubnet(subnet) => 4 + usize::from(subnet.source_prefix()).div_ceil(8),
            Self::Cookie(cookie) => 8 + cookie.server().map_or(0, <[u8]>::len),
            Self::Keepalive(timeout) => 2 * usize::from(timeout.is_some()),
            Self::Padding(len) => usize::from(*len),
            Self::Ede(error) => 2 + error.text.len(),
            Self::Unknown { data, .. } => data.len(),
        }
    }

    /// Parses the data of option `code`; all of `data` must be used.
    fn decode_typed(code: OptionCode, data: &mut Reader<'_>) -> Result<Self, DecodeError> {
        let option = match code {
            OptionCode::NSID => Self::Nsid(rfc5001_nsid::decode(data)),
            OptionCode::CLIENT_SUBNET => Self::ClientSubnet(ClientSubnet::decode(data)?),
            OptionCode::COOKIE => Self::Cookie(Cookie::decode(data)?),
            OptionCode::KEEPALIVE => Self::Keepalive(rfc7828_keepalive::decode(data)?),
            OptionCode::PADDING => Self::Padding(rfc7830_padding::decode(data)),
            OptionCode::EDE => Self::Ede(ExtendedError::decode(data)?),
            _ => Self::Unknown {
                code,
                data: data.rest().into(),
            },
        };
        if data.is_empty() {
            Ok(option)
        } else {
            Err(data.error(DecodeErrorKind::RdataLength))
        }
    }

    fn encode(&self, w: &mut Writer<'_>) -> Result<(), EncodeError> {
        w.put_u16(self.code().0)?;
        let at = w.reserve_u16()?;
        match self {
            Self::Nsid(id) => w.put_bytes(id)?,
            Self::ClientSubnet(subnet) => subnet.encode(w)?,
            Self::Cookie(cookie) => cookie.encode(w)?,
            Self::Keepalive(timeout) => rfc7828_keepalive::encode(*timeout, w)?,
            Self::Padding(len) => rfc7830_padding::encode(*len, w)?,
            Self::Ede(error) => error.encode(w)?,
            Self::Unknown { data, .. } => w.put_bytes(data)?,
        }
        let len = u16::try_from(w.len() - at - 2).map_err(|_| EncodeError::BufferFull)?;
        w.patch_u16(at, len);
        Ok(())
    }
}

/// An option that was kept as [`EdnsOption::Unknown`] although its code is typed, because its content is
/// invalid (D9).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InvalidOption {
    /// The option code.
    pub code: OptionCode,
    /// Why the content is invalid.
    pub error: DecodeError,
}

/// The content of an OPT record (RFC 6891 §6.1): what the sender supports and the extended header bits.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Edns {
    /// Largest UDP message the sender reassembles, in bytes (the OPT CLASS). Values under 512 mean 512
    /// (RFC 6891 §6.2.3); that is left to the user of this field.
    pub udp_payload: u16,
    /// Upper 8 bits of the 12-bit response code (RFC 6891 §6.1.3); see `Message::rcode`.
    pub ext_rcode: u8,
    /// EDNS version, 0 (RFC 6891 §6.1.3); a responder that does not know it answers BADVERS.
    pub version: u8,
    /// DNSSEC OK (RFC 3225).
    pub dnssec_ok: bool,
    /// The 15 remaining flag bits, which must be zero when sent and ignored when received.
    pub z: u16,
    /// The options, in order.
    pub options: Vec<EdnsOption>,
}

impl Default for Edns {
    fn default() -> Self {
        Self {
            udp_payload: DEFAULT_UDP_PAYLOAD,
            ext_rcode: 0,
            version: 0,
            dnssec_ok: false,
            z: 0,
            options: Vec::new(),
        }
    }
}

impl Edns {
    /// Builds the value from an OPT record's CLASS, TTL and RDATA; an option with invalid content is kept
    /// unknown and listed in the second element.
    ///
    /// # Errors
    ///
    /// [`DecodeError`] when the option framing is broken: an option cut short or running past the RDATA.
    pub(crate) fn from_opt(
        class: u16,
        ttl: u32,
        mut rdata: Reader<'_>,
    ) -> Result<(Self, Vec<InvalidOption>), DecodeError> {
        let [ext_rcode, version, flags_hi, flags_lo] = ttl.to_be_bytes();
        let flags = u16::from_be_bytes([flags_hi, flags_lo]);
        let mut options = Vec::new();
        let mut invalid = Vec::new();
        while !rdata.is_empty() {
            let code = OptionCode(rdata.u16().map_err(rdlength)?);
            let len = usize::from(rdata.u16().map_err(rdlength)?);
            let mut data = rdata.sub(len).map_err(rdlength)?;
            let raw = data;
            match EdnsOption::decode_typed(code, &mut data) {
                Ok(option) => options.push(option),
                Err(error) => {
                    invalid.push(InvalidOption { code, error });
                    let mut raw = raw;
                    options.push(EdnsOption::Unknown {
                        code,
                        data: raw.rest().into(),
                    });
                }
            }
        }
        let edns = Self {
            udp_payload: class,
            ext_rcode,
            version,
            dnssec_ok: flags & !Z_MASK != 0,
            z: flags & Z_MASK,
            options,
        };
        Ok((edns, invalid))
    }

    /// The length of the OPT record on the wire, which truncation keeps room for (RFC 6891 §7).
    #[must_use]
    pub fn wire_len(&self) -> usize {
        OPT_FIXED_LEN
            + self
                .options
                .iter()
                .map(|o| OPTION_HEADER_LEN + o.data_len())
                .sum::<usize>()
    }

    /// Writes the OPT record: root owner, type OPT, CLASS and TTL from the fields (RFC 6891 §6.1.2).
    ///
    /// # Errors
    ///
    /// [`EncodeError::BufferFull`] when it does not fit.
    pub(crate) fn encode(&self, w: &mut Writer<'_>) -> Result<(), EncodeError> {
        let flags = (u16::from(self.dnssec_ok) << 15) | (self.z & Z_MASK);
        let [flags_hi, flags_lo] = flags.to_be_bytes();
        w.put_u8(0)?;
        w.put_u16(RecordType::OPT.0)?;
        w.put_u16(self.udp_payload)?;
        w.put_bytes(&[self.ext_rcode, self.version, flags_hi, flags_lo])?;
        let at = w.reserve_u16()?;
        for option in &self.options {
            option.encode(w)?;
        }
        let len = u16::try_from(w.len() - at - 2).map_err(|_| EncodeError::BufferFull)?;
        w.patch_u16(at, len);
        Ok(())
    }
}

/// An OPT record whose options run past its RDATA is a RDATA length error.
fn rdlength(mut e: DecodeError) -> DecodeError {
    e.kind = DecodeErrorKind::RdataLength;
    e
}
