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

use std::borrow::Cow;

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

/// The 16 flag bits of an OPT record, the low half of its TTL (RFC 6891 §6.1.3).
///
/// Only DO is defined; the other 15 bits (Z) must be zero when sent and are ignored when received, but they are
/// kept so a message re-encodes as received.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
pub struct EdnsFlags(u16);

impl EdnsFlags {
    /// DNSSEC OK (RFC 3225 §3).
    pub const DO: Self = Self(0x8000);

    /// The flags of a wire value.
    #[must_use]
    pub const fn from_bits(bits: u16) -> Self {
        Self(bits)
    }

    /// The wire value.
    #[must_use]
    pub const fn bits(self) -> u16 {
        self.0
    }

    /// Whether every bit of `other` is set.
    #[must_use]
    pub const fn contains(self, other: Self) -> bool {
        self.0 & other.0 == other.0
    }

    /// These flags with `other` set.
    #[must_use]
    pub const fn with(self, other: Self) -> Self {
        Self(self.0 | other.0)
    }

    /// These flags with `other` cleared.
    #[must_use]
    pub const fn without(self, other: Self) -> Self {
        Self(self.0 & !other.0)
    }
}

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
pub enum EdnsOption<'a> {
    /// Name server identifier: empty in a query (RFC 5001).
    Nsid(Cow<'a, [u8]>),
    /// Client subnet (RFC 7871).
    ClientSubnet(ClientSubnet),
    /// Cookie (RFC 7873).
    Cookie(Cookie),
    /// TCP keepalive: the idle timeout in 100 ms units, absent in a query (RFC 7828).
    Keepalive(Option<u16>),
    /// Padding of this many zero bytes (RFC 7830).
    Padding(u16),
    /// Extended DNS Error (RFC 8914).
    Ede(ExtendedError<'a>),
    /// An option without a typed variant, or whose content is invalid for its code (D9).
    Unknown {
        /// The option code.
        code: OptionCode,
        /// The option data as received.
        data: Cow<'a, [u8]>,
    },
}

impl<'a> EdnsOption<'a> {
    /// The same option, owning its bytes.
    #[must_use]
    pub fn into_owned(self) -> EdnsOption<'static> {
        match self {
            Self::Nsid(id) => EdnsOption::Nsid(Cow::Owned(id.into_owned())),
            Self::ClientSubnet(subnet) => EdnsOption::ClientSubnet(subnet),
            Self::Cookie(cookie) => EdnsOption::Cookie(cookie),
            Self::Keepalive(timeout) => EdnsOption::Keepalive(timeout),
            Self::Padding(len) => EdnsOption::Padding(len),
            Self::Ede(error) => EdnsOption::Ede(error.into_owned()),
            Self::Unknown { code, data } => EdnsOption::Unknown {
                code,
                data: Cow::Owned(data.into_owned()),
            },
        }
    }

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
    fn decode_typed(code: OptionCode, data: &mut Reader<'a>) -> Result<Self, DecodeError> {
        let option = match code {
            OptionCode::NSID => Self::Nsid(rfc5001_nsid::decode(data)),
            OptionCode::CLIENT_SUBNET => Self::ClientSubnet(ClientSubnet::decode(data)?),
            OptionCode::COOKIE => Self::Cookie(Cookie::decode(data)?),
            OptionCode::KEEPALIVE => Self::Keepalive(rfc7828_keepalive::decode(data)?),
            OptionCode::PADDING => Self::Padding(rfc7830_padding::decode(data)),
            OptionCode::EDE => Self::Ede(ExtendedError::decode(data)?),
            _ => Self::Unknown {
                code,
                data: Cow::Borrowed(data.rest()),
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
pub struct Edns<'a> {
    /// Largest UDP message the sender reassembles, in bytes (the OPT CLASS). Values under 512 mean 512
    /// (RFC 6891 §6.2.3); that is left to the user of this field.
    pub udp_payload: u16,
    /// Upper 8 bits of the 12-bit response code (RFC 6891 §6.1.3); see `Message::rcode`.
    pub ext_rcode: u8,
    /// EDNS version, 0 (RFC 6891 §6.1.3); a responder that does not know it answers BADVERS.
    pub version: u8,
    /// The flags: DO and the reserved bits.
    pub flags: EdnsFlags,
    /// The options, in order.
    pub options: Vec<EdnsOption<'a>>,
}

impl Default for Edns<'_> {
    fn default() -> Self {
        Self {
            udp_payload: DEFAULT_UDP_PAYLOAD,
            ext_rcode: 0,
            version: 0,
            flags: EdnsFlags::default(),
            options: Vec::new(),
        }
    }
}

impl<'a> Edns<'a> {
    /// The same EDNS data, owning its bytes.
    #[must_use]
    pub fn into_owned(self) -> Edns<'static> {
        Edns {
            udp_payload: self.udp_payload,
            ext_rcode: self.ext_rcode,
            version: self.version,
            flags: self.flags,
            options: self
                .options
                .into_iter()
                .map(EdnsOption::into_owned)
                .collect(),
        }
    }

    /// Builds the value from an OPT record's CLASS, TTL and RDATA; an option with invalid content is kept
    /// unknown and listed in the second element.
    ///
    /// # Errors
    ///
    /// [`DecodeError`] when the option framing is broken: an option cut short or running past the RDATA.
    pub(crate) fn from_opt(
        class: u16,
        ttl: u32,
        rdata: Reader<'a>,
    ) -> Result<(Self, Vec<InvalidOption>), DecodeError> {
        let [ext_rcode, version, flags_hi, flags_lo] = ttl.to_be_bytes();
        let flags = u16::from_be_bytes([flags_hi, flags_lo]);
        let mut options = Vec::new();
        let mut invalid = Vec::new();
        read_options(rdata, |option, error| {
            options.push(option);
            invalid.extend(error);
        })?;
        let edns = Self {
            udp_payload: class,
            ext_rcode,
            version,
            flags: EdnsFlags(flags),
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
        let [flags_hi, flags_lo] = self.flags.0.to_be_bytes();
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
/// Reads the options of an OPT record's RDATA, handing each to `each` with, when its content is invalid for its
/// code, why it is kept as [`EdnsOption::Unknown`].
///
/// # Errors
///
/// [`DecodeError`] when the option framing is broken: an option cut short or running past the RDATA.
pub(crate) fn read_options<'a>(
    mut rdata: Reader<'a>,
    mut each: impl FnMut(EdnsOption<'a>, Option<InvalidOption>),
) -> Result<(), DecodeError> {
    while !rdata.is_empty() {
        let code = OptionCode(rdata.u16().map_err(rdlength)?);
        let len = usize::from(rdata.u16().map_err(rdlength)?);
        let mut data = rdata.sub(len).map_err(rdlength)?;
        let mut raw = data;
        match EdnsOption::decode_typed(code, &mut data) {
            Ok(option) => each(option, None),
            Err(error) => each(
                EdnsOption::Unknown {
                    code,
                    data: Cow::Borrowed(raw.rest()),
                },
                Some(InvalidOption { code, error }),
            ),
        }
    }
    Ok(())
}

fn rdlength(mut e: DecodeError) -> DecodeError {
    e.kind = DecodeErrorKind::RdataLength;
    e
}
