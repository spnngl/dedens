//! EDNS(0): the OPT pseudo-record and its options (RFC 6891).
//!
//! A [`Message`](crate::Message) holds the OPT record as an [`Edns`] value, not among its records (D8). A typed
//! option (D12) with a type of its own has a file named after it; NSID, keepalive and padding are arms of
//! [`EdnsOption`]'s decode and encode (D159). Every other option, and an option whose content is invalid, stays
//! [`EdnsOption::Unknown`]; a message decoded with an invalid one records a
//! [`Violation::InvalidOption`](crate::Violation::InvalidOption) (D9).

mod cookie;
mod ede;
mod subnet;

use std::borrow::Cow;
use std::mem;

pub use cookie::{Cookie, CookieError};
pub use ede::{EDE_LEN, ExtendedError, InfoCode};
pub use subnet::{ClientSubnet, SubnetError};

use crate::codes::{RecordType, code_type};
use crate::error::{DecodeError, DecodeErrorKind, EncodeError};
use crate::header::flag_set;
use crate::wire::{MAX_MESSAGE_LEN, Reader, Writer};

/// The UDP payload size to advertise by default: 1232 bytes avoids IP fragmentation (DNS Flag Day 2020, D10).
pub const DEFAULT_UDP_PAYLOAD: u16 = 1232;

/// Root owner, type, CLASS, TTL and RDLENGTH of an OPT record.
const OPT_FIXED_LEN: usize = 11;

/// Code and length of an option.
const OPTION_HEADER_LEN: usize = 4;

/// Where the header holds ARCOUNT (RFC 1035 §4.1.1).
const ARCOUNT_AT: usize = 10;

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
}

flag_set!(EdnsFlags);

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

/// One option of an OPT record (RFC 6891 §6.1.2).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum EdnsOption<'a> {
    /// Name server identifier: empty in a query, opaque bytes in a response (RFC 5001 §2.3).
    Nsid(Cow<'a, [u8]>),
    /// Client subnet (RFC 7871 §6).
    ClientSubnet(ClientSubnet),
    /// Cookie (RFC 7873 §4).
    Cookie(Cookie),
    /// TCP keepalive: the idle timeout in 100 ms units, absent in a query (RFC 7828 §3.1).
    Keepalive(Option<u16>),
    /// Padding of this many zero bytes: only the length is kept, as a receiver ignores the octets (RFC 7830 §3).
    Padding(u16),
    /// Extended DNS Error (RFC 8914 §2).
    Ede(ExtendedError<'a>),
    /// An option without a typed variant, or whose content is invalid for its code (D9).
    Unknown(UnknownOption<'a>),
}

/// The data of an option kept as bytes (RFC 6891 §6.1.2): its code has no typed variant, or the data is invalid for
/// its code (D9).
///
/// [`UnknownOption::new`] refuses data that reads as a typed option, so an option has one form and compares
/// equal to itself read back.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct UnknownOption<'a> {
    code: OptionCode,
    data: Cow<'a, [u8]>,
}

impl<'a> UnknownOption<'a> {
    /// The option `code` with `data`.
    ///
    /// # Errors
    ///
    /// [`DecodeError`] when `data` is longer than 65535 bytes, or reads as the typed [`EdnsOption`] of `code`:
    /// build that variant instead.
    pub fn new(code: OptionCode, data: &'a [u8]) -> Result<Self, DecodeError> {
        let error = |kind| DecodeError { offset: 0, kind };
        if data.len() > usize::from(u16::MAX) {
            return Err(error(DecodeErrorKind::RdataLength));
        }
        match EdnsOption::decode_typed(code, &mut Reader::new(data)) {
            Ok(EdnsOption::Unknown(_)) | Err(_) => Ok(Self::borrowed(code, data)),
            Ok(_) => Err(error(DecodeErrorKind::Invalid(
                "option data with a typed form",
            ))),
        }
    }

    const fn borrowed(code: OptionCode, data: &'a [u8]) -> Self {
        Self {
            code,
            data: Cow::Borrowed(data),
        }
    }

    /// The option code.
    #[must_use]
    pub const fn code(&self) -> OptionCode {
        self.code
    }

    /// The option data.
    #[must_use]
    pub fn data(&self) -> &[u8] {
        &self.data
    }

    /// The same option, owning its bytes.
    #[must_use]
    pub fn into_owned(self) -> UnknownOption<'static> {
        UnknownOption {
            code: self.code,
            data: Cow::Owned(self.data.into_owned()),
        }
    }
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
            Self::Unknown(unknown) => EdnsOption::Unknown(unknown.into_owned()),
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
            Self::Unknown(unknown) => unknown.code,
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
            Self::Unknown(unknown) => unknown.data.len(),
        }
    }

    /// Parses the data of option `code`; all of `data` must be used.
    fn decode_typed(code: OptionCode, data: &mut Reader<'a>) -> Result<Self, DecodeError> {
        let option = match code {
            OptionCode::NSID => Self::Nsid(Cow::Borrowed(data.rest())),
            OptionCode::CLIENT_SUBNET => Self::ClientSubnet(ClientSubnet::decode(data)?),
            OptionCode::COOKIE => Self::Cookie(Cookie::decode(data)?),
            OptionCode::KEEPALIVE => Self::Keepalive(match data.remaining() {
                0 => None,
                2 => Some(data.u16()?),
                _ => {
                    return Err(data.error(DecodeErrorKind::Invalid(
                        "keepalive is empty or a 2-byte timeout",
                    )));
                }
            }),
            // The option length is a `u16`, so the padding fits.
            OptionCode::PADDING => {
                Self::Padding(u16::try_from(data.rest().len()).unwrap_or(u16::MAX))
            }
            OptionCode::EDE => Self::Ede(ExtendedError::decode(data)?),
            _ => Self::Unknown(UnknownOption::borrowed(code, data.rest())),
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
            Self::Keepalive(Some(timeout)) => w.put_u16(*timeout)?,
            Self::Keepalive(None) => {}
            Self::Padding(len) => w.put_zeros(usize::from(*len))?,
            Self::Ede(error) => error.encode(w)?,
            Self::Unknown(unknown) => w.put_bytes(&unknown.data)?,
        }
        let len = u16::try_from(w.len() - at - 2).map_err(|_| EncodeError::BufferFull)?;
        w.patch_u16(at, len);
        Ok(())
    }
}

/// An option that was kept as [`EdnsOption::Unknown`] although its code is typed, because its content is
/// invalid for its code (RFC 6891 §6.1.2, D9).
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

    /// Builds the value from an OPT record's CLASS, TTL and RDATA, its options in `options`, an empty vector
    /// whose allocation is reused; an option with invalid content is kept unknown and handed to `invalid`.
    ///
    /// # Errors
    ///
    /// [`DecodeError`] when the option framing is broken: an option cut short or running past the RDATA.
    pub(crate) fn from_opt(
        class: u16,
        ttl: u32,
        rdata: Reader<'a>,
        mut options: Vec<EdnsOption<'a>>,
        mut invalid: impl FnMut(InvalidOption),
    ) -> Result<Self, DecodeError> {
        read_options(rdata, |option, error| {
            options.push(option);
            error.into_iter().for_each(&mut invalid);
        })?;
        Ok(EdnsView::new(class, ttl, rdata).with_options(options))
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

    /// Writes the OPT record after the message in `buf[..len]` and counts it in the header's ARCOUNT, returning
    /// the new length: how a server adds its EDNS to a response copied from a cache.
    ///
    /// ```
    /// # use dedens_proto::{edns::Edns, Message, Question, RecordType, Name};
    /// let mut message = Message::query(1, Question::new(Name::root(), RecordType::NS));
    /// message.edns = None;
    /// let mut buf = [0; 512];
    /// let len = message.encode(&mut buf)?;
    /// let len = Edns::default().append(&mut buf, len)?;
    /// let decoded = Message::decode(&buf[..len]).expect("decodes");
    /// assert_eq!(decoded.message.edns, Some(Edns::default()));
    /// # Ok::<(), dedens_proto::EncodeError>(())
    /// ```
    ///
    /// # Errors
    ///
    /// [`EncodeError::BufferFull`] when the record does not fit after `len`, or `buf[..len]` is shorter than a
    /// header or already counts 65535 additional records.
    pub fn append(&self, buf: &mut [u8], len: usize) -> Result<usize, EncodeError> {
        let (message, tail) = buf
            .split_at_mut_checked(len)
            .ok_or(EncodeError::BufferFull)?;
        let arcount = message
            .get_mut(ARCOUNT_AT..ARCOUNT_AT + 2)
            .ok_or(EncodeError::BufferFull)?;
        let count = u16::from_be_bytes([arcount[0], arcount[1]])
            .checked_add(1)
            .ok_or(EncodeError::BufferFull)?;
        let limit = MAX_MESSAGE_LEN.saturating_sub(len).min(tail.len());
        let mut w = Writer::uncompressed(&mut tail[..limit]);
        self.encode(&mut w)?;
        let written = w.len();
        arcount.copy_from_slice(&count.to_be_bytes());
        Ok(len + written)
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

/// Reads the options of an OPT record's RDATA, handing each to `each` with, when its content is invalid for its
/// code, why it is kept as [`EdnsOption::Unknown`].
///
/// # Errors
///
/// [`DecodeError`] when the option framing is broken: an option cut short or running past the RDATA.
pub(crate) fn read_options<'a>(
    rdata: Reader<'a>,
    mut each: impl FnMut(EdnsOption<'a>, Option<InvalidOption>),
) -> Result<(), DecodeError> {
    let mut options = Options {
        rdata,
        cookie: false,
    };
    while let Some((option, invalid)) = options.read()? {
        each(option, invalid);
    }
    Ok(())
}

/// The options of an OPT record that was checked when its message was read, in wire order; an option whose
/// content is invalid for its code comes as [`EdnsOption::Unknown`] (D9). Only the first COOKIE option is read: the
/// others are ignored, valid or not (RFC 7873 §5.2).
#[derive(Debug, Clone)]
pub struct Options<'a> {
    rdata: Reader<'a>,
    /// Whether a COOKIE option was read.
    cookie: bool,
}

impl<'a> Options<'a> {
    /// The next option and, when its content is invalid for its code, why it is kept unknown.
    fn read(&mut self) -> Result<Option<(EdnsOption<'a>, Option<InvalidOption>)>, DecodeError> {
        loop {
            let rdata = &mut self.rdata;
            if rdata.is_empty() {
                return Ok(None);
            }
            let code = OptionCode(rdata.u16().map_err(rdlength)?);
            let len = usize::from(rdata.u16().map_err(rdlength)?);
            let mut data = rdata.sub(len).map_err(rdlength)?;
            if code == OptionCode::COOKIE && mem::replace(&mut self.cookie, true) {
                continue;
            }
            let mut raw = data;
            return Ok(Some(match EdnsOption::decode_typed(code, &mut data) {
                Ok(option) => (option, None),
                Err(error) => (
                    EdnsOption::Unknown(UnknownOption::borrowed(code, raw.rest())),
                    Some(InvalidOption { code, error }),
                ),
            }));
        }
    }
}

impl<'a> Iterator for Options<'a> {
    type Item = EdnsOption<'a>;

    fn next(&mut self) -> Option<Self::Item> {
        let read = self
            .read()
            .expect("the options were checked when the message was read");
        read.map(|(option, _)| option)
    }
}

/// The OPT record of a message read in place (RFC 6891 §6.1): its fields, and its options read from the input when
/// iterated.
#[derive(Debug, Clone)]
pub struct EdnsView<'a> {
    /// As [`Edns::udp_payload`].
    pub udp_payload: u16,
    /// As [`Edns::ext_rcode`].
    pub ext_rcode: u8,
    /// As [`Edns::version`].
    pub version: u8,
    /// As [`Edns::flags`].
    pub flags: EdnsFlags,
    options: Reader<'a>,
}

impl<'a> EdnsView<'a> {
    /// The fields of an OPT record whose RDATA was checked with [`read_options`].
    pub(crate) const fn new(class: u16, ttl: u32, rdata: Reader<'a>) -> Self {
        let [ext_rcode, version, flags_hi, flags_lo] = ttl.to_be_bytes();
        Self {
            udp_payload: class,
            ext_rcode,
            version,
            flags: EdnsFlags(u16::from_be_bytes([flags_hi, flags_lo])),
            options: rdata,
        }
    }

    /// The options, in wire order.
    #[must_use]
    pub fn options(&self) -> Options<'a> {
        Options {
            rdata: self.options,
            cookie: false,
        }
    }

    /// The same EDNS data with its options parsed into a vector.
    #[must_use]
    pub fn to_edns(&self) -> Edns<'a> {
        self.with_options(self.options().collect())
    }

    /// The same EDNS data with `options`.
    const fn with_options(&self, options: Vec<EdnsOption<'a>>) -> Edns<'a> {
        Edns {
            udp_payload: self.udp_payload,
            ext_rcode: self.ext_rcode,
            version: self.version,
            flags: self.flags,
            options,
        }
    }
}

/// An OPT record whose options run past its RDATA is a RDATA length error.
fn rdlength(mut e: DecodeError) -> DecodeError {
    e.kind = DecodeErrorKind::RdataLength;
    e
}
