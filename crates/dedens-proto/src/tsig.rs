//! TSIG: the data of a transaction signature (RFC 8945 §4.2) and finding it in a message (§5.1, §5.2).
//!
//! TSIG is a meta type (RFC 6895 §3.1): it is in no zone and no cache, so it has no text form to read and no
//! place in [`RData`](crate::rdata::RData), where a decoded message keeps it as an opaque record; this module
//! reads it from the message's bytes, which a signature covers.

use core::fmt;
use std::borrow::Cow;

use crate::codes::{Class, RecordType, TsigError};
use crate::error::{DecodeError, DecodeErrorKind};
use crate::header::Header;
use crate::name::{MAX_NAME_LEN, Name};
use crate::question::Question;
use crate::record::Record;
use crate::text::encoding::Base64;
use crate::wire::{MAX_MESSAGE_LEN, Reader};

/// The bytes of the RDATA's fixed fields besides the algorithm name: Time Signed, Fudge, MAC Size, Original ID,
/// Error and Other Len (RFC 8945 §4.2): 6 + 5 × 2.
const FIXED_LEN: usize = 16;

/// The most bytes an RDATA holds: RDLENGTH is 16 bits (RFC 1035 §3.2.1).
const MAX_RDATA_LEN: usize = 65535;

/// The largest Time Signed: it has 48 bits (RFC 8945 §4.2).
pub const MAX_TIME_SIGNED: u64 = (1 << 48) - 1;

/// TSIG data that does not fit its fields.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum TsigDataError {
    /// A Time Signed over 48 bits.
    #[error("TSIG time signed must fit 48 bits")]
    TimeSigned,
    /// A MAC and Other Data that, with the algorithm name, overrun an RDATA.
    #[error("TSIG MAC and other data overrun the RDATA")]
    Length,
}

/// The data of a TSIG record: who signed what, when, and the MAC (RFC 8945 §4.2).
///
/// The algorithm name is never compressed (RFC 8945 §4.2).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Tsig<'a> {
    /// The algorithm of the MAC, as a name (RFC 8945 §6).
    pub algorithm: Name<'a>,
    time_signed: u64,
    /// How many seconds either side of the time signed a receiver accepts (RFC 8945 §5.2.3).
    pub fudge: u16,
    mac: Cow<'a, [u8]>,
    /// The ID of the message as signed: a forwarder may have changed the one it carries (RFC 8945 §5.2.1).
    pub original_id: u16,
    /// The outcome of the check, `NOERROR` in a request (RFC 8945 §3).
    pub error: TsigError,
    other: Cow<'a, [u8]>,
}

impl<'a> Tsig<'a> {
    /// A TSIG record's data, borrowing `mac` and `other`.
    ///
    /// # Errors
    ///
    /// [`TsigDataError`] when `time_signed` is over 48 bits or the data is too long for an RDATA.
    pub fn new(
        algorithm: Name<'a>,
        time_signed: u64,
        fudge: u16,
        mac: &'a [u8],
        original_id: u16,
        error: TsigError,
        other: &'a [u8],
    ) -> Result<Self, TsigDataError> {
        if time_signed > MAX_TIME_SIGNED {
            return Err(TsigDataError::TimeSigned);
        }
        if algorithm.wire_len() + FIXED_LEN + mac.len() + other.len() > MAX_RDATA_LEN {
            return Err(TsigDataError::Length);
        }
        Ok(Self {
            algorithm,
            time_signed,
            fudge,
            mac: Cow::Borrowed(mac),
            original_id,
            error,
            other: Cow::Borrowed(other),
        })
    }

    /// The same data, owning its bytes.
    #[must_use]
    pub fn into_owned(self) -> Tsig<'static> {
        Tsig {
            algorithm: self.algorithm.into_owned(),
            time_signed: self.time_signed,
            fudge: self.fudge,
            mac: Cow::Owned(self.mac.into_owned()),
            original_id: self.original_id,
            error: self.error,
            other: Cow::Owned(self.other.into_owned()),
        }
    }

    /// When the message was signed, in seconds since 1970.
    #[must_use]
    pub const fn time_signed(&self) -> u64 {
        self.time_signed
    }

    /// The MAC, empty in an unsigned error (RFC 8945 §5.3.2).
    #[must_use]
    pub fn mac(&self) -> &[u8] {
        &self.mac
    }

    /// Other Data: the server's time as 6 bytes in a BADTIME error, empty otherwise (RFC 8945 §5.2.3).
    #[must_use]
    pub fn other(&self) -> &[u8] {
        &self.other
    }

    /// The RDATA as it goes on the wire (RFC 8945 §4.2).
    #[must_use]
    pub fn to_wire(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(
            self.algorithm.wire_len() + FIXED_LEN + self.mac.len() + self.other.len(),
        );
        out.extend_from_slice(self.algorithm.to_wire(&mut [0; MAX_NAME_LEN]));
        out.extend_from_slice(&self.time_signed.to_be_bytes()[2..]);
        out.extend_from_slice(&self.fudge.to_be_bytes());
        out.extend_from_slice(&len16(&self.mac).to_be_bytes());
        out.extend_from_slice(&self.mac);
        out.extend_from_slice(&self.original_id.to_be_bytes());
        out.extend_from_slice(&self.error.0.to_be_bytes());
        out.extend_from_slice(&len16(&self.other).to_be_bytes());
        out.extend_from_slice(&self.other);
        out
    }

    fn decode(r: &mut Reader<'a>) -> Result<Self, DecodeError> {
        let algorithm = Name::decode_uncompressed(r)?;
        let mut time = [0; 8];
        time[2..].copy_from_slice(&r.array::<6>()?);
        let time_signed = u64::from_be_bytes(time);
        let fudge = r.u16()?;
        let mac_len = r.u16()?;
        let mac = r.bytes(usize::from(mac_len))?;
        let original_id = r.u16()?;
        let error = TsigError(r.u16()?);
        let other_len = r.u16()?;
        let other = r.bytes(usize::from(other_len))?;
        if !r.is_empty() {
            return Err(r.error(DecodeErrorKind::Invalid("TSIG bytes after Other Data")));
        }
        // The RDATA is at most 65535 bytes, so its parts fit `new`.
        Self::new(
            algorithm,
            time_signed,
            fudge,
            mac,
            original_id,
            error,
            other,
        )
        .map_err(|_| r.error(DecodeErrorKind::Invalid("TSIG too long")))
    }
}

/// The length of a MAC or Other Data, which [`Tsig::new`] keeps under the RDATA's.
fn len16(bytes: &[u8]) -> u16 {
    u16::try_from(bytes.len()).expect("`Tsig::new` bounds both by the RDATA")
}

/// `algorithm time-signed fudge mac-size [mac] original-id error other-len [other]`: the error as a mnemonic, the
/// MAC and the Other Data in base64, left out when empty.
impl fmt::Display for Tsig<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{} {} {} {}",
            self.algorithm,
            self.time_signed,
            self.fudge,
            self.mac.len()
        )?;
        if !self.mac.is_empty() {
            write!(f, " {}", Base64(&self.mac))?;
        }
        write!(
            f,
            " {} {} {}",
            self.original_id,
            self.error,
            self.other.len()
        )?;
        if !self.other.is_empty() {
            write!(f, " {}", Base64(&self.other))?;
        }
        Ok(())
    }
}

/// The TSIG record of a message and where it starts, to be taken off the bytes that were signed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TsigRecord<'a> {
    /// The owner: the name of the key (RFC 8945 §4.2).
    pub name: Name<'a>,
    /// The class of the record, which must be `ANY` (RFC 8945 §4.2).
    pub class: Class,
    /// The TTL of the record, which must be 0 (RFC 8945 §4.2).
    pub ttl: u32,
    /// The record's data.
    pub tsig: Tsig<'a>,
    /// The offset in the message where the record starts: the signed message ends there.
    pub start: usize,
}

/// Reads the TSIG record of `msg`, the last record of its additional section, if it has one (RFC 8945 §5.1).
///
/// Bytes outside data: anything wrong is an error, never a panic. Only the structure up to the TSIG is read:
/// questions and records before it are skipped, the OPT record among them.
///
/// # Errors
///
/// [`DecodeError`] when the message is cut short or broken, when a TSIG record is anywhere but last in the
/// additional section or there is more than one, when anything follows it, or when its data is invalid.
pub fn find_tsig(msg: &[u8]) -> Result<Option<TsigRecord<'_>>, DecodeError> {
    if msg.len() > MAX_MESSAGE_LEN {
        return Err(DecodeError {
            offset: MAX_MESSAGE_LEN,
            kind: DecodeErrorKind::Invalid("message longer than 65535 bytes"),
        });
    }
    let mut r = Reader::new(msg);
    let (_, counts) = Header::decode(&mut r)?;
    for _ in 0..counts.questions {
        Question::decode(&mut r)?;
    }
    let before_additional = u32::from(counts.answers) + u32::from(counts.authority);
    let total = before_additional + u32::from(counts.additional);
    let misplaced = |offset| DecodeError {
        offset,
        kind: DecodeErrorKind::Invalid("TSIG not the last record of the additional section"),
    };
    let mut found = None;
    for index in 0..total {
        let start = r.position();
        let raw = Record::read_raw(&mut r)?;
        if raw.rtype != RecordType::TSIG {
            continue;
        }
        if index + 1 != total || index < before_additional {
            return Err(misplaced(start));
        }
        let mut rdata = raw.rdata;
        found = Some(TsigRecord {
            name: raw.name,
            class: raw.class,
            ttl: raw.ttl,
            tsig: Tsig::decode(&mut rdata)?,
            start,
        });
    }
    if found.is_some() && !r.is_empty() {
        return Err(DecodeError {
            offset: r.position(),
            kind: DecodeErrorKind::Invalid("bytes after the TSIG record"),
        });
    }
    Ok(found)
}
