//! RRSIG: the signature of an `RRset` (RFC 4034 §3).

use core::fmt;
use std::borrow::Cow;

use crate::codes::{RecordType, SecAlgorithm};
use crate::error::{DecodeError, DecodeErrorKind, EncodeError};
use crate::name::{MAX_NAME_LEN, Name};
use crate::text::encoding::Base64;
use crate::text::{Fields, TextError, TextErrorKind};
use crate::wire::{Reader, Writer};

/// The bytes of the fixed fields of an RRSIG, before the signer's name (RFC 4034 §3.1).
const FIXED_LEN: usize = 18;

/// The longest signature an RRSIG holds: what an RDATA has left after the fixed fields and the longest signer.
const MAX_SIGNATURE_LEN: usize = super::MAX_RDATA_LEN - FIXED_LEN - MAX_NAME_LEN;

/// An RRSIG signature that is empty or too long (RFC 4034 §3.1.8).
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum RrsigError {
    /// A signature of no bytes, or of more than an RDATA has room for after the fixed fields and any signer name.
    #[error("RRSIG signature must be 1 to 65262 bytes")]
    SignatureLength,
}

/// A signature over an `RRset`, with what a validator needs to find the key and check the window.
///
/// The signer's name is never compressed (RFC 4034 §3.1.7, RFC 3597 §4): RDATA with a compression pointer there
/// is kept opaque (D70).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Rrsig<'a> {
    /// The type of the `RRset` signed.
    pub type_covered: RecordType,
    /// The algorithm of the signature.
    pub algorithm: SecAlgorithm,
    /// The labels of the owner name of the `RRset`, not counting the root or a leading `*` (RFC 4034 §3.1.3).
    pub labels: u8,
    /// The TTL of the `RRset` as signed (RFC 4034 §3.1.4).
    pub original_ttl: u32,
    /// The end of the validity period, in seconds since 1970 modulo 2³²: serial number arithmetic compares it
    /// (RFC 4034 §3.1.5).
    pub expiration: u32,
    /// The start of the validity period, as [`Rrsig::expiration`].
    pub inception: u32,
    /// The key tag of the DNSKEY that checks the signature (RFC 4034 appendix B).
    pub key_tag: u16,
    /// The owner name of that DNSKEY.
    pub signer: Name<'a>,
    signature: Cow<'a, [u8]>,
}

impl<'a> Rrsig<'a> {
    /// An RRSIG record's data, borrowing `signature`.
    ///
    /// # Errors
    ///
    /// [`RrsigError`] when `signature` is empty or longer than 65262 bytes.
    #[expect(
        clippy::too_many_arguments,
        reason = "the nine fields of RFC 4034 §3.1, in their order"
    )]
    pub fn new(
        type_covered: RecordType,
        algorithm: SecAlgorithm,
        labels: u8,
        original_ttl: u32,
        expiration: u32,
        inception: u32,
        key_tag: u16,
        signer: Name<'a>,
        signature: &'a [u8],
    ) -> Result<Self, RrsigError> {
        if signature.is_empty() || signature.len() > MAX_SIGNATURE_LEN {
            return Err(RrsigError::SignatureLength);
        }
        Ok(Self {
            type_covered,
            algorithm,
            labels,
            original_ttl,
            expiration,
            inception,
            key_tag,
            signer,
            signature: Cow::Borrowed(signature),
        })
    }

    /// The same data, owning its bytes.
    #[must_use]
    pub fn into_owned(self) -> Rrsig<'static> {
        Rrsig {
            type_covered: self.type_covered,
            algorithm: self.algorithm,
            labels: self.labels,
            original_ttl: self.original_ttl,
            expiration: self.expiration,
            inception: self.inception,
            key_tag: self.key_tag,
            signer: self.signer.into_owned(),
            signature: Cow::Owned(self.signature.into_owned()),
        }
    }

    /// The signature, in the format of its algorithm.
    #[must_use]
    pub fn signature(&self) -> &[u8] {
        &self.signature
    }

    /// The RDATA without the signature, which is what the signature covers first (RFC 4034 §3.1.8.1): the
    /// fields as on the wire, the signer's name uncompressed and in the case it was read in. A validator lowers
    /// the name's case first (RFC 4034 §6.2).
    #[must_use]
    pub fn signed_rdata(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(FIXED_LEN + self.signer.wire_len());
        out.extend_from_slice(&u16::from(self.type_covered).to_be_bytes());
        out.push(self.algorithm.into());
        out.push(self.labels);
        out.extend_from_slice(&self.original_ttl.to_be_bytes());
        out.extend_from_slice(&self.expiration.to_be_bytes());
        out.extend_from_slice(&self.inception.to_be_bytes());
        out.extend_from_slice(&self.key_tag.to_be_bytes());
        out.extend_from_slice(self.signer.to_wire(&mut [0; MAX_NAME_LEN]));
        out
    }

    pub(super) fn decode(r: &mut Reader<'a>) -> Result<Self, DecodeError> {
        let type_covered = RecordType(r.u16()?);
        let algorithm = SecAlgorithm(r.u8()?);
        let labels = r.u8()?;
        let original_ttl = r.u32()?;
        let expiration = r.u32()?;
        let inception = r.u32()?;
        let key_tag = r.u16()?;
        let signer = Name::decode_uncompressed(r)?;
        let signature = r.rest();
        Self::new(
            type_covered,
            algorithm,
            labels,
            original_ttl,
            expiration,
            inception,
            key_tag,
            signer,
            signature,
        )
        .map_err(|_| {
            r.error(DecodeErrorKind::Invalid(
                "RRSIG signature of invalid length",
            ))
        })
    }

    pub(super) fn encode(&self, w: &mut Writer<'_>) -> Result<(), EncodeError> {
        w.put_bytes(&self.signed_rdata())?;
        w.put_bytes(&self.signature)
    }
}

impl Rrsig<'static> {
    /// Reads `type algorithm labels original-ttl expiration inception key-tag signer signature`, the times as
    /// `YYYYMMDDHHmmSS` or as seconds, the signature in base64 with blanks allowed within (RFC 4034 §3.2).
    pub(super) fn from_text(f: &mut Fields<'_, '_>) -> Result<Self, TextError> {
        let type_covered = f.parse("RRSIG type covered")?;
        let algorithm = f.parse("RRSIG algorithm")?;
        let labels = f.number("RRSIG labels")?;
        let original_ttl = f.number("RRSIG original TTL")?;
        let expiration = Self::time(f, "RRSIG signature expiration")?;
        let inception = Self::time(f, "RRSIG signature inception")?;
        let key_tag = f.number("RRSIG key tag")?;
        let signer = f.name("RRSIG signer name")?;
        let at = f.peek()?;
        let signature = f.base64_rest("RRSIG signature")?;
        Rrsig::new(
            type_covered,
            algorithm,
            labels,
            original_ttl,
            expiration,
            inception,
            key_tag,
            signer,
            &signature,
        )
        .map_err(|_| {
            let kind = TextErrorKind::Invalid("RRSIG signature: 1 to 65262 bytes");
            at.map_or_else(|| f.end_error(kind), |t| t.error(kind))
        })
        .map(Rrsig::into_owned)
    }

    fn time(f: &mut Fields<'_, '_>, what: &'static str) -> Result<u32, TextError> {
        let token = f.next(what)?;
        time::parse(token.raw).ok_or(token.error(TextErrorKind::Invalid(what)))
    }
}

/// `type algorithm labels original-ttl expiration inception key-tag signer signature`: the type as a mnemonic,
/// the algorithm as a number, the times as `YYYYMMDDHHmmSS` (UTC), the signature in base64.
impl fmt::Display for Rrsig<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{} {} {} {} {} {} {} {} {}",
            self.type_covered,
            u8::from(self.algorithm),
            self.labels,
            self.original_ttl,
            time::Time(self.expiration),
            time::Time(self.inception),
            self.key_tag,
            self.signer,
            Base64(&self.signature)
        )
    }
}

/// The times of an RRSIG in text: `YYYYMMDDHHmmSS` or seconds since 1970 (RFC 4034 §3.2).
mod time {
    use core::fmt;

    const SECONDS_PER_DAY: u32 = 86400;
    /// Days from 0000-03-01 to 1970-01-01, the epoch of the algorithm below.
    const EPOCH_DAYS: u64 = 719_468;

    /// Seconds since 1970 written as `YYYYMMDDHHmmSS` in UTC.
    pub(super) struct Time(pub(super) u32);

    impl fmt::Display for Time {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            let (days, secs) = (self.0 / SECONDS_PER_DAY, self.0 % SECONDS_PER_DAY);
            let (year, month, day) = civil_from_days(u64::from(days) + EPOCH_DAYS);
            let (hour, minute, second) = (secs / 3600, secs % 3600 / 60, secs % 60);
            write!(
                f,
                "{year:04}{month:02}{day:02}{hour:02}{minute:02}{second:02}"
            )
        }
    }

    /// Reads 14 digits as a UTC date and time, or up to 10 digits as seconds. A date past 2106-02-07 wraps modulo
    /// 2³², as the times do on the wire (RFC 4034 §3.1.5); one before 1970 is refused.
    pub(super) fn parse(text: &[u8]) -> Option<u32> {
        if !text.iter().all(u8::is_ascii_digit) {
            return None;
        }
        if text.len() != 14 {
            return (text.len() <= 10)
                .then(|| crate::text::number(text))
                .flatten();
        }
        let field = |range: core::ops::Range<usize>| -> Option<u64> {
            crate::text::number(text.get(range)?)
        };
        let (year, month, day) = (field(0..4)?, field(4..6)?, field(6..8)?);
        let (hour, minute, second) = (field(8..10)?, field(10..12)?, field(12..14)?);
        if !(1..=12).contains(&month)
            || day < 1
            || day > days_in_month(year, month)
            || hour > 23
            || minute > 59
            || second > 59
        {
            return None;
        }
        let days = days_from_civil(year, month, day)?;
        let seconds = days * u64::from(SECONDS_PER_DAY) + hour * 3600 + minute * 60 + second;
        u32::try_from(seconds % (1 << 32)).ok()
    }

    fn days_in_month(year: u64, month: u64) -> u64 {
        let leap =
            year.is_multiple_of(4) && (!year.is_multiple_of(100) || year.is_multiple_of(400));
        match month {
            2 if leap => 29,
            2 => 28,
            4 | 6 | 9 | 11 => 30,
            _ => 31,
        }
    }

    /// Days since 1970-01-01 of a date from 1970 on (Howard Hinnant's `days_from_civil`).
    fn days_from_civil(year: u64, month: u64, day: u64) -> Option<u64> {
        let year = if month <= 2 {
            year.checked_sub(1)?
        } else {
            year
        };
        let era = year / 400;
        let year_of_era = year % 400;
        let shifted_month = if month > 2 { month - 3 } else { month + 9 };
        let day_of_year = (153 * shifted_month + 2) / 5 + day - 1;
        let day_of_era = year_of_era * 365 + year_of_era / 4 - year_of_era / 100 + day_of_year;
        (era * 146_097 + day_of_era).checked_sub(EPOCH_DAYS)
    }

    /// The date of a day count from 0000-03-01 (Howard Hinnant's `civil_from_days`).
    fn civil_from_days(days: u64) -> (u64, u64, u64) {
        let era = days / 146_097;
        let day_of_era = days % 146_097;
        let year_of_era =
            (day_of_era - day_of_era / 1460 + day_of_era / 36524 - day_of_era / 146_096) / 365;
        let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
        let shifted_month = (5 * day_of_year + 2) / 153;
        let day = day_of_year - (153 * shifted_month + 2) / 5 + 1;
        let month = if shifted_month < 10 {
            shifted_month + 3
        } else {
            shifted_month - 9
        };
        let year = year_of_era + era * 400 + u64::from(month <= 2);
        (year, month, day)
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn dates_and_seconds() {
            assert_eq!(parse(b"19700101000000"), Some(0));
            assert_eq!(parse(b"20030322173103"), Some(1_048_354_263));
            assert_eq!(parse(b"1048354263"), Some(1_048_354_263));
            assert_eq!(Time(1_048_354_263).to_string(), "20030322173103");
            assert_eq!(Time(0).to_string(), "19700101000000");
            assert_eq!(Time(u32::MAX).to_string(), "21060207062815");
            assert_eq!(parse(b"21060207062815"), Some(u32::MAX));
            // 2106-02-07 06:28:16 is 2³²: the time wraps.
            assert_eq!(parse(b"21060207062816"), Some(0));
        }

        #[test]
        fn refused() {
            for bad in [
                &b""[..],
                b"4294967296",
                b"12345678901",
                b"1969123123595",
                b"19691231235959",
                b"20030230000000",
                b"20031301000000",
                b"20030322240000",
                b"20030322176000",
                b"20030322173160",
                b"2003-03-22",
            ] {
                assert_eq!(parse(bad), None, "{}", String::from_utf8_lossy(bad));
            }
            assert_eq!(parse(b"20000229000000"), Some(951_782_400));
            assert_eq!(parse(b"19000229000000"), None);
        }

        #[test]
        fn every_day_round_trips() {
            for days in (0..=u32::MAX / SECONDS_PER_DAY).step_by(7) {
                let seconds = days * SECONDS_PER_DAY + 86399;
                assert_eq!(parse(Time(seconds).to_string().as_bytes()), Some(seconds));
            }
        }
    }
}
