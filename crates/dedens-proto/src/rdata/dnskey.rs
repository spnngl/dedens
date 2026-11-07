//! DNSKEY: a public key of a zone (RFC 4034 §2), and CDNSKEY, the child's copy of it (RFC 7344 §3.2, RFC 8078 §4).

use core::fmt;
use std::borrow::Cow;

use super::MAX_RDATA_LEN;
use crate::codes::SecAlgorithm;
use crate::error::{DecodeError, DecodeErrorKind, EncodeError};
use crate::text::encoding::Base64;
use crate::text::{Fields, TextError, TextErrorKind};
use crate::wire::{Reader, Writer};

/// The only protocol value there is (RFC 4034 §2.1.2); a DNSKEY with another is invalid, so it has no field.
const PROTOCOL: u8 = 3;

/// A DNSKEY public key that is empty or longer than an RDATA holds (RFC 4034 §2.1.4).
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum DnskeyError {
    /// A key of no bytes, or of more than fit the 65535 bytes of an RDATA.
    #[error("DNSKEY public key must be 1 to 65531 bytes")]
    KeyLength,
}

/// A public key, its flags and its algorithm; the same fields in a CDNSKEY record.
///
/// The protocol field is always 3 (RFC 4034 §2.1.2): RDATA with another value is kept opaque (D9).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Dnskey<'a> {
    flags: u16,
    algorithm: SecAlgorithm,
    public_key: Cow<'a, [u8]>,
}

impl<'a> Dnskey<'a> {
    /// Bit 7 of the flags: the key signs the zone's `RRsets` (RFC 4034 §2.1.1).
    pub const ZONE_KEY: u16 = 0x0100;
    /// Bit 15 of the flags: the key is a secure entry point, one that a DS record or a trust anchor refers to (RFC
    /// 4034 §2.1.1, RFC 3757).
    pub const SEP: u16 = 0x0001;
    /// Bit 8 of the flags: the key is revoked (RFC 5011 §7).
    pub const REVOKE: u16 = 0x0080;

    /// A DNSKEY record's data, borrowing `public_key`.
    ///
    /// # Errors
    ///
    /// [`DnskeyError`] when `public_key` is empty or too long for an RDATA.
    pub fn new(
        flags: u16,
        algorithm: SecAlgorithm,
        public_key: &'a [u8],
    ) -> Result<Self, DnskeyError> {
        if public_key.is_empty() || 4 + public_key.len() > MAX_RDATA_LEN {
            return Err(DnskeyError::KeyLength);
        }
        Ok(Self {
            flags,
            algorithm,
            public_key: Cow::Borrowed(public_key),
        })
    }

    /// The same data, owning its key.
    #[must_use]
    pub fn into_owned(self) -> Dnskey<'static> {
        Dnskey {
            flags: self.flags,
            algorithm: self.algorithm,
            public_key: Cow::Owned(self.public_key.into_owned()),
        }
    }

    /// The flags, whose bits [`Dnskey::ZONE_KEY`], [`Dnskey::SEP`] and [`Dnskey::REVOKE`] name.
    #[must_use]
    pub const fn flags(&self) -> u16 {
        self.flags
    }

    /// Whether the zone key bit is set.
    #[must_use]
    pub const fn is_zone_key(&self) -> bool {
        self.flags & Self::ZONE_KEY != 0
    }

    /// Whether the secure entry point bit is set.
    #[must_use]
    pub const fn is_secure_entry_point(&self) -> bool {
        self.flags & Self::SEP != 0
    }

    /// Whether the revoke bit is set.
    #[must_use]
    pub const fn is_revoked(&self) -> bool {
        self.flags & Self::REVOKE != 0
    }

    /// The algorithm of the key.
    #[must_use]
    pub const fn algorithm(&self) -> SecAlgorithm {
        self.algorithm
    }

    /// The public key, in the format of its algorithm.
    #[must_use]
    pub fn public_key(&self) -> &[u8] {
        &self.public_key
    }

    /// Whether this is the CDNSKEY form that asks the parent to remove the DS `RRset`: `0 3 0 AA==` (RFC 8078 §4).
    #[must_use]
    pub fn is_delete(&self) -> bool {
        self.flags == 0 && self.algorithm == SecAlgorithm(0) && *self.public_key == [0]
    }

    pub(super) fn decode(r: &mut Reader<'a>) -> Result<Self, DecodeError> {
        let flags = r.u16()?;
        let protocol = r.u8()?;
        let algorithm = SecAlgorithm(r.u8()?);
        let key = r.rest();
        if protocol != PROTOCOL {
            return Err(r.error(DecodeErrorKind::Invalid("DNSKEY protocol is not 3")));
        }
        Self::new(flags, algorithm, key)
            .map_err(|_| r.error(DecodeErrorKind::Invalid("empty DNSKEY public key")))
    }

    pub(super) fn encode(&self, w: &mut Writer<'_>) -> Result<(), EncodeError> {
        w.put_u16(self.flags)?;
        w.put_u8(PROTOCOL)?;
        w.put_u8(self.algorithm.into())?;
        w.put_bytes(&self.public_key)
    }
}

impl Dnskey<'static> {
    /// Reads `flags protocol algorithm key`, the key in base64 with blanks allowed within (RFC 4034 §2.2).
    pub(super) fn from_text(f: &mut Fields<'_, '_>) -> Result<Self, TextError> {
        let flags = f.number("DNSKEY flags")?;
        let protocol = f.next("DNSKEY protocol")?;
        if crate::text::number::<u8>(protocol.raw) != Some(PROTOCOL) {
            return Err(protocol.error(TextErrorKind::Invalid("DNSKEY protocol: must be 3")));
        }
        let algorithm = f.parse("DNSKEY algorithm")?;
        let at = f.peek()?;
        // The delete form is written with a lone 0 as the key (RFC 8078 §4).
        let key = if (flags, algorithm) == (0, SecAlgorithm(0)) && at.is_some_and(|t| t.raw == b"0")
        {
            f.next("DNSKEY public key")?;
            vec![0]
        } else {
            f.base64_rest("DNSKEY public key")?
        };
        Dnskey::new(flags, algorithm, &key)
            .map_err(|_| {
                let kind = TextErrorKind::Invalid("DNSKEY public key: 1 to 65531 bytes");
                at.map_or_else(|| f.end_error(kind), |t| t.error(kind))
            })
            .map(Dnskey::into_owned)
    }
}

/// `flags 3 algorithm key`, the algorithm as a number, the key in base64.
impl fmt::Display for Dnskey<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{} {PROTOCOL} {} {}",
            self.flags,
            u8::from(self.algorithm),
            Base64(&self.public_key)
        )
    }
}
