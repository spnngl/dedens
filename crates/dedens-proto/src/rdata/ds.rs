//! DS: delegation signer (RFC 4034 §5), and CDS, the child's copy of it (RFC 7344 §3.1, RFC 8078 §4).

use core::fmt;
use std::borrow::Cow;

use super::MAX_RDATA_LEN;
use crate::codes::{DigestType, SecAlgorithm};
use crate::error::{DecodeError, DecodeErrorKind, EncodeError};
use crate::text::{Fields, Hex, TextError, TextErrorKind};
use crate::wire::{Reader, Writer};

/// A DS digest that is empty or longer than an RDATA holds (RFC 4034 §5.1.4).
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum DsError {
    /// A digest of no bytes, or of more than fit the 65535 bytes of an RDATA.
    #[error("DS digest must be 1 to 65531 bytes")]
    DigestLength,
}

/// A digest of the DNSKEY of a child zone, kept by its parent; the same fields in a CDS record.
///
/// RFC 4034 §5.1.4 sets the digest's length by its type; checking it is for the validator, which knows the
/// digest types it supports.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Ds<'a> {
    key_tag: u16,
    algorithm: SecAlgorithm,
    digest_type: DigestType,
    digest: Cow<'a, [u8]>,
}

impl<'a> Ds<'a> {
    /// A DS record's data, borrowing `digest`.
    ///
    /// # Errors
    ///
    /// [`DsError`] when `digest` is empty or too long for an RDATA.
    pub fn new(
        key_tag: u16,
        algorithm: SecAlgorithm,
        digest_type: DigestType,
        digest: &'a [u8],
    ) -> Result<Self, DsError> {
        if digest.is_empty() || 4 + digest.len() > MAX_RDATA_LEN {
            return Err(DsError::DigestLength);
        }
        Ok(Self {
            key_tag,
            algorithm,
            digest_type,
            digest: Cow::Borrowed(digest),
        })
    }

    /// The same data, owning its digest.
    #[must_use]
    pub fn into_owned(self) -> Ds<'static> {
        Ds {
            key_tag: self.key_tag,
            algorithm: self.algorithm,
            digest_type: self.digest_type,
            digest: Cow::Owned(self.digest.into_owned()),
        }
    }

    /// The key tag of the DNSKEY this digests (RFC 4034 appendix B).
    #[must_use]
    pub const fn key_tag(&self) -> u16 {
        self.key_tag
    }

    /// The algorithm of that DNSKEY.
    #[must_use]
    pub const fn algorithm(&self) -> SecAlgorithm {
        self.algorithm
    }

    /// How the digest was made.
    #[must_use]
    pub const fn digest_type(&self) -> DigestType {
        self.digest_type
    }

    /// The digest.
    #[must_use]
    pub fn digest(&self) -> &[u8] {
        &self.digest
    }

    /// Whether this is the CDS form that asks the parent to remove the DS `RRset`: `0 0 0 00` (RFC 8078 §4).
    #[must_use]
    pub fn is_delete(&self) -> bool {
        self.key_tag == 0
            && self.algorithm == SecAlgorithm(0)
            && self.digest_type == DigestType(0)
            && *self.digest == [0]
    }

    pub(super) fn decode(r: &mut Reader<'a>) -> Result<Self, DecodeError> {
        let key_tag = r.u16()?;
        let algorithm = SecAlgorithm(r.u8()?);
        let digest_type = DigestType(r.u8()?);
        let digest = r.rest();
        Self::new(key_tag, algorithm, digest_type, digest)
            .map_err(|_| r.error(DecodeErrorKind::Invalid("empty DS digest")))
    }

    pub(super) fn encode(&self, w: &mut Writer<'_>) -> Result<(), EncodeError> {
        w.put_u16(self.key_tag)?;
        w.put_u8(self.algorithm.into())?;
        w.put_u8(self.digest_type.into())?;
        w.put_bytes(&self.digest)
    }
}

impl Ds<'static> {
    /// Reads `key-tag algorithm digest-type digest`, the digest in hex with blanks allowed within (RFC 4034 §5.3).
    pub(super) fn from_text(f: &mut Fields<'_, '_>) -> Result<Self, TextError> {
        let key_tag = f.number("DS key tag")?;
        let algorithm = f.parse("DS algorithm")?;
        let digest_type = f.parse("DS digest type")?;
        let at = f.peek()?;
        // The delete form is written with a lone 0 as the digest (RFC 8078 §4).
        let digest = if (key_tag, algorithm, digest_type) == (0, SecAlgorithm(0), DigestType(0))
            && at.is_some_and(|t| t.raw == b"0")
        {
            f.next("DS digest")?;
            vec![0]
        } else {
            f.hex_rest("DS digest")?
        };
        Ds::new(key_tag, algorithm, digest_type, &digest)
            .map_err(|_| {
                let kind = TextErrorKind::Invalid("DS digest: 1 to 65531 bytes");
                at.map_or_else(|| f.end_error(kind), |t| t.error(kind))
            })
            .map(Ds::into_owned)
    }
}

/// `key-tag algorithm digest-type digest`, the algorithm and the digest type as numbers, the digest in hex.
impl fmt::Display for Ds<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{} {} {} {}",
            self.key_tag,
            u8::from(self.algorithm),
            u8::from(self.digest_type),
            Hex(&self.digest)
        )
    }
}
