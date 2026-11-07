//! NSEC3: hashed authenticated denial of existence (RFC 5155 §3), and NSEC3PARAM, the parameters a zone's NSEC3
//! records were made with (RFC 5155 §4).

use core::fmt;
use std::borrow::Cow;

use super::nsec::TypeBitmap;
use crate::codes::Nsec3HashAlgorithm;
use crate::error::{DecodeError, DecodeErrorKind, EncodeError};
use crate::text::encoding::{Base32Hex, decode_base32hex};
use crate::text::{Fields, Hex, TextError, TextErrorKind, decode_hex};
use crate::wire::{Reader, Writer};

/// A salt or a hash that does not fit the one-byte length in front of it (RFC 5155 §3.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum Nsec3Error {
    /// A salt of more than 255 bytes (RFC 5155 §3.2).
    #[error("NSEC3 salt must be at most 255 bytes")]
    SaltLength,
    /// A next hashed owner name of no bytes or of more than 255 (RFC 5155 §3.2).
    #[error("NSEC3 next hashed owner name must be 1 to 255 bytes")]
    HashLength,
}

/// The salt of NSEC3 records, of at most 255 bytes.
fn checked_salt(salt: &[u8]) -> Result<(), Nsec3Error> {
    if salt.len() > usize::from(u8::MAX) {
        return Err(Nsec3Error::SaltLength);
    }
    Ok(())
}

/// Reads a length byte and that many bytes.
fn length_prefixed<'a>(r: &mut Reader<'a>) -> Result<&'a [u8], DecodeError> {
    let len = usize::from(r.u8()?);
    r.bytes(len)
}

/// Writes `bytes` behind a length byte; they are at most 255 by construction.
fn put_length_prefixed(w: &mut Writer<'_>, bytes: &[u8]) -> Result<(), EncodeError> {
    w.put_u8(u8::try_from(bytes.len()).map_err(|_| EncodeError::BufferFull)?)?;
    w.put_bytes(bytes)
}

/// The salt in text: hex, or `-` for none (RFC 5155 §3.3).
struct Salt<'b>(&'b [u8]);

impl fmt::Display for Salt<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.0.is_empty() {
            f.write_str("-")
        } else {
            write!(f, "{}", Hex(self.0))
        }
    }
}

fn salt_from_text(f: &mut Fields<'_, '_>) -> Result<Vec<u8>, TextError> {
    let token = f.next("NSEC3 salt")?;
    let invalid = || {
        token.error(TextErrorKind::Invalid(
            "NSEC3 salt: hex or -, at most 255 bytes",
        ))
    };
    if token.raw == b"-" {
        return Ok(Vec::new());
    }
    let mut salt = Vec::new();
    decode_hex(token.raw, &mut salt).ok_or_else(invalid)?;
    if salt.is_empty() {
        return Err(invalid());
    }
    checked_salt(&salt).map_err(|_| invalid())?;
    Ok(salt)
}

/// An NSEC3 record (RFC 5155 §3): a link of the chain of hashed owner names, and the types at the name that hashes
/// to the record's owner.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Nsec3<'a> {
    /// How the owner names are hashed.
    pub hash_algorithm: Nsec3HashAlgorithm,
    /// The flags, whose bit [`Nsec3::OPT_OUT`] is the only one defined (RFC 5155 §3.1.2).
    pub flags: u8,
    /// How many times the hash is applied again (RFC 5155 §3.1.3).
    pub iterations: u16,
    /// The types of the `RRsets` at the original owner name.
    pub types: TypeBitmap<'a>,
    salt: Cow<'a, [u8]>,
    next_hashed_owner: Cow<'a, [u8]>,
}

impl<'a> Nsec3<'a> {
    /// The opt-out flag: the record may cover unsigned delegations (RFC 5155 §3.1.2.1).
    pub const OPT_OUT: u8 = 0x01;

    /// An NSEC3 record's data, borrowing `salt` and `next_hashed_owner`.
    ///
    /// # Errors
    ///
    /// [`Nsec3Error`] when `salt` is over 255 bytes, or `next_hashed_owner` is empty or over 255.
    pub fn new(
        hash_algorithm: Nsec3HashAlgorithm,
        flags: u8,
        iterations: u16,
        salt: &'a [u8],
        next_hashed_owner: &'a [u8],
        types: TypeBitmap<'a>,
    ) -> Result<Self, Nsec3Error> {
        checked_salt(salt)?;
        if !(1..=usize::from(u8::MAX)).contains(&next_hashed_owner.len()) {
            return Err(Nsec3Error::HashLength);
        }
        Ok(Self {
            hash_algorithm,
            flags,
            iterations,
            types,
            salt: Cow::Borrowed(salt),
            next_hashed_owner: Cow::Borrowed(next_hashed_owner),
        })
    }

    /// The same data, owning its bytes.
    #[must_use]
    pub fn into_owned(self) -> Nsec3<'static> {
        Nsec3 {
            hash_algorithm: self.hash_algorithm,
            flags: self.flags,
            iterations: self.iterations,
            types: self.types.into_owned(),
            salt: Cow::Owned(self.salt.into_owned()),
            next_hashed_owner: Cow::Owned(self.next_hashed_owner.into_owned()),
        }
    }

    /// Whether the opt-out flag is set.
    #[must_use]
    pub const fn is_opt_out(&self) -> bool {
        self.flags & Self::OPT_OUT != 0
    }

    /// The salt, which may be empty.
    #[must_use]
    pub fn salt(&self) -> &[u8] {
        &self.salt
    }

    /// The next hashed owner name in the zone's hash order, as the raw hash, not the base32hex of the text form.
    #[must_use]
    pub fn next_hashed_owner(&self) -> &[u8] {
        &self.next_hashed_owner
    }

    pub(super) fn decode(r: &mut Reader<'a>) -> Result<Self, DecodeError> {
        let hash_algorithm = Nsec3HashAlgorithm(r.u8()?);
        let flags = r.u8()?;
        let iterations = r.u16()?;
        let salt = length_prefixed(r)?;
        let next_hashed_owner = length_prefixed(r)?;
        let types = TypeBitmap::decode(r)?;
        Self::new(
            hash_algorithm,
            flags,
            iterations,
            salt,
            next_hashed_owner,
            types,
        )
        .map_err(|_| {
            r.error(DecodeErrorKind::Invalid(
                "empty NSEC3 next hashed owner name",
            ))
        })
    }

    pub(super) fn encode(&self, w: &mut Writer<'_>) -> Result<(), EncodeError> {
        w.put_u8(self.hash_algorithm.into())?;
        w.put_u8(self.flags)?;
        w.put_u16(self.iterations)?;
        put_length_prefixed(w, &self.salt)?;
        put_length_prefixed(w, &self.next_hashed_owner)?;
        self.types.encode(w)
    }
}

impl Nsec3<'static> {
    /// Reads `hash-algorithm flags iterations salt next-hashed-owner type...`.
    pub(super) fn from_text(f: &mut Fields<'_, '_>) -> Result<Self, TextError> {
        let hash_algorithm = f.parse("NSEC3 hash algorithm")?;
        let flags = f.number("NSEC3 flags")?;
        let iterations = f.number("NSEC3 iterations")?;
        let salt = salt_from_text(f)?;
        let owner = f.next("NSEC3 next hashed owner name")?;
        let next_hashed_owner = decode_base32hex(owner.raw)
            .filter(|hash| (1..=usize::from(u8::MAX)).contains(&hash.len()))
            .ok_or(owner.error(TextErrorKind::Invalid(
                "NSEC3 next hashed owner name: base32hex of 1 to 255 bytes",
            )))?;
        Ok(Nsec3 {
            hash_algorithm,
            flags,
            iterations,
            types: TypeBitmap::from_text(f)?,
            salt: Cow::Owned(salt),
            next_hashed_owner: Cow::Owned(next_hashed_owner),
        })
    }
}

/// `hash-algorithm flags iterations salt next-hashed-owner type...`: the algorithm as a number, the salt in hex or
/// `-`, the next hashed owner name in lowercase base32hex without padding, the types as mnemonics.
impl fmt::Display for Nsec3<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{} {} {} {} {}{}",
            u8::from(self.hash_algorithm),
            self.flags,
            self.iterations,
            Salt(&self.salt),
            Base32Hex(&self.next_hashed_owner),
            self.types
        )
    }
}

/// The parameters of a zone's NSEC3 records (RFC 5155 §4), which an authoritative server reads to make more.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Nsec3Param<'a> {
    /// How the owner names are hashed.
    pub hash_algorithm: Nsec3HashAlgorithm,
    /// The flags; a record with any set is ignored (RFC 5155 §4.1.2).
    pub flags: u8,
    /// How many times the hash is applied again.
    pub iterations: u16,
    salt: Cow<'a, [u8]>,
}

impl<'a> Nsec3Param<'a> {
    /// An NSEC3PARAM record's data, borrowing `salt`.
    ///
    /// # Errors
    ///
    /// [`Nsec3Error::SaltLength`] when `salt` is over 255 bytes.
    pub fn new(
        hash_algorithm: Nsec3HashAlgorithm,
        flags: u8,
        iterations: u16,
        salt: &'a [u8],
    ) -> Result<Self, Nsec3Error> {
        checked_salt(salt)?;
        Ok(Self {
            hash_algorithm,
            flags,
            iterations,
            salt: Cow::Borrowed(salt),
        })
    }

    /// The same data, owning its salt.
    #[must_use]
    pub fn into_owned(self) -> Nsec3Param<'static> {
        Nsec3Param {
            hash_algorithm: self.hash_algorithm,
            flags: self.flags,
            iterations: self.iterations,
            salt: Cow::Owned(self.salt.into_owned()),
        }
    }

    /// The salt, which may be empty.
    #[must_use]
    pub fn salt(&self) -> &[u8] {
        &self.salt
    }

    pub(super) fn decode(r: &mut Reader<'a>) -> Result<Self, DecodeError> {
        let hash_algorithm = Nsec3HashAlgorithm(r.u8()?);
        let flags = r.u8()?;
        let iterations = r.u16()?;
        let salt = length_prefixed(r)?;
        // At most 255 bytes, by the length byte.
        Self::new(hash_algorithm, flags, iterations, salt)
            .map_err(|_| r.error(DecodeErrorKind::Invalid("NSEC3PARAM salt too long")))
    }

    pub(super) fn encode(&self, w: &mut Writer<'_>) -> Result<(), EncodeError> {
        w.put_u8(self.hash_algorithm.into())?;
        w.put_u8(self.flags)?;
        w.put_u16(self.iterations)?;
        put_length_prefixed(w, &self.salt)
    }
}

impl Nsec3Param<'static> {
    /// Reads `hash-algorithm flags iterations salt`.
    pub(super) fn from_text(f: &mut Fields<'_, '_>) -> Result<Self, TextError> {
        Ok(Nsec3Param {
            hash_algorithm: f.parse("NSEC3PARAM hash algorithm")?,
            flags: f.number("NSEC3PARAM flags")?,
            iterations: f.number("NSEC3PARAM iterations")?,
            salt: Cow::Owned(salt_from_text(f)?),
        })
    }
}

/// `hash-algorithm flags iterations salt`: the algorithm as a number, the salt in hex or `-`.
impl fmt::Display for Nsec3Param<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{} {} {} {}",
            u8::from(self.hash_algorithm),
            self.flags,
            self.iterations,
            Salt(&self.salt)
        )
    }
}
