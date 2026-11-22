//! The MAC algorithms a key may use (RFC 8945 §6, D205).

use core::fmt;
use core::str::FromStr;

use dedens_proto::{MAX_NAME_LEN, Name};
use ring::hmac;

/// The shortest MAC a message may carry, whatever the algorithm (RFC 8945 §5.2.2.1).
pub(crate) const MIN_MAC_LEN: usize = 10;

/// An HMAC algorithm of TSIG.
///
/// `hmac-md5` is not here: RFC 8945 §6 makes it optional, and a key naming it gets the BADKEY of an algorithm
/// the server does not implement (§5.2.1). `hmac-sha1` is for interoperability only (§6).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum Algorithm {
    /// `hmac-sha1` (RFC 4635).
    HmacSha1,
    /// `hmac-sha256` (RFC 4635).
    HmacSha256,
    /// `hmac-sha384` (RFC 4635).
    HmacSha384,
    /// `hmac-sha512` (RFC 4635).
    HmacSha512,
}

impl Algorithm {
    const ALL: [Self; 4] = [
        Self::HmacSha1,
        Self::HmacSha256,
        Self::HmacSha384,
        Self::HmacSha512,
    ];

    /// The algorithm's name in lowercase wire form, as it goes in a TSIG record and in the MAC (RFC 8945 §4.3.3).
    #[must_use]
    pub const fn wire(self) -> &'static [u8] {
        match self {
            Self::HmacSha1 => b"\x09hmac-sha1\x00",
            Self::HmacSha256 => b"\x0bhmac-sha256\x00",
            Self::HmacSha384 => b"\x0bhmac-sha384\x00",
            Self::HmacSha512 => b"\x0bhmac-sha512\x00",
        }
    }

    /// The algorithm's name as a domain name.
    ///
    /// # Panics
    ///
    /// Never: `wire` holds valid names, which a test reads.
    #[must_use]
    pub fn name(self) -> Name<'static> {
        Name::from_uncompressed(self.wire()).expect("`wire` holds a valid name")
    }

    /// The algorithm that `name` names, in any case (RFC 8945 §4.2), if the crate has it.
    #[must_use]
    pub fn from_name(name: &Name<'_>) -> Option<Self> {
        let mut buf = [0; MAX_NAME_LEN];
        let wire = name.copy_wire(&mut buf);
        wire.make_ascii_lowercase();
        Self::ALL
            .into_iter()
            .find(|algorithm| algorithm.wire() == wire)
    }

    /// The bytes of a full MAC (RFC 8945 §5.2.2.1: the keyed hash's output length).
    #[must_use]
    pub const fn mac_len(self) -> usize {
        match self {
            Self::HmacSha1 => 20,
            Self::HmacSha256 => 32,
            Self::HmacSha384 => 48,
            Self::HmacSha512 => 64,
        }
    }

    /// The fewest bytes a MAC may have on the wire: the larger of 10 and half the output length (RFC 8945
    /// §5.2.2.1).
    #[must_use]
    pub fn min_mac_len(self) -> usize {
        (self.mac_len() / 2).max(MIN_MAC_LEN)
    }

    pub(crate) fn ring(self) -> hmac::Algorithm {
        match self {
            Self::HmacSha1 => hmac::HMAC_SHA1_FOR_LEGACY_USE_ONLY,
            Self::HmacSha256 => hmac::HMAC_SHA256,
            Self::HmacSha384 => hmac::HMAC_SHA384,
            Self::HmacSha512 => hmac::HMAC_SHA512,
        }
    }
}

/// The name without its root dot: `hmac-sha256`.
impl fmt::Display for Algorithm {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let wire = self.wire();
        f.write_str(&String::from_utf8_lossy(&wire[1..wire.len() - 1]))
    }
}

/// `hmac-sha256` or `hmac-sha256.`, in any case, as a configuration writes it.
impl FromStr for Algorithm {
    type Err = UnknownAlgorithm;

    fn from_str(text: &str) -> Result<Self, Self::Err> {
        let bare = text.strip_suffix('.').unwrap_or(text);
        Self::ALL
            .into_iter()
            .find(|algorithm| algorithm.to_string().eq_ignore_ascii_case(bare))
            .ok_or(UnknownAlgorithm)
    }
}

/// Text that is no algorithm of this crate.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("unknown TSIG algorithm: one of hmac-sha1, hmac-sha256, hmac-sha384, hmac-sha512")]
pub struct UnknownAlgorithm;
