//! Server Cookies (D113): the check of RFC 7873 §5.2, built as RFC 9018 §4 says, SipHash-2-4 version 1, so that
//! servers of other makes behind one anycast address verify each other's.
//!
//! A Server Cookie is 16 bytes: version 1, three reserved bytes, a timestamp, and the MAC of the Client Cookie, those
//! fields and the client's address under a secret (RFC 9018 §4.4). It weakly proves the source address of a query
//! and the Client Cookie, so a query carrying one is no spoofed-source flood and is not rate limited (D113).

use std::fmt;
use std::hash::Hasher as _;
use std::net::IpAddr;
use std::str::FromStr;

use dedens_proto::edns::Cookie;
use siphasher::sip::SipHasher24;
use zeroize::Zeroize as _;

use crate::metrics::Cookied;
use crate::validate::Clock;

/// The version of the Server Cookies made here (RFC 9018 §4.1).
const VERSION: u8 = 1;

/// The length of a version 1 Server Cookie (RFC 9018 §4): version, reserved, timestamp and hash.
const SERVER_LEN: usize = 16;

/// How old a Server Cookie may be, in seconds: RFC 9018 §4.3 says a period of 1 hour in the past.
const MAX_AGE: i32 = 3600;

/// How far ahead of our clock a timestamp may be, in seconds: RFC 9018 §4.3 says 5 minutes into the future, for
/// the skew between the servers of an anycast set.
const MAX_AHEAD: i32 = 300;

/// The secret of Server Cookies: 16 bytes (RFC 9018 §4.4). Its `Debug` text hides it.
#[derive(Clone)]
#[cfg_attr(
    feature = "serde",
    derive(serde::Deserialize),
    serde(try_from = "String")
)]
pub struct Secret([u8; 16]);

impl Secret {
    /// The secret made of `bytes`, which must come from a source of randomness, or the operator.
    #[must_use]
    pub const fn new(bytes: [u8; 16]) -> Self {
        Self(bytes)
    }
}

impl Drop for Secret {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

impl fmt::Debug for Secret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Secret(..)")
    }
}

/// A text that is no secret. It does not repeat the text, which may be one.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("a secret is 32 hexadecimal digits, as `openssl rand -hex 16` writes them")]
pub struct SecretError;

impl FromStr for Secret {
    type Err = SecretError;

    /// Reads 32 hexadecimal digits (RFC 9018 Appendix A writes its secrets so).
    fn from_str(text: &str) -> Result<Self, SecretError> {
        if text.len() != 2 * SERVER_LEN || !text.bytes().all(|b| b.is_ascii_hexdigit()) {
            return Err(SecretError);
        }
        let mut bytes = [0; 16];
        let (pairs, _) = text.as_bytes().as_chunks::<2>();
        for (byte, pair) in bytes.iter_mut().zip(pairs) {
            let pair = std::str::from_utf8(pair).map_err(|_| SecretError)?;
            *byte = u8::from_str_radix(pair, 16).map_err(|_| SecretError)?;
        }
        Ok(Self(bytes))
    }
}

impl TryFrom<String> for Secret {
    type Error = SecretError;

    fn try_from(text: String) -> Result<Self, SecretError> {
        text.parse()
    }
}

/// The secrets of Server Cookies (RFC 9018 §4.4, §5). A server alone at its address uses a random one it keeps
/// across reloads; the servers of an anycast set share secrets the operator rolls as §5 says: `current` makes the
/// cookies, and `current` and each of `accepted` verify them. Stage 1: the old secret is `current` and the new one
/// `accepted`; stage 2: the new one is `current` and the old one `accepted`; stage 3: no `accepted`.
#[derive(Debug, Clone)]
pub struct Secrets {
    current: Secret,
    accepted: Vec<Secret>,
}

impl Secrets {
    /// `current` makes the cookies; they verify under it and under each of `accepted`.
    #[must_use]
    pub const fn new(current: Secret, accepted: Vec<Secret>) -> Self {
        Self { current, accepted }
    }
}

/// What a query carries as to cookies (RFC 7873 §5.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Standing {
    /// No COOKIE option (§5.2.1).
    NoCookie,
    /// A Client Cookie alone (§5.2.3).
    ClientOnly,
    /// A Client Cookie and a Server Cookie that does not verify: unknown version, too old or too far ahead, made
    /// for another address or Client Cookie, under another secret, or not 16 bytes (§5.2.4).
    Invalid,
    /// A Client Cookie and a Server Cookie this server, or one sharing its secrets, made for the address (§5.2.5).
    Valid,
}

/// The making and checking of Server Cookies (D113).
pub struct Cookies {
    secrets: Secrets,
    clock: Clock,
    counted: Cookied,
}

impl fmt::Debug for Cookies {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Cookies")
            .field("secrets", &self.secrets)
            .finish_non_exhaustive()
    }
}

impl Cookies {
    /// Cookies under `secrets`, stamped and checked with `clock`, in seconds since the Unix epoch (the timestamp is
    /// that number modulo 2^32, compared by serial arithmetic, RFC 9018 §4.3). Counts what [`Cookies::verify`]
    /// sees with the `metrics` facade's recorder installed now.
    #[must_use]
    pub fn new(secrets: Secrets, clock: Clock) -> Self {
        Self {
            secrets,
            clock,
            counted: Cookied::new(),
        }
    }

    /// The Server Cookie for `client`, the Client Cookie of a query from `from`, stamped now (RFC 9018 §4).
    ///
    /// # Panics
    ///
    /// Never: a 16-byte Server Cookie is a valid length.
    #[must_use]
    pub fn issue(&self, client: [u8; 8], from: IpAddr) -> Cookie {
        let stamp = low32((self.clock)());
        let fields = [VERSION, 0, 0, 0];
        let hash = mac(&self.secrets.current, client, fields, stamp, from);
        let mut server = [0; SERVER_LEN];
        server[..4].copy_from_slice(&fields);
        server[4..8].copy_from_slice(&stamp.to_be_bytes());
        server[8..].copy_from_slice(&hash);
        Cookie::new(client, Some(&server)).expect("a Server Cookie of 16 bytes is valid")
    }

    /// What `cookie`, the first COOKIE option of a query from `from`, if any, says (RFC 7873 §5.2), counted.
    ///
    /// A Server Cookie is valid when it is 16 bytes of version 1, its timestamp is at most an hour old and five
    /// minutes ahead (RFC 9018 §4.3), and its hash is that of the Client Cookie, the version, reserved bytes and
    /// timestamp as received (they are not required to be zero, §4.2) and the address, under a secret (§4.4).
    #[must_use]
    pub fn verify(&self, cookie: Option<&Cookie>, from: IpAddr) -> Standing {
        let standing = self.standing(cookie, from);
        self.counted.count(standing);
        standing
    }

    fn standing(&self, cookie: Option<&Cookie>, from: IpAddr) -> Standing {
        let Some(cookie) = cookie else {
            return Standing::NoCookie;
        };
        let Some(server) = cookie.server() else {
            return Standing::ClientOnly;
        };
        let Ok(&[version, r1, r2, r3, t0, t1, t2, t3, ref hash @ ..]) =
            <&[u8; SERVER_LEN]>::try_from(server)
        else {
            return Standing::Invalid;
        };
        let stamp = u32::from_be_bytes([t0, t1, t2, t3]);
        // Serial arithmetic (RFC 1982): a difference above 2^31 is negative, the timestamp ahead of us.
        let age = low32((self.clock)()).wrapping_sub(stamp).cast_signed();
        if version != VERSION || !(-MAX_AHEAD..=MAX_AGE).contains(&age) {
            return Standing::Invalid;
        }
        let fields = [version, r1, r2, r3];
        let client = cookie.client();
        let verifies = |secret: &Secret| {
            let expected = mac(secret, client, fields, stamp, from);
            // Every byte compared, so the time taken says nothing of how many were right.
            hash.iter()
                .zip(expected)
                .fold(0, |different, (a, b)| different | (a ^ b))
                == 0
        };
        let Secrets { current, accepted } = &self.secrets;
        if verifies(current) || accepted.iter().any(verifies) {
            Standing::Valid
        } else {
            Standing::Invalid
        }
    }
}

/// The low 32 bits of `seconds`: a timestamp as RFC 9018 §4.3 has it.
fn low32(seconds: u64) -> u32 {
    let [a, b, c, d, ..] = seconds.to_le_bytes();
    u32::from_le_bytes([a, b, c, d])
}

/// The Hash Sub-Field (RFC 9018 §4.4): SipHash-2-4 of the Client Cookie, the first four bytes of the Server Cookie
/// (`fields`: version and reserved), its timestamp and the address of the client, 4 or 16 bytes, an IPv4-mapped
/// address as the IPv4 one (D91), keyed by `secret`; the 64-bit result as little-endian bytes, as the RFC's
/// implementations write it.
fn mac(secret: &Secret, client: [u8; 8], fields: [u8; 4], stamp: u32, from: IpAddr) -> [u8; 8] {
    let mut hasher = SipHasher24::new_with_key(&secret.0);
    hasher.write(&client);
    hasher.write(&fields);
    hasher.write(&stamp.to_be_bytes());
    match from.to_canonical() {
        IpAddr::V4(address) => hasher.write(&address.octets()),
        IpAddr::V6(address) => hasher.write(&address.octets()),
    }
    hasher.finish().to_le_bytes()
}
