//! Certificates: what a resolver publishes in TXT records for its provider name, signed by the provider's Ed25519
//! key (draft "Certificates").

use std::fmt;

use dedens_proto::rdata::{Txt, TxtError};
use ring::signature::{ED25519, Ed25519KeyPair, KeyPair as _, UnparsedPublicKey};

use crate::{
    error::{CertificateError, InvalidClientMagic, SigningKeyRejected},
    key::{KEY_LEN, PublicKey},
    system::{EncryptionSystem, SystemPolicy},
};

/// `<cert-magic>`: `DNSC`.
const CERT_MAGIC: [u8; 4] = *b"DNSC";

/// Length of an Ed25519 signature.
const SIGNATURE_LEN: usize = 64;

/// `<protocol-minor-version>`, the only one the draft defines.
const MINOR_VERSION: [u8; 2] = [0, 0];

/// The Anonymized `DNSCrypt` magic, `<anon-magic>`, whose first eight bytes a `<client-magic>` may not be.
const ANON_MAGIC_PREFIX: [u8; 8] = [0xff; 8];

/// The `<resume-magic>` of `PQDNSCrypt`'s stateless resumption: `PQResume`.
const RESUME_MAGIC: [u8; 8] = *b"PQResume";

/// The 8 bytes that open every query built from a certificate and tell the resolver which certificate, so which
/// secret key, the query is for (draft "Certificates": `<client-magic>`).
///
/// Never one the draft forbids: eight 0xff bytes, which an Anonymized `DNSCrypt` relay would read as its own prefix,
/// seven NUL bytes first, which look like QUIC (RFC 9000), and the `PQDNSCrypt` `<resume-magic>`.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct ClientMagic([u8; 8]);

impl ClientMagic {
    /// The 8 bytes, as they go on the wire.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 8] {
        &self.0
    }
}

impl TryFrom<[u8; 8]> for ClientMagic {
    type Error = InvalidClientMagic;

    fn try_from(bytes: [u8; 8]) -> Result<Self, InvalidClientMagic> {
        let leading_zeros = bytes.iter().take(7).all(|&byte| byte == 0);
        if bytes == ANON_MAGIC_PREFIX || bytes == RESUME_MAGIC || leading_zeros {
            return Err(InvalidClientMagic);
        }
        Ok(Self(bytes))
    }
}

impl fmt::Debug for ClientMagic {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "ClientMagic(")?;
        self.0.iter().try_for_each(|byte| write!(f, "{byte:02x}"))?;
        write!(f, ")")
    }
}

/// The interval a certificate is valid in, in Unix seconds, both ends included (draft "Certificates":
/// `<ts-start>`, `<ts-end>`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Validity {
    start: u32,
    end: u32,
}

impl Validity {
    /// The interval from `start` to `end`, both included.
    ///
    /// # Errors
    ///
    /// [`CertificateError::EmptyValidity`] when `start` is not strictly earlier than `end`: the draft says
    /// deployed clients reject those.
    pub const fn new(start: u32, end: u32) -> Result<Self, CertificateError> {
        if start < end {
            Ok(Self { start, end })
        } else {
            Err(CertificateError::EmptyValidity)
        }
    }

    /// The first second of validity.
    #[must_use]
    pub const fn start(&self) -> u32 {
        self.start
    }

    /// The last second of validity.
    #[must_use]
    pub const fn end(&self) -> u32 {
        self.end
    }

    /// Whether `now`, Unix seconds, is in the interval.
    #[must_use]
    pub fn contains(&self, now: u64) -> bool {
        u64::from(self.start) <= now && now <= u64::from(self.end)
    }
}

/// What a provider signs: all of a certificate but its signature and the fields before it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CertificateBody {
    /// The system queries built from this certificate use (`<es-version>`).
    pub system: EncryptionSystem,
    /// The resolver's short-term public key (`<resolver-pk>`).
    pub resolver_key: PublicKey,
    /// The magic of the queries (`<client-magic>`).
    pub client_magic: ClientMagic,
    /// Of two valid certificates, the client takes the higher serial (`<serial>`).
    pub serial: u32,
    /// The interval the certificate is valid in.
    pub validity: Validity,
    /// Bytes this version of the protocol does not define, signed with the rest and otherwise ignored
    /// (`<extensions>`).
    pub extensions: Vec<u8>,
}

impl CertificateBody {
    /// The bytes the signature covers: `<resolver-pk> <client-magic> <serial> <ts-start> <ts-end> <extensions>`.
    fn signed_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(KEY_LEN + 8 + 12 + self.extensions.len());
        bytes.extend_from_slice(self.resolver_key.as_bytes());
        bytes.extend_from_slice(self.client_magic.as_bytes());
        bytes.extend_from_slice(&self.serial.to_be_bytes());
        bytes.extend_from_slice(&self.validity.start.to_be_bytes());
        bytes.extend_from_slice(&self.validity.end.to_be_bytes());
        bytes.extend_from_slice(&self.extensions);
        bytes
    }
}

/// The provider's Ed25519 public key, known to the client beforehand (draft "Certificates"), which checks the
/// signature of every certificate.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ProviderKey([u8; KEY_LEN]);

impl ProviderKey {
    /// The key of 32 bytes.
    #[must_use]
    pub const fn from_bytes(bytes: [u8; KEY_LEN]) -> Self {
        Self(bytes)
    }

    /// The 32 bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; KEY_LEN] {
        &self.0
    }
}

/// The provider's Ed25519 secret key, which signs certificates, ideally off the resolver (draft "Certificates").
pub struct SigningKey {
    pair: Ed25519KeyPair,
    public: ProviderKey,
}

impl SigningKey {
    /// The key of the 32-byte seed `seed` (RFC 8032 §5.1.5).
    ///
    /// # Errors
    ///
    /// [`SigningKeyRejected`] when the crypto library refuses the seed.
    pub fn from_seed(seed: &[u8; KEY_LEN]) -> Result<Self, SigningKeyRejected> {
        let pair = Ed25519KeyPair::from_seed_unchecked(seed).map_err(|_| SigningKeyRejected)?;
        let public = <[u8; KEY_LEN]>::try_from(pair.public_key().as_ref())
            .map_err(|_| SigningKeyRejected)?;
        Ok(Self {
            pair,
            public: ProviderKey(public),
        })
    }

    /// The public key that verifies what this key signs.
    #[must_use]
    pub const fn provider_key(&self) -> ProviderKey {
        self.public
    }
}

impl fmt::Debug for SigningKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SigningKey(..)")
    }
}

/// A certificate whose signature was checked, or just made: its fields can be trusted for what they say.
///
/// Whether it is valid *now* is another question, see [`Certificate::is_valid_at`] and [`select`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Certificate {
    body: CertificateBody,
    wire: Vec<u8>,
}

impl Certificate {
    /// Reads a certificate and checks its signature with `provider`.
    ///
    /// A `<protocol-minor-version>` is read and not kept: the signature does not cover it, and this crate has
    /// nothing to do with it.
    ///
    /// # Errors
    ///
    /// [`CertificateError`]: [`UnsupportedSystem`](CertificateError::UnsupportedSystem) for a system this crate
    /// does not implement, whose `<resolver-pk>` it cannot find, and the others when a field is cut short or
    /// forbidden, or when the signature is not `provider`'s.
    pub fn parse(bytes: &[u8], provider: &ProviderKey) -> Result<Self, CertificateError> {
        let (magic, rest) = bytes
            .split_first_chunk()
            .ok_or(CertificateError::TooShort)?;
        if *magic != CERT_MAGIC {
            return Err(CertificateError::WrongMagic);
        }
        let (es_version, rest) = rest.split_first_chunk().ok_or(CertificateError::TooShort)?;
        let system = EncryptionSystem::from_es_version(*es_version).ok_or(
            CertificateError::UnsupportedSystem(u16::from_be_bytes(*es_version)),
        )?;
        let (_minor, rest) = rest
            .split_first_chunk::<2>()
            .ok_or(CertificateError::TooShort)?;
        let (signature, signed) = rest
            .split_first_chunk::<SIGNATURE_LEN>()
            .ok_or(CertificateError::TooShort)?;
        let (resolver_key, rest) = signed
            .split_first_chunk::<KEY_LEN>()
            .ok_or(CertificateError::TooShort)?;
        let (client_magic, rest) = rest.split_first_chunk().ok_or(CertificateError::TooShort)?;
        let (serial, rest) = rest.split_first_chunk().ok_or(CertificateError::TooShort)?;
        let (start, rest) = rest.split_first_chunk().ok_or(CertificateError::TooShort)?;
        let (end, extensions) = rest.split_first_chunk().ok_or(CertificateError::TooShort)?;

        let body = CertificateBody {
            system,
            resolver_key: PublicKey::from_bytes(*resolver_key),
            client_magic: ClientMagic::try_from(*client_magic)?,
            serial: u32::from_be_bytes(*serial),
            validity: Validity::new(u32::from_be_bytes(*start), u32::from_be_bytes(*end))?,
            extensions: extensions.to_vec(),
        };
        UnparsedPublicKey::new(&ED25519, provider.as_bytes())
            .verify(signed, signature)
            .map_err(|_| CertificateError::BadSignature)?;
        Ok(Self {
            body,
            wire: bytes.to_vec(),
        })
    }

    /// Reads the certificate of a TXT record: its character-strings, concatenated (draft "Certificates").
    ///
    /// # Errors
    ///
    /// As [`Certificate::parse`].
    pub fn from_txt(txt: &Txt<'_>, provider: &ProviderKey) -> Result<Self, CertificateError> {
        let bytes: Vec<u8> = txt.strings().flatten().copied().collect();
        Self::parse(&bytes, provider)
    }

    /// A certificate of `body` signed with `key`.
    #[must_use]
    pub fn sign(key: &SigningKey, body: CertificateBody) -> Self {
        let signed = body.signed_bytes();
        let signature = key.pair.sign(&signed);
        let mut wire = Vec::with_capacity(8 + SIGNATURE_LEN + signed.len());
        wire.extend_from_slice(&CERT_MAGIC);
        wire.extend_from_slice(&body.system.es_version());
        wire.extend_from_slice(&MINOR_VERSION);
        wire.extend_from_slice(signature.as_ref());
        wire.extend_from_slice(&signed);
        Self { body, wire }
    }

    /// The fields of the certificate.
    #[must_use]
    pub const fn body(&self) -> &CertificateBody {
        &self.body
    }

    /// The certificate as it is in a TXT record, from `<cert-magic>` on: 124 bytes without extensions.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.wire
    }

    /// The RDATA of a TXT record holding the certificate, in character-strings of at most 255 bytes.
    ///
    /// # Errors
    ///
    /// [`TxtError::TooLong`] when the extensions make the certificate too long for an RDATA.
    pub fn to_txt(&self) -> Result<Txt<'static>, TxtError> {
        Txt::new(self.wire.chunks(usize::from(u8::MAX)))
    }

    /// Whether `now`, in Unix seconds, is in the certificate's validity.
    #[must_use]
    pub fn is_valid_at(&self, now: u64) -> bool {
        self.body.validity.contains(now)
    }
}

/// The certificate a client builds its queries from: of the ones valid at `now`, the one of the system `policy`
/// ranks first, and of those the highest serial (draft "Certificates"). `None` when no certificate is valid and
/// allowed.
///
/// Of two certificates equal in rank and serial, the last one wins.
#[must_use]
pub fn select(
    certificates: &[Certificate],
    now: u64,
    policy: SystemPolicy,
) -> Option<&Certificate> {
    certificates
        .iter()
        .filter(|certificate| certificate.is_valid_at(now))
        .filter_map(|certificate| {
            let rank = policy.rank(certificate.body.system)?;
            Some((rank, certificate.body.serial, certificate))
        })
        .max_by_key(|&(rank, serial, _)| (rank, serial))
        .map(|(_, _, certificate)| certificate)
}
