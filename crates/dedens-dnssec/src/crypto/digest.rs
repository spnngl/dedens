//! DS digests (RFC 4034 §5.1.4, RFC 4509 §2, RFC 6605 §5) and NSEC3 hashes (RFC 5155 §5).

use dedens_proto::{DigestType, MAX_NAME_LEN, Name, Nsec3HashAlgorithm};
use ring::digest::{Algorithm, Context, MAX_OUTPUT_LEN, SHA1_FOR_LEGACY_USE_ONLY, SHA256, SHA384};
use thiserror::Error;

/// The digest algorithm of a DS record is not validated here (GOST, SM3, unknown): the delegation is insecure
/// (RFC 6840 §5.2), EDE 2.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
#[error("unsupported DS digest type {0}")]
pub struct UnsupportedDigest(pub DigestType);

/// The NSEC3 hash algorithm is not SHA-1, the only one defined (RFC 5155 §11): the zone is insecure
/// (RFC 5155 §8.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
#[error("unsupported NSEC3 hash algorithm {0}")]
pub struct UnsupportedNsec3Hash(pub Nsec3HashAlgorithm);

/// A DS digest: 20, 32 or 48 octets, held inline.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Digest {
    bytes: [u8; MAX_OUTPUT_LEN],
    len: usize,
}

impl AsRef<[u8]> for Digest {
    fn as_ref(&self) -> &[u8] {
        self.bytes.get(..self.len).unwrap_or_default()
    }
}

/// The algorithm of a DS digest type, if validated: SHA-1 (RFC 4034 §5.1.4; RFC 9905 keeps validating it),
/// SHA-256 (RFC 4509) and SHA-384 (RFC 6605 §5).
fn digest_algorithm(digest: DigestType) -> Option<&'static Algorithm> {
    match digest {
        DigestType::SHA1 => Some(&SHA1_FOR_LEGACY_USE_ONLY),
        DigestType::SHA256 => Some(&SHA256),
        DigestType::SHA384 => Some(&SHA384),
        _ => None,
    }
}

/// Whether [`ds_digest`] computes `digest` (RFC 6840 §5.2: a DS of another type is ignored, and the
/// delegation is insecure when no DS of a supported type is left).
#[must_use]
pub fn supported_digest(digest: DigestType) -> bool {
    digest_algorithm(digest).is_some()
}

/// The owner name in canonical wire form (RFC 4034 §6.2): uncompressed, ASCII letters lowercased. Length
/// octets are at most 63, below `A`, so lowercasing the whole wire form is exact.
struct CanonicalOwner {
    bytes: [u8; MAX_NAME_LEN],
    len: usize,
}

impl CanonicalOwner {
    fn new(owner: &Name<'_>) -> Self {
        let mut scratch = [0_u8; MAX_NAME_LEN];
        let wire = owner.to_wire(&mut scratch);
        let mut bytes = [0_u8; MAX_NAME_LEN];
        for (to, from) in bytes.iter_mut().zip(wire) {
            *to = from.to_ascii_lowercase();
        }
        Self {
            bytes,
            len: wire.len(),
        }
    }
}

impl AsRef<[u8]> for CanonicalOwner {
    fn as_ref(&self) -> &[u8] {
        self.bytes.get(..self.len).unwrap_or_default()
    }
}

/// The digest of a DNSKEY a DS record carries (RFC 4034 §5.1.4): `digest(owner | DNSKEY RDATA)`, the owner
/// in canonical wire form.
///
/// # Errors
///
/// [`UnsupportedDigest`] for a type [`supported_digest`] refuses.
pub fn ds_digest(
    digest: DigestType,
    owner: &Name<'_>,
    dnskey_rdata: &[u8],
) -> Result<Digest, UnsupportedDigest> {
    let algorithm = digest_algorithm(digest).ok_or(UnsupportedDigest(digest))?;
    let mut context = Context::new(algorithm);
    context.update(CanonicalOwner::new(owner).as_ref());
    context.update(dnskey_rdata);
    let hash = context.finish();
    let mut out = Digest {
        bytes: [0; MAX_OUTPUT_LEN],
        len: hash.as_ref().len(),
    };
    for (to, from) in out.bytes.iter_mut().zip(hash.as_ref()) {
        *to = *from;
    }
    Ok(out)
}

/// The NSEC3 hash of an owner name (RFC 5155 §5): SHA-1 of the canonical owner and the salt, then SHA-1 of
/// the previous hash and the salt, `iterations` more times. Always `iterations + 1` hashes: refusing a large
/// count is the caller's policy (RFC 9276 §3.2), and it spends its [`Budget`](super::Budget) first.
///
/// # Errors
///
/// [`UnsupportedNsec3Hash`] for an algorithm other than SHA-1.
pub fn nsec3_hash(
    algorithm: Nsec3HashAlgorithm,
    salt: &[u8],
    iterations: u16,
    owner: &Name<'_>,
) -> Result<[u8; 20], UnsupportedNsec3Hash> {
    if algorithm != Nsec3HashAlgorithm::SHA1 {
        return Err(UnsupportedNsec3Hash(algorithm));
    }
    Ok(nsec3_sha1(salt, iterations, owner))
}

/// [`nsec3_hash`] with SHA-1, the only algorithm RFC 5155 §11 defines; unpaid, for [`Budget`](super::Budget) to
/// call once it has spent the blocks.
pub(super) fn nsec3_sha1(salt: &[u8], iterations: u16, owner: &Name<'_>) -> [u8; 20] {
    let mut hash = sha1_of(CanonicalOwner::new(owner).as_ref(), salt);
    for _ in 0..iterations {
        hash = sha1_of(&hash, salt);
    }
    hash
}

/// `SHA-1(input | salt)`.
fn sha1_of(input: &[u8], salt: &[u8]) -> [u8; 20] {
    let mut context = Context::new(&SHA1_FOR_LEGACY_USE_ONLY);
    context.update(input);
    context.update(salt);
    let mut out = [0_u8; 20];
    for (to, from) in out.iter_mut().zip(context.finish().as_ref()) {
        *to = *from;
    }
    out
}
