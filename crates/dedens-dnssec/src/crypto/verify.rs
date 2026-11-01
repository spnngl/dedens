//! Signature verification: RSA (RFC 3110, 5702), ECDSA (RFC 6605) and Ed25519 (RFC 8080).

use dedens_proto::SecAlgorithm;
use ring::signature::{
    self, ECDSA_P256_SHA256_FIXED, ECDSA_P384_SHA384_FIXED, ED25519, RsaPublicKeyComponents,
    UnparsedPublicKey, VerificationAlgorithm,
};
use thiserror::Error;

/// Smallest and largest RSA modulus, in bits: the floor of `ring`'s `1024_8192` legacy verifiers (the 512-bit
/// keys of the RFC 5702 examples are refused) and the cap of RFC 3110 §2, below `ring`'s own 8192.
const RSA_MODULUS_BITS: std::ops::RangeInclusive<usize> = 1024..=4096;

/// `ring` refuses an RSA exponent of 2^33 or more.
const RSA_EXPONENT_LIMIT: u64 = 1 << 33;

/// Why [`verify`] did not accept a signature; 04 maps each to a verdict and an Extended DNS Error (RFC 8914).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum VerifyError {
    /// Not validated here (RFC 9904 §3, D71), so the data is insecure (RFC 6840 §5.2), EDE 1.
    #[error("unsupported DNSSEC algorithm {0}")]
    UnsupportedAlgorithm(SecAlgorithm),
    /// The public key is malformed or `ring` refuses it (RSA below 1024 bits, an even exponent): the key
    /// cannot validate anything.
    #[error("unusable public key")]
    UnusableKey,
    /// The key is usable and the signature does not match (EDE 6). `ring` reports a point off the curve and
    /// a mismatch alike, so a key of the right length on no curve ends here too.
    #[error("bad signature")]
    BadSignature,
}

/// How an algorithm's signatures are checked.
enum Scheme {
    /// PKCS#1 v1.5 (RFC 3110 §3, RFC 5702 §3) over an RFC 3110 §2 key.
    Rsa(&'static signature::RsaParameters),
    /// Fixed-width `r || s` over a key `x || y` of the given length (RFC 6605 §4, §5).
    Ecdsa {
        algorithm: &'static dyn VerificationAlgorithm,
        key_len: usize,
    },
    /// A 32-octet key and a 64-octet signature (RFC 8080 §3).
    Ed25519,
}

/// D71's policy: RSASHA1 (5), RSASHA1-NSEC3-SHA1 (7), RSASHA256 (8), RSASHA512 (10), ECDSAP256SHA256 (13),
/// ECDSAP384SHA384 (14) and ED25519 (15). RFC 9905 deprecates SHA-1 for signing but keeps validating it
/// (§2: "MUST continue to support"). Ed448 (16) is unsupported: `ring` lacks it.
fn scheme(algorithm: SecAlgorithm) -> Option<Scheme> {
    match algorithm {
        SecAlgorithm::RSASHA1 | SecAlgorithm::RSASHA1_NSEC3_SHA1 => Some(Scheme::Rsa(
            &signature::RSA_PKCS1_1024_8192_SHA1_FOR_LEGACY_USE_ONLY,
        )),
        SecAlgorithm::RSASHA256 => Some(Scheme::Rsa(
            &signature::RSA_PKCS1_1024_8192_SHA256_FOR_LEGACY_USE_ONLY,
        )),
        SecAlgorithm::RSASHA512 => Some(Scheme::Rsa(
            &signature::RSA_PKCS1_1024_8192_SHA512_FOR_LEGACY_USE_ONLY,
        )),
        SecAlgorithm::ECDSAP256SHA256 => Some(Scheme::Ecdsa {
            algorithm: &ECDSA_P256_SHA256_FIXED,
            key_len: 64,
        }),
        SecAlgorithm::ECDSAP384SHA384 => Some(Scheme::Ecdsa {
            algorithm: &ECDSA_P384_SHA384_FIXED,
            key_len: 96,
        }),
        SecAlgorithm::ED25519 => Some(Scheme::Ed25519),
        _ => None,
    }
}

/// Whether [`verify`] checks signatures of `algorithm` (RFC 6840 §5.2: a zone signed only with others is
/// insecure).
#[must_use]
pub fn supported(algorithm: SecAlgorithm) -> bool {
    scheme(algorithm).is_some()
}

/// Checks `signature` over `signed` with the DNSKEY public key field `public_key` (RFC 4034 §2.1.4).
///
/// `signed` is the RRSIG RDATA without its signature followed by the canonical `RRset` (RFC 4034 §3.1.8.1); the
/// caller builds it, and spends its [`Budget`](super::Budget) first.
///
/// # Errors
///
/// [`VerifyError`], telling an unsupported algorithm, a key that cannot be used and a signature that does not
/// match apart.
pub fn verify(
    algorithm: SecAlgorithm,
    public_key: &[u8],
    signed: &[u8],
    signature: &[u8],
) -> Result<(), VerifyError> {
    match scheme(algorithm).ok_or(VerifyError::UnsupportedAlgorithm(algorithm))? {
        Scheme::Rsa(parameters) => {
            let key = rsa_key(public_key).ok_or(VerifyError::UnusableKey)?;
            key.verify(parameters, signed, signature)
                .map_err(|_| VerifyError::BadSignature)
        }
        Scheme::Ecdsa { algorithm, key_len } => {
            if public_key.len() != key_len {
                return Err(VerifyError::UnusableKey);
            }
            // `ring` takes the uncompressed SEC1 point: 0x04 || x || y (RFC 6605 §4 stores x || y).
            let mut point = [0_u8; 1 + 96];
            let (tag, coordinates) = point.split_first_mut().ok_or(VerifyError::UnusableKey)?;
            *tag = 0x04;
            coordinates
                .get_mut(..key_len)
                .ok_or(VerifyError::UnusableKey)?
                .copy_from_slice(public_key);
            let point = point.get(..=key_len).ok_or(VerifyError::UnusableKey)?;
            UnparsedPublicKey::new(algorithm, point)
                .verify(signed, signature)
                .map_err(|_| VerifyError::BadSignature)
        }
        Scheme::Ed25519 => {
            if public_key.len() != 32 {
                return Err(VerifyError::UnusableKey);
            }
            UnparsedPublicKey::new(&ED25519, public_key)
                .verify(signed, signature)
                .map_err(|_| VerifyError::BadSignature)
        }
    }
}

/// Parses an RFC 3110 §2 key (exponent length in one octet, or a zero octet and two more; exponent; modulus)
/// and rejects what `ring` would, so that a refusal by `ring` afterwards means a bad signature.
fn rsa_key(public_key: &[u8]) -> Option<RsaPublicKeyComponents<&[u8]>> {
    let (&first, rest) = public_key.split_first()?;
    let (exponent_len, rest) = if first == 0 {
        let (len, rest) = rest.split_first_chunk::<2>()?;
        (usize::from(u16::from_be_bytes(*len)), rest)
    } else {
        (usize::from(first), rest)
    };
    let (e, n) = rest.split_at_checked(exponent_len)?;
    let (e, n) = (strip_leading_zeros(e), strip_leading_zeros(n));

    if e.len() > 8 {
        return None;
    }
    let exponent = e
        .iter()
        .fold(0_u64, |acc, &byte| (acc << 8) | u64::from(byte));
    let exponent_ok = exponent % 2 == 1 && (3..RSA_EXPONENT_LIMIT).contains(&exponent);
    let unused_top_bits = usize::try_from(n.first()?.leading_zeros()).ok()?;
    let modulus_bits = (n.len() * 8).checked_sub(unused_top_bits)?;
    let modulus_ok = RSA_MODULUS_BITS.contains(&modulus_bits) && n.last()? % 2 == 1;
    (exponent_ok && modulus_ok).then_some(RsaPublicKeyComponents { n, e })
}

fn strip_leading_zeros(bytes: &[u8]) -> &[u8] {
    let zeros = bytes.iter().take_while(|&&byte| byte == 0).count();
    bytes.get(zeros..).unwrap_or_default()
}
