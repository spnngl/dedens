//! HKDF-SHA256 (RFC 5869) for the key ID (RFC 9230 §6.1) and the response keys (§6.2), on `ring`.

use ring::hkdf::{HKDF_SHA256, KeyType, Prk, Salt};

/// The length of the output of `Expand`, as `ring` wants it stated.
struct Len(usize);

impl KeyType for Len {
    fn len(&self) -> usize {
        self.0
    }
}

/// `Extract(salt, secret)`; an empty salt is the string of zeros of RFC 5869 §2.2.
pub(crate) fn extract(salt: &[u8], secret: &[u8]) -> Prk {
    Salt::new(HKDF_SHA256, salt).extract(secret)
}

/// `Expand(prk, info, N)`.
pub(crate) fn expand<const N: usize>(prk: &Prk, info: &[u8]) -> [u8; N] {
    let mut out = [0; N];
    prk.expand(&[info], Len(N))
        .and_then(|okm| okm.fill(&mut out))
        .expect("N is at most 255 times the 32 bytes of SHA-256");
    out
}
