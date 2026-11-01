//! HKDF-SHA256 (RFC 5869) for the key ID (RFC 9230 §6.1) and the response keys (§6.2), on `ring`'s HMAC.
//!
//! `Expand` is written for outputs of one hash block or less, which is all RFC 9230 asks (the key ID, 32
//! bytes; the response key, 16; its nonce, 12): the output is `HMAC(prk, info || 0x01)`, and no length can be
//! refused. `ring`'s HKDF would give the pseudorandom key as a `Prk` that cannot be wiped and an `expand` that
//! can fail.

use ring::hmac::{self, HMAC_SHA256};
use zeroize::Zeroizing;

/// The size of the output of HMAC-SHA256, `Nh` (RFC 9180 §7.2).
pub(crate) const HASH_LEN: usize = 32;

/// The pseudorandom key of `Extract`, wiped when dropped.
pub(crate) type Prk = Zeroizing<[u8; HASH_LEN]>;

/// `Extract(salt, secret)`; an empty salt is the string of zeros of RFC 5869 §2.2, which HMAC pads to the
/// same key.
pub(crate) fn extract(salt: &[u8], secret: &[u8]) -> Prk {
    let tag = hmac::sign(&hmac::Key::new(HMAC_SHA256, salt), secret);
    leading(tag.as_ref())
}

/// The first `N` bytes of `bytes`, zero-filled if there are fewer.
fn leading<const N: usize>(bytes: &[u8]) -> Zeroizing<[u8; N]> {
    let mut out = Zeroizing::new([0; N]);
    out.iter_mut()
        .zip(bytes)
        .for_each(|(out, byte)| *out = *byte);
    out
}

/// `Expand(prk, info, N)` for `N` of at most one block.
pub(crate) fn expand<const N: usize>(prk: &Prk, info: &[u8]) -> Zeroizing<[u8; N]> {
    const { assert!(N <= HASH_LEN) };
    let mut input = Zeroizing::new(info.to_vec());
    input.push(1);
    let tag = hmac::sign(&hmac::Key::new(HMAC_SHA256, prk.as_slice()), &input);
    leading(tag.as_ref())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// RFC 5869 Appendix A.1: the PRK, and the first block of the 42 bytes of OKM.
    #[test]
    fn matches_rfc_5869_test_case_1() {
        let salt: Vec<u8> = (0..=0x0c).collect();
        let info: Vec<u8> = (0xf0..=0xf9).collect();
        let prk = extract(&salt, &[0x0b; 22]);
        assert_eq!(
            prk.as_slice(),
            [
                0x07, 0x77, 0x09, 0x36, 0x2c, 0x2e, 0x32, 0xdf, 0x0d, 0xdc, 0x3f, 0x0d, 0xc4, 0x7b,
                0xba, 0x63, 0x90, 0xb6, 0xc7, 0x3b, 0xb5, 0x0f, 0x9c, 0x31, 0x22, 0xec, 0x84, 0x4a,
                0xd7, 0xc2, 0xb3, 0xe5,
            ]
        );
        let okm = expand::<HASH_LEN>(&prk, &info);
        assert_eq!(
            okm.as_slice(),
            [
                0x3c, 0xb2, 0x5f, 0x25, 0xfa, 0xac, 0xd5, 0x7a, 0x90, 0x43, 0x4f, 0x64, 0xd0, 0x36,
                0x2f, 0x2a, 0x2d, 0x2d, 0x0a, 0x90, 0xcf, 0x1a, 0x5a, 0x4c, 0x5d, 0xb0, 0x2d, 0x56,
                0xec, 0xc4, 0xc5, 0xbf,
            ]
        );
        assert_eq!(expand::<16>(&prk, &info).as_slice(), &okm[..16]);
    }
}
