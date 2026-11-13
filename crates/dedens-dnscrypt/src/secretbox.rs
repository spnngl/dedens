//! The secretbox both systems share: a stream cipher whose first 32 keystream bytes are the Poly1305 key, then the
//! message `XORed` with the rest, then the tag of the ciphertext (`NaCl`'s `crypto_secretbox`, draft "Appendix 1",
//! "Appendix 2").

use chacha20::XChaCha20;
use poly1305::Poly1305;
use poly1305::universal_hash::KeyInit as _;
use salsa20::XSalsa20;
use salsa20::cipher::{KeyIvInit as _, StreamCipher};
use subtle::ConstantTimeEq as _;
use zeroize::Zeroizing;

use crate::key::{KEY_LEN, SharedKey};
use crate::system::EncryptionSystem;

/// Length of the Poly1305 tag, which goes before the ciphertext.
pub(crate) const TAG_LEN: usize = 16;

/// Length of the nonce of both systems: 24 bytes.
pub(crate) const NONCE_LEN: usize = 24;

/// The tag did not match the ciphertext.
#[derive(Debug, Clone, Copy)]
pub(crate) struct Forged;

/// The AEAD nonce of a query: the client nonce, then 12 NUL bytes (draft "Protocol Components").
pub(crate) fn query_nonce(client_nonce: &[u8; NONCE_LEN / 2]) -> [u8; NONCE_LEN] {
    let mut nonce = [0; NONCE_LEN];
    nonce
        .iter_mut()
        .zip(client_nonce)
        .for_each(|(to, from)| *to = *from);
    nonce
}

/// Encrypts `buf` in place and returns the tag to put before it.
pub(crate) fn seal(key: &SharedKey, nonce: &[u8; NONCE_LEN], buf: &mut [u8]) -> [u8; TAG_LEN] {
    match key.system() {
        EncryptionSystem::XSalsa20Poly1305 => {
            seal_with(XSalsa20::new(&(*key.bytes()).into(), &(*nonce).into()), buf)
        }
        EncryptionSystem::XChaCha20Poly1305 => seal_with(
            XChaCha20::new(&(*key.bytes()).into(), &(*nonce).into()),
            buf,
        ),
    }
}

/// Checks `tag` over `buf`, the ciphertext, and decrypts it in place.
///
/// `buf` is left as it was when the tag does not match.
pub(crate) fn open(
    key: &SharedKey,
    nonce: &[u8; NONCE_LEN],
    tag: &[u8; TAG_LEN],
    buf: &mut [u8],
) -> Result<(), Forged> {
    match key.system() {
        EncryptionSystem::XSalsa20Poly1305 => open_with(
            XSalsa20::new(&(*key.bytes()).into(), &(*nonce).into()),
            tag,
            buf,
        ),
        EncryptionSystem::XChaCha20Poly1305 => open_with(
            XChaCha20::new(&(*key.bytes()).into(), &(*nonce).into()),
            tag,
            buf,
        ),
    }
}

/// The Poly1305 key: the first 32 bytes of the keystream, which are used for nothing else.
fn poly_key(cipher: &mut impl StreamCipher) -> Poly1305 {
    let mut block = Zeroizing::new([0; KEY_LEN]);
    cipher.apply_keystream(block.as_mut());
    Poly1305::new(<&poly1305::Key>::from(&*block))
}

fn seal_with(mut cipher: impl StreamCipher, buf: &mut [u8]) -> [u8; TAG_LEN] {
    let mac = poly_key(&mut cipher);
    cipher.apply_keystream(buf);
    mac.compute_unpadded(buf).into()
}

fn open_with(
    mut cipher: impl StreamCipher,
    tag: &[u8; TAG_LEN],
    buf: &mut [u8],
) -> Result<(), Forged> {
    let mac = poly_key(&mut cipher);
    let expected: [u8; TAG_LEN] = mac.compute_unpadded(buf).into();
    if !bool::from(expected.ct_eq(tag)) {
        return Err(Forged);
    }
    cipher.apply_keystream(buf);
    Ok(())
}
