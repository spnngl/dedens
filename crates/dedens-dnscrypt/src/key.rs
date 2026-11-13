//! X25519 keys of both ends, and the shared key each system derives from them.

use std::fmt;

use chacha20::cipher::array::Array as ChaChaArray;
use chacha20::{R20, hchacha};
use rand_core::CryptoRng;
use salsa20::cipher::array::Array as SalsaArray;
use salsa20::cipher::consts::U10;
use salsa20::hsalsa;
use subtle::ConstantTimeEq as _;
use zeroize::Zeroizing;

use crate::error::{LowOrderKey, SessionError};
use crate::system::EncryptionSystem;

/// Length of every key of this crate: X25519 public and secret keys, the shared key, Ed25519 keys and seeds.
pub const KEY_LEN: usize = 32;

/// An X25519 public key: the resolver's in a certificate, the client's in a query.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct PublicKey([u8; KEY_LEN]);

impl PublicKey {
    /// The key whose 32 bytes are `bytes`; any 32 bytes are a point of the curve's twist or of the curve.
    #[must_use]
    pub const fn from_bytes(bytes: [u8; KEY_LEN]) -> Self {
        Self(bytes)
    }

    /// The 32 bytes, as they go on the wire.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; KEY_LEN] {
        &self.0
    }
}

impl fmt::Debug for PublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "PublicKey(")?;
        self.0.iter().try_for_each(|byte| write!(f, "{byte:02x}"))?;
        write!(f, ")")
    }
}

/// An X25519 secret key, the 32 raw bytes an implementation stores (X25519 clamps them itself), wiped when
/// dropped.
pub struct SecretKey(Zeroizing<[u8; KEY_LEN]>);

impl SecretKey {
    /// The key of the 32 bytes `bytes`.
    #[must_use]
    pub fn from_bytes(bytes: [u8; KEY_LEN]) -> Self {
        Self(Zeroizing::new(bytes))
    }

    /// A fresh key from `rng`.
    ///
    /// A client makes one per query, or one for a while: the key identifies it to the resolver (draft, "Protocol
    /// Components": `<client-pk>`).
    #[must_use]
    pub fn generate(rng: &mut impl CryptoRng) -> Self {
        let mut bytes = Zeroizing::new([0; KEY_LEN]);
        rng.fill_bytes(bytes.as_mut());
        Self(bytes)
    }

    /// The public key, the base point multiplied by this key.
    #[must_use]
    pub fn public_key(&self) -> PublicKey {
        PublicKey(x25519_dalek::x25519(
            *self.0,
            x25519_dalek::X25519_BASEPOINT_BYTES,
        ))
    }

    /// The key `system` encrypts with, for this key and the other end's `peer` (draft, "Appendix 1",
    /// "Appendix 2": the shared key).
    ///
    /// One scalar multiplication: a caller that sees the same peer key again keeps the result.
    ///
    /// # Errors
    ///
    /// [`SessionError::LowOrderKey`] when `peer` is of low order, so that the shared point is all zero whatever
    /// this key is (draft, "Negative Cases"); [`SessionError::WrongSystem`] for X-Wing, whose shared key does not
    /// come from X25519 alone.
    pub fn shared_key(
        &self,
        system: EncryptionSystem,
        peer: &PublicKey,
    ) -> Result<SharedKey, SessionError> {
        let point = Zeroizing::new(x25519_dalek::x25519(*self.0, peer.0));
        if bool::from(point.ct_eq(&[0; KEY_LEN])) {
            return Err(LowOrderKey.into());
        }
        // The key schedule of NaCl's `crypto_box_beforenm`, with the system's hash: HSalsa20 or HChaCha20 of the
        // shared point and sixteen NUL bytes.
        let key = match system {
            EncryptionSystem::XSalsa20Poly1305 => <[u8; KEY_LEN]>::from(hsalsa::<U10>(
                &SalsaArray::from(*point),
                &SalsaArray::default(),
            )),
            EncryptionSystem::XChaCha20Poly1305 => <[u8; KEY_LEN]>::from(hchacha::<R20>(
                &ChaChaArray::from(*point),
                &ChaChaArray::default(),
            )),
            EncryptionSystem::XWing => return Err(SessionError::WrongSystem),
        };
        Ok(SharedKey {
            system,
            key: Zeroizing::new(key),
        })
    }
}

impl fmt::Debug for SecretKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SecretKey(..)")
    }
}

/// The key two ends share, with the system it was derived for; wiped when dropped.
///
/// Derived once per pair of keys: a client keeps one per resolver certificate, a resolver may keep one per client
/// key it sees again.
#[derive(Clone)]
pub struct SharedKey {
    system: EncryptionSystem,
    key: Zeroizing<[u8; KEY_LEN]>,
}

impl SharedKey {
    pub(crate) const fn new(system: EncryptionSystem, key: Zeroizing<[u8; KEY_LEN]>) -> Self {
        Self { system, key }
    }

    /// The system this key was derived for.
    #[must_use]
    pub const fn system(&self) -> EncryptionSystem {
        self.system
    }

    pub(crate) fn bytes(&self) -> &[u8; KEY_LEN] {
        &self.key
    }
}

impl fmt::Debug for SharedKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SharedKey")
            .field("system", &self.system)
            .finish_non_exhaustive()
    }
}
