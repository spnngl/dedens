//! X-Wing (draft-connolly-cfrg-xwing-kem), the KEM of `PQDNSCrypt`: the keys and the two operations, from the
//! `RustCrypto` `x-wing` crate (D101). The combiner, ML-KEM-768 and X25519 are the crate's, never ours.

use std::fmt;

use rand_core::CryptoRng;
use x_wing::{
    Decapsulate as _, DecapsulationKey, Decapsulator as _, Encapsulate as _, EncapsulationKey,
    KeyExport as _,
};
use zeroize::Zeroizing;

use crate::error::InvalidXWingKey;
use crate::key::KEY_LEN;

/// Length of an X-Wing encapsulation key, the `<resolver-pk>` of a PQ certificate.
pub const XWING_PUBLIC_KEY_LEN: usize = x_wing::ENCAPSULATION_KEY_SIZE;

/// Length of an X-Wing ciphertext, the `<client-pk>` of a PQ query.
pub const XWING_CIPHERTEXT_LEN: usize = x_wing::CIPHERTEXT_SIZE;

/// An X-Wing encapsulation key, the resolver's in a PQ certificate.
#[derive(Clone, PartialEq, Eq)]
pub struct XWingPublicKey {
    key: Box<EncapsulationKey>,
    bytes: Box<[u8; XWING_PUBLIC_KEY_LEN]>,
}

impl XWingPublicKey {
    /// The key of `bytes`.
    ///
    /// # Errors
    ///
    /// [`InvalidXWingKey`] when the ML-KEM part is not a valid encapsulation key (FIPS 203 §7.2).
    pub fn from_bytes(bytes: &[u8; XWING_PUBLIC_KEY_LEN]) -> Result<Self, InvalidXWingKey> {
        let key = EncapsulationKey::try_from(bytes.as_slice()).map_err(|_| InvalidXWingKey)?;
        Ok(Self {
            key: Box::new(key),
            bytes: Box::new(*bytes),
        })
    }

    /// The 1216 bytes, as they go in a certificate.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8; XWING_PUBLIC_KEY_LEN] {
        &self.bytes
    }

    /// A ciphertext for this key, and the secret it encapsulates: fresh randomness from `rng`.
    pub(crate) fn encapsulate(
        &self,
        rng: &mut impl CryptoRng,
    ) -> (Vec<u8>, Zeroizing<[u8; KEY_LEN]>) {
        let (ciphertext, secret) = self.key.encapsulate_with_rng(rng);
        (ciphertext.to_vec(), Zeroizing::new(secret.into()))
    }
}

impl fmt::Debug for XWingPublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("XWingPublicKey(..)")
    }
}

/// An X-Wing decapsulation key, the resolver's: the 32-byte seed the encapsulation key derives from, wiped when
/// dropped.
pub struct XWingSecretKey(Box<DecapsulationKey>);

impl XWingSecretKey {
    /// The key of the 32-byte seed `seed`.
    #[must_use]
    pub fn from_seed(seed: [u8; KEY_LEN]) -> Self {
        let seed = Zeroizing::new(seed);
        Self(Box::new(DecapsulationKey::from(*seed)))
    }

    /// A fresh key from `rng`.
    #[must_use]
    pub fn generate(rng: &mut impl CryptoRng) -> Self {
        let mut seed = Zeroizing::new([0; KEY_LEN]);
        rng.fill_bytes(seed.as_mut());
        Self::from_seed(*seed)
    }

    /// The encapsulation key of this key.
    #[must_use]
    pub fn public_key(&self) -> XWingPublicKey {
        let key = self.0.encapsulation_key().clone();
        let exported = key.to_bytes();
        let mut bytes = Box::new([0; XWING_PUBLIC_KEY_LEN]);
        bytes.copy_from_slice(&exported);
        XWingPublicKey {
            key: Box::new(key),
            bytes,
        }
    }

    /// The secret `ciphertext` encapsulates, or, for a ciphertext altered in transit, an unrelated one: X-Wing
    /// rejects implicitly, so that nothing tells the two apart but the failure of what the secret keys later.
    pub(crate) fn decapsulate(
        &self,
        ciphertext: &[u8; XWING_CIPHERTEXT_LEN],
    ) -> Zeroizing<[u8; KEY_LEN]> {
        let ciphertext = x_wing::Ciphertext::from(*ciphertext);
        Zeroizing::new(self.0.decapsulate(&ciphertext).into())
    }

    /// Whether `public` is the encapsulation key of this key.
    pub(crate) fn matches(&self, public: &XWingPublicKey) -> bool {
        self.0.encapsulation_key() == &*public.key
    }
}

impl fmt::Debug for XWingSecretKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("XWingSecretKey(..)")
    }
}
