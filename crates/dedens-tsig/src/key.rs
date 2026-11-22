//! Keys and the set a server accepts (RFC 8945 §2, §5.2.1).

use core::fmt;
use std::collections::HashMap;

use dedens_proto::{MAX_NAME_LEN, Name, decode_base64};
use ring::hmac;
use zeroize::Zeroizing;

use crate::algorithm::Algorithm;

/// A key that does not make one.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum KeyError {
    /// A key with no secret signs nothing a stranger cannot.
    #[error("TSIG secret is empty")]
    EmptySecret,
    /// The secret is not base64 (RFC 4648 §4).
    #[error("TSIG secret is not base64")]
    Base64,
    /// Two keys of a [`Keyring`] have one name: a message names its key, which must be one.
    #[error("two TSIG keys are named {0}")]
    Duplicate(Name<'static>),
}

/// A shared secret with its name and algorithm (RFC 8945 §2).
///
/// The secret is wiped when the key drops, and `Debug` never shows it. The HMAC key `ring` derives from it for each
/// operation is not wiped: `ring` offers no way.
#[derive(Clone)]
pub struct Key {
    name: Name<'static>,
    algorithm: Algorithm,
    secret: Zeroizing<Vec<u8>>,
}

impl Key {
    /// A key from its secret's bytes.
    ///
    /// # Errors
    ///
    /// [`KeyError::EmptySecret`] when `secret` is empty.
    pub fn new(
        name: Name<'static>,
        algorithm: Algorithm,
        secret: Vec<u8>,
    ) -> Result<Self, KeyError> {
        let secret = Zeroizing::new(secret);
        if secret.is_empty() {
            return Err(KeyError::EmptySecret);
        }
        Ok(Self {
            name,
            algorithm,
            secret,
        })
    }

    /// A key from its secret in base64, as `kdig -y` and Knot's configuration write it.
    ///
    /// # Errors
    ///
    /// [`KeyError::Base64`] when `secret` is not base64, [`KeyError::EmptySecret`] when it decodes to nothing.
    pub fn from_base64(
        name: Name<'static>,
        algorithm: Algorithm,
        secret: &str,
    ) -> Result<Self, KeyError> {
        let bytes = decode_base64(secret.trim().as_bytes()).ok_or(KeyError::Base64)?;
        Self::new(name, algorithm, bytes)
    }

    /// The key's name, the owner of its TSIG records.
    #[must_use]
    pub const fn name(&self) -> &Name<'static> {
        &self.name
    }

    /// The key's algorithm.
    #[must_use]
    pub const fn algorithm(&self) -> Algorithm {
        self.algorithm
    }

    pub(crate) fn hmac(&self) -> hmac::Key {
        hmac::Key::new(self.algorithm.ring(), &self.secret)
    }
}

impl fmt::Debug for Key {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Key")
            .field("name", &self.name)
            .field("algorithm", &self.algorithm)
            .finish_non_exhaustive()
    }
}

/// The keys a server accepts, found by name.
#[derive(Debug, Clone, Default)]
pub struct Keyring {
    keys: HashMap<Box<[u8]>, Key>,
}

impl Keyring {
    /// A keyring of `keys`.
    ///
    /// # Errors
    ///
    /// [`KeyError::Duplicate`] when two keys have the same name, which compares without case (RFC 8945 §4.3.3).
    pub fn new(keys: impl IntoIterator<Item = Key>) -> Result<Self, KeyError> {
        let mut ring = Self::default();
        for key in keys {
            let mut buf = [0; MAX_NAME_LEN];
            let index = canonical(&key.name, &mut buf).into();
            if ring.keys.contains_key(&index) {
                return Err(KeyError::Duplicate(key.name));
            }
            ring.keys.insert(index, key);
        }
        Ok(ring)
    }

    /// The key named `name`, in any case.
    #[must_use]
    pub fn get(&self, name: &Name<'_>) -> Option<&Key> {
        self.keys
            .get(canonical(name, &mut [0; MAX_NAME_LEN]) as &[u8])
    }

    /// How many keys.
    #[must_use]
    pub fn len(&self) -> usize {
        self.keys.len()
    }

    /// Whether there is no key.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.keys.is_empty()
    }
}

/// The name's wire form in lowercase, the canonical form of RFC 8945 §4.3.3 (RFC 4034 §6.2): a label's length is
/// under 64, so no byte of a length is an upper case letter.
pub(crate) fn canonical<'b>(name: &Name<'_>, buf: &'b mut [u8; MAX_NAME_LEN]) -> &'b [u8] {
    let wire = name.copy_wire(buf);
    wire.make_ascii_lowercase();
    wire
}
