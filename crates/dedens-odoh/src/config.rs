//! `ObliviousDoHConfigs` (RFC 9230 §5): the public keys of targets, and the key ID of §6.1.

use crate::error::WireError;
use crate::kdf;
use crate::suite::{AEAD_ID, KDF_ID, KEM_ID};
use crate::wire::{Reader, check_vec16, put_vec16};

/// The only `ObliviousDoHConfig.version` there is (RFC 9230 §5).
pub const VERSION: u16 = 0x0001;

/// The size of an X25519 public key (RFC 9180 §7.1), the one kind of key the suite of RFC 9230 §9 has.
pub const PUBLIC_KEY_LEN: usize = 32;

/// The size of a key ID, `Nh` of HKDF-SHA256 (RFC 9180 §7.2).
pub const KEY_ID_LEN: usize = 32;

/// `ObliviousDoHConfigContents` (RFC 9230 §5) of the one suite this crate speaks: a target's X25519 public
/// key, for DHKEM(X25519, HKDF-SHA256), HKDF-SHA256 and AES-128-GCM.
///
/// ```text
/// struct {
///    uint16 kem_id;
///    uint16 kdf_id;
///    uint16 aead_id;
///    opaque public_key<1..2^16-1>;
/// } ObliviousDoHConfigContents;
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ObliviousDoHConfigContents {
    public_key: [u8; PUBLIC_KEY_LEN],
    key_id: [u8; KEY_ID_LEN],
}

impl ObliviousDoHConfigContents {
    /// The contents for a target's public key; the key ID follows from them.
    #[must_use]
    pub fn new(public_key: [u8; PUBLIC_KEY_LEN]) -> Self {
        let mut contents = Self {
            public_key,
            key_id: [0; KEY_ID_LEN],
        };
        // `Expand(Extract("", config), "odoh key id", Nh)`, RFC 9230 §6.1.
        let prk = kdf::extract(&[], &contents.encode());
        contents.key_id = kdf::expand(&prk, b"odoh key id");
        contents
    }

    /// Reads the contents of a config; `None` for a suite other than ours, which RFC 9230 §5 has clients
    /// ignore. The structure is checked all the same.
    fn parse(bytes: &[u8]) -> Result<Option<Self>, WireError> {
        let mut reader = Reader::new(bytes);
        let suite = (reader.u16()?, reader.u16()?, reader.u16()?);
        let public_key = reader.vec16()?;
        reader.finish()?;
        check_vec16("public_key", public_key, 1)?;
        if suite != (KEM_ID, KDF_ID, AEAD_ID) {
            return Ok(None);
        }
        <[u8; PUBLIC_KEY_LEN]>::try_from(public_key)
            .map(|key| Some(Self::new(key)))
            .map_err(|_| WireError::PublicKeyLength(public_key.len()))
    }

    /// The bytes of the structure, which the key ID hashes.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(8 + PUBLIC_KEY_LEN);
        for id in [KEM_ID, KDF_ID, AEAD_ID] {
            out.extend_from_slice(&id.to_be_bytes());
        }
        put_vec16(&mut out, &self.public_key);
        out
    }

    /// The X25519 public key.
    #[must_use]
    pub const fn public_key(&self) -> &[u8; PUBLIC_KEY_LEN] {
        &self.public_key
    }

    /// The identifier a query carries to name this key (RFC 9230 §6.1).
    #[must_use]
    pub const fn key_id(&self) -> &[u8; KEY_ID_LEN] {
        &self.key_id
    }
}

/// `ObliviousDoHConfigs` (RFC 9230 §5): the configs a target publishes, in decreasing order of preference,
/// reduced to those this crate can use.
///
/// ```text
/// struct {
///    uint16 version;
///    uint16 length;
///    select (ObliviousDoHConfig.version) {
///       case 0x0001: ObliviousDoHConfigContents contents;
///    }
/// } ObliviousDoHConfig;
///
/// ObliviousDoHConfig ObliviousDoHConfigs<1..2^16-1>;
/// ```
///
/// A config of another version, or of another KEM, KDF or AEAD, is skipped when reading, as §5 tells
/// clients: the list may then be empty. Skipped configs are not kept, so [`encode`](Self::encode) writes
/// the ones this crate can use, not a copy of the input.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ObliviousDoHConfigs {
    configs: Vec<ObliviousDoHConfigContents>,
}

impl ObliviousDoHConfigs {
    /// A list of configs, most preferred first.
    #[must_use]
    pub const fn new(configs: Vec<ObliviousDoHConfigContents>) -> Self {
        Self { configs }
    }

    /// Reads the body of `/.well-known/odohconfigs` or the value of an `odohconfig` `SvcParam`.
    ///
    /// # Errors
    ///
    /// A [`WireError`] when the list is empty, truncated, longer than its length or followed by other
    /// bytes, or when a config is: a field running past its config, a config using our suite whose key is
    /// not 32 bytes.
    pub fn parse(bytes: &[u8]) -> Result<Self, WireError> {
        let mut outer = Reader::new(bytes);
        let list = outer.vec16()?;
        outer.finish()?;
        check_vec16("ObliviousDoHConfigs", list, 1)?;
        let mut reader = Reader::new(list);
        let mut configs = Vec::new();
        while !reader.is_empty() {
            let version = reader.u16()?;
            let contents = reader.vec16()?;
            if version == VERSION
                && let Some(contents) = ObliviousDoHConfigContents::parse(contents)?
            {
                configs.push(contents);
            }
        }
        Ok(Self { configs })
    }

    /// The bytes of the list, version 1 configs only.
    ///
    /// # Errors
    ///
    /// [`WireError::EmptyField`] for no config, [`WireError::FieldTooLong`] when they exceed 65535 bytes
    /// once written.
    pub fn encode(&self) -> Result<Vec<u8>, WireError> {
        let mut list = Vec::new();
        for contents in &self.configs {
            list.extend_from_slice(&VERSION.to_be_bytes());
            put_vec16(&mut list, &contents.encode());
        }
        check_vec16("ObliviousDoHConfigs", &list, 1)?;
        let mut out = Vec::with_capacity(2 + list.len());
        put_vec16(&mut out, &list);
        Ok(out)
    }

    /// The usable configs, most preferred first; empty when the target offers none this crate speaks.
    #[must_use]
    pub fn configs(&self) -> &[ObliviousDoHConfigContents] {
        &self.configs
    }
}
