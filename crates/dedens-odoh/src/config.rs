//! `ObliviousDoHConfigs` (RFC 9230 §5): the public keys of targets, and the key ID of §6.1.

use crate::error::WireError;
use crate::kdf;
use crate::suite::{AEAD_ID, KDF_ID, KEM_ID};
use crate::wire::{Field, Reader};

/// The only `ObliviousDoHConfig.version` there is (RFC 9230 §5).
pub const VERSION: u16 = 0x0001;

/// The size of an X25519 public key (RFC 9180 §7.1), the one kind of key the suite of RFC 9230 §9 has.
pub const PUBLIC_KEY_LEN: usize = 32;

/// The size of a key ID, `Nh` of HKDF-SHA256 (RFC 9180 §7.2).
pub const KEY_ID_LEN: usize = 32;

/// `len(public_key)` as `ObliviousDoHConfigContents` writes it.
const PUBLIC_KEY_PREFIX: [u8; 2] = [0, 32];

/// `len(contents)` as `ObliviousDoHConfig` writes it: three identifiers, the prefix and the key.
const CONTENTS_PREFIX: [u8; 2] = [0, 40];

const _: () = assert!(PUBLIC_KEY_LEN == 32 && 3 * 2 + 2 + PUBLIC_KEY_LEN == 40);

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
pub struct ConfigContents {
    public_key: [u8; PUBLIC_KEY_LEN],
    key_id: [u8; KEY_ID_LEN],
}

impl ConfigContents {
    /// The contents for a target's public key; the key ID follows from them.
    #[must_use]
    pub fn new(public_key: [u8; PUBLIC_KEY_LEN]) -> Self {
        let mut contents = Self {
            public_key,
            key_id: [0; KEY_ID_LEN],
        };
        // `Expand(Extract("", config), "odoh key id", Nh)`, RFC 9230 §6.1.
        let prk = kdf::extract(&[], &contents.encode());
        contents.key_id = *kdf::expand(&prk, b"odoh key id");
        contents
    }

    /// Reads the contents of a config; `None` for one this crate cannot use: another suite, which RFC 9230
    /// §5 has clients ignore, or a malformed one (a field past its config, bytes after it, a key that is not
    /// 32 bytes). One bad config must not hide the others a target publishes.
    fn parse(bytes: &[u8]) -> Option<Self> {
        let mut reader = Reader::new(bytes);
        let suite = (reader.u16().ok()?, reader.u16().ok()?, reader.u16().ok()?);
        let public_key = reader.vec16().ok()?;
        reader.finish().ok()?;
        if suite != (KEM_ID, KDF_ID, AEAD_ID) {
            return None;
        }
        <[u8; PUBLIC_KEY_LEN]>::try_from(public_key)
            .ok()
            .map(Self::new)
    }

    /// The bytes of the structure, which the key ID hashes.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(8 + PUBLIC_KEY_LEN);
        for id in [KEM_ID, KDF_ID, AEAD_ID] {
            out.extend_from_slice(&id.to_be_bytes());
        }
        out.extend_from_slice(&PUBLIC_KEY_PREFIX);
        out.extend_from_slice(&self.public_key);
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
/// reduced to those this crate can use, and never empty when read.
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
/// clients, and so is a malformed one while the list itself is well framed. Skipped configs are not kept:
/// [`encode`](Self::encode) of what [`parse`](Self::parse) read writes the configs this crate can use, not a
/// copy of the input.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Configs {
    configs: Vec<ConfigContents>,
}

impl Configs {
    /// A list of configs, most preferred first.
    #[must_use]
    pub const fn new(configs: Vec<ConfigContents>) -> Self {
        Self { configs }
    }

    /// Reads a list of configs, as a target publishes it. How a client finds the list is out of scope of
    /// RFC 9230 (§5).
    ///
    /// # Errors
    ///
    /// A [`WireError`] when the list is empty, truncated, longer than its length or followed by other
    /// bytes, or when none of its configs is usable ([`WireError::NoUsableConfig`]).
    pub fn parse(bytes: &[u8]) -> Result<Self, WireError> {
        let mut outer = Reader::new(bytes);
        let list = outer.vec16()?;
        outer.finish()?;
        if list.is_empty() {
            return Err(WireError::EmptyField("ObliviousDoHConfigs"));
        }
        let mut reader = Reader::new(list);
        let mut configs = Vec::new();
        while !reader.is_empty() {
            let version = reader.u16()?;
            let contents = reader.vec16()?;
            if version == VERSION
                && let Some(contents) = ConfigContents::parse(contents)
            {
                configs.push(contents);
            }
        }
        if configs.is_empty() {
            return Err(WireError::NoUsableConfig);
        }
        Ok(Self { configs })
    }

    /// The bytes of the list.
    ///
    /// # Errors
    ///
    /// [`WireError::EmptyField`] for no config, [`WireError::FieldTooLong`] when they exceed 65535 bytes
    /// once written.
    pub fn encode(&self) -> Result<Vec<u8>, WireError> {
        let mut list = Vec::new();
        for contents in &self.configs {
            list.extend_from_slice(&VERSION.to_be_bytes());
            list.extend_from_slice(&CONTENTS_PREFIX);
            list.extend_from_slice(&contents.encode());
        }
        let mut out = Vec::new();
        Field::new("ObliviousDoHConfigs", list, 1)?.put(&mut out);
        Ok(out)
    }

    /// The usable configs, most preferred first.
    #[must_use]
    pub fn configs(&self) -> &[ConfigContents] {
        &self.configs
    }
}
