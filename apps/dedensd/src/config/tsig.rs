//! The `keys` section (D211): the TSIG keys signed requests are verified with (RFC 8945), each a name, an algorithm
//! and a file holding the secret in base64. The files are read once, at start, before the privileges are dropped
//! (D122): a reload keeps the keys read then that its file still names, unchanged, and revokes the others.

use std::path::{Path, PathBuf};

use anyhow::{Context as _, ensure};
use dedens_proto::{Name, decode_base64};
use dedens_tsig::{Algorithm, Key, Keyring};
use serde::Deserialize;
use zeroize::Zeroizing;

use super::authoritative::Domain;
use super::keys::read_key;

/// The most keys: 1000 (D115). Each is a file read at start; a server signs with a key per peer or per updater,
/// a few dozen. Knot, NSD and BIND bound none.
pub(super) const MAX_KEYS: usize = 1000;

/// The most bytes a secret file holds: 1024, a secret of 765 bytes in base64, far past the 128-byte block of
/// SHA-512 over which HMAC hashes the key first (RFC 2104 §2); Knot's `keymgr -t` makes the hash's output, 20 to 64
/// bytes (`keymgr_generate_tsig`, `src/utils/keymgr/functions.c`).
const MAX_SECRET_FILE: usize = 1024;

/// A key, as written.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct KeyFile {
    /// The key's name, the owner of its TSIG records: both sides name it the same (RFC 8945 §4.2).
    name: Domain,
    /// The MAC algorithm: `hmac-sha1`, `hmac-sha256`, `hmac-sha384` or `hmac-sha512` (RFC 8945 §6, D205).
    #[serde(deserialize_with = "algorithm")]
    algorithm: Algorithm,
    /// The file holding the secret in base64 (RFC 4648 §4), alone: the `secret` that `keymgr -t` and `tsig-keygen`
    /// print, what `kdig -y` takes after the key's name.
    secret_file: PathBuf,
}

fn algorithm<'de, D: serde::Deserializer<'de>>(deserializer: D) -> Result<Algorithm, D::Error> {
    let text = String::deserialize(deserializer)?;
    text.parse().map_err(serde::de::Error::custom)
}

/// The file each key read at start came from, by the key's name, kept by the [`Store`](crate::lists::Store): what
/// a reload compares a key to, to tell it unchanged. The secrets are not read again after the drop (D122).
#[derive(Debug, Default)]
pub(crate) struct Origins(Vec<(Name<'static>, PathBuf)>);

impl Origins {
    /// Whether the key `name` was read from `file`.
    fn read_from(&self, name: &Name<'_>, file: &Path) -> bool {
        self.0
            .iter()
            .any(|(key, origin)| key == name && origin == file)
    }
}

/// The keys of `files`: read from their files at start, when `kept` is `None`, their files recorded in `origins`;
/// else those of `kept`, the keys of the running pipeline, that `files` still names with their algorithm and
/// their secret file as at start. A key `files` no longer names is revoked; one it adds or changes is not read
/// (a warning: it takes a restart).
///
/// # Errors
///
/// More than [`MAX_KEYS`] keys, a name given twice; at start, a file that cannot be read, others can access
/// (D115), longer than [`MAX_SECRET_FILE`] bytes or that is not base64 of a secret.
pub(super) fn keys(
    files: &[KeyFile],
    kept: Option<&Keyring>,
    origins: &mut Origins,
) -> anyhow::Result<Keyring> {
    ensure!(
        files.len() <= MAX_KEYS,
        "`keys` lists {} keys, over {MAX_KEYS}",
        files.len()
    );
    let Some(kept) = kept else {
        let keys = files.iter().map(read).collect::<anyhow::Result<Vec<_>>>()?;
        let keyring = Keyring::new(keys)?;
        origins.0 = (files.iter())
            .map(|file| (file.name.0.clone(), file.secret_file.clone()))
            .collect();
        return Ok(keyring);
    };
    let mut keys = Vec::with_capacity(files.len());
    for file in files {
        match kept.get(&file.name.0) {
            Some(key)
                if key.algorithm() == file.algorithm
                    && origins.read_from(&file.name.0, &file.secret_file) =>
            {
                keys.push(key.clone());
            }
            _ => tracing::warn!(
                key = %file.name.0,
                "a key added or changed in `keys` takes a restart: it is not read"
            ),
        }
    }
    Ok(Keyring::new(keys)?)
}

/// The key `file` describes, its secret read from its file.
fn read(file: &KeyFile) -> anyhow::Result<Key> {
    let setting = format!("`keys`, key `{}`", file.name.0);
    // One byte more than the most, to tell a file that is too long.
    let mut buffer = Zeroizing::new([0; MAX_SECRET_FILE + 1]);
    let text = read_key(&file.secret_file, &setting, &mut *buffer)?;
    // No part of the text in the error: it is the secret.
    let mut secret = decode_base64(text)
        .filter(|secret| !secret.is_empty())
        .map(Zeroizing::new)
        .with_context(|| {
            format!(
                "{setting}: {} holds no secret in base64",
                file.secret_file.display()
            )
        })?;
    if secret.len() < file.algorithm.mac_len() {
        // RFC 8945 §8: a secret at least as long as the hash's output; `keymgr -t` warns the same.
        tracing::warn!(
            key = %file.name.0,
            bytes = secret.len(),
            "TSIG secret shorter than the output of its algorithm"
        );
    }
    // Moved, not copied: the key wipes it on drop too.
    let secret = std::mem::take(&mut *secret);
    Ok(Key::new(file.name.0.clone(), file.algorithm, secret)?)
}
