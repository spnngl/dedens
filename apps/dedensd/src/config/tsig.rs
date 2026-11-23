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
use crate::lists::Stamp;

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

/// What a reload needs to tell a key read at start unchanged, by the key's name, kept by the
/// [`Store`](crate::lists::Store): the secret file, and its [`Stamp`] when it was read. The secrets are not read
/// again after the drop (D122), so a rewrite of the file in place shows in its stamp alone.
#[derive(Debug, Default)]
pub(crate) struct Origins(Vec<(Name<'static>, PathBuf, Stamp)>);

impl Origins {
    /// Whether the key `name` was read from `file`, which is still as it was then. A file that cannot be stat
    /// (gone, or its directory closed to the user the server runs as) is not: revoking is the fail-safe.
    fn unchanged(&self, name: &Name<'_>, file: &Path) -> bool {
        let read = (self.0.iter()).find(|(key, origin, _)| key == name && origin == file);
        let Some((_, _, read)) = read else {
            return false;
        };
        match Stamp::at(file) {
            Ok(now) => now == *read,
            Err(error) => {
                let file = file.display();
                tracing::warn!(key = %name, %file, %error, "cannot stat the secret file of a key");
                false
            }
        }
    }
}

/// The keys of a configuration: the [`Keyring`], and the names of the keys its `keys` lists that were not read.
#[derive(Debug)]
pub(super) struct Keys {
    pub(super) ring: Keyring,
    /// The keys a reload did not read: added, or changed (D211).
    skipped: Vec<Name<'static>>,
}

impl Keys {
    /// Whether `name` is listed in `keys` but was not read.
    pub(super) fn skipped(&self, name: &Name<'_>) -> bool {
        self.skipped.iter().any(|skipped| skipped == name)
    }
}

/// The keys of `files`: read from their files at start, when `kept` is `None`, their files and stamps recorded in
/// `origins`; else those of `kept`, the keys of the running pipeline, that `files` still names with their algorithm
/// and their secret file as at start, unchanged since (its [`Stamp`]). A key `files` no longer names, or whose
/// file changed, is revoked (a warning each); one it adds or changes is not read (a warning: it takes a restart).
///
/// # Errors
///
/// More than [`MAX_KEYS`] keys, a name given twice; at start, a file that cannot be read, others can access
/// (D115), longer than [`MAX_SECRET_FILE`] bytes or that is not base64 of a secret.
pub(super) fn keys(
    files: &[KeyFile],
    kept: Option<&Keyring>,
    origins: &mut Origins,
) -> anyhow::Result<Keys> {
    ensure!(
        files.len() <= MAX_KEYS,
        "`keys` lists {} keys, over {MAX_KEYS}",
        files.len()
    );
    let Some(kept) = kept else {
        let read = files.iter().map(read).collect::<anyhow::Result<Vec<_>>>()?;
        let (keys, stamps): (Vec<_>, Vec<_>) = read.into_iter().unzip();
        let ring = Keyring::new(keys)?;
        origins.0 = (files.iter().zip(stamps))
            .map(|(file, stamp)| (file.name.0.clone(), file.secret_file.clone(), stamp))
            .collect();
        return Ok(Keys {
            ring,
            skipped: Vec::new(),
        });
    };
    let mut keys = Vec::with_capacity(files.len());
    let mut skipped = Vec::new();
    for file in files {
        match kept.get(&file.name.0) {
            Some(key)
                if key.algorithm() == file.algorithm
                    && origins.unchanged(&file.name.0, &file.secret_file) =>
            {
                keys.push(key.clone());
            }
            _ => {
                tracing::warn!(
                    key = %file.name.0,
                    "a key added or changed in `keys` takes a restart: it is not read"
                );
                skipped.push(file.name.0.clone());
            }
        }
    }
    warn_revoked(files, kept, origins);
    Ok(Keys {
        ring: Keyring::new(keys)?,
        skipped,
    })
}

/// Warns of each key of `kept` that `files` no longer lists: it is revoked, and says so once, not at every reload.
fn warn_revoked(files: &[KeyFile], kept: &Keyring, origins: &Origins) {
    for (name, _, _) in &origins.0 {
        if kept.get(name).is_some() && !files.iter().any(|file| file.name.0 == *name) {
            tracing::warn!(key = %name, "a key `keys` no longer lists is revoked");
        }
    }
}

/// The key `file` describes, its secret read from its file, with the file's [`Stamp`].
fn read(file: &KeyFile) -> anyhow::Result<(Key, Stamp)> {
    let setting = format!("`keys`, key `{}`", file.name.0);
    // One byte more than the most, to tell a file that is too long.
    let mut buffer = Zeroizing::new([0; MAX_SECRET_FILE + 1]);
    let (stamp, text) = read_key(&file.secret_file, &setting, &mut *buffer)?;
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
    Ok((
        Key::new(file.name.0.clone(), file.algorithm, secret)?,
        stamp,
    ))
}
