//! The `keys` section (D211): the TSIG keys signed requests are verified with (RFC 8945), each a name, an algorithm
//! and a file holding the secret in base64. The files are read once, at start, before the privileges are dropped
//! (D122): a reload keeps the keys read then.

use std::path::PathBuf;

use anyhow::{Context as _, ensure};
use dedens_proto::decode_base64;
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

/// The keys of `files`: read from their files at start, when `kept` is `None`; else `kept`, the keys read at start,
/// with a warning when `files` names others, or algorithms that are not theirs.
///
/// # Errors
///
/// More than [`MAX_KEYS`] keys, a name given twice; at start, a file that cannot be read, others can access
/// (D115), longer than [`MAX_SECRET_FILE`] bytes or that is not base64 of a secret.
pub(super) fn keys(files: &[KeyFile], kept: Option<&Keyring>) -> anyhow::Result<Keyring> {
    ensure!(
        files.len() <= MAX_KEYS,
        "`keys` lists {} keys, over {MAX_KEYS}",
        files.len()
    );
    if let Some(kept) = kept {
        if differ(files, kept) {
            tracing::warn!("changes to `keys` take a restart: the keys read at start are kept");
        }
        return Ok(kept.clone());
    }
    let keys = files.iter().map(read).collect::<anyhow::Result<Vec<_>>>()?;
    Ok(Keyring::new(keys)?)
}

/// Whether `files` names other keys than `kept`, or other algorithms: the secrets are not read again.
fn differ(files: &[KeyFile], kept: &Keyring) -> bool {
    kept.len() != files.len()
        || (files.iter()).any(|file| {
            kept.get(&file.name.0)
                .is_none_or(|key| key.algorithm() != file.algorithm)
        })
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

#[cfg(test)]
mod tests {
    use super::*;

    fn file(name: &str, algorithm: Algorithm) -> KeyFile {
        KeyFile {
            name: Domain(name.parse().unwrap()),
            algorithm,
            secret_file: PathBuf::from("/nonexistent"),
        }
    }

    /// A reload names the keys read at start, or others: a name, an algorithm or a count that changed.
    #[test]
    fn the_keys_differ_by_name_algorithm_and_count() {
        let sha256 = Algorithm::HmacSha256;
        let kept = Keyring::new([
            Key::new("a.".parse().unwrap(), sha256, vec![1; 32]).unwrap(),
            Key::new("b.".parse().unwrap(), sha256, vec![2; 32]).unwrap(),
        ])
        .unwrap();
        assert!(!differ(&[file("B.", sha256), file("a.", sha256)], &kept));
        assert!(differ(&[file("a.", sha256)], &kept));
        assert!(differ(&[file("a.", sha256), file("c.", sha256)], &kept));
        assert!(differ(
            &[file("a.", sha256), file("b.", Algorithm::HmacSha512)],
            &kept
        ));
    }
}
