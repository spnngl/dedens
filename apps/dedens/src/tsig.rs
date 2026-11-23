//! The TSIG key of `-y` and `-k` (D212): `[algorithm:]name:secret`, the secret in base64, as `kdig` reads it
//! (`src/libknot/tsig.c`, `knot_tsig_key_init`). The algorithm is `hmac-sha256` when left out, as in `kdig`.

use std::fs::File;
use std::io::Read as _;
use std::path::Path;

use anyhow::{Context, anyhow, ensure};
use dedens_proto::Name;
use dedens_tsig::{Algorithm, Key};

/// The most bytes read of a key file: the key's line is a name, an algorithm and a secret of the hash's size, far
/// under it.
const MAX_KEY_FILE: u64 = 4096;

/// The key `text` writes: the secret after the last `:`, the name before it, and before that, if there is a `:`,
/// the algorithm. A name without a trailing dot is absolute all the same.
///
/// # Errors
///
/// A text that is not `[algorithm:]name:secret`: no secret, an algorithm of D205 left out, a name that is not one, a
/// secret that is not base64 or is empty.
pub(crate) fn parse(text: &str) -> Result<Key, String> {
    let (rest, secret) = text.rsplit_once(':').ok_or("not [algorithm:]name:secret")?;
    let (algorithm, name) = match rest.split_once(':') {
        Some((algorithm, name)) => (
            algorithm.parse::<Algorithm>().map_err(|e| e.to_string())?,
            name,
        ),
        None => (Algorithm::HmacSha256, rest),
    };
    let name = name
        .parse::<Name<'_>>()
        .map_err(|e| format!("{name}: not a name: {e}"))?;
    Key::from_base64(name, algorithm, secret).map_err(|e| e.to_string())
}

/// The key of the first line of the file `path`, written as [`parse`] reads it.
///
/// # Errors
///
/// The file cannot be read, is longer than [`MAX_KEY_FILE`] bytes or has no key in its first line.
pub(crate) fn read(path: &Path) -> anyhow::Result<Key> {
    let shown = path.display();
    let mut text = String::new();
    File::open(path)
        .and_then(|file| file.take(MAX_KEY_FILE + 1).read_to_string(&mut text))
        .with_context(|| format!("cannot read {shown}"))?;
    ensure!(
        u64::try_from(text.len()).is_ok_and(|len| len <= MAX_KEY_FILE),
        "{shown}: longer than {MAX_KEY_FILE} bytes"
    );
    let line = text
        .lines()
        .next()
        .map(str::trim)
        .filter(|line| !line.is_empty());
    let line = line.ok_or_else(|| anyhow!("{shown}: no key"))?;
    parse(line).map_err(|error| anyhow!("{shown}: {error}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The secret of the key D203's captures are signed with (`dedens_testkit::authoritative::TSIG_KEY`).
    const SECRET: &str = "ZGVkZW5zIHRlc3Qga2V5IGZvciBUU0lHIGNhcHR1cmVzCg==";

    #[test]
    fn a_key_is_read_as_kdig_reads_it() {
        let named = parse(&format!("dedens-test-key:{SECRET}")).expect("a key");
        assert_eq!(named.name().to_string(), "dedens-test-key.");
        assert_eq!(named.algorithm(), Algorithm::HmacSha256);
        let sha512 = parse(&format!("hmac-sha512:k.example.:{SECRET}")).expect("a key");
        assert_eq!(sha512.algorithm(), Algorithm::HmacSha512);
        assert_eq!(sha512.name().to_string(), "k.example.");
    }

    #[test]
    fn what_is_no_key_is_refused() {
        for text in [
            "",
            "name",
            "name:",
            "name:not base64!",
            ":c2VjcmV0",
            "hmac-md5:name:c2VjcmV0",
            "x:y:name:c2VjcmV0",
        ] {
            assert!(parse(text).is_err(), "{text:?}");
        }
    }
}
