//! A secret key file: 64 hexadecimal digits (D79, D99), read with the permission check of D115.

use std::path::Path;

use anyhow::{bail, ensure};
use zeroize::Zeroizing;

use super::keys::read_key;

/// The bytes of a secret: a key's seed, as 64 hexadecimal digits (D79, D99).
pub(crate) const SECRET_LEN: usize = 32;

/// The most bytes a key file holds: [`SECRET_LEN`] bytes as digits and room for whitespace.
pub(crate) const KEY_FILE_MAX: usize = 4 * SECRET_LEN;

/// The secret in `file`: [`SECRET_LEN`] bytes as hexadecimal digits, surrounding whitespace aside. Read into a buffer
/// of its size, wiped on drop, so that no copy of the secret is left where a growing buffer was; a file others can
/// access is refused, one its group can access warned about ([`read_key`], D115).
pub(crate) fn read_secret(
    file: &Path,
    setting: &str,
) -> anyhow::Result<Zeroizing<[u8; SECRET_LEN]>> {
    let shown = file.display();
    // One byte more than the most, to tell a file that is too long.
    let mut buffer = Zeroizing::new([0; KEY_FILE_MAX + 1]);
    let (_, text) = read_key(file, setting, &mut *buffer)?;
    let (pairs, rest) = text.as_chunks::<2>();
    let mut secret = Zeroizing::new([0; SECRET_LEN]);
    ensure!(
        rest.is_empty() && pairs.len() == SECRET_LEN,
        "{setting}: the key {shown} is not {} hexadecimal digits",
        2 * SECRET_LEN
    );
    for (byte, &[high, low]) in secret.iter_mut().zip(pairs) {
        let (Some(high), Some(low)) = (digit(high), digit(low)) else {
            bail!("{setting}: the key {shown} has a character that is no hexadecimal digit");
        };
        *byte = high << 4 | low;
    }
    Ok(secret)
}

/// The value of the hexadecimal digit `digit`.
fn digit(digit: u8) -> Option<u8> {
    char::from(digit)
        .to_digit(16)
        .and_then(|value| u8::try_from(value).ok())
}
