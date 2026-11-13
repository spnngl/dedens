//! ISO/IEC 7816-4 padding: one 0x80 byte, then NUL bytes (draft "Padding For Client Queries Over UDP").

use ring::hmac;

use crate::NONCE_HALF_LEN;
use crate::error::PaddingError;
use crate::key::SharedKey;

/// The block the padded plaintexts are a multiple of when the budget allows.
pub(crate) const BLOCK: usize = 64;

/// Pads the message in `buf` with 0x80 and NUL bytes, so that it is `padded_len` bytes long; `buf` is left as
/// it was when it is already that long.
pub(crate) fn pad(buf: &mut Vec<u8>, padded_len: usize) {
    if buf.len() < padded_len {
        buf.push(0x80);
        buf.resize(padded_len, 0);
    }
}

/// The length of the message in `plaintext`, before its padding.
///
/// # Errors
///
/// [`PaddingError`] when the last byte that is not NUL is not 0x80, or when there is none.
pub(crate) fn unpadded_len(plaintext: &[u8]) -> Result<usize, PaddingError> {
    match plaintext.iter().rposition(|&byte| byte != 0) {
        Some(marker) if plaintext.get(marker) == Some(&0x80) => Ok(marker),
        _ => Err(PaddingError),
    }
}

/// How many bytes of padding take a message of `len` bytes to the next multiple of [`BLOCK`], then `extra_blocks`
/// blocks further: 1 to [`BLOCK`] for none, so that the 0x80 byte always fits, and 256 at most for 3.
pub(crate) const fn to_block(len: usize, extra_blocks: usize) -> usize {
    BLOCK - len % BLOCK + BLOCK * extra_blocks
}

/// The extra blocks of padding of a response, 0 to 3, a function of the shared key and the client nonce alone, so
/// that a query sent again gets a response padded the same (draft "Padding For Resolver Responses").
///
/// The low bits of an HMAC-SHA256 of a label and the nonce, under the shared key.
pub(crate) fn response_extra_blocks(key: &SharedKey, client_nonce: &[u8; NONCE_HALF_LEN]) -> usize {
    let key = hmac::Key::new(hmac::HMAC_SHA256, key.bytes());
    let mut context = hmac::Context::with_key(&key);
    context.update(b"dedens-dnscrypt response padding");
    context.update(client_nonce);
    context
        .sign()
        .as_ref()
        .first()
        .map_or(0, |&byte| usize::from(byte & 0b11))
}
