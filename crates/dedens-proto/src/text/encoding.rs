//! Hex (RFC 3597 §5) and base64 (RFC 4648 §4, for the SVCB `ech` value) in presentation format.

use core::fmt;

const BASE64: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/// The value of each byte as a base64 character, `NOT_BASE64` for bytes outside the alphabet.
#[expect(
    clippy::cast_possible_truncation,
    reason = "indexes are below 64; `From` is not const"
)]
const BASE64_VALUES: [u8; 256] = {
    let mut values = [NOT_BASE64; 256];
    let mut i = 0;
    while i < BASE64.len() {
        values[BASE64[i] as usize] = i as u8;
        i += 1;
    }
    values
};
const NOT_BASE64: u8 = 0xFF;

/// Writes bytes as lowercase hex.
pub(crate) struct Hex<'b>(pub(crate) &'b [u8]);

impl fmt::Display for Hex<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.iter().try_for_each(|b| write!(f, "{b:02x}"))
    }
}

/// Appends the bytes of hex digits, any case, to `out`; `None` for an odd count or a non-hex byte.
pub(crate) fn decode_hex(text: &[u8], out: &mut Vec<u8>) -> Option<()> {
    let (pairs, odd) = text.as_chunks::<2>();
    if !odd.is_empty() {
        return None;
    }
    for &[high, low] in pairs {
        out.push(hex_digit(high)? << 4 | hex_digit(low)?);
    }
    Some(())
}

fn hex_digit(b: u8) -> Option<u8> {
    char::from(b)
        .to_digit(16)
        .and_then(|d| u8::try_from(d).ok())
}

/// Writes bytes as padded base64.
pub(crate) struct Base64<'b>(pub(crate) &'b [u8]);

impl fmt::Display for Base64<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for chunk in self.0.chunks(3) {
            let mut group = [0_u8; 3];
            group
                .get_mut(..chunk.len())
                .unwrap_or_default()
                .copy_from_slice(chunk);
            let bits = u32::from(group[0]) << 16 | u32::from(group[1]) << 8 | u32::from(group[2]);
            for i in 0..4 {
                if i <= chunk.len() {
                    let index = usize::try_from(bits >> (18 - 6 * i) & 0x3F).unwrap_or_default();
                    write!(f, "{}", char::from(BASE64[index]))?;
                } else {
                    f.write_str("=")?;
                }
            }
        }
        Ok(())
    }
}

/// Decodes padded base64; `None` unless the length is a multiple of four, every byte is of the alphabet, padding
/// only ends the text and the bits it leaves unused are zero, so that each byte string has one text
/// (RFC 4648 section 3.5).
pub(crate) fn decode_base64(text: &[u8]) -> Option<Vec<u8>> {
    let (groups, rest) = text.as_chunks::<4>();
    if !rest.is_empty() {
        return None;
    }
    let mut out = Vec::with_capacity(groups.len() * 3);
    for (i, group) in groups.iter().enumerate() {
        let pad = group.iter().rev().take_while(|&&b| b == b'=').count();
        if pad > 2 || (pad > 0 && i + 1 != groups.len()) {
            return None;
        }
        let mut bits = 0_u32;
        for &b in group.get(..4 - pad)? {
            let value = BASE64_VALUES[usize::from(b)];
            if value == NOT_BASE64 {
                return None;
            }
            bits = bits << 6 | u32::from(value);
        }
        // Each `=` leaves two bits of the last character unused.
        if bits & ((1 << (2 * pad)) - 1) != 0 {
            return None;
        }
        bits <<= 6 * pad;
        let bytes = bits.to_be_bytes();
        out.extend_from_slice(bytes.get(1..4 - pad)?);
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hex_round_trips() {
        let mut out = Vec::new();
        decode_hex(b"00aBff", &mut out).unwrap();
        assert_eq!(out, [0x00, 0xab, 0xff]);
        assert_eq!(Hex(&out).to_string(), "00abff");
        assert_eq!(decode_hex(b"abc", &mut out), None);
        assert_eq!(decode_hex(b"zz", &mut out), None);
    }

    #[test]
    fn base64_matches_rfc4648_vectors() {
        // RFC 4648 §10.
        for (plain, encoded) in [
            ("", ""),
            ("f", "Zg=="),
            ("fo", "Zm8="),
            ("foo", "Zm9v"),
            ("foob", "Zm9vYg=="),
            ("fooba", "Zm9vYmE="),
            ("foobar", "Zm9vYmFy"),
        ] {
            assert_eq!(Base64(plain.as_bytes()).to_string(), encoded);
            assert_eq!(decode_base64(encoded.as_bytes()).unwrap(), plain.as_bytes());
        }
        assert_eq!(decode_base64(b"Zg="), None);
        assert_eq!(decode_base64(b"Z==="), None);
        assert_eq!(decode_base64(b"Zg==Zm8="), None);
        assert_eq!(decode_base64(b"Zg!="), None);
        assert_eq!(decode_base64(b"Zh=="), None);
        assert_eq!(decode_base64(b"Zm9="), None);
    }
}
