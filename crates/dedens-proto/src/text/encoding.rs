//! Hex (RFC 3597 §5), base64 (RFC 4648 §4: the SVCB `ech` value, DNSSEC keys and signatures), unpadded base64url
//! (§5: the `dns` variable of `DoH`, RFC 8484 §6) and base32hex (§7: NSEC3 hashes, RFC 5155 §3.3) in presentation
//! format.

use core::fmt;

const BASE32HEX: &[u8; 32] = b"0123456789abcdefghijklmnopqrstuv";

const BASE64: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
const BASE64URL: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

/// The value of each byte as a base64 character, `NOT_BASE64` for bytes outside the alphabet.
const BASE64_VALUES: [u8; 256] = values_of(BASE64);
/// As [`BASE64_VALUES`], for the URL-safe alphabet.
const BASE64URL_VALUES: [u8; 256] = values_of(BASE64URL);
const NOT_BASE64: u8 = 0xFF;

#[expect(
    clippy::cast_possible_truncation,
    reason = "indexes are below 64; `From` is not const"
)]
const fn values_of(alphabet: &[u8; 64]) -> [u8; 256] {
    let mut values = [NOT_BASE64; 256];
    let mut i = 0;
    while i < alphabet.len() {
        values[alphabet[i] as usize] = i as u8;
        i += 1;
    }
    values
}

/// Writes bytes as lowercase hex, as the generic RDATA form does (RFC 3597 §5).
pub struct Hex<'b>(pub &'b [u8]);

impl fmt::Display for Hex<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.iter().try_for_each(|b| write!(f, "{b:02x}"))
    }
}

/// Appends the bytes of hex digits, any case, to `out` (RFC 3597 §5); `None` for an odd count or a non-hex byte.
pub fn decode_hex(text: &[u8], out: &mut Vec<u8>) -> Option<()> {
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

/// Writes bytes as lowercase base32hex without padding (RFC 4648 §7, RFC 5155 §3.3).
pub(crate) struct Base32Hex<'b>(pub(crate) &'b [u8]);

impl fmt::Display for Base32Hex<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // `acc` holds the `bits` bits not written yet.
        let (mut acc, mut bits) = (0_u32, 0_u32);
        let digit = |f: &mut fmt::Formatter<'_>, value: u32| {
            let index = usize::try_from(value & 0x1F).unwrap_or_default();
            write!(f, "{}", char::from(BASE32HEX[index]))
        };
        for &b in self.0 {
            acc = acc << 8 | u32::from(b);
            bits += 8;
            while bits >= 5 {
                bits -= 5;
                digit(f, acc >> bits)?;
            }
            acc &= (1 << bits) - 1;
        }
        if bits > 0 {
            digit(f, acc << (5 - bits))?;
        }
        Ok(())
    }
}

/// Decodes unpadded base32hex, any case; `None` for a byte outside the alphabet, a length no byte string has, or
/// unused bits that are not zero, so that each byte string has one text.
pub(crate) fn decode_base32hex(text: &[u8]) -> Option<Vec<u8>> {
    let mut out = Vec::with_capacity(text.len() * 5 / 8);
    let (mut acc, mut bits) = (0_u32, 0_u32);
    for &c in text {
        acc = acc << 5 | char::from(c).to_digit(32)?;
        bits += 5;
        if bits >= 8 {
            bits -= 8;
            out.push(u8::try_from(acc >> bits).ok()?);
            acc &= (1 << bits) - 1;
        }
    }
    (bits < 5 && acc == 0).then_some(out)
}

/// Writes bytes as base64url without padding (RFC 4648 §5): the text of a byte string is one, and has no `=`.
#[must_use]
pub fn encode_base64url(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for chunk in bytes.chunks(3) {
        let mut group = [0_u8; 3];
        group
            .get_mut(..chunk.len())
            .unwrap_or_default()
            .copy_from_slice(chunk);
        let bits = u32::from(group[0]) << 16 | u32::from(group[1]) << 8 | u32::from(group[2]);
        // A chunk of n bytes makes n + 1 characters.
        for i in 0..=chunk.len() {
            let index = usize::try_from(bits >> (18 - 6 * i) & 0x3F).unwrap_or_default();
            out.push(char::from(BASE64URL[index]));
        }
    }
    out
}

/// Decodes base64url without padding; `None` unless every byte is of the alphabet (no `=`, no `+` or `/`), the
/// length is not one more than a multiple of four, and the bits the last character leaves unused are zero, so that
/// each byte string has one text (RFC 4648 §3.5, §5).
#[must_use]
pub fn decode_base64url(text: &[u8]) -> Option<Vec<u8>> {
    let (groups, rest) = text.as_chunks::<4>();
    let mut out = Vec::with_capacity(groups.len() * 3 + 2);
    for group in groups {
        out.extend_from_slice(sextets(group)?.to_be_bytes().get(1..)?);
    }
    if rest.is_empty() {
        return Some(out);
    }
    // Two characters hold one byte and four unused bits, three hold two and two; one holds none.
    let missing = 4_usize.checked_sub(rest.len()).filter(|&m| m <= 2)?;
    let bits = sextets(rest)?;
    if bits & ((1 << (2 * missing)) - 1) != 0 {
        return None;
    }
    out.extend_from_slice((bits << (6 * missing)).to_be_bytes().get(1..4 - missing)?);
    Some(out)
}

/// The bits of up to four base64url characters, six each; `None` for a byte outside the alphabet.
fn sextets(chars: &[u8]) -> Option<u32> {
    chars.iter().try_fold(0_u32, |bits, &b| {
        let value = BASE64URL_VALUES[usize::from(b)];
        (value != NOT_BASE64).then(|| bits << 6 | u32::from(value))
    })
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

    #[test]
    fn base32hex_matches_rfc4648_vectors() {
        // RFC 4648 §10, without padding and in lowercase, as RFC 5155 §3.3 writes it.
        for (plain, encoded) in [
            ("", ""),
            ("f", "co"),
            ("fo", "cpng"),
            ("foo", "cpnmu"),
            ("foob", "cpnmuog"),
            ("fooba", "cpnmuoj1"),
            ("foobar", "cpnmuoj1e8"),
        ] {
            assert_eq!(Base32Hex(plain.as_bytes()).to_string(), encoded);
            assert_eq!(
                decode_base32hex(encoded.as_bytes()).unwrap(),
                plain.as_bytes()
            );
            let upper = encoded.to_ascii_uppercase();
            assert_eq!(
                decode_base32hex(upper.as_bytes()).unwrap(),
                plain.as_bytes()
            );
        }
        // Padding, a length no byte string has, a byte outside the alphabet, and unused bits that are not zero.
        for bad in ["CO======", "c", "cpn", "cpnmuo", "cw", "c!", "cp"] {
            assert_eq!(decode_base32hex(bad.as_bytes()), None, "{bad}");
        }
    }

    #[test]
    fn base64url_is_base64_without_padding_and_with_dash_and_underscore() {
        // RFC 4648 §10 without the `=`, and §5's alphabet on bytes whose base64 has `+` and `/`.
        for (plain, encoded) in [
            (&b""[..], ""),
            (b"f", "Zg"),
            (&[0x66, 0x6F], "Zm8"),
            (b"foo", "Zm9v"),
            (b"foob", "Zm9vYg"),
            (b"fooba", "Zm9vYmE"),
            (b"foobar", "Zm9vYmFy"),
            (&[0xFB, 0xEF, 0xBE, 0xFF], "----_w"),
        ] {
            assert_eq!(encode_base64url(plain), encoded);
            assert_eq!(decode_base64url(encoded.as_bytes()).unwrap(), plain);
        }
        assert_eq!(decode_base64url(b"Zg=="), None);
        assert_eq!(decode_base64url(b"Z"), None);
        assert_eq!(decode_base64url(b"Zm9vY"), None);
        assert_eq!(decode_base64url(b"Zh"), None);
        assert_eq!(decode_base64url(b"Zm9"), None);
        assert_eq!(decode_base64url(b"+/+/"), None);
        assert_eq!(decode_base64url(b"Zg!"), None);
    }
}
