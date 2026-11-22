//! CRC-32 as the journal's records carry it (D207).

/// The reflected polynomial of CRC-32/ISO-HDLC (IEEE 802.3, the CRC of zlib, PNG and Ethernet).
const POLYNOMIAL: u32 = 0xEDB8_8320;

const TABLE: [u32; 256] = table();

const fn table() -> [u32; 256] {
    let mut table = [0; 256];
    let mut byte = 0;
    while byte < 256 {
        #[expect(clippy::cast_possible_truncation, reason = "byte is below 256")]
        let mut crc = byte as u32;
        let mut bit = 0;
        while bit < 8 {
            crc = if crc & 1 == 1 {
                (crc >> 1) ^ POLYNOMIAL
            } else {
                crc >> 1
            };
            bit += 1;
        }
        table[byte] = crc;
        byte += 1;
    }
    table
}

/// The CRC-32 of `parts` one after the other.
pub(super) fn crc32(parts: &[&[u8]]) -> u32 {
    let mut crc = u32::MAX;
    for byte in parts.iter().flat_map(|p| p.iter()) {
        let index = usize::from((crc ^ u32::from(*byte)).to_le_bytes()[0]);
        crc = (crc >> 8) ^ TABLE[index];
    }
    !crc
}

#[cfg(test)]
mod tests {
    use super::crc32;

    /// The check value of the catalogue of CRCs (Williams, "A Painless Guide to CRC Error Detection Algorithms"):
    /// the CRC-32 of the nine digits.
    #[test]
    fn the_check_value_of_the_nine_digits() {
        assert_eq!(crc32(&[b"123456789"]), 0xCBF4_3926);
    }

    #[test]
    fn parts_are_the_bytes_joined() {
        assert_eq!(crc32(&[b"1234", b"", b"56789"]), crc32(&[b"123456789"]));
        assert_eq!(crc32(&[]), 0);
    }
}
