//! Key tags (RFC 4034 Appendix B).

/// The key tag of a DNSKEY, given its whole RDATA (flags, protocol, algorithm, public key; RFC 4034 §2.1).
///
/// Appendix B.1: algorithm 1 (RSAMD5) takes the second and third octets from the end; every other algorithm
/// sums the RDATA as 16-bit words and folds the carry. Not a hash: tags collide, so a validator tries every
/// key with the RRSIG's tag.
#[must_use]
pub fn key_tag(dnskey_rdata: &[u8]) -> u16 {
    const RSAMD5: u8 = 1;
    if dnskey_rdata.get(3) == Some(&RSAMD5)
        && let Some(&[high, low, _]) = dnskey_rdata.last_chunk::<3>()
    {
        return u16::from_be_bytes([high, low]);
    }
    let sum = dnskey_rdata.chunks(2).fold(0_u32, |sum, pair| {
        let high = pair.first().copied().map_or(0, u32::from) << 8;
        let low = pair.get(1).copied().map_or(0, u32::from);
        sum + high + low
    });
    // The sum of at most 65535 octets fits 32 bits; fold the carry once (RFC 4034 Appendix B).
    let folded = sum + (sum >> 16);
    u16::try_from(folded & 0xFFFF).unwrap_or_default()
}
