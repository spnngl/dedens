//! The client's side of Anonymized `DNSCrypt`: the prefix that tells a relay which resolver a query is for (draft
//! "Anonymized `DNSCrypt`", D100).
//!
//! The relay strips it and forwards the rest, a `DNSCrypt` query or the certificate query, to the resolver over UDP.

use std::net::{IpAddr, SocketAddr};

/// `<anon-magic>`: eight `0xff` and two zeros, the first 10 bytes of every query to a relay.
pub const RELAY_MAGIC: [u8; 10] = [0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x00, 0x00];

/// The length of what `<anon-magic>`, `<server-ip>` and `<server-port>` add to a query: 10, 16 and 2 bytes.
pub const RELAY_PREFIX_LEN: usize = RELAY_MAGIC.len() + 16 + 2;

/// The `<anondnscrypt-query>` for `inner`, a `DNSCrypt` query or a certificate query, to the resolver at `target`:
/// `<anon-magic>`, the resolver's address as 16 bytes (an IPv4 one as `::ffff:a.b.c.d`) and its port in two, then
/// `inner` unchanged.
///
/// Over TCP the caller adds the two-byte length, which covers all of this.
#[must_use]
pub fn relay_query(target: SocketAddr, inner: &[u8]) -> Vec<u8> {
    let address = match target.ip() {
        IpAddr::V4(ip) => ip.to_ipv6_mapped(),
        IpAddr::V6(ip) => ip,
    };
    let mut query = Vec::with_capacity(RELAY_PREFIX_LEN + inner.len());
    query.extend_from_slice(&RELAY_MAGIC);
    query.extend_from_slice(&address.octets());
    query.extend_from_slice(&target.port().to_be_bytes());
    query.extend_from_slice(inner);
    query
}
