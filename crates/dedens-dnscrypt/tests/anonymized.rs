//! draft-denis-dprive-dnscrypt-11, "Anonymized `DNSCrypt`": the prefix a client puts before a query for a relay.

use std::net::SocketAddr;

use dedens_dnscrypt::{RELAY_MAGIC, RELAY_PREFIX_LEN, relay_query};

/// The draft's example: a query for a server at 192.0.2.1:443 is prefixed with the magic, the address mapped to
/// IPv6 and the port.
#[test]
fn the_drafts_prefix_for_192_0_2_1_port_443() {
    let target: SocketAddr = "192.0.2.1:443".parse().expect("an address");
    let query = relay_query(target, b"inner");
    let expected: [u8; 28] = [
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x00, 0x00, // <anon-magic>
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // <server-ip>, ::ffff:
        0xff, 0xff, 0xc0, 0x00, 0x02, 0x01, // 192.0.2.1
        0x01, 0xbb, // <server-port>, 443
    ];
    assert_eq!(query[..RELAY_PREFIX_LEN], expected);
    assert_eq!(query[RELAY_PREFIX_LEN..], *b"inner");
}

/// An IPv6 target is written as it is, its port in big-endian.
#[test]
fn an_ipv6_target_is_written_whole() {
    let target: SocketAddr = "[2001:db8::1]:5353".parse().expect("an address");
    let query = relay_query(target, &[]);
    assert_eq!(query[..10], RELAY_MAGIC);
    assert_eq!(
        query[10..26],
        [
            0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01
        ]
    );
    assert_eq!(query[26..], [0x14, 0xe9]);
    assert_eq!(query.len(), RELAY_PREFIX_LEN);
}
