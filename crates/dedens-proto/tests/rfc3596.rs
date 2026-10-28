//! RFC 3596: AAAA records (§2), `ip6.arpa` reverse names (§2.5).

mod common;

use std::net::{IpAddr, Ipv6Addr};

use common::{decode_record, encode_record, record_wire};
use dedens_proto::{Class, DecodeErrorKind, Name, RData, Record, RecordType, Ttl};
use proptest::prelude::*;

#[test]
fn s2_2_aaaa_is_sixteen_octets() {
    let addr: Ipv6Addr = "2001:db8::1".parse().unwrap();
    let decoded = decode_record(&record_wire(RecordType::AAAA, &addr.octets())).unwrap();
    assert_eq!(decoded.record.data(), RData::Aaaa(addr));
    assert_eq!(decoded.invalid_rdata, None);
}

#[test]
fn s2_2_other_lengths_are_kept_opaque() {
    for len in [0, 4, 15, 17] {
        let decoded = decode_record(&record_wire(RecordType::AAAA, &vec![1; len])).unwrap();
        assert_eq!(
            decoded.invalid_rdata.map(|e| e.kind),
            Some(DecodeErrorKind::RdataLength),
            "{len}"
        );
        assert!(matches!(decoded.record.data(), RData::Opaque(_)));
    }
}

/// The example of §2.5.
#[test]
fn s2_5_ip6_arpa_is_nibbles_low_order_first() {
    let addr: IpAddr = "4321:0:1:2:3:4:567:89ab".parse().unwrap();
    let expected: Name<'_> =
        "b.a.9.8.7.6.5.0.4.0.0.0.3.0.0.0.2.0.0.0.1.0.0.0.0.0.0.0.1.2.3.4.IP6.ARPA."
            .parse()
            .unwrap();
    assert_eq!(Name::reverse(addr), expected);
    assert_eq!(
        Name::reverse(addr).to_string(),
        "b.a.9.8.7.6.5.0.4.0.0.0.3.0.0.0.2.0.0.0.1.0.0.0.0.0.0.0.1.2.3.4.ip6.arpa."
    );
}

#[test]
fn s2_1_the_type_is_28() {
    assert_eq!(RData::Aaaa(Ipv6Addr::LOCALHOST).rtype(), RecordType(28));
}

proptest! {
    #[test]
    fn round_trip(octets in any::<[u8; 16]>()) {
        let rec = Record::new(Name::root(), Class::IN, Ttl::ZERO, &RData::Aaaa(Ipv6Addr::from(octets)));
        let wire = encode_record(&rec);
        prop_assert_eq!(decode_record(&wire)?.record, rec);
    }
}
