//! RFC 3596: AAAA records (§2).

mod common;

use std::net::Ipv6Addr;

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
