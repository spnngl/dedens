//! RFC 2181: TTL range (§8) and label contents (§11).

mod common;

use common::{decode_record, encode_with, record_wire};
use dedens_proto::{Class, Name, RData, Record, RecordType, Ttl};
use proptest::prelude::*;

#[test]
fn s8_a_ttl_with_the_top_bit_set_is_zero() {
    assert_eq!(Ttl::from_wire(0x8000_0000), Ttl::ZERO);
    assert_eq!(Ttl::from_wire(u32::MAX), Ttl::ZERO);
    assert_eq!(Ttl::from_wire(0x7FFF_FFFF), Ttl::MAX);
    assert_eq!(Ttl::new(0x8000_0000), None);
}

#[test]
fn s8_a_decoded_record_has_the_clamped_ttl() {
    let mut wire = record_wire(RecordType::A, &[1, 2, 3, 4]);
    wire[5..9].copy_from_slice(&0xFFFF_FFFFu32.to_be_bytes());
    assert_eq!(decode_record(&wire).unwrap().record.ttl, Ttl::ZERO);
}

#[test]
fn s11_any_octet_is_valid_in_a_label() {
    for half in [0u8..=127, 128..=255] {
        let octets: Vec<u8> = half.collect();
        let name = Name::from_labels(octets.chunks(63)).unwrap();
        let rec = Record::new(name.clone(), Class::IN, Ttl::ZERO, RData::Ptr(name));
        let wire = encode_with(|w| rec.encode(w));
        assert_eq!(decode_record(&wire).unwrap().record, rec);
    }
}

proptest! {
    #[test]
    fn ttl_round_trip(ttl in 0..=Ttl::MAX.get()) {
        prop_assert_eq!(Ttl::new(ttl).map(Ttl::get), Some(ttl));
    }
}
