//! RFC 8659: CAA records (§4).

mod common;

use common::{decode_record, encode_with, record, record_wire};
use dedens_proto::rdata::Caa;
use dedens_proto::{DecodeErrorKind, RData, RecordType};
use proptest::prelude::*;

#[test]
fn s4_1_fields_are_flags_tag_and_value() {
    let wire = [&[0x80, 5][..], b"issue", b"ca.example"].concat();
    let decoded = decode_record(&record_wire(RecordType::CAA, &wire)).unwrap();
    let RData::Caa(caa) = decoded.record.data else {
        panic!("not CAA")
    };
    assert!(caa.is_critical());
    assert_eq!(
        (caa.tag(), caa.value()),
        (&b"issue"[..], &b"ca.example"[..])
    );
}

#[test]
fn s4_1_1_only_the_critical_bit_is_defined_and_the_rest_is_kept() {
    let wire = [&[0x01, 3][..], b"foo"].concat();
    let decoded = decode_record(&record_wire(RecordType::CAA, &wire)).unwrap();
    let RData::Caa(caa) = decoded.record.data else {
        panic!("not CAA")
    };
    assert!(!caa.is_critical());
    assert_eq!(caa.flags(), 1);
}

#[test]
fn s4_1_1_tags_are_one_to_fifteen_letters_or_digits() {
    assert!(Caa::new(0, b"issuewild", b"").is_ok());
    assert!(Caa::new(0, b"", b"").is_err());
    assert!(Caa::new(0, b"sixteen-chars-ab", b"").is_err());
    assert!(Caa::new(0, b"is sue", b"").is_err());
    let bad_tag = [&[0, 2][..], b"a-"].concat();
    let decoded = decode_record(&record_wire(RecordType::CAA, &bad_tag)).unwrap();
    assert!(decoded.invalid_rdata.is_some());
}

#[test]
fn s4_1_1_a_tag_longer_than_the_rdata_is_kept_opaque() {
    let decoded = decode_record(&record_wire(RecordType::CAA, &[0, 9, b'a'])).unwrap();
    assert_eq!(
        decoded.invalid_rdata.map(|e| e.kind),
        Some(DecodeErrorKind::RdataLength)
    );
}

proptest! {
    #[test]
    fn round_trip(rec in record()) {
        let wire = encode_with(|w| rec.encode(w));
        prop_assert_eq!(decode_record(&wire)?.record, rec);
    }
}
