//! RFC 3597: unknown RR types are kept as opaque RDATA (§4, §5).

mod common;

use common::{decode_record, encode_with, record, record_wire};
use dedens_proto::rdata::Opaque;
use dedens_proto::{Class, DecodeErrorKind, RData, RecordType};
use proptest::prelude::*;

#[test]
fn s4_unknown_types_keep_their_bytes() {
    let decoded = decode_record(&record_wire(RecordType(65280), &[0xDE, 0xAD])).unwrap();
    assert_eq!(decoded.invalid_rdata, None);
    assert_eq!(
        decoded.record.data,
        RData::Opaque(Opaque::new(RecordType(65280), &[0xDE, 0xAD]).unwrap())
    );
}

#[test]
fn s4_empty_rdata_is_valid() {
    let decoded = decode_record(&record_wire(RecordType(65280), &[])).unwrap();
    assert_eq!(decoded.invalid_rdata, None);
}

/// A record owned by `a.` whose RDATA is `rdata`; a pointer to offset 0 in it means `a.`.
fn owned_by_a(rtype: RecordType, rdata: &[u8]) -> Vec<u8> {
    let mut wire = vec![1, b'a'];
    wire.extend_from_slice(&record_wire(rtype, rdata));
    wire
}

#[test]
fn s4_names_of_rfc_1035_types_are_decompressed() {
    // MINFO: two names; MB: one.
    let minfo =
        decode_record(&owned_by_a(RecordType::MINFO, &[0xC0, 0, 1, b'b', 0xC0, 0])).unwrap();
    assert_eq!(minfo.invalid_rdata, None);
    let RData::Opaque(o) = &minfo.record.data else {
        panic!("not opaque")
    };
    assert_eq!(o.data(), [1, b'a', 0, 1, b'b', 1, b'a', 0]);
    let mb = decode_record(&owned_by_a(RecordType::MB, &[0xC0, 0])).unwrap();
    assert!(matches!(&mb.record.data, RData::Opaque(o) if o.data() == [1, b'a', 0]));
}

#[test]
fn s4_names_of_older_types_with_names_are_decompressed_too() {
    // NAPTR: order, preference, flags, services, regexp, replacement.
    let rdata = [&[0, 1, 0, 2, 1, b'u', 0, 0][..], &[0xC0, 0]].concat();
    let naptr = decode_record(&owned_by_a(RecordType::NAPTR, &rdata)).unwrap();
    assert!(
        matches!(&naptr.record.data, RData::Opaque(o) if o.data() == [0, 1, 0, 2, 1, b'u', 0, 0, 1, b'a', 0])
    );
    // SRV prohibits compression (RFC 2782), but older servers compressed (RFC 2052).
    let srv = decode_record(&owned_by_a(RecordType::SRV, &[0, 1, 0, 2, 0, 3, 0xC0, 0])).unwrap();
    assert!(matches!(&srv.record.data, RData::Srv(s) if s.target.to_string() == "a."));
}

#[test]
fn s4_invalid_rdata_with_names_is_an_error() {
    // Bytes holding a pointer mean nothing outside their message (D9).
    assert!(decode_record(&owned_by_a(RecordType::RP, &[0xC0, 0])).is_err());
    assert!(decode_record(&owned_by_a(RecordType::SRV, &[0, 1, 0xC0, 0])).is_err());
}

#[test]
fn s4_opaque_rdata_never_holds_pointers() {
    assert!(Opaque::new(RecordType::RP, &[0xC0, 0, 0]).is_err());
    assert!(Opaque::new(RecordType::RP, &[0, 0]).is_ok());
    assert!(
        Opaque::new(RecordType::RP, &[0, 0, 7]).is_err(),
        "bytes after the fields"
    );
    assert!(
        Opaque::new(RecordType(65280), &[0xC0, 0]).is_ok(),
        "unknown types are not parsed"
    );
}

#[test]
fn s4_rdlength_must_fit_in_the_message() {
    let mut wire = record_wire(RecordType(65280), &[1, 2, 3]);
    wire.pop();
    let err = decode_record(&wire).unwrap_err();
    assert_eq!(err.kind, DecodeErrorKind::RdataLength);
}

#[test]
fn s4_known_types_with_a_bad_length_are_kept_opaque_unless_compressible() {
    let a = decode_record(&record_wire(RecordType::A, &[1, 2, 3])).unwrap();
    assert!(a.invalid_rdata.is_some() && matches!(a.record.data, RData::Opaque(_)));
    // MX holds a compressible name: its RDATA cannot be kept as bytes (D9).
    assert!(decode_record(&record_wire(RecordType::MX, &[0, 1])).is_err());
}

#[test]
fn s5_unknown_types_print_as_typenn() {
    assert_eq!(RecordType(65280).to_string(), "TYPE65280");
    assert_eq!(Class(3).to_string(), "CH");
    assert_eq!(Class(4000).to_string(), "CLASS4000");
}

proptest! {
    #[test]
    fn opaque_round_trip(rec in record()) {
        let wire = encode_with(|w| rec.encode(w));
        prop_assert_eq!(decode_record(&wire)?.record, rec);
    }
}
