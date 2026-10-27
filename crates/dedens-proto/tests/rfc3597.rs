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
        RData::Opaque(Opaque {
            rtype: RecordType(65280),
            data: (*b"\xDE\xAD").into()
        })
    );
}

#[test]
fn s4_empty_rdata_is_valid() {
    let decoded = decode_record(&record_wire(RecordType(65280), &[])).unwrap();
    assert_eq!(decoded.invalid_rdata, None);
}

#[test]
fn s4_an_unsupported_type_with_names_is_not_decompressed() {
    // RP (17) may look like it holds names, but only the RFC 1035 types are decompressed.
    let decoded = decode_record(&record_wire(RecordType(17), &[0xC0, 0])).unwrap();
    assert_eq!(decoded.record.data.rtype(), RecordType(17));
    assert!(matches!(&decoded.record.data, RData::Opaque(o) if *o.data == [0xC0, 0]));
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
