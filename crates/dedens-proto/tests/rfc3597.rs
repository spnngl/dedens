//! RFC 3597: unknown RR types are kept as opaque RDATA (§4), and written in a generic text form (§5).

mod common;

use common::{decode_answer, decode_record, encode_record, record, record_wire};
use dedens_proto::rdata::{Opaque, RData};
use dedens_proto::{Class, DecodeError, DecodeErrorKind, DecodedRecord, RecordType};
use proptest::prelude::*;

#[test]
fn s4_unknown_types_keep_their_bytes() {
    let decoded = decode_record(&record_wire(RecordType(65280), &[0xDE, 0xAD])).unwrap();
    assert_eq!(decoded.invalid_rdata, None);
    assert_eq!(
        decoded.record.data(),
        RData::Opaque(Opaque::new(RecordType(65280), &[0xDE, 0xAD]).unwrap())
    );
}

#[test]
fn s4_empty_rdata_is_valid() {
    let decoded = decode_record(&record_wire(RecordType(65280), &[])).unwrap();
    assert_eq!(decoded.invalid_rdata, None);
}

/// Decodes a record whose RDATA is `rdata` after a question for `a.`: a pointer to offset 12 means `a.`.
fn after_a(rtype: RecordType, rdata: &[u8]) -> Result<DecodedRecord<'static>, DecodeError> {
    let header = [0, 0, 0, 0, 0, 1, 0, 1, 0, 0, 0, 0];
    let question = [1, b'a', 0, 0, 1, 0, 1];
    decode_answer(&[&header[..], &question, &record_wire(rtype, rdata)].concat())
}

#[test]
fn s4_names_of_rfc_1035_types_are_decompressed() {
    // MINFO: two names; MB: one.
    let minfo = after_a(RecordType::MINFO, &[0xC0, 12, 1, b'b', 0xC0, 12]).unwrap();
    assert_eq!(minfo.invalid_rdata, None);
    let RData::Opaque(o) = &minfo.record.data() else {
        panic!("not opaque")
    };
    assert_eq!(o.data(), [1, b'a', 0, 1, b'b', 1, b'a', 0]);
    let mb = after_a(RecordType::MB, &[0xC0, 12]).unwrap();
    assert!(matches!(&mb.record.data(), RData::Opaque(o) if o.data() == [1, b'a', 0]));
}

#[test]
fn s4_names_of_older_types_with_names_are_decompressed_too() {
    // NAPTR: order, preference, flags, services, regexp, replacement.
    let rdata = [&[0, 1, 0, 2, 1, b'u', 0, 0][..], &[0xC0, 12]].concat();
    let naptr = after_a(RecordType::NAPTR, &rdata).unwrap();
    assert!(
        matches!(&naptr.record.data(), RData::Opaque(o) if o.data() == [0, 1, 0, 2, 1, b'u', 0, 0, 1, b'a', 0])
    );
    // SRV prohibits compression (RFC 2782), but older servers compressed (RFC 2052).
    let srv = after_a(RecordType::SRV, &[0, 1, 0, 2, 0, 3, 0xC0, 12]).unwrap();
    assert!(matches!(&srv.record.data(), RData::Srv(s) if s.target.to_string() == "a."));
}

#[test]
fn s4_invalid_rdata_with_names_is_an_error() {
    // Bytes holding a pointer mean nothing outside their message (D9).
    assert!(after_a(RecordType::RP, &[0xC0, 12]).is_err());
    assert!(after_a(RecordType::SRV, &[0, 1, 0xC0, 12]).is_err());
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
    assert!(a.invalid_rdata.is_some() && matches!(a.record.data(), RData::Opaque(_)));
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
        let wire = encode_record(&rec);
        prop_assert_eq!(decode_record(&wire)?.record, rec);
    }
}

#[test]
fn s5_generic_text_form() {
    let rec: dedens_proto::Record<'_> =
        "a.example. 60 CLASS32 TYPE731 \\# 6 abcd (\n ef 01 23 45 )"
            .parse()
            .unwrap();
    assert_eq!((rec.class, rec.rtype()), (Class(32), RecordType(731)));
    assert_eq!(
        rec.data(),
        RData::Opaque(Opaque::new(RecordType(731), &[0xab, 0xcd, 0xef, 1, 0x23, 0x45]).unwrap())
    );
    assert_eq!(
        rec.to_string(),
        "a.example.\t60\tCLASS32\tTYPE731\t\\# 6 abcdef012345"
    );

    let rec: dedens_proto::Record<'_> = r"b.example. 60 HS TYPE62347 \# 0".parse().unwrap();
    assert_eq!(
        (rec.class, rec.data().to_string()),
        (Class::HS, r"\# 0".to_owned())
    );

    // A known type written generically reads as its typed form, the same as its own text form.
    let generic: dedens_proto::Record<'_> = r"e.example. 60 IN A \# 4 0A000001".parse().unwrap();
    assert_eq!(generic.data(), RData::A([10, 0, 0, 1].into()));
    let typed: dedens_proto::Record<'_> = "e.example. 60 CLASS1 TYPE1 10.0.0.2".parse().unwrap();
    assert_eq!(
        (typed.class, typed.data()),
        (Class::IN, RData::A([10, 0, 0, 2].into()))
    );
    assert_eq!(
        generic.generic().to_string(),
        "e.example.\t60\tIN\tA\t\\# 4 0a000001"
    );
}

#[test]
fn s5_generic_text_errors() {
    for bad in [
        r"x. 60 TYPE731 \# 3 abcd",
        r"x. 60 TYPE731 \# 2 abc",
        r"x. 60 TYPE731 \# 1 zz",
        r"x. 60 TYPE731 \#",
        "x. 60 TYPE731 abcd",
        // A pointer inside RDATA means nothing in text.
        r"x. 60 NS \# 2 c00c",
        r"x. 60 TYPE731 \# 65536 00",
    ] {
        assert!(
            bad.parse::<dedens_proto::Record<'_>>().is_err(),
            "accepted {bad}"
        );
    }
}
