//! RFC 1035: header (§4.1.1), question (§4.1.2), name encoding and limits (§2.3.4, §3.1, §4.1.4).

mod common;

use std::net::Ipv4Addr;

use common::{
    counts, decode_record, encode_with, header, name, name_of, question, reader, record,
    record_wire,
};
use dedens_proto::header::HEADER_LEN;
use dedens_proto::name::{MAX_LABEL_LEN, MAX_NAME_LEN};
use dedens_proto::rdata::{CharacterString, Mx, Soa, Txt};
use dedens_proto::{
    Class, Counts, DecodeErrorKind, Header, Name, Opcode, Question, RData, Rcode, RecordType,
};
use proptest::prelude::*;

/// §4.1.4 figure: F.ISI.ARPA at 20, FOO.F.ISI.ARPA at 40, ARPA at 64, the root at 92.
fn figure() -> Vec<u8> {
    let mut msg = vec![0; 20];
    msg.extend_from_slice(&[1, b'F', 3, b'I', b'S', b'I', 4, b'A', b'R', b'P', b'A', 0]);
    msg.resize(40, 0);
    msg.extend_from_slice(&[3, b'F', b'O', b'O', 0xC0, 20]);
    msg.resize(64, 0);
    msg.extend_from_slice(&[0xC0, 26]);
    msg.resize(93, 0);
    msg
}

#[test]
fn s4_1_4_figure_decodes_at_each_offset() {
    let msg = figure();
    let at = |offset: usize| {
        let mut r = reader(&msg);
        r.bytes(offset).unwrap();
        let decoded = Name::decode(&mut r).unwrap();
        (decoded, r.position())
    };
    assert_eq!(at(20), (name_of(&[b"F", b"ISI", b"ARPA"]), 32));
    assert_eq!(at(40), (name_of(&[b"FOO", b"F", b"ISI", b"ARPA"]), 46));
    assert_eq!(at(64), (name_of(&[b"ARPA"]), 66));
    assert_eq!(at(92), (Name::root(), 93));
}

#[test]
fn s4_1_4_pointers_use_the_low_14_bits() {
    // The name sits at 0x0102 (258): the pointer is 0xC1 0x02.
    let mut msg = vec![0; 0x0102];
    msg.extend_from_slice(&[1, b'a', 0]);
    msg.extend_from_slice(&[0xC1, 0x02]);
    let mut r = reader(&msg);
    r.bytes(0x0105).unwrap();
    assert_eq!(Name::decode(&mut r).unwrap(), name_of(&[b"a"]));
}

#[test]
fn s4_1_4_a_name_may_be_only_a_pointer_or_labels_then_a_pointer() {
    // "a" + pointer(0 = "b" root) and a bare pointer.
    let msg = [1, b'b', 0, 1, b'a', 0xC0, 0, 0xC0, 0];
    let mut r = reader(&msg);
    r.bytes(3).unwrap();
    assert_eq!(Name::decode(&mut r).unwrap(), name_of(&[b"a", b"b"]));
    assert_eq!(Name::decode(&mut r).unwrap(), name_of(&[b"b"]));
    assert!(r.is_empty());
}

#[test]
fn s4_1_4_label_types_01_and_10_are_rejected() {
    for first in [0x40, 0x7F, 0x80, 0xBF] {
        let err = Name::decode(&mut reader(&[first, 0, 0])).unwrap_err();
        assert_eq!(err.kind, DecodeErrorKind::ReservedLabelType);
    }
}

#[test]
fn s2_3_4_label_and_name_limits() {
    assert_eq!(MAX_LABEL_LEN, 63);
    assert_eq!(MAX_NAME_LEN, 255);
    // A 63-byte label decodes; a length byte of 64 is a reserved label type (0b01......).
    let mut wire = vec![63];
    wire.extend_from_slice(&[b'x'; 63]);
    wire.push(0);
    assert!(Name::decode(&mut reader(&wire)).is_ok());
    wire[0] = 64;
    assert!(Name::decode(&mut reader(&wire)).is_err());
    // 255 bytes of wire form decode; 256 do not.
    let labels = |last: usize| {
        let mut wire = Vec::new();
        for _ in 0..3 {
            wire.push(63);
            wire.extend_from_slice(&[b'x'; 63]);
        }
        wire.push(u8::try_from(last).unwrap());
        wire.extend_from_slice(&vec![b'x'; last]);
        wire.push(0);
        wire
    };
    assert!(Name::decode(&mut reader(&labels(61))).is_ok());
    let err = Name::decode(&mut reader(&labels(62))).unwrap_err();
    assert_eq!(err.kind, DecodeErrorKind::NameTooLong);
}

#[test]
fn s3_1_a_name_needs_its_root_label() {
    let err = Name::decode(&mut reader(&[1, b'a'])).unwrap_err();
    assert_eq!(err.kind, DecodeErrorKind::UnexpectedEnd);
}

#[test]
fn s4_1_2_question_layout() {
    let wire = [3, b'w', b'w', b'w', 0, 0, 28, 0, 1];
    let q = Question::decode(&mut reader(&wire)).unwrap();
    assert_eq!(q, Question::new(name_of(&[b"www"]), RecordType::AAAA));
    assert_eq!(q.qclass, Class::IN);
    assert_eq!(encode_with(|w| q.encode(w)), wire);
}

#[test]
fn s4_1_2_question_cut_short() {
    let err = Question::decode(&mut reader(&[0, 0, 1, 0])).unwrap_err();
    assert_eq!(err.kind, DecodeErrorKind::UnexpectedEnd);
    assert_eq!(err.offset, 3);
}

#[test]
fn s4_1_1_header_is_12_bytes() {
    assert_eq!(HEADER_LEN, 12);
    let wire = encode_with(|w| Header::default().encode(Counts::default(), w));
    assert_eq!(wire, [0; 12]);
    assert_eq!(Header::default().opcode, Opcode::QUERY);
    assert_eq!(Header::default().rcode, Rcode::NOERROR);
}

proptest! {
    #[test]
    fn name_round_trips(name in name()) {
        let wire = encode_with(|w| name.encode(w));
        prop_assert_eq!(wire.as_slice(), name.as_wire());
        let mut r = reader(&wire);
        prop_assert_eq!(Name::decode(&mut r)?, name);
        prop_assert!(r.is_empty());
    }

    #[test]
    fn header_round_trips(header in header(), counts in counts()) {
        let wire = encode_with(|w| header.encode(counts, w));
        prop_assert_eq!(Header::decode(&mut reader(&wire))?, (header, counts));
    }

    #[test]
    fn question_round_trips(question in question()) {
        let wire = encode_with(|w| question.encode(w));
        prop_assert_eq!(Question::decode(&mut reader(&wire))?, question);
    }

    /// Decoding never panics and never reads outside its input, whatever the bytes.
    #[test]
    fn decoding_arbitrary_bytes_is_total(bytes in prop::collection::vec(any::<u8>(), 0..64)) {
        let mut r = reader(&bytes);
        let _ = Name::decode(&mut r);
        prop_assert!(r.position() <= bytes.len());
        let _ = Question::decode(&mut reader(&bytes));
        let _ = Header::decode(&mut reader(&bytes));
    }
}

fn decoded(rtype: RecordType, rdata: &[u8]) -> RData {
    let d = decode_record(&record_wire(rtype, rdata)).expect("decodes");
    assert_eq!(d.invalid_rdata, None);
    d.record.data
}

#[test]
fn s3_4_1_a_is_four_octets() {
    assert_eq!(
        decoded(RecordType::A, &[192, 0, 2, 1]),
        RData::A(Ipv4Addr::new(192, 0, 2, 1))
    );
    let bad = decode_record(&record_wire(RecordType::A, &[1, 2, 3])).unwrap();
    assert_eq!(
        bad.invalid_rdata.map(|e| e.kind),
        Some(DecodeErrorKind::RdataLength)
    );
}

#[test]
fn s3_3_domain_name_types() {
    let wire = b"\x03ns1\x07example\x00";
    let n = name_of(&[b"ns1", b"example"]);
    assert_eq!(decoded(RecordType::NS, wire), RData::Ns(n.clone()));
    assert_eq!(decoded(RecordType::CNAME, wire), RData::Cname(n.clone()));
    assert_eq!(decoded(RecordType::PTR, wire), RData::Ptr(n));
}

#[test]
fn s3_3_9_mx_is_preference_then_exchange() {
    let rdata = decoded(RecordType::MX, b"\x00\x0a\x04mail\x00");
    assert_eq!(
        rdata,
        RData::Mx(Mx {
            preference: 10,
            exchange: name_of(&[b"mail"])
        })
    );
}

#[test]
fn s3_3_13_soa_has_two_names_and_five_integers() {
    let mut wire = b"\x02ns\x00\x05admin\x00".to_vec();
    for v in [1u32, 2, 3, 4, 5] {
        wire.extend_from_slice(&v.to_be_bytes());
    }
    let RData::Soa(Soa {
        mname,
        rname,
        serial,
        refresh,
        retry,
        expire,
        minimum,
    }) = decoded(RecordType::SOA, &wire)
    else {
        panic!("not SOA")
    };
    assert_eq!((mname, rname), (name_of(&[b"ns"]), name_of(&[b"admin"])));
    assert_eq!([serial, refresh, retry, expire, minimum], [1, 2, 3, 4, 5]);
}

#[test]
fn s3_3_14_txt_is_one_or_more_character_strings() {
    let rdata = decoded(RecordType::TXT, b"\x03foo\x00\x03bar");
    let strings = ["foo", "", "bar"].map(|s| CharacterString::new(s.as_bytes()).unwrap());
    assert_eq!(rdata, RData::Txt(Txt::new(strings.to_vec()).unwrap()));
    // No string at all, or a string that overruns the RDATA, is invalid.
    assert!(
        decode_record(&record_wire(RecordType::TXT, &[]))
            .unwrap()
            .invalid_rdata
            .is_some()
    );
    assert!(
        decode_record(&record_wire(RecordType::TXT, b"\x05ab"))
            .unwrap()
            .invalid_rdata
            .is_some()
    );
}

#[test]
fn s3_3_character_strings_hold_255_octets() {
    assert!(CharacterString::new(&[0; 255]).is_ok());
    assert!(CharacterString::new(&[0; 256]).is_err());
}

#[test]
fn s3_3_invalid_rdata_of_compressible_types_is_an_error() {
    for rtype in [
        RecordType::NS,
        RecordType::CNAME,
        RecordType::PTR,
        RecordType::SOA,
        RecordType::MX,
    ] {
        assert!(decode_record(&record_wire(rtype, &[1])).is_err(), "{rtype}");
    }
}

#[test]
fn s4_1_4_names_in_rdata_follow_pointers_into_the_message() {
    // "example" at 12 in the owner of the first record; the second record is a CNAME pointing at it.
    let mut msg = vec![0; 12];
    msg.extend_from_slice(b"\x07example\x00");
    msg.extend_from_slice(&[0xC0, 12, 0, 5, 0, 1, 0, 0, 0, 0, 0, 2, 0xC0, 12]);
    let mut r = reader(&msg);
    r.bytes(12 + 9).unwrap();
    let d = dedens_proto::Record::decode(&mut r).unwrap();
    assert_eq!(d.record.data, RData::Cname(name_of(&[b"example"])));
    assert!(r.is_empty());
}

#[test]
fn s4_1_4_rdlength_bounds_a_name_in_rdata() {
    // The name runs past RDLENGTH: the RDATA is cut short, not read into the next field.
    let wire = record_wire(RecordType::NS, b"\x03abc");
    assert!(decode_record(&wire).is_err());
}

proptest! {
    #[test]
    fn records_round_trip(rec in record()) {
        let wire = encode_with(|w| rec.encode(w));
        let d = decode_record(&wire)?;
        prop_assert_eq!(d.invalid_rdata, None);
        prop_assert_eq!(d.record, rec);
    }
}
