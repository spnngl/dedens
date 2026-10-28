//! RFC 1035: header (§4.1.1), question (§4.1.2), name presentation (§5.1), RDATA (§3.3); the name codec's
//! tests are in `src/name.rs`.

mod common;

use std::net::Ipv4Addr;

use common::{decode_answer, decode_record, encode_record, name_of, record, record_wire};
use dedens_proto::header::HEADER_LEN;
use dedens_proto::rdata::{Mx, Soa, Txt, TxtError};
use dedens_proto::{
    Class, DecodeErrorKind, Header, Message, Opcode, Question, RData, Rcode, RecordType,
};
use proptest::prelude::*;

#[test]
fn s5_1_special_characters_are_escaped() {
    let name = name_of(&[b"a.b\\c\"d(e)f;g@h$i j"]);
    assert_eq!(name.to_string(), r#"a\.b\\c\"d\(e\)f\;g\@h\$i\032j."#);
}

/// A header with QDCOUNT 1, then `question`.
fn one_question(question: &[u8]) -> Vec<u8> {
    [&[0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0][..], question].concat()
}

#[test]
fn s4_1_2_question_layout() {
    let wire = one_question(&[3, b'w', b'w', b'w', 0, 0, 28, 0, 1]);
    let message = Message::decode(&wire).unwrap().message;
    let q = &message.questions[0];
    assert_eq!(*q, Question::new(name_of(&[b"www"]), RecordType::AAAA));
    assert_eq!(q.qclass, Class::IN);
    assert_eq!(message.to_vec().unwrap(), wire);
}

#[test]
fn s4_1_2_question_cut_short() {
    let err = Message::decode(&one_question(&[0, 0, 1, 0])).unwrap_err();
    assert_eq!(err.kind, DecodeErrorKind::UnexpectedEnd);
    assert_eq!(err.offset, 15);
}

#[test]
fn s4_1_1_header_is_12_bytes() {
    assert_eq!(HEADER_LEN, 12);
    assert_eq!(Message::default().to_vec().unwrap(), [0; 12]);
    assert_eq!(Header::default().opcode, Opcode::QUERY);
    assert_eq!(Header::default().rcode, Rcode::NOERROR);
}

fn decoded(rtype: RecordType, rdata: &[u8]) -> RData<'static> {
    let d = decode_record(&record_wire(rtype, rdata)).expect("decodes");
    assert_eq!(d.invalid_rdata, None);
    d.record.data().into_owned()
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
    let strings = [&b"foo"[..], b"", b"bar"];
    assert_eq!(rdata, RData::Txt(Txt::new(strings).unwrap()));
    let RData::Txt(txt) = rdata else {
        unreachable!("TXT")
    };
    assert!(txt.strings().eq(strings));
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
    assert!(Txt::new([&[0; 255][..]]).is_ok());
    assert_eq!(Txt::new([&[0; 256][..]]), Err(TxtError::StringTooLong));
    assert_eq!(Txt::new([]), Err(TxtError::Empty));
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
    // "example" at 12 in the question; the answer is a CNAME pointing at it.
    let mut msg = one_question(b"\x07example\x00\x00\x01\x00\x01");
    msg[7] = 1;
    msg.extend_from_slice(&[0xC0, 12, 0, 5, 0, 1, 0, 0, 0, 0, 0, 2, 0xC0, 12]);
    let d = decode_answer(&msg).unwrap();
    assert_eq!(d.record.data(), RData::Cname(name_of(&[b"example"])));
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
        let wire = encode_record(&rec);
        let d = decode_record(&wire)?;
        prop_assert_eq!(d.invalid_rdata, None);
        prop_assert_eq!(d.record, rec);
    }
}
