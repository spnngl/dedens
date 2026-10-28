//! D28: records keep their RDATA as checked wire bytes, read as typed data on demand.

mod common;

use std::net::Ipv4Addr;

use common::{dns, rec};
use dedens_proto::rdata::{Mx, Opaque};
use dedens_proto::{
    Class, DecodeErrorKind, Message, Question, RData, Record, RecordType, Ttl, message,
};

fn mx_response() -> Message<'static> {
    let mut response = Message::query(1, Question::new(dns("example.com"), RecordType::MX));
    response.answer = vec![rec(
        "example.com",
        RData::Mx(Mx {
            preference: 10,
            exchange: dns("mail.example.com"),
        }),
    )];
    response
}

#[test]
fn rdata_with_a_compressed_name_outlives_its_message_once_owned() {
    let response = mx_response();
    let wire = response.to_vec().expect("encodes");
    // The exchange is a label and a pointer to the question name.
    assert!(wire.ends_with(&[
        0, 10, 4, b'm', b'a', b'i', b'l', 0xC0, 12, 0, 0, 41, 4, 208, 0, 0, 0, 0, 0, 0
    ]));
    let owned = Message::decode(&wire)
        .expect("decodes")
        .message
        .into_owned();
    drop(wire);
    assert_eq!(owned, response);
    let again = owned.to_vec().expect("encodes");
    assert_eq!(Message::decode(&again).expect("decodes").message, response);
}

#[test]
fn records_compare_names_in_rdata_without_case() {
    let lower = rec("example.com", RData::Ns(dns("ns.example.com")));
    let upper = rec("example.com", RData::Ns(dns("NS.Example.COM")));
    assert_eq!(lower, upper);
}

#[test]
fn invalid_rdata_reads_as_opaque_and_is_written_as_received() {
    // An A record with 3 bytes of RDATA (D9).
    let wire = common::record_wire(RecordType::A, &[192, 0, 2]);
    let decoded = common::decode_record(&wire).expect("decodes");
    assert!(decoded.invalid_rdata.is_some());
    assert!(matches!(decoded.record.data(), RData::Opaque(o) if o.data() == [192, 0, 2]));
    let response = Message {
        answer: vec![decoded.record],
        ..Message::default()
    };
    let again = response.to_vec().expect("encodes");
    assert!(again.ends_with(&[0, 3, 192, 0, 2]));
}

#[test]
fn opaque_bytes_unreadable_as_their_type_stay_opaque() {
    let bad =
        Opaque::new(RecordType::A, &[1, 2, 3]).expect("invalid A RDATA is kept as bytes (D9)");
    let record = Record::new(
        dns("example.com"),
        Class::IN,
        Ttl::ZERO,
        &RData::Opaque(bad),
    );
    assert!(matches!(record.data(), RData::Opaque(o) if o.data() == [1, 2, 3]));
}

/// One value has one form: bytes that read as a typed type are refused, and so are bytes for a type with names
/// that do not read as it, which could hold a pointer written out as is (RFC 3597 §4).
#[test]
fn opaque_refuses_typed_and_name_bytes() {
    assert!(Opaque::new(RecordType::A, &[192, 0, 2, 1]).is_err());
    assert!(Opaque::new(RecordType::TXT, &[1, b'a']).is_err());
    for (rtype, data) in [
        (RecordType::NS, &[0xC0, 0x0C][..]),
        (RecordType::NS, &[3, b'a']),
        (RecordType::NS, &[0xFF]),
        (RecordType::SRV, &[0, 1, 0, 2, 0, 3, 0xC0, 0x0C]),
    ] {
        assert!(Opaque::new(rtype, data).is_err(), "{rtype} {data:?}");
    }
}

/// The TTL field of a stray OPT record holds the extended RCODE, version and DO bit (RFC 6891 §6.1.3): a cache
/// rewriting TTLs must leave it alone.
#[test]
fn ttl_offsets_skip_a_stray_opt_record() {
    let mut wire = vec![0, 0, 0x80, 0, 0, 0, 0, 1, 0, 0, 0, 0];
    wire.extend([0, 0, 41, 0x10, 0, 0, 0, 0x80, 0, 0, 0]);
    assert_eq!(message::ttl_offsets(&wire).expect("readable"), []);
}

/// A record or question that does not fit leaves the writer as it was, compression table included.
#[test]
fn failed_encoding_writes_nothing() {
    let record = rec("abcdefgh.example", RData::A(Ipv4Addr::new(192, 0, 2, 1)));
    let question = Question::new(dns("abcdefgh.example"), RecordType::A);
    let mut buf = [0; 41];
    let mut w = dedens_proto::wire::Writer::new(&mut buf);
    // A header: names are never in it, so never pointed to.
    w.put_bytes(&[7; 12]).expect("room");
    assert!(record.encode(&mut w).is_err());
    assert_eq!(w.len(), 12);
    question.encode(&mut w).expect("fits: 18 + 4 bytes");
    assert_eq!(w.len(), 34);
    assert!(
        question.encode(&mut w).is_ok(),
        "a pointer to the first one"
    );
    assert_eq!(w.len(), 40);
    assert!(question.encode(&mut w).is_err());
    assert_eq!(w.len(), 40);
}

#[test]
fn ttl_offsets_locate_every_record_ttl() {
    let mut response = mx_response();
    response.additional.push(rec(
        "mail.example.com",
        RData::A(Ipv4Addr::new(192, 0, 2, 1)),
    ));
    let mut wire = response.to_vec().expect("encodes");
    let offsets = message::ttl_offsets(&wire).expect("reads");
    assert_eq!(offsets.len(), 2, "the OPT record is not a record");
    for at in offsets {
        wire[at..at + 4].copy_from_slice(&7_u32.to_be_bytes());
    }
    let decoded = Message::decode(&wire).expect("decodes").message;
    let ttls: Vec<_> = decoded
        .answer
        .iter()
        .chain(&decoded.additional)
        .map(|r| r.ttl)
        .collect();
    assert_eq!(ttls, [Ttl::new(7).expect("valid TTL"); 2]);
}

#[test]
fn a_message_over_65535_bytes_is_refused() {
    let error = Message::decode(&vec![0; 65536]).expect_err("too long");
    assert!(matches!(error.kind, DecodeErrorKind::Invalid(_)));
}
