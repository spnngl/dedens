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
    let bad = Opaque::new(RecordType::NS, &[0xFF]).expect("NS has no opaque layout");
    let record = Record::new(
        dns("example.com"),
        Class::IN,
        Ttl::ZERO,
        &RData::Opaque(bad),
    );
    assert!(matches!(record.data(), RData::Opaque(o) if o.data() == [0xFF]));
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
