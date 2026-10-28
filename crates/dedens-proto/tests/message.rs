//! RFC 9619: one question per message (§4), and the violations of D9.

mod common;

use std::net::Ipv4Addr;

use dedens_proto::edns::EdnsOption;
use dedens_proto::rdata::RData;
use dedens_proto::{
    Class, DecodeErrorKind, Decoded, Edns, Message, Name, Question, RecordType, Violation,
};
use proptest::prelude::*;

fn question(rtype: RecordType) -> Question<'static> {
    Question::new(Name::root(), rtype)
}

#[test]
fn s4_two_questions_are_decoded_and_flagged() {
    let message = Message {
        questions: vec![question(RecordType::A), question(RecordType::AAAA)],
        ..Message::default()
    };
    let wire = message.to_vec().unwrap();
    let decoded = Message::decode(&wire).unwrap();
    assert_eq!(decoded.violations, [Violation::MultipleQuestions]);
    assert_eq!(decoded.message, message);
}

#[test]
fn s4_zero_and_one_question_are_fine() {
    let message = Message::default();
    assert_eq!(
        Message::decode(&message.to_vec().unwrap())
            .unwrap()
            .violations,
        []
    );
    let message = Message {
        questions: vec![question(RecordType::A)],
        ..message
    };
    assert_eq!(
        Message::decode(&message.to_vec().unwrap())
            .unwrap()
            .violations,
        []
    );
}

#[test]
fn trailing_bytes_are_flagged() {
    let mut wire = Message::default().to_vec().unwrap();
    wire.extend_from_slice(&[1, 2, 3]);
    let decoded = Message::decode(&wire).unwrap();
    assert_eq!(decoded.violations, [Violation::TrailingBytes { len: 3 }]);
}

#[test]
fn a_section_cut_short_is_an_error() {
    let mut wire = vec![0; 12];
    wire[5] = 1; // QDCOUNT 1, no question
    assert_eq!(
        Message::decode(&wire).unwrap_err().kind,
        DecodeErrorKind::UnexpectedEnd
    );
    let mut wire = vec![0; 12];
    wire[7] = 200; // ANCOUNT 200, no record
    assert_eq!(
        Message::decode(&wire).unwrap_err().kind,
        DecodeErrorKind::UnexpectedEnd
    );
}

#[test]
fn a_short_header_is_an_error() {
    assert!(Message::decode(&[0; 11]).is_err());
}

#[test]
fn invalid_rdata_is_flagged_with_its_place() {
    let message = Message {
        answer: vec![dedens_proto::Record::new(
            Name::root(),
            Class::IN,
            dedens_proto::Ttl::ZERO,
            &dedens_proto::RData::A("1.2.3.4".parse().unwrap()),
        )],
        ..Message::default()
    };
    let mut wire = message.to_vec().unwrap();
    let len = wire.len();
    wire[len - 5] = 3; // RDLENGTH 3 for an A record
    wire.pop();
    let decoded = Message::decode(&wire).unwrap();
    assert!(matches!(
        decoded.violations.as_slice(),
        [Violation::InvalidRdata {
            section: dedens_proto::Section::Answer,
            index: 0,
            ..
        }]
    ));
}

/// `recycle` keeps every allocation: it relies on the standard library collecting in place, which this checks.
/// The EDNS options, kept privately, are checked in `message.rs`.
#[test]
fn decoding_into_a_spare_reuses_its_vectors() {
    let a = |i| common::rec(".", RData::A(Ipv4Addr::new(192, 0, 2, i)));
    let message = Message {
        // Two questions: one violation.
        questions: vec![question(RecordType::A), question(RecordType::AAAA)],
        answer: (0..4).map(a).collect(),
        authority: vec![a(4)],
        additional: vec![a(5)],
        edns: Some(Edns {
            options: vec![EdnsOption::Padding(1), EdnsOption::Keepalive(None)],
            ..Edns::default()
        }),
        ..Message::default()
    };
    let wire = message.to_vec().unwrap();
    let mut spare = Decoded::default();
    let pointers = |d: &Decoded<'_>| {
        let m = &d.message;
        [
            m.questions.as_ptr().cast::<u8>(),
            m.answer.as_ptr().cast(),
            m.authority.as_ptr().cast(),
            m.additional.as_ptr().cast(),
            d.violations.as_ptr().cast(),
        ]
    };
    let capacities = |d: &Decoded<'_>| {
        let m = &d.message;
        [
            m.questions.capacity(),
            m.answer.capacity(),
            m.authority.capacity(),
            m.additional.capacity(),
            d.violations.capacity(),
        ]
    };

    let first = Message::decode_reusing(&wire, &mut spare).unwrap();
    assert_eq!(first, Message::decode(&wire).unwrap());
    let allocations = pointers(&first);
    spare = first.recycle();
    assert_eq!(spare.message, Message::default());
    let kept = capacities(&spare).into_iter().zip([2, 4, 1, 1, 1]);
    assert!(kept.into_iter().all(|(capacity, len)| capacity >= len));
    let second = Message::decode_reusing(&wire, &mut spare).unwrap();
    assert_eq!(second.message, message);
    assert_eq!(pointers(&second), allocations);

    spare = second.recycle();
    assert!(Message::decode_reusing(&wire[..wire.len() - 1], &mut spare).is_err());
    assert!(spare.message.answer.capacity() >= 4);
}

proptest! {
    #[test]
    fn round_trip(message in common::message()) {
        let wire = message.to_vec().unwrap();
        let decoded = Message::decode(&wire).unwrap();
        prop_assert_eq!(decoded.message, message);
    }

    #[test]
    fn decoding_never_panics(bytes in prop::collection::vec(any::<u8>(), 0..300)) {
        let _ = Message::decode(&bytes);
    }

    #[test]
    fn decoding_into_a_used_spare_is_decoding(first in common::message(), second in common::message()) {
        let (first, second) = (first.to_vec().unwrap(), second.to_vec().unwrap());
        let mut spare = Decoded::default();
        spare = Message::decode_reusing(&first, &mut spare).unwrap().recycle();
        prop_assert_eq!(
            Message::decode_reusing(&second, &mut spare).unwrap(),
            Message::decode(&second).unwrap()
        );
    }
}
