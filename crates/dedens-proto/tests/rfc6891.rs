//! RFC 6891: EDNS(0) (§6).

mod common;

use common::{decode_options, opt_message, option_wire};
use dedens_proto::edns::{EdnsFlags, EdnsOption, OptionCode};
use dedens_proto::{
    DecodeErrorKind, EncodeError, Message, Name, Opcode, Question, Rcode, RecordType, Violation,
};
use proptest::prelude::*;

fn question() -> Question<'static> {
    Question::new(Name::root(), RecordType::A)
}

#[test]
fn s6_1_2_a_query_ends_with_the_opt_record() {
    let wire = Message::query(7, question()).to_vec().unwrap();
    assert_eq!(
        wire[wire.len() - 11..],
        [0, 0, 41, 0x04, 0xD0, 0, 0, 0, 0, 0, 0]
    );
    assert_eq!(wire[10..12], [0, 1], "ARCOUNT counts the OPT record");
}

#[test]
fn s6_1_2_fields_of_the_opt_record() {
    let mut wire = opt_message(&[]);
    wire[17..21].copy_from_slice(&[0x05, 0x01, 0xFF, 0xFF]);
    let decoded = Message::decode(&wire).unwrap();
    let edns = decoded.message.edns.unwrap();
    assert_eq!(edns.udp_payload, 1232);
    assert_eq!((edns.ext_rcode, edns.version), (5, 1));
    assert_eq!(edns.flags, EdnsFlags::from_bits(0xFFFF));
    assert!(edns.flags.contains(EdnsFlags::DO));
    assert!(
        decoded.message.additional.is_empty(),
        "the OPT record is lifted out of the section"
    );
    assert_eq!(decoded.violations, []);
}

#[test]
fn s6_1_3_the_do_bit_is_the_top_flag_bit() {
    let mut message = Message::query(1, question());
    message.edns.as_mut().unwrap().flags = EdnsFlags::DO;
    let wire = message.to_vec().unwrap();
    assert_eq!(wire[wire.len() - 6..wire.len() - 2], [0, 0, 0x80, 0]);
}

#[test]
fn s6_1_3_the_extended_rcode_is_split_between_header_and_opt() {
    let mut message = Message::query(1, question());
    message.set_rcode(Rcode(16)).unwrap(); // BADVERS
    assert_eq!(message.header.rcode, Rcode(0));
    assert_eq!(message.edns.as_ref().unwrap().ext_rcode, 1);
    let wire = message.to_vec().unwrap();
    assert_eq!(Message::decode(&wire).unwrap().message.rcode(), Rcode(16));
}

#[test]
fn s6_1_3_a_large_rcode_needs_edns() {
    let mut message = Message {
        edns: None,
        ..Message::default()
    };
    assert_eq!(
        message.set_rcode(Rcode(16)),
        Err(EncodeError::RcodeNeedsEdns)
    );
    assert_eq!(
        message.set_rcode(Rcode(4096)),
        Err(EncodeError::RcodeOutOfRange)
    );
    assert_eq!(message, Message::default(), "unchanged after an error");
    message.set_rcode(Rcode::NXDOMAIN).unwrap();
    assert_eq!(message.rcode(), Rcode::NXDOMAIN);
}

#[test]
fn s6_1_1_one_opt_record_at_most() {
    let mut wire = opt_message(&[]);
    wire[11] = 2;
    wire.extend_from_slice(&[0, 0, 41, 0x02, 0, 0, 0, 0, 0, 0, 0]);
    let decoded = Message::decode(&wire).unwrap();
    assert_eq!(decoded.violations, [Violation::MultipleOpt]);
    assert_eq!(
        decoded.message.edns.unwrap().udp_payload,
        1232,
        "the first one is used"
    );
    assert_eq!(
        decoded.message.additional.len(),
        1,
        "the second one is kept opaque"
    );
}

#[test]
fn s6_1_3_a_rejected_opt_record_keeps_its_ttl_field() {
    // Extended rcode 0x80 sets the top bit of the TTL field, which RFC 2181 §8 would make a TTL of 0.
    let mut wire = opt_message(&[]);
    wire[11] = 2;
    wire.extend_from_slice(&[0, 0, 41, 0x02, 0, 0x80, 0, 0x80, 0, 0, 0]);
    let decoded = Message::decode(&wire).unwrap();
    assert_eq!(decoded.message.additional[0].ttl.get(), 0x8000_8000);
}

#[test]
fn s6_1_3_the_header_rcode_holds_four_bits() {
    let mut message = Message::default();
    message.header.rcode = Rcode(16);
    assert_eq!(message.to_vec(), Err(EncodeError::RcodeOutOfRange));
    message.header.rcode = Rcode(0);
    message.header.opcode = Opcode(16);
    assert_eq!(message.to_vec(), Err(EncodeError::OpcodeOutOfRange));
}

#[test]
fn s6_1_1_opt_belongs_to_the_additional_section() {
    let mut wire = opt_message(&[]);
    wire[7] = 1; // ANCOUNT instead of ARCOUNT
    wire[11] = 0;
    let decoded = Message::decode(&wire).unwrap();
    assert_eq!(decoded.violations, [Violation::OptOutsideAdditional]);
    assert_eq!(decoded.message.edns, None);
    assert_eq!(decoded.message.answer.len(), 1);
}

#[test]
fn s6_1_2_the_owner_of_opt_is_the_root() {
    let mut wire = vec![0x12, 0x34, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 1];
    wire.extend_from_slice(&[1, b'a', 0, 0, 41, 0x04, 0xD0, 0, 0, 0, 0, 0, 0]);
    let decoded = Message::decode(&wire).unwrap();
    assert_eq!(decoded.violations, [Violation::OptOwnerNotRoot]);
    assert_eq!(decoded.message.edns, None);
}

#[test]
fn s6_1_2_options_keep_their_order() {
    let mut options = option_wire(0xFF01, b"one");
    options.extend(option_wire(0xFF00, b""));
    let decoded = decode_options(&options);
    let codes: Vec<_> = decoded
        .message
        .edns
        .unwrap()
        .options
        .iter()
        .map(EdnsOption::code)
        .collect();
    assert_eq!(codes, [OptionCode(0xFF01), OptionCode(0xFF00)]);
}

#[test]
fn s6_1_2_an_unknown_option_is_kept() {
    let decoded = decode_options(&option_wire(0xFF01, b"data"));
    assert_eq!(decoded.violations, []);
    assert_eq!(
        decoded.message.edns.unwrap().options,
        [EdnsOption::Unknown {
            code: OptionCode(0xFF01),
            data: b"data".as_slice().into()
        }]
    );
}

#[test]
fn s6_1_2_options_that_overrun_the_rdata_are_an_error() {
    let mut options = option_wire(0xFF01, b"data");
    options.pop();
    let err = Message::decode(&opt_message(&options)).unwrap_err();
    assert_eq!(err.kind, DecodeErrorKind::RdataLength);
    let err = Message::decode(&opt_message(&[0xFF])).unwrap_err();
    assert_eq!(err.kind, DecodeErrorKind::RdataLength);
}

proptest! {
    #[test]
    fn round_trip(edns in common::edns()) {
        let message = Message { edns: Some(edns), ..Message::default() };
        let wire = message.to_vec().unwrap();
        prop_assert_eq!(wire.len(), 12 + message.edns.as_ref().unwrap().wire_len());
        let decoded = Message::decode(&wire).unwrap();
        prop_assert_eq!(decoded.violations, []);
        prop_assert_eq!(decoded.message, message);
    }
}
