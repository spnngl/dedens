//! D20: a message read in place agrees with `Message::decode`, and stays within its fixed table.

mod common;

use std::fs;
use std::net::Ipv4Addr;
use std::path::PathBuf;

use dedens_proto::view::MAX_ENTRIES;
use dedens_proto::{
    DecodeErrorKind, Message, MessageIndex, Question, RData, RecordType, Section, Ttl,
};
use proptest::prelude::*;

/// The view and `Message::decode` accept the same inputs and read the same message from them.
fn assert_agrees(index: &mut MessageIndex, wire: &[u8]) {
    let decoded = Message::decode(wire);
    let viewed = index.read(wire).map(|view| view.to_decoded());
    assert_eq!(viewed, decoded);
}

#[test]
fn every_capture_reads_as_decoded() {
    let mut index = MessageIndex::new();
    let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/testdata");
    for entry in fs::read_dir(dir).expect("testdata directory") {
        let path = entry.expect("entry").path();
        if path.extension().is_some_and(|e| e == "bin") {
            assert_agrees(&mut index, &fs::read(path).expect("captured file"));
        }
    }
}

#[test]
fn records_are_reached_without_reading_those_before() {
    let mut message = Message::query(1, Question::new(common::dns("example."), RecordType::A));
    message.answer = (0..5)
        .map(|i| {
            common::rec(
                &format!("h{i}.example."),
                RData::A(Ipv4Addr::new(192, 0, 2, i)),
            )
        })
        .collect();
    let wire = message.to_vec().expect("encodes");
    let mut index = MessageIndex::new();
    let view = index.read(&wire).expect("reads");
    let third = view.answer().nth(2).expect("third record");
    assert_eq!(third.to_record(), message.answer[2]);
    assert_eq!(view.answer().len(), 5);
    assert_eq!(view.section(Section::Additional).len(), 0);
    assert_eq!(view.edns(), message.edns);
}

#[test]
fn a_ttl_is_rewritten_in_a_copy_of_the_bytes() {
    let mut message = Message::query(1, Question::new(common::dns("example."), RecordType::A));
    message.answer = vec![common::rec(
        "example.",
        RData::A(Ipv4Addr::new(192, 0, 2, 1)),
    )];
    let mut wire = message.to_vec().expect("encodes");
    let mut index = MessageIndex::new();
    let at = index
        .read(&wire)
        .expect("reads")
        .answer()
        .next()
        .expect("record")
        .ttl_offset();
    wire[at..at + 4].copy_from_slice(&7_u32.to_be_bytes());
    let view = index.read(&wire).expect("reads");
    let record = view.answer().next().expect("record");
    assert_eq!(record.ttl(), Ttl::new(7).expect("valid TTL"));
    assert_eq!(record.rtype(), RecordType::A);
}

#[test]
fn the_largest_count_of_entries_fits_the_table() {
    // Root-name questions, 5 bytes each: as many entries as a message can hold.
    let questions = u16::try_from(MAX_ENTRIES).expect("fits the count field");
    let mut wire = vec![0, 1, 0, 0];
    wire.extend_from_slice(&questions.to_be_bytes());
    wire.extend_from_slice(&[0; 6]);
    for _ in 0..MAX_ENTRIES {
        wire.extend_from_slice(&[0, 0, 1, 0, 1]);
    }
    assert!(wire.len() <= 65535);
    let mut index = MessageIndex::new();
    assert_eq!(
        index.read(&wire).expect("reads").questions().len(),
        MAX_ENTRIES
    );
    assert_agrees(&mut index, &wire);
}

#[test]
fn a_message_over_65535_bytes_is_refused() {
    let mut index = MessageIndex::new();
    let error = index.read(&vec![0; 65536]).expect_err("too long");
    assert!(matches!(error.kind, DecodeErrorKind::Invalid(_)));
}

proptest! {
    #[test]
    fn reads_what_decode_reads(message in common::message()) {
        let wire = message.to_vec().expect("encodes");
        assert_agrees(&mut MessageIndex::new(), &wire);
    }

    #[test]
    fn agrees_with_decode_on_damaged_messages(
        message in common::message(),
        at in any::<prop::sample::Index>(),
        byte in any::<u8>(),
    ) {
        let mut wire = message.to_vec().expect("encodes");
        let at = at.index(wire.len());
        wire[at] = byte;
        assert_agrees(&mut MessageIndex::new(), &wire);
    }

    #[test]
    fn agrees_with_decode_on_any_bytes(bytes in prop::collection::vec(any::<u8>(), 0..300)) {
        assert_agrees(&mut MessageIndex::new(), &bytes);
    }
}
