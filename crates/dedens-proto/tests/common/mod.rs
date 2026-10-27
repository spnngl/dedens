//! Shared proptest strategies and helpers of the integration tests.

#![allow(dead_code, reason = "each test crate uses a subset")]

use dedens_proto::wire::{Reader, Writer};
use dedens_proto::{Class, Counts, Flags, Header, Name, Opcode, Question, Rcode, RecordType};
use proptest::prelude::*;

/// A name of up to 5 labels of 1 to 20 arbitrary bytes.
pub(crate) fn name() -> impl Strategy<Value = Name> {
    prop::collection::vec(prop::collection::vec(any::<u8>(), 1..=20), 0..=5).prop_map(|labels| {
        Name::from_labels(labels.iter().map(Vec::as_slice)).expect("labels are within the limits")
    })
}

pub(crate) fn flags() -> impl Strategy<Value = Flags> {
    any::<u16>().prop_map(Flags::from_word)
}

pub(crate) fn header() -> impl Strategy<Value = Header> {
    (any::<u16>(), flags(), 0u8..16, 0u16..16).prop_map(|(id, flags, opcode, rcode)| Header {
        id,
        flags,
        opcode: Opcode(opcode),
        rcode: Rcode(rcode),
    })
}

pub(crate) fn counts() -> impl Strategy<Value = Counts> {
    any::<[u16; 4]>().prop_map(|[questions, answers, authority, additional]| Counts {
        questions,
        answers,
        authority,
        additional,
    })
}

pub(crate) fn question() -> impl Strategy<Value = Question> {
    (name(), any::<u16>(), any::<u16>()).prop_map(|(name, qtype, qclass)| Question {
        name,
        qtype: RecordType(qtype),
        qclass: Class(qclass),
    })
}

/// A name from labels given without the root.
pub(crate) fn name_of(labels: &[&[u8]]) -> Name {
    Name::from_labels(labels.iter().copied()).expect("labels are within the limits")
}

/// Encodes with `f` into a buffer of the maximum size and returns the bytes.
pub(crate) fn encode_with<E: std::fmt::Debug>(
    f: impl FnOnce(&mut Writer<'_>) -> Result<(), E>,
) -> Vec<u8> {
    let mut buf = vec![0; dedens_proto::wire::MAX_MESSAGE_LEN];
    let mut w = Writer::new(&mut buf);
    f(&mut w).expect("fits in 65535 bytes");
    w.written().to_vec()
}

/// A reader over the whole of `bytes`.
pub(crate) fn reader(bytes: &[u8]) -> Reader<'_> {
    Reader::new(bytes)
}
