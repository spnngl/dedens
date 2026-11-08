//! D21: a query read in place agrees with `Message::decode`; `Edns::append` adds an OPT record to a message.

mod common;

use std::fs;

use dedens_proto::edns::{Cookie, Edns, EdnsOption, EdnsView};
use dedens_proto::{
    DecodeError, Decoded, EncodeError, Header, Message, Query, Question, Rcode, RecordType,
    Violation,
};
use proptest::prelude::*;

/// What a query reader keeps of a decoded message.
type Summary<'a> = (
    Header,
    Rcode,
    Option<Question<'a>>,
    Option<Edns<'a>>,
    Vec<Violation>,
);

fn summary(decoded: Decoded<'_>) -> Summary<'_> {
    let Decoded {
        message,
        violations,
        ..
    } = decoded;
    (
        message.header,
        message.rcode(),
        message.questions.into_iter().next(),
        message.edns,
        violations,
    )
}

fn assert_agrees(wire: &[u8]) {
    let read = Query::read(wire).map(|q| {
        (
            q.header(),
            q.rcode(),
            q.question().cloned(),
            q.edns().map(EdnsView::to_edns),
            q.violations().to_vec(),
        )
    });
    let decoded: Result<_, DecodeError> = Message::decode(wire).map(summary);
    // `Debug` shows names as written, so this also catches a change of case, which `==` ignores.
    assert_eq!(format!("{read:?}"), format!("{decoded:?}"));
}

#[test]
fn every_capture_reads_as_decoded() {
    for entry in fs::read_dir(dedens_testkit::path("proto")).expect("testdata directory") {
        let path = entry.expect("entry").path();
        if path.extension().is_some_and(|e| e == "bin") {
            assert_agrees(&fs::read(path).expect("captured file"));
        }
    }
}

#[test]
fn a_query_with_a_cookie_is_read_in_place() {
    let mut message = Message::query(
        9,
        Question::new(common::dns("example.com."), RecordType::AAAA),
    );
    let cookie = Cookie::new([1, 2, 3, 4, 5, 6, 7, 8], None).expect("client cookie");
    if let Some(edns) = message.edns.as_mut() {
        edns.options.push(EdnsOption::Cookie(cookie));
    }
    let wire = message.to_vec().expect("encodes");
    let query = Query::read(&wire).expect("reads");
    assert_eq!(query.header().id, 9);
    assert_eq!(query.question(), message.questions.first());
    let edns = query.edns().expect("EDNS");
    assert_eq!(edns.udp_payload, 1232);
    assert_eq!(
        edns.options().collect::<Vec<_>>(),
        [EdnsOption::Cookie(cookie)]
    );
    assert_eq!(query.violations(), []);
    assert_eq!(query.wire(), wire);
}

#[test]
fn append_adds_opt_after_the_records() {
    let mut message = Message::query(3, Question::new(common::dns("example."), RecordType::A));
    message.edns = None;
    message.additional = vec![common::rec(
        "example.",
        dedens_proto::rdata::RData::A([192, 0, 2, 1].into()),
    )];
    let mut buf = [0; 512];
    let len = message.encode(&mut buf).expect("encodes");
    let edns = Edns::default();
    let len = edns.append(&mut buf, len).expect("appends");
    let decoded = Message::decode(&buf[..len]).expect("decodes");
    assert_eq!(decoded.violations, []);
    assert_eq!(decoded.message.additional, message.additional);
    assert_eq!(decoded.message.edns, Some(edns));
}

#[test]
fn append_refuses_what_does_not_fit() {
    let mut message = Message::query(3, Question::new(common::dns("example."), RecordType::A));
    message.edns = None;
    let mut buf = [0; 40];
    let len = message.encode(&mut buf).expect("encodes");
    let edns = Edns::default();
    // 11 bytes of OPT after 25 of query: one byte short.
    assert_eq!(
        edns.append(&mut buf[..len + 10], len),
        Err(EncodeError::BufferFull)
    );
    assert_eq!(buf[11], 0, "ARCOUNT unchanged");
    assert_eq!(edns.append(&mut buf, 5), Err(EncodeError::BufferFull));
    assert_eq!(edns.append(&mut buf, 41), Err(EncodeError::BufferFull));
}

proptest! {
    #[test]
    fn reads_what_decode_reads(message in common::message()) {
        assert_agrees(&message.to_vec().expect("encodes"));
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
        assert_agrees(&wire);
    }

    #[test]
    fn agrees_with_decode_on_any_bytes(bytes in prop::collection::vec(any::<u8>(), 0..300)) {
        assert_agrees(&bytes);
    }
}
