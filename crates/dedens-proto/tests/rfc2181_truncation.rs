//! RFC 2181 §9 (truncation) and RFC 6891 §7 (the OPT record survives it), in `Message::encode_truncated`.

mod common;

use std::net::{Ipv4Addr, Ipv6Addr};

use common::{dns, message, rec};
use dedens_proto::edns::EdnsOption;
use dedens_proto::{Edns, Flags, Message, Question, RData, Record, RecordType, Violation};
use proptest::prelude::*;

fn a(n: u8) -> RData<'static> {
    RData::A(Ipv4Addr::new(192, 0, 2, n))
}

/// A question and `answers` A records on the root name: 12 + 5 header and question, 15 bytes per record.
fn response(answers: u8, additional: u8) -> Message<'static> {
    let mut message = Message::query(1, Question::new(dns(""), RecordType::A));
    message.edns = None;
    message.answer = (0..answers).map(|n| rec("", a(n))).collect();
    message.additional = (0..additional).map(|n| rec("", a(n))).collect();
    message
}

fn truncated(message: &Message<'_>, size: usize) -> (Message<'static>, bool) {
    let mut buf = vec![0; size];
    let encoded = message
        .encode_truncated(&mut buf)
        .expect("room for the essentials");
    assert!(encoded.len <= size);
    let decoded = Message::decode(&buf[..encoded.len]).expect("a decodable message");
    assert_eq!(decoded.violations, []);
    assert_eq!(
        decoded.message.header.flags.contains(Flags::TC),
        encoded.truncated
    );
    (decoded.message.into_owned(), encoded.truncated)
}

/// The records of an `RRset` need not be next to each other: none of them may stay when one is dropped.
#[test]
fn s9_an_interleaved_rrset_is_dropped_whole() {
    let mut message = response(0, 0);
    message.additional = vec![
        rec("x", a(1)),
        rec("y", a(2)),
        rec("x", a(3)),
        rec("z", a(4)),
    ];
    let full = message.to_vec().expect("encodes").len();
    // Room for all but the last record: z is dropped, x and y are whole.
    let (decoded, _) = truncated(&message, full - 1);
    assert_eq!(decoded.additional, message.additional[..3]);
    // Room for x and y only: the second x does not fit, so the first goes too, and y after it.
    let (decoded, tc) = truncated(&message, full - 16 - 18);
    assert!(!tc);
    assert_eq!(decoded.additional, []);
    // An RRset written before the cut and continued after it is dropped too.
    message.additional = vec![
        rec("x", a(1)),
        rec("y", a(2)),
        rec("y", a(3)),
        rec("x", a(4)),
    ];
    let full = message.to_vec().expect("encodes").len();
    let (decoded, _) = truncated(&message, full - 1);
    assert_eq!(decoded.additional, []);
}

/// Thousands of additional records, as a hostile upstream may send: whole `RRsets` are kept, in linear time.
#[test]
fn s9_thousands_of_additional_records() {
    let names: Vec<String> = (0..2000).map(|i| format!("n{i}")).collect();
    let mut message = response(1, 0);
    message.additional = names.iter().map(|n| rec(n, a(1))).collect();
    // Room for about half: each `RRset` has one record, so the records that fit stay.
    let (decoded, tc) = truncated(&message, 16 * 1024);
    assert!(!tc);
    assert!(decoded.additional.len() > 800, "16 KiB of 20-byte records");
    assert!(message.additional.starts_with(&decoded.additional));
    // A second record for each `RRset` after the first ones: any cut splits one, so none stays.
    message
        .additional
        .extend(names.iter().map(|n| rec(n, a(2))));
    let (decoded, tc) = truncated(&message, 32 * 1024);
    assert!(!tc);
    assert_eq!(decoded.additional, []);
}

#[test]
fn s9_a_message_that_fits_is_whole() {
    let message = response(3, 0);
    let (decoded, tc) = truncated(&message, 512);
    assert_eq!(decoded, message);
    assert!(!tc);
}

#[test]
fn s9_lost_answers_set_tc() {
    let message = response(5, 0);
    let (decoded, tc) = truncated(&message, 17 + 15 * 3 + 14);
    assert!(tc);
    assert_eq!(decoded.answer, message.answer[..3]);
}

#[test]
fn s9_lost_additional_data_does_not_set_tc_and_drops_its_whole_rrset() {
    let message = response(1, 4);
    let mut buf = vec![0; 17 + 15 * 3];
    let encoded = message.encode_truncated(&mut buf).unwrap();
    assert_eq!((encoded.truncated, encoded.dropped), (false, 4));
    let (decoded, tc) = truncated(&message, 17 + 15 * 3);
    assert!(!tc);
    assert_eq!(decoded.answer.len(), 1);
    assert_eq!(
        decoded.additional,
        [],
        "2 of the 4 A records would pass for the whole RRset"
    );
}

#[test]
fn s9_whole_additional_rrsets_before_the_cut_are_kept() {
    let mut message = response(1, 2);
    let aaaa = |n| {
        rec(
            "",
            RData::Aaaa(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, n)),
        )
    };
    message.additional.extend([aaaa(1), aaaa(2)]);
    // Header, question, the answer, the 2 A records and 1 of the 2 AAAA records (27 bytes).
    let (decoded, tc) = truncated(&message, 17 + 15 * 3 + 27);
    assert!(!tc);
    assert_eq!(decoded.additional, message.additional[..2]);
}

#[test]
fn s9_nothing_is_written_after_the_first_record_that_does_not_fit() {
    let mut message = response(2, 1);
    message.authority = vec![rec("", a(9))];
    let (decoded, tc) = truncated(&message, 17 + 15 + 14);
    assert!(tc);
    assert_eq!(
        (
            decoded.answer.len(),
            decoded.authority.len(),
            decoded.additional.len()
        ),
        (1, 0, 0)
    );
}

#[test]
fn s9_the_header_and_questions_are_never_dropped() {
    let message = response(1, 0);
    let mut buf = [0; 16];
    assert_eq!(
        message.encode_truncated(&mut buf),
        Err(dedens_proto::EncodeError::BufferFull)
    );
}

#[test]
fn encode_does_not_truncate() {
    let message = response(5, 0);
    let mut buf = [0; 40];
    assert_eq!(
        message.encode(&mut buf),
        Err(dedens_proto::EncodeError::BufferFull)
    );
}

#[test]
fn rfc6891_s7_the_opt_record_is_kept() {
    let mut message = response(5, 0);
    message.edns = Some(Edns {
        options: vec![EdnsOption::Padding(10)],
        ..Edns::default()
    });
    let size = 17 + 15 * 2 + 14 + message.edns.as_ref().unwrap().wire_len();
    let (decoded, tc) = truncated(&message, size);
    assert!(tc);
    assert_eq!(decoded.answer.len(), 2);
    assert_eq!(decoded.edns, message.edns);
}

#[test]
fn rfc6891_s7_the_opt_record_must_fit() {
    let mut message = response(0, 0);
    message.edns = Some(Edns::default());
    let mut buf = vec![0; 17 + 10];
    assert_eq!(
        message.encode_truncated(&mut buf),
        Err(dedens_proto::EncodeError::BufferFull)
    );
}

proptest! {
    #[test]
    fn a_truncated_message_decodes_to_a_prefix(m in message(), size in 12usize..600) {
        let mut buf = vec![0; size];
        if let Ok(encoded) = m.encode_truncated(&mut buf) {
            let decoded = Message::decode(&buf[..encoded.len]).unwrap();
            prop_assert!(decoded.violations.iter().all(|v| matches!(v, Violation::MultipleQuestions)));
            let d = decoded.message;
            prop_assert_eq!(&d.questions, &m.questions);
            prop_assert_eq!(&d.edns, &m.edns);
            prop_assert!(m.answer.starts_with(&d.answer));
            prop_assert!(m.authority.starts_with(&d.authority));
            prop_assert!(m.additional.starts_with(&d.additional));
            // Every `RRset` kept in the additional section is whole.
            let rrset = |of: &[Record<'_>], r: &Record<'_>| {
                of.iter().filter(|o| o.name == r.name && o.rtype() == r.rtype() && o.class == r.class).count()
            };
            for r in &d.additional {
                prop_assert_eq!(rrset(&d.additional, r), rrset(&m.additional, r));
            }
            prop_assert_eq!(
                encoded.truncated,
                d.answer.len() < m.answer.len() || (d.answer.len() == m.answer.len() && d.authority.len() < m.authority.len()),
            );
        }
    }
}
