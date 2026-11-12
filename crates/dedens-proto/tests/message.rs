//! Whole messages: one question each, queries read in place, truncation, and the responses captured from public
//! servers.
//!
//! - RFC 9619: one question per message (§4), and the violations of D9.
//! - D21: a query read in place agrees with `Message::decode`; `Edns::append` adds an OPT record to a message.
//! - RFC 2181 §9 (truncation) and RFC 6891 §7 (the OPT record survives it), in `Message::encode_truncated`.
//! - RFC 1034 §4.3.2 step 3b: `Message::referral` tells a captured referral from an answer, NXDOMAIN and NODATA.
//! - Responses captured from public servers by `just capture` (`testdata/proto/capture.yaml`): they decode without
//!   a violation and re-encode to an equal message.

use std::fs;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::path::PathBuf;

use dedens_proto::edns::{Cookie, Edns, EdnsOption, EdnsView, InfoCode};
use dedens_proto::rdata::RData;
use dedens_proto::{
    Class, DecodeError, DecodeErrorKind, Decoded, EncodeError, Flags, Header, Message, Name, Query,
    Question, Rcode, Record, RecordType, Violation,
};
use dedens_testkit::{captured, dns, message};
use proptest::prelude::*;

use crate::util::rec;

// --- RFC 9619 ---

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
            &dedens_proto::rdata::RData::A("1.2.3.4".parse().unwrap()),
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
    let a = |i| crate::util::rec(".", RData::A(Ipv4Addr::new(192, 0, 2, i)));
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

/// A message takes at most 65535 bytes, the most TCP's length prefix tells (RFC 1035 §4.2.2).
#[test]
fn messages_up_to_65535_bytes_decode() {
    let wire = vec![0; 65_535];
    let decoded = Message::decode(&wire).expect("readable");
    assert_eq!(
        decoded.violations,
        [Violation::TrailingBytes { len: 65_535 - 12 }]
    );
    assert!(Message::decode(&vec![0; 65_536]).is_err());
}

proptest! {
    #[test]
    fn round_trip(message in crate::util::message()) {
        let wire = message.to_vec().unwrap();
        let decoded = Message::decode(&wire).unwrap();
        prop_assert_eq!(decoded.message, message);
    }

    #[test]
    fn decoding_never_panics(bytes in prop::collection::vec(any::<u8>(), 0..300)) {
        let _ = Message::decode(&bytes);
    }

    #[test]
    fn decoding_into_a_used_spare_is_decoding(first in crate::util::message(), second in crate::util::message()) {
        let (first, second) = (first.to_vec().unwrap(), second.to_vec().unwrap());
        let mut spare = Decoded::default();
        spare = Message::decode_reusing(&first, &mut spare).unwrap().recycle();
        prop_assert_eq!(
            Message::decode_reusing(&second, &mut spare).unwrap(),
            Message::decode(&second).unwrap()
        );
    }
}

// --- D21 ---

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
        Question::new(dedens_testkit::dns("example.com."), RecordType::AAAA),
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
    let mut message = Message::query(
        3,
        Question::new(dedens_testkit::dns("example."), RecordType::A),
    );
    message.edns = None;
    message.additional = vec![crate::util::rec(
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
    let mut message = Message::query(
        3,
        Question::new(dedens_testkit::dns("example."), RecordType::A),
    );
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
    fn reads_what_decode_reads(message in crate::util::message()) {
        assert_agrees(&message.to_vec().expect("encodes"));
    }

    #[test]
    fn agrees_with_decode_on_damaged_messages(
        message in crate::util::message(),
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

// --- RFC 2181 §9, RFC 6891 §7: truncation ---

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
    // TC joins the flags of the message, which stay with its opcode and rcode (RFC 1035 §4.1.1).
    let mut header = message.header;
    if encoded.truncated {
        header.flags = header.flags.with(Flags::TC);
    }
    assert_eq!(decoded.message.header, header);
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

/// `truncated` is a prefix of `message`, cut as D10 says: TC only for lost answer or authority records, and only
/// whole `RRsets` in the additional section.
fn assert_cut_from(message: &Message<'_>, truncated: &Message<'_>, tc: bool) {
    assert_eq!(truncated.questions, message.questions);
    assert_eq!(truncated.edns, message.edns);
    assert!(message.answer.starts_with(&truncated.answer));
    assert!(message.authority.starts_with(&truncated.authority));
    assert!(message.additional.starts_with(&truncated.additional));
    let lost = |of: &Message<'_>| of.answer.len() + of.authority.len();
    assert_eq!(tc, lost(truncated) < lost(message));
    let rrset = |of: &[Record<'_>], r: &Record<'_>| {
        of.iter()
            .filter(|o| o.name == r.name && o.rtype() == r.rtype() && o.class == r.class)
            .count()
    };
    for r in &truncated.additional {
        assert_eq!(
            rrset(&truncated.additional, r),
            rrset(&message.additional, r)
        );
    }
}

/// Each captured response cut at every size that holds its header, question and OPT record.
#[test]
fn s9_every_capture_truncates_at_every_size() {
    for entry in fs::read_dir(dir()).expect("testdata directory") {
        let path = entry.expect("entry").path();
        if path.extension().is_none_or(|e| e != "bin") {
            continue;
        }
        let message = message(&fs::read(&path).expect("captured file"));
        let mut essentials = message.clone();
        essentials.answer.clear();
        essentials.authority.clear();
        essentials.additional.clear();
        let essentials = essentials.to_vec().expect("encodes").len();
        let full = message.to_vec().expect("encodes").len();
        for size in essentials..=full {
            let (decoded, tc) = truncated(&message, size);
            assert_cut_from(&message, &decoded, tc);
        }
        assert_eq!(truncated(&message, full).0, message, "{}", path.display());
    }
}

/// The records of every DNSSEC capture as additional data of a captured referral: past the 192 names of the
/// compression table (D112), a cut section written again is no longer and keeps whole `RRsets`.
#[test]
fn s9_additional_data_past_a_full_name_table_truncates_to_whole_rrsets() {
    let mut message = message(&captured("referral_root"));
    for id in dedens_testkit::dnssec::names() {
        let response = dedens_testkit::dnssec::response(&id);
        message
            .additional
            .extend([response.answer, response.authority, response.additional].concat());
    }
    for zone in ["rfc4035_appendix_a.zone", "rfc5155_appendix_a.zone"] {
        message.additional.extend(dedens_testkit::zone(zone));
    }
    // The table holds the suffixes of the owner names, among other names.
    let mut suffixes: Vec<String> = message
        .additional
        .iter()
        .flat_map(|r| {
            let labels: Vec<_> = r.name.labels().collect();
            (0..labels.len()).map(move |i| format!("{:?}", &labels[i..]))
        })
        .collect();
    suffixes.sort();
    suffixes.dedup();
    assert!(suffixes.len() > 192, "{} owner suffixes", suffixes.len());
    for size in (512..=65535).step_by(509) {
        let (decoded, tc) = truncated(&message, size);
        assert_cut_from(&message, &decoded, tc);
    }
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
    fn a_truncated_message_decodes_to_a_prefix(m in crate::util::message(), size in 12usize..600) {
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

// --- Captured responses ---

fn dir() -> PathBuf {
    dedens_testkit::path("proto")
}

#[test]
fn every_capture_decodes_and_round_trips() {
    let mut count = 0;
    for entry in fs::read_dir(dir()).expect("testdata directory") {
        let path = entry.expect("entry").path();
        if path.extension().is_none_or(|e| e != "bin") {
            continue;
        }
        let name = path
            .file_stem()
            .expect("stem")
            .to_string_lossy()
            .into_owned();
        let wire = fs::read(&path).expect("captured file");
        let decoded = Message::decode(&wire).expect("decodes");
        assert_eq!(decoded.violations, [], "{name}");
        let message = decoded.message;
        let wire = message.to_vec().expect("encodes");
        let again = Message::decode(&wire).expect("decodes again");
        assert_eq!(again.violations, [], "{name}");
        assert_eq!(again.message, message, "{name}");
        count += 1;
    }
    assert!(count >= 16, "{count} captures");
}

#[test]
fn a_response_has_an_answer_and_opt() {
    let message = message(&captured("a"));
    assert!(message.header.flags.contains(Flags::QR));
    assert!(
        message
            .answer
            .iter()
            .any(|r| matches!(r.data(), RData::A(_)))
    );
    assert!(message.edns.is_some());
}

#[test]
fn a_cname_chain_ends_in_an_address() {
    let message = message(&captured("cname_chain"));
    assert!(matches!(
        message.answer.first().map(Record::data),
        Some(RData::Cname(_))
    ));
    assert!(
        message
            .answer
            .iter()
            .any(|r| matches!(r.data(), RData::A(_)))
    );
}

#[test]
fn nxdomain_carries_the_zone_soa() {
    let message = message(&captured("nxdomain_soa"));
    assert_eq!(message.rcode(), Rcode::NXDOMAIN);
    assert_eq!(message.answer, []);
    assert!(
        message
            .authority
            .iter()
            .any(|r| matches!(r.data(), RData::Soa(_)))
    );
}

#[test]
fn a_large_txt_answer_decodes() {
    let message = message(&captured("txt_large"));
    assert!(
        message
            .answer
            .iter()
            .any(|r| matches!(r.data(), RData::Txt(_)))
    );
}

#[test]
fn https_and_caa_and_srv_have_typed_data() {
    assert!(
        message(&captured("https"))
            .answer
            .iter()
            .any(|r| matches!(r.data(), RData::Https(_)))
    );
    assert!(
        message(&captured("caa"))
            .answer
            .iter()
            .any(|r| matches!(r.data(), RData::Caa(_)))
    );
    assert!(
        message(&captured("srv"))
            .answer
            .iter()
            .any(|r| matches!(r.data(), RData::Srv(_)))
    );
}

#[test]
fn any_gets_a_minimal_hinfo_answer_rfc8482() {
    let message = message(&captured("any_rfc8482"));
    assert_eq!(message.answer.len(), 1);
    // HINFO has no typed RDATA in D11: it stays opaque.
    assert_eq!(
        message.answer.first().map(|r| r.data().rtype()),
        Some(RecordType(13))
    );
}

#[test]
fn a_truncated_response_has_tc_and_no_records() {
    let message = message(&captured("truncated"));
    assert!(message.header.flags.contains(Flags::TC));
    assert_eq!(message.answer, []);
}

#[test]
fn a_dnssec_failure_comes_with_an_extended_error() {
    let message = message(&captured("ede"));
    assert_eq!(message.rcode(), Rcode::SERVFAIL);
    let edns = message.edns.expect("OPT");
    assert!(
        edns.options
            .iter()
            .any(|o| matches!(o, EdnsOption::Ede(e) if e.code == InfoCode::DNSKEY_MISSING))
    );
}

#[test]
fn nsid_is_answered() {
    let edns = message(&captured("nsid")).edns.expect("OPT");
    assert!(
        edns.options
            .iter()
            .any(|o| matches!(o, EdnsOption::Nsid(id) if !id.is_empty()))
    );
}

#[test]
fn a_cookie_is_returned_with_a_server_part() {
    let edns = message(&captured("cookie")).edns.expect("OPT");
    let cookie = edns.options.iter().find_map(|o| match o {
        EdnsOption::Cookie(c) => Some(c),
        _ => None,
    });
    let cookie = cookie.expect("COOKIE option");
    assert_eq!(cookie.client(), [1, 2, 3, 4, 5, 6, 7, 8]);
    assert!(cookie.server().is_some());
}

#[test]
fn referrals_are_told_from_other_responses() {
    let zone = |name: &str| message(&captured(name)).referral().map(ToString::to_string);
    assert_eq!(zone("referral_root").as_deref(), Some("com."));
    assert_eq!(zone("referral_com").as_deref(), Some("example.com."));
    // An answer, NXDOMAIN and NODATA (with a SOA), an HINFO answer and SERVFAIL are not.
    for name in ["a", "nxdomain_soa", "nodata", "any_rfc8482", "ede"] {
        assert_eq!(zone(name), None, "{name}");
    }
}
