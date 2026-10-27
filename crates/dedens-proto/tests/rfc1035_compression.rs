//! RFC 1035 §4.1.4: message compression in the encoder.

mod common;

use std::net::Ipv4Addr;

use common::{dns, rec};
use dedens_proto::rdata::{Mx, Srv};
use dedens_proto::{Message, Question, RData, RecordType};

fn a() -> RData<'static> {
    RData::A(Ipv4Addr::new(192, 0, 2, 1))
}

fn answer(records: Vec<dedens_proto::Record<'static>>) -> Message<'static> {
    Message {
        answer: records,
        ..Message::default()
    }
}

/// How many times `needle` appears in `haystack`.
fn occurrences(haystack: &[u8], needle: &[u8]) -> usize {
    haystack
        .windows(needle.len())
        .filter(|w| *w == needle)
        .count()
}

#[test]
fn hundreds_of_distinct_names_are_all_compressed() {
    let mut message = Message::query(1, Question::new(dns("example."), RecordType::A));
    message.edns = None;
    message.answer = (0..250)
        .map(|n| {
            rec(
                &format!("h{n}.example."),
                RData::A(Ipv4Addr::new(192, 0, 2, 1)),
            )
        })
        .collect();
    let wire = message.to_vec().unwrap();
    // Header, question; each record: its own label, a pointer to `example.`, fixed fields, address.
    let records: usize = (0..250)
        .map(|n| 1 + format!("h{n}").len() + 2 + 10 + 4)
        .sum();
    assert_eq!(wire.len(), 12 + 9 + 4 + records);
    assert_eq!(Message::decode(&wire).unwrap().message, message);
}

#[test]
fn a_repeated_name_costs_a_two_byte_pointer() {
    let message = answer(vec![rec("example.com", a()), rec("example.com", a())]);
    let wire = message.to_vec().unwrap();
    // header, "example.com" (13 bytes), 10 fixed + 4 RDATA; then pointer (2) and again 14.
    assert_eq!(wire.len(), 12 + 13 + 14 + 2 + 14);
    assert_eq!(wire[12 + 13 + 14..][..2], [0xC0, 12]);
    assert_eq!(Message::decode(&wire).unwrap().message, message);
}

#[test]
fn a_shared_suffix_is_pointed_to() {
    let message = answer(vec![rec("example.com", a()), rec("www.example.com", a())]);
    let wire = message.to_vec().unwrap();
    // "www" label, then a pointer to "example.com" at offset 12.
    assert_eq!(wire[12 + 13 + 14..][..6], [3, b'w', b'w', b'w', 0xC0, 12]);
    assert_eq!(Message::decode(&wire).unwrap().message, message);
}

#[test]
fn the_longest_earlier_suffix_wins_and_is_itself_compressed() {
    let message = answer(vec![
        rec("a.example.com", a()),
        rec("b.example.com", a()),
        rec("b.example.com", a()),
        rec("com", a()),
    ]);
    let wire = message.to_vec().unwrap();
    assert_eq!(occurrences(&wire, b"\x07example\x03com\x00"), 1);
    assert_eq!(occurrences(&wire, b"\x01b"), 1);
    assert_eq!(Message::decode(&wire).unwrap().message, message);
}

#[test]
fn a_question_name_is_pointed_to_by_the_answer() {
    let mut message = Message::query(1, Question::new(dns("example.com"), RecordType::A));
    message.edns = None;
    message.answer = vec![rec("example.com", a())];
    let wire = message.to_vec().unwrap();
    assert_eq!(occurrences(&wire, b"\x07example"), 1);
    assert_eq!(Message::decode(&wire).unwrap().message, message);
}

#[test]
fn rdata_names_of_rfc_1035_types_are_compressed() {
    let message = answer(vec![
        rec(
            "example.com",
            RData::Mx(Mx {
                preference: 10,
                exchange: dns("mail.example.com"),
            }),
        ),
        rec("example.com", RData::Ns(dns("ns.example.com"))),
    ]);
    let wire = message.to_vec().unwrap();
    assert_eq!(occurrences(&wire, b"\x07example"), 1);
    assert_eq!(Message::decode(&wire).unwrap().message, message);
}

#[test]
fn rdata_names_of_other_types_are_not_compressed_nor_pointed_to() {
    let srv = Srv {
        priority: 1,
        weight: 1,
        port: 80,
        target: dns("example.com"),
    };
    let message = answer(vec![
        rec("_http._tcp.test", RData::Srv(srv)),
        rec("example.com", a()),
        rec("example.com", a()),
    ]);
    let wire = message.to_vec().unwrap();
    // The name inside the SRV RDATA stays whole, and the later owners do not point into it: they hold the
    // name once more, the third points to the second.
    assert_eq!(occurrences(&wire, b"\x07example\x03com\x00"), 2);
    assert_eq!(Message::decode(&wire).unwrap().message, message);
}

#[test]
fn names_keep_their_case_and_only_match_byte_for_byte() {
    let message = answer(vec![rec("Example.COM", a()), rec("example.com", a())]);
    let wire = message.to_vec().unwrap();
    assert_eq!(occurrences(&wire, b"\x07Example\x03COM\x00"), 1);
    assert_eq!(occurrences(&wire, b"\x07example\x03com\x00"), 1);
    assert_eq!(Message::decode(&wire).unwrap().message, message);
}

#[test]
fn pointers_only_reach_the_first_16384_bytes() {
    let filler = rec(
        "filler.test",
        RData::Txt(dedens_proto::rdata::Txt::new([&[b'x'; 255][..]]).unwrap()),
    );
    let mut records = vec![filler; 70];
    records.push(rec("late.example", a()));
    records.push(rec("late.example", a()));
    let message = answer(records);
    let wire = message.to_vec().unwrap();
    assert!(wire.len() > 0x4000 + 100);
    assert_eq!(occurrences(&wire, b"\x04late\x07example\x00"), 2);
    assert_eq!(Message::decode(&wire).unwrap().message, message);
}

#[test]
fn a_full_name_table_only_costs_compression() {
    let records = (0..400)
        .map(|i| rec(&format!("host{i}.example.com"), a()))
        .collect();
    let message = answer(records);
    let wire = message.to_vec().unwrap();
    assert_eq!(Message::decode(&wire).unwrap().message, message);
}
