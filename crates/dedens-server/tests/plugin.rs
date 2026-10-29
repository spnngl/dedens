//! Plugin stages (D54): an answer is written after the client's question, with AA when the plugin is
//! authoritative; a query the plugin passes on goes to the next stage.

mod common;

use std::net::Ipv4Addr;

use common::{decode, dns, run, servers, wire};
use dedens_proto::edns::{EdnsOption, InfoCode};
use dedens_proto::{
    Class, Edns, Flags, Message, Name, Query, Question, RData, Rcode, Record, RecordType, Ttl,
};
use dedens_server::{Answer, Forward, Pipeline, Plugin, Records, Stage, Transport};

/// Answers A queries for `local.test.` with `count` addresses, and blocks `blocked.test.`.
#[derive(Debug)]
struct Local {
    records: Records,
}

impl Local {
    fn new(count: u8) -> Self {
        let name = dns("local.test");
        let records: Vec<_> = (0..count)
            .map(|i| {
                let data = RData::A(Ipv4Addr::new(192, 0, 2, i));
                Record::new(name.clone(), Class::IN, Ttl::from_wire(60), &data)
            })
            .collect();
        Self {
            records: Records::new(&name, &records).expect("the records fit"),
        }
    }
}

impl Plugin for Local {
    fn answer(&self, query: &Query<'_>) -> Option<Answer<'_>> {
        let question = query.question()?;
        if question.name == dns("blocked.test") {
            return Some(Answer {
                rcode: Rcode::NXDOMAIN,
                records: None,
                authoritative: false,
                error: Some(InfoCode::BLOCKED),
            });
        }
        (question.name == dns("local.test")).then_some(Answer {
            rcode: Rcode::NOERROR,
            records: (question.qtype == RecordType::A).then_some(&self.records),
            authoritative: true,
            error: None,
        })
    }
}

fn pipeline(count: u8) -> Pipeline {
    Pipeline::new(vec![
        Stage::Plugin(Box::new(Local::new(count))),
        Stage::Forward(Forward::new(servers()).expect("servers")),
    ])
}

fn query(name: &str, qtype: RecordType, edns: bool) -> Vec<u8> {
    let name: Name<'static> = name.parse().expect("a name");
    let mut query = Message::query(7, Question::new(name, qtype));
    if !edns {
        query.edns = None;
    }
    wire(&query)
}

/// RFC 1035 §4.1.1: AA, the plugin holding the name; the answer owned by the question's name, in its case
/// (RFC 4343 §4), the OPT record after the records (RFC 6891 §7).
#[test]
fn an_answer_follows_the_question_in_its_case() {
    let done = run(
        &pipeline(2),
        &query("LoCaL.TeSt.", RecordType::A, true),
        Transport::Udp,
        &[],
    );
    assert_eq!(done.asked, []);
    let wire = done.reply.expect("a reply");
    let reply = decode(&wire);
    assert_eq!(reply.header.id, 7);
    assert_eq!(
        reply.header.flags,
        Flags::QR | Flags::AA | Flags::RD | Flags::RA
    );
    assert_eq!(reply.rcode(), Rcode::NOERROR);
    assert_eq!(reply.questions[0].name.to_string(), "LoCaL.TeSt.");
    let owners: Vec<_> = reply.answer.iter().map(|r| r.name.to_string()).collect();
    assert_eq!(owners, ["LoCaL.TeSt.", "LoCaL.TeSt."]);
    let data: Vec<_> = reply.answer.iter().map(Record::data).collect();
    assert_eq!(
        data,
        [
            RData::A(Ipv4Addr::new(192, 0, 2, 0)),
            RData::A(Ipv4Addr::new(192, 0, 2, 1))
        ]
    );
    assert_eq!(reply.edns, Some(Edns::default()));
}

/// RFC 2308 §2.2: no data, NOERROR with an empty answer.
#[test]
fn a_name_without_records_of_the_type_has_no_data() {
    let wire = run(
        &pipeline(1),
        &query("local.test.", RecordType::MX, false),
        Transport::Udp,
        &[],
    )
    .reply
    .expect("a reply");
    let reply = decode(&wire);
    assert_eq!((reply.rcode(), reply.answer.len()), (Rcode::NOERROR, 0));
    assert!(reply.header.flags.contains(Flags::AA));
}

/// RFC 8914 §4.16: Blocked; AA clear, the plugin being no authority.
#[test]
fn an_error_goes_in_our_opt_record() {
    let wire = run(
        &pipeline(1),
        &query("blocked.test.", RecordType::A, true),
        Transport::Udp,
        &[],
    )
    .reply
    .expect("a reply");
    let reply = decode(&wire);
    assert_eq!(reply.rcode(), Rcode::NXDOMAIN);
    assert!(!reply.header.flags.contains(Flags::AA));
    let options = reply.edns.expect("our OPT record").options;
    assert!(
        matches!(&options[..], [EdnsOption::Ede(e)] if e.code == InfoCode::BLOCKED),
        "{options:?}"
    );
}

/// RFC 2181 §9: records that do not fit 512 bytes are left out, with TC.
#[test]
fn records_too_large_for_the_client_set_tc() {
    let wire = run(
        &pipeline(40),
        &query("local.test.", RecordType::A, false),
        Transport::Udp,
        &[],
    )
    .reply
    .expect("a reply");
    let reply = decode(&wire);
    assert!(reply.header.flags.contains(Flags::TC));
    assert_eq!(reply.answer.len(), 0);
    let tcp = run(
        &pipeline(40),
        &query("local.test.", RecordType::A, false),
        Transport::Tcp,
        &[],
    )
    .reply
    .expect("a reply");
    assert_eq!(decode(&tcp).answer.len(), 40);
}

#[test]
fn a_query_passed_on_goes_upstream() {
    let done = run(
        &pipeline(1),
        &query("example.com.", RecordType::A, true),
        Transport::Udp,
        &[],
    );
    assert_eq!(done.asked, servers());
}

/// A plugin answers without RD: its data is local, no recursion (RFC 1034 §4.3.1).
#[test]
fn a_plugin_answers_without_recursion_desired() {
    let mut message = Message::query(
        7,
        Question::new("local.test.".parse().expect("a name"), RecordType::A),
    );
    message.header.flags = Flags::default();
    let wire = run(&pipeline(1), &common::wire(&message), Transport::Udp, &[])
        .reply
        .expect("a reply");
    let reply = decode(&wire);
    assert_eq!(reply.answer.len(), 1);
    assert_eq!(reply.header.flags, Flags::QR | Flags::AA | Flags::RA);
}
