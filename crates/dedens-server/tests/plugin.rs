//! Plugin stages (D54): an answer is written after the client's question, with AA when the plugin is
//! authoritative; a query the plugin passes on goes to the next stage.

mod common;

use std::net::Ipv4Addr;

use common::{decode, dns, run, servers, wire};
use dedens_proto::edns::{EdnsOption, InfoCode};
use dedens_proto::{
    Class, Edns, Flags, Message, Name, Opcode, Query, Question, RData, Rcode, Record, RecordType,
    Ttl,
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
    assert_eq!((reply.header.id, reply.header.opcode), (7, Opcode::QUERY));
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

/// Answers every query with its fields.
#[derive(Debug)]
struct Fixed {
    rcode: Rcode,
    records: Option<Records>,
    error: Option<InfoCode>,
}

impl Fixed {
    /// A pipeline of this plugin alone, answering `records` of `local.test.`, none when empty.
    fn pipeline(rcode: Rcode, records: &[&str], error: Option<InfoCode>) -> Pipeline {
        let records: Vec<Record<'static>> = records
            .iter()
            .map(|text| text.parse().expect("a record"))
            .collect();
        let records = (!records.is_empty())
            .then(|| Records::new(&dns("local.test"), &records).expect("the records fit"));
        Pipeline::new(vec![Stage::Plugin(Box::new(Self {
            rcode,
            records,
            error,
        }))])
    }
}

impl Plugin for Fixed {
    fn answer(&self, _: &Query<'_>) -> Option<Answer<'_>> {
        Some(Answer {
            rcode: self.rcode,
            records: self.records.as_ref(),
            authoritative: true,
            error: self.error,
        })
    }
}

/// RFC 6891 §6.1.3: an RCODE past 4 bits needs an OPT record; a client without one gets SERVFAIL. RCODE 15 fits.
#[test]
fn an_extended_rcode_goes_to_edns_clients_only() {
    for (rcode, edns, sent) in [(16_u16, true, 16_u16), (16, false, 2), (15, false, 15)] {
        let pipeline = Fixed::pipeline(Rcode::from(rcode), &[], None);
        let wire = run(
            &pipeline,
            &query("local.test.", RecordType::A, edns),
            Transport::Udp,
            &[],
        )
        .reply
        .expect("a reply");
        assert_eq!(decode(&wire).rcode(), Rcode::from(sent), "{rcode} {edns}");
    }
}

/// RFC 2181 §9: records filling the client's UDP size to the byte go out whole, with an extended error (RFC 8914);
/// a byte less, they are left out with TC.
#[test]
fn records_that_just_fit_go_out_whole() {
    let records: Vec<String> = (0..40)
        .map(|i| format!("local.test. 60 IN A 192.0.2.{i}"))
        .collect();
    let records: Vec<&str> = records.iter().map(String::as_str).collect();
    let pipeline = Fixed::pipeline(Rcode::NOERROR, &records, Some(InfoCode::BLOCKED));
    let mut query = Message::query(7, Question::new(dns("local.test"), RecordType::A));
    let whole = run(&pipeline, &wire(&query), Transport::Tcp, &[])
        .reply
        .expect("a reply");
    let size = u16::try_from(whole.len()).expect("a UDP size");
    assert!(size > 512, "{size}");
    for (payload, count) in [(size, 40), (size - 1, 0)] {
        query.edns.as_mut().expect("EDNS").udp_payload = payload;
        let wire = run(&pipeline, &wire(&query), Transport::Udp, &[])
            .reply
            .expect("a reply");
        let reply = decode(&wire);
        assert_eq!(reply.answer.len(), count, "{payload}");
        assert_eq!(
            reply.header.flags.contains(Flags::TC),
            count == 0,
            "{payload}"
        );
        let options = reply.edns.expect("our OPT record").options;
        assert!(matches!(&options[..], [EdnsOption::Ede(_)]), "{options:?}");
    }
}

/// RFC 8467 §4.1: an answer to a padded query over TLS is padded to the next multiple of 468 bytes, whatever its
/// length.
#[test]
fn answers_are_padded_to_the_next_block() {
    let long = "a".repeat(255);
    for n in 150..=170 {
        let record = format!("local.test. 60 IN TXT \"{long}\" \"{}\"", "b".repeat(n));
        let pipeline = Fixed::pipeline(Rcode::NOERROR, &[&record], None);
        let len = |padded: bool| {
            let mut query = Message::query(7, Question::new(dns("local.test"), RecordType::TXT));
            if padded {
                query.edns.as_mut().expect("EDNS").options = vec![EdnsOption::Padding(0)];
            }
            let reply = run(&pipeline, &wire(&query), Transport::Tls, &[]).reply;
            reply.expect("a reply").len()
        };
        let plain = len(false);
        assert_eq!(len(true), (plain + 4).next_multiple_of(468), "{n}");
    }
}
