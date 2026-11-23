//! The authoritative stage in the pipeline (D208): a zone answers its names with AA whatever RD says (RFC 1034
//! §4.3.2), to every client, and passes the other names on to the stages after it for the clients the access lists
//! permit (D91, RFC 5358 §4), RA set only for them, and only when a forward or recurse stage follows (RFC 1035
//! §4.1.1).

use std::net::IpAddr;
use std::sync::Arc;

use dedens_proto::edns::{EdnsOption, InfoCode};
use dedens_proto::{Class, Flags, Message, Question, Rcode, RecordType, Transport};
use dedens_server::{Access, Authoritative, Denial, Forward, Network, Pipeline, Stage, Step};
use dedens_testkit::dns;
use dedens_zone::{Limits, Source, Zone};

use crate::util::{decode, servers, wire};

/// The zone of RFC 4035 Appendix A, `example.`.
pub(crate) fn example() -> Arc<Zone> {
    let text = std::fs::read(dedens_testkit::path("zones/rfc4035_appendix_a.zone"))
        .expect("the zone file");
    let source = Source {
        name: "rfc4035_appendix_a.zone",
        text: &text,
        default_ttl: None,
    };
    let loaded = Zone::load(
        dns("example"),
        source,
        &mut |_: &str| Err("no include".to_owned()),
        &Limits::default(),
    );
    Arc::new(loaded.expect("the zone loads").zone)
}

/// The authoritative stage serving [`example`].
pub(crate) fn zones() -> Stage {
    Stage::Authoritative(Authoritative::new([example()]).expect("one zone"))
}

/// An authoritative server for `example.` alone.
fn authoritative() -> Pipeline {
    Pipeline::new(vec![zones()])
}

/// [`example`] first, then forwarding for the clients of 10.0.0.0/8, the others `denial`.
fn mixed(denial: Denial) -> Pipeline {
    let local: Network = "10.0.0.0/8".parse().expect("a network");
    Pipeline::new(vec![
        zones(),
        Stage::Forward(Forward::new(servers()).expect("servers")),
    ])
    .with_access(Access::new([local], [], denial))
}

/// A client the access lists of [`mixed`] permit.
const INSIDE: &str = "10.1.2.3";
/// A client they deny.
const OUTSIDE: &str = "192.0.2.1";

fn addr(text: &str) -> IpAddr {
    text.parse().expect("an address")
}

/// What the query for `name` and `qtype`, with `flags` alone (RD or not), from `from` over UDP comes to, and what
/// was written: the reply, for [`Step::Reply`].
fn ask(
    pipeline: &Pipeline,
    (name, qtype): (&str, RecordType),
    flags: Flags,
    from: &str,
) -> (Step, Vec<u8>) {
    let mut query = Message::query(7, Question::new(dns(name), qtype));
    query.header.flags = flags;
    let mut out = vec![0; 65535];
    let step = pipeline.query(&wire(&query), Transport::Udp, addr(from), 0, &mut out);
    if let Step::Reply(len) = step {
        out.truncate(len);
    }
    (step, out)
}

/// The reply [`ask`] gets.
struct Replied {
    rcode: Rcode,
    flags: Flags,
    /// The records of every section, as text.
    records: Vec<String>,
    options: Vec<EdnsOption<'static>>,
}

fn replied(pipeline: &Pipeline, question: (&str, RecordType), flags: Flags, from: &str) -> Replied {
    let (step, out) = ask(pipeline, question, flags, from);
    assert!(matches!(step, Step::Reply(_)), "{step:?}");
    let reply = decode(&out).into_owned();
    Replied {
        rcode: reply.rcode(),
        flags: reply.header.flags,
        records: reply
            .answer
            .iter()
            .chain(&reply.authority)
            .chain(&reply.additional)
            .map(|record| record.to_string().replace('\t', " "))
            .collect(),
        options: reply.edns.map(|edns| edns.options).unwrap_or_default(),
    }
}

fn has(records: &[String], record: &str) -> bool {
    records.iter().any(|r| r == record)
}

#[test]
fn rfc1034_4_3_2_a_zone_answers_with_aa_whatever_rd() {
    for flags in [Flags::RD, Flags::NONE] {
        let reply = replied(
            &authoritative(),
            ("ns1.example", RecordType::A),
            flags,
            OUTSIDE,
        );
        assert_eq!(reply.rcode, Rcode::NOERROR);
        assert!(
            reply.flags.contains(Flags::AA | Flags::QR),
            "{:?}",
            reply.flags
        );
        assert_eq!(
            reply.flags.contains(Flags::RD),
            flags == Flags::RD,
            "RD copied"
        );
        // No stage forwards or recurses: no recursion is available (RFC 1035 §4.1.1).
        assert!(!reply.flags.contains(Flags::RA), "{:?}", reply.flags);
        assert_eq!(reply.records[0], "ns1.example. 3600 IN A 192.0.2.1");
    }
}

#[test]
fn rfc2308_2_1_a_name_the_zone_lacks_is_nxdomain_with_its_soa() {
    let reply = replied(
        &authoritative(),
        ("nothing.example", RecordType::A),
        Flags::RD,
        OUTSIDE,
    );
    assert_eq!(reply.rcode, Rcode::NXDOMAIN);
    assert!(reply.flags.contains(Flags::AA));
    assert!(
        reply.records.iter().any(|record| record.contains(" SOA ")),
        "{:?}",
        reply.records
    );
}

#[test]
fn rfc1034_4_3_2_a_delegation_is_a_referral_without_aa() {
    let reply = replied(
        &authoritative(),
        ("www.a.example", RecordType::A),
        Flags::RD,
        OUTSIDE,
    );
    assert_eq!(reply.rcode, Rcode::NOERROR);
    assert!(!reply.flags.contains(Flags::AA), "{:?}", reply.flags);
    assert!(has(&reply.records, "a.example. 3600 IN NS ns1.a.example."));
    assert!(has(&reply.records, "ns1.a.example. 3600 IN A 192.0.2.5"));
}

#[test]
fn a_name_outside_every_zone_is_refused_without_a_later_stage() {
    let reply = replied(
        &authoritative(),
        ("example.org", RecordType::A),
        Flags::RD,
        OUTSIDE,
    );
    assert_eq!((reply.rcode, reply.records.len()), (Rcode::REFUSED, 0));
    assert!(!reply.flags.contains(Flags::RA), "{:?}", reply.flags);
    assert!(!reply.flags.contains(Flags::AA), "{:?}", reply.flags);
}

#[test]
fn a_zone_transfer_is_still_refused() {
    let reply = replied(
        &authoritative(),
        ("example", RecordType::AXFR),
        Flags::NONE,
        OUTSIDE,
    );
    assert_eq!(reply.rcode, Rcode::REFUSED);
}

#[test]
fn a_zone_answers_every_client_ra_only_for_those_recursion_serves() {
    for denial in [Denial::Refuse, Denial::Drop] {
        let pipeline = mixed(denial);
        assert_eq!(
            pipeline.denial(addr(OUTSIDE)),
            None,
            "the zones answer every client"
        );
        assert!(!pipeline.drops(addr(OUTSIDE)));
        for (from, ra) in [(INSIDE, true), (OUTSIDE, false)] {
            let reply = replied(&pipeline, ("ns1.example", RecordType::A), Flags::RD, from);
            assert_eq!(reply.rcode, Rcode::NOERROR);
            assert!(reply.flags.contains(Flags::AA));
            assert_eq!(reply.flags.contains(Flags::RA), ra, "{from}");
        }
    }
}

#[test]
fn rfc5358_4_a_name_outside_the_zones_goes_on_for_the_clients_the_access_lists_permit() {
    let question = ("example.org", RecordType::A);
    let pipeline = mixed(Denial::Refuse);
    let (step, _) = ask(&pipeline, question, Flags::RD, INSIDE);
    assert!(matches!(step, Step::Upstream(_)), "{step:?}");
    // The others get what the lists say: REFUSED with EDE 18 (RFC 8914 §4.19), or nothing.
    let reply = replied(&pipeline, question, Flags::RD, OUTSIDE);
    assert_eq!(reply.rcode, Rcode::REFUSED);
    assert!(!reply.flags.contains(Flags::RA), "{:?}", reply.flags);
    assert!(
        matches!(&reply.options[..], [EdnsOption::Ede(e)] if e.code == InfoCode::PROHIBITED),
        "{:?}",
        reply.options
    );
    let (step, _) = ask(&mixed(Denial::Drop), question, Flags::RD, OUTSIDE);
    assert!(matches!(step, Step::Drop), "{step:?}");
}

#[test]
fn a_referral_goes_on_for_a_client_asking_for_recursion_it_has() {
    let pipeline = mixed(Denial::Refuse);
    let question = ("www.a.example", RecordType::A);
    let (step, _) = ask(&pipeline, question, Flags::RD, INSIDE);
    assert!(matches!(step, Step::Upstream(_)), "{step:?}");
    // Without RD, or recursion, the referral is the answer.
    let reply = replied(&pipeline, question, Flags::NONE, INSIDE);
    assert!(!reply.flags.contains(Flags::AA), "{:?}", reply.flags);
    assert!(reply.flags.contains(Flags::RA), "{:?}", reply.flags);
    assert!(has(&reply.records, "a.example. 3600 IN NS ns1.a.example."));
    let reply = replied(&pipeline, question, Flags::RD, OUTSIDE);
    assert!(!reply.flags.contains(Flags::AA), "{:?}", reply.flags);
    assert!(!reply.flags.contains(Flags::RA), "{:?}", reply.flags);
    assert!(has(&reply.records, "a.example. 3600 IN NS ns1.a.example."));
}

#[test]
fn rfc1034_4_3_2_a_name_of_another_class_goes_on() {
    // Step 2 matches the class too: `example.` in CH is no zone of the stage, served or not by the stages after.
    let mut question = Question::new(dns("ns1.example"), RecordType::A);
    question.qclass = Class::CH;
    let mut query = Message::query(7, question);
    query.header.flags = Flags::RD;
    let mut out = vec![0; 65535];
    let pipeline = mixed(Denial::Refuse);
    let step = pipeline.query(&wire(&query), Transport::Udp, addr(INSIDE), 0, &mut out);
    assert!(matches!(step, Step::Upstream(_)), "{step:?}");
}
