//! The resolutions of `testdata/recursion/` (D188): each response answers its question, each case shows what its
//! README row says, and [`Authorities`] replays every exchange, REFUSED for anything else.

use std::net::{IpAddr, Ipv4Addr};

use dedens_proto::edns::EdnsFlags;
use dedens_proto::{Flags, Message, Rcode, RecordType};
use dedens_testkit::recursion::{self, Authorities, QueryFlag, Resolution, Transport};
use dedens_testkit::{dns, message};

/// The ID of the replayed queries; the captures' are random.
const ID: u16 = 0x1234;

/// The last response of `id`: the one answering its question.
fn last(id: &str) -> Message<'static> {
    let resolution = Resolution::read(id);
    let exchange = resolution.exchanges.last().expect("an exchange");
    message(&exchange.response)
}

#[test]
fn each_response_answers_its_question() {
    let all = Resolution::all();
    assert_eq!(all.len(), 14, "every case of the README");
    for (id, resolution) in all {
        for exchange in &resolution.exchanges {
            let response = message(&exchange.response);
            assert!(response.header.flags.contains(Flags::QR), "{id}");
            let [question] = response.questions.as_slice() else {
                unreachable!("{id}: one question");
            };
            assert_eq!(question.name, exchange.name, "{id}");
            assert_eq!(question.qtype, exchange.rtype, "{id}");
            assert!(
                [Rcode::NOERROR, Rcode::NXDOMAIN].contains(&response.rcode()),
                "{id}: {} {}",
                exchange.name,
                exchange.rtype
            );
        }
    }
}

#[test]
fn each_resolution_primes_and_asks_the_key_of_each_zone() {
    for (id, resolution) in Resolution::all() {
        let first = resolution.exchanges.first().expect("an exchange");
        assert_eq!(
            (&first.name, first.rtype),
            (&dns("."), RecordType::NS),
            "{id}"
        );
        for exchange in &resolution.exchanges {
            assert!(
                resolution
                    .exchanges
                    .iter()
                    .any(|e| e.name == exchange.zone && e.rtype == RecordType::DNSKEY),
                "{id}: {}",
                exchange.zone
            );
        }
    }
}

#[test]
fn a_resolution_reads_back_as_written() {
    let resolution = Resolution::read("priming");
    let yaml = resolution.to_yaml().expect("YAML");
    assert_eq!(Resolution::parse(&yaml).expect("a resolution"), resolution);
}

#[test]
fn negative_cases_end_in_nxdomain_or_nodata() {
    for id in ["nxdomain-signed", "nxdomain-nsec3", "nxdomain-unsigned"] {
        assert_eq!(last(id).rcode(), Rcode::NXDOMAIN, "{id}");
    }
    for id in ["nodata-signed", "nodata-unsigned"] {
        let response = last(id);
        assert_eq!(response.rcode(), Rcode::NOERROR, "{id}");
        assert!(response.answer.is_empty(), "{id}");
        assert!(
            response
                .authority
                .iter()
                .any(|r| r.rdata.rtype() == RecordType::SOA),
            "{id}"
        );
    }
    for id in ["nxdomain-signed", "nodata-signed", "nxdomain-nsec3"] {
        let denied = last(id)
            .authority
            .iter()
            .any(|r| [RecordType::NSEC, RecordType::NSEC3].contains(&r.rdata.rtype()));
        assert!(denied, "{id}: a denial");
    }
}

#[test]
fn chains_cross_zones_to_an_address() {
    for (id, alias, zones) in [
        ("cname", RecordType::CNAME, 3),
        ("dname", RecordType::DNAME, 2),
    ] {
        let resolution = Resolution::read(id);
        let responses: Vec<_> = resolution
            .exchanges
            .iter()
            .map(|e| message(&e.response))
            .collect();
        let aliased = responses
            .iter()
            .any(|r| r.answer.iter().any(|a| a.rdata.rtype() == alias));
        assert!(aliased, "{id}: an {alias}");
        // The validator's DS of each label (the walk) come after the answer.
        let last = (resolution.exchanges.iter().zip(&responses))
            .rfind(|(e, _)| e.rtype == resolution.rtype)
            .map(|(_, r)| r)
            .expect("a response");
        assert!(
            last.answer.iter().any(|r| r.rdata.rtype() == RecordType::A),
            "{id}: an address"
        );
        let mut answering: Vec<_> = resolution
            .exchanges
            .iter()
            .zip(&responses)
            .filter(|(_, r)| !r.answer.is_empty() && r.header.flags.contains(Flags::AA))
            .map(|(e, _)| e.zone.to_string())
            .collect();
        answering.dedup();
        assert!(answering.len() >= zones, "{id}: {answering:?}");
    }
}

#[test]
fn the_truncated_answer_was_asked_again_over_tcp() {
    let resolution = Resolution::read("truncated");
    let [.., udp, tcp] = resolution.exchanges.as_slice() else {
        unreachable!("two exchanges");
    };
    assert_eq!(
        (udp.transport, tcp.transport),
        (Transport::Udp, Transport::Tcp)
    );
    assert!(message(&udp.response).header.flags.contains(Flags::TC));
    assert!(!message(&tcp.response).header.flags.contains(Flags::TC));
    assert!(tcp.response.len() > 1232);
}

#[test]
fn authorities_replay_every_exchange_under_the_query_id() {
    for (id, resolution) in Resolution::all() {
        let authorities = Authorities::new([&resolution]);
        for exchange in &resolution.exchanges {
            let query = exchange.query(ID).to_vec().expect("a query");
            let mut captured = exchange.response.clone();
            captured[..2].copy_from_slice(&ID.to_be_bytes());
            assert_eq!(
                authorities.answer(exchange.server, exchange.transport, &query),
                captured,
                "{id}: {} {} over {:?}",
                exchange.name,
                exchange.rtype,
                exchange.transport
            );
        }
    }
}

#[test]
fn authorities_answer_over_tcp_what_came_over_udp_alone() {
    let resolution = Resolution::read("priming");
    let exchange = &resolution.exchanges[0];
    assert_eq!(exchange.transport, Transport::Udp);
    let query = exchange.query(ID).to_vec().expect("a query");
    let replayed = Authorities::new([&resolution]).answer(exchange.server, Transport::Tcp, &query);
    assert_eq!(replayed[2..], exchange.response[2..]);
}

#[test]
fn a_query_sets_the_flags_given() {
    let name = dns("example.com");
    let bare = recursion::query(ID, &name, RecordType::A, &[]);
    assert_eq!(bare.header.flags, Flags::NONE);
    assert!(!bare.edns.expect("EDNS").flags.contains(EdnsFlags::DO));
    let all = [QueryFlag::Rd, QueryFlag::Cd, QueryFlag::Do];
    let flagged = recursion::query(ID, &name, RecordType::A, &all);
    assert_eq!(flagged.header.flags, Flags::RD.with(Flags::CD));
    let edns = flagged.edns.expect("EDNS");
    assert!(edns.flags.contains(EdnsFlags::DO));
    assert_eq!(edns.udp_payload, 1232);
}

#[test]
fn authorities_answer_in_the_case_of_the_query() {
    let resolution = Resolution::read("signed-com");
    let exchange = resolution
        .exchanges
        .iter()
        .find(|e| e.name == dns("example.com"))
        .expect("an exchange for example.com");
    let mut query = exchange.query(ID);
    query.questions[0].name = dns("ExAmPlE.CoM");
    let replayed = Authorities::new([&resolution]).answer(
        exchange.server,
        Transport::Udp,
        &query.to_vec().expect("a query"),
    );
    assert_eq!(
        message(&replayed).questions[0].name.to_string(),
        "ExAmPlE.CoM."
    );
}

#[test]
fn authorities_refuse_another_server_or_question() {
    let resolution = Resolution::read("priming");
    let authorities = Authorities::new([&resolution]);
    let exchange = &resolution.exchanges[0];
    let elsewhere = IpAddr::V4(Ipv4Addr::LOCALHOST);
    let query = exchange.query(ID).to_vec().expect("a query");
    let mut other = exchange.query(ID);
    other.questions[0].qtype = RecordType::TXT;
    let other = other.to_vec().expect("a query");
    let mut recursive = exchange.query(ID);
    recursive.header.flags = Flags::RD;
    let recursive = recursive.to_vec().expect("a query");
    for (server, query, flags) in [
        (elsewhere, &query, Flags::QR),
        (exchange.server, &other, Flags::QR),
        (elsewhere, &recursive, Flags::QR.with(Flags::RD)),
    ] {
        let refused = message(&authorities.answer(server, Transport::Udp, query));
        assert_eq!(refused.rcode(), Rcode::REFUSED);
        assert_eq!(refused.header.id, ID);
        assert_eq!(refused.header.flags, flags);
        assert_eq!(refused.questions, message(query).questions);
    }
}
