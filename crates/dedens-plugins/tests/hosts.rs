//! The hosts plugin (D54) on the example file of hosts(5) (Linux man-pages, `testdata/plugins/hosts.5`): A and AAAA
//! records for its names (RFC 1035 §3.4.1, RFC 3596 §2.1), PTR records for the reverse names of its addresses
//! (RFC 1035 §3.5, RFC 3596 §2.5), no data for other types (RFC 2308 §2.2).

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

use dedens_plugins::{Hosts, LineError, LineErrorKind};
use dedens_proto::rdata::RData;
use dedens_proto::{Class, Flags, Message, Name, Question, Rcode, RecordType, Transport, Ttl};
use dedens_server::{Forward, Pipeline, Stage, Step};

const HOSTS: &str = include_str!("../../../testdata/plugins/hosts.5");

fn pipeline(fallthrough: bool) -> Pipeline {
    let hosts = Hosts::new(HOSTS, Ttl::from_wire(3600), fallthrough).expect("the example reads");
    let upstream = SocketAddr::from(([192, 0, 2, 53], 53));
    Pipeline::new(vec![
        Stage::Plugin(Box::new(hosts)),
        Stage::Forward(Forward::new([upstream]).expect("a server")),
    ])
}

/// The reply of `pipeline` to a query for `name` and `qtype` in `class`; `None` when the query goes upstream.
fn ask(
    pipeline: &Pipeline,
    name: &str,
    qtype: RecordType,
    class: Class,
) -> Option<Message<'static>> {
    let name: Name<'static> = name.parse().expect("a name");
    let mut query = Message::query(7, Question::new(name, qtype));
    query.questions[0].qclass = class;
    let query = query.to_vec().expect("a query fits");
    let mut out = vec![0; 65535];
    match pipeline.query(
        &query,
        Transport::Udp,
        Ipv4Addr::LOCALHOST.into(),
        0,
        &mut out,
    ) {
        Step::Reply(len) => Some(
            Message::decode(&out[..len])
                .expect("the reply decodes")
                .message
                .into_owned(),
        ),
        Step::Upstream(_) => None,
        step => unreachable!("{step:?}"),
    }
}

fn data(reply: &Message<'_>) -> Vec<RData<'static>> {
    reply
        .answer
        .iter()
        .map(|record| record.data().into_owned())
        .collect()
}

#[test]
fn names_and_aliases_have_their_addresses() {
    let pipeline = pipeline(false);
    for name in ["foo.example.org.", "foo.", "FOO.Example.ORG."] {
        let reply = ask(&pipeline, name, RecordType::A, Class::IN).expect("a reply");
        assert_eq!(reply.rcode(), Rcode::NOERROR);
        assert!(reply.header.flags.contains(Flags::AA), "{name}");
        assert_eq!(reply.answer[0].name.to_string(), name);
        assert_eq!(reply.answer[0].ttl, Ttl::from_wire(3600));
        assert_eq!(data(&reply), [RData::A(Ipv4Addr::new(192, 168, 1, 10))]);
    }
    let reply = ask(&pipeline, "localhost.", RecordType::AAAA, Class::IN).expect("a reply");
    assert_eq!(data(&reply), [RData::Aaaa(Ipv6Addr::LOCALHOST)]);
}

#[test]
fn addresses_point_to_their_canonical_name() {
    let pipeline = pipeline(false);
    for (address, name) in [
        (IpAddr::from([192, 168, 1, 10]), "foo.example.org."),
        (IpAddr::V6(Ipv6Addr::LOCALHOST), "localhost."),
    ] {
        let reverse = Name::reverse(address).to_string();
        let reply = ask(&pipeline, &reverse, RecordType::PTR, Class::IN).expect("a reply");
        assert_eq!(data(&reply), [RData::Ptr(name.parse().expect("a name"))]);
    }
}

/// RFC 2308 §2.2: a listed name without records of the type has no data; `fallthrough` passes it on instead.
#[test]
fn other_types_have_no_data_unless_falling_through() {
    for qtype in [RecordType::MX, RecordType::AAAA] {
        let reply = ask(&pipeline(false), "foo.example.org.", qtype, Class::IN).expect("a reply");
        assert_eq!((reply.rcode(), reply.answer.len()), (Rcode::NOERROR, 0));
        assert!(reply.header.flags.contains(Flags::AA));
        assert!(ask(&pipeline(true), "foo.example.org.", qtype, Class::IN).is_none());
    }
}

#[test]
fn other_names_and_classes_go_on() {
    let pipeline = pipeline(false);
    assert!(ask(&pipeline, "example.org.", RecordType::A, Class::IN).is_none());
    assert!(ask(&pipeline, "localhost.", RecordType::A, Class::CH).is_none());
}

#[test]
fn addresses_with_a_zone_are_left_out() {
    let hosts = Hosts::new(
        "fe80::1%lo0 localhost\n127.0.0.1 localhost",
        Ttl::ZERO,
        false,
    );
    assert!(hosts.is_ok());
}

/// A byte order mark at the head of the file is no part of its first line.
#[test]
fn a_byte_order_mark_is_left_out() {
    let text = format!("\u{feff}{HOSTS}");
    assert!(Hosts::new(&text, Ttl::ZERO, false).is_ok());
}

#[test]
fn unreadable_lines_are_errors() {
    for (text, line, kind) in [
        (
            "127.0.0.1 localhost\n127.0.0.256 bad",
            2,
            LineErrorKind::Address("127.0.0.256".to_owned()),
        ),
        ("# none\n\n192.0.2.1  # no name", 3, LineErrorKind::NoName),
        (
            "192.0.2.1%eth0 a.example",
            1,
            LineErrorKind::Address("192.0.2.1%eth0".to_owned()),
        ),
    ] {
        assert_eq!(
            Hosts::new(text, Ttl::ZERO, false).map(|_| ()),
            Err(LineError { line, kind })
        );
    }
    let long = format!("192.0.2.1 {}.example", "a".repeat(64));
    let error = Hosts::new(&long, Ttl::ZERO, false).expect_err("a label of 64 bytes");
    assert!(matches!(error.kind, LineErrorKind::Name(..)), "{error}");
}
