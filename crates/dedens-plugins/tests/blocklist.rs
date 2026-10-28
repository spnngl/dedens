//! The blocklist plugin (D54) on published lists: the heads of `StevenBlack/hosts` (`testdata/stevenblack.hosts`)
//! and of the Multi LIGHT domains of `hagezi/dns-blocklists` (`testdata/hagezi-light.txt`). Blocked
//! answers carry the Extended DNS Error Blocked (RFC 8914 §4.16).

use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};

use dedens_plugins::{Action, Blocklist, LineErrorKind};
use dedens_proto::edns::{EdnsOption, InfoCode};
use dedens_proto::{Class, Flags, Message, Name, Question, RData, Rcode, RecordType, Ttl};
use dedens_server::{Forward, Pipeline, Stage, Step, Transport};

const STEVENBLACK: &str = include_str!("testdata/stevenblack.hosts");
const HAGEZI: &str = include_str!("testdata/hagezi-light.txt");

fn pipeline(text: &str, action: Action) -> Pipeline {
    let blocklist = Blocklist::new(text, action, Ttl::from_wire(60)).expect("the list reads");
    let upstream = SocketAddr::from(([192, 0, 2, 53], 53));
    Pipeline::new(vec![
        Stage::Plugin(Box::new(blocklist)),
        Stage::Forward(Forward::new(&[upstream]).expect("a server")),
    ])
}

/// The reply of `pipeline` to a query with EDNS for `name` and `qtype` in `class`; `None` when it goes upstream.
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
    match pipeline.query(&query, Transport::Udp, 0, &mut out) {
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

fn blocked(pipeline: &Pipeline, name: &str) -> bool {
    ask(pipeline, name, RecordType::A, Class::IN).is_some()
}

/// A listed name blocks itself and its subdomains, in any case; its parents and other names go on.
#[test]
fn listed_names_and_their_subdomains_are_blocked() {
    let hosts = pipeline(STEVENBLACK, Action::Nxdomain);
    for name in [
        "2no.co.",
        "WWW.2no.CO.",
        "a.b.ad-assets.futurecdn.net.",
        "0.0.0.0.",
    ] {
        assert!(blocked(&hosts, name), "{name}");
    }
    for name in ["co.", "futurecdn.net.", "example.com."] {
        assert!(!blocked(&hosts, name), "{name}");
    }
    let domains = pipeline(HAGEZI, Action::Nxdomain);
    assert!(blocked(&domains, "telemetry.001-studio.com."));
    assert!(blocked(&domains, "x.0.07c225f3.online."));
    assert!(!blocked(&domains, "001-studio.com."));
}

/// The host's own entries at the head of a hosts file are not blocked: localhost (RFC 6761 §6.3), names of one
/// label, and lines of other addresses.
#[test]
fn the_entries_of_the_host_are_not_blocked() {
    let hosts = pipeline(STEVENBLACK, Action::Nxdomain);
    for name in [
        "localhost.",
        "localhost.localdomain.",
        "local.",
        "printer.local.",
        "broadcasthost.",
        "ip6-allnodes.",
    ] {
        assert!(!blocked(&hosts, name), "{name}");
    }
    let other = pipeline("192.168.1.1 router.example\n", Action::Nxdomain);
    assert!(!blocked(&other, "router.example."));
}

#[test]
fn each_action_has_its_reply() {
    for (action, qtype, rcode, data) in [
        (Action::Nxdomain, RecordType::A, Rcode::NXDOMAIN, vec![]),
        (Action::Nodata, RecordType::A, Rcode::NOERROR, vec![]),
        (Action::Refused, RecordType::A, Rcode::REFUSED, vec![]),
        (
            Action::Null,
            RecordType::A,
            Rcode::NOERROR,
            vec![RData::A(Ipv4Addr::UNSPECIFIED)],
        ),
        (
            Action::Null,
            RecordType::AAAA,
            Rcode::NOERROR,
            vec![RData::Aaaa(Ipv6Addr::UNSPECIFIED)],
        ),
        (Action::Null, RecordType::MX, Rcode::NOERROR, vec![]),
    ] {
        let reply =
            ask(&pipeline(HAGEZI, action), "Ad.001zb.com.", qtype, Class::IN).expect("a reply");
        assert_eq!(reply.rcode(), rcode, "{action:?}");
        assert!(!reply.header.flags.contains(Flags::AA), "{action:?}");
        let answer: Vec<_> = reply.answer.iter().map(|r| r.data().into_owned()).collect();
        assert_eq!(answer, data, "{action:?}");
        for record in &reply.answer {
            assert_eq!(record.name.to_string(), "Ad.001zb.com.");
            assert_eq!(record.ttl, Ttl::from_wire(60));
        }
        let options = reply.edns.expect("our OPT record").options;
        assert!(
            matches!(&options[..], [EdnsOption::Ede(e)] if e.code == InfoCode::BLOCKED),
            "{options:?}"
        );
    }
}

#[test]
fn other_classes_go_on() {
    let hosts = pipeline(STEVENBLACK, Action::Nxdomain);
    assert!(ask(&hosts, "2no.co.", RecordType::A, Class::CH).is_none());
}

#[test]
fn fields_that_are_not_names_are_errors() {
    let text = format!("ads.example\n0.0.0.0 {}.example", "a".repeat(64));
    let error =
        Blocklist::new(&text, Action::Nxdomain, Ttl::ZERO).expect_err("a label of 64 bytes");
    assert_eq!(error.line, 2);
    assert!(matches!(error.kind, LineErrorKind::Name(..)), "{error}");
}
