//! The `tlds` stage (D128) on IANA's TLD list as bundled: special-use names answered as RFC 6761 §6, RFC 6762 §22.1
//! and RFC 7686 §2 ask of a caching server, RFC 6761 §6.5 and RFC 9476 §2 names left to the list; a TLD not in the
//! root zone NXDOMAIN without a SOA (RFC 2308 §5) to a query without DO, passed on with DO.

use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;

use dedens_plugins::{SPECIAL, TopLevel, Use, special};
use dedens_proto::edns::EdnsFlags;
use dedens_proto::rdata::RData;
use dedens_proto::{Class, Flags, Message, Name, Question, Rcode, RecordType, Transport, Ttl};
use dedens_roots::{Kind, Tlds};
use dedens_server::{Forward, Pipeline, Stage, Step};

fn pipeline() -> Pipeline {
    let stage = TopLevel::new(Arc::new(Tlds::bundled().clone()), Ttl::from_wire(3600));
    let upstream = SocketAddr::from(([192, 0, 2, 53], 53));
    Pipeline::new(vec![
        Stage::Plugin(Box::new(stage)),
        Stage::Forward(Forward::new([upstream]).expect("a server")),
    ])
}

/// The reply of `pipeline` to a query for `name` and `qtype` in `class`, with DO when `signed`; `None` when the
/// query goes upstream.
fn ask(
    pipeline: &Pipeline,
    (name, qtype, class): (&str, RecordType, Class),
    signed: bool,
) -> Option<Message<'static>> {
    let name: Name<'static> = name.parse().expect("a name");
    let mut query = Message::query(7, Question::new(name, qtype));
    query.questions[0].qclass = class;
    if let Some(edns) = query.edns.as_mut() {
        edns.flags = if signed {
            EdnsFlags::DO
        } else {
            EdnsFlags::default()
        };
    }
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

fn a(name: &str) -> (&str, RecordType, Class) {
    (name, RecordType::A, Class::IN)
}

/// NXDOMAIN with nothing in any section and AA clear: no SOA, so no cache keeps it (RFC 2308 §5).
fn assert_bare_nxdomain(reply: Option<Message<'_>>, name: &str) {
    let reply = reply.expect(name);
    assert_eq!(reply.rcode(), Rcode::NXDOMAIN, "{name}");
    assert!(!reply.header.flags.contains(Flags::AA), "{name}");
    assert!(
        reply.answer.is_empty() && reply.authority.is_empty(),
        "{name}"
    );
}

#[test]
fn every_special_use_tld_of_the_list_is_in_the_table() {
    let listed: Vec<_> = Tlds::bundled()
        .iter()
        .filter(|tld| matches!(tld.kind(), Kind::SpecialUse { .. }))
        .map(|tld| tld.name().to_string())
        .collect();
    for name in &listed {
        let label = name.trim_end_matches('.');
        assert!(special(label.as_bytes()).is_some(), "{name} has no row");
    }
    assert_eq!(listed.len(), SPECIAL.len());
}

#[test]
fn rfc6761_s6_3_localhost_names_are_the_loopback_addresses() {
    let pipeline = pipeline();
    for name in ["localhost.", "LocalHost.", "a.b.localhost."] {
        let reply = ask(&pipeline, a(name), false).expect("answered");
        assert_eq!(reply.rcode(), Rcode::NOERROR);
        assert!(reply.header.flags.contains(Flags::AA), "{name}");
        assert_eq!(reply.answer[0].name.to_string(), name);
        assert_eq!(reply.answer[0].data(), RData::A(Ipv4Addr::LOCALHOST));
        let reply = ask(&pipeline, (name, RecordType::AAAA, Class::IN), true).expect("answered");
        assert_eq!(reply.answer[0].data(), RData::Aaaa(Ipv6Addr::LOCALHOST));
    }
    let any = ask(&pipeline, ("localhost.", RecordType::ANY, Class::IN), false).expect("answered");
    assert_eq!(any.answer[0].data(), RData::A(Ipv4Addr::LOCALHOST));
    let mx = ask(&pipeline, ("localhost.", RecordType::MX, Class::IN), false).expect("answered");
    assert_eq!((mx.rcode(), mx.answer.len()), (Rcode::NOERROR, 0));
}

#[test]
fn rfc6761_rfc6762_rfc7686_names_never_resolved_are_nxdomain_with_do_too() {
    let pipeline = pipeline();
    let names = SPECIAL
        .iter()
        .filter(|(_, then)| *then == Use::Nxdomain)
        .map(|(label, _)| *label);
    for label in names {
        for name in [format!("{label}."), format!("x.{}.", label.to_uppercase())] {
            assert_bare_nxdomain(ask(&pipeline, a(&name), false), &name);
            assert_bare_nxdomain(ask(&pipeline, a(&name), true), &name);
        }
    }
}

#[test]
fn rfc6761_s6_5_rfc9476_s2_names_resolved_normally_follow_the_list() {
    let pipeline = pipeline();
    // Reserved, so not in the root zone: NXDOMAIN without DO, as the root would say; passed on with DO.
    for name in ["www.example.", "x.alt.", "foo.internal."] {
        assert_bare_nxdomain(ask(&pipeline, a(name), false), name);
        assert!(ask(&pipeline, a(name), true).is_none(), "{name}");
    }
    // Delegated.
    for name in ["1.0.0.127.in-addr.arpa.", "arpa.", "example.com.", "Example.FR."] {
        assert!(ask(&pipeline, a(name), false).is_none(), "{name}");
    }
}

#[test]
fn a_tld_not_in_the_root_zone_is_nxdomain_without_do_only() {
    let pipeline = pipeline();
    for name in ["nonexistent-tld.", "www.example.nonexistent-tld."] {
        assert_bare_nxdomain(ask(&pipeline, a(name), false), name);
        assert!(ask(&pipeline, a(name), true).is_none(), "{name}");
    }
}

#[test]
fn the_root_and_other_classes_go_on() {
    let pipeline = pipeline();
    assert!(ask(&pipeline, (".", RecordType::NS, Class::IN), false).is_none());
    for name in ["localhost.", "x.onion.", "nonexistent-tld."] {
        assert!(
            ask(&pipeline, (name, RecordType::A, Class::CH), false).is_none(),
            "{name}"
        );
    }
}
