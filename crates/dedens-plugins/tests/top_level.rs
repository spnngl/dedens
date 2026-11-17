//! The `tlds` stage (D128) on IANA's TLD list as bundled: special-use names answered as RFC 6761 §6, RFC 6762 §22.1
//! and RFC 7686 §2 ask of a caching server, RFC 6761 §6.5 and RFC 9476 §2 names left to the list; a TLD not in the
//! root zone NXDOMAIN without a SOA (RFC 2308 §5) to a query without DO, passed on with DO or once the list is
//! older than `MAX_LIST_AGE`, its `meta.generated` shifted from.

use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;

use dedens_plugins::{MAX_LIST_AGE, SPECIAL, TopLevel, Use, special};
use dedens_proto::edns::EdnsFlags;
use dedens_proto::rdata::RData;
use dedens_proto::{Class, Flags, Message, Name, Question, Rcode, RecordType, Transport, Ttl};
use dedens_roots::{Kind, Tlds};
use dedens_server::{Forward, Pipeline, Stage, Step};

/// The stage on the bundled list as IANA generated it, then the upstream.
fn pipeline() -> Pipeline {
    pipeline_at(Tlds::bundled().generated())
}

/// The stage on the bundled list at `now`, in seconds since 1970, then the upstream.
fn pipeline_at(now: u64) -> Pipeline {
    let stage = TopLevel::new(
        Arc::new(Tlds::bundled().clone()),
        Ttl::from_wire(3600),
        Arc::new(move || now),
    );
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
    for name in [
        "1.0.0.127.in-addr.arpa.",
        "arpa.",
        "example.com.",
        "Example.FR.",
    ] {
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
fn a_list_older_than_its_max_age_lets_a_tld_outside_it_go_on() {
    let generated = Tlds::bundled().generated();
    let fresh = pipeline_at(generated + MAX_LIST_AGE - 1);
    let stale = pipeline_at(generated + MAX_LIST_AGE);
    for name in ["nonexistent-tld.", "www.example."] {
        assert_bare_nxdomain(ask(&fresh, a(name), false), name);
        assert!(ask(&stale, a(name), false).is_none(), "{name}");
    }
    // The special-use names do not hang on the list.
    assert_bare_nxdomain(ask(&stale, a("x.onion."), false), "x.onion.");
    let localhost = ask(&stale, a("localhost."), false).expect("answered");
    assert_eq!(localhost.answer[0].data(), RData::A(Ipv4Addr::LOCALHOST));
    assert_eq!(MAX_LIST_AGE, 30 * 86_400, "30 days (D128)");
    let top_level = TopLevel::new(
        Arc::new(Tlds::bundled().clone()),
        Ttl::from_wire(0),
        Arc::new(|| 0),
    );
    assert_eq!(top_level.stale_at(), generated + MAX_LIST_AGE);
}

#[test]
fn special_use_names_are_special_in_every_class_others_go_on() {
    let pipeline = pipeline();
    assert!(ask(&pipeline, (".", RecordType::NS, Class::IN), false).is_none());
    for class in [Class::CH, Class::HS, Class::ANY] {
        assert_bare_nxdomain(
            ask(&pipeline, ("x.onion.", RecordType::A, class), false),
            "x.onion.",
        );
        assert_bare_nxdomain(
            ask(&pipeline, ("invalid.", RecordType::TXT, class), true),
            "invalid.",
        );
        // The TLD list is of class IN: `version.bind` in CH (RFC 4892 §2) is no TLD outside it.
        for name in ["nonexistent-tld.", "version.bind.", "example.com."] {
            assert!(
                ask(&pipeline, (name, RecordType::TXT, class), false).is_none(),
                "{name}"
            );
        }
    }
    // The loopback addresses are of class IN, which ANY takes in; another class has no data at the name.
    let any = ask(&pipeline, ("localhost.", RecordType::A, Class::ANY), false).expect("answered");
    assert_eq!(any.answer[0].data(), RData::A(Ipv4Addr::LOCALHOST));
    for qtype in [RecordType::A, RecordType::AAAA, RecordType::ANY] {
        let chaos = ask(&pipeline, ("localhost.", qtype, Class::CH), false).expect("answered");
        assert_eq!(
            (chaos.rcode(), chaos.answer.len()),
            (Rcode::NOERROR, 0),
            "{qtype}"
        );
        assert!(chaos.header.flags.contains(Flags::AA));
    }
}

/// `dedensd_tlds_answers_total{kind}` counts the answers of the stage: `special_use` for the table's names,
/// `unknown` for a TLD not in the root zone; `dedensd_tlds_stale_total` a TLD outside a list too old, passed on;
/// another query passed on counts nothing.
#[cfg(feature = "metrics")]
#[test]
fn answers_are_counted_by_kind() {
    use metrics_util::debugging::{DebugValue, DebuggingRecorder};

    let recorder = DebuggingRecorder::new();
    let snapshotter = recorder.snapshotter();
    let (pipeline, stale) = metrics::with_local_recorder(&recorder, || {
        (
            pipeline(),
            pipeline_at(Tlds::bundled().generated() + MAX_LIST_AGE),
        )
    });
    for name in [
        "localhost.",
        "x.onion.",
        "x.test.",
        "nonexistent-tld.",
        "example.com.",
    ] {
        let _ = ask(&pipeline, a(name), false);
    }
    for name in ["nonexistent-tld.", "x.nonexistent-tld.", "example.com."] {
        assert!(ask(&stale, a(name), false).is_none());
    }
    let mut counted: Vec<_> = snapshotter
        .snapshot()
        .into_vec()
        .into_iter()
        .filter_map(|(key, _, _, value)| {
            let DebugValue::Counter(n) = value else {
                return None;
            };
            let (_, key) = key.into_parts();
            let kind = key
                .labels()
                .find(|l| l.key() == "kind")
                .map(|l| l.value().to_owned());
            Some((key.name().to_owned(), kind, n))
        })
        .collect();
    counted.sort();
    let entry = |name: &str, kind: Option<&str>, n| (name.to_owned(), kind.map(str::to_owned), n);
    assert_eq!(
        counted,
        [
            entry("dedensd_tlds_answers_total", Some("special_use"), 3),
            entry("dedensd_tlds_answers_total", Some("unknown"), 1),
            entry("dedensd_tlds_stale_total", None, 2),
        ]
    );
}
