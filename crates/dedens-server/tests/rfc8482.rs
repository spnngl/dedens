//! RFC 8482 §4.4: ANY over UDP and CoAP is answered with an empty, truncated response, never forwarded nor cached
//! (D114); over the other transports it is answered as any query. The query is the question of a real ANY response,
//! `any_rfc8482`, captured from cloudflare.com's name server (`capture.yaml`).

mod common;

use common::{caching, decode, forwarder, query_for, run, wire};
use dedens_proto::edns::{Edns, EdnsFlags};
use dedens_proto::{Class, Flags, Rcode, RecordType, Transport};
use dedens_testkit::captured;

/// The real ANY response, and its query with the EDNS and DO bit given.
fn any(edns: Option<bool>) -> (Vec<u8>, Vec<u8>) {
    let response = captured("any_rfc8482");
    let mut query = query_for(&response);
    assert_eq!(query.questions[0].qtype, RecordType::ANY);
    query.edns = edns.map(|dnssec| Edns {
        flags: if dnssec {
            EdnsFlags::DO
        } else {
            EdnsFlags::default()
        },
        ..Edns::default()
    });
    (response, wire(&query))
}

/// Over UDP and CoAP, ANY gets no upstream query and the same reply: NOERROR, TC, the question and the OPT record
/// of the query, nothing else, no larger than the query.
#[test]
fn any_over_udp_and_coap_is_truncated_and_empty() {
    for transport in [Transport::Udp, Transport::Coap] {
        for edns in [None, Some(false), Some(true)] {
            for pipeline in [forwarder(), caching()] {
                let (_, query) = any(edns);
                let done = run(&pipeline, &query, transport, &[]);
                assert_eq!(done.asked, [], "{transport:?}, EDNS {edns:?}");
                let reply = done.reply.expect("a reply");
                let message = decode(&reply);
                let asked = decode(&query);
                assert_eq!(message.rcode(), Rcode::NOERROR);
                assert!(message.header.flags.contains(Flags::TC));
                assert!(message.header.flags.contains(Flags::QR));
                assert!(message.header.flags.contains(Flags::RD));
                assert!(!message.header.flags.contains(Flags::AA));
                assert!(!message.header.flags.contains(Flags::AD));
                assert_eq!(message.questions, asked.questions);
                assert_eq!(
                    message.answer.len() + message.authority.len() + message.additional.len(),
                    0
                );
                assert_eq!(message.edns.is_some(), edns.is_some());
                assert_eq!(
                    message
                        .edns
                        .is_some_and(|e| e.flags.contains(EdnsFlags::DO)),
                    edns == Some(true)
                );
                // S1 of the audit: no amplification.
                assert!(reply.len() <= query.len(), "{} bytes", reply.len());
            }
        }
    }
}

/// §4.4: a responder may answer ANY differently per transport; the others are answered as before, the response
/// of upstream, and the client of UDP that asks again over TCP gets it.
#[test]
fn any_over_the_other_transports_is_forwarded() {
    for transport in [
        Transport::Tcp,
        Transport::Tls,
        Transport::Quic,
        Transport::Https,
        Transport::Odoh,
    ] {
        let (response, query) = any(Some(false));
        let done = run(&forwarder(), &query, transport, &[Some(&response)]);
        assert_eq!(done.asked.len(), 1, "{transport:?}");
        assert_eq!(done.requests[0].questions[0].qtype, RecordType::ANY);
        let reply = done.reply.expect("a reply");
        let message = decode(&reply);
        assert!(!message.header.flags.contains(Flags::TC), "{transport:?}");
        assert_eq!(
            message.answer.len(),
            decode(&response).answer.len(),
            "{transport:?}"
        );
    }
}

/// The cache key has no transport: the ANY stored for a TCP client is served to TCP clients only, and a UDP or
/// CoAP client gets the truncated reply whatever is stored.
#[test]
fn a_cached_any_is_not_served_over_udp_or_coap() {
    let (response, query) = any(Some(false));
    let pipeline = caching();
    let done = run(&pipeline, &query, Transport::Tcp, &[Some(&response)]);
    assert_eq!(done.asked.len(), 1);

    for transport in [Transport::Udp, Transport::Coap] {
        let done = run(&pipeline, &query, transport, &[]);
        assert_eq!(done.asked, []);
        let reply = done.reply.expect("a reply");
        let message = decode(&reply);
        assert!(message.header.flags.contains(Flags::TC), "{transport:?}");
        assert_eq!(message.answer.len(), 0, "{transport:?}");
    }

    let done = run(&pipeline, &query, Transport::Tcp, &[]);
    assert_eq!(done.asked, [], "the entry is still there for TCP");
    let reply = done.reply.expect("a reply");
    let message = decode(&reply);
    assert_eq!(message.answer.len(), decode(&response).answer.len());
}

/// Only the type counts, not the class: QCLASS ANY or CH asking for ANY is truncated as well (D114).
#[test]
fn any_in_another_class_is_truncated_too() {
    let (_, query) = any(None);
    let mut query = decode(&query).into_owned();
    query.questions[0].qclass = Class::CH;
    let done = run(&forwarder(), &wire(&query), Transport::Udp, &[]);
    assert_eq!(done.asked, []);
    let reply = done.reply.expect("a reply");
    let message = decode(&reply);
    assert!(message.header.flags.contains(Flags::TC));
}

/// Any other type over UDP is not touched.
#[test]
fn another_type_over_udp_is_forwarded() {
    let response = captured("a");
    let query = wire(&query_for(&response));
    let done = run(&forwarder(), &query, Transport::Udp, &[Some(&response)]);
    assert_eq!(done.asked.len(), 1);
    let reply = done.reply.expect("a reply");
    let message = decode(&reply);
    assert!(!message.header.flags.contains(Flags::TC));
    assert_ne!(message.answer.len(), 0);
}
