//! The forward stage (D41): what goes upstream, and the client's question case kept in the reply (RFC 4343 §4).

mod common;

use std::borrow::Cow;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};

use common::{captured, decode, dns, forwarder, query_for, run, wire};
use dedens_proto::edns::{ClientSubnet, Cookie, EdnsOption};
use dedens_proto::{Edns, Flags, Message};
use dedens_server::{Forward, Pipeline, Server, Stage, Step, Transport, Via};

#[test]
fn upstream_gets_the_question_and_our_edns_without_the_clients_options() {
    let response = captured("a");
    let mut query = query_for(&response);
    query.edns = Some(Edns {
        udp_payload: 4096,
        options: vec![
            EdnsOption::ClientSubnet(
                ClientSubnet::new(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 0)), 24, 0)
                    .expect("a valid subnet"),
            ),
            EdnsOption::Cookie(Cookie::new([1; 8], None).expect("a client cookie")),
            EdnsOption::Nsid(Cow::Borrowed(b"")),
        ],
        ..Edns::default()
    });
    let done = run(
        &forwarder(),
        &wire(&query),
        Transport::Udp,
        &[Some(&response)],
    );
    let request = &done.requests[0];
    assert_eq!(request.questions, query.questions);
    assert_eq!(request.header.flags, Flags::RD);
    assert_eq!(request.edns, Some(Edns::default()));
    assert_eq!(
        (&request.answer, &request.authority, &request.additional),
        (&vec![], &vec![], &vec![])
    );
}

#[test]
fn the_reply_has_the_question_in_the_clients_case() {
    let response = captured("a");
    let mut query = query_for(&response);
    let upper = query.questions[0].name.to_string().to_ascii_uppercase();
    query.questions[0].name = dns(&upper);
    let done = run(
        &forwarder(),
        &wire(&query),
        Transport::Udp,
        &[Some(&response)],
    );
    let wire = done.reply.expect("a reply");
    let reply = decode(&wire);
    assert_eq!(reply.questions[0].name.to_string(), upper);
    let upstream = Message::decode(&response).expect("decodes").message;
    assert_ne!(upstream.questions[0].name.to_string(), upper);
}

#[test]
fn a_forward_stage_has_a_server() {
    assert_eq!(Forward::new(Vec::<SocketAddr>::new()), None);
}

/// D65: each server is asked over its own transport, handed to the caller as configured, and printed so.
#[test]
fn servers_go_upstream_as_configured() {
    let addr: SocketAddr = "192.0.2.1:853".parse().expect("an address");
    let tls = Server {
        addr,
        via: Via::Tls(Some("dns.example".into())),
    };
    let quic = Server {
        addr,
        via: Via::Quic(None),
    };
    let pipeline = Pipeline::new(vec![Stage::Forward(
        Forward::new([tls.clone(), quic.clone()]).expect("servers"),
    )]);
    let mut out = vec![0; 65535];
    let query = query_for(&captured("a"));
    let Step::Upstream(first) = pipeline.query(&wire(&query), Transport::Udp, 0, &mut out) else {
        unreachable!("a forwarder sends the query upstream");
    };
    assert_eq!(first.server(), &tls);
    let Step::Upstream(second) = pipeline.receive(first, None, 0, &mut out) else {
        unreachable!("the next server is asked");
    };
    assert_eq!(second.server(), &quic);
    assert_eq!(Server::from(addr).to_string(), "192.0.2.1:853");
    assert_eq!(tls.to_string(), "tls://192.0.2.1:853#dns.example");
    assert_eq!(quic.to_string(), "quic://192.0.2.1:853");
    let https = Server {
        addr: "192.0.2.1:443".parse().expect("an address"),
        via: Via::Https {
            name: Some("dns.example".into()),
            path: "/dns-query".into(),
        },
    };
    assert_eq!(
        https.to_string(),
        "https://192.0.2.1:443/dns-query#dns.example"
    );
}
