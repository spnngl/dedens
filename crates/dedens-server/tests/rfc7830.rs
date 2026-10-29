//! RFC 7830 in the server core: replies to a padded query over TLS or QUIC are padded (§4), to a multiple of 468
//! bytes (RFC 8467 §4.1), with zeros (§3); no other reply is.

mod common;

use common::{caching, captured, decode, forwarder, query_for, reply, run, wire};
use dedens_proto::edns::{EdnsOption, InfoCode};
use dedens_proto::{Edns, Message, Rcode};
use dedens_server::{Step, Transport};

/// The query of the `a` capture, with EDNS and, when `padded`, an empty Padding option.
fn query(padded: bool) -> Message<'static> {
    let mut query = query_for(&captured("a"));
    query.edns = Some(Edns {
        options: if padded {
            vec![EdnsOption::Padding(0)]
        } else {
            Vec::new()
        },
        ..Edns::default()
    });
    query
}

/// The length of the Padding option of `wire`, which must be the last option.
fn padding(wire: &[u8]) -> Option<u16> {
    let edns = decode(wire).edns.expect("an OPT record");
    match edns.options.last() {
        Some(EdnsOption::Padding(len)) => Some(*len),
        _ => None,
    }
}

#[test]
fn padded_queries_over_tls_and_quic_get_padded_replies() {
    let response = captured("a");
    for transport in [Transport::Tls, Transport::Quic] {
        let wire = reply(
            &forwarder(),
            &wire(&query(true)),
            transport,
            Some(&response),
        );
        assert_eq!(wire.len() % 468, 0, "{transport:?}");
        assert!(padding(&wire).is_some(), "{transport:?}");
        let reread = decode(&wire);
        assert_eq!(reread.answer, decode(&response).answer, "{transport:?}");
    }
}

#[test]
fn other_replies_are_not_padded() {
    let response = captured("a");
    for (transport, padded) in [
        (Transport::Udp, true),
        (Transport::Tcp, true),
        (Transport::Tls, false),
        (Transport::Quic, false),
    ] {
        let wire = reply(
            &forwarder(),
            &wire(&query(padded)),
            transport,
            Some(&response),
        );
        assert_eq!(padding(&wire), None, "{transport:?}");
    }
}

#[test]
fn failures_are_padded() {
    let wire = reply(&forwarder(), &wire(&query(true)), Transport::Tls, None);
    assert_eq!(
        (decode(&wire).rcode(), wire.len() % 468),
        (Rcode::SERVFAIL, 0)
    );
}

/// A cache hit is padded too, with zeros though the buffer held other bytes.
#[test]
fn cache_hits_are_padded_with_zeros() {
    let pipeline = caching();
    let response = captured("a");
    let query = wire(&query(true));
    assert!(
        run(&pipeline, &query, Transport::Tls, &[Some(&response)])
            .reply
            .is_some()
    );
    let mut out = vec![0xFF; 65535];
    let Step::Reply(len) = pipeline.query(&query, Transport::Tls, 0, &mut out) else {
        unreachable!("a cache hit");
    };
    assert_eq!(len % 468, 0);
    let len_of_padding = usize::from(padding(&out[..len]).expect("padded"));
    assert!(out[len - len_of_padding..len].iter().all(|&byte| byte == 0));
}

/// Stale data answers with EDE 3, then padding.
#[test]
fn stale_answers_are_padded_after_their_extended_error() {
    let pipeline = caching();
    let response = captured("a");
    let query = wire(&query(true));
    assert!(
        run(&pipeline, &query, Transport::Tls, &[Some(&response)])
            .reply
            .is_some()
    );
    // The `a` capture's records live 300 seconds at most.
    let late = common::run_at(&pipeline, &query, Transport::Tls, 301, &[None, None]);
    let wire = late.reply.expect("a stale reply");
    assert_eq!(wire.len() % 468, 0);
    let options = decode(&wire).edns.expect("an OPT record").options;
    assert!(
        matches!(options.as_slice(), [EdnsOption::Ede(ede), EdnsOption::Padding(_)] if ede.code == InfoCode::STALE_ANSWER),
        "{options:?}"
    );
}
