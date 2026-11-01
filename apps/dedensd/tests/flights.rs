//! The validator's questions in flight are shared (D86): queries that need the same DS or DNSKEY of the same server
//! at the same time send it once. Run on loopback against a responder answering the captures of `dedens-dnssec`.

mod common;

use std::thread;
use std::time::Duration;

use common::{Responder, Server, ask_udp, captured_dnssec, query_for};
use dedens_proto::{Rcode, RecordType};

/// Clients asking at once.
const CLIENTS: u16 = 8;

/// A forwarder with no cache stage, validating: every query reaches the validator.
fn validating(listen: &str, upstream: &str) -> String {
    format!(
        "listen: ['{listen}']\npipeline: [up]\nstages:\n  up:\n    type: forward\n    servers: ['{upstream}']\n    timeout_ms: 5000\n    tries: 1\n    dnssec: validate\n"
    )
}

/// The clock of `dedensd` is the system's, so the signatures of a capture are long expired: a query ends bogus at
/// its first check, the root's DNSKEY under the trust anchor. What is asserted is the questions upstream, not that
/// verdict.
#[test]
fn concurrent_queries_send_the_root_keys_question_once() {
    // The responder answers one query at a time, each late: the validator's first question, sent when the first
    // client's answer arrives, queues behind the other clients' and is answered last, so that every query asks it
    // while it is in flight.
    let responder = Responder::dnssec(&["alg8_a", "root_dnskey"], Duration::from_millis(150));
    let server = Server::configured(|listen| validating(listen, &responder.addr.to_string()));
    let query = query_for(&captured_dnssec("alg8_a"), 1);
    let clients: Vec<_> = (0..CLIENTS)
        .map(|id| {
            let mut query = query.clone();
            query[..2].copy_from_slice(&(id + 1).to_be_bytes());
            let addr = server.addr;
            thread::spawn(move || ask_udp(addr, &query))
        })
        .collect();
    for client in clients {
        let reply = client.join().expect("a reply");
        assert_eq!(reply.header.rcode, Rcode::SERVFAIL);
    }
    assert_eq!(
        responder.asked("nlnetlabs.nl.", RecordType::A),
        usize::from(CLIENTS),
        "the client's own question is each query's"
    );
    assert_eq!(
        responder.asked(".", RecordType::DNSKEY),
        1,
        "the validator's question is asked once and shared"
    );
}
