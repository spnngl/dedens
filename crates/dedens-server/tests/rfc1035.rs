//! RFC 1035 in the server core: the reply header (§4.1.1), reply sizes over UDP (§4.2.1) and TCP (§4.2.2), and
//! moving past failing servers (§7.3).

mod common;

use common::{
    captured, decode, forwarder, query_for, reply, run, servers, wire, with_flags, with_rcode,
};
use dedens_proto::{Flags, Message, Opcode, Rcode, Transport};
use dedens_server::Pipeline;

#[test]
fn a_forwarded_answer_comes_back_under_the_clients_id() {
    let response = captured("a");
    let done = run(
        &forwarder(),
        &wire(&query_for(&response)),
        Transport::Udp,
        &[Some(&response)],
    );
    assert_eq!(done.asked, servers()[..1]);
    let wire = done.reply.expect("a reply");
    let reply = decode(&wire);
    let upstream = Message::decode(&response).expect("decodes").message;
    assert_eq!(reply.header.id, 7);
    assert_eq!(reply.rcode(), Rcode::NOERROR);
    assert_eq!(reply.answer, upstream.answer);
    assert_eq!(reply.authority, upstream.authority);
}

#[test]
fn replies_set_qr_and_ra_copy_rd_and_clear_aa() {
    let response = with_flags(captured("a"), Flags::AA);
    for rd in [Flags::RD, Flags::NONE] {
        let mut query = query_for(&response);
        query.header.flags = rd;
        let wire = reply(&forwarder(), &wire(&query), Transport::Udp, Some(&response));
        assert_eq!(decode(&wire).header.flags, Flags::QR | Flags::RA | rd);
    }
}

#[test]
fn an_unreadable_query_gets_formerr_with_its_header_alone() {
    let mut query = query_for(&captured("a"));
    query.header.opcode = Opcode::NOTIFY;
    let mut bytes = wire(&query);
    bytes.truncate(15);
    let wire = reply(&forwarder(), &bytes, Transport::Udp, None);
    let reply = decode(&wire);
    assert_eq!(reply.header.id, 7);
    assert_eq!(reply.header.opcode, Opcode::NOTIFY);
    assert_eq!(reply.rcode(), Rcode::FORMERR);
    assert_eq!(reply.questions, []);
    // Its OPT record could not be read: the reply has none (RFC 6891 §7).
    assert_eq!(reply.edns, None);
}

#[test]
fn responses_and_bytes_shorter_than_a_header_are_dropped() {
    let response = captured("a");
    for bytes in [&[0; 11][..], &response, &response[..20]] {
        let done = run(&forwarder(), bytes, Transport::Udp, &[]);
        assert_eq!((done.asked, done.reply), (vec![], None));
    }
}

#[test]
fn opcodes_other_than_query_get_notimp() {
    for opcode in [
        Opcode::IQUERY,
        Opcode::STATUS,
        Opcode::NOTIFY,
        Opcode::UPDATE,
    ] {
        let mut query = query_for(&captured("a"));
        query.header.opcode = opcode;
        let wire = reply(&forwarder(), &wire(&query), Transport::Udp, None);
        let reply = decode(&wire);
        assert_eq!(
            (reply.header.opcode, reply.rcode()),
            (opcode, Rcode::NOTIMP)
        );
        assert_eq!(reply.questions, query.questions);
    }
}

#[test]
fn a_query_without_question_gets_formerr() {
    let mut query = query_for(&captured("a"));
    query.questions.clear();
    let wire = reply(&forwarder(), &wire(&query), Transport::Udp, None);
    assert_eq!(decode(&wire).rcode(), Rcode::FORMERR);
}

#[test]
fn without_stages_every_query_is_refused() {
    let query = query_for(&captured("a"));
    let wire = reply(&Pipeline::default(), &wire(&query), Transport::Udp, None);
    let reply = decode(&wire);
    assert_eq!(reply.rcode(), Rcode::REFUSED);
    assert_eq!(reply.questions, query.questions);
}

#[test]
fn udp_replies_without_edns_fit_512_bytes_and_tcp_ones_come_whole() {
    let response = captured("txt_large");
    let upstream = Message::decode(&response).expect("decodes").message;
    let mut query = query_for(&response);
    query.edns = None;
    let udp = reply(&forwarder(), &wire(&query), Transport::Udp, Some(&response));
    assert!(udp.len() <= 512, "{} bytes", udp.len());
    assert!(decode(&udp).header.flags.contains(Flags::TC));
    let tcp = reply(&forwarder(), &wire(&query), Transport::Tcp, Some(&response));
    let tcp = decode(&tcp);
    assert!(!tcp.header.flags.contains(Flags::TC));
    assert_eq!(tcp.answer, upstream.answer);
}

#[test]
fn servers_that_fail_refuse_or_do_not_answer_are_passed_over_in_order() {
    let answer = captured("a");
    let failures = [
        None,
        Some(with_rcode(answer.clone(), Rcode::SERVFAIL)),
        Some(with_rcode(answer.clone(), Rcode::REFUSED)),
        Some(with_rcode(answer.clone(), Rcode::NOTIMP)),
        Some(with_rcode(answer.clone(), Rcode::FORMERR)),
        Some(captured("truncated")),
        Some(answer[..30].to_vec()),
    ];
    for failure in &failures {
        let query = wire(&query_for(&answer));
        let done = run(
            &forwarder(),
            &query,
            Transport::Udp,
            &[failure.as_deref(), Some(&answer)],
        );
        assert_eq!(done.asked, servers(), "after {failure:?}");
        let wire = done.reply.expect("a reply");
        assert_eq!(decode(&wire).rcode(), Rcode::NOERROR);
        // The same request goes to each server.
        assert_eq!(done.requests[0], done.requests[1]);
    }
}

#[test]
fn a_name_error_is_an_answer_not_a_failure() {
    let response = captured("nxdomain_soa");
    let done = run(
        &forwarder(),
        &wire(&query_for(&response)),
        Transport::Udp,
        &[Some(&response)],
    );
    assert_eq!(done.asked.len(), 1);
    let wire = done.reply.expect("a reply");
    assert_eq!(decode(&wire).rcode(), Rcode::NXDOMAIN);
}

#[test]
fn servfail_follows_the_last_failing_server() {
    let answer = captured("a");
    let query = query_for(&answer);
    let done = run(&forwarder(), &wire(&query), Transport::Udp, &[]);
    assert_eq!(done.asked, servers());
    let wire = done.reply.expect("a reply");
    let reply = decode(&wire);
    assert_eq!(reply.rcode(), Rcode::SERVFAIL);
    assert_eq!(reply.questions, query.questions);
    assert_eq!(reply.answer, []);
}
