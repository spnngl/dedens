//! The server core's messages: responses to what a query asks and how it asks it.
//!
//! - RFC 1035 in the server core: the reply header (§4.1.1), reply sizes over UDP (§4.2.1) and TCP (§4.2.2), and moving
//!   past failing servers (§7.3): any RCODE but NOERROR, NXDOMAIN and YXDOMAIN (RFC 6672 §2.2) is a failure (D41).
//! - RFC 6891 in the server core: the OPT record of replies (§7), the UDP payload they fit (§6.2.3, §6.2.5), BADVERS
//!   (§6.1.3), FORMERR with our OPT record to OPT records that break a rule (§6.1.1, §6.1.2, §7); DO copied (RFC 3225
//!   §3).
//! - RFC 7830 in the server core: replies to a padded query over TLS or QUIC are padded (§4), to a multiple of 468
//!   bytes (RFC 8467 §4.1), with zeros (§3); no other reply is.
//! - RFC 9619 in the server core: a query with more than one question gets FORMERR (§3).
//! - RFC 8482 §4.4: ANY over UDP and CoAP is answered with an empty, truncated response, never forwarded nor cached
//!   (D114); over the other transports it is answered as any query. The query is the question of a real ANY response,
//!   `any_rfc8482`, captured from cloudflare.com's name server (`capture.yaml`).
//! - RFC 5936 in the server core: zone transfers, AXFR and IXFR (RFC 1995), come from a zone's servers, so a forwarder
//!   refuses them over either transport; none is defined over UDP (§4.2).

use std::net::Ipv4Addr;
use std::sync::Arc;

use dedens_proto::edns::{Cookie, Edns, EdnsFlags, EdnsOption, InfoCode};
use dedens_proto::{Class, Flags, Message, Opcode, Question, Rcode, RecordType, Transport};
use dedens_server::{Clock, Cookies, Pipeline, Secret, Secrets, Step};
use dedens_testkit::{captured, dns, query};

use crate::util::{caching, decode, forwarder, reply, run, servers, wire, with_flags, with_rcode};

// --- RFC 1035 in the server core ---

#[test]
fn a_forwarded_answer_comes_back_under_the_clients_id() {
    let response = captured("a");
    let done = run(
        &forwarder(),
        &wire(&query("a", 7)),
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
        let mut query = query("a", 7);
        query.header.flags = rd;
        let wire = reply(&forwarder(), &wire(&query), Transport::Udp, Some(&response));
        assert_eq!(decode(&wire).header.flags, Flags::QR | Flags::RA | rd);
    }
}

#[test]
fn an_unreadable_query_gets_formerr_with_its_header_alone() {
    let mut query = query("a", 7);
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
        let mut query = query("a", 7);
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
    let mut query = query("a", 7);
    query.questions.clear();
    let wire = reply(&forwarder(), &wire(&query), Transport::Udp, None);
    assert_eq!(decode(&wire).rcode(), Rcode::FORMERR);
}

#[test]
fn without_stages_every_query_is_refused() {
    let query = query("a", 7);
    let wire = reply(&Pipeline::default(), &wire(&query), Transport::Udp, None);
    let reply = decode(&wire);
    assert_eq!(reply.rcode(), Rcode::REFUSED);
    assert_eq!(reply.questions, query.questions);
}

#[test]
fn udp_replies_without_edns_fit_512_bytes_and_tcp_ones_come_whole() {
    let response = captured("txt_large");
    let upstream = Message::decode(&response).expect("decodes").message;
    let mut query = query("txt_large", 7);
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
        Some(with_rcode(answer.clone(), Rcode::YXRRSET)),
        Some(with_rcode(answer.clone(), Rcode::NOTAUTH)),
        Some(with_rcode(answer.clone(), Rcode::NOTZONE)),
        Some(extended("a", Rcode::BADVERS)),
        Some(extended("a", Rcode::BADCOOKIE)),
        Some(captured("truncated")),
        Some(answer[..30].to_vec()),
    ];
    for failure in &failures {
        let query = wire(&query("a", 7));
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

/// The capture `case` with the 12-bit RCODE `rcode`, its upper bits in the capture's OPT record (RFC 6891 §6.1.3).
fn extended(case: &str, rcode: Rcode) -> Vec<u8> {
    let mut message = Message::decode(&captured(case))
        .expect("a captured response decodes")
        .message
        .into_owned();
    message
        .set_rcode(rcode)
        .expect("the capture has an OPT record");
    wire(&message)
}

#[test]
fn a_name_error_is_an_answer_not_a_failure() {
    let response = captured("nxdomain_soa");
    let done = run(
        &forwarder(),
        &wire(&query("nxdomain_soa", 7)),
        Transport::Udp,
        &[Some(&response)],
    );
    assert_eq!(done.asked.len(), 1);
    let wire = done.reply.expect("a reply");
    assert_eq!(decode(&wire).rcode(), Rcode::NXDOMAIN);
}

#[test]
fn a_dname_loop_is_an_answer_not_a_failure() {
    let response = with_rcode(captured("a"), Rcode::YXDOMAIN);
    let done = run(
        &forwarder(),
        &wire(&query("a", 7)),
        Transport::Udp,
        &[Some(&response)],
    );
    assert_eq!(done.asked.len(), 1);
    let wire = done.reply.expect("a reply");
    assert_eq!(decode(&wire).rcode(), Rcode::YXDOMAIN);
}

/// None of the failures speaks of the client's query: after the last server, the client gets SERVFAIL, in our OPT
/// record's 12 bits, not the upstream's extended RCODE.
#[test]
fn servfail_follows_the_last_server_answering_another_rcode() {
    for rcode in [Rcode::BADVERS, Rcode::BADCOOKIE] {
        let failure = extended("a", rcode);
        let done = run(
            &forwarder(),
            &wire(&query("a", 7)),
            Transport::Udp,
            &[
                Some(&failure),
                Some(&with_rcode(captured("a"), Rcode::NXRRSET)),
            ],
        );
        assert_eq!(done.asked, servers(), "after {rcode}");
        let wire = done.reply.expect("a reply");
        let reply = decode(&wire);
        assert_eq!(reply.rcode(), Rcode::SERVFAIL);
        assert_eq!(reply.answer, []);
    }
}

#[test]
fn servfail_follows_the_last_failing_server() {
    let query = query("a", 7);
    let done = run(&forwarder(), &wire(&query), Transport::Udp, &[]);
    assert_eq!(done.asked, servers());
    let wire = done.reply.expect("a reply");
    let reply = decode(&wire);
    assert_eq!(reply.rcode(), Rcode::SERVFAIL);
    assert_eq!(reply.questions, query.questions);
    assert_eq!(reply.answer, []);
}

// --- RFC 6891 in the server core ---

#[test]
fn replies_have_our_opt_record_when_the_query_had_one() {
    let response = captured("a");
    let mut query = query("a", 7);
    query.edns = Some(Edns {
        udp_payload: 4096,
        ..Edns::default()
    });
    let with = reply(&forwarder(), &wire(&query), Transport::Udp, Some(&response));
    assert_eq!(decode(&with).edns, Some(Edns::default()));
    query.edns = None;
    let without = reply(&forwarder(), &wire(&query), Transport::Udp, Some(&response));
    assert_eq!(decode(&without).edns, None);
}

#[test]
fn udp_replies_fit_the_clients_payload_and_512_bytes_at_least() {
    let response = captured("txt_large");
    for (payload, limit) in [(600, 600), (100, 512), (0, 512), (4096, 1232)] {
        let mut query = query("txt_large", 7);
        query.edns = Some(Edns {
            udp_payload: payload,
            ..Edns::default()
        });
        let wire = reply(&forwarder(), &wire(&query), Transport::Udp, Some(&response));
        assert!(
            wire.len() <= limit,
            "payload {payload}: {} bytes",
            wire.len()
        );
        let truncated = decode(&wire).header.flags.contains(Flags::TC);
        assert_eq!(truncated, response.len() > limit, "payload {payload}");
    }
}

#[test]
fn an_edns_version_above_0_gets_badvers_with_version_0() {
    let mut query = query("a", 7);
    query.edns = Some(Edns {
        version: 1,
        ..Edns::default()
    });
    let done = run(&forwarder(), &wire(&query), Transport::Udp, &[]);
    assert_eq!(done.asked, []);
    let wire = done.reply.expect("a reply");
    let reply = decode(&wire);
    assert_eq!(reply.rcode(), Rcode::BADVERS);
    assert_eq!(reply.edns.map(|edns| edns.version), Some(0));
}

#[test]
fn several_opt_records_get_formerr() {
    let query = wire(&query("a", 7));
    // The OPT record without options is the last 11 bytes; a second one after it, counted in ARCOUNT.
    let mut twice = query.clone();
    twice.extend_from_slice(&query[query.len() - 11..]);
    twice[11] += 1;
    let wire = reply(&forwarder(), &twice, Transport::Udp, None);
    let reply = decode(&wire);
    assert_eq!(reply.rcode(), Rcode::FORMERR);
    // RFC 6891 §6.1.1: the query had an OPT record, so the reply has ours.
    assert_eq!(reply.edns, Some(Edns::default()));
}

/// The query of the `a` capture without EDNS, then `opt`, an OPT record of the additional section.
fn with_opt(opt: &[u8]) -> Vec<u8> {
    let mut query = query("a", 7);
    query.edns = None;
    let mut bytes = wire(&query);
    bytes.extend_from_slice(opt);
    bytes[11] = 1;
    bytes
}

/// RFC 6891 §6.1.2 and §7: an OPT record outside the additional section, or not owned by the root, is a problem
/// with the OPT record: FORMERR, with our OPT record. The client's is not read: its DO is not copied.
#[test]
fn a_misplaced_opt_record_gets_formerr_with_ours() {
    let mut query = query("a", 7);
    query.edns = Some(Edns {
        flags: EdnsFlags::DO,
        ..Edns::default()
    });
    // The OPT record, the last 11 bytes, counted in the authority section instead of the additional one.
    let mut authority = wire(&query);
    authority[9] = 1;
    authority[11] = 0;
    // An OPT record owned by the question's name, a pointer to it.
    let owned = with_opt(&[0xC0, 0x0C, 0, 41, 0x04, 0xD0, 0, 0, 0x80, 0, 0, 0]);
    for bytes in [authority, owned] {
        let done = run(&forwarder(), &bytes, Transport::Udp, &[]);
        assert_eq!(done.asked, []);
        let wire = done.reply.expect("a reply");
        let reply = decode(&wire);
        assert_eq!(reply.rcode(), Rcode::FORMERR);
        assert_eq!(reply.edns, Some(Edns::default()));
    }
}

/// RFC 6891 §7: an option that cannot be read, a COOKIE of 3 bytes (RFC 7873 §4), is a problem with the OPT record:
/// FORMERR, with our OPT record.
#[test]
fn an_invalid_option_gets_formerr_with_our_opt_record() {
    let bytes = with_opt(&[0, 0, 41, 0x04, 0xD0, 0, 0, 0, 0, 0, 7, 0, 10, 0, 3, 1, 2, 3]);
    let wire = reply(&forwarder(), &bytes, Transport::Udp, None);
    let reply = decode(&wire);
    assert_eq!(reply.rcode(), Rcode::FORMERR);
    assert_eq!(reply.edns, Some(Edns::default()));
}

/// RFC 6891 §6.1.2, §7: an option overrunning its OPT record, a COOKIE of 8 bytes in an RDATA of 4, leaves the record
/// unread: FORMERR with our OPT record, the client's DO not copied (D41).
#[test]
fn an_option_overrunning_its_opt_record_gets_formerr_with_our_opt_record() {
    let bytes = with_opt(&[0, 0, 41, 0x04, 0xD0, 0, 0, 0x80, 0, 0, 4, 0, 10, 0, 8]);
    let wire = reply(&forwarder(), &bytes, Transport::Udp, None);
    let reply = decode(&wire);
    assert_eq!((reply.rcode(), reply.questions.len()), (Rcode::FORMERR, 1));
    assert_eq!(reply.edns, Some(Edns::default()));
}

#[test]
fn the_do_bit_goes_upstream_and_back() {
    let response = captured("a");
    for flags in [EdnsFlags::DO, EdnsFlags::default()] {
        let mut query = query("a", 7);
        query.edns = Some(Edns {
            flags,
            ..Edns::default()
        });
        let done = run(
            &forwarder(),
            &wire(&query),
            Transport::Udp,
            &[Some(&response)],
        );
        let request = done.requests[0].edns.as_ref().expect("EDNS upstream");
        assert_eq!(request.flags, flags);
        let wire = done.reply.expect("a reply");
        assert_eq!(decode(&wire).edns.map(|edns| edns.flags), Some(flags));
    }
}

// --- RFC 7830 in the server core ---

/// The query of the `a` capture, with EDNS and, when `padded`, an empty Padding option.
fn a_query(padded: bool) -> Message<'static> {
    let mut query = query("a", 7);
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
            &wire(&a_query(true)),
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
            &wire(&a_query(padded)),
            transport,
            Some(&response),
        );
        assert_eq!(padding(&wire), None, "{transport:?}");
    }
}

#[test]
fn failures_are_padded() {
    let wire = reply(&forwarder(), &wire(&a_query(true)), Transport::Tls, None);
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
    let query = wire(&a_query(true));
    assert!(
        run(&pipeline, &query, Transport::Tls, &[Some(&response)])
            .reply
            .is_some()
    );
    let mut out = vec![0xFF; 65535];
    let Step::Reply(len) = pipeline.query(
        &query,
        Transport::Tls,
        Ipv4Addr::LOCALHOST.into(),
        0,
        &mut out,
    ) else {
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
    let query = wire(&a_query(true));
    assert!(
        run(&pipeline, &query, Transport::Tls, &[Some(&response)])
            .reply
            .is_some()
    );
    // The `a` capture's records live 300 seconds at most.
    let late = crate::util::run_at(&pipeline, &query, Transport::Tls, 301, &[None, None]);
    let wire = late.reply.expect("a stale reply");
    assert_eq!(wire.len() % 468, 0);
    let options = decode(&wire).edns.expect("an OPT record").options;
    assert!(
        matches!(options.as_slice(), [EdnsOption::Ede(ede), EdnsOption::Padding(_)] if ede.code == InfoCode::STALE_ANSWER),
        "{options:?}"
    );
}

/// Padding comes after the COOKIE option (RFC 7873 §5.2.3) the reply carries, which the OPT record's length counts.
#[test]
fn a_reply_with_a_cookie_is_padded_after_it() {
    let clock: Clock = Arc::new(|| 1_559_731_985);
    let secret: Secret = "e5e973e5a6b2a43f48e7dc849e37bfcf"
        .parse()
        .expect("a secret");
    let pipeline = forwarder().with_cookies(Cookies::new(Secrets::new(secret, vec![]), clock));
    let mut query = a_query(true);
    let client = Cookie::new([1; 8], None).expect("a cookie");
    let edns = query.edns.as_mut().expect("EDNS");
    edns.options.insert(0, EdnsOption::Cookie(client));
    let response = captured("a");
    let wire = reply(&pipeline, &wire(&query), Transport::Tls, Some(&response));
    assert_eq!(wire.len() % 468, 0);
    let reread = decode(&wire);
    assert_eq!(reread.answer, decode(&response).answer);
    let options = reread.edns.expect("an OPT record").options;
    assert!(
        matches!(options.as_slice(), [EdnsOption::Cookie(cookie), EdnsOption::Padding(_)] if cookie.client() == client.client() && cookie.server().is_some()),
        "{options:?}"
    );
}

/// The OPT record opens the additional section of a forwarded reply (D9): padding must not land after the last
/// record. The `cookie` capture holds isc.org's NS records with their glue as additional data.
#[test]
fn a_padded_reply_keeps_its_additional_records() {
    let response = captured("cookie");
    let mut query = query("cookie", 7);
    query.edns = Some(Edns {
        options: vec![EdnsOption::Padding(0)],
        ..Edns::default()
    });
    let wire = reply(&forwarder(), &wire(&query), Transport::Tls, Some(&response));
    let reread = decode(&wire);
    let upstream = decode(&response);
    assert_ne!(upstream.additional.len(), 0);
    assert_eq!(reread.additional, upstream.additional);
    assert_eq!(reread.answer, upstream.answer);
    assert!(padding(&wire).is_some());
    assert_eq!(wire.len() % 468, 0);
}

// --- RFC 9619 in the server core ---

#[test]
fn two_questions_get_formerr_without_asking_upstream() {
    let mut query = query("a", 7);
    query.questions.push(query.questions[0].clone());
    let done = run(&forwarder(), &wire(&query), Transport::Udp, &[]);
    assert_eq!(done.asked, []);
    let wire = done.reply.expect("a reply");
    let reply = decode(&wire);
    assert_eq!(reply.rcode(), Rcode::FORMERR);
    assert_eq!(reply.questions, query.questions[..1]);
}

// --- RFC 8482 §4.4 ---

/// The real ANY response, and its query with the EDNS and DO bit given.
fn any(edns: Option<bool>) -> (Vec<u8>, Vec<u8>) {
    let response = captured("any_rfc8482");
    let mut query = query("any_rfc8482", 7);
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
    let query = wire(&query("a", 7));
    let done = run(&forwarder(), &query, Transport::Udp, &[Some(&response)]);
    assert_eq!(done.asked.len(), 1);
    let reply = done.reply.expect("a reply");
    let message = decode(&reply);
    assert!(!message.header.flags.contains(Flags::TC));
    assert_ne!(message.answer.len(), 0);
}

// --- RFC 5936 in the server core ---

#[test]
fn zone_transfers_are_refused() {
    for qtype in [RecordType::AXFR, RecordType::IXFR] {
        for transport in [Transport::Udp, Transport::Tcp] {
            let query = Message::query(7, Question::new(dns("example.com"), qtype));
            let done = run(&forwarder(), &wire(&query), transport, &[]);
            assert_eq!(done.asked, []);
            let wire = done.reply.expect("a reply");
            assert_eq!(
                decode(&wire).rcode(),
                Rcode::REFUSED,
                "{qtype} over {transport:?}"
            );
        }
    }
}
