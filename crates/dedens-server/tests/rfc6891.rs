//! RFC 6891 in the server core: the OPT record of replies (§7), the UDP payload they fit (§6.2.3, §6.2.5),
//! BADVERS (§6.1.3) and several OPT records (§6.1.1); DO copied (RFC 3225 §3).

mod common;

use common::{decode, forwarder, query_for, reply, run, wire};
use dedens_proto::edns::{Edns, EdnsFlags};
use dedens_proto::{Flags, Rcode, Transport};
use dedens_testkit::captured;

#[test]
fn replies_have_our_opt_record_when_the_query_had_one() {
    let response = captured("a");
    let mut query = query_for(&response);
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
        let mut query = query_for(&response);
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
    let mut query = query_for(&captured("a"));
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
    let query = wire(&query_for(&captured("a")));
    // The OPT record without options is the last 11 bytes; a second one after it, counted in ARCOUNT.
    let mut twice = query.clone();
    twice.extend_from_slice(&query[query.len() - 11..]);
    twice[11] += 1;
    let wire = reply(&forwarder(), &twice, Transport::Udp, None);
    assert_eq!(decode(&wire).rcode(), Rcode::FORMERR);
}

#[test]
fn the_do_bit_goes_upstream_and_back() {
    let response = captured("a");
    for flags in [EdnsFlags::DO, EdnsFlags::default()] {
        let mut query = query_for(&response);
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
