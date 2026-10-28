//! RFC 6840 in the server core: AD only for clients that asked for it (§5.8); CD copied upstream and back
//! (RFC 4035 §3.2.2).

mod common;

use common::{captured, decode, forwarder, query_for, run, wire, with_flags};
use dedens_proto::{Edns, EdnsFlags, Flags};
use dedens_server::Transport;

#[test]
fn ad_stays_only_for_queries_with_ad_or_do() {
    let response = with_flags(captured("a"), Flags::AD);
    for (ad, dnssec, kept) in [
        (Flags::NONE, false, false),
        (Flags::AD, false, true),
        (Flags::NONE, true, true),
    ] {
        let mut query = query_for(&response);
        query.header.flags = Flags::RD | ad;
        query.edns = Some(Edns {
            flags: if dnssec {
                EdnsFlags::DO
            } else {
                EdnsFlags::default()
            },
            ..Edns::default()
        });
        let done = run(
            &forwarder(),
            &wire(&query),
            Transport::Udp,
            &[Some(&response)],
        );
        let wire = done.reply.expect("a reply");
        assert_eq!(
            decode(&wire).header.flags.contains(Flags::AD),
            kept,
            "AD {ad:?}, DO {dnssec}"
        );
    }
}

#[test]
fn cd_goes_upstream_and_back() {
    let response = captured("a");
    for cd in [Flags::CD, Flags::NONE] {
        let mut query = query_for(&response);
        query.header.flags = Flags::RD | cd;
        let done = run(
            &forwarder(),
            &wire(&query),
            Transport::Udp,
            &[Some(&response)],
        );
        assert_eq!(done.requests[0].header.flags, Flags::RD | cd);
        let wire = done.reply.expect("a reply");
        assert_eq!(
            decode(&wire).header.flags.contains(Flags::CD),
            cd == Flags::CD
        );
    }
}
