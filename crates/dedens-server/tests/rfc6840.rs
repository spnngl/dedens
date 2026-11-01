//! RFC 6840 in the server core: AD asked upstream as the client asked (§5.7) and kept only for clients that
//! asked for it (§5.8); CD copied upstream and back (RFC 4035 §3.2.2).

mod common;

use common::{
    Captures, captured, client_query, decode, forwarder, query_for, run, run_captured, validating,
    wire, with_flags,
};
use dedens_proto::{Edns, EdnsFlags, Flags, RecordType};
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
        assert_eq!(done.requests[0].header.flags, Flags::RD | ad);
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

/// §5.7-5.8 with validation (D77): a secure answer has AD for a client that set AD or DO, not for one that set
/// neither; the verdict is the same cached or not.
#[test]
fn a_validated_answer_has_ad_only_for_clients_with_ad_or_do() {
    let pipeline = validating();
    let captures = Captures::new();
    for (flags, dnssec, ad) in [
        (Flags::NONE, false, false),
        (Flags::AD, false, true),
        (Flags::NONE, true, true),
        (Flags::NONE, false, false),
    ] {
        let query = client_query("cloudflare.com.", RecordType::A, flags, dnssec);
        let done = run_captured(&pipeline, &query, 0, &captures);
        let wire = done.reply.expect("a reply");
        assert_eq!(
            decode(&wire).header.flags.contains(Flags::AD),
            ad,
            "{flags:?}, DO {dnssec}"
        );
    }
}

/// §5.9: CD is set on every upstream query, whether the client set it or not, and the validator's questions too.
/// §5.6: the DO bit of the reply is the query's.
#[test]
fn cd_is_set_on_every_upstream_query_and_do_is_copied_back() {
    let pipeline = validating();
    for dnssec in [true, false] {
        let query = client_query("google.com.", RecordType::A, Flags::NONE, dnssec);
        let done = run_captured(&pipeline, &query, 0, &Captures::new());
        assert!(
            done.requests
                .iter()
                .all(|r| r.header.flags.contains(Flags::CD))
        );
        let wire = done.reply.expect("a reply");
        let edns = decode(&wire).edns.expect("our OPT record");
        assert_eq!(edns.flags.contains(EdnsFlags::DO), dnssec);
    }
}
