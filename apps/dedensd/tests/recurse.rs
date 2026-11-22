//! RFC 6303 §3, RFC 8375 §4 and RFC 6761 §6.3: `dedensd` with a cache stage and a recurse stage (D195) answers the
//! zones served locally itself, with no query to the Internet. The resolution of a capture by `dedensd`'s loop runs
//! in `dedens-sim`'s `tests/recurse.rs`, on the captured servers' addresses, which a process here cannot reach. The
//! process runs on the real clock, where the signatures of the captures have ended (D197): it validates nothing here,
//! `dnssec: off`, and fetches no trust anchors.

use std::net::Ipv4Addr;

use dedens_proto::rdata::RData;
use dedens_proto::{Flags, Rcode, RecordType};

use crate::rfc6761::ask;
use crate::util::Server;

#[test]
fn rfc6303_3_dedensd_answers_the_zones_served_locally() {
    let server = Server::configured(|listen| {
        format!(
            "listen: ['{listen}']\npipeline: [cache, root]\nstages:\n  cache:\n    type: cache\n  root:\n    type: recurse\n    dnssec: off\n"
        )
    });
    let reverse = ask(&server, "1.0.0.127.in-addr.arpa.", RecordType::PTR, false);
    assert_eq!(reverse.rcode(), Rcode::NXDOMAIN);
    assert!(reverse.header.flags.contains(Flags::AA));
    assert_eq!(reverse.authority[0].rtype(), RecordType::SOA);
    let home = ask(&server, "home.arpa.", RecordType::SOA, false);
    assert_eq!((home.rcode(), home.answer.len()), (Rcode::NOERROR, 1));
    let localhost = ask(&server, "localhost.", RecordType::A, false);
    assert_eq!(localhost.answer[0].data(), RData::A(Ipv4Addr::LOCALHOST));
}
