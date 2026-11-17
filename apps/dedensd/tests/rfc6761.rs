//! RFC 6761 §6, RFC 6762 §22.1, RFC 7686 §2 and RFC 9476 §2: `dedensd` with a `tlds` stage (D128) before a forward
//! stage answers the special-use names as their RFCs ask of a caching server, with no upstream query; a name of a
//! TLD not in the root zone is NXDOMAIN without DO and passed on with DO; `arpa` is passed on, and a name of one's
//! own network under `internal` comes from a hosts stage before.

use std::net::{Ipv4Addr, Ipv6Addr, UdpSocket};
use std::time::Duration;

use dedens_proto::edns::EdnsFlags;
use dedens_proto::rdata::RData;
use dedens_proto::{Flags, Message, Question, Rcode, RecordType};

use crate::util::{Server, ask_udp, silent};

/// A server answering `printer.internal` from a hosts stage, then the special-use and absent TLDs from the bundled
/// list, and forwarding the rest to `upstream`.
fn config(listen: &str, upstream: &str) -> String {
    format!(
        "listen: ['{listen}']\nroots: off\npipeline: [hosts, tlds, up]\nstages:\n  hosts:\n    type: hosts\n    entries: ['192.0.2.7 printer.internal']\n  tlds:\n    type: tlds\n  up:\n    type: forward\n    servers: ['{upstream}']\n    timeout_ms: 200\n    tries: 1\n"
    )
}

/// The reply of `server` to `name` and `qtype`, with DO when `signed`.
pub(crate) fn ask(
    server: &Server,
    name: &str,
    qtype: RecordType,
    signed: bool,
) -> Message<'static> {
    let name = name.parse().expect("a name");
    let mut query = Message::query(7, Question::new(name, qtype));
    if let Some(edns) = query.edns.as_mut() {
        edns.flags = if signed {
            EdnsFlags::DO
        } else {
            EdnsFlags::default()
        };
    }
    ask_udp(server.addr, &query.to_vec().expect("a query fits"))
}

/// The names, in lower case, of the queries `upstream` received so far.
pub(crate) fn asked(upstream: &UdpSocket) -> Vec<String> {
    upstream
        .set_read_timeout(Some(Duration::from_millis(100)))
        .expect("a timeout");
    let mut names = Vec::new();
    let mut buf = [0; 4096];
    while let Ok(len) = upstream.recv(&mut buf) {
        let query = Message::decode(&buf[..len]).expect("a query").message;
        names.push(query.questions[0].name.to_string().to_ascii_lowercase());
    }
    names
}

#[test]
fn rfc6761_6_3_localhost_and_its_subnames_are_the_loopback_addresses() {
    let (upstream, at) = silent();
    let server = Server::configured(|listen| config(listen, &at.to_string()));
    for name in ["localhost.", "www.LocalHost."] {
        let a = ask(&server, name, RecordType::A, false);
        assert_eq!(a.rcode(), Rcode::NOERROR, "{name}");
        assert!(a.header.flags.contains(Flags::AA), "{name}");
        assert_eq!(a.answer[0].data(), RData::A(Ipv4Addr::LOCALHOST), "{name}");
        let aaaa = ask(&server, name, RecordType::AAAA, true);
        assert_eq!(
            aaaa.answer[0].data(),
            RData::Aaaa(Ipv6Addr::LOCALHOST),
            "{name}"
        );
        let mx = ask(&server, name, RecordType::MX, false);
        assert_eq!((mx.rcode(), mx.answer.len()), (Rcode::NOERROR, 0), "{name}");
    }
    assert_eq!(asked(&upstream), Vec::<String>::new());
}

/// RFC 6761 §6.2 and §6.4, RFC 6762 §22.1, RFC 7686 §2: NXDOMAIN, DO or not, and no query upstream.
#[test]
fn rfc6761_6_and_rfc7686_2_names_never_resolved_are_nxdomain_with_no_upstream_query() {
    let (upstream, at) = silent();
    let server = Server::configured(|listen| config(listen, &at.to_string()));
    for name in [
        "invalid.",
        "x.invalid.",
        "x.test.",
        "printer.local.",
        "onion.",
        "x.onion.",
    ] {
        for signed in [false, true] {
            let reply = ask(&server, name, RecordType::A, signed);
            assert_eq!(reply.rcode(), Rcode::NXDOMAIN, "{name} {signed}");
            assert!(reply.authority.is_empty(), "{name} {signed}");
        }
    }
    assert_eq!(asked(&upstream), Vec::<String>::new());
}

/// RFC 6761 §6.5, RFC 9476 §2: `example` and `alt` are not special, and not in the root zone: NXDOMAIN without DO,
/// as the root gives, and passed on with DO, as a TLD that does not exist is; `arpa` is passed on, and
/// `printer.internal` comes from the hosts stage.
#[test]
fn rfc6761_6_5_names_of_no_special_use_are_left_to_the_root_zone() {
    let (upstream, at) = silent();
    let server = Server::configured(|listen| config(listen, &at.to_string()));
    for name in ["www.example.", "x.alt.", "nonexistent-tld."] {
        assert_eq!(
            ask(&server, name, RecordType::A, false).rcode(),
            Rcode::NXDOMAIN,
            "{name}"
        );
        assert_eq!(asked(&upstream), Vec::<String>::new(), "{name}");
        assert_eq!(
            ask(&server, name, RecordType::A, true).rcode(),
            Rcode::SERVFAIL,
            "{name}"
        );
        assert_eq!(asked(&upstream), [name], "{name}");
    }
    let arpa = "1.0.0.127.in-addr.arpa.";
    assert_eq!(
        ask(&server, arpa, RecordType::PTR, false).rcode(),
        Rcode::SERVFAIL
    );
    assert_eq!(asked(&upstream), [arpa]);
    let printer = ask(&server, "printer.internal.", RecordType::A, false);
    assert_eq!(
        printer.answer[0].data(),
        RData::A(Ipv4Addr::new(192, 0, 2, 7))
    );
    assert_eq!(asked(&upstream), Vec::<String>::new());
}
