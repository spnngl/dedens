//! RFC 5358 in the server core (D91): a server answers the networks it is told to, so that it is no reflector for
//! forged sources (§4). The longest network holding the client decides, `deny` wins a tie, a client in no network is
//! denied, an IPv4-mapped address is the IPv4 one; a denied client gets REFUSED with EDE 18 (RFC 8914 §4.19) or
//! nothing.

mod common;

use std::net::{IpAddr, Ipv4Addr};

use common::{captured, decode, forwarder, query_for, wire};
use dedens_proto::edns::{EdnsOption, InfoCode};
use dedens_proto::{Flags, Rcode};
use dedens_server::{Access, Denial, Network, NetworkError, Pipeline, Step, Transport};

fn nets<const N: usize>(texts: [&str; N]) -> [Network; N] {
    texts.map(|text| text.parse().expect("a network"))
}

fn addr(text: &str) -> IpAddr {
    text.parse().expect("an address")
}

/// A forwarder answering the clients `access` permits.
fn serving(access: Access) -> Pipeline {
    forwarder().with_access(access)
}

/// Whether the pipeline answers a query of the `a` capture from `from`: it goes upstream, or is replied to by a
/// stage, unlike a denied client's.
fn permitted(pipeline: &Pipeline, from: &str) -> bool {
    let query = wire(&query_for(&captured("a")));
    let mut out = vec![0; 65535];
    match pipeline.query(&query, Transport::Udp, addr(from), 0, &mut out) {
        Step::Upstream(_) => true,
        Step::Reply(len) => decode(&out[..len]).rcode() != Rcode::REFUSED,
        Step::Drop => false,
        step @ Step::Refresh(..) => unreachable!("{step:?}"),
    }
}

#[test]
fn a_denied_client_gets_refused_with_prohibited() {
    let pipeline = serving(Access::new(nets(["10.0.0.0/8"]), [], Denial::Refuse));
    let query = query_for(&captured("a"));
    let mut out = vec![0; 65535];
    let Step::Reply(len) = pipeline.query(
        &wire(&query),
        Transport::Udp,
        addr("192.0.2.1"),
        0,
        &mut out,
    ) else {
        unreachable!("a reply");
    };
    let reply = decode(&out[..len]);
    assert_eq!(reply.rcode(), Rcode::REFUSED);
    assert_eq!(reply.header.id, query.header.id);
    assert_eq!(reply.questions, query.questions);
    assert!(reply.header.flags.contains(Flags::QR));
    let options = reply.edns.expect("our OPT record").options;
    assert!(
        matches!(&options[..], [EdnsOption::Ede(e)] if e.code == InfoCode::PROHIBITED),
        "{options:?}"
    );
    assert!(permitted(&pipeline, "10.1.2.3"));
}

#[test]
fn a_denied_client_gets_nothing_when_the_action_is_drop() {
    let pipeline = serving(Access::new(nets(["10.0.0.0/8"]), [], Denial::Drop));
    assert!(!permitted(&pipeline, "192.0.2.1"));
    let mut out = vec![0; 65535];
    let query = wire(&query_for(&captured("a")));
    let step = pipeline.query(&query, Transport::Tcp, addr("192.0.2.1"), 0, &mut out);
    assert!(matches!(step, Step::Drop), "{step:?}");
    assert!(permitted(&pipeline, "10.1.2.3"));
}

#[test]
fn a_denied_response_or_stub_is_not_answered() {
    let pipeline = serving(Access::new([], [], Denial::Refuse));
    let mut out = vec![0; 65535];
    let from = addr("192.0.2.1");
    // A response is never answered, whatever its sender (RFC 1035 §4.1.1).
    let response = captured("a");
    let step = pipeline.query(&response, Transport::Udp, from, 0, &mut out);
    assert!(matches!(step, Step::Drop), "{step:?}");
    let query = wire(&query_for(&captured("a")));
    // Fewer bytes than a header cannot be answered either.
    let step = pipeline.query(&query[..11], Transport::Udp, from, 0, &mut out);
    assert!(matches!(step, Step::Drop), "{step:?}");
    // A header alone is a query that does not read, and is refused as it would be answered FORMERR.
    let Step::Reply(len) = pipeline.query(&query[..12], Transport::Udp, from, 0, &mut out) else {
        unreachable!("a reply");
    };
    let reply = decode(&out[..len]);
    assert_eq!(reply.rcode(), Rcode::REFUSED);
    assert_eq!(reply.header.id, decode(&query).header.id);
    assert_eq!(reply.questions.len(), 0);
}

#[test]
fn a_pipeline_without_access_answers_everyone() {
    let pipeline = Pipeline::default();
    let query = wire(&query_for(&captured("a")));
    let mut out = vec![0; 65535];
    let step = pipeline.query(&query, Transport::Udp, addr("192.0.2.1"), 0, &mut out);
    let Step::Reply(len) = step else {
        unreachable!("{step:?}");
    };
    // REFUSED as no stage answers, with no Prohibited.
    let reply = decode(&out[..len]);
    let options = reply.edns.map(|edns| edns.options).unwrap_or_default();
    assert!(
        !options
            .iter()
            .any(|o| matches!(o, EdnsOption::Ede(e) if e.code == InfoCode::PROHIBITED)),
        "{options:?}"
    );
}

#[test]
fn an_address_in_no_network_is_denied() {
    let access = Access::new(nets(["10.0.0.0/8", "2001:db8::/32"]), [], Denial::Refuse);
    assert!(access.permits(addr("10.255.255.255")));
    assert!(access.permits(addr("2001:db8::1")));
    assert!(!access.permits(addr("11.0.0.0")));
    assert!(!access.permits(addr("2001:db9::1")));
    assert!(!Access::new([], [], Denial::Refuse).permits(addr("10.0.0.1")));
}

#[test]
fn the_longest_network_holding_the_address_decides() {
    let access = Access::new(
        nets(["10.0.0.0/8", "10.9.9.0/24"]),
        nets(["10.9.0.0/16", "0.0.0.0/0"]),
        Denial::Refuse,
    );
    assert!(access.permits(addr("10.1.1.1")), "/8 beats /0");
    assert!(!access.permits(addr("10.9.1.1")), "/16 beats /8");
    assert!(access.permits(addr("10.9.9.9")), "/24 beats /16");
    assert!(!access.permits(addr("8.8.8.8")), "/0");
}

#[test]
fn deny_wins_a_tie() {
    let both = ["10.0.0.0/8", "::1/128"];
    let access = Access::new(nets(both), nets(both), Denial::Refuse);
    assert!(!access.permits(addr("10.1.1.1")));
    assert!(!access.permits(addr("::1")));
}

#[test]
fn an_ipv4_mapped_address_is_the_ipv4_one() {
    let access = Access::new(nets(["10.0.0.0/8"]), nets(["10.9.0.0/16"]), Denial::Refuse);
    assert!(access.permits(addr("::ffff:10.1.1.1")));
    assert!(!access.permits(addr("::ffff:10.9.1.1")));
    assert!(!access.permits(addr("::ffff:192.0.2.1")));
    // And an IPv6 network holds no IPv4 client.
    let access = Access::new(nets(["::/0"]), [], Denial::Refuse);
    assert!(access.permits(addr("2001:db8::1")));
    assert!(!access.permits(addr("192.0.2.1")));
    assert!(!access.permits(IpAddr::V4(Ipv4Addr::LOCALHOST)));
}

#[test]
fn by_default_loopback_private_and_link_local_networks_are_answered() {
    let access = Access::local(Denial::Refuse);
    for text in [
        "127.0.0.1",
        "127.255.255.255",
        "10.1.2.3",
        "172.16.0.1",
        "172.31.255.255",
        "192.168.1.1",
        "169.254.1.1",
        "::1",
        "fc00::1",
        "fd12:3456::1",
        "fe80::1",
        "::ffff:127.0.0.1",
    ] {
        assert!(access.permits(addr(text)), "{text}");
    }
    for text in [
        "0.0.0.0",
        "8.8.8.8",
        "172.15.255.255",
        "172.32.0.1",
        "192.0.2.1",
        "100.64.0.1",
        "::",
        "2001:db8::1",
        "fec0::1",
        "::ffff:8.8.8.8",
    ] {
        assert!(!access.permits(addr(text)), "{text}");
    }
}

#[test]
fn networks_have_no_bits_past_their_length() {
    for text in ["192.0.2.0/24", "0.0.0.0/0", "192.0.2.1/32", "2001:db8::/32"] {
        assert_eq!(
            text.parse::<Network>().expect("a network").to_string(),
            text
        );
    }
    let Err(NetworkError::HostBits { meant, .. }) = "192.0.2.1/24".parse::<Network>() else {
        unreachable!("bits set");
    };
    assert_eq!(meant.to_string(), "192.0.2.0/24");
    let error = "2001:db8::1/32".parse::<Network>().unwrap_err();
    assert!(error.to_string().contains("`2001:db8::/32`"), "{error}");
}

#[test]
fn text_that_is_no_network_is_refused() {
    for text in [
        "",
        "192.0.2.0",
        "192.0.2.0/33",
        "192.0.2.0/",
        "/24",
        "example.org/24",
        "::/129",
        "10.0.0.0/8 ",
    ] {
        assert_eq!(
            text.parse::<Network>(),
            Err(NetworkError::Malformed(text.to_owned())),
            "{text:?}"
        );
    }
}

#[test]
fn an_ipv6_network_starting_in_the_mapped_range_is_refused() {
    for text in ["::ffff:0:0/95", "::ffff:0:0/80", "::ffff:10.0.0.0/64"] {
        let error = text.parse::<Network>().unwrap_err();
        assert_eq!(error, NetworkError::MappedRange(text.to_owned()), "{text}");
        assert!(error.to_string().contains("::ffff:0:0/96"), "{error}");
    }
    // `::/0` starts outside it, and holds IPv6 clients only.
    assert!("::/0".parse::<Network>().is_ok());
}

#[test]
fn an_ipv4_network_written_as_ipv6_is_refused_for_the_ipv4_one() {
    let error = "::ffff:192.0.2.0/120".parse::<Network>().unwrap_err();
    assert!(
        matches!(&error, NetworkError::Mapped { meant, .. } if meant.to_string() == "192.0.2.0/24"),
        "{error}"
    );
    assert!(error.to_string().contains("`192.0.2.0/24`"), "{error}");
}
