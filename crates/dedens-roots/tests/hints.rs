//! Root hints, the configured list of root servers a resolver primes from: RFC 8109 (priming) §2, RFC 1034 §5.3.3
//! (SBELT). The bundled `src/named.root`, and copies of it cut or changed by line.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use dedens_proto::{Name, RecordType};
use dedens_roots::{HintsError, RootHints};

const NAMED_ROOT: &str = include_str!("../src/named.root");

// --- RFC 8109 §2 ---

#[test]
fn s2_the_bundled_hints_hold_13_root_servers_each_with_ipv4_and_ipv6() {
    let servers = RootHints::bundled().servers();
    let names: Vec<String> = servers
        .iter()
        .map(|server| server.name().to_string())
        .collect();
    let expected: Vec<String> = ('A'..='M')
        .map(|letter| format!("{letter}.ROOT-SERVERS.NET."))
        .collect();
    assert_eq!(names, expected);
    for server in servers {
        assert_eq!(
            (server.ipv4().len(), server.ipv6().len()),
            (1, 1),
            "{}",
            server.name()
        );
    }
    let a = servers.first().expect("a root server");
    assert_eq!(
        a.addresses().collect::<Vec<_>>(),
        [
            IpAddr::V4(Ipv4Addr::new(198, 41, 0, 4)),
            IpAddr::V6(Ipv6Addr::new(0x2001, 0x503, 0xba3e, 0, 0, 0, 2, 0x30)),
        ]
    );
}

#[test]
fn s2_a_server_name_matches_its_addresses_whatever_the_case() {
    let lower = NAMED_ROOT.replace(
        "A.ROOT-SERVERS.NET.      3600000      A ",
        "a.root-servers.net. 3600000 A ",
    );
    let hints = RootHints::read(lower.as_bytes()).expect("hints");
    let a = hints.servers().first().expect("a root server");
    assert_eq!(
        a.name(),
        &"a.root-servers.net.".parse::<Name<'_>>().expect("a name")
    );
    assert_eq!(a.ipv4().len(), 1);
}

#[test]
fn s2_a_copy_with_only_ns_records_has_nowhere_to_prime_from() {
    let ns: String = NAMED_ROOT
        .lines()
        .filter(|line| line.contains(" NS "))
        .flat_map(|line| [line, "\n"])
        .collect();
    assert_eq!(RootHints::read(ns.as_bytes()), Err(HintsError::Empty));
    assert_eq!(RootHints::read(b""), Err(HintsError::Empty));
}

#[test]
fn s2_a_copy_with_another_record_or_an_include_is_refused() {
    let mx = format!("{NAMED_ROOT}\n. 3600000 MX 10 A.ROOT-SERVERS.NET.\n");
    let line = mx.lines().count();
    assert_eq!(
        RootHints::read(mx.as_bytes()),
        Err(HintsError::Unexpected {
            line,
            rtype: RecordType::MX
        })
    );
    let below = NAMED_ROOT.replacen(
        ".                        3600000      NS",
        "net. 3600000 NS",
        1,
    );
    assert!(matches!(
        RootHints::read(below.as_bytes()),
        Err(HintsError::Unexpected {
            rtype: RecordType::NS,
            ..
        })
    ));
    let include = format!("$INCLUDE other.root\n{NAMED_ROOT}");
    assert!(matches!(
        RootHints::read(include.as_bytes()),
        Err(HintsError::NotARecord { .. })
    ));
    assert!(matches!(
        RootHints::read(b". 3600000 NS"),
        Err(HintsError::Text(_))
    ));
}
