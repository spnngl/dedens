//! The access lists of a zone (D211): who may transfer it (RFC 5936 §5), notify the server of it or update it, by
//! network and TSIG key (RFC 8945), nothing permitted by default.

use std::net::IpAddr;

use dedens_server::{Action, Authoritative, Grant, Network, ZoneAccess};
use dedens_testkit::dns;
use dedens_tsig::{Algorithm, Key};

use crate::authoritative::example;

fn key(name: &str, algorithm: Algorithm) -> Key {
    Key::new(
        dns(name),
        algorithm,
        b"a secret of thirty-two bytes....".to_vec(),
    )
    .expect("a key")
}

fn networks(texts: &[&str]) -> Vec<Network> {
    (texts.iter())
        .map(|text| text.parse().expect("a network"))
        .collect()
}

fn addr(text: &str) -> IpAddr {
    text.parse().expect("an address")
}

#[test]
fn rfc5936_s5_nothing_is_permitted_by_default() {
    let access = ZoneAccess::default();
    let signed = key("transfer.", Algorithm::HmacSha256);
    for action in [Action::Transfer, Action::Notify, Action::Update] {
        assert!(
            !access.permits(action, addr("192.0.2.1"), None),
            "{action:?}"
        );
        assert!(
            !access.permits(action, addr("::1"), Some(&signed)),
            "{action:?}"
        );
    }
}

#[test]
fn rfc9103_s9_4_a_line_without_a_key_permits_unsigned_requests_from_its_networks() {
    let open = Grant::new(networks(&["192.0.2.0/24", "2001:db8::/32"]), None);
    let access = ZoneAccess::default().with(Action::Transfer, [open]);
    assert!(access.permits(Action::Transfer, addr("192.0.2.7"), None));
    assert!(access.permits(Action::Transfer, addr("2001:db8::1"), None));
    // An IPv4-mapped IPv6 address is the IPv4 one.
    assert!(access.permits(Action::Transfer, addr("::ffff:192.0.2.7"), None));
    assert!(!access.permits(Action::Transfer, addr("198.51.100.1"), None));
    // A signed request is matched by its key alone: Knot's `check_addr_key` and NSD's `acl_key_matches` too.
    let signed = key("transfer.", Algorithm::HmacSha256);
    assert!(!access.permits(Action::Transfer, addr("192.0.2.7"), Some(&signed)));
    // The other lists are their own.
    assert!(!access.permits(Action::Notify, addr("192.0.2.7"), None));
    assert!(!access.permits(Action::Update, addr("192.0.2.7"), None));
}

#[test]
fn rfc8945_a_line_with_a_key_permits_only_requests_signed_with_it() {
    let signed = key("update.", Algorithm::HmacSha256);
    let grant = Grant::new(networks(&["0.0.0.0/0", "::/0"]), Some(&signed));
    let access = ZoneAccess::default().with(Action::Update, [grant]);
    assert!(access.permits(Action::Update, addr("198.51.100.1"), Some(&signed)));
    // Names compare without case.
    let upper = key("UPDATE.", Algorithm::HmacSha256);
    assert!(access.permits(Action::Update, addr("2001:db8::1"), Some(&upper)));
    assert!(!access.permits(Action::Update, addr("198.51.100.1"), None));
    let other = key("other.", Algorithm::HmacSha256);
    assert!(!access.permits(Action::Update, addr("198.51.100.1"), Some(&other)));
    // A key of the same name with another algorithm is another key (RFC 8945 §10).
    let algorithm = key("update.", Algorithm::HmacSha512);
    assert!(!access.permits(Action::Update, addr("198.51.100.1"), Some(&algorithm)));
}

#[test]
fn rfc1996_s5_a_keyed_line_holds_to_its_networks() {
    let signed = key("notify.", Algorithm::HmacSha256);
    let access = ZoneAccess::default().with(
        Action::Notify,
        [
            Grant::new(networks(&["10.0.0.0/8"]), Some(&signed)),
            Grant::new(networks(&["192.0.2.53/32"]), None),
        ],
    );
    assert!(access.permits(Action::Notify, addr("10.1.2.3"), Some(&signed)));
    assert!(!access.permits(Action::Notify, addr("192.0.2.53"), Some(&signed)));
    assert!(access.permits(Action::Notify, addr("192.0.2.53"), None));
    assert!(!access.permits(Action::Notify, addr("10.1.2.3"), None));
    // A line without a network matches no client.
    let none = ZoneAccess::default().with(Action::Notify, [Grant::new([], Some(&signed))]);
    assert!(!none.permits(Action::Notify, addr("10.1.2.3"), Some(&signed)));
}

#[test]
fn the_stage_holds_each_zones_lists() {
    let open = Grant::new(networks(&["192.0.2.0/24"]), None);
    let access = ZoneAccess::default().with(Action::Transfer, [open]);
    let stage = Authoritative::guarded([(example(), access)]).expect("one zone");
    let (zone, access) = stage.access(&dns("www.example.")).expect("in the zone");
    assert_eq!(zone.apex(), &dns("example."));
    assert!(access.permits(Action::Transfer, addr("192.0.2.1"), None));
    assert!(stage.access(&dns("example.org.")).is_none());
    let plain = Authoritative::new([example()]).expect("one zone");
    let (_, access) = plain.access(&dns("example.")).expect("in the zone");
    assert!(!access.permits(Action::Transfer, addr("192.0.2.1"), None));
}
