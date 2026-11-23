//! The access lists of a zone (D211): who may transfer it (RFC 5936 §5), notify the server of it or update it, by
//! network and TSIG key (RFC 8945), nothing permitted by default.

use std::net::IpAddr;
use std::sync::Arc;

use dedens_proto::{Message, Question, RecordType};
use dedens_server::{Action, Authoritative, Grant, Network, Pipeline, VerifiedKey, ZoneAccess};
use dedens_testkit::dns;
use dedens_tsig::{Algorithm, Key, Keyring, sign_request};

use crate::authoritative::example;
use crate::util::wire;

fn key(name: &str, algorithm: Algorithm) -> Key {
    Key::new(
        dns(name),
        algorithm,
        b"a secret of thirty-two bytes....".to_vec(),
    )
    .expect("a key")
}

/// When the requests are signed and verified.
const NOW: u64 = 1_750_000_000;

/// A key, and a pipeline holding it that verifies requests with it, its clock at [`NOW`].
struct Peer {
    key: Key,
    pipeline: Pipeline,
}

impl Peer {
    fn new(name: &str, algorithm: Algorithm) -> Self {
        let key = key(name, algorithm);
        let pipeline = holding(&key, NOW);
        Self { key, pipeline }
    }

    /// A request signed with this peer's key at [`NOW`].
    fn request(&self) -> Vec<u8> {
        let mut request = wire(&Message::query(
            7,
            Question::new(dns("example."), RecordType::SOA),
        ));
        sign_request(&self.key, &mut request, NOW).expect("signed");
        request
    }

    /// The key of a request this peer signs, verified: the one way to get a [`VerifiedKey`].
    fn verified(&self) -> VerifiedKey<'_> {
        let request = self.request();
        self.pipeline.verified_key(&request).expect("verified")
    }
}

/// A pipeline holding `key`, its clock at `now`.
fn holding(key: &Key, now: u64) -> Pipeline {
    let ring = Keyring::new([key.clone()]).expect("one key");
    Pipeline::new(Vec::new()).with_keys(ring, Arc::new(move || now))
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
    let peer = Peer::new("transfer.", Algorithm::HmacSha256);
    for action in [Action::Transfer, Action::Notify, Action::Update] {
        assert!(
            !access.permits(action, addr("192.0.2.1"), None),
            "{action:?}"
        );
        assert!(
            !access.permits(action, addr("::1"), Some(peer.verified())),
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
    let peer = Peer::new("transfer.", Algorithm::HmacSha256);
    assert!(!access.permits(Action::Transfer, addr("192.0.2.7"), Some(peer.verified())));
    // The other lists are their own.
    assert!(!access.permits(Action::Notify, addr("192.0.2.7"), None));
    assert!(!access.permits(Action::Update, addr("192.0.2.7"), None));
}

#[test]
fn rfc8945_a_line_with_a_key_permits_only_requests_signed_with_it() {
    let peer = Peer::new("update.", Algorithm::HmacSha256);
    let grant = Grant::new(networks(&["0.0.0.0/0", "::/0"]), Some(&peer.key));
    let access = ZoneAccess::default().with(Action::Update, [grant]);
    let from = addr("198.51.100.1");
    assert!(access.permits(Action::Update, from, Some(peer.verified())));
    // Names compare without case.
    let upper = Peer::new("UPDATE.", Algorithm::HmacSha256);
    assert!(access.permits(Action::Update, addr("2001:db8::1"), Some(upper.verified())));
    assert!(!access.permits(Action::Update, from, None));
    let other = Peer::new("other.", Algorithm::HmacSha256);
    assert!(!access.permits(Action::Update, from, Some(other.verified())));
    // A key of the same name with another algorithm is another key (RFC 8945 §10).
    let algorithm = Peer::new("update.", Algorithm::HmacSha512);
    assert!(!access.permits(Action::Update, from, Some(algorithm.verified())));
}

#[test]
fn rfc1996_s5_a_keyed_line_holds_to_its_networks() {
    let peer = Peer::new("notify.", Algorithm::HmacSha256);
    let access = ZoneAccess::default().with(
        Action::Notify,
        [
            Grant::new(networks(&["10.0.0.0/8"]), Some(&peer.key)),
            Grant::new(networks(&["192.0.2.53/32"]), None),
        ],
    );
    assert!(access.permits(Action::Notify, addr("10.1.2.3"), Some(peer.verified())));
    assert!(!access.permits(Action::Notify, addr("192.0.2.53"), Some(peer.verified())));
    assert!(access.permits(Action::Notify, addr("192.0.2.53"), None));
    assert!(!access.permits(Action::Notify, addr("10.1.2.3"), None));
    // A line without a network matches no client.
    let none = ZoneAccess::default().with(Action::Notify, [Grant::new([], Some(&peer.key))]);
    assert!(!none.permits(Action::Notify, addr("10.1.2.3"), Some(peer.verified())));
}

/// RFC 8945 §5.2: a request that is unsigned, or whose MAC does not verify, makes no key to ask the lists with.
#[test]
fn rfc8945_s5_2_only_a_verified_request_makes_a_key() {
    let peer = Peer::new("update.", Algorithm::HmacSha256);
    let query = wire(&Message::query(
        7,
        Question::new(dns("example."), RecordType::SOA),
    ));
    assert!(peer.pipeline.verified_key(&query).is_none());
    let request = peer.request();
    let verified = peer.pipeline.verified_key(&request);
    assert_eq!(verified.map(|key| key.key().name()), Some(peer.key.name()));
    // A time outside the fudge by the pipeline's own clock, a key of another keyring, no keyring at all.
    assert!(
        holding(&peer.key, NOW + 1000)
            .verified_key(&request)
            .is_none()
    );
    let other = Peer::new("other.", Algorithm::HmacSha256);
    assert!(other.pipeline.verified_key(&request).is_none());
    assert!(Pipeline::new(Vec::new()).verified_key(&request).is_none());
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
