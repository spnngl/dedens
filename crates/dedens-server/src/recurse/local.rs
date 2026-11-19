//! The zones a recursive resolver answers itself, sending no query for them (D195): the reverse zones of private,
//! special and documentation addresses (RFC 6303 §4), `home.arpa` (RFC 8375 §4), `resolver.arpa` (RFC 9462 §6.4),
//! `localhost` and `invalid` (RFC 6761 §6.3, §6.4).

use std::net::{Ipv4Addr, Ipv6Addr};

use dedens_proto::rdata::{RData, Soa};
use dedens_proto::{Class, Message, Name, Question, Rcode, Record, RecordType, Ttl};

/// What a locally served zone answers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Local {
    /// The empty zone of RFC 6303 §3: its SOA and NS at the apex, no data there otherwise, no name below.
    Empty,
    /// As [`Local::Empty`], every name below existing without data: RFC 9462 §6.4 answers NODATA for any name
    /// under `resolver.arpa`, this resolver having no Designated Resolver to name (§4).
    NoData,
    /// The loopback address for A and AAAA, at the name and below, no data of another type (RFC 6761 §6.3 item 4).
    Loopback,
    /// No name, the apex included (RFC 6761 §6.4 item 4): NXDOMAIN, without a SOA, as `invalid` is no zone.
    Nxdomain,
}

/// The zones served locally by default, by RFC: each may be resolved instead (RFC 6303 §3 asks for the switch).
pub(super) const ZONES: [(&str, Local); 37] = [
    // RFC 6303 §4.1: RFC 1918's private addresses.
    ("10.in-addr.arpa", Local::Empty),
    ("16.172.in-addr.arpa", Local::Empty),
    ("17.172.in-addr.arpa", Local::Empty),
    ("18.172.in-addr.arpa", Local::Empty),
    ("19.172.in-addr.arpa", Local::Empty),
    ("20.172.in-addr.arpa", Local::Empty),
    ("21.172.in-addr.arpa", Local::Empty),
    ("22.172.in-addr.arpa", Local::Empty),
    ("23.172.in-addr.arpa", Local::Empty),
    ("24.172.in-addr.arpa", Local::Empty),
    ("25.172.in-addr.arpa", Local::Empty),
    ("26.172.in-addr.arpa", Local::Empty),
    ("27.172.in-addr.arpa", Local::Empty),
    ("28.172.in-addr.arpa", Local::Empty),
    ("29.172.in-addr.arpa", Local::Empty),
    ("30.172.in-addr.arpa", Local::Empty),
    ("31.172.in-addr.arpa", Local::Empty),
    ("168.192.in-addr.arpa", Local::Empty),
    // RFC 6303 §4.2: "this" network, loopback, link local, the documentation networks, broadcast.
    ("0.in-addr.arpa", Local::Empty),
    ("127.in-addr.arpa", Local::Empty),
    ("254.169.in-addr.arpa", Local::Empty),
    ("2.0.192.in-addr.arpa", Local::Empty),
    ("100.51.198.in-addr.arpa", Local::Empty),
    ("113.0.203.in-addr.arpa", Local::Empty),
    ("255.255.255.255.in-addr.arpa", Local::Empty),
    // RFC 6303 §4.3: the unspecified address and loopback; the 32 nibbles of each.
    (
        "0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.ip6.arpa",
        Local::Empty,
    ),
    (
        "1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.ip6.arpa",
        Local::Empty,
    ),
    // RFC 6303 §4.4, §4.5, §4.6: unique local, link local and documentation addresses.
    ("d.f.ip6.arpa", Local::Empty),
    ("8.e.f.ip6.arpa", Local::Empty),
    ("9.e.f.ip6.arpa", Local::Empty),
    ("a.e.f.ip6.arpa", Local::Empty),
    ("b.e.f.ip6.arpa", Local::Empty),
    ("8.b.d.0.1.0.0.2.ip6.arpa", Local::Empty),
    // RFC 8375 §4 item 4.B: `home.arpa` per RFC 6303 §3. RFC 9462 §6.4: `resolver.arpa`.
    ("home.arpa", Local::Empty),
    ("resolver.arpa", Local::NoData),
    // RFC 6761 §6.3, §6.4.
    ("localhost", Local::Loopback),
    ("invalid", Local::Nxdomain),
];

/// The TTL of every record of a locally served zone, and the SOA's MINIMUM: RFC 6303 §3's zone file.
const TTL: u32 = 10800;

/// The zones served locally, and what each answers.
#[derive(Debug, Clone)]
pub(super) struct LocalZones(Box<[(Name<'static>, Local)]>);

impl Default for LocalZones {
    /// Every zone of [`ZONES`].
    fn default() -> Self {
        Self(
            ZONES
                .iter()
                .map(|&(zone, local)| (zone.parse().expect("a zone of the list parses"), local))
                .collect(),
        )
    }
}

impl LocalZones {
    /// The zones without `zone`, resolved instead; `None` when `zone` is not served locally.
    pub(super) fn without(&self, zone: &Name<'_>) -> Option<Self> {
        let at = self.0.iter().position(|(held, _)| held == zone)?;
        let mut zones = self.0.to_vec();
        zones.remove(at);
        Some(Self(zones.into()))
    }

    /// The answer to `question`, as its zone serves it, if a zone of these holds it: its rcode, and its answer and
    /// authority sections in a message. A DS question at a zone's apex is its parent's (RFC 4035 §3.1.4.1), and RFC 8375 §4 item
    /// 4.B asks that it be resolved, so that a validator below proves the zone unsigned.
    pub(super) fn answer(&self, question: &Question<'_>) -> Option<(Rcode, Message<'static>)> {
        let (zone, local) = self
            .0
            .iter()
            .find(|(zone, _)| question.name.is_within(zone))?;
        let apex = question.name == *zone;
        if apex && question.qtype == RecordType::DS && *local != Local::Nxdomain {
            return None;
        }
        let ttl = Ttl::from_wire(TTL);
        let soa = || {
            let soa = Soa {
                mname: zone.clone(),
                rname: "nobody.invalid".parse().expect("the name parses"),
                serial: 1,
                refresh: 3600,
                retry: 1200,
                expire: 604_800,
                minimum: TTL,
            };
            Record::new(zone.clone(), Class::IN, ttl, &RData::Soa(soa))
        };
        let owned = question.name.clone().into_owned();
        let mut message = Message::default();
        let mut rcode = Rcode::NOERROR;
        let data = match (local, question.qtype) {
            (Local::Nxdomain, _) => return Some((Rcode::NXDOMAIN, message)),
            (Local::Loopback, RecordType::A) => Some(RData::A(Ipv4Addr::LOCALHOST)),
            (Local::Loopback, RecordType::AAAA) => Some(RData::Aaaa(Ipv6Addr::LOCALHOST)),
            (Local::Empty | Local::NoData, RecordType::SOA) if apex => {
                message.answer.push(soa());
                None
            }
            (Local::Empty | Local::NoData, RecordType::NS) if apex => Some(RData::Ns(zone.clone())),
            (Local::Empty, _) if !apex => {
                rcode = Rcode::NXDOMAIN;
                None
            }
            _ => None,
        };
        match data {
            Some(data) => message
                .answer
                .push(Record::new(owned, Class::IN, ttl, &data)),
            None if message.answer.is_empty() => message.authority.push(soa()),
            None => {}
        }
        Some((rcode, message))
    }
}
