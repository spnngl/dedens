//! Answers for top-level domains no upstream server need be asked about (D128): special-use names (RFC 6761 §6,
//! RFC 6762 §22.1, RFC 7686 §2) and TLDs that are not in the root zone.

use std::net::{Ipv4Addr, Ipv6Addr};
use std::sync::Arc;

use dedens_proto::edns::EdnsFlags;
use dedens_proto::rdata::RData;
use dedens_proto::{Class, Name, Query, Rcode, Record, RecordType, Ttl};
use dedens_roots::{Status, Tlds};
use dedens_server::{Answer, Plugin, Records};

/// What the stage does with a special-use TLD and the names below it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Use {
    /// A and AAAA queries answered with the loopback addresses, other types with no data (RFC 6761 §6.3).
    Loopback,
    /// NXDOMAIN, DO or not: the name is never resolved through the DNS.
    Nxdomain,
    /// As any TLD: the RFC asks caching servers not to treat it as special, or none applies to it.
    Ordinary,
}

/// The special-use TLDs (IANA's special-use domain names registry, RFC 6761 §4) and what each RFC asks of a caching
/// server, item 4 of its considerations.
pub const SPECIAL: [(&str, Use); 9] = [
    // RFC 6761 §6.3: "MAY recognize localhost names as special and SHOULD NOT attempt to look up NS records for
    // them" (item 4); the loopback addresses, for the name and its subnames (item 3).
    ("localhost", Use::Loopback),
    // RFC 6761 §6.4: "SHOULD recognize "invalid" names as special and SHOULD NOT attempt to look up NS records for
    // them, or otherwise query authoritative DNS servers", "immediately return NXDOMAIN".
    ("invalid", Use::Nxdomain),
    // RFC 6761 §6.2: "SHOULD recognize test names as special and SHOULD NOT, by default, attempt to look up NS records
    // for them", "generate immediate negative responses".
    ("test", Use::Nxdomain),
    // RFC 6762 §22.1: "SHOULD recognize these names as special and SHOULD NOT send queries for these names to their
    // configured (unicast) caching DNS server(s)", "generate immediate NXDOMAIN".
    ("local", Use::Nxdomain),
    // RFC 7686 §2: "MUST NOT attempt to look up NS records for them, or otherwise query authoritative DNS servers",
    // "MUST generate NXDOMAIN".
    ("onion", Use::Nxdomain),
    // RFC 6761 §6.5: "SHOULD NOT recognize example names as special and SHOULD resolve them normally".
    ("example", Use::Ordinary),
    // RFC 9476 §2: "SHOULD NOT recognize .alt names as special and SHOULD NOT perform any special handling".
    ("alt", Use::Ordinary),
    // No RFC: ICANN reserved it for private use (2024); a name of one's own network comes from a stage before this
    // one, as a hosts stage, and the root answers NXDOMAIN for the others.
    ("internal", Use::Ordinary),
    // RFC 3172: the infrastructure domain, delegated in the root zone.
    ("arpa", Use::Ordinary),
];

/// The use of `label`, a TLD, from [`SPECIAL`]; `None` when it is not there.
#[must_use]
pub fn special(label: &[u8]) -> Option<Use> {
    SPECIAL
        .iter()
        .find(|(name, _)| name.as_bytes().eq_ignore_ascii_case(label))
        .map(|&(_, then)| then)
}

/// The `tlds` stage (D128): answers, with no upstream query, the names of [`SPECIAL`] TLDs as their RFCs say and the
/// names of TLDs that are not in the root zone.
///
/// A TLD is in the root zone when the list holds it as [`Status::Active`]. Below one that is not, a query without DO
/// is answered NXDOMAIN; one with DO goes on: no proof could come with the denial, which a validating client would
/// take for bogus. The NXDOMAIN of this stage carry no SOA (RFC 2308 §5): no cache downstream keeps them. AA is set
/// on the loopback answers, the server's own data, clear on the NXDOMAIN. The root, other classes and other names
/// go to the next stage.
#[derive(Debug)]
pub struct TopLevel {
    tlds: Arc<Tlds>,
    a: Records,
    aaaa: Records,
    counted: Counted,
}

impl TopLevel {
    /// The stage of `tlds`, its loopback records with `ttl`.
    ///
    /// # Panics
    ///
    /// Never: one address record fits a message.
    #[must_use]
    pub fn new(tlds: Arc<Tlds>, ttl: Ttl) -> Self {
        let localhost: Name<'static> = "localhost.".parse().expect("a name");
        let records = |data: RData<'static>| {
            Records::new(
                &localhost,
                &[Record::new(localhost.clone(), Class::IN, ttl, &data)],
            )
            .expect("one record fits a message")
        };
        Self {
            tlds,
            a: records(RData::A(Ipv4Addr::LOCALHOST)),
            aaaa: records(RData::Aaaa(Ipv6Addr::LOCALHOST)),
            counted: Counted::new(),
        }
    }

    /// The TLDs it answers from.
    #[must_use]
    pub fn tlds(&self) -> &Arc<Tlds> {
        &self.tlds
    }

    fn loopback(&self, qtype: RecordType) -> Answer<'_> {
        let records = match qtype {
            // One RRset of the name (RFC 8482 §4.1), as the hosts stage answers.
            RecordType::A | RecordType::ANY => Some(&self.a),
            RecordType::AAAA => Some(&self.aaaa),
            _ => None,
        };
        Answer {
            rcode: Rcode::NOERROR,
            records,
            authoritative: true,
            error: None,
        }
    }
}

/// NXDOMAIN, with no SOA and AA clear: the stage holds no zone.
const NXDOMAIN: Answer<'static> = Answer {
    rcode: Rcode::NXDOMAIN,
    records: None,
    authoritative: false,
    error: None,
};

impl Plugin for TopLevel {
    fn answer(&self, query: &Query<'_>) -> Option<Answer<'_>> {
        let question = query.question()?;
        if question.qclass != Class::IN {
            return None;
        }
        let label = question.name.labels().last()?;
        match special(label) {
            Some(Use::Loopback) => {
                self.counted.special_use();
                return Some(self.loopback(question.qtype));
            }
            Some(Use::Nxdomain) => {
                self.counted.special_use();
                return Some(NXDOMAIN);
            }
            Some(Use::Ordinary) | None => {}
        }
        let delegated = self
            .tlds
            .get(&question.name)
            .is_some_and(|tld| tld.status() == Status::Active);
        let signed = query
            .edns()
            .is_some_and(|edns| edns.flags.contains(EdnsFlags::DO));
        if delegated || signed {
            return None;
        }
        self.counted.unknown();
        Some(NXDOMAIN)
    }
}

/// The counters of `dedensd_tlds_answers_total{kind}`: queries answered by the stage, `special_use` from [`SPECIAL`],
/// `unknown` for a TLD not in the root zone.
#[cfg(feature = "metrics")]
#[derive(Debug)]
struct Counted {
    special_use: metrics::Counter,
    unknown: metrics::Counter,
}

/// The counters of answers: none without the `metrics` feature.
#[cfg(not(feature = "metrics"))]
#[derive(Debug)]
struct Counted;

#[cfg(feature = "metrics")]
impl Counted {
    fn new() -> Self {
        const ANSWERS: &str = "dedensd_tlds_answers_total";
        metrics::describe_counter!(
            ANSWERS,
            "Queries the tlds stage answered, by kind: special_use or unknown (a TLD not in the root zone)."
        );
        Self {
            special_use: metrics::counter!(ANSWERS, "kind" => "special_use"),
            unknown: metrics::counter!(ANSWERS, "kind" => "unknown"),
        }
    }

    fn special_use(&self) {
        self.special_use.increment(1);
    }

    fn unknown(&self) {
        self.unknown.increment(1);
    }
}

#[cfg(not(feature = "metrics"))]
#[expect(
    clippy::unused_self,
    reason = "the same calls with and without the feature"
)]
impl Counted {
    const fn new() -> Self {
        Self
    }

    const fn special_use(&self) {}

    const fn unknown(&self) {}
}
