//! The authoritative stage (D208): the zones this server is the authority for, each answered from its
//! [`Zone`] (D206), with its access lists (D211).

use std::fmt;
use std::net::IpAddr;
use std::sync::Arc;

use dedens_proto::edns::InfoCode;
use dedens_proto::rdata::RData;
use dedens_proto::{
    Class, MAX_NAME_LEN, Message, Name, Query, Question, Rcode, RecordType, Serial, Transport,
};
use dedens_zone::Zone;

use crate::Step;
use crate::metrics::Answers;
use crate::reply::Client;
use crate::transfer::{History, Transfer};
use crate::zone_access::{Action, ZoneAccess};

/// The zones a server is the authority for, found by the longest apex a name is at or below (RFC 1034 §4.3.2
/// step 2). Each is shared: a reload keeps the zones whose files did not change, and swaps in the others whole
/// (D204, D208).
#[derive(Clone)]
pub struct Authoritative {
    /// Sorted by apex in canonical order (RFC 4034 §6.1), no apex twice.
    zones: Box<[Arc<Zone>]>,
    /// The access lists of the zone at the same index of `zones`.
    access: Box<[ZoneAccess]>,
    /// The changes that led to the zone at the same index of `zones`, IXFR's answers (D214).
    histories: Box<[History]>,
    answers: Answers,
}

/// Two zones of [`Authoritative::new`] have the same apex: which answers would be a guess.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("zone `{0}` is given twice")]
pub struct Duplicate(pub Name<'static>);

impl Authoritative {
    /// The stage answering from `zones`.
    ///
    /// # Errors
    ///
    /// [`Duplicate`] when two zones have the same apex, whatever their class.
    pub fn new(zones: impl IntoIterator<Item = Arc<Zone>>) -> Result<Self, Duplicate> {
        Self::guarded(zones.into_iter().map(|zone| (zone, ZoneAccess::default())))
    }

    /// The stage answering from `zones`, each with its access lists: what it permits of transfers, NOTIFY and
    /// UPDATE (D211). [`Authoritative::new`] permits nothing.
    ///
    /// # Errors
    ///
    /// [`Duplicate`] when two zones have the same apex, whatever their class.
    pub fn guarded(
        zones: impl IntoIterator<Item = (Arc<Zone>, ZoneAccess)>,
    ) -> Result<Self, Duplicate> {
        let mut zones: Vec<_> = zones.into_iter().collect();
        zones.sort_by(|(a, _), (b, _)| a.apex().cmp(b.apex()));
        if let Some(pair) = zones
            .windows(2)
            .find(|pair| pair[0].0.apex() == pair[1].0.apex())
        {
            return Err(Duplicate(pair[0].0.apex().clone()));
        }
        let (zones, access): (Vec<_>, Vec<_>) = zones.into_iter().unzip();
        Ok(Self {
            histories: vec![History::default(); zones.len()].into(),
            zones: zones.into(),
            access: access.into(),
            answers: Answers::new(),
        })
    }

    /// The same stage, the zone of apex `apex` with `history`, the changes that led to its version, IXFR's answers
    /// (D214); unchanged when no zone has that apex. A history that does not end at the zone's serial answers
    /// nothing.
    #[must_use]
    pub fn with_history(mut self, apex: &Name<'_>, history: History) -> Self {
        if let Some(index) = self.apex(apex) {
            self.histories[index] = history;
        }
        self
    }

    /// The index in `zones` of the zone of apex `apex`.
    fn apex(&self, apex: &Name<'_>) -> Option<usize> {
        self.index(apex)
            .filter(|&index| self.zones[index].apex() == apex)
    }

    /// The zones, sorted by apex in canonical order.
    #[must_use]
    pub fn zones(&self) -> &[Arc<Zone>] {
        &self.zones
    }

    /// The zone whose apex is the longest `name` is at or below, if any. Allocates nothing; a binary search for
    /// each label `name` shares with the zone just before it in canonical order, at most.
    #[must_use]
    pub fn zone(&self, name: &Name<'_>) -> Option<&Arc<Zone>> {
        self.index(name).map(|index| &self.zones[index])
    }

    /// [`Authoritative::zone`] of `name`, with its access lists (D211): what a transfer, NOTIFY or UPDATE of the
    /// zone asks.
    #[must_use]
    pub fn access(&self, name: &Name<'_>) -> Option<(&Arc<Zone>, &ZoneAccess)> {
        self.index(name)
            .map(|index| (&self.zones[index], &self.access[index]))
    }

    /// The index in `zones` of [`Authoritative::zone`] of `name`.
    fn index(&self, name: &Name<'_>) -> Option<usize> {
        let mut buf = [0; MAX_NAME_LEN];
        self.find(name.to_wire(&mut buf), name.label_count())
    }

    /// [`Authoritative::index`] of the name `wire`, uncompressed, of `count` labels.
    fn find(&self, wire: &[u8], count: usize) -> Option<usize> {
        let mut labels = count;
        let mut end = self.zones.len();
        loop {
            // The suffix of `labels` labels of the name: names within an apex follow it in canonical order with
            // no other name between, so the zone just before the suffix holds it, or the apex it shares with that
            // zone's is the longest that can.
            let suffix = Name::from_uncompressed(skip_labels(wire, count - labels)).ok()?;
            end = self.zones[..end].partition_point(|zone| *zone.apex() <= suffix);
            let before = self.zones[..end].last()?;
            if suffix.is_within(before.apex()) {
                return Some(end - 1);
            }
            labels = suffix.shared_labels(before.apex());
        }
    }

    /// The zone that answers `question`: [`Authoritative::zone`] of its name, but for a DS, which the parent
    /// zone holds (RFC 4035 §3.1.4.1): the zone of the name's parent when there is one, else the name's own. Knot
    /// and NSD search the zone for a DS the same way (`process_query.c:186-201`, `query.c:1497-1535`).
    fn zone_of(&self, question: &Question<'_>) -> Option<&Arc<Zone>> {
        let mut buf = [0; MAX_NAME_LEN];
        let wire = question.name.to_wire(&mut buf);
        let count = question.name.label_count();
        if question.qtype == RecordType::DS
            && count > 0
            && let Some(index) = self.find(skip_labels(wire, 1), count - 1)
        {
            return Some(&self.zones[index]);
        }
        self.find(wire, count).map(|index| &self.zones[index])
    }

    /// The reply to `client`, written into `out`, when a zone answers its question; `None` passes the query on.
    ///
    /// The zone answers, AA set (RFC 1034 §4.3.2), whatever RD says: a referral too, without AA, as Knot and NSD
    /// answer it; the name is never resolved from the zone's cut (D208). Only a name of another class than the
    /// zone's passes on: the zone refuses any other name it is not the authority for.
    pub(crate) fn reply(&self, client: &Client<'_>, out: &mut [u8]) -> Option<Step> {
        let question = client.question.as_ref()?;
        let zone = self.zone_of(question)?;
        if question.qclass != zone.class() && question.qclass != Class::ANY {
            return None;
        }
        let answer = zone.answer(question);
        self.answers.count(&answer.end);
        Some(
            client
                .zone(zone, &answer, out)
                .map_or(Step::Drop, Step::Reply),
        )
    }
}

impl Authoritative {
    /// The answer to `query`, an AXFR or IXFR from `client` at `from`, when a zone has its name as apex and its
    /// class (RFC 5936 §2.2, RFC 1995 §3); `None` passes it on (D214).
    ///
    /// The zone's access list decides first: REFUSED with EDE 18 (Prohibited) to a client it does not permit (D211).
    /// Over TCP and TLS the transfer is a [`Step::Transfer`]. An IXFR from a client whose serial is not behind
    /// the zone's, or over UDP, gets the SOA alone (RFC 1995 §2, §4; Knot's `ixfr_process_query`, BIND's
    /// `xfrout.c`); the changes since the client's serial, condensed (§6), when the history has them, else the
    /// zone whole. An IXFR without the client's SOA in its authority section is FORMERR (§3). An AXFR over UDP
    /// (RFC 5936 §4.2), and either over a transport other than TCP and TLS (RFC 9103 §7.8, D214), is REFUSED
    /// with EDE 21 (Not Supported).
    pub(crate) fn transfer(
        &self,
        query: &Query<'_>,
        client: &Client<'_>,
        from: IpAddr,
        out: &mut [u8],
    ) -> Option<Step> {
        let question = client.question.as_ref()?;
        let index = self
            .apex(&question.name)
            .filter(|&index| self.zones[index].class() == question.qclass)?;
        let zone = &self.zones[index];
        let replied = |len: Option<usize>| Some(len.map_or(Step::Drop, Step::Reply));
        let ixfr = question.qtype == RecordType::IXFR;
        let stream = matches!(client.transport, Transport::Tcp | Transport::Tls);
        let carried = stream || ixfr && client.transport == Transport::Udp;
        let refusal = if !self.access[index].permits(Action::Transfer, from, client.key()) {
            Some(InfoCode::PROHIBITED)
        } else if !carried {
            Some(InfoCode::NOT_SUPPORTED)
        } else {
            None
        };
        if let Some(error) = refusal {
            return replied(client.reply(Message::default(), Rcode::REFUSED, Some(error), out));
        }
        let changes = if ixfr {
            let Some(serial) = client_serial(query) else {
                return replied(client.reply(Message::default(), Rcode::FORMERR, None, out));
            };
            let current = Serial::new(zone.soa().serial);
            let behind = serial < current;
            if !stream || !behind {
                let message = Message {
                    answer: vec![zone.soa_record()],
                    ..Message::default()
                };
                return replied(client.authoritative(message, Rcode::NOERROR, out));
            }
            self.histories[index].since(serial, current)
        } else {
            None
        };
        let request = (client.header, question.clone().into_owned());
        let transfer = Transfer::new(Arc::clone(zone), changes, request, client.opt(None));
        Some(Step::Transfer(Box::new(transfer)))
    }
}

/// The serial of the client's SOA in the authority section of `query`, an IXFR (RFC 1995 §3).
fn client_serial(query: &Query<'_>) -> Option<Serial> {
    let decoded = Message::decode(query.wire()).ok()?;
    decoded
        .message
        .authority
        .iter()
        .find_map(|record| match record.data() {
            RData::Soa(soa) => Some(Serial::new(soa.serial)),
            _ => None,
        })
}

/// `wire`, an uncompressed name, past its first `count` labels.
fn skip_labels(wire: &[u8], count: usize) -> &[u8] {
    let mut at = 0;
    for _ in 0..count {
        at += 1 + usize::from(wire[at]);
    }
    &wire[at..]
}

impl fmt::Debug for Authoritative {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Authoritative")
            .field(
                "zones",
                &self
                    .zones
                    .iter()
                    .map(|zone| zone.apex())
                    .collect::<Vec<_>>(),
            )
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    use dedens_proto::Ttl;
    use dedens_zone::{Limits, Source};

    use super::*;

    /// The zone of RFC 1035 §5.3 with `apex` as its origin, whatever it names: only the apex matters here.
    fn zone(apex: &str) -> Arc<Zone> {
        let text = std::fs::read(dedens_testkit::path("zones/rfc1035_isi.zone")).expect("the file");
        let source = Source {
            name: apex,
            text: &text,
            default_ttl: Some(Ttl::from_wire(3600)),
        };
        let mut include = |_: &str| {
            std::fs::read(dedens_testkit::path("zones/rfc1035_isi_mailboxes.zone"))
                .map_err(|e| e.to_string())
        };
        let origin = apex.parse().expect("a name");
        let loaded = Zone::load(origin, source, &mut include, &Limits::default());
        Arc::new(loaded.expect("a zone").zone)
    }

    fn found(stage: &Authoritative, name: &str) -> Option<String> {
        stage
            .zone(&name.parse().expect("a name"))
            .map(|zone| zone.apex().to_string())
    }

    #[test]
    fn the_longest_apex_answers() {
        let stage =
            Authoritative::new(["example.", "a.example.", "b.c.example.", "org.", "."].map(zone))
                .expect("no apex twice");
        let cases = [
            ("example.", "example."),
            ("www.example.", "example."),
            ("x.a.example.", "a.example."),
            ("A.EXAMPLE.", "a.example."),
            // `c.example` is no apex: the walk goes back up past `b.c.example`.
            ("z.c.example.", "example."),
            ("x.b.c.example.", "b.c.example."),
            ("zz.example.", "example."),
            ("net.", "."),
            ("www.org.", "org."),
        ];
        for (name, apex) in cases {
            assert_eq!(found(&stage, name).as_deref(), Some(apex), "{name}");
        }
        let sorted: Vec<_> = (stage.zones().iter())
            .map(|zone| zone.apex().to_string())
            .collect();
        assert_eq!(
            sorted,
            [".", "example.", "a.example.", "b.c.example.", "org."]
        );
    }

    #[test]
    fn a_name_outside_the_zones_has_none() {
        let stage =
            Authoritative::new(["example.", "b.c.example."].map(zone)).expect("no apex twice");
        for name in [".", "org.", "c.example.org.", "a.example.org."] {
            assert_eq!(found(&stage, name), None, "{name}");
        }
        assert_eq!(
            found(&Authoritative::new([]).expect("none"), "example."),
            None
        );
    }

    #[test]
    fn an_apex_given_twice_is_an_error() {
        let error = Authoritative::new(["example.", "EXAMPLE."].map(zone)).expect_err("twice");
        assert_eq!(error.to_string(), "zone `example.` is given twice");
    }
}
