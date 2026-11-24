//! The authoritative stage (D208): the zones this server is the authority for, each answered from its
//! [`Zone`] (D206), with its access lists (D211), and those it holds no version of (D215).

use std::fmt;
use std::sync::Arc;

use dedens_proto::edns::InfoCode;
use dedens_proto::{Class, MAX_NAME_LEN, Message, Name, Question, Rcode, RecordType};
use dedens_zone::Zone;

use crate::Step;
use crate::metrics::Answers;
use crate::reply::Client;
use crate::zone_access::ZoneAccess;

/// The zones a server is the authority for, found by the longest apex a name is at or below (RFC 1034 §4.3.2
/// step 2). Each is shared: a reload keeps the zones whose files did not change, and swaps in the others whole
/// (D204, D208).
#[derive(Clone)]
pub struct Authoritative {
    /// Sorted by apex in canonical order (RFC 4034 §6.1), no apex twice.
    zones: Box<[Arc<Zone>]>,
    /// The access lists of the zone at the same index of `zones`.
    access: Box<[ZoneAccess]>,
    /// The apexes of the zones the server is the authority for without a version to answer from, sorted as
    /// `zones`, none of theirs: a secondary zone not transferred yet or expired (D215).
    unavailable: Box<[Name<'static>]>,
    answers: Answers,
}

/// What holds the name of a question.
enum Authority<'a> {
    /// A zone that answers it.
    Zone(&'a Arc<Zone>),
    /// A zone without a version.
    Unavailable,
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
            zones: zones.into(),
            access: access.into(),
            unavailable: Box::default(),
            answers: Answers::new(),
        })
    }

    /// The stage with `apexes` the zones of class IN it is the authority for but holds no version of: a name whose
    /// longest apex is one of them is answered SERVFAIL with EDE 24, Invalid Data (RFC 8914 §4.25: "its most recent
    /// zone being too old or having expired"), as Knot answers a zone without contents (`NS_NEED_ZONE_CONTENTS`,
    /// `nameserver/internet.h`) and NSD one configured but not loaded (`query.c`, `answer_lookup_zone`) (D215). The
    /// name is never passed on: no other stage knows the zone better.
    ///
    /// # Errors
    ///
    /// [`Duplicate`] when an apex is given twice, or is that of a zone of the stage.
    pub fn with_unavailable(
        mut self,
        apexes: impl IntoIterator<Item = Name<'static>>,
    ) -> Result<Self, Duplicate> {
        let mut apexes: Vec<_> = apexes.into_iter().collect();
        apexes.sort();
        if let Some(pair) = apexes.windows(2).find(|pair| pair[0] == pair[1]) {
            return Err(Duplicate(pair[0].clone()));
        }
        if let Some(apex) = apexes.iter().find(|apex| {
            self.zones
                .binary_search_by(|zone| zone.apex().cmp(apex))
                .is_ok()
        }) {
            return Err(Duplicate(apex.clone()));
        }
        self.unavailable = apexes.into();
        Ok(self)
    }

    /// The apexes of the zones without a version, sorted in canonical order.
    #[must_use]
    pub fn unavailable(&self) -> &[Name<'static>] {
        &self.unavailable
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
        find(
            &self.zones,
            |zone| zone.apex(),
            name.to_wire(&mut buf),
            name.label_count(),
        )
    }

    /// What holds the name `wire`, uncompressed, of `count` labels: the zone or the unavailable apex that is the
    /// longest it is at or below.
    fn holder(&self, wire: &[u8], count: usize) -> Option<Authority<'_>> {
        let zone = find(&self.zones, |zone| zone.apex(), wire, count).map(|i| &self.zones[i]);
        let unavailable = find(&self.unavailable, |apex| apex, wire, count);
        match (zone, unavailable) {
            (Some(zone), Some(i))
                if zone.apex().label_count() > self.unavailable[i].label_count() =>
            {
                Some(Authority::Zone(zone))
            }
            (_, Some(_)) => Some(Authority::Unavailable),
            (Some(zone), None) => Some(Authority::Zone(zone)),
            (None, None) => None,
        }
    }

    /// What answers `question`: what holds its name, but for a DS, which the parent zone holds (RFC 4035
    /// §3.1.4.1): what holds the name's parent when there is one, else the name's own. Knot and NSD search the
    /// zone for a DS the same way (`process_query.c:186-201`, `query.c:1497-1535`).
    fn authority(&self, question: &Question<'_>) -> Option<Authority<'_>> {
        let mut buf = [0; MAX_NAME_LEN];
        let wire = question.name.to_wire(&mut buf);
        let count = question.name.label_count();
        if question.qtype == RecordType::DS
            && count > 0
            && let Some(parent) = self.holder(skip_labels(wire, 1), count - 1)
        {
            return Some(parent);
        }
        self.holder(wire, count)
    }

    /// The reply to `client`, written into `out`, when a zone answers its question; `None` passes the query on.
    ///
    /// The zone answers, AA set (RFC 1034 §4.3.2), whatever RD says: a referral too, without AA, as Knot and NSD
    /// answer it; the name is never resolved from the zone's cut (D208). Only a name of another class than the
    /// zone's passes on: the zone refuses any other name it is not the authority for.
    pub(crate) fn reply(&self, client: &Client<'_>, out: &mut [u8]) -> Option<Step> {
        let question = client.question.as_ref()?;
        let zone = match self.authority(question)? {
            Authority::Zone(zone) => zone,
            Authority::Unavailable => {
                if question.qclass != Class::IN && question.qclass != Class::ANY {
                    return None;
                }
                self.answers.unavailable();
                return Some(
                    client
                        .reply(
                            Message::default(),
                            Rcode::SERVFAIL,
                            Some(InfoCode::INVALID_DATA),
                            out,
                        )
                        .map_or(Step::Drop, Step::Reply),
                );
            }
        };
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

/// The index in `items`, sorted by `apex` in canonical order, of the one whose apex is the longest the name `wire`,
/// uncompressed, of `count` labels, is at or below. Allocates nothing; a binary search for each label the name
/// shares with the item just before it in canonical order, at most.
fn find<T>(
    items: &[T],
    apex: impl Fn(&T) -> &Name<'static>,
    wire: &[u8],
    count: usize,
) -> Option<usize> {
    let mut labels = count;
    let mut end = items.len();
    loop {
        // The suffix of `labels` labels of the name: names within an apex follow it in canonical order with no
        // other name between, so the item just before the suffix holds it, or the apex it shares with that item's
        // is the longest that can.
        let suffix = Name::from_uncompressed(skip_labels(wire, count - labels)).ok()?;
        end = items[..end].partition_point(|item| *apex(item) <= suffix);
        let before = apex(items[..end].last()?);
        if suffix.is_within(before) {
            return Some(end - 1);
        }
        labels = suffix.shared_labels(before);
    }
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
            .field("unavailable", &self.unavailable)
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
        let stage = Authoritative::new(["example."].map(zone)).expect("one zone");
        let names = |names: [&str; 2]| names.map(|name| name.parse().expect("a name"));
        let error = (stage
            .clone()
            .with_unavailable(names(["a.example.", "A.EXAMPLE."])))
        .expect_err("twice");
        assert_eq!(error.to_string(), "zone `a.example.` is given twice");
        let error = (stage.with_unavailable(names(["org.", "Example."]))).expect_err("a zone");
        assert_eq!(error.to_string(), "zone `Example.` is given twice");
    }

    /// What holds `name`: the apex of its zone, or `!` and the unavailable apex.
    fn held(stage: &Authoritative, name: &str, qtype: RecordType) -> Option<String> {
        let question = Question::new(name.parse().expect("a name"), qtype);
        stage.authority(&question).map(|authority| match authority {
            Authority::Zone(zone) => zone.apex().to_string(),
            Authority::Unavailable => "unavailable".to_owned(),
        })
    }

    #[test]
    fn an_unavailable_zone_holds_its_names_by_the_longest_apex() {
        let stage = Authoritative::new(["example.", "b.a.example."].map(zone))
            .and_then(|stage| {
                stage.with_unavailable(["a.example.", "org."].map(|n| n.parse().expect("a name")))
            })
            .expect("no apex twice");
        let cases = [
            ("example.", RecordType::A, Some("example.")),
            ("a.example.", RecordType::A, Some("unavailable")),
            ("x.a.example.", RecordType::A, Some("unavailable")),
            ("b.a.example.", RecordType::A, Some("b.a.example.")),
            ("x.b.a.example.", RecordType::A, Some("b.a.example.")),
            // The DS of the unavailable zone is its parent's; that of the child below it, its own.
            ("a.example.", RecordType::DS, Some("example.")),
            ("b.a.example.", RecordType::DS, Some("unavailable")),
            ("www.org.", RecordType::A, Some("unavailable")),
            ("net.", RecordType::A, None),
        ];
        for (name, qtype, holder) in cases {
            assert_eq!(
                held(&stage, name, qtype).as_deref(),
                holder,
                "{name} {qtype}"
            );
        }
        assert_eq!(
            stage
                .unavailable()
                .iter()
                .map(ToString::to_string)
                .collect::<Vec<_>>(),
            ["a.example.", "org."]
        );
        // The zones of the stage are those it answers from.
        assert_eq!(found(&stage, "x.a.example.").as_deref(), Some("example."));
    }
}
