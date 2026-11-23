//! The authoritative stage (D208): the zones this server is the authority for, each answered from its
//! [`Zone`] (D206).

use std::fmt;
use std::sync::Arc;

use dedens_proto::{MAX_NAME_LEN, Name, Question, RecordType};
use dedens_zone::{End, Zone};

use crate::Step;
use crate::metrics::Answers;
use crate::reply::Client;

/// The zones a server is the authority for, found by the longest apex a name is at or below (RFC 1034 §4.3.2
/// step 2). Each is shared: a reload keeps the zones whose files did not change, and swaps in the others whole
/// (D204, D208).
#[derive(Clone)]
pub struct Authoritative {
    /// Sorted by apex in canonical order (RFC 4034 §6.1), no apex twice.
    zones: Box<[Arc<Zone>]>,
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
        let mut zones: Vec<_> = zones.into_iter().collect();
        zones.sort_by(|a, b| a.apex().cmp(b.apex()));
        if let Some(pair) = zones
            .windows(2)
            .find(|pair| pair[0].apex() == pair[1].apex())
        {
            return Err(Duplicate(pair[0].apex().clone()));
        }
        Ok(Self {
            zones: zones.into(),
            answers: Answers::new(),
        })
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
        let mut buf = [0; MAX_NAME_LEN];
        let wire = name.to_wire(&mut buf);
        let mut labels = name.label_count();
        let mut end = self.zones.len();
        loop {
            // The suffix of `labels` labels of `name`: names within an apex follow it in canonical order with no
            // other name between, so the zone just before the suffix holds it, or the apex it shares with that
            // zone's is the longest that can.
            let suffix =
                Name::from_uncompressed(skip_labels(wire, name.label_count() - labels)).ok()?;
            end = self.zones[..end].partition_point(|zone| *zone.apex() <= suffix);
            let before = self.zones[..end].last()?;
            if suffix.is_within(before.apex()) {
                return Some(before);
            }
            labels = suffix.shared_labels(before.apex());
        }
    }

    /// The zone that answers `question`: [`Authoritative::zone`] of its name, but for a DS, which the parent
    /// zone holds (RFC 4035 §3.1.4.1): the zone of the name's parent when there is one, else the name's own. Knot
    /// and NSD search the zone for a DS the same way (`process_query.c:186-201`, `query.c:1497-1535`).
    fn zone_of(&self, question: &Question<'_>) -> Option<&Arc<Zone>> {
        if question.qtype == RecordType::DS
            && let Some(zone) = question.name.parent().and_then(|parent| self.zone(&parent))
        {
            return Some(zone);
        }
        self.zone(&question.name)
    }

    /// The reply to `client`, written into `out`, when a zone answers its question; `None` passes the query on.
    ///
    /// The zone answers, AA set (RFC 1034 §4.3.2), whatever RD says: a referral too, without AA, as Knot and NSD
    /// answer it; the name is never resolved from the zone's cut (D208). Only a name of another class than the
    /// zone's passes on.
    pub(crate) fn reply(&self, client: &Client<'_>, out: &mut [u8]) -> Option<Step> {
        let question = client.question.as_ref()?;
        let zone = self.zone_of(question)?;
        let answer = zone.answer(question);
        if matches!(answer.end, End::NotAuth) {
            return None;
        }
        self.answers.count(&answer.end);
        Some(
            client
                .zone(zone, &answer, out)
                .map_or(Step::Drop, Step::Reply),
        )
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
