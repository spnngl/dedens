//! [`Changeset`]: the records that take one version of a zone to the next (RFC 1995 §4, D207).

use core::cmp::Ordering;
use std::collections::HashMap;

use dedens_proto::rdata::RData;
use dedens_proto::{Class, Name, Record, RecordType, Serial};

/// Why records are no changeset.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum ChangesetError {
    /// An end that is no SOA record (RFC 1995 §4: a difference sequence starts each part with an SOA).
    #[error("the first and the last record of a changeset are SOA records (RFC 1995 §4)")]
    NotSoa,
    /// Two SOA records that are not of one zone: another owner or class (RFC 1995 §4).
    #[error("the two SOA records are of different zones (RFC 1995 §4)")]
    DifferentZone,
    /// A new serial that is not ahead of the old one (RFC 1995 §4 sends the differences of an older version to a
    /// newer; RFC 1982 §3.2 says what ahead is).
    #[error("serial {to} is not ahead of serial {from} (RFC 1982 §3.2, RFC 1995 §4)")]
    NotAhead {
        /// The serial the changeset starts from.
        from: Serial,
        /// The serial it ends at.
        to: Serial,
    },
    /// An SOA record among those removed or added: the SOA of a zone changes by its two ends (RFC 1995 §4).
    #[error("an SOA record among the removed or added records (RFC 1995 §4)")]
    SoaInBody,
    /// Two changesets that do not follow each other: the first ends at another SOA than the second starts from
    /// (RFC 1995 §6).
    #[error(
        "the changesets are not consecutive: the first ends at another SOA than the second starts from"
    )]
    NotConsecutive,
}

/// The difference between two versions of a zone: the old and the new SOA, the records the new version lacks and
/// those it adds (RFC 1995 §4).
///
/// Sent as the IXFR sequence is: the old SOA then the removed records, the new SOA then the added ones. RRSIG
/// records are ordinary records here. Records are as an IXFR sends them: owner, class, TTL and RDATA each.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Changeset {
    from: Record<'static>,
    from_serial: Serial,
    to: Record<'static>,
    to_serial: Serial,
    removed: Vec<Record<'static>>,
    added: Vec<Record<'static>>,
}

/// The serial of `record`, if it is an SOA.
fn serial_of(record: &Record<'_>) -> Option<Serial> {
    match record.data() {
        RData::Soa(soa) => Some(Serial::new(soa.serial)),
        _ => None,
    }
}

impl Changeset {
    /// A changeset from `from` to `to`, the SOA records of the old and the new version.
    ///
    /// # Errors
    ///
    /// [`ChangesetError`] when an end is no SOA, the two differ in owner or class, `to` is not ahead of `from`
    /// (RFC 1982 §3.2), or an SOA is among `removed` or `added`.
    pub fn new(
        from: Record<'static>,
        to: Record<'static>,
        removed: Vec<Record<'static>>,
        added: Vec<Record<'static>>,
    ) -> Result<Self, ChangesetError> {
        let (Some(old), Some(new)) = (serial_of(&from), serial_of(&to)) else {
            return Err(ChangesetError::NotSoa);
        };
        if from.name != to.name || from.class != to.class {
            return Err(ChangesetError::DifferentZone);
        }
        if new.partial_cmp(&old) != Some(Ordering::Greater) {
            return Err(ChangesetError::NotAhead { from: old, to: new });
        }
        if removed
            .iter()
            .chain(&added)
            .any(|r| r.rtype() == RecordType::SOA)
        {
            return Err(ChangesetError::SoaInBody);
        }
        Ok(Self {
            from,
            from_serial: old,
            to,
            to_serial: new,
            removed,
            added,
        })
    }

    /// The SOA record of the version the changeset starts from.
    #[must_use]
    pub const fn from_soa(&self) -> &Record<'static> {
        &self.from
    }

    /// The SOA record of the version it ends at.
    #[must_use]
    pub const fn to_soa(&self) -> &Record<'static> {
        &self.to
    }

    /// The serial of the version it starts from.
    #[must_use]
    pub const fn from_serial(&self) -> Serial {
        self.from_serial
    }

    /// The serial of the version it ends at.
    #[must_use]
    pub const fn to_serial(&self) -> Serial {
        self.to_serial
    }

    /// The records the new version lacks.
    #[must_use]
    pub fn removed(&self) -> &[Record<'static>] {
        &self.removed
    }

    /// The records the new version adds.
    #[must_use]
    pub fn added(&self) -> &[Record<'static>] {
        &self.added
    }

    /// The zone's apex and class: the owner and class of the SOA records.
    #[must_use]
    pub const fn zone(&self) -> (&Name<'static>, Class) {
        (&self.from.name, self.from.class)
    }

    /// The one changeset that does what `self` and then `next` do (RFC 1995 §6: a server may send the net
    /// difference of several versions in one sequence).
    ///
    /// A record added by one and removed by the other, or the other way round, cancels. A record is the same
    /// when its owner, class, TTL and RDATA are, so a TTL changed twice leaves the first removal and the last
    /// addition. The order is that of first appearance: removals of `self`, then of `next`.
    ///
    /// # Errors
    ///
    /// [`ChangesetError::NotConsecutive`] unless `self` ends at the SOA `next` starts from (TTL aside), and the
    /// errors of [`Changeset::new`] for the joined ends.
    pub fn condense(self, next: Self) -> Result<Self, ChangesetError> {
        if self.to.data() != next.from.data() || self.to.name != next.from.name {
            return Err(ChangesetError::NotConsecutive);
        }
        // Per record: whether the zone had it at the start (its first step removes it), and has it at the end (its
        // last step adds it).
        let mut index: HashMap<Record<'static>, usize> = HashMap::new();
        let mut steps: Vec<(Record<'static>, bool, bool)> = Vec::new();
        let sequence = [
            (self.removed, false),
            (self.added, true),
            (next.removed, false),
            (next.added, true),
        ];
        for (records, adds) in sequence {
            for record in records {
                if let Some(step) = index.get(&record).and_then(|&at| steps.get_mut(at)) {
                    step.2 = adds;
                } else {
                    index.insert(record.clone(), steps.len());
                    steps.push((record, !adds, adds));
                }
            }
        }
        let (mut removed, mut added) = (Vec::new(), Vec::new());
        for (record, at_start, at_end) in steps {
            match (at_start, at_end) {
                (true, false) => removed.push(record),
                (false, true) => added.push(record),
                _ => {}
            }
        }
        Self::new(self.from, next.to, removed, added)
    }
}
