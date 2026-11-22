//! The difference of two [`Zone`]s as a [`Changeset`], and a changeset applied to a zone (RFC 1995 §4, D207).

use core::cmp::Ordering;

use dedens_proto::rdata::RData;
use dedens_proto::{Class, DecodedRecord, Name, Record, RecordType, Serial, WireRdata};

use crate::builder::Builder;
use crate::{
    Changeset, ChangesetError, ErrorKind, Limits, Loaded, Node, Place, Report, RrSet, Zone,
};

impl Zone {
    /// The changeset that takes `old` to `new`: `old.apply(&diff)` gives `new` again.
    ///
    /// An `RRset` whose records and TTL are the same is not in it; one whose RDATA changed has the records
    /// that went removed and those that came added; one whose TTL changed has every record removed then added
    /// (a TTL is the record's: RFC 2181 §5.2 has one per `RRset`). RDATA compares as [`WireRdata`] does, so a
    /// change of case in a name inside RDATA is no change (RFC 4343 §3). The cost is one walk of both zones, and
    /// for each `RRset` the product of its two sizes, at most [`Limits::records_per_rrset`] squared.
    ///
    /// # Errors
    ///
    /// [`ChangesetError::DifferentZone`] when the apex or the class differs, and the errors of
    /// [`Changeset::new`]: `new`'s serial must be ahead of `old`'s.
    pub fn diff(old: &Self, new: &Self) -> Result<Changeset, ChangesetError> {
        if old.apex != new.apex || old.class != new.class {
            return Err(ChangesetError::DifferentZone);
        }
        let (mut removed, mut added) = (Vec::new(), Vec::new());
        let mut sink = Sink {
            class: old.class,
            removed: &mut removed,
            added: &mut added,
        };
        for (name, old_node, new_node) in merge(old.nodes.iter(), new.nodes.iter()) {
            let (old_sets, old_signatures) = sets_of(old_node);
            let (new_sets, new_signatures) = sets_of(new_node);
            for (rtype, o, n) in merge(pairs(old_sets), pairs(new_sets)) {
                sink.set(name, *rtype, o, n);
            }
            for (_, o, n) in merge(pairs(old_signatures), pairs(new_signatures)) {
                sink.set(name, RecordType::RRSIG, o, n);
            }
        }
        Changeset::new(old.soa_record(), new.soa_record(), removed, added)
    }

    /// The zone after `changeset`, checked as a loaded zone is; `self` is not changed (D204, D207).
    ///
    /// The changeset must start at the zone's SOA (its TTL aside). The records it removes are looked up by
    /// owner, type and RDATA, TTL ignored (RFC 1995 §4); one the zone lacks is an error. The records it adds
    /// join the `RRset` of their type, taking the lowest TTL as a load does (RFC 2181 §5.2). Every check of a
    /// load then runs again on the whole zone, so a changeset that leaves a CNAME beside other data, or no NS at
    /// the apex, is refused with the changeset's record as the place (record `n` of the IXFR sequence of RFC 1995 §4, the old
    /// SOA being 1, is line `n` of file 1; a record of the zone is line 0). The cost is a copy of the zone and a walk of it: a change is
    /// not cheap, and D204 chose immutable versions swapped whole over cheap changes.
    ///
    /// # Errors
    ///
    /// The [`Report`] of every error: [`ErrorKind::WrongVersion`], [`ErrorKind::RemoveAbsent`], those of a load,
    /// and [`ErrorKind::Limit`] for what `limits` bounds.
    pub fn apply(&self, changeset: &Changeset, limits: &Limits) -> Result<Loaded, Report> {
        let mut builder = Builder::from_zone(self, "zone".to_owned(), limits);
        let file = builder.file("changeset".to_owned());
        if self.soa_record().data() != changeset.from_soa().data()
            || self.apex != changeset.from_soa().name
        {
            let at = Place {
                file,
                line: 1,
                column: 1,
            };
            builder.error(
                Some(at),
                ErrorKind::WrongVersion {
                    zone: Serial::new(self.soa.serial),
                    changeset: changeset.from_serial(),
                },
            );
            return Err(builder.into_report());
        }
        let place = |n: usize| Place {
            file,
            line: n,
            column: 1,
        };
        builder.remove(place(1), changeset.from_soa());
        for (n, record) in changeset.removed().iter().enumerate() {
            builder.remove(place(n + 2), record);
        }
        let to = changeset.removed().len() + 2;
        builder.add(place(to), decoded(changeset.to_soa()));
        for (n, record) in changeset.added().iter().enumerate() {
            builder.add(place(to + 1 + n), decoded(record));
        }
        let (zone, report) = builder.finish()?;
        Ok(Loaded { zone, report })
    }

    /// The SOA as a record.
    fn soa_record(&self) -> Record<'static> {
        Record::new(
            self.apex.clone(),
            self.class,
            self.soa_ttl,
            &RData::Soa(self.soa.clone()),
        )
    }
}

fn decoded(record: &Record<'static>) -> DecodedRecord<'static> {
    DecodedRecord {
        record: record.clone(),
        invalid_rdata: None,
    }
}

/// Where the records of a difference go.
struct Sink<'a> {
    class: Class,
    removed: &'a mut Vec<Record<'static>>,
    added: &'a mut Vec<Record<'static>>,
}

impl Sink<'_> {
    /// The records of `old` and `new`, the `RRset`s of `rtype` at `name`, that make the difference.
    fn set(
        &mut self,
        name: &Name<'static>,
        rtype: RecordType,
        old: Option<&RrSet>,
        new: Option<&RrSet>,
    ) {
        // The SOA is the changeset's two ends.
        if rtype == RecordType::SOA {
            return;
        }
        let none: &[WireRdata<'static>] = &[];
        let (old_rdatas, new_rdatas) = (
            old.map_or(none, RrSet::rdatas),
            new.map_or(none, RrSet::rdatas),
        );
        let retimed = matches!((old, new), (Some(o), Some(n)) if o.ttl != n.ttl);
        if let Some(set) = old {
            for rdata in old_rdatas
                .iter()
                .filter(|r| retimed || !new_rdatas.contains(r))
            {
                self.removed.push(self.record(name, set, rdata));
            }
        }
        if let Some(set) = new {
            for rdata in new_rdatas
                .iter()
                .filter(|r| retimed || !old_rdatas.contains(r))
            {
                self.added.push(self.record(name, set, rdata));
            }
        }
    }

    fn record(
        &self,
        name: &Name<'static>,
        set: &RrSet,
        rdata: &WireRdata<'static>,
    ) -> Record<'static> {
        Record {
            name: name.clone(),
            class: self.class,
            ttl: set.ttl,
            rdata: rdata.clone(),
        }
    }
}

type TypedSets = [(RecordType, RrSet)];

/// The `RRset`s and the signature sets of a node, none for a node a version lacks.
fn sets_of(node: Option<&Node>) -> (&TypedSets, &TypedSets) {
    node.map_or((&[], &[]), |n| (&n.rrsets, &n.signatures))
}

fn pairs(sets: &TypedSets) -> impl Iterator<Item = (&RecordType, &RrSet)> {
    sets.iter().map(|(t, s)| (t, s))
}

/// The entries of two sorted sequences by key, in order, each with its value in either or both.
fn merge<'a, K: Ord + 'a, V: 'a>(
    old: impl Iterator<Item = (&'a K, &'a V)>,
    new: impl Iterator<Item = (&'a K, &'a V)>,
) -> impl Iterator<Item = (&'a K, Option<&'a V>, Option<&'a V>)> {
    let (mut old, mut new) = (old.peekable(), new.peekable());
    core::iter::from_fn(move || {
        let order = match (old.peek(), new.peek()) {
            (None, None) => return None,
            (Some(_), None) => Ordering::Less,
            (None, Some(_)) => Ordering::Greater,
            (Some((a, _)), Some((b, _))) => a.cmp(b),
        };
        match order {
            Ordering::Less => old.next().map(|(k, v)| (k, Some(v), None)),
            Ordering::Greater => new.next().map(|(k, v)| (k, None, Some(v))),
            Ordering::Equal => old
                .next()
                .zip(new.next())
                .map(|((k, o), (_, n))| (k, Some(o), Some(n))),
        }
    })
}
