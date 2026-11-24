//! An UPDATE request made to a zone (RFC 2136 §3.2, §3.4.2, §3.6): its prerequisites checked against one version,
//! its changes made in order, and the result a [`Changeset`] and the zone it gives (D216).

use std::collections::BTreeMap;

use dedens_proto::rdata::{RData, Soa};
use dedens_proto::{
    Change, Name, Prerequisite, Rcode, Record, RecordType, Serial, Update, WireRdata,
};

use crate::denial::Denial;
use crate::difference::{Sink, merge, pairs};
use crate::{Changeset, ChangesetError, Limits, Loaded, Report, RrSet, Zone};

/// An update that changed the zone: the changeset from the old version, and the new version, checked.
#[derive(Debug, Clone, PartialEq)]
pub struct Updated {
    /// From the zone's SOA to the new one.
    pub changeset: Changeset,
    /// The zone after the changeset, with its warnings.
    pub loaded: Loaded,
}

/// Why an update is not made; the zone is left as it was (RFC 2136 §3.2.5, §3.7).
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum Rejection {
    /// The request names another zone or class (§3.1.1).
    #[error("the request is for another zone")]
    OtherZone,
    /// A name that must own no record owns one (§2.4.5).
    #[error("{0} is in use")]
    NameInUse(Name<'static>),
    /// A name that must own a record owns none (§2.4.4).
    #[error("{0} is not in use")]
    NameNotInUse(Name<'static>),
    /// An `RRset` that must not exist does (§2.4.3).
    #[error("the {1} RRset of {0} exists")]
    RrsetExists(Name<'static>, RecordType),
    /// An `RRset` that must exist, or hold given RDATAs, does not (§2.4.1, §2.4.2).
    #[error("the {1} RRset of {0} is not as required")]
    RrsetAbsent(Name<'static>, RecordType),
    /// The zone is signed, with a chain or signatures alone: a change would need signatures and denial records
    /// this server does not make (D209).
    #[error("the zone is signed")]
    Signed,
    /// A change of a type that only signing makes: RRSIG, NSEC, NSEC3, NSEC3PARAM (RFC 3007 §3.1.1).
    #[error("records of type {0} are not changed by an update")]
    Dnssec(RecordType),
    /// The zone after the changes fails a check of a load (D204), such as a CNAME at the apex.
    #[error("the zone after the update fails its checks: {0}")]
    Checks(Report),
    /// The changes make no changeset: the server's fault, for the SOA is kept out of its body and its serial goes
    /// ahead.
    #[error("the update makes no changeset: {0}")]
    Changeset(ChangesetError),
}

impl Rejection {
    /// The RCODE that answers it: §2.4's for a prerequisite, NOTAUTH for another zone (§3.1.1), REFUSED for what
    /// the server will not do, as Knot answers its semantic checks and NSEC3PARAM (`src/knot/updates/ddns.c`).
    #[must_use]
    pub const fn rcode(&self) -> Rcode {
        match self {
            Self::OtherZone => Rcode::NOTAUTH,
            Self::NameInUse(_) => Rcode::YXDOMAIN,
            Self::NameNotInUse(_) => Rcode::NXDOMAIN,
            Self::RrsetExists(..) => Rcode::YXRRSET,
            Self::RrsetAbsent(..) => Rcode::NXRRSET,
            Self::Signed | Self::Dnssec(_) | Self::Checks(_) => Rcode::REFUSED,
            // An internal failure (§3.4.2.1).
            Self::Changeset(_) => Rcode::SERVFAIL,
        }
    }
}

/// The `RRset`s of a name as the update leaves them, sorted by type.
type Sets = Vec<(RecordType, RrSet)>;

impl Zone {
    /// Makes `update` to the zone (RFC 2136 §3.2 to §3.6): `Ok(None)` when its prerequisites hold and its
    /// changes leave the zone as it was, which keeps its serial.
    ///
    /// The prerequisites are checked against this version, in the order [`Update::read`] gives them. The changes
    /// are then made in order (§3.4.2), and those §3.4.2 says to ignore are: an SOA but at the apex with a serial
    /// ahead of the current one (RFC 1982), which replaces it; a CNAME onto a name with other data, other data onto
    /// a CNAME (RFC 2181 §10.1; a DNAME is other data, RFC 6672 §5.2); the deletion of the SOA, of the apex's NS
    /// `RRset` or of its last NS record. A deletion of every `RRset` at the apex keeps the SOA and the NS. An added
    /// record already present is not added twice; every added record sets its `RRset`'s TTL, the one TTL of a set
    /// (RFC 2181 §5.2), as Knot's `solve_add_different_ttl` (`src/knot/updates/zone-update.c`) does. The serial goes
    /// up by one unless the update raised it (§3.6). The result is the changeset applied by [`Zone::apply`], so
    /// every check of a load runs on the new version.
    ///
    /// The cost is the update's names copied once, and the cost of [`Zone::apply`]: a copy of the zone.
    ///
    /// # Errors
    ///
    /// The [`Rejection`]: a prerequisite not met, a signed zone, a DNSSEC type, or a zone that fails its checks.
    pub fn update(
        &self,
        update: &Update<'_>,
        limits: &Limits,
    ) -> Result<Option<Updated>, Rejection> {
        if *update.zone() != self.apex || update.class() != self.class {
            return Err(Rejection::OtherZone);
        }
        if !matches!(self.denial, Denial::Unsigned)
            || self
                .nodes
                .iter()
                .any(|(_, node)| !node.signatures.is_empty())
        {
            return Err(Rejection::Signed);
        }
        for prerequisite in update.prerequisites() {
            self.check(prerequisite)?;
        }
        let mut touched: BTreeMap<Name<'static>, Sets> = BTreeMap::new();
        for change in update.changes() {
            let (name, rtype) = match change {
                Change::Add(record) => (&record.name, record.rtype()),
                Change::DeleteRrset(name, rtype) => (name, *rtype),
                Change::Delete(name, rdata) => (name, rdata.rtype()),
                Change::DeleteName(name) => (name, RecordType::ANY),
            };
            if matches!(
                rtype,
                RecordType::RRSIG | RecordType::NSEC | RecordType::NSEC3 | RecordType::NSEC3PARAM
            ) {
                return Err(Rejection::Dnssec(rtype));
            }
            let at_apex = *name == self.apex;
            let sets = touched.entry(name.clone().into_owned()).or_insert_with(|| {
                self.node(name)
                    .map_or_else(Vec::new, |node| node.rrsets.clone())
            });
            match change {
                Change::Add(record) => add(sets, record, at_apex),
                Change::DeleteRrset(_, rtype) => {
                    if !(at_apex && matches!(*rtype, RecordType::SOA | RecordType::NS)) {
                        sets.retain(|(t, _)| t != rtype);
                    }
                }
                Change::DeleteName(_) => {
                    sets.retain(|(t, _)| at_apex && matches!(*t, RecordType::SOA | RecordType::NS));
                }
                Change::Delete(_, rdata) => delete(sets, rdata, at_apex),
            }
        }
        let Some(changeset) = self.changeset(&touched).map_err(Rejection::Changeset)? else {
            return Ok(None);
        };
        let loaded = self.apply(&changeset, limits).map_err(Rejection::Checks)?;
        Ok(Some(Updated { changeset, loaded }))
    }

    /// Checks `prerequisite` against this version (RFC 2136 §3.2.5). A name in use owns a record: an empty
    /// non-terminal is not in use.
    fn check(&self, prerequisite: &Prerequisite<'_>) -> Result<(), Rejection> {
        let sets = |name: &Name<'_>| {
            self.node(name)
                .map(|node| &node.rrsets[..])
                .unwrap_or_default()
        };
        let set =
            |name: &Name<'_>, rtype| sets(name).iter().find(|(t, _)| *t == rtype).map(|(_, s)| s);
        let owned = |name: &Name<'_>| name.clone().into_owned();
        match prerequisite {
            Prerequisite::Exists(name, rtype) if set(name, *rtype).is_none() => {
                Err(Rejection::RrsetAbsent(owned(name), *rtype))
            }
            Prerequisite::Absent(name, rtype) if set(name, *rtype).is_some() => {
                Err(Rejection::RrsetExists(owned(name), *rtype))
            }
            Prerequisite::InUse(name) if sets(name).is_empty() => {
                Err(Rejection::NameNotInUse(owned(name)))
            }
            Prerequisite::NotInUse(name) if !sets(name).is_empty() => {
                Err(Rejection::NameInUse(owned(name)))
            }
            Prerequisite::Equals(name, rtype, rdatas)
                if !set(name, *rtype).is_some_and(|set| {
                    // Distinct on both sides: equal lengths and one in the other make them equal.
                    set.rdatas.len() == rdatas.len()
                        && rdatas.iter().all(|r| set.rdatas.iter().any(|s| s == r))
                }) =>
            {
                Err(Rejection::RrsetAbsent(owned(name), *rtype))
            }
            _ => Ok(()),
        }
    }

    /// The changeset from this version to the `RRset`s of the `touched` names, `None` when they are as they were.
    /// The SOA is the one an update set, or this one with its serial one up (RFC 2136 §3.6).
    fn changeset(
        &self,
        touched: &BTreeMap<Name<'static>, Sets>,
    ) -> Result<Option<Changeset>, ChangesetError> {
        let (mut removed, mut added) = (Vec::new(), Vec::new());
        let mut sink = Sink {
            class: self.class,
            removed: &mut removed,
            added: &mut added,
        };
        for (name, sets) in touched {
            let old = self.node(name).map_or(&[][..], |node| &node.rrsets[..]);
            for (rtype, o, n) in merge(pairs(old), pairs(sets)) {
                sink.set(name, *rtype, o, n);
            }
        }
        let from = self.soa_record();
        let set = touched
            .get(&self.apex)
            .and_then(|sets| sets.iter().find(|(t, _)| *t == RecordType::SOA))
            .map(|(_, set)| set);
        let to = match set.and_then(|set| Some((set.ttl, set.rdatas.first()?))) {
            Some((ttl, rdata)) if ttl != self.soa_ttl || *rdata != from.rdata => Record {
                ttl,
                rdata: rdata.clone(),
                ..from.clone()
            },
            _ if removed.is_empty() && added.is_empty() => return Ok(None),
            // One ahead, wrapping at 2^32 (RFC 1982 §3.1).
            _ => Record::new(
                self.apex.clone(),
                self.class,
                self.soa_ttl,
                &RData::Soa(Soa {
                    serial: self.soa.serial.wrapping_add(1),
                    ..self.soa.clone()
                }),
            ),
        };
        Changeset::new(from, to, removed, added).map(Some)
    }
}

/// Adds `record` to the `RRset`s of its name (RFC 2136 §3.4.2.2), or ignores it as the section says.
fn add(sets: &mut Sets, record: &Record<'_>, at_apex: bool) {
    let rtype = record.rtype();
    let rdata = record.rdata.clone().into_owned();
    let set = RrSet {
        ttl: record.ttl,
        rdatas: vec![rdata.clone()],
    };
    let cname = sets.iter().any(|(t, _)| *t == RecordType::CNAME);
    let others = sets.iter().any(|(t, _)| *t != RecordType::CNAME);
    let found = sets.binary_search_by_key(&rtype, |(t, _)| *t);
    match rtype {
        // An SOA only replaces the apex's: no other name may have one (RFC 1035 §5.2).
        RecordType::SOA => {
            if let Ok(at) = found
                && at_apex
                && ahead(sets, &rdata)
            {
                sets[at].1 = set;
            }
            return;
        }
        RecordType::CNAME if others => return,
        RecordType::CNAME => {
            if let Ok(at) = found {
                sets[at].1 = set;
                return;
            }
        }
        _ if cname => return,
        _ => {}
    }
    match found {
        Ok(at) => {
            let existing = &mut sets[at].1;
            existing.ttl = record.ttl;
            if !existing.rdatas.contains(&rdata) {
                existing.rdatas.push(rdata);
            }
        }
        Err(at) => sets.insert(at, (rtype, set)),
    }
}

/// Whether the SOA `rdata` has a serial ahead of the one in `sets` (RFC 2136 §3.4.2.2, RFC 1982).
fn ahead(sets: &Sets, rdata: &WireRdata<'_>) -> bool {
    let serial = |rdata: &WireRdata<'_>| match rdata.data() {
        RData::Soa(soa) => Some(Serial::new(soa.serial)),
        _ => None,
    };
    let current = sets
        .iter()
        .find(|(t, _)| *t == RecordType::SOA)
        .and_then(|(_, set)| set.rdatas.first())
        .and_then(serial);
    matches!((serial(rdata), current), (Some(new), Some(old)) if new > old)
}

/// Deletes the record of `rdata` from the `RRset`s of its name (RFC 2136 §3.4.2.4): never the SOA, nor the apex's
/// last NS.
fn delete(sets: &mut Sets, rdata: &WireRdata<'_>, at_apex: bool) {
    let rtype = rdata.rtype();
    if rtype == RecordType::SOA {
        return;
    }
    let Ok(at) = sets.binary_search_by_key(&rtype, |(t, _)| *t) else {
        return;
    };
    let rdatas = &mut sets[at].1.rdatas;
    if at_apex && rtype == RecordType::NS && rdatas.len() == 1 {
        return;
    }
    rdatas.retain(|r| r != rdata);
    if rdatas.is_empty() {
        sets.remove(at);
    }
}
