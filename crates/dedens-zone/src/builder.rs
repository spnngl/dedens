//! The records of a load gathered and checked, then made into a [`Zone`] (D204).

use std::collections::BTreeMap;

use dedens_proto::rdata::RData;
use dedens_proto::{Class, DecodedRecord, Name, RecordType, Ttl, WireRdata};

use crate::{
    Bound, ErrorKind, Kind, Limits, Node, Place, Report, RrSet, Warning, WarningKind, Zone,
    ZoneError,
};

/// The records of one type at one name while the zone is read.
struct Building {
    /// The first record's place.
    at: Place,
    /// The lowest TTL met.
    ttl: Ttl,
    /// Whether a record had another TTL than the first.
    mixed_ttls: bool,
    rdatas: Vec<WireRdata<'static>>,
}

/// What a name holds while the zone is read; nothing for an empty non-terminal.
#[derive(Default)]
struct Pending {
    sets: BTreeMap<RecordType, Building>,
    /// By the type covered.
    signatures: BTreeMap<RecordType, Building>,
}

impl Pending {
    fn types(&self) -> usize {
        self.sets.len() + self.signatures.len()
    }
}

/// A cut being walked below, in canonical order (RFC 4034 §6.1 keeps a subtree together).
struct Cut {
    name: Name<'static>,
    /// The DNAME's place, none for a delegation.
    dname: Option<Place>,
    /// Whether the first name below was reported.
    warned: bool,
}

/// A delegation with name servers inside it, whose addresses are checked once every node is known.
struct Delegation {
    name: Name<'static>,
    at: Place,
    targets: Vec<Name<'static>>,
}

/// Gathers the records of a zone, one by one, and checks them (RFC 1035 §5.2, RFC 2181, RFC 6672).
pub(crate) struct Builder<'l> {
    apex: Name<'static>,
    limits: &'l Limits,
    class: Option<Class>,
    names: BTreeMap<Name<'static>, Pending>,
    records: usize,
    rdata_bytes: usize,
    report: Report,
    warnings: Vec<Warning>,
    stopped: bool,
}

impl<'l> Builder<'l> {
    pub(crate) fn new(apex: Name<'static>, file: String, limits: &'l Limits) -> Self {
        Self {
            apex,
            limits,
            class: None,
            names: BTreeMap::new(),
            records: 0,
            rdata_bytes: 0,
            report: Report {
                files: vec![file],
                ..Report::default()
            },
            warnings: Vec::new(),
            stopped: false,
        }
    }

    /// Whether the error limit stopped the load: nothing more is read.
    pub(crate) const fn stopped(&self) -> bool {
        self.stopped
    }

    pub(crate) const fn include_depth(&self) -> usize {
        self.limits.include_depth
    }

    /// The index of a file now read.
    pub(crate) fn file(&mut self, name: String) -> usize {
        self.report.files.push(name);
        self.report.files.len() - 1
    }

    /// Reports an error, or [`ErrorKind::Stopped`] once there are too many.
    pub(crate) fn error(&mut self, at: Option<Place>, kind: ErrorKind) {
        if self.stopped {
            return;
        }
        if self.report.errors.len() >= self.limits.errors {
            self.stopped = true;
            self.report.errors.push(ZoneError {
                at: None,
                kind: ErrorKind::Stopped {
                    limit: self.limits.errors,
                },
            });
        } else {
            self.report.errors.push(ZoneError { at, kind });
        }
    }

    /// Reports that `bound` is reached, once: each further record would say the same.
    pub(crate) fn limit(&mut self, at: Option<Place>, bound: Bound) {
        let limit = match bound {
            Bound::Records => self.limits.records,
            Bound::Names => self.limits.names,
            Bound::RecordsPerRrset => self.limits.records_per_rrset,
            Bound::RrsetsPerName => self.limits.rrsets_per_name,
            Bound::RdataBytes => self.limits.rdata_bytes,
            Bound::IncludeDepth => self.limits.include_depth,
        };
        let kind = ErrorKind::Limit { bound, limit };
        if !self.report.errors.iter().any(|e| e.kind == kind) {
            self.error(at, kind);
        }
    }

    /// Checks a record as it is read and keeps it; a record in error is left out.
    pub(crate) fn add(&mut self, at: Place, decoded: DecodedRecord<'static>) {
        let DecodedRecord {
            record,
            invalid_rdata,
        } = decoded;
        let rtype = record.rtype();
        let class = *self.class.get_or_insert(record.class);
        if record.class != class {
            self.error(
                Some(at),
                ErrorKind::ClassMismatch {
                    found: record.class,
                    zone: class,
                },
            );
            return;
        }
        if let Some(e) = invalid_rdata {
            self.error(Some(at), ErrorKind::InvalidRdata(e));
            return;
        }
        if !record.name.is_within(&self.apex) {
            let owner = record.name;
            self.error(Some(at), ErrorKind::OutsideZone { owner });
            return;
        }
        if rtype == RecordType::SOA && record.name != self.apex {
            self.error(Some(at), ErrorKind::SoaNotAtApex);
            return;
        }
        let size = record.rdata.wire().len();
        if self.records >= self.limits.records {
            self.limit(Some(at), Bound::Records);
            return;
        }
        if self.rdata_bytes.saturating_add(size) > self.limits.rdata_bytes {
            self.limit(Some(at), Bound::RdataBytes);
            return;
        }
        if self.names.len() >= self.limits.names && !self.names.contains_key(&record.name) {
            self.limit(Some(at), Bound::Names);
            return;
        }
        let pending = self.names.entry(record.name).or_default();
        // RRSIG is kept by the type it covers. After the invalid RDATA check it always reads as a signature.
        let covered = match record.rdata.data() {
            RData::Rrsig(sig) if rtype == RecordType::RRSIG => Some(sig.type_covered),
            _ => None,
        };
        let new_type = covered.map_or_else(
            || !pending.sets.contains_key(&rtype),
            |c| !pending.signatures.contains_key(&c),
        );
        if new_type && pending.types() >= self.limits.rrsets_per_name {
            self.limit(Some(at), Bound::RrsetsPerName);
            return;
        }
        let set = match covered {
            Some(c) => pending.signatures.entry(c),
            None => pending.sets.entry(rtype),
        };
        let building = set.or_insert_with(|| Building {
            at,
            ttl: record.ttl,
            mixed_ttls: false,
            rdatas: Vec::new(),
        });
        if building.rdatas.contains(&record.rdata) {
            // A duplicate (RFC 2181 §5: an RRset holds each record once) merges; its TTL still counts.
            building.mixed_ttls |= building.ttl != record.ttl;
            building.ttl = building.ttl.min(record.ttl);
            return;
        }
        if !building.rdatas.is_empty() {
            let kind = match rtype {
                RecordType::SOA => Some(ErrorKind::MultipleSoa),
                RecordType::CNAME => Some(ErrorKind::MultipleCname),
                RecordType::DNAME => Some(ErrorKind::MultipleDname),
                _ => None,
            };
            if let Some(kind) = kind {
                self.error(Some(at), kind);
                return;
            }
        }
        if building.rdatas.len() >= self.limits.records_per_rrset {
            self.limit(Some(at), Bound::RecordsPerRrset);
            return;
        }
        building.mixed_ttls |= !building.rdatas.is_empty() && building.ttl != record.ttl;
        building.ttl = building.ttl.min(record.ttl);
        building.rdatas.push(record.rdata);
        self.records += 1;
        self.rdata_bytes += size;
    }

    /// The checks of the whole zone, and the zone if every one passes.
    ///
    /// # Errors
    ///
    /// The [`Report`] of every error, if any.
    pub(crate) fn finish(mut self) -> Result<(Zone, Report), Report> {
        self.check_names();
        let (nodes, delegations) = self.nodes();
        self.check_glue(&nodes, delegations);
        let soa = nodes.get(&self.apex).and_then(|apex| {
            let set = apex.rrset(RecordType::SOA)?;
            match set.rdatas().first()?.data() {
                RData::Soa(soa) => Some((soa.into_owned(), set.ttl())),
                _ => None,
            }
        });
        let apex = &self.apex;
        let has_ns = nodes
            .get(apex)
            .is_some_and(|n| n.rrset(RecordType::NS).is_some());
        if soa.is_none() {
            self.error(None, ErrorKind::NoSoa);
        }
        if !has_ns {
            self.error(None, ErrorKind::NoApexNs);
        }
        let (Some((soa, soa_ttl)), Some(class), true) =
            (soa, self.class, self.report.errors.is_empty())
        else {
            return Err(self.report);
        };
        self.report.warnings = self.warnings;
        Ok((
            Zone {
                apex: self.apex,
                class,
                soa,
                soa_ttl,
                nodes,
                records: self.records,
            },
            self.report,
        ))
    }

    /// What each name holds must go together (RFC 2181 §10.1, RFC 6672 §2.3, §2.4).
    fn check_names(&mut self) {
        let mut found = Vec::new();
        for (name, pending) in &self.names {
            let sets = &pending.sets;
            let at_of = |t: RecordType| sets.get(&t).map(|b| b.at);
            if let (Some(at), true) = (
                at_of(RecordType::CNAME),
                sets.contains_key(&RecordType::DNAME),
            ) {
                found.push((at, ErrorKind::CnameWithDname));
            } else if let Some(at) = at_of(RecordType::CNAME) {
                // NSEC is the other record a CNAME may have, with signatures (RFC 4035 §2.5, §3.1.5).
                let other = sets
                    .keys()
                    .find(|t| !matches!(**t, RecordType::CNAME | RecordType::NSEC));
                if let Some(other) = other {
                    found.push((at, ErrorKind::CnameWithOtherData { other: *other }));
                }
            }
            if let (Some(at), true) = (at_of(RecordType::NS), name != &self.apex)
                && sets.contains_key(&RecordType::DNAME)
            {
                found.push((at, ErrorKind::DnameWithNs));
            }
        }
        for (at, kind) in found {
            self.error(Some(at), kind);
        }
    }

    /// The nodes: the names with records, the empty non-terminals between them and the apex, and each one's kind.
    ///
    /// The names come in canonical order, and in it a name's ancestors that are no name of the zone are exactly
    /// those deeper than what it shares with the name before it: an ancestor there would sort after the
    /// previous name and before this one. So the empty non-terminals are found with no lookup.
    fn nodes(&mut self) -> (BTreeMap<Name<'static>, Node>, Vec<Delegation>) {
        let names = std::mem::take(&mut self.names);
        let mut total = names.len();
        let mut nodes = Vec::with_capacity(total);
        let mut delegations = Vec::new();
        let mut cut: Option<Cut> = None;
        let apex_labels = self.apex.label_count();
        for (name, pending) in names {
            let shared = nodes
                .last()
                .map_or(apex_labels, |(previous, _): &(Name<'static>, Node)| {
                    previous.shared_labels(&name)
                });
            for depth in shared + 1..name.label_count() {
                total += 1;
                if total > self.limits.names {
                    self.limit(None, Bound::Names);
                }
                let ent = name.ancestor(depth);
                self.place(
                    &mut nodes,
                    &mut delegations,
                    &mut cut,
                    ent,
                    Pending::default(),
                );
            }
            self.place(&mut nodes, &mut delegations, &mut cut, name, pending);
        }
        // Already in canonical order, so the map is built in one pass.
        (nodes.into_iter().collect(), delegations)
    }

    /// Adds the node of `name`, the next in canonical order, marking it by the `cut` it is below.
    fn place(
        &mut self,
        nodes: &mut Vec<(Name<'static>, Node)>,
        delegations: &mut Vec<Delegation>,
        cut: &mut Option<Cut>,
        name: Name<'static>,
        pending: Pending,
    ) {
        let mut kind = if pending.sets.is_empty() && pending.signatures.is_empty() {
            Kind::EmptyNonTerminal
        } else {
            Kind::Authoritative
        };
        if let Some(c) = cut
            .as_mut()
            .filter(|c| name != c.name && name.is_within(&c.name))
        {
            if let Some(at) = c.dname
                && !std::mem::replace(&mut c.warned, true)
            {
                self.warnings.push(Warning {
                    at,
                    kind: WarningKind::BelowDname {
                        first: name.clone(),
                    },
                });
            }
            kind = Kind::Occluded;
        } else {
            *cut = None;
            let dname = pending.sets.get(&RecordType::DNAME).map(|b| b.at);
            if let (Some(ns), true) = (pending.sets.get(&RecordType::NS), name != self.apex) {
                kind = Kind::Delegation;
                *cut = Some(Cut {
                    name: name.clone(),
                    dname: None,
                    warned: false,
                });
                let targets = in_domain_targets(&name, ns);
                if !targets.is_empty() {
                    delegations.push(Delegation {
                        name: name.clone(),
                        at: ns.at,
                        targets,
                    });
                }
            } else if dname.is_some() {
                *cut = Some(Cut {
                    name: name.clone(),
                    dname,
                    warned: false,
                });
            }
        }
        let node = self.node(&name, kind, pending);
        nodes.push((name, node));
    }

    fn node(&mut self, name: &Name<'_>, kind: Kind, pending: Pending) -> Node {
        let wildcard = name.labels().next() == Some(b"*".as_slice());
        let dname = pending.sets.contains_key(&RecordType::DNAME);
        let mut set = |rtype: RecordType, b: Building| {
            if b.mixed_ttls {
                self.warnings.push(Warning {
                    at: b.at,
                    kind: WarningKind::DifferentTtls {
                        rtype,
                        kept: b.ttl.get(),
                    },
                });
            }
            (
                rtype,
                RrSet {
                    ttl: b.ttl,
                    rdatas: b.rdatas,
                },
            )
        };
        let rrsets = pending.sets.into_iter().map(|(t, b)| set(t, b)).collect();
        let signatures = pending
            .signatures
            .into_iter()
            .map(|(t, b)| (t, set(RecordType::RRSIG, b).1))
            .collect();
        Node {
            kind,
            wildcard,
            dname,
            rrsets,
            signatures,
        }
    }

    /// Delegations whose name servers inside the delegated domain have no address in the zone (RFC 9471 §2).
    fn check_glue(&mut self, nodes: &BTreeMap<Name<'static>, Node>, delegations: Vec<Delegation>) {
        for d in delegations {
            for target in d.targets {
                let has_address = nodes.get(&target).is_some_and(|n| {
                    n.rrset(RecordType::A).is_some() || n.rrset(RecordType::AAAA).is_some()
                });
                if !has_address {
                    self.warnings.push(Warning {
                        at: d.at,
                        kind: WarningKind::MissingGlue {
                            delegation: d.name.clone(),
                            target,
                        },
                    });
                }
            }
        }
    }
}

/// The name servers of `ns` at or below `delegation`.
fn in_domain_targets(delegation: &Name<'_>, ns: &Building) -> Vec<Name<'static>> {
    ns.rdatas
        .iter()
        .filter_map(|r| match r.data() {
            RData::Ns(target) if target.is_within(delegation) => Some(target.into_owned()),
            _ => None,
        })
        .collect()
}
