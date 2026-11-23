//! The records of a load gathered and checked, then made into a [`Zone`] (D204).

use std::collections::BTreeMap;

use dedens_proto::rdata::RData;
use dedens_proto::{
    Class, DecodedRecord, Name, Nsec3HashAlgorithm, Record, RecordType, Ttl, WireRdata,
};

use crate::denial::{Chain, Denial, Params, owner_hash_of};
use crate::zone::find;
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
    /// Where the cut's node is in the nodes.
    index: usize,
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

    /// A builder holding the records of `zone`, to change it: each record's place is the zone's, line 0.
    ///
    /// The zone's nodes are taken apart and put together again by [`Builder::finish`], so every check runs on the
    /// changed zone, and the empty non-terminals and kinds are found again (D207).
    pub(crate) fn from_zone(zone: &Zone, file: String, limits: &'l Limits) -> Self {
        let at = Place {
            file: 0,
            line: 0,
            column: 0,
        };
        let building = |set: &RrSet| Building {
            at,
            ttl: set.ttl,
            mixed_ttls: false,
            rdatas: set.rdatas.clone(),
        };
        let mut builder = Self::new(zone.apex.clone(), file, limits);
        builder.class = Some(zone.class);
        builder.records = zone.records;
        for (name, node) in &zone.nodes {
            let pending = Pending {
                sets: node.rrsets.iter().map(|(t, s)| (*t, building(s))).collect(),
                signatures: node
                    .signatures
                    .iter()
                    .map(|(t, s)| (*t, building(s)))
                    .collect(),
            };
            builder.rdata_bytes += pending
                .sets
                .values()
                .chain(pending.signatures.values())
                .flat_map(|b| &b.rdatas)
                .map(|r| r.wire().len())
                .sum::<usize>();
            if pending.types() > 0 {
                builder.names.insert(name.clone(), pending);
            }
        }
        builder
    }

    /// Removes the record of `record`'s owner, type and RDATA; its TTL and class are not compared (RFC 1995 §4
    /// deletes by data: the TTL a server changed is the difference's other half, an addition). A record the zone
    /// does not have is an error.
    pub(crate) fn remove(&mut self, at: Place, record: &Record<'static>) {
        let rtype = record.rtype();
        let covered = match record.rdata.data() {
            RData::Rrsig(sig) => Some(sig.type_covered),
            _ => None,
        };
        let pending = self.names.get_mut(&record.name);
        let found = pending.and_then(|p| {
            let set = match covered {
                Some(c) => p.signatures.get_mut(&c),
                None => p.sets.get_mut(&rtype),
            };
            let set = set?;
            let at = set.rdatas.iter().position(|r| *r == record.rdata)?;
            set.rdatas.remove(at);
            Some(set.rdatas.is_empty())
        });
        let Some(emptied) = found else {
            self.error(
                Some(at),
                ErrorKind::RemoveAbsent {
                    owner: record.name.clone(),
                    rtype,
                },
            );
            return;
        };
        self.records -= 1;
        self.rdata_bytes -= record.rdata.wire().len();
        if emptied && let Some(p) = self.names.get_mut(&record.name) {
            match covered {
                Some(c) => p.signatures.remove(&c),
                None => p.sets.remove(&rtype),
            };
            if p.types() == 0 {
                self.names.remove(&record.name);
            }
        }
    }

    /// What was reported so far, when the builder goes no further.
    pub(crate) fn into_report(self) -> Report {
        self.report
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
            RData::Rrsig(sig) => Some(sig.type_covered),
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
        let chain = self.check_chain();
        let (nodes, delegations) = self.nodes();
        self.check_glue(&nodes, delegations);
        let denial = Denial::new(chain, &nodes, self.apex.label_count());
        let soa = find(&nodes, &self.apex).and_then(|(_, apex)| {
            let set = apex.rrset(RecordType::SOA)?;
            match set.rdatas().first()?.data() {
                RData::Soa(soa) => Some((soa.into_owned(), set.ttl())),
                _ => None,
            }
        });
        let apex = &self.apex;
        let has_ns = find(&nodes, apex).is_some_and(|(_, n)| n.rrset(RecordType::NS).is_some());
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
                denial,
            },
            self.report,
        ))
    }

    /// The chain that proves names and types absent, named by the apex: NSEC3 with an NSEC3PARAM of flags 0
    /// (RFC 5155 §4.1.2), else NSEC with an NSEC there. Each link must lead to the next of the chain, the last
    /// to the first (RFC 4034 §4.1.1, RFC 5155 §7.1); the signatures are not checked (D209).
    fn check_chain(&mut self) -> Option<Chain> {
        let apex = self.names.get(&self.apex)?;
        if let Some(set) = apex.sets.get(&RecordType::NSEC3PARAM) {
            let params = set.rdatas.iter().find_map(|rdata| match rdata.data() {
                RData::Nsec3Param(p) if p.flags == 0 => Some(Params::of(&p)),
                _ => None,
            });
            if let Some(params) = params {
                let at = set.at;
                return self.check_nsec3(params, at).map(Chain::Nsec3);
            }
        }
        if apex.sets.contains_key(&RecordType::NSEC) {
            self.check_nsec();
            return Some(Chain::Nsec);
        }
        None
    }

    /// Every NSEC leads to the owner of the next, in canonical order (RFC 4034 §4.1.1).
    fn check_nsec(&mut self) {
        let links: Vec<(&Name<'static>, Name<'static>, Place)> = self
            .names
            .iter()
            .filter_map(|(name, pending)| {
                let set = pending.sets.get(&RecordType::NSEC)?;
                let next = set.rdatas.iter().find_map(|rdata| match rdata.data() {
                    RData::Nsec(nsec) => Some(nsec.next.into_owned()),
                    _ => None,
                })?;
                Some((name, next, set.at))
            })
            .collect();
        let broken: Vec<(Place, Name<'static>)> = links
            .iter()
            .zip(links.iter().cycle().skip(1))
            .filter(|((_, next, _), (following, _, _))| next != *following)
            .map(|((owner, _, at), _)| (*at, (*owner).clone()))
            .collect();
        for (at, owner) in broken {
            let rtype = RecordType::NSEC;
            self.error(Some(at), ErrorKind::BrokenChain { rtype, owner });
        }
    }

    /// The records of the chain of `params`, at `at`, sorted by the hash their owner names, each lead to the
    /// next hash (RFC 5155 §7.1); an owner whose label is no hash breaks it.
    fn check_nsec3(&mut self, params: Params, at: Place) -> Option<Params> {
        if params.algorithm() != Nsec3HashAlgorithm::SHA1 {
            let algorithm = params.algorithm();
            self.error(Some(at), ErrorKind::Nsec3Algorithm { algorithm });
            return None;
        }
        if params.iterations() > 0 {
            let iterations = params.iterations();
            let kind = WarningKind::Nsec3Iterations { iterations };
            self.warnings.push(Warning { at, kind });
        }
        let apex_labels = self.apex.label_count();
        let mut links = Vec::new();
        let mut broken = Vec::new();
        for (name, pending) in &self.names {
            let Some(set) = pending.sets.get(&RecordType::NSEC3) else {
                continue;
            };
            let next = set.rdatas.iter().find_map(|rdata| match rdata.data() {
                RData::Nsec3(n) if params.holds(&n) => Some(n.next_hashed_owner().to_vec()),
                _ => None,
            });
            // Records of other parameters are of another chain, one being made or retired (RFC 5155 §10.4).
            let Some(next) = next else { continue };
            if name.label_count() != apex_labels + 1 {
                // Off the chain, warned as WarningKind::Nsec3Owner.
                continue;
            }
            match owner_hash_of(name, apex_labels) {
                Some(hash) => links.push((hash, next, set.at, name.clone())),
                None => broken.push((set.at, name.clone())),
            }
        }
        links.sort_unstable_by_key(|link| link.0);
        broken.extend(
            links
                .iter()
                .zip(links.iter().cycle().skip(1))
                .filter(|((_, next, _, _), (following, _, _, _))| next.as_slice() != following)
                .map(|((_, _, at, owner), _)| (*at, owner.clone())),
        );
        if links.is_empty() {
            broken.push((at, self.apex.clone()));
        }
        for (at, owner) in broken {
            let rtype = RecordType::NSEC3;
            self.error(Some(at), ErrorKind::BrokenChain { rtype, owner });
        }
        Some(params)
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
    fn nodes(&mut self) -> (Vec<(Name<'static>, Node)>, Vec<Delegation>) {
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
        // The names below a name follow it in canonical order, so the next node says whether there is one.
        let mut next: Option<&Name<'static>> = None;
        for (name, node) in nodes.iter_mut().rev() {
            let name: &Name<'static> = name;
            node.proof_only = holds_only_nsec3(node) && next.is_none_or(|n| !n.is_within(name));
            next = Some(name);
        }
        (nodes, delegations)
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
            kind = Kind::Occluded { cut: c.index };
        } else {
            *cut = None;
            let dname = pending.sets.get(&RecordType::DNAME).map(|b| b.at);
            if let (Some(ns), true) = (pending.sets.get(&RecordType::NS), name != self.apex) {
                kind = Kind::Delegation;
                *cut = Some(Cut {
                    name: name.clone(),
                    index: nodes.len(),
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
                    index: nodes.len(),
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
        if let Some(b) = pending.sets.get(&RecordType::NSEC3)
            && name.label_count() != self.apex.label_count().saturating_add(1)
        {
            self.warnings.push(Warning {
                at: b.at,
                kind: WarningKind::Nsec3Owner {
                    owner: name.clone().into_owned(),
                },
            });
        }
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
            proof_only: false,
            rrsets,
            signatures,
        }
    }

    /// Delegations whose name servers inside the delegated domain have no address in the zone (RFC 9471 §2).
    fn check_glue(&mut self, nodes: &[(Name<'static>, Node)], delegations: Vec<Delegation>) {
        for d in delegations {
            for target in d.targets {
                let has_address = find(nodes, &target).is_some_and(|(_, n)| {
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

/// Whether `node` holds NSEC3 records and nothing else.
fn holds_only_nsec3(node: &Node) -> bool {
    let mut sets = node.rrsets().peekable();
    sets.peek().is_some() && sets.all(|(rtype, _)| rtype == RecordType::NSEC3)
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
