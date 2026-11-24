//! [`Zone`]: the checked content of one zone, immutable (D204).

use dedens_proto::rdata::{RData, Soa};
use dedens_proto::{Class, Name, Record, RecordType, Ttl};

use crate::denial::Denial;
use crate::{Node, RrSet};

/// A zone: every name at or below its apex with the `RRset`s there, in canonical order (RFC 4034 §6.1), found by
/// binary search (D206).
///
/// Immutable: a change is a new `Zone` the server swaps in whole (D204), so a query reads one version from its
/// start to its end without a lock. Every name between a name and the apex is a node, an empty non-terminal when
/// it holds no record (RFC 4592 §2.2.2).
#[derive(Debug, Clone, PartialEq)]
pub struct Zone {
    pub(crate) apex: Name<'static>,
    pub(crate) class: Class,
    pub(crate) soa: Soa<'static>,
    pub(crate) soa_ttl: Ttl,
    pub(crate) nodes: Vec<(Name<'static>, Node)>,
    pub(crate) records: usize,
    /// The NSEC or NSEC3 chain the proofs come from (D209).
    pub(crate) denial: Denial,
}

impl Zone {
    /// The apex: the owner of the SOA.
    #[must_use]
    pub const fn apex(&self) -> &Name<'static> {
        &self.apex
    }

    /// The class of every record.
    #[must_use]
    pub const fn class(&self) -> Class {
        self.class
    }

    /// The SOA record's data.
    #[must_use]
    pub const fn soa(&self) -> &Soa<'static> {
        &self.soa
    }

    /// The SOA record's TTL.
    #[must_use]
    pub const fn soa_ttl(&self) -> Ttl {
        self.soa_ttl
    }

    /// The node of `name`, if the zone has it: with a record, or as an empty non-terminal.
    #[must_use]
    pub fn node(&self, name: &Name<'_>) -> Option<&Node> {
        find(&self.nodes, name).map(|(_, node)| node)
    }

    /// The node of `name` with the name as the zone stores it, in the case of the zone file.
    #[must_use]
    pub fn find(&self, name: &Name<'_>) -> Option<(&Name<'static>, &Node)> {
        find(&self.nodes, name)
    }

    /// The `RRset` of the SOA record, at the apex: the first name in canonical order, as every other name is
    /// below it.
    #[must_use]
    pub fn soa_rrset(&self) -> Option<&RrSet> {
        self.apex_node()?.rrset(RecordType::SOA)
    }

    /// The node of the apex: the first, as every other name is below it.
    pub(crate) fn apex_node(&self) -> Option<&Node> {
        self.nodes.first().map(|(_, node)| node)
    }

    /// Every node with its name, in canonical order.
    pub fn nodes(&self) -> impl ExactSizeIterator<Item = (&Name<'static>, &Node)> {
        self.nodes.iter().map(|(name, node)| (name, node))
    }

    /// The records of the zone, duplicates merged, signatures counted.
    #[must_use]
    pub const fn record_count(&self) -> usize {
        self.records
    }

    /// The records of the zone but its SOA, from `at`, each with the place past it: the body of a zone transfer,
    /// which the SOA opens and closes (RFC 5936 §2.2). Name after name in canonical order, each `RRset` of a name
    /// followed by the signature sets; occluded names and glue included, for a secondary is a copy of the zone (RFC
    /// 5936 §3.5). [`At::default`] is the first record; a walk resumes from the place of the last record taken.
    pub fn transfer_records(&self, at: At) -> impl Iterator<Item = (Record<'_>, At)> {
        let mut at = at;
        std::iter::from_fn(move || {
            loop {
                let (owner, node) = self.nodes.get(at.node)?;
                let Some((rtype, set)) = node.rrsets.iter().chain(&node.signatures).nth(at.set)
                else {
                    at = At {
                        node: at.node + 1,
                        ..At::default()
                    };
                    continue;
                };
                // The SOA is the apex's, the first node's, and its signatures are among the rest.
                let soa = at.node == 0 && at.set < node.rrsets.len() && *rtype == RecordType::SOA;
                let Some(rdata) = set.rdatas().get(at.record).filter(|_| !soa) else {
                    at = At {
                        set: at.set + 1,
                        record: 0,
                        ..at
                    };
                    continue;
                };
                at.record += 1;
                let record = Record {
                    name: owner.reborrow(),
                    class: self.class,
                    ttl: set.ttl(),
                    rdata: rdata.reborrow(),
                };
                return Some((record, at));
            }
        })
    }

    /// The SOA as a record.
    #[must_use]
    pub fn soa_record(&self) -> Record<'static> {
        Record::new(
            self.apex.clone(),
            self.class,
            self.soa_ttl,
            &RData::Soa(self.soa.clone()),
        )
    }
}

/// A place in the walk of [`Zone::transfer_records`]: a name, one of its sets, one of its records.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct At {
    node: usize,
    set: usize,
    record: usize,
}

/// The entry of `name` in `nodes`, which are in canonical order.
pub(crate) fn find<'n>(
    nodes: &'n [(Name<'static>, Node)],
    name: &Name<'_>,
) -> Option<(&'n Name<'static>, &'n Node)> {
    let at = nodes.binary_search_by(|(key, _)| key.cmp(name)).ok()?;
    nodes.get(at).map(|(key, node)| (key, node))
}
