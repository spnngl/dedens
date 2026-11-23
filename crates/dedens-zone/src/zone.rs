//! [`Zone`]: the checked content of one zone, immutable (D204).

use dedens_proto::rdata::Soa;
use dedens_proto::{Class, Name, RecordType, Ttl};

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
        let (_, apex) = self.nodes.first()?;
        apex.rrset(RecordType::SOA)
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
}

/// The entry of `name` in `nodes`, which are in canonical order.
pub(crate) fn find<'n>(
    nodes: &'n [(Name<'static>, Node)],
    name: &Name<'_>,
) -> Option<(&'n Name<'static>, &'n Node)> {
    let at = nodes.binary_search_by(|(key, _)| key.cmp(name)).ok()?;
    nodes.get(at).map(|(key, node)| (key, node))
}
