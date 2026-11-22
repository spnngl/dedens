//! [`Zone`]: the checked content of one zone, immutable (D204).

use std::collections::BTreeMap;

use dedens_proto::rdata::Soa;
use dedens_proto::{Class, Name, Ttl};

use crate::Node;

/// A zone: every name at or below its apex with the `RRset`s there, in canonical order (RFC 4034 §6.1).
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
    pub(crate) nodes: BTreeMap<Name<'static>, Node>,
    pub(crate) records: usize,
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
    ///
    /// The node lives as long as `name` does at most: the map is searched with a borrowed key, which only a map of
    /// the same lifetime allows.
    #[must_use]
    pub fn node<'a>(&'a self, name: &Name<'a>) -> Option<&'a Node> {
        let nodes: &BTreeMap<Name<'a>, Node> = &self.nodes;
        nodes.get(name)
    }

    /// Every node with its name, in canonical order.
    pub fn nodes(&self) -> impl ExactSizeIterator<Item = (&Name<'static>, &Node)> {
        self.nodes.iter()
    }

    /// The records of the zone, duplicates merged, signatures counted.
    #[must_use]
    pub const fn record_count(&self) -> usize {
        self.records
    }
}
