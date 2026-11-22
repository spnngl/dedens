//! The names of a zone and the `RRset`s at them (D204).

use dedens_proto::{RecordType, Ttl, WireRdata};

/// The records of one type at one name: one TTL (RFC 2181 §5.2) and distinct RDATA, in the order of the text.
///
/// Two are equal when they have the same TTL and the same RDATA in any order: an `RRset` is a set (RFC 2181 §5),
/// so a zone changed by a [`Changeset`](crate::Changeset) equals the zone loaded from the text of its result.
#[derive(Debug, Clone)]
pub struct RrSet {
    pub(crate) ttl: Ttl,
    /// Never empty.
    pub(crate) rdatas: Vec<WireRdata<'static>>,
}

impl PartialEq for RrSet {
    fn eq(&self, other: &Self) -> bool {
        // RDATA is distinct within a set, so equal lengths and one containing the other make the sets equal.
        self.ttl == other.ttl
            && self.rdatas.len() == other.rdatas.len()
            && self.rdatas.iter().all(|r| other.rdatas.contains(r))
    }
}

impl RrSet {
    /// The TTL of every record.
    #[must_use]
    pub const fn ttl(&self) -> Ttl {
        self.ttl
    }

    /// The RDATA of each record, encoded; at least one.
    #[must_use]
    pub fn rdatas(&self) -> &[WireRdata<'static>] {
        &self.rdatas
    }
}

/// What a name is to the answers of its zone, from where the zone is cut (RFC 1034 §4.2.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    /// The zone is the authority for the name: its records are answers.
    Authoritative,
    /// A delegation point below the apex: its NS `RRset` refers to the child zone, which holds the rest of its
    /// data (RFC 1034 §4.2.1); records of other types here are glue or DS (RFC 4035 §2.4).
    Delegation,
    /// Below a delegation point or a DNAME owner: kept as written, never answered from (RFC 1034 §4.2.1, RFC 6672
    /// §2.4). Below a delegation, an address is glue (RFC 9471 §2).
    Occluded,
    /// No record here; a name below it has one (RFC 4592 §2.2.2, RFC 8020).
    EmptyNonTerminal,
}

/// A name of the zone: its `RRset`s, and what the name is to answers.
///
/// The signatures are kept apart, by the type they cover: they never count among the types a name holds
/// (RFC 2181 §10.1).
#[derive(Debug, Clone, PartialEq)]
pub struct Node {
    pub(crate) kind: Kind,
    pub(crate) wildcard: bool,
    pub(crate) dname: bool,
    /// By type.
    pub(crate) rrsets: Vec<(RecordType, RrSet)>,
    /// By the type covered.
    pub(crate) signatures: Vec<(RecordType, RrSet)>,
}

impl Node {
    /// What the name is to answers.
    #[must_use]
    pub const fn kind(&self) -> Kind {
        self.kind
    }

    /// Whether the owner is a wildcard: its first label is `*` (RFC 4592 §2.1.1).
    #[must_use]
    pub const fn is_wildcard(&self) -> bool {
        self.wildcard
    }

    /// Whether a DNAME `RRset` is here (RFC 6672 §2.4).
    #[must_use]
    pub const fn is_dname_owner(&self) -> bool {
        self.dname
    }

    /// The `RRset`s by type, signatures left out.
    pub fn rrsets(&self) -> impl ExactSizeIterator<Item = (RecordType, &RrSet)> {
        self.rrsets.iter().map(|(t, set)| (*t, set))
    }

    /// The `RRset` of `rtype`.
    #[must_use]
    pub fn rrset(&self, rtype: RecordType) -> Option<&RrSet> {
        let at = self.rrsets.binary_search_by_key(&rtype, |(t, _)| *t).ok()?;
        self.rrsets.get(at).map(|(_, set)| set)
    }

    /// Every signature `RRset`, by the type it covers.
    pub fn signature_sets(&self) -> impl Iterator<Item = &RrSet> {
        self.signatures.iter().map(|(_, set)| set)
    }

    /// The signatures over the `RRset` of `covered`.
    #[must_use]
    pub fn signatures(&self, covered: RecordType) -> Option<&RrSet> {
        let at = self
            .signatures
            .binary_search_by_key(&covered, |(t, _)| *t)
            .ok()?;
        self.signatures.get(at).map(|(_, set)| set)
    }
}
