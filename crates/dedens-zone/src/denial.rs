//! The proofs of a pre-signed zone that a name or type is absent: from its NSEC chain (RFC 4035 §3.1.3) or its
//! NSEC3 chain (RFC 5155 §7.2), indexed once at load (D209).

use core::num::NonZeroU32;
use core::ptr;

use dedens_dnssec::crypto::nsec3_hash;
use dedens_dnssec::denial::owner_hash;
use dedens_proto::rdata::{Nsec3, Nsec3Param, RData};
use dedens_proto::{Name, Nsec3HashAlgorithm, RecordType};

use crate::answer::{Entry, Match};
use crate::{Kind, Node, Zone};

/// A SHA-1 hash, the one NSEC3 has (RFC 5155 §11).
pub(crate) type Hash = [u8; 20];

/// The NSEC3 records a node's name leads to, found at load so that a query hashes only the name it proves absent:
/// the next closer name, which is no node (D209).
///
/// Each is the place, in the nodes, of the owner of the record, kept as `place + 1` so that none is a niche, in 32
/// bits: 8 bytes in all, a `Node` of 80. The places are below [`Limits::names`](crate::Limits::names), 2²⁴ by
/// default; a zone of 2³² - 1 names or more (343 GB of nodes) has no links, a bound nobody raises that far.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub(crate) struct Links {
    /// The record of the name's own hash, if the chain has one: not for an empty non-terminal made only by unsigned
    /// delegations of an opt-out chain (RFC 5155 §7.1), nor for a name that is no answer's: below a cut, or an
    /// NSEC3 owner.
    matching: Option<NonZeroU32>,
    /// The record that covers the hash of the name's wildcard, `*.` and the name (RFC 5155 §7.2.2), for a name that
    /// may be a closest encloser: not a delegation point.
    wildcard: Option<NonZeroU32>,
}

impl Links {
    fn of(matching: Option<usize>, wildcard: Option<usize>) -> Self {
        let one = |place: Option<usize>| {
            place.and_then(|p| NonZeroU32::new(u32::try_from(p).ok()?.checked_add(1)?))
        };
        Self {
            matching: one(matching),
            wildcard: one(wildcard),
        }
    }

    /// The place of the owner of the record of the name's hash.
    pub(crate) fn matching(self) -> Option<usize> {
        self.matching
            .and_then(|p| usize::try_from(p.get() - 1).ok())
    }

    /// The place of the owner of the record that covers the hash of the name's wildcard.
    pub(crate) fn wildcard(self) -> Option<usize> {
        self.wildcard
            .and_then(|p| usize::try_from(p.get() - 1).ok())
    }
}

/// The place, in the nodes, of the record of `hash` in `chain`.
fn matching_in(chain: &[(Hash, usize)], hash: &Hash) -> Option<usize> {
    let at = chain.binary_search_by(|(h, _)| h.cmp(hash)).ok()?;
    chain.get(at).map(|(_, place)| *place)
}

/// The place of the owner of the record that covers `hash`: the last before it in hash order, or the last of all,
/// whose next hash wraps to the first (RFC 5155 §3.1.7); the record of the hash itself if the chain has one.
fn covering_in(chain: &[(Hash, usize)], hash: &Hash) -> Option<usize> {
    let at = match chain.binary_search_by(|(h, _)| h.cmp(hash)) {
        Ok(at) => at,
        Err(0) => chain.len().checked_sub(1)?,
        Err(at) => at - 1,
    };
    chain.get(at).map(|(_, place)| *place)
}

/// The parameters of an NSEC3 chain, which every record of it and the zone's NSEC3PARAM share (RFC 5155 §4).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Params {
    algorithm: Nsec3HashAlgorithm,
    salt: Box<[u8]>,
    iterations: u16,
}

impl Params {
    /// The parameters an NSEC3PARAM gives.
    pub(crate) fn of(param: &Nsec3Param<'_>) -> Self {
        Self {
            algorithm: param.hash_algorithm,
            salt: param.salt().into(),
            iterations: param.iterations,
        }
    }

    pub(crate) const fn algorithm(&self) -> Nsec3HashAlgorithm {
        self.algorithm
    }

    pub(crate) const fn iterations(&self) -> u16 {
        self.iterations
    }

    /// Whether `nsec3` is of this chain: same algorithm, iterations and salt (RFC 5155 §7.2).
    pub(crate) fn holds(&self, nsec3: &Nsec3<'_>) -> bool {
        nsec3.hash_algorithm == self.algorithm
            && nsec3.iterations == self.iterations
            && nsec3.salt() == &*self.salt
    }

    /// Whether `node` holds an NSEC3 record of this chain.
    fn of_node(&self, node: &Node) -> bool {
        node.rrset(RecordType::NSEC3).is_some_and(|set| {
            set.rdatas()
                .iter()
                .any(|rdata| matches!(rdata.data(), RData::Nsec3(n) if self.holds(&n)))
        })
    }

    /// The hash of `name`; `None` for an algorithm other than SHA-1, which a load refuses.
    fn hash(&self, name: &Name<'_>) -> Option<Hash> {
        nsec3_hash(self.algorithm, &self.salt, self.iterations, name).ok()
    }
}

/// The hash an NSEC3 record's owner stands for: its first label in base32hex, one label below the apex
/// (RFC 5155 §3); `None` for another owner, which the chain leaves out.
pub(crate) fn owner_hash_of(owner: &Name<'_>, apex_labels: usize) -> Option<Hash> {
    if owner.label_count() != apex_labels + 1 {
        return None;
    }
    owner_hash(owner.labels().next()?)
}

/// How a zone proves what it lacks, chosen by its apex: by NSEC3 with an NSEC3PARAM there, by NSEC with an NSEC
/// there, else not at all (D209).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub(crate) enum Denial {
    /// The zone is not signed: answers carry no proof.
    #[default]
    Unsigned,
    /// The places in the nodes of those with an NSEC record: in canonical order, the chain's (RFC 4034 §6.1).
    Nsec(Vec<usize>),
    /// The NSEC3 chain.
    Nsec3 {
        /// Its parameters, the NSEC3PARAM's.
        params: Params,
        /// The hash of each record's owner and the owner's place in the nodes, in hash order.
        chain: Vec<(Hash, usize)>,
    },
}

/// The chain the apex of a zone being loaded names, checked before its nodes are made.
pub(crate) enum Chain {
    Nsec,
    Nsec3(Params),
}

impl Denial {
    /// The index of the records of `chain` in `nodes`; an NSEC3 owner hashed once, from its name. With NSEC3, each
    /// node learns its [`Links`]: two more hashes of its name, so a load costs about three times the hashes of the
    /// chain's records, the cost an answer then does not pay.
    pub(crate) fn new(
        chain: Option<Chain>,
        nodes: &mut [(Name<'static>, Node)],
        apex_labels: usize,
    ) -> Self {
        match chain {
            None => Self::Unsigned,
            Some(Chain::Nsec) => Self::Nsec(
                nodes
                    .iter()
                    .enumerate()
                    .filter(|(_, (_, node))| node.rrset(RecordType::NSEC).is_some())
                    .map(|(at, _)| at)
                    .collect(),
            ),
            Some(Chain::Nsec3(params)) => {
                let mut chain: Vec<(Hash, usize)> = nodes
                    .iter()
                    .enumerate()
                    .filter(|(_, (_, node))| params.of_node(node))
                    .filter_map(|(at, (name, _))| Some((owner_hash_of(name, apex_labels)?, at)))
                    .collect();
                chain.sort_unstable();
                for (name, node) in nodes.iter_mut() {
                    node.nsec3 = Self::links(&params, &chain, name, node);
                }
                Self::Nsec3 { params, chain }
            }
        }
    }

    /// What `node`, named `name`, leads to in the chain: nothing for a name no answer is built from, an NSEC3
    /// owner or a name below a cut (RFC 5155 §7.2.8, RFC 1034 §4.2.1).
    fn links(params: &Params, chain: &[(Hash, usize)], name: &Name<'_>, node: &Node) -> Links {
        let kind = node.kind();
        if node.is_proof_only() || matches!(kind, Kind::Occluded { .. }) {
            return Links::default();
        }
        let matching = params.hash(name).and_then(|hash| matching_in(chain, &hash));
        let wildcard = (kind != Kind::Delegation)
            .then(|| name.wildcard().ok())
            .flatten()
            .and_then(|wildcard| params.hash(&wildcard))
            .and_then(|hash| covering_in(chain, &hash));
        Links::of(matching, wildcard)
    }

    /// The type of the proofs' records: NSEC or NSEC3.
    pub(crate) const fn rtype(&self) -> Option<RecordType> {
        match self {
            Self::Unsigned => None,
            Self::Nsec(_) => Some(RecordType::NSEC),
            Self::Nsec3 { .. } => Some(RecordType::NSEC3),
        }
    }
}

/// A closest provable encloser (RFC 5155 §7.2.1).
struct Provable<'a> {
    /// The encloser.
    encloser: Entry<'a>,
    /// The owner of its NSEC3 record.
    record: Entry<'a>,
    /// The owner of the NSEC3 record that covers the next closer name, the encloser's child on the way to the name.
    cover: Option<Entry<'a>>,
}

/// The owners of the NSEC or NSEC3 records that prove an answer, each once.
pub(crate) type Proofs<'a> = Vec<Entry<'a>>;

fn add<'a>(proofs: &mut Proofs<'a>, entry: Option<Entry<'a>>) {
    if let Some(entry) = entry
        && !proofs.iter().any(|p| ptr::eq(p.node, entry.node))
    {
        proofs.push(entry);
    }
}

impl Zone {
    /// Proves that `name`, answered from a wildcard whose closest encloser is `encloser`, is not in the zone:
    /// the NSEC that covers it (RFC 4035 §3.1.3.3), or the NSEC3 that covers its next closer name (RFC 5155
    /// §7.2.6).
    pub(crate) fn prove_wildcard_answer<'a>(
        &'a self,
        name: &Name<'_>,
        encloser: &Entry<'a>,
        proofs: &mut Proofs<'a>,
    ) {
        match &self.denial {
            Denial::Unsigned => {}
            Denial::Nsec(owners) => add(proofs, self.nsec_covering(owners, name)),
            Denial::Nsec3 { params, chain } => {
                let provable = self.closest_provable(params, chain, name, *encloser);
                add(proofs, provable.and_then(|provable| provable.cover));
            }
        }
    }

    /// Proves that `name`, found at `at`, has no `RRset` of the type asked: the NSEC of the name, or the one that
    /// covers an empty non-terminal (RFC 4035 §3.1.3.1); for a wildcard, the NSEC that covers the name and the
    /// wildcard's (§3.1.3.4). With NSEC3 the record of the name (RFC 5155 §7.2.3), else, as for a DS asked at an
    /// unsigned delegation of an opt-out chain, the closest provable encloser proof (§7.2.4); for a wildcard,
    /// that proof and the record of the wildcard (§7.2.5).
    pub(crate) fn prove_no_data<'a>(
        &'a self,
        name: &Name<'_>,
        at: &Match<'a>,
        proofs: &mut Proofs<'a>,
    ) {
        match (&self.denial, at) {
            (Denial::Unsigned, _) => {}
            (Denial::Nsec(owners), Match::Exact(entry)) => {
                add(proofs, self.nsec_at(owners, entry));
            }
            (Denial::Nsec(owners), Match::Wildcard { source, .. }) => {
                add(proofs, self.nsec_covering(owners, name));
                add(proofs, self.nsec_at(owners, source));
            }
            (Denial::Nsec3 { params, chain }, Match::Exact(entry)) => {
                let found = entry.node.nsec3.matching().and_then(|at| self.entry(at));
                if found.is_some() {
                    add(proofs, found);
                } else if let Some(parent) = self.parent_of(entry) {
                    self.add_closest_provable(params, chain, entry.name, parent, proofs);
                }
            }
            (Denial::Nsec3 { params, chain }, Match::Wildcard { source, encloser }) => {
                self.add_closest_provable(params, chain, name, *encloser, proofs);
                add(
                    proofs,
                    source.node.nsec3.matching().and_then(|at| self.entry(at)),
                );
            }
        }
    }

    /// Proves that `name`, whose closest encloser is `encloser`, is not in the zone and no wildcard answers for
    /// it: the NSEC that covers the name and the one that covers the wildcard of the encloser (RFC 4035
    /// §3.1.3.2); the closest provable encloser proof and the NSEC3 that covers its wildcard (RFC 5155 §7.2.2).
    pub(crate) fn prove_no_name<'a>(
        &'a self,
        name: &Name<'_>,
        encloser: &Entry<'a>,
        proofs: &mut Proofs<'a>,
    ) {
        match &self.denial {
            Denial::Unsigned => {}
            Denial::Nsec(owners) => {
                add(proofs, self.nsec_covering(owners, name));
                if let Ok(wildcard) = encloser.name.wildcard() {
                    add(proofs, self.nsec_covering(owners, &wildcard));
                }
            }
            Denial::Nsec3 { params, chain } => {
                if let Some(provable) =
                    self.add_closest_provable(params, chain, name, *encloser, proofs)
                {
                    let wildcard = provable.node.nsec3.wildcard();
                    add(proofs, wildcard.and_then(|at| self.entry(at)));
                }
            }
        }
    }

    /// The NSEC record of `entry`, or for a name without one, an empty non-terminal, the one that covers it.
    fn nsec_at<'a>(&'a self, owners: &[usize], entry: &Entry<'a>) -> Option<Entry<'a>> {
        if entry.node.rrset(RecordType::NSEC).is_some() {
            return Some(*entry);
        }
        self.nsec_covering(owners, entry.name)
    }

    /// The owner of the NSEC record that covers `name`: the last before it in canonical order, which the apex,
    /// first of all, always is for a name below it.
    fn nsec_covering<'a>(&'a self, owners: &[usize], name: &Name<'_>) -> Option<Entry<'a>> {
        // The place of the name, or of the first node after it: a node asked for has no NSEC of its own.
        let (Ok(before) | Err(before)) = self.nodes.binary_search_by(|(key, _)| key.cmp(name));
        let owner = owners.partition_point(|&at| at < before).checked_sub(1)?;
        self.entry(*owners.get(owner)?)
    }

    /// The parent of `entry`: a node, as every ancestor of a node is (D204).
    fn parent_of<'a>(&'a self, entry: &Entry<'_>) -> Option<Entry<'a>> {
        let (name, node) = self.find(&entry.name.parent()?)?;
        Some(Entry { name, node })
    }

    /// The owner of the NSEC3 record that covers the hash of `name`, the last before it in hash order, or the
    /// last of all, whose next hash wraps to the first (RFC 5155 §3.1.7); the record of the hash itself if the
    /// chain has one.
    fn nsec3_covering<'a>(
        &'a self,
        params: &Params,
        chain: &[(Hash, usize)],
        name: &Name<'_>,
    ) -> Option<Entry<'a>> {
        let hash = params.hash(name)?;
        self.entry(covering_in(chain, &hash)?)
    }

    /// The closest provable encloser of `name`: `from`, an ancestor of it, or the nearest above that has an NSEC3
    /// record (RFC 5155 §7.2.1). It is `from` itself but in an opt-out chain, where an empty non-terminal made
    /// only by unsigned delegations has none (§7.1). Its record is a link made at load; what is hashed here is
    /// the next closer name only.
    fn closest_provable<'a>(
        &'a self,
        params: &Params,
        chain: &[(Hash, usize)],
        name: &Name<'_>,
        from: Entry<'a>,
    ) -> Option<Provable<'a>> {
        // `from` is a name of the zone, so the walk is bounded by the zone's depth, not by `name`'s.
        let mut encloser = from;
        loop {
            if let Some(record) = encloser.node.nsec3.matching().and_then(|at| self.entry(at)) {
                let next_closer = name.ancestor(encloser.name.label_count() + 1);
                return Some(Provable {
                    encloser,
                    record,
                    cover: self.nsec3_covering(params, chain, &next_closer),
                });
            }
            encloser = self.parent_of(&encloser)?;
        }
    }

    /// Adds the closest provable encloser proof of `name` from `from` up: the encloser's record and the one
    /// that covers the next closer name; returns the encloser.
    fn add_closest_provable<'a>(
        &'a self,
        params: &Params,
        chain: &[(Hash, usize)],
        name: &Name<'_>,
        from: Entry<'a>,
        proofs: &mut Proofs<'a>,
    ) -> Option<Entry<'a>> {
        let provable = self.closest_provable(params, chain, name, from)?;
        add(proofs, Some(provable.record));
        add(proofs, provable.cover);
        Some(provable.encloser)
    }
}
