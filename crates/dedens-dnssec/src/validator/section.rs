//! A section of a response as `RRsets` with their signatures, and the names an answer leads along (RFC 1034
//! §3.6.2, RFC 6672 §2.2, §3.1).

use dedens_proto::name::NameError;
use dedens_proto::{Class, Name, Question, RData, Record, RecordType};

use crate::rrsig::{RrSet, Signature};

/// The `RRsets` of one section, class IN, and the RRSIG `RRsets` among them.
#[derive(Debug)]
pub(super) struct Section {
    pub(super) sets: Vec<RrSet<'static>>,
    sigs: Vec<RrSet<'static>>,
}

impl Section {
    pub(super) fn new(records: &[Record<'static>]) -> Self {
        let (sigs, sets) = RrSet::group(records)
            .into_iter()
            .filter(|set| set.class() == Class::IN)
            .partition(|set| set.rtype() == RecordType::RRSIG);
        Self { sets, sigs }
    }

    /// The `RRset` of `owner` and `rtype`.
    pub(super) fn find(&self, owner: &Name<'_>, rtype: RecordType) -> Option<&RrSet<'static>> {
        self.sets
            .iter()
            .find(|set| set.rtype() == rtype && set.owner() == owner)
    }

    /// The RRSIGs of the section that cover `set`, in the order they come.
    pub(super) fn signatures(&self, set: &RrSet<'_>) -> Vec<Signature<'_>> {
        self.sigs
            .iter()
            .filter(|sigs| sigs.owner() == set.owner())
            .flat_map(|sigs| Signature::all(sigs))
            .filter(|sig| sig.rrsig().type_covered == set.rtype())
            .collect()
    }
}

/// How an `RRset` is signed.
pub(super) enum Signer {
    /// By a zone at or above a name: the zone's apex.
    Zone(Name<'static>),
    /// By no RRSIG.
    Unsigned,
    /// By RRSIGs none of whose signer is at or above the name (RFC 4035 §5.3.1).
    Misplaced,
}

impl Section {
    /// How `set` is signed, for data that belongs at or below `within`: the signer of its first RRSIG whose
    /// signer is at or above that name (RFC 4035 §5.3.1).
    pub(super) fn signer(&self, set: &RrSet<'_>, within: &Name<'_>) -> Signer {
        let sigs = self.signatures(set);
        if sigs.is_empty() {
            return Signer::Unsigned;
        }
        sigs.iter()
            .map(|sig| &sig.rrsig().signer)
            .find(|signer| within.is_within(signer))
            .map_or(Signer::Misplaced, |signer| {
                Signer::Zone(signer.clone().into_owned())
            })
    }

    /// Whether the section has a record of proof for or against a name's existence: NSEC, NSEC3 or SOA.
    pub(super) fn has_denial(&self) -> bool {
        self.sets.iter().any(|set| {
            matches!(
                set.rtype(),
                RecordType::NSEC | RecordType::NSEC3 | RecordType::SOA
            )
        })
    }
}

/// A name in uncompressed wire form, the RDATA of a DNAME (RFC 6672 §2.1).
fn name_from_wire(mut wire: &[u8]) -> Option<Name<'static>> {
    let mut labels = Vec::new();
    loop {
        let (&len, rest) = wire.split_first()?;
        if len == 0 {
            return rest
                .is_empty()
                .then(|| Name::from_labels(labels).ok())
                .flatten();
        }
        let (label, rest) = rest.split_at_checked(usize::from(len))?;
        labels.push(label);
        wire = rest;
    }
}

/// The name a CNAME or DNAME `RRset` leads to: the first record's target.
fn target(set: &RrSet<'_>) -> Option<Name<'static>> {
    let rdata = set.rdatas().first()?;
    match rdata.data() {
        RData::Cname(name) => Some(name.into_owned()),
        _ if set.rtype() == RecordType::DNAME => name_from_wire(&rdata.wire()),
        _ => None,
    }
}

/// `name` with its suffix `owner` replaced by the DNAME's `target` (RFC 6672 §2.2).
fn substitute(
    name: &Name<'_>,
    owner: &Name<'_>,
    target: &Name<'_>,
) -> Result<Name<'static>, NameError> {
    let prefix = name.label_count().saturating_sub(owner.label_count());
    Name::from_labels(name.labels().take(prefix).chain(target.labels()))
}

/// The DNAME `RRset` that rewrites `name`: one whose owner is a proper ancestor.
fn dname_of<'s>(section: &'s Section, name: &Name<'_>) -> Option<&'s RrSet<'static>> {
    section.sets.iter().find(|set| {
        set.rtype() == RecordType::DNAME && name.is_within(set.owner()) && name != set.owner()
    })
}

/// Where an answer leads from the name asked.
pub(super) struct Chain {
    /// The last name: the one the answer is for, after its CNAMEs and DNAMEs.
    pub(super) end: Name<'static>,
    /// Whether the answer has an `RRset` of the type asked at that name.
    pub(super) found: bool,
    /// How many CNAME and DNAME links were followed.
    pub(super) links: usize,
}

impl Chain {
    /// Follows `section` from the question's name through CNAME and DNAME `RRsets` (RFC 1034 §3.6.2, RFC 6672
    /// §3.1), at most as many links as the section has `RRsets`: a loop ends there.
    pub(super) fn follow(question: &Question<'_>, section: &Section) -> Self {
        let mut end = question.name.clone().into_owned();
        let mut links = 0;
        while links <= section.sets.len() {
            let here = |set: &&RrSet<'_>| set.owner() == &end;
            let wanted = |set: &&RrSet<'_>| {
                question.qtype == RecordType::ANY || set.rtype() == question.qtype
            };
            if section.sets.iter().filter(here).any(|set| wanted(&set)) {
                return Self {
                    end,
                    found: true,
                    links,
                };
            }
            let next = if let Some(cname) = section.find(&end, RecordType::CNAME) {
                target(cname)
            } else if let Some(dname) = dname_of(section, &end) {
                target(dname).and_then(|to| substitute(&end, dname.owner(), &to).ok())
            } else {
                None
            };
            let Some(next) = next else { break };
            end = next;
            links += 1;
        }
        Self {
            end,
            found: false,
            links,
        }
    }
}

/// Whether `cname` is what a DNAME of `section` makes of its owner (RFC 6672 §3.1): the server synthesizes it
/// unsigned, so it is not validated (RFC 6672 §5.3.3).
pub(super) fn synthesized(cname: &RrSet<'_>, section: &Section) -> bool {
    cname.rtype() == RecordType::CNAME
        && dname_of(section, cname.owner()).is_some_and(|dname| {
            target(dname)
                .and_then(|to| substitute(cname.owner(), dname.owner(), &to).ok())
                .is_some_and(|name| target(cname).is_some_and(|got| got == name))
        })
}
