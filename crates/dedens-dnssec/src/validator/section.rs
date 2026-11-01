//! A section of a response as `RRsets` with their signatures, and the names an answer leads along (RFC 1034
//! §3.6.2, RFC 6672 §2.2, §3.1).

use std::collections::HashMap;

use dedens_proto::name::NameError;
use dedens_proto::{Class, Name, Question, RData, Record, RecordType};

use crate::rrsig::{RrSet, Signature};

/// The `RRsets` of one section, class IN, and the RRSIG `RRsets` among them, indexed by owner and type.
#[derive(Debug)]
pub(super) struct Section {
    pub(super) sets: Vec<RrSet<'static>>,
    index: HashMap<(Name<'static>, RecordType), usize>,
    sigs: Vec<RrSet<'static>>,
    sigs_of: HashMap<Name<'static>, Vec<usize>>,
}

impl Section {
    pub(super) fn new(records: &[Record<'static>]) -> Self {
        let (sigs, sets): (Vec<_>, Vec<_>) = RrSet::group(records)
            .into_iter()
            .filter(|set| set.class() == Class::IN)
            .partition(|set| set.rtype() == RecordType::RRSIG);
        let index = sets
            .iter()
            .enumerate()
            .map(|(at, set)| ((set.owner().clone(), set.rtype()), at))
            .collect();
        let mut sigs_of: HashMap<Name<'static>, Vec<usize>> = HashMap::new();
        for (at, set) in sigs.iter().enumerate() {
            sigs_of.entry(set.owner().clone()).or_default().push(at);
        }
        Self {
            sets,
            index,
            sigs,
            sigs_of,
        }
    }

    /// The `RRset` of `owner` and `rtype`.
    pub(super) fn find(&self, owner: &Name<'_>, rtype: RecordType) -> Option<&RrSet<'static>> {
        let at = self.index.get(&(owner.clone().into_owned(), rtype))?;
        self.sets.get(*at)
    }

    /// The RRSIGs of the section that cover `set`, in the order they come.
    pub(super) fn signatures(&self, set: &RrSet<'_>) -> Vec<Signature<'_>> {
        self.sigs_of
            .get(set.owner())
            .into_iter()
            .flatten()
            .filter_map(|at| self.sigs.get(*at))
            .flat_map(|sigs| Signature::all(sigs))
            .filter(|sig| sig.rrsig().type_covered == set.rtype())
            .collect()
    }

    /// Whether the section has a record of proof for or against a name's existence: NSEC, NSEC3 or SOA.
    pub(super) fn has_denial(&self) -> bool {
        self.sets.iter().any(|set| is_denial(set.rtype()))
    }
}

/// Whether records of `rtype` are the proof of a denial: NSEC, NSEC3 or the SOA that bounds it (RFC 4035 §5.4).
pub(super) const fn is_denial(rtype: RecordType) -> bool {
    matches!(
        rtype,
        RecordType::NSEC | RecordType::NSEC3 | RecordType::SOA
    )
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
pub(super) fn dname_of<'s>(section: &'s Section, name: &Name<'_>) -> Option<&'s RrSet<'static>> {
    (1..=name.label_count()).find_map(|skip| {
        let ancestor = Name::from_labels(name.labels().skip(skip)).ok()?;
        section.find(&ancestor, RecordType::DNAME)
    })
}

/// Where an answer leads from the name asked.
#[derive(Debug)]
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
            let present = if question.qtype == RecordType::ANY {
                section.sets.iter().any(|set| set.owner() == &end)
            } else {
                section.find(&end, question.qtype).is_some()
            };
            if present {
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
