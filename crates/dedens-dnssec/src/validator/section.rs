//! A section of a response as `RRsets` with their signatures, and the names an answer leads along (RFC 1034
//! §3.6.2, RFC 6672 §2.2, §3.1).

use std::collections::{HashMap, HashSet};

use dedens_proto::name::NameError;
use dedens_proto::{Class, Name, Question, RData, Record, RecordType};

use crate::rrsig::{RrSet, Signature};

/// The `RRsets` of one section, class IN, and the RRSIG records among them, indexed by owner and type, and
/// grouped by the owner and type they cover once, so that finding the signatures of an `RRset` reads only
/// those (an owner with many types and many signatures costs no more than its records).
#[derive(Debug)]
pub(super) struct Section {
    pub(super) sets: Vec<RrSet<'static>>,
    index: HashMap<(Name<'static>, RecordType), usize>,
    /// The RRSIG records of each owner and type covered, as an `RRset` of RRSIGs.
    sigs: HashMap<(Name<'static>, RecordType), RrSet<'static>>,
}

impl Section {
    pub(super) fn new(records: &[Record<'static>]) -> Self {
        let (sig_records, data): (Vec<_>, Vec<_>) = records
            .iter()
            .filter(|record| record.class == Class::IN)
            .cloned()
            .partition(|record| record.rtype() == RecordType::RRSIG);
        let sets = RrSet::group(&data);
        let index = sets
            .iter()
            .enumerate()
            .map(|(at, set)| ((set.owner().clone(), set.rtype()), at))
            .collect();
        // One pass over the RRSIG records: each is read once, to learn what it covers.
        let mut covering: HashMap<(Name<'static>, RecordType), Vec<Record<'static>>> =
            HashMap::new();
        for record in sig_records {
            if let RData::Rrsig(rrsig) = record.data() {
                covering
                    .entry((record.name.clone(), rrsig.type_covered))
                    .or_default()
                    .push(record);
            }
        }
        let sigs = covering
            .into_iter()
            .filter_map(|(key, records)| Some((key, RrSet::group(&records).pop()?)))
            .collect();
        Self { sets, index, sigs }
    }

    /// The `RRset` of `owner` and `rtype`.
    pub(super) fn find(&self, owner: &Name<'_>, rtype: RecordType) -> Option<&RrSet<'static>> {
        let at = self.index.get(&(owner.clone().into_owned(), rtype))?;
        self.sets.get(*at)
    }

    /// The RRSIGs of the section that cover `set`, in the order they come.
    pub(super) fn signatures(&self, set: &RrSet<'_>) -> Vec<Signature<'_>> {
        self.sigs
            .get(&(set.owner().clone().into_owned(), set.rtype()))
            .map(Signature::all)
            .unwrap_or_default()
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

/// The name a CNAME or DNAME `RRset` leads to: the first record's target.
fn target(set: &RrSet<'_>) -> Option<Name<'static>> {
    let rdata = set.rdatas().first()?;
    match rdata.data() {
        RData::Cname(name) => Some(name.into_owned()),
        _ if set.rtype() == RecordType::DNAME => Name::from_uncompressed(&rdata.wire())
            .ok()
            .map(Name::into_owned),
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
    /// Every name the answer passed through, the one asked and the last included: the owners an answer may
    /// have `RRsets` at (RFC 1034 §3.6.2, RFC 6672 §3.1).
    pub(super) names: HashSet<Name<'static>>,
}

impl Chain {
    /// Whether an `RRset` of the answer section belongs to the answer: its owner is a name of the chain, or the
    /// owner of a DNAME that rewrote one. Others are out of bailiwick: nothing checks them, and the verdict
    /// says nothing of them (D75).
    pub(super) fn answers(&self, set: &RrSet<'_>) -> bool {
        self.names.contains(set.owner())
            || (set.rtype() == RecordType::DNAME
                && self
                    .names
                    .iter()
                    .any(|name| name != set.owner() && name.is_within(set.owner())))
    }

    /// Whether an `RRset` of the authority section that is no proof of denial is about the answer: its owner is
    /// a name of the chain or above one, as the NS and DS records of the zone cut an answer came from are.
    pub(super) fn about(&self, set: &RrSet<'_>) -> bool {
        self.names.iter().any(|name| name.is_within(set.owner()))
    }
}

impl Chain {
    /// Follows `section` from the question's name through CNAME and DNAME `RRsets` (RFC 1034 §3.6.2, RFC 6672
    /// §3.1), at most as many links as the section has `RRsets`: a loop ends there.
    pub(super) fn follow(question: &Question<'_>, section: &Section) -> Self {
        let mut end = question.name.clone().into_owned();
        let mut names = HashSet::from([end.clone()]);
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
                    names,
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
            names.insert(next.clone());
            end = next;
            links += 1;
        }
        Self {
            end,
            found: false,
            links,
            names,
        }
    }
}

/// Whether `cname` is what a DNAME of `section` makes of its owner (RFC 6672 §3.1): the server synthesizes it
/// unsigned, so it is not validated (RFC 6672 §5.3.3). Every record of the set is that one: a set with another
/// record is not the DNAME's doing, and is checked as any other.
pub(super) fn synthesized(cname: &RrSet<'_>, section: &Section) -> bool {
    cname.rtype() == RecordType::CNAME
        && !cname.rdatas().is_empty()
        && dname_of(section, cname.owner()).is_some_and(|dname| {
            target(dname)
                .and_then(|to| substitute(cname.owner(), dname.owner(), &to).ok())
                .is_some_and(|name| {
                    cname
                        .rdatas()
                        .iter()
                        .all(|rdata| matches!(rdata.data(), RData::Cname(got) if got == name))
                })
        })
}

#[cfg(test)]
mod tests {
    use dedens_proto::rdata::{Opaque, Rrsig};
    use dedens_proto::{SecAlgorithm, Ttl, WireRdata};

    use super::*;

    fn rrsig_record(owner: &Name<'static>, covered: RecordType, tag: u16) -> Record<'static> {
        let rrsig = Rrsig::new(
            covered,
            SecAlgorithm(13),
            1,
            3600,
            2,
            1,
            tag,
            owner.clone(),
            &[0; 64],
        )
        .expect("an RRSIG");
        Record {
            name: owner.clone(),
            class: Class::IN,
            ttl: Ttl::from_wire(3600),
            rdata: WireRdata::new(&RData::Rrsig(rrsig)),
        }
    }

    /// An owner with many types and two RRSIGs for each: the signatures of a set are those of its type alone,
    /// grouped once, not found by reading every RRSIG of the owner for every set (D75).
    #[test]
    fn the_signatures_of_a_set_are_those_of_its_type() {
        let owner: Name<'static> = "junk.example".parse().expect("a name");
        let mut records = Vec::new();
        for n in 0..700_u16 {
            let rtype = RecordType(1000 + n);
            records.push(rrsig_record(&owner, rtype, n));
            records.push(rrsig_record(&owner, rtype, n + 1));
        }
        let section = Section::new(&records);
        assert!(section.sets.is_empty());
        assert_eq!(section.sigs.len(), 700);
        for set in section.sigs.values() {
            assert_eq!(set.rdatas().len(), 2);
        }
        let data = Record {
            name: owner.clone(),
            class: Class::IN,
            ttl: Ttl::from_wire(60),
            rdata: WireRdata::new(&RData::Opaque(
                Opaque::new(RecordType(1005), &[1]).expect("opaque"),
            )),
        };
        let signed = Section::new(&[
            data,
            rrsig_record(&owner, RecordType(1005), 5),
            rrsig_record(&owner, RecordType(1006), 6),
        ]);
        let set = signed.sets.first().expect("a set");
        let sigs = signed.signatures(set);
        assert_eq!(sigs.len(), 1);
        assert_eq!(sigs.first().map(|sig| sig.rrsig().key_tag), Some(5));
    }
}
