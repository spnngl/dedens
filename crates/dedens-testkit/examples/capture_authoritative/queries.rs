//! The questions put to Knot and NSD for each zone, derived from the zone's own records so that every kind of
//! answer is asked for: data, NODATA, NXDOMAIN, a wildcard's expansion, a delegation, a DNAME, an empty
//! non-terminal, the apex, a name outside the zone.

use std::collections::{HashMap, HashSet};

use dedens_proto::{Name, Record, RecordType};

use crate::Result;

/// A question: the name in the case asked, and the type.
pub(crate) type Asked = (Name<'static>, RecordType);

/// TLDs with a DS and TLDs without, and glue owners, asked for in the root zone: its 1,400 delegations would
/// make the file of answers megabytes for little.
const ROOT_DELEGATIONS_WITH_DS: usize = 3;
const ROOT_DELEGATIONS_WITHOUT_DS: usize = 3;
const ROOT_GLUE_OWNERS: usize = 2;

/// The types tried for NODATA, the first that the owner lacks.
const NODATA_TYPES: [RecordType; 4] = [
    RecordType::A,
    RecordType::AAAA,
    RecordType::TXT,
    RecordType::MX,
];

/// `label` below `name`.
fn below(label: &str, name: &Name<'_>) -> Result<Name<'static>> {
    Ok(Name::from_labels(
        std::iter::once(label.as_bytes()).chain(name.labels()),
    )?)
}

/// The name of `name`'s parent.
fn parent(name: &Name<'_>) -> Result<Name<'static>> {
    Ok(Name::from_labels(name.labels().skip(1))?)
}

/// `name` with the case of its letters alternating, `0x20`-style: a server compares names without case.
fn mixed_case(name: &Name<'_>) -> Result<Name<'static>> {
    let labels: Vec<Vec<u8>> = name
        .labels()
        .map(|label| {
            label
                .iter()
                .enumerate()
                .map(|(i, byte)| {
                    if i % 2 == 0 {
                        byte.to_ascii_uppercase()
                    } else {
                        byte.to_ascii_lowercase()
                    }
                })
                .collect()
        })
        .collect();
    Ok(Name::from_labels(labels.iter().map(Vec::as_slice))?)
}

/// What a zone holds, by owner.
struct Contents {
    /// The owners, in the order of the zone.
    owners: Vec<Name<'static>>,
    /// The types at each owner.
    types: HashMap<Name<'static>, Vec<RecordType>>,
}

impl Contents {
    fn new(records: &[Record<'static>]) -> Self {
        let mut owners = Vec::new();
        let mut types: HashMap<Name<'static>, Vec<RecordType>> = HashMap::new();
        for record in records {
            let at = types.entry(record.name.clone()).or_insert_with(|| {
                owners.push(record.name.clone());
                Vec::new()
            });
            if !at.contains(&record.rtype()) {
                at.push(record.rtype());
            }
        }
        Self { owners, types }
    }

    fn has(&self, owner: &Name<'static>, rtype: RecordType) -> bool {
        self.types.get(owner).is_some_and(|at| at.contains(&rtype))
    }

    /// The owners asked for: all, except in the root zone.
    fn selected(&self, apex: &Name<'static>) -> Vec<Name<'static>> {
        if !apex.is_root() {
            return self.owners.clone();
        }
        let delegations: Vec<&Name<'static>> = self
            .owners
            .iter()
            .filter(|owner| !owner.is_root() && self.has(owner, RecordType::NS))
            .collect();
        let with_ds = delegations
            .iter()
            .filter(|owner| self.has(owner, RecordType::DS))
            .take(ROOT_DELEGATIONS_WITH_DS);
        let without_ds = delegations
            .iter()
            .filter(|owner| !self.has(owner, RecordType::DS))
            .take(ROOT_DELEGATIONS_WITHOUT_DS);
        let glue = self
            .owners
            .iter()
            .filter(|owner| {
                !self.has(owner, RecordType::NS)
                    && (self.has(owner, RecordType::A) || self.has(owner, RecordType::AAAA))
            })
            .take(ROOT_GLUE_OWNERS);
        std::iter::once(apex)
            .chain(with_ds.copied())
            .chain(without_ds.copied())
            .chain(glue)
            .cloned()
            .collect()
    }
}

/// The questions for a zone of `records` under `apex`, without duplicates, in a fixed order.
pub(crate) fn list(apex: &Name<'static>, records: &[Record<'static>]) -> Result<Vec<Asked>> {
    let contents = Contents::new(records);
    let mut asked: Vec<Asked> = Vec::new();
    let mut seen: HashSet<Asked> = HashSet::new();
    let mut ask = |name: Name<'static>, rtype: RecordType| {
        if seen.insert((name.clone(), rtype)) {
            asked.push((name, rtype));
        }
    };
    let nodata = |owner: &Name<'static>| {
        NODATA_TYPES
            .into_iter()
            .find(|rtype| !contents.has(owner, *rtype))
    };
    for owner in contents.selected(apex) {
        let present = contents.types.get(&owner).cloned().unwrap_or_default();
        for rtype in present {
            ask(owner.clone(), rtype);
        }
        ask(owner.clone(), RecordType::ANY);
        if let Some(rtype) = nodata(&owner) {
            ask(owner.clone(), rtype);
        }
        // An empty non-terminal between the owner and the apex.
        let mut ancestor = parent(&owner)?;
        while !ancestor.is_root() && ancestor.is_within(apex) && ancestor != *apex {
            if !contents.types.contains_key(&ancestor) {
                ask(ancestor.clone(), RecordType::A);
            }
            ancestor = parent(&ancestor)?;
        }
        if !owner.is_root() && owner != *apex && contents.has(&owner, RecordType::NS) {
            ask(below("www", &owner)?, RecordType::A);
            ask(owner.clone(), RecordType::DS);
            ask(owner.clone(), RecordType::SOA);
        }
        if contents.has(&owner, RecordType::DNAME) {
            ask(below("dedens-below", &owner)?, RecordType::A);
            ask(below("b", &below("a", &owner)?)?, RecordType::A);
        }
        if owner.labels().next() == Some(&b"*"[..]) {
            let site = parent(&owner)?;
            let name = below("dedens-wild", &site)?;
            for rtype in contents.types.get(&owner).cloned().unwrap_or_default() {
                ask(name.clone(), rtype);
            }
            if let Some(rtype) = nodata(&owner) {
                ask(name.clone(), rtype);
            }
            ask(below("a", &name)?, RecordType::A);
        }
    }
    ask(mixed_case(apex)?, RecordType::SOA);
    ask(below("dedens-nxdomain", apex)?, RecordType::A);
    ask(below("a", &below("dedens-nxdomain", apex)?)?, RecordType::A);
    if !apex.is_root() {
        ask("dedens-outside.invalid.".parse()?, RecordType::A);
    }
    Ok(asked)
}
