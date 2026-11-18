//! An `RRset` and the signatures over it, owned: the unit the resolver caches and reasons on (RFC 2181 §5).

use std::cmp::Ordering;
use std::collections::{HashMap, HashSet};
use std::mem::size_of;

use dedens_cache::Cost;
use dedens_proto::rdata::RData;
use dedens_proto::{Class, Name, Record, RecordType, Ttl, WireRdata};

/// The records of one owner name, class and type (RFC 2181 §5), with the RRSIG records covering them (RFC 4034
/// §3), owned.
///
/// [`Rrset::group`] builds them from the records of a section: duplicates dropped (RFC 2181 §5), the RDATA sorted,
/// and one TTL, the smallest of the records and their signatures (RFC 2181 §5.2).
///
/// Two `RRsets` are equal when they hold the same data: owner name (any case), class, type, records and signatures,
/// whatever order the records came in. The TTL is not data: it only says how long the data may be kept.
#[derive(Debug, Clone)]
pub struct Rrset {
    owner: Name<'static>,
    class: Class,
    rtype: RecordType,
    ttl: Ttl,
    rdatas: Box<[WireRdata<'static>]>,
    rrsigs: Box<[WireRdata<'static>]>,
}

impl Rrset {
    /// The `RRsets` of `records`, the records of one section, in the order their first records come. Each takes the
    /// RRSIG records at its name and class covering its type; signatures covering no `RRset` of `records` are
    /// dropped, and so are the records of the QTYPEs and meta types and those of the QCLASSes, which are not data
    /// (RFC 6895 §3.1, §3.2).
    ///
    /// Memory linear in the number of records, work too but for the sort of each `RRset`'s RDATA: each record finds
    /// its `RRset` by hash, and each RDATA its duplicate, even among RDATA that differs only in case.
    #[must_use]
    pub fn group(records: &[Record<'_>]) -> Vec<Self> {
        let mut sets: Vec<Building<'_, '_>> = Vec::with_capacity(records.len());
        let mut index: HashMap<(&Name<'_>, RecordType, Class), usize> =
            HashMap::with_capacity(records.len());
        let data = records.iter().filter(|r| data_class(r.class));
        let covered = data
            .clone()
            .filter(|r| r.rtype() != RecordType::RRSIG && data_type(r.rtype()));
        for record in covered {
            let rdata = record.rdata.clone().into_owned();
            let at = *index
                .entry((&record.name, record.rtype(), record.class))
                .or_insert_with(|| {
                    sets.push(Building {
                        first: record,
                        ttl: record.ttl,
                        rdatas: Vec::new(),
                        rrsigs: Vec::new(),
                    });
                    sets.len() - 1
                });
            let set = &mut sets[at];
            set.ttl = set.ttl.min(record.ttl);
            set.rdatas.push(rdata);
        }
        for record in data.filter(|r| r.rtype() == RecordType::RRSIG) {
            let RData::Rrsig(rrsig) = record.data() else {
                continue;
            };
            if let Some(&at) = index.get(&(&record.name, rrsig.type_covered, record.class)) {
                let set = &mut sets[at];
                set.ttl = set.ttl.min(record.ttl);
                set.rrsigs.push(record.rdata.clone().into_owned());
            }
        }
        sets.into_iter()
            .map(|set| Self {
                owner: set.first.name.clone().into_owned(),
                class: set.first.class,
                rtype: set.first.rtype(),
                ttl: set.ttl,
                rdatas: canonical(set.rdatas),
                rrsigs: canonical(set.rrsigs),
            })
            .collect()
    }

    /// The owner name, in the case of its first record.
    #[must_use]
    pub const fn owner(&self) -> &Name<'static> {
        &self.owner
    }

    /// The class.
    #[must_use]
    pub const fn class(&self) -> Class {
        self.class
    }

    /// The type.
    #[must_use]
    pub const fn rtype(&self) -> RecordType {
        self.rtype
    }

    /// The TTL received, the smallest of the records and their signatures (RFC 2181 §5.2), or as
    /// [`Rrset::cap_ttl`] lowered it: what the cache bounds into the time it keeps the `RRset`. What is left of
    /// that time is the `ttl` of a cache hit.
    #[must_use]
    pub const fn ttl(&self) -> Ttl {
        self.ttl
    }

    /// Lowers the TTL to `cap`, if above. A validator that accepts the `RRset` as authentic caps it to the least of
    /// the Original TTL of the RRSIG that proved it and the seconds left to that RRSIG's Signature Expiration
    /// (RFC 4035 §5.3.3; the TTLs received are in [`Rrset::ttl`] already), then caches it
    /// [`Checked::Secure`](dedens_cache::Checked::Secure), whose lifetime has no floor: an `RRset` is never kept
    /// past its signature.
    pub fn cap_ttl(&mut self, cap: Ttl) {
        self.ttl = self.ttl.min(cap);
    }

    /// The RDATA of the records, without duplicates, sorted.
    #[must_use]
    pub fn rdatas(&self) -> &[WireRdata<'static>] {
        &self.rdatas
    }

    /// The RDATA of the RRSIG records covering the `RRset`, without duplicates, sorted.
    #[must_use]
    pub fn rrsigs(&self) -> &[WireRdata<'static>] {
        &self.rrsigs
    }
}

/// The heap bytes an `RRset` takes behind an `Arc`, as the cache holds it: the `Arc`'s allocation, the owner name
/// and the RDATA, each counted as the allocator is asked for it (`tests/memory.rs` checks it on captures). The
/// allocator's own rounding and bookkeeping are not counted (D193).
impl Cost for Rrset {
    fn cost(&self) -> usize {
        let rdata = |rdatas: &[WireRdata<'_>]| {
            rdatas
                .iter()
                .map(|r| size_of::<WireRdata<'_>>() + r.wire().len())
                .sum::<usize>()
        };
        2 * size_of::<usize>()
            + size_of::<Self>()
            + self.owner.wire_len()
            + rdata(&self.rdatas)
            + rdata(&self.rrsigs)
    }
}

impl PartialEq for Rrset {
    fn eq(&self, other: &Self) -> bool {
        self.owner == other.owner
            && self.class == other.class
            && self.rtype == other.rtype
            && same_rdatas(&self.rdatas, &other.rdatas)
            && same_rdatas(&self.rrsigs, &other.rrsigs)
    }
}

impl Eq for Rrset {}

/// An `RRset` of [`Rrset::group`] being gathered, from its first record.
struct Building<'r, 'a> {
    first: &'r Record<'a>,
    ttl: Ttl,
    rdatas: Vec<WireRdata<'static>>,
    rrsigs: Vec<WireRdata<'static>>,
}

/// Whether records of `rtype` are data: not 0, OPT, the QTYPEs and meta types of 128 to 255 nor the reserved 65535
/// (RFC 6895 §3.1).
fn data_type(rtype: RecordType) -> bool {
    rtype != RecordType::OPT && !matches!(u16::from(rtype), 0 | 128..=255 | 65535)
}

/// Whether records of `class` are data: not the reserved 0 and 65535, nor the QCLASSes NONE (254) and ANY (255)
/// (RFC 6895 §3.2).
fn data_class(class: Class) -> bool {
    !matches!(u16::from(class), 0 | 254 | 255 | 65535)
}

/// Orders RDATA by wire bytes, ASCII letters folded. Equal RDATA, whose names may differ in case only (RFC 4343),
/// folds to the same bytes: it sorts together.
fn folded(a: &WireRdata<'_>, b: &WireRdata<'_>) -> Ordering {
    let (a, b) = (a.wire(), b.wire());
    a.iter()
        .map(u8::to_ascii_lowercase)
        .cmp(b.iter().map(u8::to_ascii_lowercase))
}

/// The runs of `rdatas`, sorted by [`folded`]: the RDATA folding the same, which holds duplicates (names differing
/// in case only, RFC 4343) and RDATA unequal but for the case of bytes not in names (a TXT string, an RRSIG
/// signature), of which an attacker may send thousands.
fn runs<'r, 'a>(rdatas: &'r [WireRdata<'a>]) -> impl Iterator<Item = &'r [WireRdata<'a>]> {
    rdatas.chunk_by(|x, y| folded(x, y).is_eq())
}

/// `rdatas` sorted by [`folded`], duplicates dropped (RFC 2181 §5) by hash, as [`WireRdata`]'s `Hash` and `Eq`
/// read the data, names in any case. Duplicates sort into one of the [`runs`]: without a run longer than one, the
/// usual, nothing is hashed. The sort is stable: a run keeps the order it came in, and the first of duplicates.
/// Moved into a slice of their size: shrinking the `Vec`, grown by pushes, cost a sixth more on a zone
/// (`docs/benchmarks.md`).
fn canonical(mut rdatas: Vec<WireRdata<'static>>) -> Box<[WireRdata<'static>]> {
    rdatas.sort_by(folded);
    if runs(&rdatas).any(|run| run.len() > 1) {
        let first: Vec<bool> = {
            let mut seen = HashSet::with_capacity(rdatas.len());
            rdatas.iter().map(|rdata| seen.insert(rdata)).collect()
        };
        let mut first = first.into_iter();
        rdatas.retain(|_| first.next() == Some(true));
    }
    rdatas.drain(..).collect()
}

/// Whether `a` and `b`, each of [`canonical`], hold the same RDATA, in whatever order within their [`runs`]: a run
/// of one is compared alone, a longer one by hash. Without duplicates, runs of one length are equal when every RDATA
/// of one is in the other.
fn same_rdatas(a: &[WireRdata<'_>], b: &[WireRdata<'_>]) -> bool {
    a.len() == b.len()
        && runs(a).zip(runs(b)).all(|(a, b)| match (a, b) {
            ([a], [b]) => a == b,
            _ if a.len() == b.len() => {
                let a: HashSet<&WireRdata<'_>> = a.iter().collect();
                b.iter().all(|rdata| a.contains(rdata))
            }
            _ => false,
        })
}
