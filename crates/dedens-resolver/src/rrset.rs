//! An `RRset` and the signatures over it, owned: the unit the resolver caches and reasons on (RFC 2181 §5).

use std::mem::size_of;

use dedens_proto::rdata::RData;
use dedens_proto::{Class, Name, Record, RecordType, Ttl, WireRdata};

/// The records of one owner name, class and type (RFC 2181 §5), with the RRSIG records covering them (RFC 4034
/// §3), owned.
///
/// [`Rrset::group`] builds them from the records of a section: duplicates dropped (RFC 2181 §5), the RDATA in one
/// order, so that two `RRsets` of the same data compare equal whatever order their records came in, and one TTL,
/// the smallest of the records and their signatures (RFC 2181 §5.2).
///
/// Two `RRsets` are equal when they hold the same data: owner name (any case), class, type, records and signatures.
/// The TTL is not data: it only says how long the data may be kept.
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
    /// dropped, and so are the records of the QTYPEs and meta types, which are not data (RFC 6895 §3.1).
    #[must_use]
    pub fn group(records: &[Record<'_>]) -> Vec<Self> {
        let mut sets: Vec<Building<'_, '_>> = Vec::new();
        for record in records
            .iter()
            .filter(|r| data_type(r.rtype()) && r.rtype() != RecordType::RRSIG)
        {
            let rdata = record.rdata.clone().into_owned();
            match sets.iter_mut().find(|s| s.holds(record, record.rtype())) {
                Some(set) => {
                    set.ttl = set.ttl.min(record.ttl);
                    set.rdatas.push(rdata);
                }
                None => sets.push(Building {
                    first: record,
                    ttl: record.ttl,
                    rdatas: vec![rdata],
                    rrsigs: Vec::new(),
                }),
            }
        }
        for record in records.iter().filter(|r| r.rtype() == RecordType::RRSIG) {
            let RData::Rrsig(rrsig) = record.data() else {
                continue;
            };
            if let Some(set) = sets
                .iter_mut()
                .find(|s| s.holds(record, rrsig.type_covered))
            {
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

    /// The TTL received: the smallest of the records and their signatures (RFC 2181 §5.2).
    #[must_use]
    pub const fn ttl(&self) -> Ttl {
        self.ttl
    }

    /// The RDATA of the records, without duplicates, in one order.
    #[must_use]
    pub fn rdatas(&self) -> &[WireRdata<'static>] {
        &self.rdatas
    }

    /// The RDATA of the RRSIG records covering the `RRset`, without duplicates, in one order.
    #[must_use]
    pub fn rrsigs(&self) -> &[WireRdata<'static>] {
        &self.rrsigs
    }

    /// Heap bytes the `RRset` takes behind an `Arc`: the `Arc`'s allocation, the owner name and the RDATA, each
    /// counted as the allocator was asked for it.
    pub(crate) fn cost(&self) -> usize {
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
            && self.rdatas == other.rdatas
            && self.rrsigs == other.rrsigs
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

impl Building<'_, '_> {
    /// Whether `record`, of type `rtype` or covering it, belongs to this `RRset`: same type, class and owner name,
    /// whatever its case (RFC 4343).
    fn holds(&self, record: &Record<'_>, rtype: RecordType) -> bool {
        self.first.rtype() == rtype
            && self.first.class == record.class
            && self.first.name == record.name
    }
}

/// Whether records of `rtype` are data: not 0, OPT, the QTYPEs and meta types of 128 to 255 nor the reserved 65535
/// (RFC 6895 §3.1).
fn data_type(rtype: RecordType) -> bool {
    rtype != RecordType::OPT && !matches!(u16::from(rtype), 0 | 128..=255 | 65535)
}

/// `rdatas` in one order, duplicates dropped (RFC 2181 §5): by wire bytes, ASCII letters folded, then by the bytes
/// themselves. Names in RDATA compare case-insensitively (RFC 4343), so two spellings of one name end up side by
/// side and only the first stays.
fn canonical(mut rdatas: Vec<WireRdata<'static>>) -> Box<[WireRdata<'static>]> {
    rdatas.sort_by(|a, b| {
        let (a, b) = (a.wire(), b.wire());
        let folded = a
            .iter()
            .map(u8::to_ascii_lowercase)
            .cmp(b.iter().map(u8::to_ascii_lowercase));
        folded.then_with(|| a.cmp(&b))
    });
    rdatas.dedup();
    rdatas.into_boxed_slice()
}
