//! The `RRset`, and the records its signature is made of (RFC 4034 §6, RFC 2181 §5).

use std::borrow::Cow;
use std::collections::HashMap;

use dedens_proto::rdata::{Dnskey, RData, Rrsig};
use dedens_proto::{Class, Name, Record, RecordType, Ttl, WireRdata};

use super::canonical;
use crate::crypto;

/// The records of one owner, class and type (RFC 2181 §5): the unit a signature covers.
///
/// Never empty. Its TTL is the lowest of its records, as RFC 2181 §5.2 has it when they differ.
#[derive(Debug, Clone)]
pub struct RrSet<'a> {
    owner: Name<'a>,
    class: Class,
    rtype: RecordType,
    ttl: Ttl,
    rdatas: Vec<WireRdata<'a>>,
}

impl<'a> RrSet<'a> {
    /// The `RRsets` of `records`, in the order their first record appears: records of the same owner (whatever
    /// the case, RFC 4343), class and type are one `RRset`.
    #[must_use]
    pub fn group(records: &[Record<'a>]) -> Vec<Self> {
        let mut index: HashMap<_, usize> = HashMap::new();
        let mut sets: Vec<Self> = Vec::new();
        for record in records {
            let key: (Name<'a>, _, _) = (record.name.clone(), record.class, record.rtype());
            if let Some(set) = index.get(&key).and_then(|&i| sets.get_mut(i)) {
                set.ttl = set.ttl.min(record.ttl);
                set.rdatas.push(record.rdata.clone());
            } else {
                index.insert(key, sets.len());
                sets.push(Self {
                    owner: record.name.clone(),
                    class: record.class,
                    rtype: record.rtype(),
                    ttl: record.ttl,
                    rdatas: vec![record.rdata.clone()],
                });
            }
        }
        sets
    }

    /// The same `RRset`, owning its bytes.
    #[must_use]
    pub fn into_owned(self) -> RrSet<'static> {
        RrSet {
            owner: self.owner.into_owned(),
            class: self.class,
            rtype: self.rtype,
            ttl: self.ttl,
            rdatas: self.rdatas.into_iter().map(WireRdata::into_owned).collect(),
        }
    }

    /// The owner name.
    #[must_use]
    pub const fn owner(&self) -> &Name<'a> {
        &self.owner
    }

    /// The class.
    #[must_use]
    pub const fn class(&self) -> Class {
        self.class
    }

    /// The type of its records.
    #[must_use]
    pub const fn rtype(&self) -> RecordType {
        self.rtype
    }

    /// The lowest TTL of its records.
    #[must_use]
    pub const fn ttl(&self) -> Ttl {
        self.ttl
    }

    /// The RDATA of its records, as received (duplicates included).
    #[must_use]
    pub fn rdatas(&self) -> &[WireRdata<'a>] {
        &self.rdatas
    }

    /// The RDATA in canonical form and order, duplicates dropped (RFC 4034 §6.2 item 3, §6.3; RFC 6840 §5.1).
    #[must_use]
    pub fn canonical_rdatas(&self) -> Vec<Vec<u8>> {
        let mut rdatas: Vec<Vec<u8>> = self
            .rdatas
            .iter()
            .map(|rdata| canonical::rdata(self.rtype, &rdata.wire()))
            .collect();
        rdatas.sort_unstable();
        rdatas.dedup();
        rdatas
    }
}

/// An RRSIG record to check an `RRset` with: where it was published, its TTL and its fields.
#[derive(Debug, Clone)]
pub struct Signature<'k> {
    pub(super) owner: &'k Name<'k>,
    pub(super) class: Class,
    pub(super) ttl: Ttl,
    pub(super) rrsig: Rrsig<'k>,
}

impl<'k> Signature<'k> {
    /// The RRSIG records of `rrsigs`, an `RRset` of that type; records of another type or RDATA invalid for it
    /// are left out.
    #[must_use]
    pub fn all(rrsigs: &'k RrSet<'_>) -> Vec<Self> {
        rrsigs
            .rdatas
            .iter()
            .filter_map(|rdata| match rdata.data() {
                RData::Rrsig(rrsig) => Some(Self {
                    owner: &rrsigs.owner,
                    class: rrsigs.class,
                    ttl: rrsigs.ttl,
                    rrsig,
                }),
                _ => None,
            })
            .collect()
    }

    /// The fields of the RRSIG.
    #[must_use]
    pub const fn rrsig(&self) -> &Rrsig<'k> {
        &self.rrsig
    }

    /// Whether RFC 4035 §5.3.1's first condition holds: same owner, class and type covered.
    pub(super) fn covers(&self, rrset: &RrSet<'_>) -> bool {
        self.rrsig.type_covered == rrset.rtype
            && self.class == rrset.class
            && *self.owner == rrset.owner
    }
}

/// A DNSKEY record to check signatures with: where it was published, its key tag and its fields.
///
/// A DNSKEY whose protocol is not 3 (RFC 4034 §2.1.2) is no [`Key`]: it decodes as opaque RDATA.
#[derive(Debug, Clone)]
pub struct Key<'k> {
    pub(super) owner: &'k Name<'k>,
    pub(super) class: Class,
    pub(super) dnskey: Dnskey<'k>,
    /// The RDATA, which the key tag and the DS digests are computed over.
    pub(super) wire: Cow<'k, [u8]>,
    pub(super) tag: u16,
}

impl<'k> Key<'k> {
    /// The DNSKEY records of `dnskeys`, an `RRset` of that type; records of another type or RDATA invalid for it
    /// are left out.
    #[must_use]
    pub fn all(dnskeys: &'k RrSet<'_>) -> Vec<Self> {
        dnskeys
            .rdatas
            .iter()
            .filter_map(|rdata| match rdata.data() {
                RData::Dnskey(dnskey) => {
                    let wire = rdata.wire();
                    Some(Self {
                        owner: &dnskeys.owner,
                        class: dnskeys.class,
                        dnskey,
                        tag: crypto::key_tag(&wire),
                        wire,
                    })
                }
                _ => None,
            })
            .collect()
    }

    /// The fields of the DNSKEY.
    #[must_use]
    pub const fn dnskey(&self) -> &Dnskey<'k> {
        &self.dnskey
    }

    /// The key tag (RFC 4034 Appendix B).
    #[must_use]
    pub const fn tag(&self) -> u16 {
        self.tag
    }

    /// Whether `sig` names this key (RFC 4035 §5.3.1): signer, algorithm and key tag.
    pub(super) fn matches(&self, sig: &Signature<'_>) -> bool {
        self.tag == sig.rrsig.key_tag
            && self.dnskey.algorithm() == sig.rrsig.algorithm
            && self.class == sig.class
            && *self.owner == sig.rrsig.signer
    }
}
