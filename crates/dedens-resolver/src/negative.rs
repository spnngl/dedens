//! What the `RRset` cache keeps beside `RRsets`: negative answers (RFC 2308) and failure holds (RFC 9520), entries
//! of the same store and so of the same byte budget (D193, D199).
//!
//! Their keys start with a byte no name's wire form starts with, so they never meet an `RRset`'s: a name's first
//! octet is a label length, at most 63.

use std::mem::size_of;
use std::sync::Arc;

use dedens_cache::{Checked, Config, Cost};
use dedens_proto::rdata::RData;
use dedens_proto::{RecordType, Ttl};

use crate::rank::Rank;
use crate::resolution::Failure;
use crate::rrset::Rrset;
use crate::rrset_cache::Ranked;

/// What a negative answer says is not there (RFC 2308 §2).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    /// The name does not exist (RFC 2308 §2.1): nothing is below it either, if proven (RFC 8020).
    NxDomain,
    /// The name has no record of the type (RFC 2308 §2.2).
    NoData(RecordType),
}

impl Kind {
    /// The type a key carries: ANY for a name that does not exist, no type of its own.
    pub(crate) const fn key_type(self) -> RecordType {
        match self {
            Self::NxDomain => RecordType::ANY,
            Self::NoData(rtype) => rtype,
        }
    }
}

/// A negative answer the cache holds: the zone's SOA and the denials that prove it, each with the time the entry has
/// left as its TTL, and the verdict they were stored with.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Denied {
    /// The zone's SOA, without which a denial is not taken (RFC 2308 §5).
    pub soa: Ranked,
    /// The NSEC and NSEC3 `RRsets` proving it (RFC 4035 §3.1.3).
    pub denials: Vec<Ranked>,
}

/// A negative answer stored: its sets, the SOA first, as they were judged together.
#[derive(Debug)]
pub(crate) struct Absent {
    kind: Kind,
    sets: Box<[(Arc<Rrset>, Rank)]>,
    checked: Checked,
    /// The time it was stored for.
    ttl: u32,
    /// The time it is no longer fresh at.
    expires: u32,
}

impl Absent {
    /// The answer of `soa` and `denials`, stored for `ttl` seconds from `now`.
    pub(crate) fn new(
        kind: Kind,
        soa: &Ranked,
        denials: &[Ranked],
        checked: Checked,
        ttl: u32,
        now: u32,
    ) -> Self {
        let set = |ranked: &Ranked| (Arc::clone(&ranked.rrset), ranked.rank);
        Self {
            kind,
            sets: std::iter::once(soa).chain(denials).map(set).collect(),
            checked,
            ttl,
            expires: now.saturating_add(ttl),
        }
    }

    /// The seconds left at `now`, 0 once expired.
    fn left(&self, now: u32) -> u32 {
        self.expires.saturating_sub(now).min(self.ttl)
    }

    /// The answer as a hit for `kind` at `now`, if fresh and of that kind: every set with the time left.
    pub(crate) fn hit(&self, kind: Kind, now: u32) -> Option<Denied> {
        let left = self.left(now);
        if left == 0 || self.kind != kind {
            return None;
        }
        let ranked = |(rrset, rank): &(Arc<Rrset>, Rank)| Ranked {
            rrset: Arc::clone(rrset),
            rank: *rank,
            checked: self.checked,
            ttl: Ttl::from_wire(left),
        };
        let (soa, denials) = self.sets.split_first()?;
        Some(Denied {
            soa: ranked(soa),
            denials: denials.iter().map(ranked).collect(),
        })
    }

    /// Whether `new` replaces this answer at `now`, as an `RRset` does (`Cached::merge`): an expired one gives way to
    /// anything; one judged secure to nothing less, and an unchecked one to nothing but a verdict; the same data does not renew it, which would lengthen its
    /// life; other data of equal trust, the last heard of, does.
    pub(crate) fn replaced_by(&self, new: &Self, now: u32) -> bool {
        if self.left(now) == 0 {
            return true;
        }
        let verdict = |absent: &Self| match absent.checked {
            Checked::Secure => 2,
            Checked::Insecure => 1,
            _ => 0,
        };
        let same = self.kind == new.kind
            && self.sets.len() == new.sets.len()
            && (self.sets.iter().zip(&new.sets)).all(|(held, offered)| held.0 == offered.0);
        match verdict(new).cmp(&verdict(self)) {
            std::cmp::Ordering::Greater => true,
            std::cmp::Ordering::Equal => !same,
            std::cmp::Ordering::Less => false,
        }
    }
}

impl Cost for Absent {
    fn cost(&self) -> usize {
        size_of::<Self>()
            + size_of_val(&*self.sets)
            + self.sets.iter().map(|(set, _)| set.cost()).sum::<usize>()
    }
}

/// The seconds a negative answer of `soa` and `denials` lives, `checked`: the least of their TTLs and the SOA's
/// MINIMUM field (RFC 2308 §5), bounded as a negative response is (D124, [`Config::negative_lifetime`]). `None` for
/// a TTL of 0, and for an SOA whose MINIMUM cannot be read.
pub(crate) fn lifetime(
    config: &Config,
    soa: &Ranked,
    denials: &[Ranked],
    checked: Checked,
) -> Option<u32> {
    let minimum = soa
        .rrset
        .rdatas()
        .iter()
        .find_map(|rdata| match rdata.data() {
            RData::Soa(soa) => Some(soa.minimum),
            _ => None,
        })?;
    let ttl = std::iter::once(soa)
        .chain(denials)
        .map(|ranked| ranked.ttl.min(ranked.rrset.ttl()))
        .min()?;
    config.negative_lifetime(ttl.min(Ttl::from_wire(minimum)), checked)
}

/// Which servers a failure hold is of: a hash, keyed, of the zone and the names of the servers of its delegation
/// (D199), so that a question held when a delegation's servers fail is asked again when the delegation changes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct ServerSet(pub(crate) u64);

impl ServerSet {
    /// The octets of the hash in a key.
    pub(crate) const fn bytes(self) -> [u8; 8] {
        self.0.to_be_bytes()
    }
}

/// A failure held, so that it is not asked again at once (RFC 9520 §3.2).
#[derive(Debug, Clone, Copy)]
pub(crate) struct Hold {
    failure: Failure,
    /// How long it holds, the first failure's [`Config::failure_min`] doubled with each further one, at most
    /// [`Config::failure_max`].
    length: u32,
    /// The time it ends at.
    until: u32,
}

impl Hold {
    /// The hold of a first failure at `now`.
    pub(crate) const fn first(failure: Failure, config: &Config, now: u32) -> Self {
        let length = shortest(config);
        Self {
            failure,
            length,
            until: now.saturating_add(length),
        }
    }

    /// The failure held at `now`, until the hold ends: not one that would outlast `failure_max` (a clock gone back,
    /// as the response cache reads it).
    pub(crate) const fn active(&self, config: &Config, now: u32) -> Option<Failure> {
        if now < self.until && self.until - now <= config.failure_max {
            Some(self.failure)
        } else {
            None
        }
    }

    /// Takes `failure`, heard at `now`, into this hold: one heard during the hold counts for nothing (the question
    /// was not asked); one after it doubles the hold, unless a quiet spell as long as the longest hold went by,
    /// which starts again (RFC 9520 §3.2: back off, at most 5 minutes).
    pub(crate) const fn again(&mut self, failure: Failure, config: &Config, now: u32) {
        if now < self.until && self.until - now <= config.failure_max {
            return;
        }
        self.length = if self.until <= now && now <= self.until.saturating_add(config.failure_max) {
            let doubled = self.length.saturating_mul(2);
            if doubled < config.failure_max {
                doubled
            } else {
                config.failure_max
            }
        } else {
            shortest(config)
        };
        self.failure = failure;
        self.until = now.saturating_add(self.length);
    }
}

/// The shortest hold: [`Config::failure_min`], at least the second RFC 9520 §3.2 asks for.
const fn shortest(config: &Config) -> u32 {
    if config.failure_min == 0 {
        1
    } else {
        config.failure_min
    }
}

impl Cost for Hold {
    fn cost(&self) -> usize {
        0
    }
}
