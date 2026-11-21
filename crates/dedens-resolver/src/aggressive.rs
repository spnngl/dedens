//! Aggressive use of the cache for denial (RFC 8198 §4, D199): a name a zone's secure NSEC or NSEC3 records held in
//! the cache prove absent, or without the type asked, is answered without a query, whatever other name those records
//! were asked for.
//!
//! The records are those the index of spans ([`Spans`](crate::spans)) finds for the name, fetched from the `RRset`
//! cache fresh and secure, with the zone's SOA, which the answer carries (RFC 2308 §5). What they prove is decided by
//! the validator's own code, [`denial::prove`](dedens_dnssec::denial::prove): the cover of the name, the closest
//! encloser, and that no wildcard could have answered (RFC 8198 §5.3, §5.4 for NSEC; RFC 5155 §8 for NSEC3).
//! Wildcard answers are not synthesised (RFC 8198 §5.1): a name a wildcard answers is a miss, and asked.

use dedens_cache::Checked;
use dedens_dnssec::crypto::{Budget, Nsec3Blocks, Verifications};
use dedens_dnssec::denial::{Fact, MaxIterations, hashed_owner, prove};
use dedens_proto::rdata::RData;
use dedens_proto::{Class, Name, Question, Record, RecordType, Ttl};
use tracing::debug;

use crate::negative::{Denied, Kind, lifetime};
use crate::rrset_cache::{Ranked, RrsetCache};
use crate::spans::{Chain, HASH_LEN};

/// The SHA-1 blocks of NSEC3 hashing one lookup may spend, the hashes it makes and those the proof makes again
/// ([`Budget::DEFAULT_NSEC3_BLOCKS`], 8192, is for a whole validation, D71): 6 names at the most iterations
/// RFC 9276 allows without a salt, hundreds at none. A lookup that would spend more is a miss, asked as it would be
/// without the cache.
const NSEC3_BLOCKS: Nsec3Blocks = Nsec3Blocks(2048);

/// The negative answer the secure NSEC or NSEC3 records held prove for `name` and `qtype` at `now`, if one is.
///
/// None for what the records cannot prove or the cache must not answer: DS, whose insecure delegation an opt-out
/// NSEC3 would claim (RFC 8198 §5.2 leaves it to the parent's own answer), ANY, RRSIG and NXNAME; a name under an
/// opt-out NSEC3 record, which proves no insecure delegation is absent (RFC 5155 §6, §9.2); a name whose records
/// held are not all fresh and secure.
pub(crate) fn synthesise(
    rrsets: &RrsetCache,
    name: &Name<'_>,
    qtype: RecordType,
    now: u32,
) -> Option<(Kind, Denied)> {
    if matches!(
        qtype,
        RecordType::DS | RecordType::ANY | RecordType::RRSIG | RecordType::NXNAME
    ) {
        return None;
    }
    let (apex, chain) = rrsets.spans().zone_of(name)?;
    let soa = secure(rrsets, &apex, (&apex, RecordType::SOA), now)?;
    let mut budget = Budget::new(Verifications(0), NSEC3_BLOCKS);
    let denials = match &chain {
        Chain::Nsec => nsec(rrsets, &apex, name, now)?,
        Chain::Nsec3 { salt, iterations } => {
            nsec3(rrsets, &apex, name, (salt, *iterations), &mut budget, now)?
        }
    };
    let records: Vec<Record<'static>> = denials
        .iter()
        .flat_map(|ranked| {
            let rrset = &ranked.rrset;
            rrset.rdatas().iter().map(|rdata| Record {
                name: rrset.owner().clone(),
                class: rrset.class(),
                ttl: ranked.ttl,
                rdata: rdata.clone(),
            })
        })
        .collect();
    let question = Question::new(name.clone().into_owned(), qtype);
    let proof = prove(
        &apex,
        &question,
        &records,
        MaxIterations::default(),
        &mut budget,
    )
    .inspect_err(|reason| debug!(%name, rtype = %qtype, %reason, "no proof in the cache"))
    .ok()?;
    let kind = match proof.fact {
        Fact::NameError { compact: false } => Kind::NxDomain,
        Fact::NoData | Fact::WildcardNoData => Kind::NoData(qtype),
        _ => return None,
    };
    if proof.opt_out {
        debug!(%name, rtype = %qtype, "the proof is under an opt-out NSEC3 record");
        return None;
    }
    let mut denied = Denied { soa, denials };
    let left = lifetime(
        rrsets.config(),
        &denied.soa,
        &denied.denials,
        Checked::Secure,
    )?;
    for ranked in std::iter::once(&mut denied.soa).chain(&mut denied.denials) {
        ranked.ttl = Ttl::from_wire(left);
    }
    Some((kind, denied))
}

/// The `RRset` of `owner` and `rtype` in the zone `apex`, fresh, secure and signed by `apex` alone: the key of an
/// `RRset` is its owner, type and class, so a set of another zone at the same name (a child's NSEC at its own apex,
/// or an NSEC3 at the name of one of the parent's hashes) may have replaced the parent's record, and `denial::prove`
/// takes every record it is given for the zone's (RFC 6840 §4.1). The NSEC at the apex is read under its own key
/// ([`RrsetCache::get_nsec`]).
fn secure(
    rrsets: &RrsetCache,
    apex: &Name<'_>,
    (owner, rtype): (&Name<'_>, RecordType),
    now: u32,
) -> Option<Ranked> {
    let held = if rtype == RecordType::NSEC {
        rrsets.get_nsec(owner, owner == apex, now)
    } else {
        rrsets.get(owner, rtype, Class::IN, now)
    }?;
    (held.checked == Checked::Secure && held.rrset.signer().is_some_and(|signer| signer == *apex))
        .then_some(held)
}

/// The NSEC records that cover `name` and the wildcard at its closest encloser (RFC 4035 §5.4): the one at or before
/// `name`, the closest encloser the longest name above `name` that its owner or its next name is within (RFC 4034
/// §6.1: a name sorts next to the names below it), then the one at or before `*.` that.
fn nsec(rrsets: &RrsetCache, apex: &Name<'_>, name: &Name<'_>, now: u32) -> Option<Vec<Ranked>> {
    let spans = rrsets.spans();
    let cover = secure(
        rrsets,
        apex,
        (&spans.owner_before(apex, name)?, RecordType::NSEC),
        now,
    )?;
    let next = cover
        .rrset
        .rdatas()
        .iter()
        .find_map(|rdata| match rdata.data() {
            RData::Nsec(nsec) => Some(nsec.next.into_owned()),
            _ => None,
        })?;
    if cover.rrset.owner() == name {
        return Some(vec![cover]);
    }
    let encloser = std::iter::successors(Some(name.clone().into_owned()), |above| {
        Name::from_labels(above.labels().skip(1)).ok()
    })
    .find(|above| cover.rrset.owner().is_within(above) || next.is_within(above))?;
    let wildcard =
        Name::from_labels(std::iter::once(b"*".as_slice()).chain(encloser.labels())).ok()?;
    let at = spans.owner_before(apex, &wildcard)?;
    let mut denials = vec![cover];
    if denials.iter().all(|held| *held.rrset.owner() != at) {
        denials.push(secure(rrsets, apex, (&at, RecordType::NSEC), now)?);
    }
    Some(denials)
}

/// The NSEC3 records of the closest encloser proof for `name` (RFC 5155 §8.3): for `name` and each name above it,
/// the record at or before its hash, up to the one whose hash is matched, which makes the closest encloser; then the
/// one at or before the hash of the wildcard below it, unless `name` itself is matched. The hashes are paid from
/// `budget`.
fn nsec3(
    rrsets: &RrsetCache,
    apex: &Name<'_>,
    name: &Name<'_>,
    (salt, iterations): (&[u8], u16),
    budget: &mut Budget,
    now: u32,
) -> Option<Vec<Ranked>> {
    let spans = rrsets.spans();
    let mut hashes: Vec<[u8; HASH_LEN]> = Vec::new();
    let mut hash = |hashed: &Name<'_>, matched: &mut bool| -> Option<()> {
        let one = budget.nsec3_hash(salt, iterations, hashed).ok()?;
        let before = spans.hash_before(apex, &one)?;
        *matched = before == one;
        if !hashes.contains(&before) {
            hashes.push(before);
        }
        Some(())
    };
    let mut encloser = None;
    for (at, above) in std::iter::successors(Some(name.clone().into_owned()), |above| {
        Name::from_labels(above.labels().skip(1)).ok()
    })
    .enumerate()
    {
        if !above.is_within(apex) {
            return None;
        }
        let mut matched = false;
        hash(&above, &mut matched)?;
        if matched {
            encloser = Some((at, above));
            break;
        }
    }
    let (at, encloser) = encloser?;
    if at > 0 {
        let wildcard =
            Name::from_labels(std::iter::once(b"*".as_slice()).chain(encloser.labels())).ok()?;
        hash(&wildcard, &mut false)?;
    }
    hashes
        .iter()
        .map(|before| {
            secure(
                rrsets,
                apex,
                (&hashed_owner(apex, before).ok()?, RecordType::NSEC3),
                now,
            )
        })
        .collect()
}
