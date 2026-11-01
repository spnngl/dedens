//! Authenticated denial of existence: what a set of NSEC or NSEC3 records proves about a name and a type
//! (RFC 4035 §5.4, RFC 5155 §8, RFC 6840 §4, RFC 9824).
//!
//! Pure set logic, no signatures and no I/O. [`prove`] answers a question that got a name error, no data, or a
//! referral; [`prove_wildcard_answer`] answers one that got a wildcard expansion. Both return the [`Fact`] proven
//! and the TTL the proof may be cached for, or why nothing is proven.
//!
//! What the caller owes, as this module trusts it:
//!
//! - The records are verified first, each RRSIG valid and its signer exactly `apex`: RFC 6840 §4.1 tells a
//!   delegation's NSEC from the child's by the signer, which no record here carries. An NSEC3 with an unchecked
//!   signature could carry any iteration count, so [`Unproven::IterationsAboveLimit`] (insecure) holds only for
//!   verified records (RFC 9276 §3.2).
//! - A question for DS is for a delegation's name. An opt-out span proves "no DS" for any name it covers, one below
//!   a delegation included (RFC 5155 §8.6), which only the caller knows is not asked.
//! - [`Proof::opt_out`] is checked before an answer is marked authenticated (RFC 5155 §9.2).
//!
//! NXNAME (RFC 9824) is read first: a question for the type is refused before any record is looked at, and an NSEC
//! or NSEC3 matching the name with NXNAME in its bitmap is a name error whatever else the bitmap lists (NS and DS
//! included), before the delegation and DS rules apply.
//!
//! Which verdict an [`Unproven`] makes (bogus, insecure) is the caller's, as for an exhausted [`Budget`] (D71);
//! D74 records what this module chooses.

#[cfg(test)]
mod fixtures;
mod names;
mod nsec;
mod nsec3;

use dedens_proto::Question;
use dedens_proto::codes::RecordType;
use dedens_proto::edns::InfoCode;
use dedens_proto::name::{Name, NameError};
use dedens_proto::rdata::TypeBitmap;
use dedens_proto::record::{Record, Ttl};

use crate::crypto::{Budget, BudgetExhausted, UnsupportedNsec3Hash};

/// What a set of records proves.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Fact {
    /// The name does not exist, and no wildcard could have answered for it (RFC 4035 §5.4, RFC 5155 §8.4).
    NameError {
        /// Whether one NSEC at the name says so with the NXNAME type, as a zone with compact denial of existence
        /// does under NOERROR (RFC 9824 §3.1): the answer's rcode is then not NXDOMAIN, which the caller
        /// expects.
        compact: bool,
    },
    /// The name exists, or is an empty non-terminal, but has no record of the type asked and no CNAME
    /// (RFC 4035 §5.4, RFC 5155 §8.5).
    NoData,
    /// The name does not exist, but a wildcard does that has no record of the type asked and no CNAME
    /// (RFC 4035 §5.4, RFC 5155 §8.7).
    WildcardNoData,
    /// The name does not exist, so the wildcard the answer was expanded from is the closest match
    /// (RFC 4035 §5.3.4, RFC 5155 §8.8).
    WildcardAnswer,
    /// The name is a delegation with no DS: the child zone is insecure, by an NSEC or NSEC3 for the name, or an
    /// opt-out NSEC3 over it (RFC 4035 §5.2, RFC 5155 §8.6, §8.9, RFC 6840 §4.4).
    InsecureDelegation,
}

/// A proven [`Fact`] and how long it may be relied on.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Proof {
    /// What was proven.
    pub fact: Fact,
    /// The least TTL of the records the proof used (RFC 9077 §3, RFC 2308 §5).
    pub ttl: Ttl,
    /// Whether the NSEC3 record that covers the next closer name has the opt-out flag: the name is then proven
    /// absent from the signed names only, and may exist as an insecure delegation. The answer must not be
    /// marked authenticated (AD, RFC 5155 §9.2), whatever the [`Fact`]. Always false for NSEC and for a name
    /// the records match.
    pub opt_out: bool,
}

impl Proof {
    /// A proof by records that leave no room for an unsigned name.
    const fn new(fact: Fact, ttl: Ttl) -> Self {
        Self {
            fact,
            ttl,
            opt_out: false,
        }
    }

    /// The same proof, with the opt-out mark of the record that covers the next closer name.
    const fn with_opt_out(self, opt_out: bool) -> Self {
        Self { opt_out, ..self }
    }
}

/// Why records prove nothing about a name.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum Unproven {
    /// The question asks for NXNAME, which is no type to ask for (RFC 9824 §3.5): refuse it with
    /// [`InfoCode::INVALID_QUERY_TYPE`].
    #[error("NXNAME is not a type to ask for")]
    NxnameQuery,
    /// The name is not in the zone the records are of.
    #[error("the name is outside the zone")]
    OutsideZone,
    /// No NSEC or NSEC3 record is usable: none in the zone, or NSEC3 records of an unknown hash algorithm or
    /// with unknown flags, which are ignored (RFC 5155 §8.1, §8.2).
    #[error("no usable NSEC or NSEC3 record")]
    NoUsableRecords,
    /// The NSEC3 records were made with more iterations than the limit: the answer is insecure, with
    /// [`InfoCode::UNSUPPORTED_NSEC3_ITERATIONS`] (RFC 9276 §3.2).
    #[error("{iterations} NSEC3 iterations, above the limit of {limit}")]
    IterationsAboveLimit {
        /// The iterations of the zone's NSEC3 records.
        iterations: u16,
        /// The limit given.
        limit: u16,
    },
    /// The NSEC3 records have more than one set of parameters (salt, iterations): one zone has one set, so the
    /// records are not the zone's, or not from one time. The caller makes the response bogus (RFC 5155 §8.2).
    #[error("NSEC3 records of more than one set of parameters")]
    ConflictingNsec3Parameters,
    /// The hashes of the proof would cost more than the budget has left (D71); the caller picks the verdict.
    #[error(transparent)]
    Budget(#[from] BudgetExhausted),
    /// An NSEC3 hash algorithm [`crate::crypto::nsec3_hash`] does not do.
    #[error(transparent)]
    UnsupportedHash(#[from] UnsupportedNsec3Hash),
    /// A name the proof builds is not a valid name.
    #[error(transparent)]
    Name(#[from] NameError),
    /// No record covers the name, or the name the proof needs absent.
    #[error("no record covers the name")]
    NotCovered,
    /// No closest encloser is proven (RFC 5155 §8.3).
    #[error("no closest encloser is proven")]
    NoClosestEncloser,
    /// The closest encloser is a delegation or holds a DNAME, so names below it are not in the zone
    /// (RFC 5155 §8.3, RFC 6840 §4.1).
    #[error("the closest encloser is a delegation or a DNAME")]
    EncloserBelowCut,
    /// The wildcard at the closest encloser is neither matched nor covered.
    #[error("the wildcard is not denied")]
    WildcardNotDenied,
    /// The wildcard exists and has the type asked or a CNAME, so the answer was no denial.
    #[error("the wildcard has the type or a CNAME")]
    WildcardHasType,
    /// The name has the type asked or a CNAME (RFC 6840 §4.3).
    #[error("the name has the type or a CNAME")]
    TypePresent,
    /// The record is of a delegation, whose records prove only that DS is absent (RFC 6840 §4.1).
    #[error("a delegation proves nothing but the absence of DS")]
    AtDelegation,
    /// A DS question answered from the child zone's apex, by a record that says nothing of the delegation
    /// (RFC 4035 §5.2, RFC 5155 §8.6).
    #[error("the record is from the child's apex, not the delegation")]
    FromChildApex,
    /// The RRSIG's label count leaves no label for a wildcard to have replaced (RFC 4035 §5.3.4).
    #[error("the answer is not a wildcard expansion")]
    NotExpanded,
    /// The name that a wildcard should not have been bypassed for exists (RFC 5155 §8.8).
    #[error("a name closer than the wildcard exists")]
    CloserNameExists,
}

impl Unproven {
    /// The extended error to attach to the answer when this is the reason (RFC 8914).
    #[must_use]
    pub const fn info_code(&self) -> Option<InfoCode> {
        match self {
            Self::IterationsAboveLimit { .. } => Some(InfoCode::UNSUPPORTED_NSEC3_ITERATIONS),
            Self::NxnameQuery => Some(InfoCode::INVALID_QUERY_TYPE),
            _ => None,
        }
    }
}

/// The most NSEC3 iterations a zone may use before its denials are not checked (RFC 9276 §3.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MaxIterations(pub u16);

impl Default for MaxIterations {
    /// 150, as Unbound and BIND (D74).
    fn default() -> Self {
        Self(150)
    }
}

/// The records of one zone that the proof is made of.
enum Evidence<'r> {
    Nsec(Vec<nsec::Link<'r>>),
    Nsec3(nsec3::Chain<'r>),
}

impl<'r> Evidence<'r> {
    /// NSEC3 records when there are usable ones, NSEC records otherwise: a zone has one or the other.
    fn of(
        apex: &Name<'_>,
        records: &'r [Record<'r>],
        max: MaxIterations,
    ) -> Result<Self, Unproven> {
        if let Some(chain) = nsec3::Chain::new(apex, records, max)? {
            return Ok(Self::Nsec3(chain));
        }
        let links = nsec::links(apex, records);
        if links.is_empty() {
            return Err(Unproven::NoUsableRecords);
        }
        Ok(Self::Nsec(links))
    }
}

/// What the types at a name the records match say about a question of `qtype`.
fn at_name(types: &TypeBitmap<'_>, qtype: RecordType) -> Result<Fact, Unproven> {
    let delegation = types.contains(RecordType::NS) && !types.contains(RecordType::SOA);
    if types.contains(RecordType::NXNAME) {
        Ok(Fact::NameError { compact: true })
    } else if qtype == RecordType::DS {
        if types.contains(RecordType::SOA) {
            Err(Unproven::FromChildApex)
        } else if types.contains(RecordType::DS) || types.contains(RecordType::CNAME) {
            Err(Unproven::TypePresent)
        } else if delegation {
            Ok(Fact::InsecureDelegation)
        } else {
            Ok(Fact::NoData)
        }
    } else if delegation {
        Err(Unproven::AtDelegation)
    } else if types.contains(qtype) || types.contains(RecordType::CNAME) {
        Err(Unproven::TypePresent)
    } else {
        Ok(Fact::NoData)
    }
}

/// Whether the types at a wildcard leave a question of `qtype` without an answer (RFC 4035 §5.4, RFC 6840 §4.3).
fn wildcard_lacks(types: &TypeBitmap<'_>, qtype: RecordType) -> Result<Fact, Unproven> {
    if types.contains(qtype) || types.contains(RecordType::CNAME) {
        Err(Unproven::WildcardHasType)
    } else {
        Ok(Fact::WildcardNoData)
    }
}

/// The least of some TTLs.
fn least(ttls: impl IntoIterator<Item = Ttl>) -> Ttl {
    ttls.into_iter().min().unwrap_or(Ttl::MAX)
}

/// What `records`, the verified NSEC and NSEC3 records of a response to `question`, prove about it, for a zone
/// whose apex is `apex`: a name error, no data, a wildcard no data, or an insecure delegation, the last when the
/// question is for DS (RFC 4035 §5.2, §5.4, RFC 5155 §8.3 to §8.9, RFC 6840 §4).
///
/// Records that are not NSEC or NSEC3, or not in `apex`, are ignored. The hashes of NSEC3 are paid from `budget`.
///
/// # Errors
///
/// [`Unproven`] with the reason the records prove nothing; the caller chooses the verdict.
pub fn prove(
    apex: &Name<'_>,
    question: &Question<'_>,
    records: &[Record<'_>],
    max: MaxIterations,
    budget: &mut Budget,
) -> Result<Proof, Unproven> {
    if question.qtype == RecordType::NXNAME {
        return Err(Unproven::NxnameQuery);
    }
    if !question.name.is_within(apex) {
        return Err(Unproven::OutsideZone);
    }
    match Evidence::of(apex, records, max)? {
        Evidence::Nsec(links) => nsec::prove(&links, question),
        Evidence::Nsec3(chain) => nsec3::prove(&chain, apex, question, budget),
    }
}

/// What `records` prove about `qname` answered by wildcard expansion: that no name closer than the wildcard
/// exists, given the label count of the answer's RRSIG, which is how many labels the wildcard has without its
/// `*` (RFC 4035 §5.3.4, §5.4, RFC 5155 §8.8).
///
/// # Errors
///
/// [`Unproven`] with the reason the records prove nothing; the caller chooses the verdict.
pub fn prove_wildcard_answer(
    apex: &Name<'_>,
    qname: &Name<'_>,
    rrsig_labels: u8,
    records: &[Record<'_>],
    max: MaxIterations,
    budget: &mut Budget,
) -> Result<Proof, Unproven> {
    let labels = usize::from(rrsig_labels);
    if !qname.is_within(apex) {
        return Err(Unproven::OutsideZone);
    }
    if labels >= qname.label_count() || labels < apex.label_count() {
        return Err(Unproven::NotExpanded);
    }
    // The name one label below the wildcard's parent: the one that, existing, would have been the answer.
    let next_closer = names::suffix(qname, labels + 1)?;
    match Evidence::of(apex, records, max)? {
        Evidence::Nsec(links) => nsec::prove_wildcard_answer(&links, &next_closer),
        Evidence::Nsec3(chain) => nsec3::prove_wildcard_answer(&chain, &next_closer, budget),
    }
}
