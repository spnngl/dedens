//! Denial by NSEC records (RFC 4035 §5.4, RFC 6840 §4.1): a chain of the names of the zone in canonical order.

use dedens_proto::rdata::{RData, TypeBitmap};
use dedens_proto::{Class, Name, Question, Record, RecordType, Ttl};

use super::names::{Canonical, covers, shared_labels, suffix, wildcard};
use super::{Fact, Proof, Unproven, at_name, least, wildcard_lacks};

/// An NSEC record: a name of the zone, the next one in canonical order, and the types at the first.
#[derive(Debug)]
pub(super) struct Link<'r> {
    owner: &'r Name<'r>,
    next: Name<'r>,
    types: TypeBitmap<'r>,
    ttl: Ttl,
}

impl Link<'_> {
    /// Whether the record proves `name` absent: it sorts between owner and next, and is not below a delegation
    /// or a DNAME at the owner, which the record proves nothing about (RFC 6840 §4.1).
    fn covers(&self, name: &Name<'_>) -> bool {
        let below_cut = name.is_within(self.owner)
            && (self.types.contains(RecordType::DNAME)
                || self.types.contains(RecordType::NS) && !self.types.contains(RecordType::SOA));
        !below_cut
            && covers(
                &Canonical(self.owner),
                &Canonical(&self.next),
                &Canonical(name),
            )
    }
}

/// The IN NSEC records in `apex`, whose next names are in it too.
pub(super) fn links<'r>(apex: &Name<'_>, records: &'r [Record<'r>]) -> Vec<Link<'r>> {
    records
        .iter()
        .filter(|r| r.class == Class::IN && r.name.is_within(apex))
        .filter_map(|r| match r.data() {
            RData::Nsec(nsec) if nsec.next.is_within(apex) => Some(Link {
                owner: &r.name,
                next: nsec.next,
                types: nsec.types,
                ttl: r.ttl,
            }),
            _ => None,
        })
        .collect()
}

/// RFC 4035 §5.4: the name is matched, or covered with a proof that no wildcard applies.
pub(super) fn prove(links: &[Link<'_>], question: &Question<'_>) -> Result<Proof, Unproven> {
    let (qname, qtype) = (&question.name, question.qtype);
    if let Some(link) = links.iter().find(|l| l.owner == qname) {
        return Ok(Proof::new(at_name(&link.types, qtype)?, link.ttl));
    }
    let covering = links
        .iter()
        .find(|l| l.covers(qname))
        .ok_or(Unproven::NotCovered)?;
    // The next name is below the name: it is an empty non-terminal, which has no data of any type.
    if covering.next.is_within(qname) {
        return Ok(Proof::new(Fact::NoData, covering.ttl));
    }
    // The closest encloser is the longest ancestor of the name that the NSEC shows to exist: the owner and
    // the next name are both names of the zone, so their common ancestors with the name are.
    let depth = shared_labels(qname, covering.owner).max(shared_labels(qname, &covering.next));
    let wildcard = wildcard(&suffix(qname, depth)?)?;
    if let Some(link) = links.iter().find(|l| *l.owner == wildcard) {
        return Ok(Proof::new(
            wildcard_lacks(&link.types, qtype)?,
            least([covering.ttl, link.ttl]),
        ));
    }
    let denying = links
        .iter()
        .find(|l| l.covers(&wildcard))
        .ok_or(Unproven::WildcardNotDenied)?;
    let ttl = least([covering.ttl, denying.ttl]);
    // The next name is below the wildcard: `*.ce` is an empty non-terminal, which exists and has no data of any
    // type (RFC 4592 §2.2.1), as a matched wildcard of no types would.
    if denying.next.is_within(&wildcard) {
        return Ok(Proof::new(Fact::WildcardNoData, ttl));
    }
    Ok(Proof::new(Fact::NameError { compact: false }, ttl))
}

/// RFC 4035 §5.3.4: an NSEC covers the next closer name, so the wildcard was the closest match.
pub(super) fn prove_wildcard_answer(
    links: &[Link<'_>],
    next_closer: &Name<'_>,
) -> Result<Proof, Unproven> {
    if links.iter().any(|l| l.owner == next_closer) {
        return Err(Unproven::CloserNameExists);
    }
    let covering = links
        .iter()
        .find(|l| l.covers(next_closer))
        .ok_or(Unproven::NotCovered)?;
    // The next name is below the next closer name: that is an empty non-terminal, which exists.
    if covering.next.is_within(next_closer) {
        return Err(Unproven::CloserNameExists);
    }
    Ok(Proof::new(Fact::WildcardAnswer, covering.ttl))
}

#[cfg(test)]
mod tests {
    use dedens_proto::Record;
    use proptest::prelude::*;

    use super::super::fixtures::{names, zone};
    use super::*;

    /// The NSEC records of the example zone of RFC 4035 Appendix A, which chain all of its names.
    fn chain() -> Vec<Record<'static>> {
        let mut records = zone("tests/zones/rfc4035_appendix_a.zone");
        records.retain(|r| r.rtype() == RecordType::NSEC);
        records
    }

    proptest! {
        /// RFC 4035 §5.4: against a whole chain, every name is the owner of one NSEC or sorts between the owner
        /// and the next name of one (the last wraps to the apex), never both and never two; and a link that
        /// covers a name never matches it.
        #[test]
        fn a_name_is_matched_or_covered_by_exactly_one_link(name in names()) {
            let records = chain();
            let apex: Name<'static> = "example.".parse().expect("a name");
            let links = links(&apex, &records);
            let matched = links.iter().filter(|l| l.owner == &name).count();
            let covered = links
                .iter()
                .filter(|l| covers(&Canonical(l.owner), &Canonical(&l.next), &Canonical(&name)))
                .count();
            prop_assert_eq!(matched + covered, 1, "{}", name);
            for link in &links {
                prop_assert!(!(link.owner == &name && link.covers(&name)), "{}", name);
            }
        }
    }
}
