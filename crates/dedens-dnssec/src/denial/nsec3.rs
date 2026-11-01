//! Denial by NSEC3 records (RFC 5155 §8, RFC 6840 §4.1): a chain of the hashes of the names of the zone.

use dedens_proto::codes::{Nsec3HashAlgorithm, RecordType};
use dedens_proto::name::Name;
use dedens_proto::rdata::{Nsec3, RData, TypeBitmap};
use dedens_proto::record::{Record, Ttl};
use dedens_proto::{Class, Question};

use super::names::{covers, wildcard};
use super::{Fact, MaxIterations, Proof, Unproven, at_name, least, wildcard_lacks};
use crate::crypto::Budget;

/// The length of a SHA-1 hash, the only one NSEC3 has (RFC 5155 §11).
const HASH_LEN: usize = 20;

type Hash = [u8; HASH_LEN];

/// An NSEC3 record: the hash that is its owner's first label, the next one in hash order, and the types at the
/// name that hashes to the first.
#[derive(Debug)]
pub(super) struct Entry<'r> {
    hash: Hash,
    next: Hash,
    opt_out: bool,
    types: TypeBitmap<'r>,
    ttl: Ttl,
}

/// The NSEC3 records of one zone made with one set of parameters (RFC 5155 §8.2).
#[derive(Debug)]
pub(super) struct Chain<'r> {
    entries: Vec<Entry<'r>>,
    iterations: u16,
    salt: Vec<u8>,
}

/// The hash a label of 32 characters of base32hex spells, in either case (RFC 5155 §3.3, RFC 4648 §7).
fn owner_hash(label: &[u8]) -> Option<Hash> {
    if label.len() != HASH_LEN * 8 / 5 {
        return None;
    }
    let mut hash = [0; HASH_LEN];
    let (mut bytes, mut acc, mut bits) = (hash.iter_mut(), 0_u16, 0_u8);
    for &c in label {
        let digit = match c.to_ascii_lowercase() {
            d @ b'0'..=b'9' => d - b'0',
            l @ b'a'..=b'v' => l - b'a' + 10,
            _ => return None,
        };
        acc = acc << 5 | u16::from(digit);
        bits += 5;
        if bits >= 8 {
            bits -= 8;
            *bytes.next()? = u8::try_from(acc >> bits).ok()?;
            acc &= (1 << bits) - 1;
        }
    }
    Some(hash)
}

impl<'r> Chain<'r> {
    /// The usable NSEC3 records of `apex`, or none: IN records one label below the apex that is a hash, of SHA-1
    /// and flags 0 or 1 (RFC 5155 §8.1, §8.2).
    ///
    /// # Errors
    ///
    /// [`Unproven::IterationsAboveLimit`] when the iterations of any usable record are above `max` (RFC 9276
    /// §3.2), and otherwise [`Unproven::ConflictingNsec3Parameters`] when the usable records differ in iterations
    /// or salt (RFC 5155 §8.2): no record decides which set is the zone's.
    pub(super) fn new(
        apex: &Name<'_>,
        records: &'r [Record<'r>],
        max: MaxIterations,
    ) -> Result<Option<Self>, Unproven> {
        let depth = apex.label_count() + 1;
        let mut chain: Option<Self> = None;
        let mut conflict = false;
        let mut most = 0;
        for record in records.iter().filter(|r| {
            r.class == Class::IN && r.name.is_within(apex) && r.name.label_count() == depth
        }) {
            let RData::Nsec3(nsec3) = record.data() else {
                continue;
            };
            let (Some(hash), Ok(next)) = (
                record.name.labels().next().and_then(owner_hash),
                Hash::try_from(nsec3.next_hashed_owner()),
            ) else {
                continue;
            };
            if nsec3.hash_algorithm != Nsec3HashAlgorithm::SHA1
                || nsec3.flags & !Nsec3::OPT_OUT != 0
            {
                continue;
            }
            most = most.max(nsec3.iterations);
            let chain = chain.get_or_insert_with(|| Self {
                entries: Vec::new(),
                iterations: nsec3.iterations,
                salt: nsec3.salt().to_vec(),
            });
            conflict |= nsec3.iterations != chain.iterations || nsec3.salt() != chain.salt;
            chain.entries.push(Entry {
                hash,
                next,
                opt_out: nsec3.is_opt_out(),
                types: nsec3.types,
                ttl: record.ttl,
            });
        }
        if most > max.0 {
            return Err(Unproven::IterationsAboveLimit {
                iterations: most,
                limit: max.0,
            });
        }
        if conflict {
            return Err(Unproven::ConflictingNsec3Parameters);
        }
        Ok(chain)
    }

    /// The hash of `name` with the chain's parameters, paid from `budget`.
    fn hash(&self, name: &Name<'_>, budget: &mut Budget) -> Result<Hash, Unproven> {
        Ok(budget.nsec3_hash(&self.salt, self.iterations, name)?)
    }

    /// The record of the name that hashes to `hash`.
    fn matching(&self, hash: &Hash) -> Option<&Entry<'r>> {
        self.entries.iter().find(|e| e.hash == *hash)
    }

    /// The record whose hash and next hash have `hash` between them.
    fn covering(&self, hash: &Hash) -> Option<&Entry<'r>> {
        self.entries.iter().find(|e| covers(&e.hash, &e.next, hash))
    }

    /// The closest encloser of `qname`, which has no matching record, as RFC 5155 §8.3 finds it: the longest
    /// ancestor with one, if the name one label below it, the next closer name, has a covering one.
    fn closest_encloser(
        &self,
        apex: &Name<'_>,
        qname: &Name<'_>,
        qhash: &Hash,
        budget: &mut Budget,
    ) -> Result<Encloser<'_, 'r>, Unproven> {
        let labels: Vec<&[u8]> = qname.labels().collect();
        let mut next_closer = self.covering(qhash);
        for skip in 1..=labels.len().saturating_sub(apex.label_count()) {
            let name = Name::from_labels(labels.iter().skip(skip).copied())?;
            let hash = self.hash(&name, budget)?;
            if let Some(entry) = self.matching(&hash) {
                let next_closer = next_closer.ok_or(Unproven::NoClosestEncloser)?;
                // Below a delegation or a DNAME there are no names of the zone (RFC 5155 §8.3).
                let delegation =
                    entry.types.contains(RecordType::NS) && !entry.types.contains(RecordType::SOA);
                if delegation || entry.types.contains(RecordType::DNAME) {
                    return Err(Unproven::EncloserBelowCut);
                }
                return Ok(Encloser {
                    name,
                    entry,
                    next_closer,
                });
            }
            next_closer = self.covering(&hash);
        }
        Err(Unproven::NoClosestEncloser)
    }
}

/// A closest encloser and the two records that prove it.
struct Encloser<'c, 'r> {
    name: Name<'static>,
    entry: &'c Entry<'r>,
    next_closer: &'c Entry<'r>,
}

/// RFC 5155 §8.3 to §8.9: the name is matched, or its closest encloser is proven and the wildcard at it is
/// covered (name error), matched (wildcard no data), or the question is for a DS under an opt-out span.
pub(super) fn prove(
    chain: &Chain<'_>,
    apex: &Name<'_>,
    question: &Question<'_>,
    budget: &mut Budget,
) -> Result<Proof, Unproven> {
    let (qname, qtype) = (&question.name, question.qtype);
    let qhash = chain.hash(qname, budget)?;
    if let Some(entry) = chain.matching(&qhash) {
        return Ok(Proof::new(at_name(&entry.types, qtype)?, entry.ttl));
    }
    let encloser = chain.closest_encloser(apex, qname, &qhash, budget)?;
    let opt_out = encloser.next_closer.opt_out;
    let ttl = least([encloser.entry.ttl, encloser.next_closer.ttl]);
    // A delegation without DS may sit in an opt-out span, unsigned and unlisted (RFC 5155 §6, §8.6, §8.9). This
    // comes before the wildcard: a DS question asks for a delegation, and a response that also has a record
    // covering the wildcard is no less one.
    if qtype == RecordType::DS && opt_out {
        return Ok(Proof::new(Fact::InsecureDelegation, ttl).with_opt_out(true));
    }
    let wildcard_hash = chain.hash(&wildcard(&encloser.name)?, budget)?;
    if let Some(entry) = chain.matching(&wildcard_hash) {
        let fact = wildcard_lacks(&entry.types, qtype)?;
        return Ok(Proof::new(fact, least([ttl, entry.ttl])).with_opt_out(opt_out));
    }
    if let Some(entry) = chain.covering(&wildcard_hash) {
        let fact = Fact::NameError { compact: false };
        return Ok(Proof::new(fact, least([ttl, entry.ttl])).with_opt_out(opt_out));
    }
    Err(Unproven::WildcardNotDenied)
}

/// RFC 5155 §8.8: an NSEC3 covers the next closer name, so the wildcard was the closest match. Under an opt-out
/// span the next closer name may exist as an insecure delegation, and the proof says so (RFC 5155 §9.2).
pub(super) fn prove_wildcard_answer(
    chain: &Chain<'_>,
    next_closer: &Name<'_>,
    budget: &mut Budget,
) -> Result<Proof, Unproven> {
    let hash = chain.hash(next_closer, budget)?;
    if chain.matching(&hash).is_some() {
        return Err(Unproven::CloserNameExists);
    }
    let covering = chain.covering(&hash).ok_or(Unproven::NotCovered)?;
    Ok(Proof::new(Fact::WildcardAnswer, covering.ttl).with_opt_out(covering.opt_out))
}

#[cfg(test)]
mod tests {
    use proptest::prelude::*;

    use super::super::fixtures::{names, zone};
    use super::*;

    /// RFC 5155 Appendix A: `H(example)`.
    #[test]
    fn owner_label_is_base32hex_of_20_bytes() {
        let hash = owner_hash(b"0p9mhaveqvm6t7vbl5lop2u3t2rp3tom").unwrap();
        assert_eq!(hash[..3], [0x06, 0x53, 0x68]);
        assert_eq!(owner_hash(b"0P9MHAVEQVM6T7VBL5LOP2U3T2RP3TOM"), Some(hash));
        assert_eq!(owner_hash(b"0p9mhaveqvm6t7vbl5lop2u3t2rp3to"), None);
        assert_eq!(owner_hash(b"0p9mhaveqvm6t7vbl5lop2u3t2rp3tow"), None);
    }

    proptest! {
        /// RFC 5155 §8: against a whole chain, a hash is the owner of one NSEC3 or sorts between the hash and
        /// the next hash of one (the last wraps to the first), never both and never two: for the hash of a name
        /// around the zone's, and for any 20 bytes.
        #[test]
        fn a_hash_is_matched_or_covered_by_exactly_one_record(
            name in names(),
            bytes in any::<[u8; 20]>(),
        ) {
            let mut records = zone("../dedens-proto/tests/zones/rfc5155_appendix_a.zone");
            records.retain(|r| r.rtype() == RecordType::NSEC3);
            let apex: Name<'static> = "example.".parse().expect("a name");
            let chain = Chain::new(&apex, &records, MaxIterations::default())
                .expect("one set of parameters")
                .expect("NSEC3 records");
            let named = chain.hash(&name, &mut Budget::default()).expect("a hash");
            for hash in [named, bytes] {
                let matched = chain.entries.iter().filter(|e| e.hash == hash).count();
                let covered = chain
                    .entries
                    .iter()
                    .filter(|e| covers(&e.hash, &e.next, &hash))
                    .count();
                prop_assert_eq!(matched + covered, 1, "{:?}", hash);
            }
        }
    }
}
