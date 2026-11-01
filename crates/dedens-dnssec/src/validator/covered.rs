//! What [`Verdict::Secure`](super::Verdict::Secure) covers of a response (D75, RFC 4035 §3.2.3).
//!
//! The validator verifies the `RRsets` on the name path of the answer and says nothing of the others. A caller that
//! hands out or shows a secure response, with AD or as validated, shows [`covered()`] of it: the one definition of
//! what the verdict is about, computed with the predicates the validator checks by, so that the two cannot drift.

use std::collections::HashSet;

use dedens_proto::{Class, Message, Name, RData, Record, RecordType};

use super::response::Parsed;
use super::section::{is_denial, synthesized};

/// An owner and a type: an `RRset`.
type Key = (Name<'static>, RecordType);

/// `response`, a response whose verdict is secure, cut to the records that verdict covers:
///
/// - class IN, and no additional section (RFC 4035 §3.2.3);
/// - in the answer section, the `RRsets` owned by a name the question's CNAME and DNAME links pass through, and the
///   DNAME sets that rewrote one (RFC 1034 §3.6.2, RFC 6672 §3.1);
/// - in the authority section, the proofs of denial (NSEC, NSEC3, SOA: the validator verifies all of them) and the
///   sets at or above a name of that path (the NS and DS of the zone cut);
/// - the RRSIGs of the sets that stay, but not those of the CNAME a DNAME makes: it is unsigned and not verified
///   (RFC 6672 §5.3.3), and every record of its set is the one the DNAME makes, so it stays whole (RFC 4035 §4.8
///   lets the resolver return it, and a client that does not synthesize one would lose the answer).
///
/// Header, question and EDNS are kept, the TTLs too: the caller caps them. A response with no question is
/// left with no answer and no authority section.
///
/// Of a response that is not secure the result says nothing.
#[must_use]
pub fn covered(response: &Message<'_>) -> Message<'static> {
    let mut covered = response.clone().into_owned();
    covered.additional.clear();
    let Some(question) = covered.questions.first() else {
        covered.answer.clear();
        covered.authority.clear();
        return covered;
    };
    let Parsed {
        answer,
        authority,
        chain,
    } = Parsed::new(question, &covered.answer, &covered.authority);
    let mut verified = HashSet::new();
    let mut unverified = HashSet::new();
    for set in answer.sets.iter().filter(|set| chain.answers(set)) {
        let key = (set.owner().clone(), set.rtype());
        if synthesized(set, &answer) {
            unverified.insert(key.clone());
        }
        verified.insert(key);
    }
    let proofs = authority
        .sets
        .iter()
        .filter(|set| is_denial(set.rtype()) || chain.about(set))
        .map(|set| (set.owner().clone(), set.rtype()))
        .collect();
    retain(&mut covered.answer, &verified, &unverified);
    retain(&mut covered.authority, &proofs, &HashSet::new());
    covered
}

/// Keeps the class IN records of the `RRsets` in `sets`, and the signatures of those, except of `unsigned`.
fn retain(records: &mut Vec<Record<'static>>, sets: &HashSet<Key>, unsigned: &HashSet<Key>) {
    records.retain(|record| {
        record.class == Class::IN
            && match record.data() {
                RData::Rrsig(rrsig) => {
                    let covered = (record.name.clone(), rrsig.type_covered);
                    sets.contains(&covered) && !unsigned.contains(&covered)
                }
                _ => sets.contains(&(record.name.clone(), record.rtype())),
            }
    });
}
