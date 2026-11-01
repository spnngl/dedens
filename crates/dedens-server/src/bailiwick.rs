//! What a secure verdict covers of a response (D77, D75, RFC 4035 §3.2.3).
//!
//! The validator verifies the `RRsets` on the name path of the answer and says nothing of the others: it ignores
//! them, neither verifying nor walking to them. A response is handed out and cached under AD, so it is cut to what
//! was verified: [`cut`] follows the same path from the question and drops the rest.

use std::collections::HashSet;

use dedens_proto::{Class, Message, Name, RData, Record, RecordType};

/// Cuts `message`, a response the validator found secure, to the records the verdict covers:
///
/// - class IN, and no additional section (RFC 4035 §3.2.3);
/// - in the answer section, the `RRsets` owned by a name the question's CNAME and DNAME links pass through, and
///   the DNAME sets that rewrote one (RFC 1034 §3.6.2, RFC 6672 §3.1);
/// - of the CNAME a DNAME makes, which is unsigned and not verified (RFC 6672 §5.3.3), only the one record that
///   is what the DNAME makes of its owner: others of its set are nobody's;
/// - in the authority section, the proofs of denial (NSEC, NSEC3, SOA: all verified) and the sets at or above a
///   name of the path (the NS and DS of the zone cut);
/// - signatures only where they sign a set that stays.
pub(crate) fn cut(message: &mut Message<'static>) {
    message.additional.clear();
    message.answer.retain(|record| record.class == Class::IN);
    message.authority.retain(|record| record.class == Class::IN);
    let Some(question) = message.questions.first() else {
        message.answer.clear();
        message.authority.clear();
        return;
    };
    let path = Path::follow(&message.answer, &question.name, question.qtype);

    message.answer.retain(|record| path.answers(record));
    let synthesized = synthesized(&message.answer);
    let mut seen = HashSet::new();
    let answer = std::mem::take(&mut message.answer);
    message.answer = answer
        .into_iter()
        .filter(|record| {
            let made = synthesized
                .iter()
                .find(|(owner, _)| owner == &record.name)
                .filter(|_| record.rtype() == RecordType::CNAME);
            // The set is the DNAME's doing: one record, the one it makes, unsigned.
            made.is_none_or(|(_, expected)| {
                matches!(record.data(), RData::Cname(target) if &target == expected)
                    && seen.insert(record.name.clone().into_owned())
            })
        })
        .collect();
    let asked_rrsig = question.qtype == RecordType::RRSIG;
    message
        .authority
        .retain(|record| path.about(record, record_type(record)));
    keep_signed(&mut message.answer, &synthesized, asked_rrsig);
    keep_signed(&mut message.authority, &[], false);
}

/// The type a record stands for: the type a signature covers, else its own.
fn record_type(record: &Record<'_>) -> RecordType {
    match record.data() {
        RData::Rrsig(rrsig) => rrsig.type_covered,
        _ => record.rtype(),
    }
}

/// Drops the signatures of `records` that sign no set among them, and those of the `synthesized` CNAMEs, which
/// the validator did not verify. `asked`: the question was for signatures, which stay.
fn keep_signed(
    records: &mut Vec<Record<'static>>,
    synthesized: &[(Name<'static>, Name<'static>)],
    asked: bool,
) {
    let signed: HashSet<(Name<'static>, RecordType)> = records
        .iter()
        .filter(|record| record.rtype() != RecordType::RRSIG)
        .map(|record| (record.name.clone().into_owned(), record.rtype()))
        .collect();
    records.retain(|record| {
        if record.rtype() != RecordType::RRSIG || asked {
            return true;
        }
        let covered = record_type(record);
        signed.contains(&(record.name.clone().into_owned(), covered))
            && !(covered == RecordType::CNAME
                && synthesized.iter().any(|(owner, _)| owner == &record.name))
    });
}

/// Where the answer leads from the name asked: [`Path::follow`] is the validator's own walk.
struct Path {
    /// Every name the answer passes through, the one asked and the last included.
    names: HashSet<Name<'static>>,
}

impl Path {
    /// Follows `answer` from `name` through CNAME and DNAME records, until a set of `qtype` (any, for ANY) is at
    /// the name or no link goes on. At most as many links as there are records: a loop ends there.
    fn follow(answer: &[Record<'static>], name: &Name<'_>, qtype: RecordType) -> Self {
        let mut end = name.clone().into_owned();
        let mut names = HashSet::from([end.clone()]);
        for _ in 0..=answer.len() {
            let present = answer.iter().any(|record| {
                record.name == end && (qtype == RecordType::ANY || record.rtype() == qtype)
            });
            if present {
                break;
            }
            let next = if let Some(cname) = first(answer, &end, RecordType::CNAME) {
                target(cname)
            } else if let Some((owner, to)) = dname_of(answer, &end) {
                substitute(&end, &owner, &to)
            } else {
                None
            };
            let Some(next) = next else { break };
            names.insert(next.clone());
            end = next;
        }
        Self { names }
    }

    /// Whether an answer record is on the path: owned by one of its names, or a DNAME rewriting one.
    fn answers(&self, record: &Record<'_>) -> bool {
        self.names.contains(&record.name)
            || (record.rtype() == RecordType::DNAME
                && self
                    .names
                    .iter()
                    .any(|name| name != &record.name && name.is_within(&record.name)))
    }

    /// Whether an authority record stays: a proof of denial, or owned at or above a name of the path. `kind` is
    /// the type it stands for.
    fn about(&self, record: &Record<'_>, kind: RecordType) -> bool {
        matches!(kind, RecordType::NSEC | RecordType::NSEC3 | RecordType::SOA)
            || self.names.iter().any(|name| name.is_within(&record.name))
    }
}

/// The CNAME sets of `answer` a DNAME of it makes, by owner, with the target the DNAME makes of it: unsigned and
/// so not verified by the validator when its first record is that one.
fn synthesized(answer: &[Record<'static>]) -> Vec<(Name<'static>, Name<'static>)> {
    let mut found: Vec<(Name<'static>, Name<'static>)> = Vec::new();
    for record in answer.iter().filter(|r| r.rtype() == RecordType::CNAME) {
        if found.iter().any(|(owner, _)| owner == &record.name) {
            continue;
        }
        let Some((owner, to)) = dname_of(answer, &record.name) else {
            continue;
        };
        let Some(expected) = substitute(&record.name, &owner, &to) else {
            continue;
        };
        let leads = first(answer, &record.name, RecordType::CNAME).and_then(target);
        if leads.as_ref() == Some(&expected) {
            found.push((record.name.clone().into_owned(), expected));
        }
    }
    found
}

/// The first record of `rtype` owned by `owner`.
fn first<'r>(
    records: &'r [Record<'static>],
    owner: &Name<'_>,
    rtype: RecordType,
) -> Option<&'r Record<'static>> {
    records
        .iter()
        .find(|record| &record.name == owner && record.rtype() == rtype)
}

/// The name a CNAME or DNAME record leads to.
fn target(record: &Record<'_>) -> Option<Name<'static>> {
    match record.data() {
        RData::Cname(name) => Some(name.into_owned()),
        _ if record.rtype() == RecordType::DNAME => name_from_wire(&record.rdata.wire()),
        _ => None,
    }
}

/// The DNAME at the nearest proper ancestor of `name`: its owner and its target.
fn dname_of(
    records: &[Record<'static>],
    name: &Name<'_>,
) -> Option<(Name<'static>, Name<'static>)> {
    (1..=name.label_count()).find_map(|skip| {
        let ancestor = Name::from_labels(name.labels().skip(skip)).ok()?;
        let dname = first(records, &ancestor, RecordType::DNAME)?;
        Some((ancestor, target(dname)?))
    })
}

/// `name` with its suffix `owner` replaced by the DNAME's `target` (RFC 6672 §2.2).
fn substitute(name: &Name<'_>, owner: &Name<'_>, target: &Name<'_>) -> Option<Name<'static>> {
    let prefix = name.label_count().saturating_sub(owner.label_count());
    Name::from_labels(name.labels().take(prefix).chain(target.labels())).ok()
}

/// A name in uncompressed wire form, the RDATA of a DNAME (RFC 6672 §2.1).
fn name_from_wire(mut wire: &[u8]) -> Option<Name<'static>> {
    let mut labels = Vec::new();
    loop {
        let (&len, rest) = wire.split_first()?;
        if len == 0 {
            return rest
                .is_empty()
                .then(|| Name::from_labels(labels).ok())
                .flatten();
        }
        let (label, rest) = rest.split_at_checked(usize::from(len))?;
        labels.push(label);
        wire = rest;
    }
}
