//! What a response says of the question asked, and the rank of each `RRset` kept: the one place a response is
//! judged. Its [`Read`] mirrors the outcome of the scrubber of recursive step 05 (PR #113), and [`Read::ranked`] its
//! `Scrubbed::ranked`, so that the scrubber replaces [`read`] without its caller changing (D191).

use std::collections::HashMap;
use std::sync::Arc;

use dedens_cache::Checked;
use dedens_proto::rdata::RData;
use dedens_proto::{Flags, Message, Name, Opcode, Question, Rcode, Record, RecordType};

use crate::rrset::Rrset;
use crate::rrset_cache::{Rank, Ranked};

/// What a response to a question asked of a zone's server says.
#[derive(Debug)]
pub(super) enum Read {
    /// The data asked for, at the end of the CNAME chain from the name asked (RFC 1034 §4.3.2 step 3a).
    Answer { chain: Vec<Ranked>, data: Ranked },
    /// A CNAME chain leaving the zone, or ending without data: the resolution restarts at `target` (RFC 1034
    /// §5.3.3 step 4c).
    Cname {
        chain: Vec<Ranked>,
        target: Name<'static>,
    },
    /// A referral to `child`, a zone strictly below the one asked and holding the name (RFC 1034 §4.3.2 step 3b):
    /// its NS `RRset` and the addresses given for those of its servers within the zone asked.
    Referral {
        child: Name<'static>,
        ns: Ranked,
        glue: Vec<Ranked>,
    },
    /// The name asked has no data of the type (RFC 2308 §2.2).
    NoData { soa: Ranked },
    /// The name, or the chain's end, does not exist (RFC 2308 §2.1).
    NxDomain { chain: Vec<Ranked>, soa: Ranked },
    /// A DNAME makes the chain's end longer than 255 bytes (RFC 6672 §2.2): the chain, the DNAME last.
    YxDomain { chain: Vec<Ranked> },
    /// A negative answer without the zone's SOA, which cannot be cached (RFC 2308 §5): another server is asked.
    NoSoa,
    /// Neither an authoritative answer nor a referral down: the server is lame for the zone (RFC 4697 §2.2).
    Lame,
    /// No answer to the question: another server is asked.
    Unusable(Unusable),
}

/// Why a response says nothing of the question.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Unusable {
    /// QR clear, or another opcode than QUERY.
    NotResponse,
    /// TC set: the transport asks again over TCP, so a truncated response that comes here is cut short.
    Truncated,
    /// A response code other than NOERROR, NXDOMAIN and YXDOMAIN; or YXDOMAIN without a DNAME whose synthesis is
    /// too long.
    Rcode(Rcode),
    /// Another question, or several.
    QuestionMismatch,
    /// A CNAME `RRset` of the chain holds other than one record (RFC 2181 §10.1).
    Malformed,
}

impl Read {
    /// The `RRsets` kept, ranked, to cache: the chain, the data, the SOA, the referral's NS and glue.
    pub(super) fn ranked(&self) -> Vec<&Ranked> {
        match self {
            Self::Answer { chain, data } => chain.iter().chain([data]).collect(),
            Self::Cname { chain, .. } | Self::YxDomain { chain } => chain.iter().collect(),
            Self::Referral { ns, glue, .. } => [ns].into_iter().chain(glue).collect(),
            Self::NoData { soa } => vec![soa],
            Self::NxDomain { chain, soa } => chain.iter().chain([soa]).collect(),
            Self::NoSoa | Self::Lame | Self::Unusable(_) => Vec::new(),
        }
    }

    /// Whether the response serves the question: an answer, a denial or a referral, which credit the server in
    /// the infrastructure cache (D191).
    pub(super) const fn usable(&self) -> bool {
        matches!(
            self,
            Self::Answer { .. }
                | Self::Cname { .. }
                | Self::Referral { .. }
                | Self::NoData { .. }
                | Self::NxDomain { .. }
                | Self::YxDomain { .. }
        )
    }
}

/// What `response` says of `question`, asked of a server of `zone`; a referral keeps the first `servers` names of
/// its NS records.
///
/// A referral is told before the AA bit, as Unbound's `response_type_from_server` does, since servers set AA on
/// referrals too (step 05): a NOERROR response without answer or SOA whose first NS record is owned strictly below
/// `zone` and holds the name. Otherwise only an authoritative response answers: the CNAME chain from the name asked
/// and the data at its end, whose owners are within `zone`, and the SOA of a denial; a negative answer without it
/// is [`Read::NoSoa`]. A non-authoritative one is lame.
///
/// Work linear in the size of the response: the chain is walked through an index of the answer's `RRsets`.
pub(super) fn read(
    response: &Message<'_>,
    question: &Question<'_>,
    zone: &Name<'_>,
    servers: usize,
) -> Read {
    let header = &response.header;
    if !header.flags.contains(Flags::QR) || header.opcode != Opcode::QUERY {
        return Read::Unusable(Unusable::NotResponse);
    }
    if header.flags.contains(Flags::TC) {
        return Read::Unusable(Unusable::Truncated);
    }
    let rcode = response.rcode();
    if ![Rcode::NOERROR, Rcode::NXDOMAIN, Rcode::YXDOMAIN].contains(&rcode) {
        return Read::Unusable(Unusable::Rcode(rcode));
    }
    if !matches!(response.questions.as_slice(), [asked] if asked == question) {
        return Read::Unusable(Unusable::QuestionMismatch);
    }
    let has_soa = response
        .authority
        .iter()
        .any(|r| r.rtype() == RecordType::SOA);
    if rcode == Rcode::NOERROR
        && response.answer.is_empty()
        && !has_soa
        && let Some(referral) = referral(response, question, zone, servers)
    {
        return referral;
    }
    if !header.flags.contains(Flags::AA) {
        return Read::Lame;
    }
    answer(response, question, zone, rcode)
}

/// What the authoritative `response` answers.
fn answer(response: &Message<'_>, question: &Question<'_>, zone: &Name<'_>, rcode: Rcode) -> Read {
    let sets = Rrset::group(&response.answer);
    let of_class = |set: &&Rrset| set.class() == question.qclass;
    let index: HashMap<(&Name<'static>, RecordType), usize> = sets
        .iter()
        .enumerate()
        .filter(|(_, set)| of_class(set))
        .map(|(i, set)| ((set.owner(), set.rtype()), i))
        .collect();
    let mut taken = vec![false; sets.len()];
    let mut name = question.name.clone().into_owned();
    let mut hops = Vec::new();
    let mut data = None;
    loop {
        if let Some(&i) = index.get(&(&name, question.qtype)) {
            data = Some(i);
            break;
        }
        if question.qtype == RecordType::CNAME {
            break;
        }
        let Some(&i) = index.get(&(&name, RecordType::CNAME)) else {
            break;
        };
        // A CNAME followed is not followed again: a loop ends there.
        if std::mem::replace(&mut taken[i], true) {
            break;
        }
        let Some(target) = target(&sets[i]) else {
            return Read::Unusable(Unusable::Malformed);
        };
        hops.push(i);
        name = target;
        if !name.is_within(zone) {
            break;
        }
    }
    let dname = (sets.iter()).position(|set| of_class(&set) && too_long(set, &name, zone));
    let mut sets: Vec<Option<Rrset>> = sets.into_iter().map(Some).collect();
    let first = &question.name;
    let mut take = |i: usize| sets[i].take().map(|set| answered(set, first));
    let mut chain: Vec<Ranked> = hops.into_iter().filter_map(&mut take).collect();
    if let Some(data) = data.and_then(&mut take) {
        return Read::Answer { chain, data };
    }
    if !name.is_within(zone) {
        return Read::Cname {
            chain,
            target: name,
        };
    }
    if let Some(dname) = dname.and_then(&mut take) {
        chain.push(dname);
        return Read::YxDomain { chain };
    }
    let soa = Rrset::group(&response.authority).into_iter().find(|set| {
        set.rtype() == RecordType::SOA
            && set.class() == question.qclass
            && set.owner().is_within(zone)
            && name.is_within(set.owner())
    });
    let soa = soa.map(|soa| ranked(soa, Rank::AuthorityAuthoritative));
    match (rcode, soa) {
        (Rcode::NXDOMAIN, Some(soa)) => Read::NxDomain { chain, soa },
        (Rcode::NOERROR, _) if !chain.is_empty() => Read::Cname {
            chain,
            target: name,
        },
        (Rcode::NOERROR, Some(soa)) => Read::NoData { soa },
        (Rcode::NXDOMAIN | Rcode::NOERROR, None) => Read::NoSoa,
        (rcode, _) => Read::Unusable(Unusable::Rcode(rcode)),
    }
}

/// The referral of `response` to the name of `question`, asked of `zone`: `None` unless its first NS record of
/// the class refers down, to a zone holding the name (RFC 1034 §4.3.2 step 3b), as one asked of a lame server may
/// refer up or sideways. The first `servers` names of the child's NS records are kept, with the glue for those
/// within `zone`: glue for a server out of the zone asked is not the server's to give (RFC 9471 §2.1, §2.2).
fn referral(
    response: &Message<'_>,
    question: &Question<'_>,
    zone: &Name<'_>,
    servers: usize,
) -> Option<Read> {
    let is_ns = |r: &&Record<'_>| r.rtype() == RecordType::NS && r.class == question.qclass;
    let child = &response.authority.iter().find(is_ns)?.name;
    if child == zone || !child.is_within(zone) || !question.name.is_within(child) {
        return None;
    }
    let mut names: Vec<Name<'static>> = Vec::new();
    let mut ns: Vec<Record<'_>> = Vec::new();
    for record in response
        .authority
        .iter()
        .filter(is_ns)
        .filter(|r| &r.name == child)
    {
        let RData::Ns(name) = record.data() else {
            continue;
        };
        if names.contains(&name) {
            continue;
        }
        if names.len() == servers {
            break;
        }
        names.push(name.into_owned());
        ns.push(record.clone());
    }
    let ns = Rrset::group(&ns).into_iter().next()?;
    let glue: Vec<Record<'_>> = response
        .additional
        .iter()
        .filter(|r| {
            matches!(r.rtype(), RecordType::A | RecordType::AAAA)
                && r.class == question.qclass
                && r.name.is_within(zone)
                && names.contains(&r.name)
        })
        .cloned()
        .collect();
    Some(Read::Referral {
        child: child.clone().into_owned(),
        ns: ranked(ns, Rank::AuthorityNonAuthoritative),
        glue: Rrset::group(&glue)
            .into_iter()
            .map(|set| ranked(set, Rank::AdditionalNonAuthoritative))
            .collect(),
    })
}

/// Whether `set` is a DNAME within `zone`, above `name`, whose synthesis from `name` is longer than 255 bytes (RFC
/// 6672 §2.2). A DNAME owning the name itself synthesizes nothing, and its target is never too long.
fn too_long(set: &Rrset, name: &Name<'_>, zone: &Name<'_>) -> bool {
    let owner = set.owner();
    if set.rtype() != RecordType::DNAME || !name.is_within(owner) || !owner.is_within(zone) {
        return false;
    }
    set.rdatas().iter().any(|rdata| match rdata.data() {
        RData::Opaque(data) => Name::from_uncompressed(data.data())
            .is_ok_and(|target| name.wire_len() - owner.wire_len() + target.wire_len() > MAX_NAME),
        _ => false,
    })
}

/// The longest name, in wire bytes (RFC 1035 §3.1).
const MAX_NAME: usize = 255;

/// The name a CNAME `RRset` points to, when it holds one record, as RFC 2181 §10.1 has it.
pub(super) fn target(cname: &Rrset) -> Option<Name<'static>> {
    match cname.rdatas() {
        [one] => match one.data() {
            RData::Cname(target) => Some(target.into_owned()),
            _ => None,
        },
        _ => None,
    }
}

/// `set` of an authoritative answer: authoritative at the name asked, past it not (RFC 2181 §5.4.1).
fn answered(set: Rrset, asked: &Name<'_>) -> Ranked {
    let rank = if set.owner() == asked {
        Rank::AnswerAuthoritative
    } else {
        Rank::AnswerNonAuthoritative
    };
    ranked(set, rank)
}

/// `set` as received, at `rank`, not yet validated.
fn ranked(set: Rrset, rank: Rank) -> Ranked {
    Ranked {
        ttl: set.ttl(),
        rrset: Arc::new(set),
        rank,
        checked: Checked::Unchecked,
    }
}
