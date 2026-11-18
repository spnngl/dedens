//! What a response may say: the records a server asked as one zone is trusted with, sorted by what they are for,
//! each with its [`Rank`] (D192).
//!
//! A server is trusted for the zone it was asked as and nothing else (RFC 2181 §6.1, RFC 5452 §6): a record owned
//! outside that zone, or of another class, is dropped whatever its section, as Unbound's `scrub_sanitize`
//! (`iterator/iter_scrub.c`) does; so is a record whose RDATA does not parse for its type (D9). Within the zone,
//! each section keeps only what its outcome needs:
//!
//! - an answer keeps the records at the name asked, or the CNAME and DNAME chain from it (RFC 1034 §4.3.2 step 3a)
//!   and the records at its end. A DNAME's CNAME is synthesised and the server's kept only when it is the same
//!   (RFC 6672 §3.4: a resolver synthesises); a chain leaving the zone, or ending without data, is
//!   [`Outcome::Cname`]: the zone's servers say nothing past it. A DNAME whose synthesis is longer than 255 bytes
//!   is the answer [`Outcome::YxDomain`] (RFC 6672 §2.2);
//! - a referral keeps one NS `RRset`, owned strictly below the zone and at or above the name asked (RFC 1034
//!   §4.3.2 step 3b), its DS records or the NSEC or NSEC3 records proving it has none (RFC 4035 §3.1.4), and the
//!   address records of its name servers within the zone as glue. A referral to the name asked, for its DS, is the
//!   answer: DS records are the parent's (RFC 4035 §3.1.4.1);
//! - a negative answer keeps one SOA at or above the name and the NSEC and NSEC3 records (RFC 2308 §2, RFC 4035
//!   §3.1.3); without the SOA it is [`Outcome::NoSoa`], which nothing caches (RFC 2308 §5). An answer keeps the
//!   NSEC and NSEC3 records of its wildcard proofs. Their NS records are dropped: Unbound's
//!   `iter-scrub-promiscuous`;
//! - an NSEC whose next name leaves the zone is dropped (Unbound's `sanitize_nsec_is_overreach`); an RRSIG stays
//!   with the `RRset` it covers, in its section, or goes.
//!
//! AA ranks the records (RFC 1035 §4.1.1, RFC 2181 §5.4.1) and does not decide the outcome, as in Unbound's
//! `response_type_from_server` (`iterator/iter_resptype.c`): a response without AA but with RA set is a cache
//! talking, [`Outcome::Lame`]; so is a referral that leads nowhere below the zone, whatever AA. Every bound is a
//! named constant below.

use std::collections::{HashMap, HashSet};

use dedens_proto::rdata::RData;
use dedens_proto::{Flags, Message, Name, Opcode, Question, Rcode, Record, RecordType, Section};

/// The most records of an NS or DS `RRset` kept, in a referral or an answer: 20, Unbound's `iter-scrub-ns`
/// (`shorten_rrset`). A referral's name servers are each a lookup more: a long list is a resolver's work
/// multiplied for one response (the NXNS attack).
pub const MAX_NS: usize = 20;

/// The most CNAME and DNAME hops followed in a response: 11, Unbound's `iter-scrub-cname` (whose check, `>`, lets a
/// twelfth through). The rest is the resolution's to ask again, under its own bound.
pub const MAX_CHAIN: usize = 11;

/// The most RRSIG records kept on an `RRset`: 8, Unbound's `iter-scrub-rrsig`. The validator tries each, so each
/// one more is a signature check more.
pub const MAX_SIGNATURES: usize = 8;

/// The most address records kept from an additional section: 100, Unbound's `iter-scrub-glue-count`.
pub const MAX_GLUE: usize = 100;

/// Where a record was read, which decides whether later data replaces it (RFC 2181 §5.4.1), least trusted first.
///
/// The RFC puts the additional section of an authoritative answer and the authority and additional sections of a
/// non-authoritative one at one level; they are three here, as in Unbound (`rrset_trust`). Only
/// [`Rank::AnswerNonAuthoritative`] and above may answer a client.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Rank {
    /// The additional section of a non-authoritative answer, or a referral's glue.
    AdditionalNonAuthoritative,
    /// The authority section of a non-authoritative answer, or a referral's NS, DS and NSEC records.
    AuthorityNonAuthoritative,
    /// The additional section of an authoritative answer.
    AdditionalAuthoritative,
    /// The answer section of a non-authoritative answer, or of an authoritative one past its first owner name: AA
    /// covers that name only (RFC 1035 §4.1.1). The least rank that answers a client.
    AnswerNonAuthoritative,
    /// The authority section of an authoritative answer.
    AuthorityAuthoritative,
    /// The answer section of an authoritative answer, at the name asked or the first owner name (a DNAME's).
    AnswerAuthoritative,
}

/// A response scrubbed: what it says, and what was dropped from it.
#[derive(Debug, Clone)]
pub struct Scrubbed<'m> {
    /// What the response says.
    pub outcome: Outcome<'m>,
    /// The records dropped, in message order; none when the outcome is [`Outcome::Lame`] or [`Outcome::Unusable`],
    /// which keep nothing.
    pub dropped: Vec<Dropped>,
    /// The name asked, which ranks a chain.
    name: Name<'m>,
    /// Whether AA was set, which ranks every record.
    authoritative: bool,
}

/// What a scrubbed response says.
#[derive(Debug, Clone)]
pub enum Outcome<'m> {
    /// Data at the name asked or at the end of its chain.
    Answer {
        /// The CNAME and DNAME records from the name asked, in order, synthesised CNAMEs included, with their RRSIGs.
        chain: Vec<Record<'m>>,
        /// The records of the type asked at the chain's end, with their RRSIGs.
        records: Vec<Record<'m>>,
        /// NSEC and NSEC3 records proving a wildcard expansion, with their RRSIGs.
        denials: Vec<Record<'m>>,
        /// The addresses of the name servers of an NS answer, within the zone.
        additional: Vec<Record<'m>>,
    },
    /// A chain the zone's servers cannot finish: it leaves the zone, ends without data, or is past [`MAX_CHAIN`].
    Cname {
        /// The CNAME and DNAME records followed, as in [`Outcome::Answer`].
        chain: Vec<Record<'m>>,
        /// The name to resolve next.
        target: Name<'m>,
        /// NSEC and NSEC3 records, as in [`Outcome::Answer`].
        denials: Vec<Record<'m>>,
    },
    /// A delegation toward the name asked (RFC 1034 §4.3.2 step 3b).
    Referral {
        /// The zone delegated, strictly below the zone asked.
        child: Name<'m>,
        /// Its NS records, at most [`MAX_NS`].
        ns: Vec<Record<'m>>,
        /// Its DS records, or the NSEC or NSEC3 records proving it has none, with their RRSIGs.
        proof: Vec<Record<'m>>,
        /// The addresses of its name servers within the zone asked, at most [`MAX_GLUE`].
        glue: Vec<Record<'m>>,
    },
    /// The name exists, without data of the type asked (RFC 2308 §2.2).
    NoData {
        /// The zone's SOA, whose TTL and MINIMUM bound the negative answer's (RFC 2308 §5).
        soa: Record<'m>,
        /// The NSEC or NSEC3 records, with their RRSIGs and the SOA's.
        denials: Vec<Record<'m>>,
    },
    /// The name, or the end of its chain, does not exist (RFC 2308 §2.1).
    NxDomain {
        /// The CNAME and DNAME records followed, as in [`Outcome::Answer`].
        chain: Vec<Record<'m>>,
        /// As in [`Outcome::NoData`].
        soa: Record<'m>,
        /// As in [`Outcome::NoData`].
        denials: Vec<Record<'m>>,
    },
    /// A DNAME makes a name longer than 255 bytes of the name asked, or of its chain: the answer is YXDOMAIN
    /// (RFC 6672 §2.2).
    YxDomain {
        /// The CNAME and DNAME records followed, as in [`Outcome::Answer`], the DNAME last.
        chain: Vec<Record<'m>>,
    },
    /// A negative answer without the zone's SOA: nothing caches it (RFC 2308 §5).
    NoSoa(Negative<'m>),
    /// The server is not authoritative for the name: a cache answering (RA set, AA clear), or a referral that
    /// leads nowhere below the zone (RFC 4697 §2.2).
    Lame,
    /// The response cannot be read as one to the question.
    Unusable(Unusable),
}

/// The negative answer of an [`Outcome::NoSoa`].
#[derive(Debug, Clone)]
pub enum Negative<'m> {
    /// As [`Outcome::NoData`].
    NoData,
    /// As [`Outcome::NxDomain`].
    NxDomain {
        /// The CNAME and DNAME records followed, as in [`Outcome::Answer`].
        chain: Vec<Record<'m>>,
    },
}

/// Why a response cannot be read as one to the question.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Unusable {
    /// QR is unset, or the opcode is not QUERY.
    NotResponse,
    /// TC is set: the question goes again over TCP (RFC 7766 §5).
    Truncated,
    /// A response code other than NOERROR, NXDOMAIN and YXDOMAIN; or YXDOMAIN without a DNAME whose synthesis is
    /// too long (RFC 6672 §2.2).
    Rcode(Rcode),
    /// Not exactly the question asked, name, type and class.
    QuestionMismatch,
    /// The name asked is outside the zone the server was asked as: the caller's error.
    OutsideZone,
}

/// A record dropped: its place in the response and why.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Dropped {
    /// Its section.
    pub section: Section,
    /// Its index in the section.
    pub index: usize,
    /// Why it was dropped.
    pub reason: Reason,
}

/// Why a record was dropped.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Reason {
    /// Its class is not the question's.
    OtherClass,
    /// Its owner is outside the zone the server was asked as.
    OutsideZone,
    /// Its RDATA does not parse for its type (D9), or a DNAME's is compressed (RFC 6672 §2.5); or it is the CNAME a
    /// DNAME so dropped would have made.
    Malformed,
    /// An answer record on no chain from the name asked, or not of the type asked at its end.
    OffChain,
    /// An NS `RRset` other than the referral's: at or above the zone, beside the name asked, or a second one.
    NotDelegation,
    /// A type the authority section does not carry in this outcome.
    NotAllowed,
    /// An additional record that is not the address of a name server kept.
    NotGlue,
    /// An NSEC whose next name is outside the zone.
    Overreach,
    /// Past [`MAX_NS`], in an NS or DS `RRset`.
    TooManyRecords,
    /// Past [`MAX_CHAIN`].
    ChainTooLong,
    /// Past [`MAX_SIGNATURES`].
    TooManySignatures,
    /// Past [`MAX_GLUE`].
    TooMuchGlue,
}

impl<'m> Scrubbed<'m> {
    /// Every record kept with its rank, in the order of the outcome's fields.
    #[must_use]
    pub fn ranked(&self) -> Vec<(Rank, &Record<'m>)> {
        let aa = self.authoritative;
        let (authority, additional) = if aa {
            (Rank::AuthorityAuthoritative, Rank::AdditionalAuthoritative)
        } else {
            (
                Rank::AuthorityNonAuthoritative,
                Rank::AdditionalNonAuthoritative,
            )
        };
        // AA covers the name asked, and the first owner name: a DNAME's, above it.
        let answer = |chain: &[Record<'m>], r: &Record<'m>| {
            if aa && (r.name == self.name || chain.first().is_some_and(|f| f.name == r.name)) {
                Rank::AnswerAuthoritative
            } else {
                Rank::AnswerNonAuthoritative
            }
        };
        let with = |rank: Rank| move |r| (rank, r);
        match &self.outcome {
            Outcome::Answer {
                chain,
                records,
                denials,
                additional: glue,
            } => chain
                .iter()
                .chain(records)
                .map(|r| (answer(chain, r), r))
                .chain(denials.iter().map(with(authority)))
                .chain(glue.iter().map(with(additional)))
                .collect(),
            Outcome::Cname { chain, denials, .. } => chain
                .iter()
                .map(|r| (answer(chain, r), r))
                .chain(denials.iter().map(with(authority)))
                .collect(),
            Outcome::NxDomain {
                chain,
                soa,
                denials,
            } => chain
                .iter()
                .map(|r| (answer(chain, r), r))
                .chain([soa].into_iter().chain(denials).map(with(authority)))
                .collect(),
            Outcome::NoData { soa, denials } => [soa]
                .into_iter()
                .chain(denials)
                .map(with(authority))
                .collect(),
            Outcome::YxDomain { chain } | Outcome::NoSoa(Negative::NxDomain { chain }) => {
                chain.iter().map(|r| (answer(chain, r), r)).collect()
            }
            Outcome::Referral {
                ns, proof, glue, ..
            } => ns
                .iter()
                .chain(proof)
                .map(with(Rank::AuthorityNonAuthoritative))
                .chain(glue.iter().map(with(Rank::AdditionalNonAuthoritative)))
                .collect(),
            Outcome::NoSoa(Negative::NoData) | Outcome::Lame | Outcome::Unusable(_) => Vec::new(),
        }
    }
}

/// Scrubs `response` to `question`, from a server asked as authoritative for `zone`: the records it may be trusted
/// with, sorted by outcome; the module's documentation has the rules.
#[must_use]
pub fn scrub<'m>(
    response: &'m Message<'m>,
    question: &Question<'_>,
    zone: &Name<'_>,
) -> Scrubbed<'m> {
    let header = &response.header;
    let unusable = |why| Scrubbed {
        outcome: Outcome::Unusable(why),
        dropped: Vec::new(),
        name: Name::root(),
        authoritative: false,
    };
    if !header.flags.contains(Flags::QR) || header.opcode != Opcode::QUERY {
        return unusable(Unusable::NotResponse);
    }
    if header.flags.contains(Flags::TC) {
        return unusable(Unusable::Truncated);
    }
    let rcode = response.rcode();
    if ![Rcode::NOERROR, Rcode::NXDOMAIN, Rcode::YXDOMAIN].contains(&rcode) {
        return unusable(Unusable::Rcode(rcode));
    }
    let [asked] = response.questions.as_slice() else {
        return unusable(Unusable::QuestionMismatch);
    };
    if asked.name != question.name
        || asked.qtype != question.qtype
        || asked.qclass != question.qclass
    {
        return unusable(Unusable::QuestionMismatch);
    }
    if !asked.name.is_within(zone) {
        return unusable(Unusable::OutsideZone);
    }
    let aa = header.flags.contains(Flags::AA);
    let mut s = Scrub::new(response, asked, zone);
    let outcome = match s.outcome(&asked.name, asked.qtype, rcode, header.flags) {
        Ok(outcome) => outcome,
        Err(why) => return unusable(why),
    };
    Scrubbed {
        dropped: if matches!(outcome, Outcome::Lame) {
            Vec::new()
        } else {
            s.dropped()
        },
        outcome,
        name: asked.name.clone(),
        authoritative: aa,
    }
}

/// The fate of a record of the response, while it is scrubbed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Fate {
    /// Not decided yet; dropped at the end, for its section's reason.
    Pending,
    Kept,
    Dropped(Reason),
}

/// Why the way from the name asked stops.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Stop {
    /// At the data, or where the answer section says no more.
    End,
    /// Before its end: at [`MAX_CHAIN`], or out of the zone.
    Cut,
    /// At a DNAME whose synthesis is longer than 255 bytes.
    TooLong,
}

/// The way from the name asked through the answer section.
struct Walk<'m> {
    /// The CNAME and DNAME records followed, synthesised CNAMEs included.
    chain: Vec<Record<'m>>,
    /// The records of the type asked at `end`.
    records: Vec<Record<'m>>,
    /// Where the chain ends.
    end: Name<'m>,
    stop: Stop,
}

/// A response being scrubbed: the fate of each record, by section.
struct Scrub<'m, 'z> {
    response: &'m Message<'m>,
    zone: &'z Name<'z>,
    fates: [Vec<Fate>; 3],
}

/// Where a section's fates are in [`Scrub::fates`].
const fn slot(section: Section) -> usize {
    match section {
        Section::Answer => 0,
        Section::Authority => 1,
        Section::Additional => 2,
    }
}

/// The target of a DNAME, a name not compressed (RFC 6672 §2.1, §2.5); `None` for any other RDATA.
fn dname_target(r: &Record<'_>) -> Option<Name<'static>> {
    match r.data() {
        RData::Opaque(data) => Name::from_uncompressed(data.data())
            .ok()
            .map(Name::into_owned),
        _ => None,
    }
}

/// Whether the RDATA of `r` does not parse for its type.
fn malformed(r: &Record<'_>) -> bool {
    if r.rtype() == RecordType::DNAME {
        return dname_target(r).is_none();
    }
    RData::has_typed_form(r.rtype()) && matches!(r.data(), RData::Opaque(_))
}

impl<'m, 'z> Scrub<'m, 'z> {
    /// Drops the records of another class, those owned outside `zone`, and those whose RDATA does not parse.
    fn new(response: &'m Message<'m>, question: &Question<'_>, zone: &'z Name<'z>) -> Self {
        let fates = |records: &[Record<'_>]| {
            records
                .iter()
                .map(|r| {
                    if r.class != question.qclass {
                        Fate::Dropped(Reason::OtherClass)
                    } else if !r.name.is_within(zone) {
                        Fate::Dropped(Reason::OutsideZone)
                    } else if malformed(r) {
                        Fate::Dropped(Reason::Malformed)
                    } else {
                        Fate::Pending
                    }
                })
                .collect()
        };
        Self {
            response,
            zone,
            fates: [
                fates(&response.answer),
                fates(&response.authority),
                fates(&response.additional),
            ],
        }
    }

    fn records(&self, section: Section) -> &'m [Record<'m>] {
        match section {
            Section::Answer => &self.response.answer,
            Section::Authority => &self.response.authority,
            Section::Additional => &self.response.additional,
        }
    }

    /// The records of `section` not decided yet, with their index.
    fn pending(
        &self,
        section: Section,
    ) -> impl Iterator<Item = (usize, &'m Record<'m>)> + use<'m, '_, 'z> {
        self.records(section)
            .iter()
            .enumerate()
            .filter(move |&(i, _)| self.fates[slot(section)][i] == Fate::Pending)
    }

    fn set(&mut self, section: Section, index: usize, fate: Fate) -> &'m Record<'m> {
        self.fates[slot(section)][index] = fate;
        &self.records(section)[index]
    }

    /// Keeps the pending records of `section` that `wanted` picks into `into`, at most `max`, the rest of them
    /// dropped for `over`.
    fn take(
        &mut self,
        section: Section,
        wanted: impl Fn(&Record<'m>) -> bool,
        max: usize,
        over: Reason,
        into: &mut Vec<Record<'m>>,
    ) {
        let picked: Vec<usize> = self
            .pending(section)
            .filter(|(_, r)| wanted(r))
            .map(|(i, _)| i)
            .collect();
        for (n, i) in picked.into_iter().enumerate() {
            if n < max {
                into.push(self.set(section, i, Fate::Kept).clone());
            } else {
                self.set(section, i, Fate::Dropped(over));
            }
        }
    }

    /// What the response to `name` and `qtype` says. As Unbound's `response_type_from_server`, a NOERROR response
    /// without an SOA is a referral when the authority section holds one, or an answer section without AA holds
    /// one for an NS question; a delegation that leads nowhere below the zone is lame.
    fn outcome(
        &mut self,
        name: &Name<'m>,
        qtype: RecordType,
        rcode: Rcode,
        flags: Flags,
    ) -> Result<Outcome<'m>, Unusable> {
        let aa = flags.contains(Flags::AA);
        if rcode == Rcode::NOERROR {
            let soa = self
                .pending(Section::Authority)
                .any(|(_, r)| r.rtype() == RecordType::SOA);
            let answered = self.pending(Section::Answer).next().is_some();
            if !soa && (!answered || !aa) {
                if let Some(referral) = self.referral(name, qtype, Section::Authority) {
                    return Ok(referral);
                }
                // NS at the zone or above it, the latter dropped as outside it.
                if !answered
                    && self
                        .records(Section::Authority)
                        .iter()
                        .any(|r| r.rtype() == RecordType::NS)
                {
                    return Ok(Outcome::Lame);
                }
            }
            if !aa
                && matches!(qtype, RecordType::NS | RecordType::ANY)
                && let Some(referral) = self.referral(name, qtype, Section::Answer)
            {
                return Ok(referral);
            }
        }
        if !aa && flags.contains(Flags::RA) {
            return Ok(Outcome::Lame);
        }
        self.answer(name, qtype, rcode)
    }

    /// The referral toward `name` from the NS records of `section`, if the first one owned strictly below the zone
    /// is at or above `name`; the other NS records are dropped. For a DS question at that NS owner, its DS records
    /// are the answer, as in Unbound (6cb75924d).
    fn referral(
        &mut self,
        name: &Name<'_>,
        qtype: RecordType,
        section: Section,
    ) -> Option<Outcome<'m>> {
        let child = self
            .pending(section)
            .find(|(_, r)| {
                r.rtype() == RecordType::NS && r.name != *self.zone && name.is_within(&r.name)
            })
            .map(|(_, r)| r.name.clone())?;
        let mut ds = Vec::new();
        self.take(
            Section::Authority,
            |r| r.rtype() == RecordType::DS && r.name == child,
            MAX_NS,
            Reason::TooManyRecords,
            &mut ds,
        );
        if qtype == RecordType::DS && child == *name && !ds.is_empty() {
            self.sign(Section::Authority, &mut [&mut ds]);
            return Some(Outcome::Answer {
                chain: Vec::new(),
                records: ds,
                denials: Vec::new(),
                additional: Vec::new(),
            });
        }
        let mut ns = Vec::new();
        let is_ns = |r: &Record<'_>| r.rtype() == RecordType::NS;
        self.take(
            section,
            |r| is_ns(r) && r.name == child,
            MAX_NS,
            Reason::TooManyRecords,
            &mut ns,
        );
        self.take(section, is_ns, 0, Reason::NotDelegation, &mut Vec::new());
        let mut proof = ds;
        self.denials(&mut proof);
        self.sign(section, &mut [&mut ns]);
        self.sign(Section::Authority, &mut [&mut proof]);
        let glue = self.glue(&ns);
        Some(Outcome::Referral {
            child,
            ns,
            proof,
            glue,
        })
    }

    /// The answer, or negative answer, to `name` and `qtype`.
    fn answer(
        &mut self,
        name: &Name<'m>,
        qtype: RecordType,
        rcode: Rcode,
    ) -> Result<Outcome<'m>, Unusable> {
        let Walk {
            mut chain,
            mut records,
            end: at,
            stop,
        } = self.walk(name, qtype, rcode == Rcode::NOERROR);
        self.sign(Section::Answer, &mut [&mut chain, &mut records]);
        if stop == Stop::TooLong {
            return Ok(Outcome::YxDomain { chain });
        }
        if rcode == Rcode::YXDOMAIN {
            return Err(Unusable::Rcode(rcode));
        }
        let nxdomain = rcode == Rcode::NXDOMAIN;
        let mut denials = Vec::new();
        if !records.is_empty() || stop == Stop::Cut || !(nxdomain || chain.is_empty()) {
            self.denials(&mut denials);
            self.sign(Section::Authority, &mut [&mut denials]);
            return Ok(if records.is_empty() {
                Outcome::Cname {
                    chain,
                    target: at,
                    denials,
                }
            } else {
                let additional = self.glue(&records);
                Outcome::Answer {
                    chain,
                    records,
                    denials,
                    additional,
                }
            });
        }
        let Some((i, _)) = self
            .pending(Section::Authority)
            .find(|(_, r)| r.rtype() == RecordType::SOA && at.is_within(&r.name))
        else {
            return Ok(Outcome::NoSoa(if nxdomain {
                Negative::NxDomain { chain }
            } else {
                Negative::NoData
            }));
        };
        let soa = self.set(Section::Authority, i, Fate::Kept).clone();
        let mut signed = vec![soa.clone()];
        self.denials(&mut denials);
        self.sign(Section::Authority, &mut [&mut signed, &mut denials]);
        denials.extend(signed.into_iter().skip(1));
        Ok(if nxdomain {
            Outcome::NxDomain {
                chain,
                soa,
                denials,
            }
        } else {
            Outcome::NoData { soa, denials }
        })
    }

    /// Follows the CNAME and DNAME records of the answer section from `name`, and keeps the records of `qtype` at the
    /// end when `answers`.
    fn walk(&mut self, name: &Name<'m>, qtype: RecordType, answers: bool) -> Walk<'m> {
        let (mut chain, mut records) = (Vec::new(), Vec::new());
        let mut at = name.clone();
        let mut hops = 0;
        let stop = loop {
            if !at.is_within(self.zone) {
                break Stop::Cut;
            }
            if let Some((i, alias)) = self.dname(&at) {
                if hops == MAX_CHAIN {
                    self.set(Section::Answer, i, Fate::Dropped(Reason::ChainTooLong));
                    break Stop::Cut;
                }
                let dname = self.set(Section::Answer, i, Fate::Kept);
                chain.push(dname.clone());
                let Some(alias) = alias else {
                    break Stop::TooLong;
                };
                let cname =
                    if let Some((j, _)) = self.cname(&at).filter(|(_, target)| *target == alias) {
                        self.set(Section::Answer, j, Fate::Kept).clone()
                    } else {
                        // The server's signatures cover its own CNAME, not this one.
                        self.drop_signatures(&at, RecordType::CNAME);
                        Record::new(
                            at.clone(),
                            dname.class,
                            dname.ttl,
                            &RData::Cname(alias.clone()),
                        )
                    };
                hops += 1;
                at = alias;
                // A question for the CNAME is answered by it (RFC 6672 §2.3), not by the alias's data.
                if qtype == RecordType::CNAME {
                    records.push(cname);
                    break Stop::End;
                }
                chain.push(cname);
                continue;
            }
            if answers {
                let max = if matches!(qtype, RecordType::NS | RecordType::DS) {
                    MAX_NS
                } else {
                    usize::MAX
                };
                self.take(
                    Section::Answer,
                    |r| {
                        r.name == at
                            && (r.rtype() == qtype
                                || qtype == RecordType::ANY && r.rtype() != RecordType::RRSIG)
                    },
                    max,
                    Reason::TooManyRecords,
                    &mut records,
                );
                if !records.is_empty() {
                    break Stop::End;
                }
            }
            let Some((i, target)) = self.cname(&at) else {
                break Stop::End;
            };
            if self.under_malformed_dname(&at) {
                self.set(Section::Answer, i, Fate::Dropped(Reason::Malformed));
                break Stop::End;
            }
            if hops == MAX_CHAIN {
                self.set(Section::Answer, i, Fate::Dropped(Reason::ChainTooLong));
                break Stop::Cut;
            }
            chain.push(self.set(Section::Answer, i, Fate::Kept).clone());
            hops += 1;
            at = target;
        };
        Walk {
            chain,
            records,
            end: at,
            stop,
        }
    }

    /// The first pending DNAME strictly above `at` (RFC 6672 §2.2), with the name it makes of `at`: `None` when
    /// longer than 255 bytes.
    fn dname(&self, at: &Name<'_>) -> Option<(usize, Option<Name<'static>>)> {
        self.pending(Section::Answer).find_map(|(i, r)| {
            if r.rtype() != RecordType::DNAME || r.name == *at || !at.is_within(&r.name) {
                return None;
            }
            let target = dname_target(r)?;
            let kept = at.label_count() - r.name.label_count();
            let alias = Name::from_labels(at.labels().take(kept).chain(target.labels())).ok();
            Some((i, alias))
        })
    }

    /// Whether a DNAME dropped as [`Reason::Malformed`] is strictly above `at`: the CNAME there is its synthesis,
    /// which nothing checks.
    fn under_malformed_dname(&self, at: &Name<'_>) -> bool {
        self.records(Section::Answer)
            .iter()
            .zip(&self.fates[slot(Section::Answer)])
            .any(|(r, fate)| {
                *fate == Fate::Dropped(Reason::Malformed)
                    && r.rtype() == RecordType::DNAME
                    && r.name != *at
                    && at.is_within(&r.name)
            })
    }

    /// The first pending CNAME at `at`, with its target.
    fn cname(&self, at: &Name<'_>) -> Option<(usize, Name<'m>)> {
        self.pending(Section::Answer)
            .filter(|(_, r)| r.rtype() == RecordType::CNAME && r.name == *at)
            .find_map(|(i, r)| match r.data() {
                RData::Cname(target) => Some((i, target)),
                _ => None,
            })
    }

    /// Drops the pending RRSIGs of the answer section at `at` covering `rtype`, as off the chain.
    fn drop_signatures(&mut self, at: &Name<'_>, rtype: RecordType) {
        let found: Vec<usize> = self
            .pending(Section::Answer)
            .filter(|(_, r)| {
                r.rtype() == RecordType::RRSIG
                    && r.name == *at
                    && matches!(r.data(), RData::Rrsig(sig) if sig.type_covered == rtype)
            })
            .map(|(i, _)| i)
            .collect();
        for i in found {
            self.set(Section::Answer, i, Fate::Dropped(Reason::OffChain));
        }
    }

    /// Keeps the NSEC and NSEC3 records of the authority section into `into`; an NSEC whose next name is outside
    /// the zone is dropped.
    fn denials(&mut self, into: &mut Vec<Record<'m>>) {
        let found: Vec<(usize, bool)> = self
            .pending(Section::Authority)
            .filter_map(|(i, r)| match r.data() {
                RData::Nsec(nsec) => Some((i, nsec.next.is_within(self.zone))),
                RData::Nsec3(_) => Some((i, true)),
                _ => None,
            })
            .collect();
        for (i, within) in found {
            if within {
                into.push(self.set(Section::Authority, i, Fate::Kept).clone());
            } else {
                self.set(Section::Authority, i, Fate::Dropped(Reason::Overreach));
            }
        }
    }

    /// Keeps the RRSIGs of `section` covering an `RRset` of `sets`, each into the set it covers, at most
    /// [`MAX_SIGNATURES`] an `RRset`.
    fn sign(&mut self, section: Section, sets: &mut [&mut Vec<Record<'m>>]) {
        let mut covered: HashMap<(Name<'m>, RecordType), (usize, usize)> = HashMap::new();
        for (set, records) in sets.iter().enumerate() {
            for r in records.iter() {
                covered
                    .entry((r.name.clone(), r.rtype()))
                    .or_insert((set, 0));
            }
        }
        let found: Vec<(usize, usize, bool)> = self
            .pending(section)
            .filter_map(|(i, r)| match r.data() {
                RData::Rrsig(sig) => {
                    let (set, count) = covered.get_mut(&(r.name.clone(), sig.type_covered))?;
                    *count += 1;
                    Some((i, *set, *count <= MAX_SIGNATURES))
                }
                _ => None,
            })
            .collect();
        for (i, set, kept) in found {
            if kept {
                sets[set].push(self.set(section, i, Fate::Kept).clone());
            } else {
                self.set(section, i, Fate::Dropped(Reason::TooManySignatures));
            }
        }
    }

    /// The address records of the additional section at the names of the name servers in `records`, at most
    /// [`MAX_GLUE`], with their RRSIGs.
    fn glue(&mut self, records: &[Record<'m>]) -> Vec<Record<'m>> {
        let servers: HashSet<Name<'_>> = records
            .iter()
            .filter_map(|r| match r.data() {
                RData::Ns(server) => Some(server.into_owned()),
                _ => None,
            })
            .collect();
        let mut glue = Vec::new();
        if !servers.is_empty() {
            self.take(
                Section::Additional,
                |r| {
                    matches!(r.rtype(), RecordType::A | RecordType::AAAA)
                        && servers.contains(&r.name)
                },
                MAX_GLUE,
                Reason::TooMuchGlue,
                &mut glue,
            );
            self.sign(Section::Additional, &mut [&mut glue]);
        }
        glue
    }

    /// The records dropped, the pending ones for their section's reason.
    fn dropped(&self) -> Vec<Dropped> {
        [
            (Section::Answer, Reason::OffChain),
            (Section::Authority, Reason::NotAllowed),
            (Section::Additional, Reason::NotGlue),
        ]
        .into_iter()
        .flat_map(|(section, pending)| {
            self.fates[slot(section)].iter().enumerate().filter_map(
                move |(index, fate)| match *fate {
                    Fate::Kept => None,
                    Fate::Pending => Some(Dropped {
                        section,
                        index,
                        reason: pending,
                    }),
                    Fate::Dropped(reason) => Some(Dropped {
                        section,
                        index,
                        reason,
                    }),
                },
            )
        })
        .collect()
    }
}
