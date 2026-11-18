//! What a response may say: the records a server asked as one zone is trusted with, sorted by what they are for,
//! each with its [`Rank`] (D192).
//!
//! A server is trusted for the zone it was asked as and nothing else (RFC 2181 §6.1, RFC 5452 §6): a record owned
//! outside that zone, or of another class, is dropped whatever its section, as Unbound's `scrub_sanitize`
//! (`iterator/iter_scrub.c`) does. Within the zone, each section keeps only what its outcome needs:
//!
//! - an authoritative answer (AA) keeps the records at the name asked, or the CNAME and DNAME chain from it
//!   (RFC 1034 §4.3.2 step 3a) and the records at its end. A DNAME's CNAME is synthesised and the server's kept
//!   only when it is the same (RFC 6672 §3.4: a resolver synthesises); a chain leaving the zone, or ending without
//!   data, is [`Outcome::Cname`]: the zone's servers say nothing past it;
//! - a referral keeps one NS `RRset`, owned strictly below the zone and at or above the name asked (RFC 1034
//!   §4.3.2 step 3b), its DS records or the NSEC or NSEC3 records proving it has none (RFC 4035 §3.1.4), and the
//!   address records of its name servers within the zone as glue;
//! - a negative answer keeps one SOA at or above the name and the NSEC and NSEC3 records (RFC 2308 §2, RFC 4035
//!   §3.1.3); an answer keeps the NSEC and NSEC3 records of its wildcard proofs. Their NS records are dropped:
//!   Unbound's `iter-scrub-promiscuous`;
//! - an NSEC whose next name leaves the zone is dropped (Unbound's `sanitize_nsec_is_overreach`); an RRSIG stays
//!   with the `RRset` it covers, in its section, or goes.
//!
//! A response without AA is a referral or nothing ([`Outcome::Lame`]): its answer and authority would be data the
//! server holds from elsewhere (RFC 2181 §5.4.1, RFC 4697 §2.2). Every bound is a named constant below.

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
    /// The additional section of a non-authoritative answer: the glue of a referral.
    AdditionalNonAuthoritative,
    /// The authority section of a non-authoritative answer: the NS, DS and NSEC records of a referral.
    AuthorityNonAuthoritative,
    /// The additional section of an authoritative answer.
    AdditionalAuthoritative,
    /// A CNAME chain of an authoritative answer past the name asked: the server answers for the first owner name
    /// only (RFC 1035 §4.1.1, AA). The least rank that answers a client.
    AnswerNonAuthoritative,
    /// The authority section of an authoritative answer.
    AuthorityAuthoritative,
    /// The answer section of an authoritative answer, at the name asked.
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
        authority: Vec<Record<'m>>,
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
        authority: Vec<Record<'m>>,
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
        /// The SOA and NSEC or NSEC3 records, with their RRSIGs.
        authority: Vec<Record<'m>>,
    },
    /// The name, or the end of its chain, does not exist (RFC 2308 §2.1).
    NxDomain {
        /// The CNAME and DNAME records followed, as in [`Outcome::Answer`].
        chain: Vec<Record<'m>>,
        /// The SOA and NSEC or NSEC3 records, with their RRSIGs.
        authority: Vec<Record<'m>>,
    },
    /// The server is not authoritative for the name: an answer without AA, or a referral that leads nowhere below
    /// the zone (RFC 4697 §2.2).
    Lame,
    /// The response cannot be read as one to the question.
    Unusable(Unusable),
}

/// Why a response cannot be read as one to the question.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Unusable {
    /// QR is unset, or the opcode is not QUERY.
    NotResponse,
    /// TC is set: the question goes again over TCP (RFC 7766 §5).
    Truncated,
    /// A response code other than NOERROR and NXDOMAIN.
    Rcode(Rcode),
    /// Not exactly the question asked, name, type and class.
    QuestionMismatch,
    /// The name asked is outside the zone the server was asked as: the caller's error.
    OutsideZone,
    /// A DNAME's synthesised name is longer than 255 bytes, which the server should have answered with YXDOMAIN
    /// (RFC 6672 §2.2).
    DnameTooLong,
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
    /// Past [`MAX_NS`].
    TooManyNs,
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
        let answer = |r: &Record<'m>| {
            if r.name == self.name {
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
                authority,
                additional,
            } => chain
                .iter()
                .chain(records)
                .map(|r| (answer(r), r))
                .chain(authority.iter().map(with(Rank::AuthorityAuthoritative)))
                .chain(additional.iter().map(with(Rank::AdditionalAuthoritative)))
                .collect(),
            Outcome::Cname {
                chain, authority, ..
            }
            | Outcome::NxDomain { chain, authority } => chain
                .iter()
                .map(|r| (answer(r), r))
                .chain(authority.iter().map(with(Rank::AuthorityAuthoritative)))
                .collect(),
            Outcome::NoData { authority } => authority
                .iter()
                .map(with(Rank::AuthorityAuthoritative))
                .collect(),
            Outcome::Referral {
                ns, proof, glue, ..
            } => ns
                .iter()
                .chain(proof)
                .map(with(Rank::AuthorityNonAuthoritative))
                .chain(glue.iter().map(with(Rank::AdditionalNonAuthoritative)))
                .collect(),
            Outcome::Lame | Outcome::Unusable(_) => Vec::new(),
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
    };
    if !header.flags.contains(Flags::QR) || header.opcode != Opcode::QUERY {
        return unusable(Unusable::NotResponse);
    }
    if header.flags.contains(Flags::TC) {
        return unusable(Unusable::Truncated);
    }
    let rcode = response.rcode();
    if rcode != Rcode::NOERROR && rcode != Rcode::NXDOMAIN {
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
    let name = asked.name.clone();
    let aa = header.flags.contains(Flags::AA);
    let nxdomain = rcode == Rcode::NXDOMAIN;
    let mut s = Scrub::new(response, asked, zone);
    let referral = !nxdomain
        && response.answer.is_empty()
        && !response
            .authority
            .iter()
            .any(|r| r.rtype() == RecordType::SOA);
    let outcome = match referral.then(|| s.referral(&name)).flatten() {
        Some(referral) => referral,
        None if !aa => Outcome::Lame,
        None => match s.answer(&name, asked.qtype, nxdomain) {
            Ok(outcome) => outcome,
            Err(why) => return unusable(why),
        },
    };
    if matches!(outcome, Outcome::Lame) {
        return Scrubbed {
            outcome,
            dropped: Vec::new(),
            name,
        };
    }
    Scrubbed {
        outcome,
        dropped: s.dropped(),
        name,
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

/// The way from the name asked through the answer section.
struct Walk<'m> {
    /// The CNAME and DNAME records followed, synthesised CNAMEs included.
    chain: Vec<Record<'m>>,
    /// The records of the type asked at `end`.
    records: Vec<Record<'m>>,
    /// Where the chain ends.
    end: Name<'m>,
    /// Whether the chain stops before its end: at [`MAX_CHAIN`], or out of the zone.
    cut: bool,
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

impl<'m, 'z> Scrub<'m, 'z> {
    /// Drops the records of another class, and those owned outside `zone`.
    fn new(response: &'m Message<'m>, question: &Question<'_>, zone: &'z Name<'z>) -> Self {
        let fates = |records: &[Record<'_>]| {
            records
                .iter()
                .map(|r| {
                    if r.class != question.qclass {
                        Fate::Dropped(Reason::OtherClass)
                    } else if !r.name.is_within(zone) {
                        Fate::Dropped(Reason::OutsideZone)
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

    /// The referral toward `name`, if the authority section holds an NS `RRset` owned strictly below the zone and
    /// at or above `name`.
    fn referral(&mut self, name: &Name<'_>) -> Option<Outcome<'m>> {
        let child = self
            .pending(Section::Authority)
            .find(|(_, r)| {
                r.rtype() == RecordType::NS && r.name != *self.zone && name.is_within(&r.name)
            })
            .map(|(_, r)| r.name.clone())?;
        let mut ns = Vec::new();
        let is_ns = |r: &Record<'_>| r.rtype() == RecordType::NS;
        self.take(
            Section::Authority,
            |r| is_ns(r) && r.name == child,
            MAX_NS,
            Reason::TooManyNs,
            &mut ns,
        );
        self.take(
            Section::Authority,
            is_ns,
            0,
            Reason::NotDelegation,
            &mut Vec::new(),
        );
        let mut proof = Vec::new();
        self.take(
            Section::Authority,
            |r| r.rtype() == RecordType::DS && r.name == child,
            MAX_NS,
            Reason::TooManyNs,
            &mut proof,
        );
        self.denials(&mut proof);
        self.sign(Section::Authority, &mut [&mut ns, &mut proof]);
        let glue = self.glue(&ns);
        Some(Outcome::Referral {
            child,
            ns,
            proof,
            glue,
        })
    }

    /// The answer, or negative answer, of an authoritative response to `name` and `qtype`.
    fn answer(
        &mut self,
        name: &Name<'m>,
        qtype: RecordType,
        nxdomain: bool,
    ) -> Result<Outcome<'m>, Unusable> {
        let Walk {
            mut chain,
            mut records,
            end: at,
            cut,
        } = self.walk(name, qtype, nxdomain)?;
        self.sign(Section::Answer, &mut [&mut chain, &mut records]);
        let mut authority = Vec::new();
        if records.is_empty() && !cut && (nxdomain || chain.is_empty()) {
            self.take(
                Section::Authority,
                |r| r.rtype() == RecordType::SOA && at.is_within(&r.name),
                1,
                Reason::NotAllowed,
                &mut authority,
            );
        }
        self.denials(&mut authority);
        self.sign(Section::Authority, &mut [&mut authority]);
        Ok(if !records.is_empty() {
            let additional = self.glue(&records);
            Outcome::Answer {
                chain,
                records,
                authority,
                additional,
            }
        } else if cut || !(nxdomain || chain.is_empty()) {
            Outcome::Cname {
                chain,
                target: at,
                authority,
            }
        } else if nxdomain {
            Outcome::NxDomain { chain, authority }
        } else {
            Outcome::NoData { authority }
        })
    }

    /// Follows the CNAME and DNAME records of the answer section from `name`, and keeps the records of `qtype` at the
    /// end; none for an NXDOMAIN.
    fn walk(
        &mut self,
        name: &Name<'m>,
        qtype: RecordType,
        nxdomain: bool,
    ) -> Result<Walk<'m>, Unusable> {
        let (mut chain, mut records) = (Vec::new(), Vec::new());
        let mut at = name.clone();
        let mut hops = 0;
        let mut cut = false;
        loop {
            if !at.is_within(self.zone) {
                cut = true;
                break;
            }
            if let Some((i, alias)) = self.dname(&at)? {
                if hops == MAX_CHAIN {
                    self.set(Section::Answer, i, Fate::Dropped(Reason::ChainTooLong));
                    cut = true;
                    break;
                }
                let dname = self.set(Section::Answer, i, Fate::Kept);
                chain.push(dname.clone());
                let cname = self.cname(&at).filter(|(_, target)| *target == alias);
                let cname = match cname {
                    Some((j, _)) => self.set(Section::Answer, j, Fate::Kept).clone(),
                    None => Record::new(
                        at.clone(),
                        dname.class,
                        dname.ttl,
                        &RData::Cname(alias.clone()),
                    ),
                };
                hops += 1;
                at = alias;
                // A question for the CNAME is answered by it (RFC 6672 §2.3), not by the alias's data.
                if qtype == RecordType::CNAME {
                    records.push(cname);
                    break;
                }
                chain.push(cname);
                continue;
            }
            if !nxdomain {
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
                    Reason::TooManyNs,
                    &mut records,
                );
                if !records.is_empty() {
                    break;
                }
            }
            let Some((i, target)) = self.cname(&at) else {
                break;
            };
            if hops == MAX_CHAIN {
                self.set(Section::Answer, i, Fate::Dropped(Reason::ChainTooLong));
                cut = true;
                break;
            }
            chain.push(self.set(Section::Answer, i, Fate::Kept).clone());
            hops += 1;
            at = target;
        }
        Ok(Walk {
            chain,
            records,
            end: at,
            cut,
        })
    }

    /// The first pending DNAME strictly above `at` (RFC 6672 §2.2), with the name it makes of `at`; `None` too for a
    /// DNAME whose RDATA is not a name, left to be dropped.
    fn dname(&self, at: &Name<'_>) -> Result<Option<(usize, Name<'static>)>, Unusable> {
        for (i, r) in self.pending(Section::Answer) {
            if r.rtype() != RecordType::DNAME || r.name == *at || !at.is_within(&r.name) {
                continue;
            }
            let RData::Opaque(data) = r.data() else {
                continue;
            };
            let Ok(target) = Name::from_uncompressed(data.data()) else {
                continue;
            };
            let kept = at.label_count() - r.name.label_count();
            return Name::from_labels(at.labels().take(kept).chain(target.labels()))
                .map(|alias| Some((i, alias)))
                .map_err(|_| Unusable::DnameTooLong);
        }
        Ok(None)
    }

    /// The first pending CNAME at `at`, with its target.
    fn cname(&self, at: &Name<'_>) -> Option<(usize, Name<'m>)> {
        self.pending(Section::Answer)
            .find_map(|(i, r)| match r.data() {
                RData::Cname(target) if r.name == *at => Some((i, target)),
                _ => None,
            })
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
