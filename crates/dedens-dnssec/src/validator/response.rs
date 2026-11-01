//! The verdict on a response: each `RRset` of its answer and authority sections against the keys of the zone its
//! owner is in, and what it lacks against the proof of denial (RFC 4035 §5.3, §5.4).
//!
//! The zone of an `RRset` is found by walking the chain of trust to its owner (RFC 4035 §5.3.1), never from the
//! signer its RRSIGs name: those are the forger's.

use std::sync::Arc;

use dedens_proto::edns::InfoCode;
use dedens_proto::{Name, Question, RData, Rcode, Record, RecordType, Ttl};

use super::chain::{Cut, Settled, parent, sig_failure};
use super::section::{Chain, Section, is_denial, synthesized};
use super::verdict::{Delegation, Failure, InsecureReason, Unusable, Verdict};
use super::{Mode, Need, Validation};
use crate::crypto;
use crate::denial::{self, Fact, Proof, Unproven};
use crate::rrsig::{Key, RrSet, verify_any};

/// The longest a negative response is relied on: three hours (RFC 9077 §3.4, RFC 2308 §5).
const DENIAL_TTL_CAP: Ttl = Ttl::from_wire(3 * 60 * 60);

/// The sections of the response being validated, read once, and where its answer leads.
#[derive(Debug)]
pub(super) struct Parsed {
    pub(super) answer: Section,
    pub(super) authority: Section,
    pub(super) chain: Chain,
}

impl Parsed {
    pub(super) fn new(
        question: &Question<'_>,
        answer: &[Record<'static>],
        authority: &[Record<'static>],
    ) -> Self {
        let answer = Section::new(answer);
        let chain = Chain::follow(question, &answer);
        Self {
            answer,
            authority: Section::new(authority),
            chain,
        }
    }
}

/// The zone a name was found to be in.
struct Located {
    apex: Name<'static>,
    settled: Settled,
}

/// An `RRset` to check and the zone of its owner.
struct Item<'p> {
    set: &'p RrSet<'static>,
    section: &'p Section,
    zone: Located,
}

/// The NSEC, NSEC3 and SOA records of a response that verified, as the records `denial` reads.
#[derive(Debug)]
struct Evidence {
    records: Vec<Record<'static>>,
    /// The longest the proof may be relied on (RFC 9077 §3.4).
    limit: Ttl,
}

/// The evidence of each zone a response has been checked in, once, and which zone each proof is of.
///
/// A response may hold proofs of two zones (a wildcard answer of one, a no data of the zone a CNAME led to): each
/// NSEC, NSEC3 or SOA `RRset` is checked against the keys of one zone, the one that signed it among the zones the
/// response is about, or `fallback`, the zone of the name it ends on, when its signer is none of them. A wrong
/// signer only makes the `RRset` fail with the keys of `fallback` (D75).
struct Evidences {
    known: Vec<(Name<'static>, Result<Arc<Evidence>, Unusable>)>,
    zones: Vec<Name<'static>>,
    fallback: Name<'static>,
}

impl Evidences {
    /// The proofs of a response that holds a single zone's: all of them are `apex`'s.
    fn only(apex: &Name<'static>) -> Self {
        Self {
            known: Vec::new(),
            zones: vec![apex.clone()],
            fallback: apex.clone(),
        }
    }

    /// Whether the `RRset` `set` of `authority` is a proof of the zone `apex`.
    fn owns(&self, apex: &Name<'static>, set: &RrSet<'static>, authority: &Section) -> bool {
        let signers: Vec<Name<'static>> = authority
            .signatures(set)
            .iter()
            .map(|sig| sig.rrsig().signer.clone().into_owned())
            .collect();
        let owner = self
            .zones
            .iter()
            .filter(|zone| signers.contains(zone))
            .max_by_key(|zone| zone.label_count())
            .unwrap_or(&self.fallback);
        owner == apex
    }
}

/// The zone that holds the data of `name` and `rtype`: for a DS, the parent's.
fn home(name: &Name<'_>, rtype: RecordType) -> Name<'static> {
    if rtype == RecordType::DS {
        parent(name).unwrap_or_else(|| name.clone().into_owned())
    } else {
        name.clone().into_owned()
    }
}

/// What the records prove, when they prove nothing, as the verdict of what depends on it.
fn unproven(error: Unproven, ttl: Ttl) -> Unusable {
    match error {
        Unproven::IterationsAboveLimit { .. } => Unusable::Insecure {
            reason: InsecureReason::Nsec3Iterations,
            ttl,
        },
        Unproven::NxnameQuery => Unusable::Failed(Failure::indeterminate(
            InfoCode::INVALID_QUERY_TYPE,
            error.to_string(),
        )),
        // The hashes ran out: nothing is known of the zone (D71, D75).
        Unproven::Budget(_) => Unusable::Failed(Failure::indeterminate(
            InfoCode::DNSSEC_INDETERMINATE,
            error.to_string(),
        )),
        Unproven::NoUsableRecords
        | Unproven::NotCovered
        | Unproven::NoClosestEncloser
        | Unproven::WildcardNotDenied => {
            Unusable::Failed(Failure::bogus(InfoCode::NSEC_MISSING, error.to_string()))
        }
        _ => Unusable::Failed(Failure::bogus(InfoCode::DNSSEC_BOGUS, error.to_string())),
    }
}

/// Why no record of a DS `RRset` can vouch for a key, when none can: the first unsupported digest, or algorithm
/// of a record with a supported digest, as `trusted_keys` tells them (RFC 6840 §5.2).
fn unsupported_ds(ds: &RrSet<'_>) -> Option<InsecureReason> {
    let mut reason = None;
    for rdata in ds.rdatas() {
        let RData::Ds(record) = rdata.data() else {
            continue;
        };
        if !crypto::supported_digest(record.digest_type()) {
            reason.get_or_insert(InsecureReason::UnsupportedDigest);
        } else if !crypto::supported(record.algorithm()) {
            reason.get_or_insert(InsecureReason::UnsupportedAlgorithm);
        } else {
            return None;
        }
    }
    reason
}

/// The keys of a zone found secure, or the verdict of its being anything else.
fn secure_keys(zone: &Located) -> Result<(Arc<RrSet<'static>>, Ttl), Unusable> {
    match &zone.settled {
        Settled::Unusable(unusable) => Err(unusable.clone()),
        Settled::Secure { keys, ttl } => Ok((Arc::clone(keys), *ttl)),
    }
}

impl Validation {
    /// The verdict on the response, or the response of another question it needs.
    ///
    /// Every question is asked before any signature is checked, so a rerun after an answer does no work twice.
    pub(super) fn judge(&mut self) -> Result<Verdict, Need> {
        let response = Arc::clone(&self.response);
        let question = self.question.clone();
        if question.qtype == RecordType::NXNAME {
            return Ok(Verdict::indeterminate(
                InfoCode::INVALID_QUERY_TYPE,
                "NXNAME is no type to ask for",
            ));
        }
        if !matches!(response.rcode(), Rcode::NOERROR | Rcode::NXDOMAIN) {
            return Ok(Verdict::indeterminate(
                InfoCode::DNSSEC_INDETERMINATE,
                format!("the response is {}", response.rcode()),
            ));
        }
        if let Mode::Referral(child) = self.mode.clone() {
            return self.referral(&child);
        }
        let parsed = Arc::clone(&self.parsed);
        self.answer_verdict(&question, response.rcode(), &parsed)
    }

    /// What the DS records of `child`, or their proven absence, in the referral say of the delegation (RFC 4035
    /// §5.2). Nothing else of the referral is read: its NS records and glue are not signed by the parent, and
    /// that the parent sent it is not proven. Signed means a verified DS `RRset` with a record whose algorithm
    /// and digest are supported; one with none is an unsigned delegation as far as this validator goes (RFC 4035
    /// §5.2, RFC 6840 §5.2).
    fn referral(&mut self, child: &Name<'static>) -> Result<Verdict, Need> {
        Ok(match self.cut(child, false)? {
            Cut::Anchored => Verdict::Referral {
                child: child.clone(),
                delegation: Delegation::Signed,
            },
            Cut::Signed { ds, .. } => Verdict::Referral {
                child: child.clone(),
                delegation: match unsupported_ds(&ds) {
                    None => Delegation::Signed,
                    Some(reason) => Delegation::Unsigned { reason },
                },
            },
            Cut::Inside { .. } => Verdict::bogus(
                InfoCode::DNSSEC_BOGUS,
                format!("{child} is referred to but proven no delegation"),
            ),
            Cut::Unusable(Unusable::Insecure { reason, .. })
            | Cut::Beneath(Unusable::Insecure { reason, .. }) => Verdict::Referral {
                child: child.clone(),
                delegation: Delegation::Unsigned { reason },
            },
            Cut::Unusable(Unusable::Failed(failure)) | Cut::Beneath(Unusable::Failed(failure)) => {
                failure.into()
            }
        })
    }

    /// The zone `name` belongs to, with the keys to check what is signed in it.
    fn locate(&mut self, name: &Name<'static>) -> Result<Located, Need> {
        let (apex, settled) = self.zone_of(name)?;
        Ok(Located { apex, settled })
    }

    /// The verdict on an answer: its `RRsets`, those of its authority section, and the denial of what it lacks.
    fn answer_verdict(
        &mut self,
        question: &Question<'static>,
        rcode: Rcode,
        parsed: &Parsed,
    ) -> Result<Verdict, Need> {
        let Parsed {
            answer,
            authority,
            chain,
        } = parsed;
        if chain.found && rcode == Rcode::NXDOMAIN {
            return Ok(Verdict::bogus(
                InfoCode::DNSSEC_BOGUS,
                format!("{} has an answer and the rcode is NXDOMAIN", chain.end),
            ));
        }
        // A CNAME chain that stops before the type asked has no denial to make: the caller asks on.
        let partial =
            !chain.found && chain.links > 0 && rcode == Rcode::NOERROR && !authority.has_denial();
        let needs_denial = !chain.found && !partial;

        // What is asked of the chain of trust, before anything is checked.
        let mut items = Vec::new();
        let sets = answer
            .sets
            .iter()
            .filter(|set| chain.answers(set) && !synthesized(set, answer))
            .map(|set| (set, answer))
            .chain(
                authority
                    .sets
                    .iter()
                    .filter(|set| !is_denial(set.rtype()) && chain.about(set))
                    .map(|set| (set, authority)),
            );
        for (set, section) in sets {
            let zone = self.locate(&home(set.owner(), set.rtype()))?;
            items.push(Item { set, section, zone });
        }
        let denial_zone = if needs_denial || authority.has_denial() {
            Some(self.locate(&home(&chain.end, question.qtype))?)
        } else {
            None
        };

        let mut zones: Vec<Name<'static>> =
            items.iter().map(|item| item.zone.apex.clone()).collect();
        zones.extend(denial_zone.as_ref().map(|zone| zone.apex.clone()));
        let fallback = denial_zone.as_ref().map_or_else(
            || home(&chain.end, question.qtype),
            |zone| zone.apex.clone(),
        );
        let mut evidences = Evidences {
            known: Vec::new(),
            zones,
            fallback,
        };
        let mut verdict = Verdict::Secure { ttl: Ttl::MAX };
        // Bogus outranks every other verdict, so the first one is the last word and the rest costs nothing.
        for item in &items {
            verdict = verdict.worse(self.item_verdict(item, authority, &mut evidences));
            if matches!(verdict, Verdict::Bogus { .. }) {
                return Ok(verdict);
            }
        }
        // The proofs of the zones the answer came from, wildcard or not, are checked too: the verdict covers the
        // whole authority section (RFC 4035 §3.2.3).
        for item in items.iter().filter(|_| authority.has_denial()) {
            let zone = &item.zone;
            if denial_zone.as_ref().is_some_and(|d| d.apex == zone.apex) {
                continue;
            }
            let checked = self.denial_verdict(authority, zone, None, rcode, &mut evidences);
            verdict = verdict.worse(checked);
            if matches!(verdict, Verdict::Bogus { .. }) {
                return Ok(verdict);
            }
        }
        if let Some(zone) = denial_zone {
            let asked = Question::new(chain.end.clone(), question.qtype);
            verdict = verdict.worse(self.denial_verdict(
                authority,
                &zone,
                needs_denial.then_some(&asked),
                rcode,
                &mut evidences,
            ));
        }
        Ok(match verdict {
            Verdict::Secure { ttl } if partial => Verdict::Incomplete {
                next: chain.end.clone(),
                ttl,
            },
            other => other,
        })
    }

    /// The verdict on one `RRset` (RFC 4035 §5.3), a wildcard expansion included (§5.3.4).
    fn item_verdict(
        &mut self,
        item: &Item<'_>,
        authority: &Section,
        evidences: &mut Evidences,
    ) -> Verdict {
        let (keys, keys_ttl) = match secure_keys(&item.zone) {
            Ok(secure) => secure,
            Err(unusable) => return unusable.into(),
        };
        let apex = &item.zone.apex;
        let (ttl, wildcard) = match self.authentic(item.set, item.section, apex, &keys, keys_ttl) {
            Ok(authentic) => authentic,
            Err(unusable) => return unusable.into(),
        };
        let Some(encloser) = wildcard else {
            return Verdict::Secure { ttl };
        };
        let evidence = match self.evidence_in(evidences, apex, &keys, keys_ttl, authority) {
            Ok(evidence) => evidence,
            Err(unusable) => return unusable.into(),
        };
        match self.no_closer(item.set, &encloser, apex, &evidence, ttl) {
            Ok(ttl) => Verdict::Secure { ttl },
            Err(unusable) => unusable.into(),
        }
    }

    /// The TTL of `set` and the encloser of the wildcard that made it, once a signature of the zone `apex`
    /// verifies it (RFC 4035 §5.3.1): every RRSIG is tried, and a key is the zone's by being in its DNSKEY
    /// `RRset`, whose owner the RRSIG's signer must be.
    fn authentic(
        &mut self,
        set: &RrSet<'static>,
        section: &Section,
        apex: &Name<'static>,
        keys: &RrSet<'static>,
        keys_ttl: Ttl,
    ) -> Result<(Ttl, Option<Name<'static>>), Unusable> {
        let owner = set.owner();
        if !owner.is_within(apex) || (set.rtype() == RecordType::DNSKEY && owner != apex) {
            return Err(Unusable::Failed(Failure::bogus(
                InfoCode::DNSSEC_BOGUS,
                format!(
                    "{owner} {} is in no zone with keys: the zone is {apex}",
                    set.rtype()
                ),
            )));
        }
        let sigs = section.signatures(set);
        if sigs.is_empty() {
            return Err(Unusable::Failed(Failure::bogus(
                InfoCode::RRSIGS_MISSING,
                format!(
                    "{owner} {} is unsigned in the secure zone {apex}",
                    set.rtype()
                ),
            )));
        }
        match verify_any(set, &sigs, &Key::all(keys), self.now, &mut self.budget) {
            Ok(verified) => Ok((verified.ttl.min(keys_ttl), verified.wildcard)),
            Err(error) => Err(Unusable::Failed(sig_failure(&error, set))),
        }
    }

    /// That no name closer than the wildcard `encloser` made `set` exists: the signature says `set` is an
    /// expansion, and the proof must say it was not for a name that is there (RFC 4035 §5.3.4, RFC 5155 §8.8).
    fn no_closer(
        &mut self,
        set: &RrSet<'static>,
        encloser: &Name<'static>,
        apex: &Name<'static>,
        evidence: &Evidence,
        ttl: Ttl,
    ) -> Result<Ttl, Unusable> {
        let Ok(labels) = u8::try_from(encloser.label_count()) else {
            return Err(Unusable::Failed(Failure::bogus(
                InfoCode::DNSSEC_BOGUS,
                "a wildcard of too many labels",
            )));
        };
        let max = self.config.limits.iterations;
        match denial::prove_wildcard_answer(
            apex,
            set.owner(),
            labels,
            &evidence.records,
            max,
            &mut self.budget,
        ) {
            Ok(proof) if proof.opt_out => Err(Unusable::Insecure {
                reason: InsecureReason::OptOut,
                ttl: ttl.min(proof.ttl).min(evidence.limit),
            }),
            Ok(proof) => Ok(ttl.min(proof.ttl).min(evidence.limit)),
            Err(error) => Err(unproven(error, evidence.limit)),
        }
    }

    /// `set` checked as `authentic` does, a wildcard expansion's proof included, with the response's own
    /// `authority`: the TTL it may be relied on for.
    pub(super) fn verify_set(
        &mut self,
        set: &RrSet<'static>,
        section: &Section,
        authority: &Section,
        apex: &Name<'static>,
        keys: &RrSet<'static>,
        keys_ttl: Ttl,
    ) -> Result<Ttl, Unusable> {
        let (ttl, wildcard) = self.authentic(set, section, apex, keys, keys_ttl)?;
        let Some(encloser) = wildcard else {
            return Ok(ttl);
        };
        let evidence = self.evidence(apex, keys, keys_ttl, authority, &Evidences::only(apex))?;
        self.no_closer(set, &encloser, apex, &evidence, ttl)
    }

    /// The verdict on what a response says does not exist (RFC 4035 §5.4), when `asked` is the name and type
    /// it left without an answer; the NSEC, NSEC3 and SOA records of an answer are only checked, `asked` being
    /// none.
    fn denial_verdict(
        &mut self,
        authority: &Section,
        zone: &Located,
        asked: Option<&Question<'static>>,
        rcode: Rcode,
        evidences: &mut Evidences,
    ) -> Verdict {
        let (keys, keys_ttl) = match secure_keys(zone) {
            Ok(secure) => secure,
            Err(unusable) => return unusable.into(),
        };
        let evidence = match self.evidence_in(evidences, &zone.apex, &keys, keys_ttl, authority) {
            Ok(evidence) => evidence,
            Err(unusable) => return unusable.into(),
        };
        let Some(asked) = asked else {
            return Verdict::Secure {
                ttl: evidence.limit,
            };
        };
        let proof = match self.prove(&zone.apex, asked, &evidence) {
            Ok(proof) => proof,
            Err(unusable) => return unusable.into(),
        };
        let consistent = match proof.fact {
            Fact::NameError { compact } => compact || rcode == Rcode::NXDOMAIN,
            Fact::NoData | Fact::WildcardNoData | Fact::InsecureDelegation => {
                rcode == Rcode::NOERROR
            }
            _ => false,
        };
        if !consistent {
            return Verdict::bogus(
                InfoCode::DNSSEC_BOGUS,
                format!("the proof is {:?}, the response is {rcode}", proof.fact),
            );
        }
        if proof.opt_out {
            // The name may exist, unsigned, in the span (RFC 5155 §9.2).
            return Verdict::Insecure {
                reason: InsecureReason::OptOut,
            };
        }
        Verdict::Secure { ttl: proof.ttl }
    }

    /// The evidence of the zone `apex`, checked once for a response.
    fn evidence_in(
        &mut self,
        evidences: &mut Evidences,
        apex: &Name<'static>,
        keys: &RrSet<'static>,
        keys_ttl: Ttl,
        authority: &Section,
    ) -> Result<Arc<Evidence>, Unusable> {
        if let Some((_, known)) = evidences.known.iter().find(|(name, _)| name == apex) {
            return known.clone();
        }
        let evidence = self
            .evidence(apex, keys, keys_ttl, authority, evidences)
            .map(Arc::new);
        evidences.known.push((apex.clone(), evidence.clone()));
        evidence
    }

    /// The NSEC, NSEC3 and SOA `RRsets` of `authority`, all of which `keys` of the zone `apex` must verify
    /// (RFC 4035 §5.5): an unsigned or forged one among them makes the response bogus, not just the proof
    /// lesser. Only these reach [`denial`], which trusts its records (D74). Of a SOA only the limits of its TTL
    /// and MINIMUM are kept (RFC 9077 §3.4).
    fn evidence(
        &mut self,
        apex: &Name<'static>,
        keys: &RrSet<'static>,
        keys_ttl: Ttl,
        authority: &Section,
        scope: &Evidences,
    ) -> Result<Evidence, Unusable> {
        let mut records = Vec::new();
        let mut limit = keys_ttl.min(DENIAL_TTL_CAP);
        let proofs = authority
            .sets
            .iter()
            .filter(|set| is_denial(set.rtype()) && scope.owns(apex, set, authority));
        for set in proofs {
            let (ttl, wildcard) = self.authentic(set, authority, apex, keys, keys_ttl)?;
            if wildcard.is_some() {
                return Err(Unusable::Failed(Failure::bogus(
                    InfoCode::DNSSEC_BOGUS,
                    format!("{} {} is a wildcard expansion", set.owner(), set.rtype()),
                )));
            }
            limit = limit.min(ttl);
            if set.rtype() == RecordType::SOA {
                if let Some(RData::Soa(soa)) = set.rdatas().first().map(|rdata| rdata.data()) {
                    limit = limit.min(Ttl::from_wire(soa.minimum));
                }
            } else {
                records.extend(set.rdatas().iter().map(|rdata| Record {
                    name: set.owner().clone(),
                    class: set.class(),
                    ttl,
                    rdata: rdata.clone(),
                }));
            }
        }
        Ok(Evidence { records, limit })
    }

    /// What `evidence` proves about `question` in the zone `apex` (RFC 4035 §5.4, RFC 5155 §8, RFC 9077 §3.4).
    fn prove(
        &mut self,
        apex: &Name<'static>,
        question: &Question<'_>,
        evidence: &Evidence,
    ) -> Result<Proof, Unusable> {
        let max = self.config.limits.iterations;
        match denial::prove(apex, question, &evidence.records, max, &mut self.budget) {
            Ok(proof) => Ok(Proof {
                ttl: proof.ttl.min(evidence.limit),
                ..proof
            }),
            Err(error) => Err(unproven(error, evidence.limit)),
        }
    }

    /// What the verified NSEC and NSEC3 records of `authority` prove about `question` in the zone `apex`, which
    /// `keys` are of (RFC 4035 §5.4, RFC 5155 §8, RFC 9077 §3.4).
    pub(super) fn prove_denial(
        &mut self,
        apex: &Name<'static>,
        keys: &RrSet<'static>,
        keys_ttl: Ttl,
        authority: &Section,
        question: &Question<'_>,
    ) -> Result<Proof, Unusable> {
        let evidence = self.evidence(apex, keys, keys_ttl, authority, &Evidences::only(apex))?;
        self.prove(apex, question, &evidence)
    }
}
