//! The verdict on a response: each `RRset` of its answer against the keys of its signer, and what it lacks
//! against the proof of denial (RFC 4035 §5.3, §5.4).

use std::sync::Arc;

use dedens_proto::edns::InfoCode;
use dedens_proto::{Message, Name, Question, RData, Rcode, Record, RecordType, Ttl};

use super::chain::{Delegation, Settled, parent};
use super::section::{Chain, Section, Signer, synthesized};
use super::verdict::{Failure, InsecureReason, Unusable, Verdict, ede};
use super::{Need, Validation};
use crate::denial::{self, Fact, Proof, Unproven};
use crate::rrsig::{Key, RrSet, verify_any};

/// The longest a negative response is relied on: three hours (RFC 9077 §3.4, RFC 2308 §5).
const DENIAL_TTL_CAP: Ttl = Ttl::from_wire(3 * 60 * 60);

/// A name and the zone it was found to belong to.
struct Located {
    /// The name the walk of the chain of trust ended on.
    name: Name<'static>,
    apex: Name<'static>,
    settled: Settled,
    /// Whether `name` is the signer of the data: it must then be the apex of a zone.
    signed: bool,
}

/// An `RRset` of the answer and where its signer is.
struct Item {
    set: RrSet<'static>,
    zone: Located,
}

/// The NSEC, NSEC3 and SOA records of a response that verified, as the records `denial` reads.
struct Evidence {
    records: Vec<Record<'static>>,
    /// The longest the proof may be relied on (RFC 9077 §3.4).
    limit: Ttl,
}

/// What the records prove, when they prove nothing, as the verdict of the chain that depends on it.
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
        Unproven::NoUsableRecords
        | Unproven::NotCovered
        | Unproven::NoClosestEncloser
        | Unproven::WildcardNotDenied => {
            Unusable::Failed(Failure::bogus(InfoCode::NSEC_MISSING, error.to_string()))
        }
        _ => Unusable::Failed(Failure::bogus(InfoCode::DNSSEC_BOGUS, error.to_string())),
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
        if let Some(child) = response
            .referral()
            .filter(|child| question.name.is_within(child))
            .map(|child| child.clone().into_owned())
        {
            return self.referral(&child);
        }
        self.answer_verdict(&question, &response)
    }

    /// A referral to `child` is as secure as its delegation: the DS records or their proven absence are in the
    /// response (RFC 4035 §5.2).
    fn referral(&mut self, child: &Name<'static>) -> Result<Verdict, Need> {
        Ok(match self.cut(child, 0)? {
            Delegation::Anchored => Verdict::Secure { ttl: Ttl::MAX },
            Delegation::Signed { ttl, .. } => Verdict::Secure { ttl },
            Delegation::Inside(_) => Verdict::bogus(
                InfoCode::DNSSEC_BOGUS,
                format!("{child} is referred to but proven no delegation"),
            ),
            Delegation::Unusable(unusable) => unusable.into(),
        })
    }

    /// The zone `name` belongs to, with the keys to check what is signed in it.
    fn locate(&mut self, name: &Name<'static>, signed: bool) -> Result<Located, Need> {
        let (apex, settled) = self.zone_of(name, 0)?;
        Ok(Located {
            name: name.clone(),
            apex,
            settled,
            signed,
        })
    }

    fn answer_verdict(
        &mut self,
        question: &Question<'static>,
        response: &Message<'static>,
    ) -> Result<Verdict, Need> {
        let answer = Section::new(&response.answer);
        let authority = Section::new(&response.authority);
        let chain = Chain::follow(question, &answer);

        // What is asked of the chain of trust, before anything is checked.
        let mut items = Vec::new();
        for set in &answer.sets {
            if synthesized(set, &answer) {
                continue;
            }
            let (name, signed) = match answer.signer(set, set.owner()) {
                Signer::Zone(signer) => (signer, true),
                Signer::Unsigned if set.rtype() == RecordType::DS => (
                    parent(set.owner()).unwrap_or_else(|| set.owner().clone().into_owned()),
                    false,
                ),
                Signer::Unsigned => (set.owner().clone().into_owned(), false),
                Signer::Misplaced => {
                    return Ok(Verdict::bogus(
                        InfoCode::DNSSEC_BOGUS,
                        format!(
                            "{} {} is signed by no zone at or above it",
                            set.owner(),
                            set.rtype()
                        ),
                    ));
                }
            };
            let zone = self.locate(&name, signed)?;
            items.push(Item {
                set: set.clone(),
                zone,
            });
        }
        // A CNAME chain that stops before the type asked has no denial to make: the caller asks on.
        let partial = !chain.found
            && chain.links > 0
            && response.rcode() == Rcode::NOERROR
            && !authority.has_denial();
        let denial = if chain.found || partial {
            None
        } else {
            let signer = authority
                .sets
                .iter()
                .filter(|set| matches!(set.rtype(), RecordType::NSEC | RecordType::NSEC3))
                .find_map(|set| match authority.signer(set, &chain.end) {
                    Signer::Zone(signer) => Some(signer),
                    Signer::Unsigned | Signer::Misplaced => None,
                });
            let by_zone = signer.is_some();
            let name = signer.unwrap_or_else(|| chain.end.clone());
            Some(self.locate(&name, by_zone)?)
        };

        let mut verdict = Verdict::Secure { ttl: Ttl::MAX };
        for item in &items {
            verdict = verdict.worse(self.item_verdict(&answer, &authority, item));
        }
        if let Some(zone) = denial {
            let asked = Question::new(chain.end.clone(), question.qtype);
            verdict =
                verdict.worse(self.denial_verdict(&authority, &zone, &asked, response.rcode()));
        }
        Ok(verdict)
    }

    /// The keys of a zone found secure, or the verdict of its being anything else.
    fn secure_keys(zone: &Located) -> Result<(Arc<RrSet<'static>>, Ttl), Verdict> {
        match &zone.settled {
            Settled::Unusable(unusable) => Err(unusable.clone().into()),
            Settled::Secure { keys, ttl } => {
                if zone.signed && zone.apex != zone.name {
                    Err(Verdict::bogus(
                        InfoCode::DNSSEC_BOGUS,
                        format!("{} signs but is no zone apex", zone.name),
                    ))
                } else {
                    Ok((Arc::clone(keys), *ttl))
                }
            }
        }
    }

    /// The verdict on one `RRset` of the answer (RFC 4035 §5.3), a wildcard expansion included (§5.3.4).
    fn item_verdict(&mut self, answer: &Section, authority: &Section, item: &Item) -> Verdict {
        let (keys, keys_ttl) = match Self::secure_keys(&item.zone) {
            Ok(secure) => secure,
            Err(verdict) => return verdict,
        };
        let set = &item.set;
        if !item.zone.signed {
            return Verdict::bogus(
                InfoCode::RRSIGS_MISSING,
                format!(
                    "{} {} is unsigned in the secure zone {}",
                    set.owner(),
                    set.rtype(),
                    item.zone.apex
                ),
            );
        }
        let sigs = answer.signatures(set);
        let verified = match verify_any(set, &sigs, &Key::all(&keys), self.now, &mut self.budget) {
            Ok(verified) => verified,
            Err(error) => {
                return Verdict::Bogus {
                    ede: error.ede(set),
                };
            }
        };
        let ttl = verified.ttl.min(keys_ttl);
        let Some(encloser) = verified.wildcard else {
            return Verdict::Secure { ttl };
        };
        // The signature says the name is an expansion: no closer name may exist (RFC 4035 §5.3.4).
        let Ok(labels) = u8::try_from(encloser.label_count()) else {
            return Verdict::bogus(InfoCode::DNSSEC_BOGUS, "a wildcard of too many labels");
        };
        let evidence = match self.evidence(&keys, keys_ttl, authority) {
            Ok(evidence) => evidence,
            Err(unusable) => return unusable.into(),
        };
        let max = self.config.limits.iterations;
        match denial::prove_wildcard_answer(
            &item.zone.apex,
            set.owner(),
            labels,
            &evidence.records,
            max,
            &mut self.budget,
        ) {
            Ok(proof) if proof.opt_out => Verdict::Insecure {
                reason: InsecureReason::OptOut,
            },
            Ok(proof) => Verdict::Secure {
                ttl: ttl.min(proof.ttl).min(evidence.limit),
            },
            Err(error) => unproven(error, evidence.limit).into(),
        }
    }

    /// The verdict on what a response says does not exist (RFC 4035 §5.4).
    fn denial_verdict(
        &mut self,
        authority: &Section,
        zone: &Located,
        question: &Question<'static>,
        rcode: Rcode,
    ) -> Verdict {
        let (keys, keys_ttl) = match Self::secure_keys(zone) {
            Ok(secure) => secure,
            Err(verdict) => return verdict,
        };
        let proof = match self.prove_denial(&zone.apex, &keys, keys_ttl, authority, question) {
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

    /// The NSEC, NSEC3 and SOA `RRsets` of `authority` that `keys` verify.
    ///
    /// Only these reach [`denial`], which trusts its records (D74). Of a SOA only the limits of its TTL and
    /// MINIMUM are kept (RFC 9077 §3.4); one that fails proves nothing and costs nothing else.
    fn evidence(
        &mut self,
        keys: &RrSet<'static>,
        keys_ttl: Ttl,
        authority: &Section,
    ) -> Result<Evidence, Unusable> {
        let mut records = Vec::new();
        let mut limit = keys_ttl.min(DENIAL_TTL_CAP);
        let mut first_error = None;
        for set in &authority.sets {
            let proof = matches!(set.rtype(), RecordType::NSEC | RecordType::NSEC3);
            if !proof && set.rtype() != RecordType::SOA {
                continue;
            }
            let sigs = authority.signatures(set);
            match verify_any(set, &sigs, &Key::all(keys), self.now, &mut self.budget) {
                Ok(verified) if proof && verified.wildcard.is_none() => {
                    records.extend(set.rdatas().iter().map(|rdata| Record {
                        name: set.owner().clone(),
                        class: set.class(),
                        ttl: verified.ttl,
                        rdata: rdata.clone(),
                    }));
                }
                Ok(verified) if !proof => {
                    limit = limit.min(verified.ttl);
                    if let Some(RData::Soa(soa)) = set.rdatas().first().map(|rdata| rdata.data()) {
                        limit = limit.min(Ttl::from_wire(soa.minimum));
                    }
                }
                Ok(_) => {
                    first_error.get_or_insert_with(|| {
                        ede(
                            InfoCode::DNSSEC_BOGUS,
                            format!("{} {} is a wildcard expansion", set.owner(), set.rtype()),
                        )
                    });
                }
                Err(error) if proof => {
                    first_error.get_or_insert_with(|| error.ede(set));
                }
                Err(_) => {}
            }
        }
        if records.is_empty() {
            return Err(Unusable::Failed(Failure::Bogus(
                first_error
                    .unwrap_or_else(|| ede(InfoCode::NSEC_MISSING, "no NSEC or NSEC3 record")),
            )));
        }
        Ok(Evidence { records, limit })
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
        let evidence = self.evidence(keys, keys_ttl, authority)?;
        let max = self.config.limits.iterations;
        match denial::prove(apex, question, &evidence.records, max, &mut self.budget) {
            Ok(proof) => Ok(Proof {
                ttl: proof.ttl.min(evidence.limit),
                ..proof
            }),
            Err(error) => Err(unproven(error, evidence.limit)),
        }
    }
}
