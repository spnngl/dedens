//! The chain of trust: from a trust anchor down one label at a time, a zone's DS record in its parent and its
//! DNSKEY `RRset` under that DS (RFC 4033 §5, RFC 4035 §5.2).

use std::sync::Arc;

use dedens_proto::edns::InfoCode;
use dedens_proto::{
    Class, Message, Name, Question, RData, Rcode, Record, RecordType, Ttl, WireRdata,
};

use super::section::Section;
use super::verdict::{Failure, InsecureReason, Unusable};
use super::{Need, Validation};
use crate::denial::Fact;
use crate::rrsig::{Key, RrSet, SigError, trusted_keys, verify_any};

/// What is known of a zone: its keys, or why it has none that count.
///
/// The one outcome 06b keeps in a cache: secure keys with the TTL of the signatures and DS records that vouch
/// for them, an insecure zone with the TTL of the proof, or a failure.
#[derive(Debug, Clone)]
pub(super) enum Settled {
    /// The DNSKEY `RRset` is authenticated; every key of it is trusted (RFC 4035 §5.2).
    Secure {
        keys: Arc<RrSet<'static>>,
        ttl: Ttl,
    },
    Unusable(Unusable),
}

/// A name's place among the zones.
#[derive(Debug, Clone)]
pub(super) enum Zone {
    /// The name is the apex of a zone, or of a part of the tree no key covers.
    Apex(Settled),
    /// The name is no zone cut: it belongs to the zone with this apex.
    Inside(Name<'static>),
}

/// What the parent says of a name as a zone cut (RFC 4035 §5.2).
#[derive(Debug, Clone)]
pub(super) enum Delegation {
    /// The name holds a trust anchor.
    Anchored,
    /// The parent's authenticated DS `RRset`.
    Signed {
        ds: RrSet<'static>,
        ttl: Ttl,
    },
    /// The name is no zone cut; it belongs to the zone with this apex.
    Inside(Name<'static>),
    Unusable(Unusable),
}

/// Where a name stands to the trust anchors.
enum Position {
    Negative,
    Unanchored,
    Anchor,
    Below,
}

/// The name without its first label.
pub(super) fn parent(name: &Name<'_>) -> Option<Name<'static>> {
    (!name.is_root())
        .then(|| Name::from_labels(name.labels().skip(1)).ok())
        .flatten()
}

/// What an error of a signature check makes of a zone or delegation: insecure when only the DS records are
/// unusable (RFC 6840 §5.2, D73), bogus otherwise.
pub(super) fn unusable(error: &SigError, set: &RrSet<'_>, ttl: Ttl) -> Unusable {
    match error {
        SigError::UnsupportedDigest { .. } => Unusable::Insecure {
            reason: InsecureReason::UnsupportedDigest,
            ttl,
        },
        SigError::UnsupportedAlgorithm { .. } => Unusable::Insecure {
            reason: InsecureReason::UnsupportedAlgorithm,
            ttl,
        },
        _ => Unusable::Failed(Failure::Bogus(error.ede(set))),
    }
}

/// The records of `name` as the `RRset` of the trust anchors' `rdatas`.
fn anchor_set(
    name: &Name<'static>,
    rdatas: impl Iterator<Item = RData<'static>>,
) -> Option<RrSet<'static>> {
    let records: Vec<Record<'static>> = rdatas
        .map(|rdata| Record {
            name: name.clone(),
            class: Class::IN,
            ttl: Ttl::MAX,
            rdata: WireRdata::new(&rdata),
        })
        .collect();
    RrSet::group(&records).pop()
}

impl Validation {
    /// The response to `name` and `rtype`, which the caller supplies: [`Need`] until it has.
    fn fetch(
        &self,
        name: &Name<'static>,
        rtype: RecordType,
    ) -> Result<Result<Arc<Message<'static>>, Failure>, Need> {
        let Some(entry) = self.answers.get(&(name.clone(), rtype)) else {
            return Err(Need(Question::new(name.clone(), rtype)));
        };
        Ok(match entry {
            None => Err(Failure::indeterminate(
                InfoCode::NO_REACHABLE_AUTHORITY,
                format!("no answer for {name} {rtype}"),
            )),
            Some(message) if matches!(message.rcode(), Rcode::NOERROR | Rcode::NXDOMAIN) => {
                Ok(Arc::clone(message))
            }
            Some(message) => Err(Failure::indeterminate(
                InfoCode::DNSSEC_INDETERMINATE,
                format!("{name} {rtype}: {}", message.rcode()),
            )),
        })
    }

    fn position(&self, name: &Name<'_>) -> Position {
        let anchors = &self.config.anchors;
        if anchors.negative(name) {
            Position::Negative
        } else {
            match anchors.closest(name) {
                None => Position::Unanchored,
                Some((anchor, _)) if anchor == name => Position::Anchor,
                Some(_) => Position::Below,
            }
        }
    }

    /// Records what is known of `name`: the one place a zone's outcome is written.
    fn settle(&mut self, name: &Name<'static>, zone: Zone) {
        self.zones.insert(name.clone(), zone);
    }

    /// The zone `name` belongs to, as its apex and its keys, walking down from the trust anchor one label at a
    /// time (RFC 4035 §5.2): a name below an insecure zone is insecure, below a secure one it is in the zone
    /// unless its parent proves a delegation. The one place a zone's outcome is read.
    ///
    /// # Errors
    ///
    /// [`Need`] for the DS or DNSKEY response the walk lacks.
    pub(super) fn zone_of(
        &mut self,
        name: &Name<'static>,
        depth: usize,
    ) -> Result<(Name<'static>, Settled), Need> {
        match self.zones.get(name) {
            Some(Zone::Apex(settled)) => return Ok((name.clone(), settled.clone())),
            Some(Zone::Inside(apex)) => {
                let apex = apex.clone();
                return self.zone_of(&apex, depth);
            }
            None => {}
        }
        if depth > self.config.limits.depth {
            let failure = Failure::indeterminate(
                InfoCode::DNSSEC_INDETERMINATE,
                format!(
                    "{name} is deeper than the limit of {} labels",
                    self.config.limits.depth
                ),
            );
            return Ok((name.clone(), Settled::Unusable(Unusable::Failed(failure))));
        }
        let zone = match self.cut(name, depth)? {
            Delegation::Anchored => Zone::Apex(self.anchor_keys(name)?),
            Delegation::Signed { ds, ttl } => Zone::Apex(self.keys_from_ds(name, &ds, ttl)?),
            Delegation::Inside(apex) => Zone::Inside(apex),
            Delegation::Unusable(unusable) => Zone::Apex(Settled::Unusable(unusable)),
        };
        self.settle(name, zone);
        self.zone_of(name, depth)
    }

    /// What the parent says of `name` as a zone cut, and for a name below an insecure zone, that it is insecure.
    ///
    /// # Errors
    ///
    /// [`Need`] for a response the walk down to `name` lacks.
    pub(super) fn cut(&mut self, name: &Name<'static>, depth: usize) -> Result<Delegation, Need> {
        if let Some(known) = self.cuts.get(name) {
            return Ok(known.clone());
        }
        let delegation = match self.position(name) {
            Position::Negative => Delegation::Unusable(Unusable::Insecure {
                reason: InsecureReason::NegativeAnchor,
                ttl: Ttl::MAX,
            }),
            Position::Unanchored => Delegation::Unusable(Unusable::Insecure {
                reason: InsecureReason::NoAnchor,
                ttl: Ttl::MAX,
            }),
            Position::Anchor => Delegation::Anchored,
            Position::Below => self.below_anchor(name, depth)?,
        };
        self.cuts.insert(name.clone(), delegation.clone());
        Ok(delegation)
    }

    /// The cut at a name below its trust anchor: the DS `RRset` or the proof of its absence, from the zone of
    /// the parent name.
    fn below_anchor(&mut self, name: &Name<'static>, depth: usize) -> Result<Delegation, Need> {
        let Some(parent) = parent(name) else {
            return Ok(Delegation::Unusable(Unusable::Failed(Failure::bogus(
                InfoCode::DNSSEC_BOGUS,
                format!("{name} has no parent"),
            ))));
        };
        let (apex, settled) = self.zone_of(&parent, depth + 1)?;
        let (keys, keys_ttl) = match settled {
            Settled::Secure { keys, ttl } => (keys, ttl),
            Settled::Unusable(unusable) => return Ok(Delegation::Unusable(unusable)),
        };
        let message = match self.fetch(name, RecordType::DS)? {
            Ok(message) => message,
            Err(failure) => return Ok(Delegation::Unusable(Unusable::Failed(failure))),
        };
        Ok(self.delegation_in(name, &apex, &keys, keys_ttl, &message))
    }

    /// The DS `RRset` of `name` in `message`, or the proof that it has none, checked with the keys of the zone
    /// `apex` (RFC 4035 §5.2, RFC 5155 §8.6, RFC 6840 §4.4).
    fn delegation_in(
        &mut self,
        name: &Name<'static>,
        apex: &Name<'static>,
        keys: &RrSet<'static>,
        keys_ttl: Ttl,
        message: &Message<'static>,
    ) -> Delegation {
        let answer = Section::new(&message.answer);
        let authority = Section::new(&message.authority);
        let found = [&answer, &authority]
            .into_iter()
            .find_map(|section| section.find(name, RecordType::DS).map(|ds| (section, ds)));
        if let Some((section, ds)) = found {
            let sigs = section.signatures(ds);
            return match verify_any(ds, &sigs, &Key::all(keys), self.now, &mut self.budget) {
                Ok(verified) if verified.wildcard.is_none() => Delegation::Signed {
                    ds: ds.clone(),
                    ttl: verified.ttl.min(keys_ttl),
                },
                Ok(_) => Delegation::Unusable(Unusable::Failed(Failure::bogus(
                    InfoCode::DNSSEC_BOGUS,
                    format!("{name} DS comes from a wildcard"),
                ))),
                Err(error) => Delegation::Unusable(Unusable::Failed(Failure::Bogus(error.ede(ds)))),
            };
        }
        let question = Question::new(name.clone(), RecordType::DS);
        match self.prove_denial(apex, keys, keys_ttl, &authority, &question) {
            Err(unusable) => Delegation::Unusable(unusable),
            Ok(proof) => match proof.fact {
                Fact::InsecureDelegation => Delegation::Unusable(Unusable::Insecure {
                    reason: if proof.opt_out {
                        InsecureReason::OptOut
                    } else {
                        InsecureReason::UnsignedDelegation
                    },
                    ttl: proof.ttl,
                }),
                // The name may exist unsigned under an opt-out span (RFC 5155 §6).
                _ if proof.opt_out => Delegation::Unusable(Unusable::Insecure {
                    reason: InsecureReason::OptOut,
                    ttl: proof.ttl,
                }),
                Fact::NameError { .. } | Fact::NoData | Fact::WildcardNoData => {
                    Delegation::Inside(apex.clone())
                }
                _ => Delegation::Unusable(Unusable::Failed(Failure::bogus(
                    InfoCode::DNSSEC_BOGUS,
                    format!("{name} DS: the proof is of something else"),
                ))),
            },
        }
    }

    /// The keys of the zone `name` from its DS `RRset`, which the parent authenticated (RFC 4035 §5.2).
    fn keys_from_ds(
        &mut self,
        name: &Name<'static>,
        ds: &RrSet<'static>,
        ds_ttl: Ttl,
    ) -> Result<Settled, Need> {
        let message = match self.fetch(name, RecordType::DNSKEY)? {
            Ok(message) => message,
            Err(failure) => return Ok(Settled::Unusable(Unusable::Failed(failure))),
        };
        let answer = Section::new(&message.answer);
        let Some(keys) = answer.find(name, RecordType::DNSKEY) else {
            return Ok(missing_keys(name));
        };
        let sigs = answer.signatures(keys);
        Ok(
            match trusted_keys(keys, &sigs, ds, self.now, &mut self.budget) {
                Ok(verified) => Settled::Secure {
                    keys: Arc::new(keys.clone()),
                    ttl: verified.ttl.min(ds_ttl),
                },
                Err(error) => Settled::Unusable(unusable(&error, keys, ds_ttl)),
            },
        )
    }

    /// The keys of the zone `name` that holds a trust anchor: the DNSKEY `RRset` signed by a key of the anchor
    /// or vouched for by its DS (RFC 4035 §5.2, RFC 4509).
    fn anchor_keys(&mut self, name: &Name<'static>) -> Result<Settled, Need> {
        let message = match self.fetch(name, RecordType::DNSKEY)? {
            Ok(message) => message,
            Err(failure) => return Ok(Settled::Unusable(Unusable::Failed(failure))),
        };
        let answer = Section::new(&message.answer);
        let Some(keys) = answer.find(name, RecordType::DNSKEY) else {
            return Ok(missing_keys(name));
        };
        let sigs = answer.signatures(keys);
        let config = Arc::clone(&self.config);
        let Some((_, anchor)) = config.anchors.closest(name) else {
            return Ok(missing_keys(name));
        };
        let mut errors = Vec::new();
        let trusted = anchor_set(
            name,
            anchor
                .dnskeys()
                .iter()
                .map(|key| RData::Dnskey(key.clone())),
        );
        if let Some(trusted) = trusted {
            match verify_any(keys, &sigs, &Key::all(&trusted), self.now, &mut self.budget) {
                Ok(verified) => return Ok(secure(keys, verified.ttl)),
                Err(error) => errors.push(error),
            }
        }
        if let Some(ds) = anchor_set(name, anchor.ds().iter().map(|ds| RData::Ds(ds.clone()))) {
            match trusted_keys(keys, &sigs, &ds, self.now, &mut self.budget) {
                Ok(verified) => return Ok(secure(keys, verified.ttl)),
                Err(error) => errors.push(error),
            }
        }
        let error = errors
            .iter()
            .find(|error| !error.is_unsupported())
            .or(errors.first())
            .unwrap_or(&SigError::NoKeyForDs);
        Ok(Settled::Unusable(unusable(error, keys, Ttl::MAX)))
    }
}

fn secure(keys: &RrSet<'static>, ttl: Ttl) -> Settled {
    Settled::Secure {
        keys: Arc::new(keys.clone()),
        ttl,
    }
}

fn missing_keys(name: &Name<'_>) -> Settled {
    Settled::Unusable(Unusable::Failed(Failure::bogus(
        InfoCode::DNSKEY_MISSING,
        format!("no DNSKEY RRset of {name}"),
    )))
}
