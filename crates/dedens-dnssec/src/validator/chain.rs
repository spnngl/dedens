//! The chain of trust: from a trust anchor down one label at a time, a zone's DS record in its parent and its
//! DNSKEY `RRset` under that DS (RFC 4033 §5, RFC 4035 §5.2).

use std::sync::Arc;

use dedens_proto::edns::InfoCode;
use dedens_proto::{
    Class, Message, Name, Question, RData, Rcode, Record, RecordType, Ttl, WireRdata,
};

use super::section::{Section, dname_of, synthesized};
use super::verdict::{Failure, InsecureReason, Unusable};
use super::{Need, Validation};
use crate::denial::Fact;
use crate::rrsig::{Key, RrSet, SigError, trusted_keys, verify_any};

/// What is known of a zone: its keys, or why it has none that count.
///
/// Secure keys carry the TTL of the signatures and DS records that vouch for them (RFC 4035 §5.3.3), an insecure
/// zone the TTL of the proof; the key cache keeps them for that long (D86). A bogus zone is kept by its
/// validation alone; an indeterminate one by none (D92).
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
    /// The name is no zone cut: it belongs to the zone with this apex, as far as `ttl` holds.
    Inside { apex: Name<'static>, ttl: Ttl },
    /// The name is below a zone that is unusable: the zone's outcome, which the key cache has under the
    /// zone's name and the clock of that entry rules, so this one is never kept.
    Beneath(Unusable),
}

impl Zone {
    /// How long the key cache may keep this outcome, or `None` for one it never keeps (D86, D92): a failure,
    /// bogus or indeterminate, which anyone can cause and a later walk may find otherwise; what a trust
    /// anchor setting decides (the cache dies with those); and what is inherited from the zone above.
    pub(super) const fn lifetime(&self) -> Option<Ttl> {
        match self {
            Self::Apex(Settled::Secure { ttl, .. }) | Self::Inside { ttl, .. } => Some(*ttl),
            Self::Apex(Settled::Unusable(Unusable::Insecure { reason, ttl })) => match reason {
                InsecureReason::NoAnchor | InsecureReason::NegativeAnchor => None,
                _ => Some(*ttl),
            },
            Self::Apex(Settled::Unusable(Unusable::Failed(_))) | Self::Beneath(_) => None,
        }
    }

    /// This outcome with the TTL of what is left of its lifetime: what is derived from it never outlives it.
    pub(super) fn with_ttl(self, left: Ttl) -> Self {
        match self {
            Self::Apex(Settled::Secure { keys, ttl }) => Self::Apex(Settled::Secure {
                keys,
                ttl: ttl.min(left),
            }),
            Self::Inside { apex, ttl } => Self::Inside {
                apex,
                ttl: ttl.min(left),
            },
            Self::Apex(Settled::Unusable(Unusable::Insecure { reason, ttl })) => {
                Self::Apex(Settled::Unusable(Unusable::Insecure {
                    reason,
                    ttl: ttl.min(left),
                }))
            }
            other => other,
        }
    }
}

/// What the parent says of a name as a zone cut (RFC 4035 §5.2). Never kept: the zone it leads to is.
#[derive(Debug, Clone)]
pub(super) enum Cut {
    /// The name holds a trust anchor.
    Anchored,
    /// The parent's authenticated DS `RRset`.
    Signed {
        ds: RrSet<'static>,
        ttl: Ttl,
    },
    /// The name is no zone cut; it belongs to the zone with this apex, as far as `ttl` holds.
    Inside {
        apex: Name<'static>,
        ttl: Ttl,
    },
    Unusable(Unusable),
    /// The name is below a zone that is unusable, which says so for it too.
    Beneath(Unusable),
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

/// What an error of a signature check makes of the data it was about: bogus, but for an exhausted budget, which
/// says nothing of the data (the caller or an attacker spent it) and so is indeterminate, like a lame server
/// (RFC 9276 §3.2, D71, D75).
pub(super) fn sig_failure(error: &SigError, set: &RrSet<'_>) -> Failure {
    match error {
        SigError::BudgetExhausted(_) => Failure::indeterminate(
            InfoCode::DNSSEC_INDETERMINATE,
            format!("{} {}: {error}", set.owner(), set.rtype()),
        ),
        _ => Failure::Bogus(error.ede(set)),
    }
}

/// What an error of a signature check makes of a zone or delegation: insecure when only the DS records are
/// unusable (RFC 6840 §5.2, D73), bogus (indeterminate for the budget, [`sig_failure`]) otherwise.
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
        _ => Unusable::Failed(sig_failure(error, set)),
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
    pub(super) fn fetch(
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

    /// Records what is known of `name`: the one place a zone's outcome is written, and one that keeps nothing
    /// indeterminate: a question the caller could not answer, or a limit, says nothing of the zone, and the
    /// next attempt may do better. The key cache gets what [`Zone::lifetime`] lets it keep, never from a hit
    /// of the cache itself (that would renew it). Returns the zone, as given.
    fn settle(&mut self, name: &Name<'static>, zone: Zone) -> Zone {
        let indeterminate = matches!(
            zone,
            Zone::Apex(Settled::Unusable(Unusable::Failed(Failure::Indeterminate(
                _
            ))))
        );
        if !indeterminate {
            self.zones.insert(name.clone(), zone.clone());
            self.config.cache.put(name, &zone, self.at);
        }
        zone
    }

    /// The failure of a name too many labels below its closest trust anchor, which the limit on depth bounds: a
    /// function of the name alone, so that no order of calls changes an outcome.
    fn too_deep(&self, name: &Name<'_>) -> Option<Failure> {
        let (anchor, _) = self.config.anchors.closest(name)?;
        let depth = name.label_count().saturating_sub(anchor.label_count());
        (depth > self.config.limits.depth).then(|| {
            Failure::indeterminate(
                InfoCode::DNSSEC_INDETERMINATE,
                format!(
                    "{name} is {depth} labels below its trust anchor, the limit is {}",
                    self.config.limits.depth
                ),
            )
        })
    }

    /// The zone `name` belongs to, as its apex and its keys, walking down from the trust anchor one label at a
    /// time (RFC 4035 §5.2): a name below an insecure zone is insecure, below a secure one it is in the zone
    /// unless its parent proves a delegation. The walk is by the labels of `name`, never by what a response
    /// says of its signers. The one place a zone's outcome is read: what the validation settled, else what the
    /// key cache holds (D86), which the validation then keeps, so that it sees one outcome whatever the cache
    /// does meanwhile.
    ///
    /// # Errors
    ///
    /// [`Need`] for the DS or DNSKEY response the walk lacks.
    pub(super) fn zone_of(
        &mut self,
        name: &Name<'static>,
    ) -> Result<(Name<'static>, Settled), Need> {
        let mut at = name.clone();
        loop {
            if let Some(failure) = self.too_deep(&at) {
                return Ok((at, Settled::Unusable(Unusable::Failed(failure))));
            }
            let zone = if let Some(known) = self.zones.get(&at) {
                known.clone()
            } else if let Some(cached) = self.config.cache.get(&at, self.at) {
                self.zones.insert(at.clone(), cached.clone());
                cached
            } else {
                let found = self.resolve(&at)?;
                self.settle(&at, found)
            };
            match zone {
                Zone::Apex(settled) => return Ok((at, settled)),
                Zone::Inside { apex, .. } => at = apex,
                Zone::Beneath(unusable) => return Ok((at, Settled::Unusable(unusable))),
            }
        }
    }

    /// What `name` is: a zone with its keys, or a name in the zone above it.
    fn resolve(&mut self, name: &Name<'static>) -> Result<Zone, Need> {
        Ok(match self.cut(name, true)? {
            Cut::Anchored => Zone::Apex(self.anchor_keys(name)?),
            Cut::Signed { ds, ttl } => Zone::Apex(self.keys_from_ds(name, &ds, ttl)?),
            Cut::Inside { apex, ttl } => Zone::Inside { apex, ttl },
            Cut::Unusable(unusable) => Zone::Apex(Settled::Unusable(unusable)),
            Cut::Beneath(unusable) => Zone::Beneath(unusable),
        })
    }

    /// What the parent says of `name` as a zone cut, and for a name below an insecure zone, that it is insecure.
    ///
    /// `keys` says the DNSKEY `RRset` of the zone is wanted next: it is asked for before the DS `RRset` is
    /// checked, so that a rerun after its answer does not check again, which would spend the budget twice.
    ///
    /// # Errors
    ///
    /// [`Need`] for a response the walk down to `name` lacks.
    pub(super) fn cut(&mut self, name: &Name<'static>, keys: bool) -> Result<Cut, Need> {
        Ok(match self.position(name) {
            Position::Negative => Cut::Unusable(Unusable::Insecure {
                reason: InsecureReason::NegativeAnchor,
                ttl: Ttl::MAX,
            }),
            Position::Unanchored => Cut::Unusable(Unusable::Insecure {
                reason: InsecureReason::NoAnchor,
                ttl: Ttl::MAX,
            }),
            Position::Anchor => Cut::Anchored,
            Position::Below => self.below_anchor(name, keys)?,
        })
    }

    /// The cut at a name below its trust anchor: the DS `RRset` or the proof of its absence, from the zone of
    /// the parent name.
    fn below_anchor(&mut self, name: &Name<'static>, keys: bool) -> Result<Cut, Need> {
        let Some(parent) = parent(name) else {
            return Ok(Cut::Unusable(Unusable::Failed(Failure::bogus(
                InfoCode::DNSSEC_BOGUS,
                format!("{name} has no parent"),
            ))));
        };
        let (apex, settled) = self.zone_of(&parent)?;
        let (parent_keys, keys_ttl) = match settled {
            Settled::Secure { keys, ttl } => (keys, ttl),
            Settled::Unusable(unusable) => return Ok(Cut::Beneath(unusable)),
        };
        let message = match self.fetch(name, RecordType::DS)? {
            Ok(message) => message,
            Err(failure) => return Ok(Cut::Unusable(Unusable::Failed(failure))),
        };
        let answer = Section::new(&message.answer);
        let authority = Section::new(&message.authority);
        let has_ds = answer.find(name, RecordType::DS).is_some()
            || authority.find(name, RecordType::DS).is_some();
        if keys && has_ds {
            drop(self.fetch(name, RecordType::DNSKEY)?);
        }
        Ok(self.cut_in(name, &apex, &parent_keys, keys_ttl, [&answer, &authority]))
    }

    /// What the response to the DS query says of `name`, checked with the keys of the zone `apex`: the DS
    /// `RRset`; a CNAME or DNAME, which says the name is no cut (an authoritative server answers a DS query for
    /// a CNAME's owner with the CNAME, RFC 4035 §2.4); or the proof that the name has no DS (RFC 4035 §5.2,
    /// RFC 5155 §8.6, RFC 6840 §4.4). The rcode is not read: a name error under an opt-out span proves a
    /// delegation without DS.
    fn cut_in(
        &mut self,
        name: &Name<'static>,
        apex: &Name<'static>,
        keys: &RrSet<'static>,
        keys_ttl: Ttl,
        [answer, authority]: [&Section; 2],
    ) -> Cut {
        let found = [answer, authority]
            .into_iter()
            .find_map(|section| section.find(name, RecordType::DS).map(|ds| (section, ds)));
        if let Some((section, ds)) = found {
            let sigs = section.signatures(ds);
            return match verify_any(ds, &sigs, &Key::all(keys), self.now, &mut self.budget) {
                Ok(verified) if verified.wildcard.is_none() => Cut::Signed {
                    ds: ds.clone(),
                    ttl: verified.ttl.min(keys_ttl),
                },
                Ok(_) => Cut::Unusable(Unusable::Failed(Failure::bogus(
                    InfoCode::DNSSEC_BOGUS,
                    format!("{name} DS comes from a wildcard"),
                ))),
                Err(error) => Cut::Unusable(Unusable::Failed(sig_failure(&error, ds))),
            };
        }
        let rewrite = answer
            .find(name, RecordType::CNAME)
            .filter(|cname| !synthesized(cname, answer))
            .or_else(|| dname_of(answer, name));
        if let Some(set) = rewrite {
            return match self.verify_set(set, answer, authority, apex, keys, keys_ttl) {
                Ok(ttl) => Cut::Inside {
                    apex: apex.clone(),
                    ttl,
                },
                Err(unusable) => Cut::Unusable(unusable),
            };
        }
        let question = Question::new(name.clone(), RecordType::DS);
        match self.prove_denial(apex, keys, keys_ttl, authority, &question) {
            Err(unusable) => Cut::Unusable(unusable),
            Ok(proof) => match proof.fact {
                Fact::InsecureDelegation => Cut::Unusable(Unusable::Insecure {
                    reason: if proof.opt_out {
                        InsecureReason::OptOut
                    } else {
                        InsecureReason::UnsignedDelegation
                    },
                    ttl: proof.ttl,
                }),
                // The name may exist unsigned under an opt-out span (RFC 5155 §6).
                _ if proof.opt_out => Cut::Unusable(Unusable::Insecure {
                    reason: InsecureReason::OptOut,
                    ttl: proof.ttl,
                }),
                Fact::NameError { .. } | Fact::NoData | Fact::WildcardNoData => Cut::Inside {
                    apex: apex.clone(),
                    ttl: proof.ttl,
                },
                _ => Cut::Unusable(Unusable::Failed(Failure::bogus(
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

/// No DNSKEY `RRset` in the answer: bogus for the validation, though an answer can lack it whatever the zone.
fn missing_keys(name: &Name<'_>) -> Settled {
    Settled::Unusable(Unusable::Failed(Failure::bogus(
        InfoCode::DNSKEY_MISSING,
        format!("no DNSKEY RRset of {name}"),
    )))
}
