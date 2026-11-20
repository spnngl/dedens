//! The root's trust anchors followed through a key rollover (RFC 5011, D200): each key of the root's DNSKEY
//! `RRset` the resolver validates itself, in a state of RFC 5011 §4, written as a text a server keeps.

use core::cmp::Ordering;
use core::fmt;
use std::collections::{HashMap, HashSet};

use dedens_proto::rdata::{Dnskey, Ds};
use dedens_proto::{Class, Name, Record, RecordType};

use super::{Anchor, TrustAnchors};
use crate::crypto::{self, Budget};
use crate::rrsig::{self, Key, RrSet, SigError, Signature};

/// The first line of the text of [`Rollover`]: what it is, and the version of its format.
const HEADER: &str = "dedens rfc5011 1";

/// The last line of the text of [`Rollover`]: a text cut short lacks it, so it is refused rather than read as one
/// with fewer keys.
const END: &str = "end";

/// A day, in seconds.
const DAY: u64 = 24 * 60 * 60;

// Written out, the ceiling has no arithmetic a mutant could change unseen; it is 15 days all the same.
const _: () = assert!(Rollover::QUERY_CEILING == 15 * DAY);

/// The state of a key [`Rollover`] follows (RFC 5011 §4). `Start` is no state held, and `Removed` is one only of a
/// key that was revoked: any other key `Removed` is not kept, as Unbound drops it (`validator/autotrust.c`,
/// `autr_cleanup_keys`). A key revoked is kept so that it is never added or trusted again.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyState {
    /// A new key, seen in a validated `RRset`, not trusted before `until`, in seconds since 1970: the add
    /// hold-down (§2.2).
    AddPend {
        /// The end of the hold-down.
        until: u64,
    },
    /// A trusted key, seen in the last validated `RRset`.
    Valid,
    /// A trusted key, not seen in a validated `RRset` since `since` (§4, `KeyRem`).
    Missing {
        /// The first validated `RRset` without it.
        since: u64,
    },
    /// A key whose revocation, signed by itself, was seen, last at `seen` (§2.1): never trusted again.
    Revoked {
        /// The last `RRset` it was seen revoked in.
        seen: u64,
    },
}

impl KeyState {
    /// Whether the key is a trust anchor: valid, or missing but not yet removed (§4).
    #[must_use]
    pub const fn trusted(self) -> bool {
        matches!(self, Self::Valid | Self::Missing { .. })
    }
}

/// A key and its state; the key without its revoke bit, so that its revoked form matches it.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Tracked {
    key: Dnskey<'static>,
    state: KeyState,
}

/// The root's trust anchors followed by RFC 5011 (D200): each key the root's DNSKEY `RRset` published since a
/// [`Rollover::seed`], in its state of §4, updated by [`Rollover::observe`] from each `RRset` the trusted keys
/// sign. [`Rollover::anchors`] are the keys valid or missing.
///
/// Written as a text ([`fmt::Display`]) that [`Rollover::read`] reads back:
///
/// ```text
/// dedens rfc5011 1
/// valid 257 3 8 AwEAAaz/tAm8yTn4Mfeh5eyI96WSVexTBAvkMgJzkKTOiW1vkIbzxeF3+/4RgWOq7HrxRixHlFlExOLAJr5emLvN7SWXgnLh4+B5xQlNVz8Og8kvArMtNROxVQuCaSnIDdD5LKyWbRd2n9WGe2R8PzgCmr3EgVLrjyBxWezF0jLHwVN8efS3rCj/EWgvIWgb9tarpVUDK/b58Da+sqqls3eNbuv7pr+eoZG+SrDK6nWeL3c6H5Apxz7LjVc1uTIdsIXxuOLYA4/ilBmSVIzuDWfdRUfhHdY6+cn8HFRm+2hM8AnXGXws9555KrUB5qihylGa8subX2Nn6UwNR1AkUTV74bU=
/// end
/// ```
///
/// A key in another state has the time of its state before it: `addpend UNTIL`, `missing SINCE`, `revoked SEEN`.
/// The text is as trusted as where it is kept: the signatures it was learnt from are not kept with it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Rollover {
    /// In the order of [`order`], one per key.
    keys: Vec<Tracked>,
}

/// Why a DNSKEY `RRset` updated nothing but revocations: [`Rollover::observe`] keeps every state.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum RolloverError {
    /// The records hold no DNSKEY `RRset` of the root, class IN.
    #[error("no DNSKEY RRset of the root")]
    NoKeys,
    /// No trusted key of the `RRset` signs it (RFC 4035 §5.3).
    #[error("the root's DNSKEY RRset is not signed by a trusted key: {0}")]
    Unverified(#[from] SigError),
}

/// Why a text is not that of [`Rollover`]: its line, from 1, and what is wrong there.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("line {line}: {what}")]
pub struct RolloverStateError {
    /// The line, from 1; 0 for the text as a whole.
    pub line: usize,
    /// What is wrong with it.
    pub what: &'static str,
}

impl Rollover {
    /// The add hold-down, 30 days (RFC 5011 §2.4.1: the larger of 30 days and the `RRset`'s TTL): how long a new
    /// key is seen before it is trusted, so that a stolen key has to be published that long. Unbound's default
    /// `add-holddown` (`validator/autotrust.c`, `do_addtime`) and BIND's `dns_zone_mkey_month`
    /// (`lib/dns/zone.c`, `keyfetch_done`) are as long.
    pub const ADD_HOLD_DOWN: u64 = 30 * DAY;

    /// How long a missing key stays trusted when another key is valid, 366 days: a key the root unpublishes for a
    /// time (a standby) is trusted when it comes back. Unbound's `keep-missing` (`remove_missing_trustanchors`);
    /// BIND keeps it until revoked, RFC 5011 §4 too, which leaves a key the operator dropped trusted forever.
    pub const KEEP_MISSING: u64 = 366 * DAY;

    /// The shortest wait between two queries, an hour (RFC 5011 §2.3), as Unbound (`set_tp_times`) and BIND
    /// (`refresh_time`) floor it. The root's DNSKEY `RRset` has a TTL of 2 days and signatures of 3 weeks, so half
    /// of either is longer: a smaller one comes only from a cache's remaining TTL, or from the end of the
    /// signatures drawing near.
    pub const QUERY_FLOOR: u64 = 60 * 60;

    /// The longest wait between two queries, 15 days (RFC 5011 §2.3), as Unbound's `set_tp_times` and BIND's
    /// `refresh_time` cap it. The root's TTL of 2 days never reaches it, so no answer of the root's does in a test.
    pub const QUERY_CEILING: u64 = 1_296_000;

    /// The most keys followed, 32: RFC 5011 §2.4.3 expects a handful, the root's holds four or fewer, and the keys
    /// missing or revoked, kept, add up. A new key past it is not followed ([`Rollover::is_full`]), so that the
    /// text stays within [`Rollover::MAX_LEN`] for keys of any usual size.
    pub const MAX_KEYS: usize = 32;

    /// The longest text [`Rollover::read`] reads, 64 KiB, and a server writes: the text of a key is its base64 and
    /// its state, over a third more than its wire form, so a DNSKEY `RRset` that fits in a message of that size
    /// may not fit in a text of it. [`Rollover::MAX_KEYS`] keeps it within for keys of any usual size.
    pub const MAX_LEN: usize = 64 << 10;

    /// The keys `anchors` trusts at the root, followed from `records`, which must hold the root's DNSKEY `RRset`
    /// and its RRSIGs, at `now`, in seconds since 1970: what a resolver starts from without a text of its own
    /// (D200). A DNSKEY anchor is valid; a key of the `RRset` a DS anchor digests is valid; the `RRset` must be
    /// signed by one of those; its other keys are new ([`Rollover::observe`]). Returns the wait before the next
    /// query, in seconds.
    ///
    /// # Errors
    ///
    /// [`RolloverError`] when the records hold no DNSKEY `RRset` of the root, or no key `anchors` trusts signs it.
    pub fn seed(
        anchors: &TrustAnchors,
        records: &[Record<'_>],
        now: u64,
    ) -> Result<(Self, u64), RolloverError> {
        Self::seeded(Vec::new(), anchors, records, now)
    }

    /// [`Rollover::seed`] for a state replaced by `anchors`, which may predate a revocation (a stale download):
    /// the keys `self` holds revoked stay so, and are trusted through neither a DNSKEY anchor nor a DS one, or by
    /// any answer, as RFC 5011 §2.1 and §4 make a revocation final. Every other key of `self` is forgotten.
    ///
    /// # Errors
    ///
    /// Those of [`Rollover::seed`]; also when only a revoked key of `self` would have signed the `RRset`.
    pub fn reseed(
        &self,
        anchors: &TrustAnchors,
        records: &[Record<'_>],
        now: u64,
    ) -> Result<(Self, u64), RolloverError> {
        let revoked = (self.keys.iter())
            .filter(|tracked| matches!(tracked.state, KeyState::Revoked { .. }))
            .cloned()
            .collect();
        Self::seeded(revoked, anchors, records, now)
    }

    /// `revoked`, the keys revoked, with each DNSKEY anchor that is not one valid, updated from `records`.
    fn seeded(
        revoked: Vec<Tracked>,
        anchors: &TrustAnchors,
        records: &[Record<'_>],
        now: u64,
    ) -> Result<(Self, u64), RolloverError> {
        let (ds, dnskeys) = anchors
            .zones
            .get(&Name::root())
            .map_or((&[][..], &[][..]), |anchor| {
                (anchor.ds.as_slice(), anchor.dnskeys.as_slice())
            });
        let mut rollover = Self { keys: revoked };
        for key in dnskeys {
            let key = unrevoked(key);
            if !rollover.is_full() && !rollover.keys.iter().any(|tracked| tracked.key == key) {
                rollover.keys.push(Tracked {
                    key,
                    state: KeyState::Valid,
                });
            }
        }
        rollover.sort();
        let wait = rollover.update(ds, records, now)?;
        Ok((rollover, wait))
    }

    /// `anchors` less what trusts a key `self` holds revoked: the root's DNSKEY anchors of it, and its DS ones. What
    /// a state of revoked keys alone serves in place of its own anchors ([`Rollover::anchors`] is `None`). When
    /// nothing is left, the root's anchor is empty, not absent: no key validates the root, rather than the root
    /// being insecure.
    #[must_use]
    pub fn without_revoked(&self, anchors: &TrustAnchors) -> TrustAnchors {
        let mut anchors = anchors.clone();
        if let Some(anchor) = anchors.zones.get_mut(&Name::root()) {
            let wires: Vec<_> = (self.keys.iter())
                .filter(|tracked| matches!(tracked.state, KeyState::Revoked { .. }))
                .map(|tracked| wire(&tracked.key))
                .collect();
            anchor
                .ds
                .retain(|ds| !wires.iter().any(|wire| digests(ds, wire)));
            anchor.dnskeys.retain(|key| !self.revoked(key));
        }
        anchors
    }

    /// Updates each key from the root's DNSKEY `RRset` in `records`, with its RRSIGs, at `now`, in seconds since
    /// 1970 (RFC 5011 §4); returns the wait before the next query, in seconds: half the `RRset`'s TTL or of the
    /// time left to its signature, between [`Rollover::QUERY_FLOOR`] and [`Rollover::QUERY_CEILING`] (§2.3).
    ///
    /// First, each key followed whose revoked form is in the `RRset` and signs it is revoked (§2.1), whatever
    /// else signs it. Then the `RRset` must be signed by a trusted key; if so, each key is updated: a new key,
    /// a secure entry point of a supported algorithm, waits [`Rollover::ADD_HOLD_DOWN`] (or the TTL when longer)
    /// and is valid when seen after that, unless [`Rollover::MAX_KEYS`] keys are followed; one gone before is
    /// dropped. A valid key gone is missing, a missing key
    /// back is valid, and a missing key is dropped after [`Rollover::KEEP_MISSING`] when another is valid. A
    /// revoked key is kept for good, whether published or not: RFC 5011 §2.4.2 lets a resolver forget it after
    /// the remove hold-down, but a stale anchor it is seeded with would trust it again (§2.1, §4).
    ///
    /// # Errors
    ///
    /// [`RolloverError`] when the records hold no DNSKEY `RRset` of the root, or no trusted key signs it: only
    /// revocations are kept.
    pub fn observe(&mut self, records: &[Record<'_>], now: u64) -> Result<u64, RolloverError> {
        self.update(&[], records, now)
    }

    /// [`Rollover::observe`], a key of the `RRset` a DS record of `ds` digests trusted as a valid one.
    fn update(
        &mut self,
        ds: &[Ds<'_>],
        records: &[Record<'_>],
        now: u64,
    ) -> Result<u64, RolloverError> {
        let root = &Name::root();
        let sets = RrSet::group(records);
        let at_root = |rtype| {
            sets.iter().filter(move |set| {
                set.owner() == root && set.class() == Class::IN && set.rtype() == rtype
            })
        };
        let dnskeys = at_root(RecordType::DNSKEY)
            .next()
            .ok_or(RolloverError::NoKeys)?;
        let sigs: Vec<_> = at_root(RecordType::RRSIG)
            .flat_map(Signature::all)
            .collect();
        let published = Key::all(dnskeys);
        let [.., a, b, c, d] = now.to_be_bytes();
        let serial = u32::from_be_bytes([a, b, c, d]);
        let mut budget = Budget::new(Budget::DEFAULT_VERIFICATIONS, Budget::DEFAULT_NSEC3_BLOCKS);
        for key in published.iter().filter(|key| key.dnskey().is_revoked()) {
            let plain = unrevoked(key.dnskey());
            if let Some(tracked) = self.keys.iter_mut().find(|tracked| tracked.key == plain)
                && rrsig::verify_revocation(dnskeys, &sigs, key, serial, &mut budget)
            {
                tracked.state = KeyState::Revoked { seen: now };
            }
        }
        let ds = rrsig::counted(ds.iter().cloned()).unwrap_or_default();
        let trusted: Vec<Key<'_>> = (published.iter())
            .filter(|key| {
                !key.dnskey().is_revoked()
                    && (self.trusts(key.dnskey())
                        || (!self.revoked(key.dnskey()) && digested(&ds, key.dnskey())))
            })
            .cloned()
            .collect();
        let verified = rrsig::verify_any(dnskeys, &sigs, &trusted, serial, &mut budget)?;
        let present: Vec<Dnskey<'_>> = (published.iter())
            .map(Key::dnskey)
            .filter(|key| !key.is_revoked())
            .cloned()
            .collect();
        self.keys.retain_mut(|tracked| {
            let here = present.contains(&tracked.key);
            let next = match tracked.state {
                KeyState::AddPend { until } if here && until <= now => Some(KeyState::Valid),
                KeyState::AddPend { .. } if !here => None,
                KeyState::Valid if !here => Some(KeyState::Missing { since: now }),
                KeyState::Missing { .. } if here => Some(KeyState::Valid),
                state => Some(state),
            };
            next.inspect(|&state| tracked.state = state).is_some()
        });
        // The key that signed is published and trusted, so Valid now: a missing key is dropped only beside a valid
        // one, as Unbound's `remove_missing_trustanchors` requires.
        self.keys.retain(|tracked| match tracked.state {
            KeyState::Missing { since } => now.saturating_sub(since) <= Self::KEEP_MISSING,
            _ => true,
        });
        // The original TTL is signed; the lowest of the RRSIGs, so that one bogus signature beside the others cannot
        // stretch the wait of a new key, which is no less than the 30 days.
        let original_ttl = (sigs.iter())
            .map(Signature::rrsig)
            .filter(|rrsig| rrsig.type_covered == RecordType::DNSKEY)
            .map(|rrsig| u64::from(rrsig.original_ttl))
            .min()
            .unwrap_or_default();
        let hold_down = Self::ADD_HOLD_DOWN.max(original_ttl);
        for key in published.iter().filter(|key| {
            let dnskey = key.dnskey();
            dnskey.is_secure_entry_point()
                && dnskey.is_zone_key()
                && !dnskey.is_revoked()
                && crypto::supported(dnskey.algorithm())
        }) {
            let dnskey = key.dnskey().clone().into_owned();
            if self.keys.iter().any(|tracked| tracked.key == dnskey) {
                continue;
            }
            if self.is_full() {
                break;
            }
            let state = if digested(&ds, key.dnskey()) {
                KeyState::Valid
            } else {
                KeyState::AddPend {
                    until: now.saturating_add(hold_down),
                }
            };
            self.keys.push(Tracked { key: dnskey, state });
        }
        self.sort();
        let half = u64::from(verified.ttl.get()) / 2;
        Ok(half.clamp(Self::QUERY_FLOOR, Self::QUERY_CEILING))
    }

    /// Whether [`Rollover::MAX_KEYS`] keys are followed: a new key is not.
    #[must_use]
    pub fn is_full(&self) -> bool {
        self.keys.len() >= Self::MAX_KEYS
    }

    /// Each key followed, without its revoke bit, and its state.
    pub fn keys(&self) -> impl Iterator<Item = (&Dnskey<'static>, KeyState)> {
        self.keys
            .iter()
            .map(|tracked| (&tracked.key, tracked.state))
    }

    /// The root's anchors: the keys valid or missing, as DNSKEY anchors; `None` when there is none, every key
    /// revoked, so that the caller serves its other anchors less those revoked ([`Rollover::without_revoked`])
    /// rather than trust nothing (D200).
    #[must_use]
    pub fn anchors(&self) -> Option<TrustAnchors> {
        let dnskeys: Vec<_> = (self.keys.iter())
            .filter(|tracked| tracked.state.trusted())
            .map(|tracked| tracked.key.clone())
            .collect();
        (!dnskeys.is_empty()).then(|| TrustAnchors {
            zones: HashMap::from([(
                Name::root(),
                Anchor {
                    ds: Vec::new(),
                    dnskeys,
                },
            )]),
            negative: HashSet::new(),
        })
    }

    /// Whether `anchors` trust at the root the keys [`Rollover::anchors`] does: each of its DS records digests a
    /// trusted key and each of its DNSKEYs is one, and each trusted key is among them. What a server logs when
    /// the signed download and the rollover disagree (D200).
    #[must_use]
    pub fn agrees(&self, anchors: &TrustAnchors) -> bool {
        let Some(anchor) = anchors.zones.get(&Name::root()) else {
            return false;
        };
        let trusted: Vec<_> = (self.keys.iter())
            .filter(|tracked| tracked.state.trusted())
            .map(|tracked| (&tracked.key, wire(&tracked.key)))
            .collect();
        anchor
            .ds
            .iter()
            .all(|ds| trusted.iter().any(|(_, wire)| digests(ds, wire)))
            && (anchor.dnskeys.iter())
                .all(|key| trusted.iter().any(|(own, _)| **own == unrevoked(key)))
            && trusted.iter().all(|(own, wire)| {
                anchor.ds.iter().any(|ds| digests(ds, wire))
                    || anchor.dnskeys.iter().any(|key| unrevoked(key) == **own)
            })
    }

    /// The keys written in `text`, as [`fmt::Display`] writes them: the header line, one key per line in that
    /// order, at least one valid, missing or revoked, then `end`, each line ending with a line feed. Nothing else
    /// is read: not a blank, not a comment.
    ///
    /// # Errors
    ///
    /// [`RolloverStateError`] at the first line that is not as written, a key that is not after the one before
    /// (out of order or twice) included; at line 0 when `text` is longer than [`Rollover::MAX_LEN`], does not end
    /// with `end` and a line feed, or holds no key valid, missing or revoked: a text cut short or emptied is never
    /// read as trusting nothing, while one of revoked keys is.
    pub fn read(text: &str) -> Result<Self, RolloverStateError> {
        let whole = |what| RolloverStateError { line: 0, what };
        if text.len() > Self::MAX_LEN {
            return Err(whole("longer than 64 KiB"));
        }
        let body = (text.strip_suffix('\n'))
            .and_then(|body| body.strip_suffix(END))
            .and_then(|body| body.strip_suffix('\n'))
            .ok_or(whole("no `end` line at the end"))?;
        let mut lines = body.split('\n').zip(1..);
        let (header, line) = lines.next().ok_or(whole("empty"))?;
        if header != HEADER {
            return Err(RolloverStateError {
                line,
                what: "not `dedens rfc5011 1`",
            });
        }
        let mut keys: Vec<Tracked> = Vec::new();
        for (text, line) in lines {
            let tracked = tracked(text).ok_or(RolloverStateError { line, what: KEY })?;
            if keys
                .last()
                .is_some_and(|last| order(last, &tracked) != Ordering::Less)
            {
                return Err(RolloverStateError {
                    line,
                    what: "a key not after the one before",
                });
            }
            keys.push(tracked);
        }
        // A state of revoked keys alone is kept: it is what stops a stale anchor from trusting them again.
        if !keys.iter().any(|tracked| {
            tracked.state.trusted() || matches!(tracked.state, KeyState::Revoked { .. })
        }) {
            return Err(whole("no valid, missing or revoked key"));
        }
        Ok(Self { keys })
    }

    /// Whether `key`, in either form, is one this holds revoked.
    fn revoked(&self, key: &Dnskey<'_>) -> bool {
        let plain = unrevoked(key);
        (self.keys.iter()).any(|tracked| {
            matches!(tracked.state, KeyState::Revoked { .. }) && tracked.key == plain
        })
    }

    /// Whether `key`, not revoked, is a trust anchor.
    fn trusts(&self, key: &Dnskey<'_>) -> bool {
        (self.keys.iter()).any(|tracked| tracked.state.trusted() && tracked.key == *key)
    }

    /// Puts the keys in the order of [`order`], the text's.
    fn sort(&mut self) {
        self.keys.sort_by(order);
    }
}

/// The order of the keys in the text: by algorithm, public key, then flags.
fn order(a: &Tracked, b: &Tracked) -> Ordering {
    let fields = |tracked: &Tracked| {
        let key = &tracked.key;
        (
            u8::from(key.algorithm()),
            key.public_key().to_vec(),
            key.flags(),
        )
    };
    fields(a).cmp(&fields(b))
}

/// `key` without its revoke bit.
fn unrevoked(key: &Dnskey<'_>) -> Dnskey<'static> {
    Dnskey::new(
        key.flags() & !Dnskey::REVOKE,
        key.algorithm(),
        key.public_key(),
    )
    .map_or_else(|_| key.clone().into_owned(), Dnskey::into_owned)
}

/// The RDATA of `key` (RFC 4034 §2.1): what its key tag and DS digests are computed over.
fn wire(key: &Dnskey<'_>) -> Vec<u8> {
    let mut wire = key.flags().to_be_bytes().to_vec();
    wire.extend_from_slice(&[3, u8::from(key.algorithm())]);
    wire.extend_from_slice(key.public_key());
    wire
}

/// Whether a DS record of `ds`, those that count ([`rrsig::counted`]), digests `key` (RFC 4034 §5.1.4).
fn digested(ds: &[Ds<'_>], key: &Dnskey<'_>) -> bool {
    let wire = wire(key);
    ds.iter().any(|ds| digests(ds, &wire))
}

/// Whether `ds` is the digest of the root's key of RDATA `wire` (RFC 4034 §5.1.4): the digest covers the key tag
/// and algorithm, which need no comparing.
fn digests(ds: &Ds<'_>, wire: &[u8]) -> bool {
    crypto::ds_digest(ds.digest_type(), &Name::root(), wire)
        .is_ok_and(|digest| digest.as_ref() == ds.digest())
}

/// What a key's line is when it is not one.
const KEY: &str = "not a state, its time but for `valid`, and a DNSKEY not revoked";

/// The key of `line`: `valid KEY`, `addpend UNTIL KEY`, `missing SINCE KEY` or `revoked SEEN KEY`, `KEY` the
/// DNSKEY's data as [`Dnskey`] writes it, the revoke bit unset.
fn tracked(line: &str) -> Option<Tracked> {
    let (word, rest) = line.split_once(' ')?;
    let timed = || {
        let (time, key) = rest.split_once(' ')?;
        Some((number(time)?, key))
    };
    let (state, key) = match word {
        "valid" => (KeyState::Valid, rest),
        "addpend" => timed().map(|(until, key)| (KeyState::AddPend { until }, key))?,
        "missing" => timed().map(|(since, key)| (KeyState::Missing { since }, key))?,
        "revoked" => timed().map(|(seen, key)| (KeyState::Revoked { seen }, key))?,
        _ => return None,
    };
    let anchors = TrustAnchors::read(&format!(". IN DNSKEY {key}")).ok()?;
    let [read] = anchors.zones.get(&Name::root())?.dnskeys.as_slice() else {
        return None;
    };
    (!read.is_revoked() && read.to_string() == key).then(|| Tracked {
        key: read.clone(),
        state,
    })
}

/// A decimal number, digits only: no sign, no blank.
fn number(text: &str) -> Option<u64> {
    (!text.is_empty() && text.bytes().all(|b| b.is_ascii_digit()))
        .then(|| text.parse().ok())
        .flatten()
}

/// The text [`Rollover::read`] reads.
impl fmt::Display for Rollover {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "{HEADER}")?;
        for Tracked { key, state } in &self.keys {
            match state {
                KeyState::Valid => writeln!(f, "valid {key}")?,
                KeyState::AddPend { until } => writeln!(f, "addpend {until} {key}")?,
                KeyState::Missing { since } => writeln!(f, "missing {since} {key}")?,
                KeyState::Revoked { seen } => writeln!(f, "revoked {seen} {key}")?,
            }
        }
        writeln!(f, "{END}")
    }
}
