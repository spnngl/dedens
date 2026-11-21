//! The `RRset` cache: what the resolver learned, `RRset` by `RRset`, with how far it trusts each (RFC 2181 §5.4.1),
//! and beside them the negative answers (RFC 2308) and failure holds (RFC 9520) of the same store (D199).

use std::cmp::Ordering;
use std::hash::{BuildHasher, RandomState};
use std::sync::Arc;

use dedens_cache::{Checked, Config, ConfigError, Cost, Store};
use dedens_proto::rdata::RData;
use dedens_proto::{Class, MAX_NAME_LEN, Name, Nsec3HashAlgorithm, RecordType, Ttl};
use thiserror::Error;

use crate::metrics::Metrics;
use crate::negative::{Absent, Denied, Hold, Kind, ServerSet};
use crate::rank::Rank;
use crate::resolution::Failure;
use crate::rrset::Rrset;
use crate::spans::{Spans, hash_of};

/// The share of the capacity the index of spans may take, as a divisor (D199): the records themselves stay in the
/// store. Unbound sets its `neg-cache-size` apart, 1 MiB by default (`util/config_file.c`), a quarter of the
/// 4 MiB of its `rrset-cache-size`.
const SPANS_SHARE: usize = 32;

/// The most iterations of an NSEC3 chain the index takes, RFC 9276 §3.2's: one that asks for more is never a proof
/// an answer rests on, and its hashes cost a resolver more than a query does (as Unbound's `nsec3-max-iterations`).
const MAX_ITERATIONS: u16 = 150;
/// The default capacity, in bytes: twice the response cache's 64 MiB default, as Unbound's performance guide sets
/// `rrset-cache-size` to twice `msg-cache-size` (its defaults are 4 MiB each, `util/config_file.c`
/// `config_create`, small for a busy resolver). BIND has no separate budget: its `max-cache-size`, 90 % of memory by
/// default, holds every cache of a view.
pub const DEFAULT_CAPACITY: usize = 128 << 20;

/// An `RRset` and its trust: as the cache holds it, fresh, or as a resolution read it from a response.
///
/// Only an `RRset` of an answer section ([`Rank::AnswerNonAuthoritative`] or [`Rank::AnswerAuthoritative`]) may
/// answer a client's question, proved [`Checked::Secure`] or not: the other ranks are the authority and additional
/// sections, which RFC 2181 §5.4.1 keeps from ever being returned as answers ("Ignoring this would
/// allow the trustworthiness of relatively untrustworthy data to be increased without cause or excuse"). They
/// serve the resolution: the glue of a referral to reach its servers, its NS records to know them. An A or AAAA
/// `RRset` answered over glue not yet expired is held at the glue's rank until it expires (D193, CVE-2026-42955), so
/// it never answers a client from this cache: the response cache serves the answer it came in.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ranked {
    /// The records, shared with the cache.
    pub rrset: Arc<Rrset>,
    /// Where they were read.
    pub rank: Rank,
    /// What the validator found of them.
    pub checked: Checked,
    /// What is left of their time in the cache, which a reply gives as their TTL (RFC 1035 §4.1.3); not
    /// [`Rrset::ttl`], the TTL they were received with. For an `RRset` a resolution just read from a response,
    /// that TTL bounded by [`Config::lifetime`], the time the cache would store it for.
    pub ttl: Ttl,
}

/// What [`RrsetCache::insert`] did, with what the cache holds after.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Inserted {
    /// The `RRset` is stored: the key held none, one expired, or one it replaces (RFC 2181 §5.4.1).
    Stored(Ranked),
    /// The key held the same data unchecked: it takes the verdict, at the greater of the two ranks unless it is an
    /// address pinned to glue (D193), for no longer than it had left.
    Verdict(Ranked),
    /// The key holds an `RRset` trusted more, or as much and the same data: it stays as it was.
    Kept(Ranked),
}

impl Inserted {
    /// What the cache holds under the key.
    #[must_use]
    pub const fn held(&self) -> &Ranked {
        match self {
            Self::Stored(hit) | Self::Verdict(hit) | Self::Kept(hit) => hit,
        }
    }
}

/// Why an `RRset` was not stored. The cache is left as it was: an `RRset` held under the key stays, fresh for as
/// long as it was stored for. Unlike a refused response, which ends the response cache's entry, an `RRset` refused
/// says nothing of the one held: its trust decides alone, and it was not offered to replace it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum NotCached {
    /// TTL 0: for the transaction at hand only (RFC 1035 §3.2.1), including a TTL past 2^31 - 1 (RFC 2181 §8).
    #[error("TTL 0: not to be cached")]
    ZeroTtl,
    /// Its entry would take more than the store's entry limit (D116).
    #[error("the RRset takes more than an entry may")]
    TooLarge,
}

/// The value of a key: an `RRset`, a negative answer, or a failure held. Their keys never meet (see [`key_of`]).
#[derive(Debug)]
enum Entry {
    Rrset(Cached),
    Absent(Box<Absent>),
    Held(Hold),
}

impl Cost for Entry {
    fn cost(&self) -> usize {
        match self {
            Self::Rrset(cached) => cached.rrset.cost(),
            Self::Absent(absent) => absent.cost(),
            Self::Held(held) => held.cost(),
        }
    }
}

/// An `RRset` stored, its trust and its time.
#[derive(Debug)]
struct Cached {
    rrset: Arc<Rrset>,
    rank: Rank,
    checked: Checked,
    /// The time it was stored for, from [`Config::lifetime`].
    ttl: u32,
    /// The time it is no longer fresh at.
    expires: u32,
}

/// What an `RRset` offered does to the one held under its key.
enum Merge {
    /// It takes the held one's place.
    Replace,
    /// The held one takes its verdict.
    Verdict,
    /// Nothing.
    Keep,
}

impl Cached {
    /// The seconds left at `now`, 0 once expired; never more than it was stored for, whichever way the clock goes.
    fn left(&self, now: u32) -> u32 {
        self.expires.saturating_sub(now).min(self.ttl)
    }

    /// Sets the time left at `now`.
    const fn set_left(&mut self, left: u32, now: u32) {
        self.ttl = left;
        self.expires = now.saturating_add(left);
    }

    /// The trust that decides a replacement: secure data above any rank (RFC 2181 §5.4.1), then the rank.
    fn trust(&self) -> (bool, Rank) {
        (self.checked == Checked::Secure, self.rank)
    }

    /// The entry as a hit at `now`, if fresh.
    fn hit(&self, now: u32) -> Option<Ranked> {
        match self.left(now) {
            0 => None,
            left => Some(self.with_left(left)),
        }
    }

    fn with_left(&self, left: u32) -> Ranked {
        Ranked {
            rrset: Arc::clone(&self.rrset),
            rank: self.rank,
            checked: self.checked,
            ttl: Ttl::from_wire(left),
        }
    }

    /// What `new` does to this entry at `now`, as Unbound decides it (`need_to_update_rrset`), but for verdicts: an
    /// expired entry gives way to anything; the same data unchecked takes a verdict; else more trusted data
    /// replaces it, and so does other data of equal trust, the last heard of; bogus data gives way to any other
    /// data not bogus. More trusted data equal to bogus data does not replace it, which would lengthen its life
    /// (RFC 4035 §4.7 bounds it), unless secure.
    fn merge(&self, new: &Self, now: u32) -> Merge {
        if self.left(now) == 0 {
            return Merge::Replace;
        }
        let same = self.rrset == new.rrset;
        if same && self.checked == Checked::Unchecked && new.checked != Checked::Unchecked {
            return Merge::Verdict;
        }
        let bogus = |checked| matches!(checked, Checked::Bogus(_));
        let replace = match new.trust().cmp(&self.trust()) {
            Ordering::Greater => !(same && bogus(self.checked) && new.checked != Checked::Secure),
            Ordering::Equal => !same,
            Ordering::Less => !same && bogus(self.checked) && !bogus(new.checked),
        };
        if replace { Merge::Replace } else { Merge::Keep }
    }

    /// Whether `new`, an A or AAAA `RRset` replacing this entry or a verdict on it, is pinned to this entry as
    /// referral glue ([`Rank::AdditionalNonAuthoritative`]): trusted more, not secure. Pinned, it keeps the glue's
    /// rank, so that the next answer is pinned too, and lives no longer than the glue had left ([`Cached::bound`]): a
    /// server address taken from glue does not outlive its delegation by answers, as Unbound since CVE-2026-42955
    /// (13ec8d0f2). Stricter than Unbound, which pins only when it shortens the TTL and raises the rank on a verdict:
    /// there an answer of a shorter TTL, or an insecure verdict, unpins the address for the next answer to live its
    /// own TTL (D193).
    fn pins(&self, new: &Self) -> bool {
        matches!(new.rrset.rtype(), RecordType::A | RecordType::AAAA)
            && self.rank == Rank::AdditionalNonAuthoritative
            && new.checked != Checked::Secure
            && new.trust() > self.trust()
    }

    /// Bounds the time of `new`, which replaces this entry at `now`, against the ghost domain names (Jiang et al.,
    /// NDSS 2012): a delegation is only renewed from its parent once expired.
    ///
    /// An NS `RRset` lives no longer than the one it replaces, whatever its trust; Unbound does so since
    /// CVE-2026-40622 (8d8fa4226), but for secure data replacing data not secure and for bogus data replaced by
    /// other data, which it lets live their own TTL: stricter here, one rule whatever the verdicts, at the cost of
    /// asking for a delegation again sooner (D193). An A or AAAA `RRset` that [`Cached::pins`] says is pinned to
    /// glue lives no longer either, and keeps the glue's rank whatever its TTL.
    fn bound(&self, new: &mut Self, now: u32) {
        let left = self.left(now);
        if left == 0 {
            return;
        }
        if self.pins(new) {
            new.rank = self.rank;
        } else if new.rrset.rtype() != RecordType::NS {
            return;
        }
        new.set_left(left.min(new.ttl), now);
    }
}

/// `RRsets` under their owner name, type and class (RFC 2181 §5), shared by threads, within a byte budget.
///
/// The store is `dedens-cache`'s (D116, D193): sharded, each shard behind its own lock held for one call (never
/// across an `.await`), S3-FIFO eviction, everything a shard holds counted against its share of the capacity; an
/// [`Rrset`] a [`Ranked`] still holds after its entry was evicted is the caller's. TTLs follow the response cache's
/// [`Config`] (D124), one source for both: [`Config::lifetime`]. Time comes in as seconds from the caller.
#[derive(Debug)]
pub struct RrsetCache {
    store: Store<Entry>,
    /// The order of the secure NSEC and NSEC3 records in the store, for RFC 8198 (D199).
    spans: Spans,
    /// Keyed: the hash of a server set (D199) is not for an attacker to steer.
    hasher: RandomState,
    capacity: usize,
    config: Config,
    metrics: Metrics,
}

impl RrsetCache {
    /// An empty cache of `capacity` bytes, the shards, entry limit and TTLs of `config`, the response cache's: a
    /// 32nd of it for the index of spans, the rest for the store (D199).
    ///
    /// # Errors
    ///
    /// [`ConfigError`] when `config` is invalid, its `capacity`, the response cache's, included; then when
    /// the store's share of `capacity` cannot hold an entry of `config.max_entry_bytes`, or a tenth of a shard's
    /// share an entry of the longest key (D116).
    pub fn new(capacity: usize, config: Config) -> Result<Self, ConfigError> {
        config.validate()?;
        let spans = capacity / SPANS_SHARE;
        Ok(Self {
            store: Store::new(
                capacity - spans,
                config.shards,
                config.max_entry_bytes,
                KEY_LEN,
            )?,
            spans: Spans::new(spans, config.shards),
            hasher: RandomState::new(),
            capacity,
            config,
            metrics: Metrics::new(),
        })
    }

    /// Stores `rrset`, read at `rank` and `checked` so, at `now`, unless the cache holds an `RRset` of the same
    /// key it trusts more (RFC 2181 §5.4.1, [`Rank`]). Returns what it did and what the cache holds after.
    ///
    /// `rrset` was scrubbed (step 05): in the bailiwick of the server it came from, ranked there. The cache
    /// trusts the rank as given; data out of bailiwick ranked high would replace good data.
    ///
    /// Its time in the cache is [`Config::lifetime`], bounded against ghost domain names when it replaces an NS
    /// `RRset` or glue (as `Cached::bound` says: CVE-2026-40622, CVE-2026-42955). A validator records its verdict
    /// on an `RRset` by inserting it again with it: the same data held unchecked takes the verdict, at the greater
    /// rank unless an address pinned to glue, never living longer than it had left nor than the verdict allows
    /// ([`Inserted::Verdict`]).
    ///
    /// # Errors
    ///
    /// [`NotCached`] when `rrset` is not stored: the cache is left as it was.
    pub fn insert(
        &self,
        rrset: impl Into<Arc<Rrset>>,
        rank: Rank,
        checked: Checked,
        now: u32,
    ) -> Result<Inserted, NotCached> {
        let rrset = rrset.into();
        let ttl = self
            .config
            .lifetime(rrset.ttl(), checked)
            .ok_or(NotCached::ZeroTtl)?;
        let mut key = [0; KEY_LEN];
        let key = key_of(
            &mut key,
            None,
            rrset.owner(),
            &[
                &u16::from(rrset.rtype()).to_be_bytes(),
                &u16::from(rrset.class()).to_be_bytes(),
            ],
        );
        if key.len() + rrset.cost() > self.store.entry_limit() {
            return Err(NotCached::TooLarge);
        }
        let new = Cached {
            rrset,
            rank,
            checked,
            ttl,
            expires: now.saturating_add(ttl),
        };
        // What a key of another kind held, which keys keep apart, is replaced.
        let stored = Inserted::Stored(new.with_left(new.ttl));
        // What the shard lets go of, the `RRset` offered or the one it replaces, is freed once its lock is released.
        let ((inserted, _freed), evicted) =
            self.store.upsert(key, Entry::Rrset(new), |entry, offered| {
                match (entry, offered) {
                    (Entry::Rrset(held), None) => {
                        (Inserted::Stored(held.with_left(held.ttl)), None)
                    }
                    (Entry::Rrset(held), Some(Entry::Rrset(mut new))) => {
                        match held.merge(&new, now) {
                            Merge::Keep => (
                                Inserted::Kept(held.with_left(held.left(now))),
                                Some(Entry::Rrset(new)),
                            ),
                            Merge::Verdict => {
                                if !held.pins(&new) {
                                    held.rank = held.rank.max(new.rank);
                                }
                                held.checked = new.checked;
                                held.set_left(held.left(now).min(new.ttl), now);
                                (
                                    Inserted::Verdict(held.with_left(held.ttl)),
                                    Some(Entry::Rrset(new)),
                                )
                            }
                            Merge::Replace => {
                                held.bound(&mut new, now);
                                let hit = new.with_left(new.ttl);
                                (
                                    Inserted::Stored(hit),
                                    Some(Entry::Rrset(std::mem::replace(held, new))),
                                )
                            }
                        }
                    }
                    (_, other) => (stored, other),
                }
            });
        self.metrics.inserted(&inserted, evicted);
        self.index(inserted.held());
        Ok(inserted)
    }

    /// Indexes what the cache holds of an NSEC or NSEC3 `RRset` judged secure, under the zone that signed it: the
    /// zone's apex is the signer of its signature (RFC 4035 §5.3.1), and the owner of an NSEC3 record is a hash one
    /// label below it (RFC 5155 §3).
    fn index(&self, held: &Ranked) {
        let set = &held.rrset;
        if held.checked != Checked::Secure || set.class() != Class::IN {
            return;
        }
        // The signer of every signature covering the set is the same: one that is not may be the extra signature of
        // a server, and the validator's verdict does not say which one it checked.
        let mut signers = set.rrsigs().iter().filter_map(|rdata| match rdata.data() {
            RData::Rrsig(sig) if sig.type_covered == set.rtype() => {
                Some(sig.signer.clone().into_owned())
            }
            _ => None,
        });
        let Some(apex) = signers.next() else {
            return;
        };
        if !set.owner().is_within(&apex) || signers.any(|other| other != apex) {
            return;
        }
        match set.rtype() {
            RecordType::NSEC => self
                .spans
                .add_nsec(&apex, &set.owner().clone().into_owned()),
            RecordType::NSEC3 => {
                let Some(hash) = hash_of(set.owner()) else {
                    return;
                };
                for rdata in set.rdatas() {
                    if let RData::Nsec3(nsec3) = rdata.data() {
                        if nsec3.hash_algorithm == Nsec3HashAlgorithm::SHA1
                            && nsec3.iterations <= MAX_ITERATIONS
                        {
                            self.spans
                                .add_nsec3(&apex, nsec3.salt(), nsec3.iterations, hash);
                        }
                        break;
                    }
                }
            }
            _ => {}
        }
    }

    /// Stores a negative answer for `owner`: the SOA of its zone and the `denials` proving it, as judged together
    /// (`checked`), for the least of the SOA's TTL and MINIMUM field (RFC 2308 §5), replacing one the cache
    /// holds as an `RRset` is replaced, so that secure data is never replaced by less (D199).
    ///
    /// # Errors
    ///
    /// [`NotCached`] when it is not stored: the SOA has no readable MINIMUM, or a TTL of 0, or the entry is too
    /// large; the cache is left as it was.
    pub fn insert_negative(
        &self,
        owner: &Name<'_>,
        kind: Kind,
        soa: &Ranked,
        denials: &[Ranked],
        checked: Checked,
        now: u32,
    ) -> Result<(), NotCached> {
        let ttl = crate::negative::lifetime(&self.config, soa, denials, checked)
            .ok_or(NotCached::ZeroTtl)?;
        let new = Absent::new(kind, soa, denials, checked, ttl, now);
        let mut key = [0; KEY_LEN];
        let key = key_of(
            &mut key,
            Some(NEGATIVE),
            owner,
            &[&u16::from(kind.key_type()).to_be_bytes()],
        );
        if key.len() + new.cost() > self.store.entry_limit() {
            return Err(NotCached::TooLarge);
        }
        let (_freed, evicted) =
            self.store
                .upsert(key, Entry::Absent(Box::new(new)), |entry, offered| {
                    match (entry, offered) {
                        (Entry::Absent(held), Some(Entry::Absent(new)))
                            if held.replaced_by(&new, now) =>
                        {
                            Some(Entry::Absent(std::mem::replace(held, new)))
                        }
                        (_, other) => other,
                    }
                });
        self.metrics.evicted(evicted);
        Ok(())
    }

    /// The fresh negative answer of `kind` for `owner` at `now`, with the time left as the TTL of each of its sets.
    #[must_use]
    pub fn negative(&self, owner: &Name<'_>, kind: Kind, now: u32) -> Option<Denied> {
        let mut key = [0; KEY_LEN];
        let key = key_of(
            &mut key,
            Some(NEGATIVE),
            owner,
            &[&u16::from(kind.key_type()).to_be_bytes()],
        );
        self.store.get(key, |held| match held {
            Entry::Absent(absent) => absent.hit(kind, now),
            _ => None,
        })
    }

    /// Which servers of the zone `zone` a failure is held for: the zone and the names of `servers`, whatever their
    /// order (D199).
    pub(crate) fn server_set<'n>(
        &self,
        zone: &Name<'_>,
        servers: impl IntoIterator<Item = &'n Name<'static>>,
    ) -> ServerSet {
        let one = |name: &Name<'_>| self.hasher.hash_one(name);
        ServerSet(
            servers
                .into_iter()
                .fold(one(zone), |set, name| set.wrapping_add(one(name))),
        )
    }

    /// Holds the failure of the question `name` and `qtype` to the servers `set`, heard at `now` (RFC 9520 §3.2): for
    /// [`Config::failure_min`] seconds, as long again for each failure heard after the hold ended, at most
    /// [`Config::failure_max`], starting over after a quiet spell as long as that (D43). A failure heard during the
    /// hold counts for nothing.
    pub(crate) fn hold(
        &self,
        name: &Name<'_>,
        qtype: RecordType,
        set: ServerSet,
        failure: Failure,
        now: u32,
    ) {
        let mut key = [0; KEY_LEN];
        let key = key_of(
            &mut key,
            Some(HOLD),
            name,
            &[&u16::from(qtype).to_be_bytes(), &set.bytes()],
        );
        let first = Entry::Held(Hold::first(failure, &self.config, now));
        let (_freed, evicted) = self.store.upsert(key, first, |entry, offered| {
            if let (Entry::Held(held), Some(_)) = (&mut *entry, &offered) {
                held.again(failure, &self.config, now);
            }
            offered
        });
        self.metrics.evicted(evicted);
    }

    /// The failure held for the question `name` and `qtype` to the servers `set` at `now`, if one is.
    pub(crate) fn held(
        &self,
        name: &Name<'_>,
        qtype: RecordType,
        set: ServerSet,
        now: u32,
    ) -> Option<Failure> {
        let mut key = [0; KEY_LEN];
        let key = key_of(
            &mut key,
            Some(HOLD),
            name,
            &[&u16::from(qtype).to_be_bytes(), &set.bytes()],
        );
        self.store.get(key, |held| match held {
            Entry::Held(held) => held.active(&self.config, now),
            _ => None,
        })
    }

    /// The index of spans of the secure NSEC and NSEC3 records held, for RFC 8198.
    pub(crate) const fn spans(&self) -> &Spans {
        &self.spans
    }

    /// The fresh `RRset` of `owner`, any case, `rtype` and `class` at `now`, whatever its rank: see [`Ranked`] for
    /// the ranks that may answer a client.
    #[must_use]
    pub fn get(
        &self,
        owner: &Name<'_>,
        rtype: RecordType,
        class: Class,
        now: u32,
    ) -> Option<Ranked> {
        let mut key = [0; KEY_LEN];
        let key = key_of(
            &mut key,
            None,
            owner,
            &[
                &u16::from(rtype).to_be_bytes(),
                &u16::from(class).to_be_bytes(),
            ],
        );
        let hit = self.store.get(key, |held| match held {
            Entry::Rrset(cached) => cached.hit(now),
            Entry::Absent(_) | Entry::Held(_) => None,
        });
        self.metrics.lookup(hit.is_some());
        hit
    }

    /// Number of entries, expired ones included until evicted or replaced.
    #[must_use]
    pub fn len(&self) -> usize {
        self.store.len()
    }

    /// Whether there is no entry.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.store.is_empty()
    }

    /// Bytes taken, the index of spans included, at most the capacity (D116).
    #[must_use]
    pub fn used(&self) -> usize {
        self.store.used() + self.spans.used()
    }

    /// The bytes it was made with: a reload keeps a cache of the same capacity and config (D195).
    #[must_use]
    pub const fn capacity(&self) -> usize {
        self.capacity
    }

    /// The TTL bounds and shards it was made with: a reply from it bounds its TTLs so (D195).
    #[must_use]
    pub const fn config(&self) -> &Config {
        &self.config
    }
}

/// The first byte of the key of a negative answer: past 63, the greatest length of a label, so that no name's wire
/// form starts with it.
const NEGATIVE: u8 = 0x80;

/// The first byte of the key of a failure held, apart from [`NEGATIVE`].
const HOLD: u8 = 0x81;

/// The longest key: a tag, a name, a type and the 8 bytes of a server set.
const KEY_LEN: usize = 1 + MAX_NAME_LEN + 2 + 8;

/// The key of `owner` in `buf`: the `tag` byte of a kind of entry other than an `RRset`, then the name's wire form,
/// ASCII letters lowered (RFC 4343; the length octets, at most 63, have none), then the `tail` parts: for an
/// `RRset`, its type and class; for a negative answer, its type, `ANY` for a name that does not exist; for a
/// failure held, the type and the server set.
fn key_of<'b>(
    buf: &'b mut [u8; KEY_LEN],
    tag: Option<u8>,
    owner: &Name<'_>,
    tail: &[&[u8]],
) -> &'b [u8] {
    let mut name = [0; MAX_NAME_LEN];
    let wire = owner.to_wire(&mut name);
    let mut at = 0;
    if let Some(tag) = tag {
        buf[0] = tag;
        at = 1;
    }
    let named = &mut buf[at..at + wire.len()];
    named.copy_from_slice(wire);
    named.make_ascii_lowercase();
    at += wire.len();
    for part in tail {
        buf[at..at + part.len()].copy_from_slice(part);
        at += part.len();
    }
    &buf[..at]
}
