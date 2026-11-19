//! The `RRset` cache: what the resolver learned, `RRset` by `RRset`, with how far it trusts each (RFC 2181 §5.4.1).

use std::cmp::Ordering;
use std::sync::Arc;

use dedens_cache::{Checked, Config, ConfigError, Cost, Store};
use dedens_proto::{Class, MAX_NAME_LEN, Name, RecordType, Ttl};
use thiserror::Error;

use crate::metrics::Metrics;
use crate::rank::Rank;
use crate::rrset::Rrset;

/// The default capacity, in bytes: twice the response cache's 64 MiB default, as Unbound's performance guide sets
/// `rrset-cache-size` to twice `msg-cache-size` (its defaults are 4 MiB each, `util/config_file.c`
/// `config_create`, small for a busy resolver). BIND has no separate budget: its `max-cache-size`, 90 % of memory by
/// default, holds every cache of a view.
pub const DEFAULT_CAPACITY: usize = 128 << 20;

/// An `RRset` and its trust: as the cache holds it, fresh, or as a resolution read it from a response.
///
/// Only an `RRset` of [`Rank::AnswerNonAuthoritative`] or above, or proved [`Checked::Secure`], may answer a
/// client's question: the lesser ranks are the additional sections and the authority section of a
/// non-authoritative answer, which RFC 2181 §5.4.1 keeps from ever being returned as answers ("Ignoring this would
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
    /// [`Rrset::ttl`], the TTL they were received with, but for an `RRset` just read from a response.
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

/// The value of a key: an `RRset` now; the negative entries of step 12 come into the same key space.
#[derive(Debug)]
enum Entry {
    Rrset(Cached),
}

impl Cost for Entry {
    fn cost(&self) -> usize {
        match self {
            Self::Rrset(cached) => cached.rrset.cost(),
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
    config: Config,
    metrics: Metrics,
}

impl RrsetCache {
    /// An empty cache of `capacity` bytes, the shards, entry limit and TTLs of `config`, the response cache's.
    ///
    /// # Errors
    ///
    /// [`ConfigError`] when `config` is invalid, its `capacity`, the response cache's, included; then when
    /// `capacity` cannot hold an entry of `config.max_entry_bytes`, or a tenth of a shard's share an entry of the
    /// longest owner name (D116).
    pub fn new(capacity: usize, config: Config) -> Result<Self, ConfigError> {
        config.validate()?;
        Ok(Self {
            store: Store::new(capacity, config.shards, config.max_entry_bytes, KEY_LEN)?,
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
        let key = key_of(&mut key, rrset.owner(), rrset.rtype(), rrset.class());
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
        // What the shard lets go of, the `RRset` offered or the one it replaces, is freed once its lock is released.
        let ((inserted, _freed), evicted) =
            self.store.upsert(key, Entry::Rrset(new), |held, offered| {
                let Entry::Rrset(held) = held;
                let Some(Entry::Rrset(mut new)) = offered else {
                    return (Inserted::Stored(held.with_left(held.ttl)), None);
                };
                match held.merge(&new, now) {
                    Merge::Keep => (Inserted::Kept(held.with_left(held.left(now))), Some(new)),
                    Merge::Verdict => {
                        if !held.pins(&new) {
                            held.rank = held.rank.max(new.rank);
                        }
                        held.checked = new.checked;
                        held.set_left(held.left(now).min(new.ttl), now);
                        (Inserted::Verdict(held.with_left(held.ttl)), Some(new))
                    }
                    Merge::Replace => {
                        held.bound(&mut new, now);
                        let hit = new.with_left(new.ttl);
                        (Inserted::Stored(hit), Some(std::mem::replace(held, new)))
                    }
                }
            });
        self.metrics.inserted(&inserted, evicted);
        Ok(inserted)
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
        let key = key_of(&mut key, owner, rtype, class);
        let hit = self.store.get(key, |held| match held {
            Entry::Rrset(cached) => cached.hit(now),
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

    /// Bytes taken, at most the capacity (D116).
    #[must_use]
    pub fn used(&self) -> usize {
        self.store.used()
    }

    /// The TTL bounds and shards it was made with: a reply from it bounds its TTLs so (D195).
    #[must_use]
    pub const fn config(&self) -> &Config {
        &self.config
    }
}

/// The longest key: a name, a type and a class.
const KEY_LEN: usize = MAX_NAME_LEN + 4;

/// The key of `owner`, `rtype` and `class` in `buf`: the name's wire form, ASCII letters lowered (RFC 4343; the
/// length octets, at most 63, have none), then the type and the class.
fn key_of<'b>(
    buf: &'b mut [u8; KEY_LEN],
    owner: &Name<'_>,
    rtype: RecordType,
    class: Class,
) -> &'b [u8] {
    let mut name = [0; MAX_NAME_LEN];
    let wire = owner.to_wire(&mut name);
    let len = wire.len();
    buf[..len].copy_from_slice(wire);
    buf[..len].make_ascii_lowercase();
    buf[len..len + 2].copy_from_slice(&u16::from(rtype).to_be_bytes());
    buf[len + 2..len + 4].copy_from_slice(&u16::from(class).to_be_bytes());
    &buf[..len + 4]
}
