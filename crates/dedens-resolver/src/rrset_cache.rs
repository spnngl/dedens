//! The `RRset` cache: what the resolver learned, `RRset` by `RRset`, with how far it trusts each (RFC 2181 §5.4.1).

use std::sync::Arc;

use dedens_cache::{Checked, Config, ConfigError, Cost, Store};
use dedens_proto::{Class, MAX_NAME_LEN, Name, RecordType, Section, Ttl};
use thiserror::Error;

use crate::metrics::Metrics;
use crate::rrset::Rrset;

/// The default capacity, in bytes: twice the response cache's 64 MiB default, as Unbound's performance guide sets
/// `rrset-cache-size` to twice `msg-cache-size` (its defaults are 4 MiB each, `util/config_file.c`
/// `config_create`, small for a busy resolver). BIND has no separate budget: its `max-cache-size`, 90 % of memory by
/// default, holds every cache of a view.
pub const DEFAULT_CAPACITY: usize = 128 << 20;

/// How far an `RRset` is trusted, from where it was read: RFC 2181 §5.4.1, least trusted first, so that a greater
/// rank replaces a lesser one.
///
/// The RFC puts the additional section of an authoritative answer and the authority and additional sections of a
/// non-authoritative one at one level; they are three here, as in Unbound (`rrset_trust`): authoritative data first,
/// then the authority section over the additional. The ranks of zone data (a primary zone, a transfer, their glue)
/// are not here: the resolver holds no zone. Data a validator proved secure is trusted above every rank (RFC 2181
/// §5.4.1: "Unauthenticated RRs received and cached from the least trustworthy of those groupings [...] should not
/// be cached in preference to authenticated data"), which [`Checked::Secure`] says.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Rank {
    /// The additional section of a non-authoritative answer, such as the glue of a referral.
    AdditionalNonAuthoritative,
    /// The authority section of a non-authoritative answer, such as the NS records of a referral.
    AuthorityNonAuthoritative,
    /// The additional section of an authoritative answer.
    AdditionalAuthoritative,
    /// The answer section of a non-authoritative answer, and the data of an authoritative answer the server is not
    /// authoritative for: the records of a CNAME chain past the first name.
    AnswerNonAuthoritative,
    /// The authority section of an authoritative answer.
    AuthorityAuthoritative,
    /// The answer section of an authoritative answer, at the name asked.
    AnswerAuthoritative,
}

impl Rank {
    /// The rank of the records of `section` in an answer whose AA bit is `authoritative` (RFC 1035 §4.1.1). The
    /// answer section of an authoritative answer is only [`Rank::AnswerAuthoritative`] at the name the server is
    /// authoritative for: the caller ranks the rest of a CNAME chain [`Rank::AnswerNonAuthoritative`].
    #[must_use]
    pub const fn of(section: Section, authoritative: bool) -> Self {
        match (section, authoritative) {
            (Section::Answer, true) => Self::AnswerAuthoritative,
            (Section::Authority, true) => Self::AuthorityAuthoritative,
            (Section::Answer, false) => Self::AnswerNonAuthoritative,
            (Section::Additional, true) => Self::AdditionalAuthoritative,
            (Section::Authority, false) => Self::AuthorityNonAuthoritative,
            (Section::Additional, false) => Self::AdditionalNonAuthoritative,
        }
    }
}

/// An `RRset` the cache holds, fresh, and what it knows of it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Hit {
    /// The records, shared with the cache.
    pub rrset: Arc<Rrset>,
    /// Where they were read.
    pub rank: Rank,
    /// What the validator found of them.
    pub checked: Checked,
    /// What is left of their time in the cache, which a reply gives as their TTL (RFC 1035 §4.1.3).
    pub ttl: Ttl,
}

/// Why an `RRset` was not stored.
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

impl Cached {
    /// The seconds left at `now`, 0 once expired; never more than it was stored for, whichever way the clock goes.
    fn left(&self, now: u32) -> u32 {
        self.expires.saturating_sub(now).min(self.ttl)
    }

    /// The trust that decides a replacement: secure data above any rank (RFC 2181 §5.4.1), then the rank.
    fn trust(&self) -> (bool, Rank) {
        (self.checked == Checked::Secure, self.rank)
    }

    /// The entry as a hit at `now`, if fresh.
    fn hit(&self, now: u32) -> Option<Hit> {
        match self.left(now) {
            0 => None,
            left => Some(self.with_left(left)),
        }
    }

    fn with_left(&self, left: u32) -> Hit {
        Hit {
            rrset: Arc::clone(&self.rrset),
            rank: self.rank,
            checked: self.checked,
            ttl: Ttl::from_wire(left),
        }
    }

    /// Whether `new` replaces this entry at `now`, as Unbound decides it (`need_to_update_rrset`): an expired entry
    /// gives way to anything; else more trusted data replaces it, and so does other data of equal trust, the last
    /// heard of; bogus data gives way to any other data not bogus. More trusted data equal to bogus data does not
    /// replace it, which would lengthen its life (RFC 4035 §4.7 bounds it).
    fn replaced_by(&self, new: &Cached, now: u32) -> bool {
        if self.left(now) == 0 {
            return true;
        }
        let same = self.rrset == new.rrset;
        let bogus = |checked| matches!(checked, Checked::Bogus(_));
        match new.trust().cmp(&self.trust()) {
            std::cmp::Ordering::Greater => {
                !(same && bogus(self.checked) && new.checked != Checked::Secure)
            }
            std::cmp::Ordering::Equal => !same,
            std::cmp::Ordering::Less => !same && bogus(self.checked) && !bogus(new.checked),
        }
    }
}

/// `RRsets` under their owner name, type and class (RFC 2181 §5), shared by threads, within a byte budget.
///
/// The store is `dedens-cache`'s (D116, D193): sharded, each shard behind its own lock held for one call (never
/// across an `.await`), S3-FIFO eviction, everything a shard holds counted against its share of the capacity; an
/// [`Rrset`] a [`Hit`] still holds after its entry was evicted is the caller's. TTLs follow the response cache's
/// [`Config`] (D124), one source for both: [`Config::lifetime`]. Time comes in as seconds from the caller.
#[derive(Debug)]
pub struct RrsetCache {
    store: Store<Option<Entry>>,
    config: Config,
    metrics: Metrics,
}

impl RrsetCache {
    /// An empty cache of `capacity` bytes, the shards, entry limit and TTLs of `config`, the response cache's.
    ///
    /// # Errors
    ///
    /// [`ConfigError`] when `config` is invalid, or `capacity` too small for its shards and entry limit (D116).
    pub fn new(capacity: usize, config: Config) -> Result<Self, ConfigError> {
        config.validate()?;
        Ok(Self {
            store: Store::new(capacity, config.shards, config.max_entry_bytes)?,
            config,
            metrics: Metrics::new(),
        })
    }

    /// Stores `rrset`, read at `rank` and `checked` so, at `now`, unless the cache holds an `RRset` of the same
    /// key it trusts more (RFC 2181 §5.4.1, [`Rank`]). Returns what the cache holds after: `rrset` or the one kept.
    ///
    /// Its time in the cache is [`Config::lifetime`]. An NS `RRset` that replaces one not expired lives no longer
    /// than the one it replaces: a delegation is only renewed from its parent once expired, so a name its
    /// registry deleted does not live on (the ghost domain names of Jiang et al., NDSS 2012; Unbound does the same).
    ///
    /// # Errors
    ///
    /// [`NotCached`] when `rrset` is not stored: the cache is left as it was.
    pub fn insert(
        &self,
        rrset: Rrset,
        rank: Rank,
        checked: Checked,
        now: u32,
    ) -> Result<Hit, NotCached> {
        let ttl = self
            .config
            .lifetime(rrset.ttl(), checked)
            .ok_or(NotCached::ZeroTtl)?;
        let mut key = [0; KEY_LEN];
        let key = key_of(&mut key, rrset.owner(), rrset.rtype(), rrset.class());
        if key.len() + rrset.cost() > self.store.entry_limit() {
            return Err(NotCached::TooLarge);
        }
        let ns = rrset.rtype() == RecordType::NS;
        let mut new = Cached {
            rrset: Arc::new(rrset),
            rank,
            checked,
            ttl,
            expires: now.saturating_add(ttl),
        };
        let ((hit, stored), evicted) = self.store.update(key, |held| {
            if let Some(Entry::Rrset(cached)) = held {
                let left = cached.left(now);
                if !cached.replaced_by(&new, now) {
                    // Not expired, or it would have been replaced.
                    return (cached.with_left(left), false);
                }
                if ns && left > 0 {
                    new.ttl = new.ttl.min(left);
                    new.expires = now.saturating_add(new.ttl);
                }
            }
            let hit = new.with_left(new.ttl);
            *held = Some(Entry::Rrset(new));
            (hit, true)
        });
        self.metrics.inserted(stored, evicted);
        Ok(hit)
    }

    /// The fresh `RRset` of `owner`, any case, `rtype` and `class` at `now`.
    #[must_use]
    pub fn get(&self, owner: &Name<'_>, rtype: RecordType, class: Class, now: u32) -> Option<Hit> {
        let mut key = [0; KEY_LEN];
        let key = key_of(&mut key, owner, rtype, class);
        let hit = self.store.get(key, |held| match held {
            Some(Entry::Rrset(cached)) => cached.hit(now),
            None => None,
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
