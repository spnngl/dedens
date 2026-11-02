//! Token buckets of work, one per client network, in a table of fixed size (D117).
//!
//! The table of D113's rate limit, for work instead of queries: each network, a /24 of IPv4 or a /48 of IPv6, owns a
//! bucket in a fixed-size table indexed by a keyed hash of the network, so an attacker neither picks a victim's
//! bucket nor grows memory (D22, D58); networks that collide share a bucket, which only makes the limit tighter for
//! both. A table of one bucket is a global one. Whoever spends work, a validation (D77) or a decapsulation (D79),
//! takes it from a bucket of its own network before the global allowance it comes out of, so that one client
//! cannot spend what all share.
//!
//! ```
//! use dedens_server::{Budget, Budgets, Slot};
//!
//! // Two units at once, one more a second.
//! let budgets = Budgets::new(Budget { per_second: 1, burst: 2, table: 1 << 10 })?;
//! let client = Slot::new("192.0.2.7".parse()?, true);
//! assert!(budgets.admit(client, 0) && budgets.admit(client, 0));
//! assert!(!budgets.admit(client, 0));
//! // The same /24, the same bucket; another network has its own.
//! assert!(!budgets.admit(Slot::new("192.0.2.200".parse()?, true), 0));
//! assert!(budgets.admit(Slot::new("198.51.100.7".parse()?, true), 0));
//! assert!(budgets.admit(client, 1));
//! # Ok::<(), Box<dyn std::error::Error>>(())
//! ```

use std::fmt;
use std::hash::{BuildHasher as _, RandomState};
use std::net::IpAddr;
use std::sync::atomic::{AtomicU64, Ordering};

/// The IPv4 prefix length of a client network: a /24, as D113's.
const IPV4_PREFIX: u8 = 24;

/// The IPv6 prefix length of a client network: a /48, the smallest block a site is given, where D113's rate
/// limit keys a /56: a holder of a /48 has 256 of those, and would have 256 buckets of work.
const IPV6_PREFIX: u8 = 48;

/// The most a bucket holds: its debt is at most twice that, which a 32-bit word keeps.
pub const MAX_BUDGET: u32 = 1 << 30;

/// The most buckets: 2^24, 128 MiB.
const MAX_TABLE: usize = 1 << 24;

/// The size and rate of the buckets of a [`Budgets`].
///
/// A bucket is spent in units of work, each worth what the caller says: a validation (D77) or a decapsulation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Budget {
    /// Units refilled each second by each bucket: the sustained rate of a network.
    pub per_second: u32,
    /// Units a bucket holds at most, and the debt it keeps at most (D106), up to [`MAX_BUDGET`]: what a quiet
    /// network may spend at once.
    pub burst: u32,
    /// The buckets, 8 bytes each: rounded up to a power of two, at most 2^24. A table much smaller than the
    /// networks that talk to the server limits them as one.
    pub table: usize,
}

/// A [`Budget`] that does not make a table.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum BudgetError {
    /// The burst is over [`MAX_BUDGET`].
    #[error("the burst is {0}, not 0 to {MAX_BUDGET}")]
    Burst(u32),
    /// The table is empty or over 2^24 buckets.
    #[error("the table has {0} buckets, not 1 to 16777216")]
    Table(usize),
}

/// A client network: its address under the prefix of its family.
#[derive(Debug, Clone, Copy, PartialEq, Eq, std::hash::Hash)]
pub(crate) enum Net {
    /// The first `ipv4` bits of an IPv4 address.
    V4(u32),
    /// The first `ipv6` bits of an IPv6 address.
    V6(u128),
}

/// The network of `from`, under `ipv4` or `ipv6` bits of prefix, 1 to the width of the family: what a table
/// keys by. An IPv4-mapped IPv6 address counts as IPv4. Shared with D113's rate limit, which has its own prefixes.
pub(crate) fn network(from: IpAddr, ipv4: u8, ipv6: u8) -> Net {
    // The shifts below are 0 to width - 1.
    match from.to_canonical() {
        IpAddr::V4(address) => Net::V4(u32::from(address) & (u32::MAX << (32 - u32::from(ipv4)))),
        IpAddr::V6(address) => {
            Net::V6(u128::from(address) & (u128::MAX << (128 - u32::from(ipv6))))
        }
    }
}

/// A client network's bucket: which one it is, by the network and whether its address is proven, for the charges
/// that follow an admission.
///
/// An address is proven when the client cannot have spoofed it (a connection, a valid Server Cookie, D113): it has a
/// bucket of its own, so that a flood from a spoofed source drains the bucket of the network's unproven queries
/// and not that of its proven ones.
#[derive(Debug, Clone, Copy, PartialEq, Eq, std::hash::Hash)]
pub struct Slot {
    net: Net,
    proven: bool,
}

impl Slot {
    /// The only bucket of a table of one.
    pub const ONLY: Self = Self {
        net: Net::V4(0),
        proven: false,
    };

    /// The bucket of the network of `from`, `proven` or not: an IPv4-mapped IPv6 address counts as IPv4.
    #[must_use]
    pub fn new(from: IpAddr, proven: bool) -> Self {
        Self {
            net: network(from, IPV4_PREFIX, IPV6_PREFIX),
            proven,
        }
    }
}

/// Token buckets of work by client network, in a table of fixed size.
pub struct Budgets {
    config: Budget,
    hasher: RandomState,
    /// `len() - 1`, `len()` being a power of two.
    mask: u64,
    /// Each bucket: the second it was last used (low 32 bits), what it owes (high 32): the burst less the units
    /// left, so that zero is a bucket that never was used, full.
    words: Box<[AtomicU64]>,
}

impl fmt::Debug for Budgets {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Budgets")
            .field("config", &self.config)
            .field("buckets", &self.words.len())
            .finish_non_exhaustive()
    }
}

impl Budgets {
    /// The buckets of `config`, with a hash key random to this process.
    ///
    /// # Errors
    ///
    /// [`BudgetError`] when `config` is out of its bounds.
    ///
    /// # Panics
    ///
    /// Never: the table is at most 2^24 buckets, which fit a `u64`.
    pub fn new(config: Budget) -> Result<Self, BudgetError> {
        if config.burst > MAX_BUDGET {
            return Err(BudgetError::Burst(config.burst));
        }
        if !(1..=MAX_TABLE).contains(&config.table) {
            return Err(BudgetError::Table(config.table));
        }
        let len = config.table.next_power_of_two();
        Ok(Self {
            config,
            hasher: RandomState::new(),
            mask: u64::try_from(len - 1).expect("the table has at most 2^24 buckets"),
            words: (0..len).map(|_| AtomicU64::new(0)).collect(),
        })
    }

    /// The settings these buckets were made with, for a reload to tell whether to keep them.
    #[must_use]
    pub const fn config(&self) -> Budget {
        self.config
    }

    /// The bucket of `slot`: the one of a table of one, else the one its keyed hash selects.
    fn word(&self, slot: Slot) -> &AtomicU64 {
        let index = if self.mask == 0 {
            0
        } else {
            usize::try_from(self.hasher.hash_one(slot) & self.mask)
                .expect("the mask is below the table length, a usize")
        };
        self.words
            .get(index)
            .expect("the index is masked below the table length")
    }

    /// Whether a unit of work may start at second `now`: some unit is left, after the refill, and is taken. The
    /// clock never goes back: a later second is kept, and the bucket is not refilled by the clock going forward
    /// again. A refusal that changes nothing writes nothing, so that a flood does not make the cores fight for the
    /// bucket's cache line.
    #[must_use]
    pub fn admit(&self, slot: Slot, now: u32) -> bool {
        let mut admitted = false;
        // An `Err` is a word left as it was.
        self.word(slot)
            .try_update(Ordering::Relaxed, Ordering::Relaxed, |word| {
                let (last, debt) = unpack(word);
                let earned = self
                    .config
                    .per_second
                    .saturating_mul(now.saturating_sub(last));
                let debt = debt.saturating_sub(earned);
                admitted = debt < self.config.burst;
                let next = pack(last.max(now), if admitted { debt + 1 } else { debt });
                (next != word).then_some(next)
            })
            .ok();
        admitted
    }

    /// Gives back the unit an [`admit`](Budgets::admit) took, for work that did not start.
    pub fn refund(&self, slot: Slot) {
        self.word(slot)
            .try_update(Ordering::Relaxed, Ordering::Relaxed, |word| {
                let (last, debt) = unpack(word);
                (debt > 0).then(|| pack(last, debt - 1))
            })
            .ok();
    }

    /// Whether work done left the bucket owing units: a query in this state asks no more questions (D106).
    #[must_use]
    pub fn in_debt(&self, slot: Slot) -> bool {
        let (_, debt) = unpack(self.word(slot).load(Ordering::Relaxed));
        debt > self.config.burst
    }

    /// Takes `units` of work done, down to a debt of one burst and no further (D106).
    pub fn charge(&self, slot: Slot, units: u32) {
        let floor = self.config.burst.saturating_mul(2);
        self.word(slot)
            .update(Ordering::Relaxed, Ordering::Relaxed, |word| {
                let (last, debt) = unpack(word);
                pack(last, debt.saturating_add(units).min(floor))
            });
    }
}

fn unpack(word: u64) -> (u32, u32) {
    let [l0, l1, l2, l3, d0, d1, d2, d3] = word.to_le_bytes();
    (
        u32::from_le_bytes([l0, l1, l2, l3]),
        u32::from_le_bytes([d0, d1, d2, d3]),
    )
}

fn pack(last: u32, debt: u32) -> u64 {
    let [l0, l1, l2, l3] = last.to_le_bytes();
    let [d0, d1, d2, d3] = debt.to_le_bytes();
    u64::from_le_bytes([l0, l1, l2, l3, d0, d1, d2, d3])
}

#[cfg(test)]
mod tests {
    use super::*;

    fn budgets(per_second: u32, burst: u32) -> Budgets {
        Budgets::new(Budget {
            per_second,
            burst,
            table: 1,
        })
        .expect("a table of one")
    }

    /// D106: the debt stops at one burst. 10 000 units admitted together, each then charged 256, would leave 2.5
    /// million units owed, 256 s of refill; the bucket admits again once `burst / per_second + 1` seconds have
    /// passed, and not before the debt is paid down to nothing.
    #[test]
    fn the_debt_of_a_flood_stops_at_one_burst() {
        let bucket = budgets(10_000, 20_000);
        let start = 1_000;
        assert!((0..10_000).all(|_| bucket.admit(Slot::ONLY, start)));
        for _ in 0..10_000 {
            bucket.charge(Slot::ONLY, 256);
        }
        assert!(!bucket.admit(Slot::ONLY, start));
        assert!(!bucket.admit(Slot::ONLY, start + 2));
        assert!(bucket.admit(Slot::ONLY, start + 3));
    }

    /// D106: the bucket is in debt once work done took more than it held, and not before.
    #[test]
    fn the_bucket_is_in_debt_only_below_zero() {
        let bucket = budgets(1, 10);
        assert!(bucket.admit(Slot::ONLY, 1));
        bucket.charge(Slot::ONLY, 9);
        assert!(!bucket.in_debt(Slot::ONLY));
        bucket.charge(Slot::ONLY, 1);
        assert!(bucket.in_debt(Slot::ONLY));
    }

    /// D106: a debt within the burst is kept whole, so that the clamp costs work that owes less nothing.
    #[test]
    fn a_debt_within_the_burst_is_repaid_as_owed() {
        let bucket = budgets(10, 100);
        assert!(bucket.admit(Slot::ONLY, 1));
        bucket.charge(Slot::ONLY, 150);
        // 100 - 1 - 150 = -51: five seconds repay 50, which leaves a unit owed; a sixth admits.
        assert!(!bucket.admit(Slot::ONLY, 6));
        assert!(bucket.admit(Slot::ONLY, 7));
    }

    /// A burst of 0 admits nothing: a bucket may be made to shed all.
    #[test]
    fn an_empty_bucket_admits_nothing() {
        let bucket = budgets(1_000, 0);
        assert!(!bucket.admit(Slot::ONLY, 1_000_000));
    }

    /// A clock that goes back repays nothing and does not make the next second refill again.
    #[test]
    fn the_clock_never_goes_back() {
        let bucket = budgets(1, 1);
        assert!(bucket.admit(Slot::ONLY, 100));
        assert!(!bucket.admit(Slot::ONLY, 50));
        assert!(!bucket.admit(Slot::ONLY, 100));
        assert!(bucket.admit(Slot::ONLY, 101));
    }

    /// A refund gives the unit back, and no more than was taken.
    #[test]
    fn a_refund_gives_the_unit_back() {
        let bucket = budgets(1, 1);
        assert!(bucket.admit(Slot::ONLY, 5));
        assert!(!bucket.admit(Slot::ONLY, 5));
        bucket.refund(Slot::ONLY);
        assert!(bucket.admit(Slot::ONLY, 5));
        bucket.refund(Slot::ONLY);
        bucket.refund(Slot::ONLY);
        assert!(bucket.admit(Slot::ONLY, 5));
        assert!(!bucket.admit(Slot::ONLY, 5));
    }

    /// A refused unit writes nothing: the word is as it was, whatever the clock says.
    #[test]
    fn a_refusal_leaves_the_word_as_it_was() {
        let bucket = budgets(1, 1);
        assert!(bucket.admit(Slot::ONLY, 5));
        let before = bucket.words[0].load(Ordering::Relaxed);
        assert!(!bucket.admit(Slot::ONLY, 5));
        assert!(!bucket.admit(Slot::ONLY, 3));
        assert_eq!(bucket.words[0].load(Ordering::Relaxed), before);
    }

    /// The bucket is shared by the addresses of a /24 of IPv4 and of a /48 of IPv6, and not by others; an
    /// IPv4-mapped address is the IPv4 one; a proven address has a bucket of its own.
    #[test]
    fn a_network_shares_a_bucket() {
        let slot = |text: &str| Slot::new(text.parse().expect("an address"), true);
        assert_eq!(slot("192.0.2.1"), slot("192.0.2.254"));
        assert_ne!(slot("192.0.2.1"), slot("192.0.3.1"));
        assert_eq!(slot("192.0.2.1"), slot("::ffff:192.0.2.9"));
        assert_eq!(slot("2001:db8:1:ff::1"), slot("2001:db8:1:ffff:ffff::1"));
        assert_ne!(slot("2001:db8:1:ff::1"), slot("2001:db8:2:ff::1"));
        assert_ne!(
            slot("192.0.2.1"),
            Slot::new("192.0.2.1".parse().expect("an address"), false)
        );
    }

    #[test]
    fn a_table_is_bounded() {
        let config = |burst, table| Budget {
            per_second: 1,
            burst,
            table,
        };
        assert_eq!(
            Budgets::new(config(MAX_BUDGET + 1, 1)).unwrap_err(),
            BudgetError::Burst(MAX_BUDGET + 1)
        );
        assert_eq!(
            Budgets::new(config(1, 0)).unwrap_err(),
            BudgetError::Table(0)
        );
        assert_eq!(
            Budgets::new(config(1, (1 << 24) + 1)).unwrap_err(),
            BudgetError::Table((1 << 24) + 1)
        );
    }
}
