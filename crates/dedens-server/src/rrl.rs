//! Response rate limiting (D113): a source that sends more queries than its rate over UDP gets TC=1, so that it
//! retries over TCP, or nothing, instead of the answers an attacker spoofing its address would aim at it.
//!
//! The scheme is that of BIND 9's `rate-limit` and Knot DNS's `rrl` module, simplified: the rate is per client
//! network, not per answer, so a spoofed flood cannot dodge it by varying the name. Each network, a /24 of IPv4
//! or a /56 of IPv6 by default, owns a token bucket in a fixed-size table. The table is indexed by a keyed hash of
//! the network, so an attacker neither picks a victim's bucket nor grows memory (D22, D58): networks that collide
//! share a bucket, which only makes the limit tighter for both.

use std::fmt;
use std::hash::{BuildHasher as _, RandomState};
use std::net::IpAddr;
use std::sync::atomic::{AtomicU64, Ordering};

use crate::access::{Access, Denial, Network};
use crate::budget::{Net, network};
use crate::metrics::Limited;

/// The most a bucket holds: its debt is 24 bits.
pub const MAX_BURST: u32 = 0x00FF_FFFF;

/// The most `slip` can be, as BIND 9 has it.
const MAX_SLIP: u8 = 10;

/// The most buckets: 2^24, 128 MiB.
const MAX_TABLE: usize = 1 << 24;

/// What the limit of one address family is.
///
/// Rates are of queries of one network, not of one address: the values of [`Config::default`] are those of Knot DNS,
/// 50 queries per second and 125 at once for an address, times its multiplier for the prefix, 32 for a /24 of IPv4
/// and 3 for a /56 of IPv6.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Rate {
    /// The length of the network that shares a bucket, in bits: 1 to 32 for IPv4, 1 to 128 for IPv6.
    pub prefix: u8,
    /// The queries per second a network may send for good: its bucket refills so fast.
    pub per_second: u32,
    /// The queries a quiet network may send at once: the size of the bucket, from `per_second` (the bucket refills
    /// by whole seconds, so a smaller one would hold the rate under `per_second`) to [`MAX_BURST`], 16 777 215.
    pub burst: u32,
}

/// The settings of a [`RateLimit`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Config {
    /// The limit of IPv4 sources. An IPv4-mapped IPv6 address counts as IPv4.
    pub ipv4: Rate,
    /// The limit of IPv6 sources.
    pub ipv6: Rate,
    /// Of the queries over the rate, one in `slip` is answered with TC=1 and the others dropped: 0 drops them all,
    /// 1 answers them all, as BIND 9's `slip`, at most 10. A spoofing attacker gains little from a truncated
    /// answer the size of its query, and the real client retries over TCP when it gets one.
    pub slip: u8,
    /// The buckets, 8 bytes each: rounded up to a power of two, at most 2^24. A bucket is shared by the networks
    /// whose hashes collide, so a table much smaller than the networks that talk to the server limits them as
    /// one.
    pub table: usize,
    /// Sources that are never limited, whose address a client cannot spoof from outside or whose queries come
    /// through a proxy that hides the client: loopback by default, as BIND 9's `exempt-clients` takes a list.
    pub exempt: Vec<Network>,
}

impl Default for Config {
    /// Knot DNS's defaults (`rate-limit` 50, `instant-limit` 125 per address, scaled by prefix in
    /// `src/knot/modules/rrl/functions.c`), with BIND 9's `slip` default of 2 and its prefix lengths of 24 and
    /// 56, over a table of 65 536 buckets, 512 KiB: D113.
    fn default() -> Self {
        Self {
            ipv4: Rate {
                prefix: 24,
                per_second: 1600,
                burst: 4000,
            },
            ipv6: Rate {
                prefix: 56,
                per_second: 150,
                burst: 375,
            },
            slip: 2,
            table: 1 << 16,
            exempt: ["127.0.0.0/8", "::1/128"]
                .into_iter()
                .map(|network| network.parse().expect("a loopback network"))
                .collect(),
        }
    }
}

/// A [`Config`] that does not make a limit.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum RateLimitError {
    /// A prefix length is 0 or longer than the address.
    #[error("the {family} prefix length is {prefix}, not 1 to {max}")]
    Prefix {
        /// `IPv4` or `IPv6`.
        family: &'static str,
        /// The length given.
        prefix: u8,
        /// The address length in bits.
        max: u8,
    },
    /// A rate is 0.
    #[error("the {0} rate per second is 0")]
    Rate(&'static str),
    /// A burst is below the rate or over 16 777 215.
    #[error("the {family} burst is {burst}, not {per_second} (the rate) to 16777215")]
    Burst {
        /// `IPv4` or `IPv6`.
        family: &'static str,
        /// The size given.
        burst: u32,
        /// The rate, the least a burst may be.
        per_second: u32,
    },
    /// The slip is over 10.
    #[error("the slip is {0}, not 0 to {MAX_SLIP}")]
    Slip(u8),
    /// The table is empty or over 2^24 buckets.
    #[error("the table has {0} buckets, not 1 to 16777216")]
    Table(usize),
}

/// What to do with a query (D113).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verdict {
    /// Within the rate: answer.
    Pass,
    /// Over the rate, one in `slip`: answer with TC=1, or BADCOOKIE with a Server Cookie when the query carried a
    /// Client Cookie (RFC 7873 §5.2.3).
    Slip,
    /// Over the rate: do not answer.
    Drop,
}

/// The rate limit of UDP queries by source network: a token bucket per network, in a table of fixed size.
pub struct RateLimit {
    /// What it was made with, for a reload to tell whether to keep it.
    config: Config,
    exempt: Access,
    hasher: RandomState,
    /// `len() - 1`, `len()` being a power of two.
    mask: u64,
    /// Each bucket: the second it was last used (low 32 bits), what it owes (next 24), the limited queries since
    /// the last slip (top 8). Zero is a bucket that never saw a query.
    buckets: Box<[AtomicU64]>,
    counted: Limited,
}

impl fmt::Debug for RateLimit {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RateLimit")
            .field("config", &self.config)
            .field("buckets", &self.buckets.len())
            .finish_non_exhaustive()
    }
}

impl RateLimit {
    /// A limit under `config`, with a hash key random to this process. Counts what [`RateLimit::check`] decides
    /// with the `metrics` facade's recorder installed now.
    ///
    /// # Errors
    ///
    /// [`RateLimitError`] when `config` is out of its bounds.
    ///
    /// # Panics
    ///
    /// Never: the table is at most 2^24 buckets, which fit a `u64`.
    pub fn new(config: Config) -> Result<Self, RateLimitError> {
        for (family, rate, max) in [("IPv4", config.ipv4, 32), ("IPv6", config.ipv6, 128)] {
            if !(1..=max).contains(&rate.prefix) {
                return Err(RateLimitError::Prefix {
                    family,
                    prefix: rate.prefix,
                    max,
                });
            }
            if rate.per_second == 0 {
                return Err(RateLimitError::Rate(family));
            }
            if !(rate.per_second..=MAX_BURST).contains(&rate.burst) {
                return Err(RateLimitError::Burst {
                    family,
                    burst: rate.burst,
                    per_second: rate.per_second,
                });
            }
        }
        if config.slip > MAX_SLIP {
            return Err(RateLimitError::Slip(config.slip));
        }
        if !(1..=MAX_TABLE).contains(&config.table) {
            return Err(RateLimitError::Table(config.table));
        }
        let len = config.table.next_power_of_two();
        Ok(Self {
            exempt: Access::new(config.exempt.iter().copied(), [], Denial::Drop),
            config,
            hasher: RandomState::new(),
            mask: u64::try_from(len - 1).expect("the table has at most 2^24 buckets"),
            buckets: (0..len).map(|_| AtomicU64::new(0)).collect(),
            counted: Limited::new(),
        })
    }

    /// The settings this limit was made with.
    #[must_use]
    pub const fn config(&self) -> &Config {
        &self.config
    }

    /// Whether `from` is on the exempt list ([`Config::exempt`]): a source whose queries are not limited by
    /// network, which the per-network budgets of validation and Oblivious `DoH` (D117) leave alone too.
    #[must_use]
    pub fn exempts(&self, from: IpAddr) -> bool {
        self.exempt.permits(from)
    }

    /// What to do with a UDP query from `from` at second `now` (the clock of the cache, D43), counted.
    ///
    /// `can_truncate` is whether a TC=1 answer exists on the transport: without it a slip is a drop, and the slip
    /// count stays. Exempt sources ([`Config::exempt`]) pass.
    ///
    /// # Panics
    ///
    /// Never: the index is masked below the table length, which is a `usize`.
    #[must_use]
    pub fn check(&self, from: IpAddr, now: u32, can_truncate: bool) -> Verdict {
        if self.exempt.permits(from) {
            return Verdict::Pass;
        }
        let key = network(from, self.config.ipv4.prefix, self.config.ipv6.prefix);
        let rate = match key {
            Net::V4(_) => self.config.ipv4,
            Net::V6(_) => self.config.ipv6,
        };
        let index = usize::try_from(self.hasher.hash_one(key) & self.mask)
            .expect("the mask is below the table length, a usize");
        let bucket = self
            .buckets
            .get(index)
            .expect("the index is masked below the table length");
        let slip = if can_truncate { self.config.slip } else { 0 };
        let mut verdict = Verdict::Pass;
        bucket.update(Ordering::Relaxed, Ordering::Relaxed, |word| {
            let (word, decided) = step(word, now, rate, slip);
            verdict = decided;
            word
        });
        self.counted.count(verdict);
        verdict
    }
}

/// The bucket `word` after a query at second `now`, and what to do with it.
///
/// The bucket owes one token per query it passed and refills `rate.per_second` tokens per second, so it passes
/// `burst` queries at once and `per_second` a second after. A limited query owes nothing: an attacker cannot dig a
/// debt that locks a network out longer than the flood lasts.
fn step(word: u64, now: u32, rate: Rate, slip: u8) -> (u64, Verdict) {
    let [l0, l1, l2, l3, d0, d1, d2, slips] = word.to_le_bytes();
    let last = u32::from_le_bytes([l0, l1, l2, l3]);
    let debt = u32::from_le_bytes([d0, d1, d2, 0]);
    let earned = u64::from(now.saturating_sub(last)) * u64::from(rate.per_second);
    let debt = u32::try_from(u64::from(debt).saturating_sub(earned))
        .expect("what is owed less what is earned is at most what was owed, 24 bits");
    // A clock that went back keeps the later second.
    let last = last.max(now);
    let (debt, slips, verdict) = if debt < rate.burst {
        (debt + 1, slips, Verdict::Pass)
    } else if slip != 0 && slips + 1 >= slip {
        (debt, 0, Verdict::Slip)
    } else {
        // Without a slip the count stays, and with one it is below `slip`, at most 10.
        (
            debt,
            if slip == 0 { slips } else { slips + 1 },
            Verdict::Drop,
        )
    };
    let [l0, l1, l2, l3] = last.to_le_bytes();
    let [d0, d1, d2, _] = debt.to_le_bytes();
    (
        u64::from_le_bytes([l0, l1, l2, l3, d0, d1, d2, slips]),
        verdict,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    const RATE: Rate = Rate {
        prefix: 24,
        per_second: 2,
        burst: 3,
    };

    fn run(slip: u8, queries: &[u32]) -> Vec<Verdict> {
        let mut word = 0;
        queries
            .iter()
            .map(|&now| {
                let (next, verdict) = step(word, now, RATE, slip);
                word = next;
                verdict
            })
            .collect()
    }

    #[test]
    fn a_burst_passes_then_the_rate_limits() {
        use Verdict::{Drop, Pass};
        assert_eq!(
            run(0, &[10, 10, 10, 10, 10]),
            [Pass, Pass, Pass, Drop, Drop]
        );
    }

    #[test]
    fn the_bucket_refills_per_second() {
        use Verdict::{Drop, Pass};
        // Two tokens come back a second on.
        assert_eq!(
            run(0, &[10, 10, 10, 10, 11, 11, 11]),
            [Pass, Pass, Pass, Drop, Pass, Pass, Drop]
        );
    }

    #[test]
    fn one_in_slip_is_answered() {
        use Verdict::{Drop, Pass, Slip};
        assert_eq!(
            run(2, &[5, 5, 5, 5, 5, 5, 5]),
            [Pass, Pass, Pass, Drop, Slip, Drop, Slip]
        );
        assert_eq!(run(1, &[5, 5, 5, 5, 5]), [Pass, Pass, Pass, Slip, Slip]);
    }

    #[test]
    fn a_clock_going_back_does_not_refill() {
        use Verdict::{Drop, Pass};
        assert_eq!(run(0, &[10, 10, 10, 9, 9]), [Pass, Pass, Pass, Drop, Drop]);
    }
}
