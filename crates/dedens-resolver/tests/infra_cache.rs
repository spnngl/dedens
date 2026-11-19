//! The infra cache on the root servers' addresses (`dedens-roots`' bundled hints): RFC 6298 §2 (round-trip time
//! and timeout), §5.5 and §5.7 (backing off, and after); RFC 4697 §2.2.1 (lame servers per zone); RFC 5452 §4.4 (a
//! random server within the band); RFC 6891 §7 (EDNS kept once seen); D116 (byte budget), D194.

use std::convert::Infallible;
use std::net::{IpAddr, Ipv6Addr, SocketAddr};
use std::time::Duration;

use dedens_cache::ConfigError;
use dedens_proto::{Name, Rcode};
use dedens_resolver::{Choice, Edns, InfraCache, Marks};
use dedens_roots::RootHints;
use rand_core::{TryCryptoRng, TryRng};

/// `SplitMix64` from a fixed seed, so that a draw replays: a CSPRNG by marker only, for tests.
pub(crate) struct Seeded(pub(crate) u64);

impl TryRng for Seeded {
    type Error = Infallible;

    fn try_next_u32(&mut self) -> Result<u32, Infallible> {
        Ok(u32::try_from(self.try_next_u64()? >> 32).unwrap_or_default())
    }

    fn try_next_u64(&mut self) -> Result<u64, Infallible> {
        self.0 = self.0.wrapping_add(0x9e37_79b9_7f4a_7c15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
        Ok(z ^ (z >> 31))
    }

    fn try_fill_bytes(&mut self, dst: &mut [u8]) -> Result<(), Infallible> {
        for chunk in dst.chunks_mut(8) {
            let word = self.try_next_u64()?.to_le_bytes();
            chunk.copy_from_slice(&word[..chunk.len()]);
        }
        Ok(())
    }
}

impl TryCryptoRng for Seeded {}

const MS: Duration = Duration::from_millis(1);
/// Time enough for any timeout.
const LONG: Duration = Duration::from_secs(600);
/// Draws per test of a spread: enough that a server never drawn is not chance.
const DRAWS: usize = 3000;

fn cache() -> InfraCache {
    InfraCache::new(InfraCache::DEFAULT_CAPACITY, 64).expect("a valid size")
}

/// The IPv4 addresses of the root servers, A to M, port 53.
fn roots() -> Vec<SocketAddr> {
    RootHints::bundled()
        .servers()
        .iter()
        .flat_map(|server| server.ipv4().iter().copied())
        .map(|ip| SocketAddr::new(IpAddr::V4(ip), 53))
        .collect()
}

fn root() -> Name<'static> {
    Name::root()
}

fn name(text: &str) -> Name<'static> {
    text.parse().expect("a valid name")
}

fn select(cache: &InfraCache, servers: &[SocketAddr], now: u32) -> Option<Choice> {
    cache.select(servers, &root(), LONG, now, &mut Seeded(7))
}

/// The timeout `server` is asked with, alone.
fn timeout(cache: &InfraCache, server: SocketAddr, now: u32) -> Duration {
    select(cache, &[server], now).expect("not skipped").timeout
}

/// How many of `DRAWS` draws among `servers` for `zone` each server got, in their order.
fn spread(cache: &InfraCache, servers: &[SocketAddr], zone: &Name<'_>, now: u32) -> Vec<usize> {
    let mut rng = Seeded(1);
    let mut drawn = vec![0; servers.len()];
    for _ in 0..DRAWS {
        let choice = cache
            .select(servers, zone, LONG, now, &mut rng)
            .expect("a server");
        let at = servers
            .iter()
            .position(|&s| s == choice.server)
            .expect("one of them");
        drawn[at] += 1;
    }
    drawn
}

#[test]
fn rfc6298_2_2_unknown_then_first_measurement() {
    let cache = cache();
    let [a, ..] = roots()[..] else {
        panic!("13 roots")
    };
    assert_eq!(timeout(&cache, a, 0), InfraCache::UNKNOWN_TIMEOUT);
    // SRTT = R, RTTVAR = R/2, RTO = SRTT + 4 RTTVAR.
    cache.reply(a, 20 * MS, Marks::default(), 0);
    assert_eq!(timeout(&cache, a, 0), 60 * MS);
}

#[test]
fn rfc6298_2_3_smoothed() {
    let cache = cache();
    let [a, ..] = roots()[..] else {
        panic!("13 roots")
    };
    cache.reply(a, 100 * MS, Marks::default(), 0);
    cache.reply(a, 200 * MS, Marks::default(), 0);
    // RTTVAR = 3/4 * 50 + 1/4 * |100 - 200| = 62; SRTT = 7/8 * 100 + 1/8 * 200 = 112; RTO = 112 + 4 * 62.
    assert_eq!(timeout(&cache, a, 0), 360 * MS);
}

#[test]
fn rfc6298_2_4_least_timeout() {
    let cache = cache();
    let [a, ..] = roots()[..] else {
        panic!("13 roots")
    };
    for _ in 0..50 {
        cache.reply(a, 2 * MS, Marks::default(), 0);
    }
    assert_eq!(timeout(&cache, a, 0), InfraCache::MIN_TIMEOUT);
}

#[test]
fn timeout_within_the_time_left() {
    let cache = cache();
    let [a, ..] = roots()[..] else {
        panic!("13 roots")
    };
    let choice = cache
        .select(&[a], &root(), 30 * MS, 0, &mut Seeded(7))
        .expect("a server");
    assert_eq!(choice.timeout, 30 * MS);
}

#[test]
fn rfc6298_5_5_back_off_skip_and_probe() {
    let cache = cache();
    let [a, ..] = roots()[..] else {
        panic!("13 roots")
    };
    let mut sent = timeout(&cache, a, 0);
    for _ in 0..InfraCache::TIMEOUT_LIMIT - 1 {
        cache.timeout(a, sent, 0);
        assert_eq!(timeout(&cache, a, 0), sent * 2, "doubled");
        sent *= 2;
    }
    cache.timeout(a, sent, 0);
    // Skipped until its timeout, 3.008 s, has passed: probed at 4 s.
    assert_eq!(select(&cache, &[a], 0), None);
    assert_eq!(select(&cache, &[a], 3), None);
    let probe = select(&cache, &[a], 4).expect("probed");
    assert_eq!(probe.timeout, sent * 2);
    // RFC 6298 §5.7: the answer to the probe starts the estimate anew.
    cache.reply(a, 30 * MS, Marks::default(), 4);
    assert_eq!(timeout(&cache, a, 4), 90 * MS);
}

#[test]
fn rfc6298_5_7_estimate_restarted_after_backing_off() {
    let cache = cache();
    let [a, ..] = roots()[..] else {
        panic!("13 roots")
    };
    cache.reply(a, 100 * MS, Marks::default(), 0);
    for _ in 0..InfraCache::TIMEOUT_LIMIT {
        cache.timeout(a, timeout(&cache, a, 0), 0);
    }
    // As a first measurement, not smoothed into the old 100 ms (which would give 311 ms).
    cache.reply(a, 30 * MS, Marks::default(), 5);
    assert_eq!(timeout(&cache, a, 5), 90 * MS);
}

#[test]
fn rfc6298_5_5_queries_in_flight_back_off_once() {
    let cache = cache();
    let [a, ..] = roots()[..] else {
        panic!("13 roots")
    };
    let sent = timeout(&cache, a, 0);
    cache.timeout(a, sent, 0);
    cache.timeout(a, sent, 0);
    assert_eq!(timeout(&cache, a, 0), sent * 2);
    // An answer since brought it under the timeout sent: kept.
    cache.reply(a, 20 * MS, Marks::default(), 0);
    cache.timeout(a, sent, 0);
    assert_eq!(timeout(&cache, a, 0), 60 * MS);
}

#[test]
fn rfc6298_5_5_most_timeout() {
    let cache = cache();
    let [a, ..] = roots()[..] else {
        panic!("13 roots")
    };
    let mut now = 0;
    for _ in 0..20 {
        let sent = select(&cache, &[a], now).map_or(InfraCache::MAX_TIMEOUT, |c| c.timeout);
        cache.timeout(a, sent, now);
        now += 200;
    }
    assert_eq!(timeout(&cache, a, now), InfraCache::MAX_TIMEOUT);
}

#[test]
fn every_server_skipped_is_none() {
    let cache = cache();
    let roots = roots();
    for &server in &roots {
        for _ in 0..InfraCache::TIMEOUT_LIMIT {
            cache.timeout(server, InfraCache::UNKNOWN_TIMEOUT, 0);
        }
    }
    assert_eq!(select(&cache, &roots, 0), None);
    // One left: chosen whatever its time.
    let m = *roots.last().expect("13 roots");
    cache.reply(m, 5 * InfraCache::MAX_TIMEOUT, Marks::default(), 0);
    assert_eq!(select(&cache, &roots, 0).map(|c| c.server), Some(m));
}

#[test]
fn rfc5452_4_4_random_within_the_band() {
    let cache = cache();
    let [a, b, c, d, ..] = roots()[..] else {
        panic!("13 roots")
    };
    cache.reply(a, 20 * MS, Marks::default(), 0); // 60 ms
    cache.reply(b, 100 * MS, Marks::default(), 0); // 300 ms
    cache.reply(c, 1000 * MS, Marks::default(), 0); // 3 s, out of the band
    // d not heard: 376 ms, in the band, so asked.
    let drawn = spread(&cache, &[a, b, c, d], &root(), 0);
    assert_eq!(drawn[2], 0, "{drawn:?}");
    for at in [0, 1, 3] {
        assert!(drawn[at] > DRAWS / 4, "{drawn:?}");
    }
}

#[test]
fn band_edge() {
    let cache = cache();
    let [a, b, c, ..] = roots()[..] else {
        panic!("13 roots")
    };
    cache.reply(a, 100 * MS, Marks::default(), 0); // 300 ms
    // Not heard, backed off from what was sent: 700 ms, the band's edge, and 702 ms past it.
    cache.timeout(b, 350 * MS, 0);
    cache.timeout(c, 351 * MS, 0);
    assert_eq!(timeout(&cache, b, 0), 300 * MS + InfraCache::BAND);
    let drawn = spread(&cache, &[a, b, c], &root(), 0);
    assert!(drawn[1] > DRAWS / 3, "{drawn:?}");
    assert_eq!(drawn[2], 0, "{drawn:?}");
}

#[test]
fn rfc4697_2_2_1_lame_for_its_zone_only() {
    let cache = cache();
    let [a, b, ..] = roots()[..] else {
        panic!("13 roots")
    };
    let zone = name("example.");
    cache.lame(a, &zone, 0);
    assert_eq!(spread(&cache, &[a, b], &zone, 0)[0], 0);
    // Lame for the zone, not for a subzone or another zone, nor in another case (RFC 4343).
    assert!(spread(&cache, &[a, b], &name("sub.example."), 0)[0] > DRAWS / 3);
    assert!(spread(&cache, &[a, b], &name("example.net."), 0)[0] > DRAWS / 3);
    assert_eq!(spread(&cache, &[a, b], &name("EXAMPLE."), 0)[0], 0);
    // Nor once its time is out.
    assert_eq!(
        spread(&cache, &[a, b], &zone, InfraCache::LAME_TTL - 1)[0],
        0
    );
    assert!(spread(&cache, &[a, b], &zone, InfraCache::LAME_TTL)[0] > DRAWS / 3);
}

#[test]
fn rfc4697_2_2_1_every_server_lame_is_asked() {
    let cache = cache();
    let [a, b, ..] = roots()[..] else {
        panic!("13 roots")
    };
    let zone = name("example.");
    cache.lame(a, &zone, 0);
    cache.lame(b, &zone, 0);
    let drawn = spread(&cache, &[a, b], &zone, 0);
    assert!(drawn.iter().all(|&n| n > DRAWS / 3), "{drawn:?}");
}

/// A server that answered FORMERR to EDNS and NOERROR without it, as the transport says (D190).
const UNSUPPORTED: Edns = Edns::Unsupported {
    rejected: Rcode::FORMERR,
    answered: Rcode::NOERROR,
};

#[test]
fn rfc6891_7_edns_kept_once_seen() {
    let cache = cache();
    let [a, b, ..] = roots()[..] else {
        panic!("13 roots")
    };
    let marks = |edns| Marks {
        edns,
        ..Marks::default()
    };
    cache.reply(a, 20 * MS, marks(Edns::Supported), 0);
    cache.reply(a, 20 * MS, marks(UNSUPPORTED), 0);
    cache.reply(a, 20 * MS, marks(Edns::Unknown), 0);
    assert_eq!(
        select(&cache, &[a], 0).map(|c| c.marks.edns),
        Some(Edns::Supported)
    );
    cache.reply(b, 20 * MS, marks(UNSUPPORTED), 0);
    cache.reply(b, 20 * MS, marks(Edns::Unknown), 0);
    assert_eq!(
        select(&cache, &[b], 0).map(|c| c.marks.edns),
        Some(UNSUPPORTED)
    );
    cache.reply(b, 20 * MS, marks(Edns::Supported), 0);
    assert_eq!(
        select(&cache, &[b], 0).map(|c| c.marks.edns),
        Some(Edns::Supported)
    );
}

#[test]
fn marks_stay_until_the_entry_expires() {
    let cache = cache();
    let [a, ..] = roots()[..] else {
        panic!("13 roots")
    };
    let seen = Marks {
        edns: UNSUPPORTED,
        no_case: true,
        tcp: true,
    };
    cache.reply(a, 20 * MS, seen, 0);
    // A later answer that shows none of them keeps them, and does not renew the entry.
    cache.reply(a, 20 * MS, Marks::default(), 100);
    let last = InfraCache::SERVER_TTL - 1;
    assert_eq!(select(&cache, &[a], last).map(|c| c.marks), Some(seen));
    let expired = select(&cache, &[a], InfraCache::SERVER_TTL).expect("a server");
    assert_eq!(expired.marks, Marks::default());
    assert_eq!(expired.timeout, InfraCache::UNKNOWN_TIMEOUT);
}

#[test]
fn skipped_server_stays_skipped_past_expiry() {
    let cache = cache();
    let [a, ..] = roots()[..] else {
        panic!("13 roots")
    };
    let mut now = 0;
    for _ in 0..12 {
        let sent = select(&cache, &[a], now).map_or(InfraCache::MAX_TIMEOUT, |c| c.timeout);
        cache.timeout(a, sent, now);
        now += 130;
    }
    // Last timeout at 1430, past the first entry's 900 s: skipped for 120 s from it.
    let last = now - 130;
    assert_eq!(select(&cache, &[a], last + 119), None);
    assert_eq!(timeout(&cache, a, last + 120), InfraCache::MAX_TIMEOUT);
}

#[test]
fn default_capacity_holds_unbounds_hosts() {
    let cache = cache();
    assert!(cache.is_empty());
    for n in 0..10_000 {
        cache.reply(documentation(n), 20 * MS, Marks::default(), 0);
    }
    assert_eq!(cache.len(), 10_000);
    assert!(!cache.is_empty());
}

#[test]
fn size_bound_evicts() {
    let capacity = 64 << 10;
    let cache = InfraCache::new(capacity, 4).expect("a valid size");
    let zone = name("example.");
    for n in 0..10_000 {
        cache.reply(documentation(n), 20 * MS, Marks::default(), 0);
        cache.lame(documentation(n), &zone, 0);
        assert!(cache.used() <= capacity, "{} bytes", cache.used());
    }
    assert!(cache.len() < 2000, "{} entries", cache.len());
    // Full, within two entries (about 270 bytes each) of each shard's share.
    assert!(cache.used() > capacity - 4 * 600, "{} bytes", cache.used());
    // The last heard of is still held.
    assert_eq!(timeout(&cache, documentation(9_999), 0), 60 * MS);
}

#[test]
fn sizes_checked() {
    assert_eq!(
        InfraCache::new(InfraCache::DEFAULT_CAPACITY, 3).err(),
        Some(ConfigError::Shards(3))
    );
    assert!(matches!(
        InfraCache::new(256, 1),
        Err(ConfigError::Capacity(_))
    ));
    // Room for the longest entry, a lame IPv6 server for a zone of 255 octets.
    let small = InfraCache::new(4096, 1).expect("a valid size");
    // What a reload compares to keep the cache (D195).
    assert_eq!(small.capacity(), 4096);
    let label = "a".repeat(63);
    let longest = name(&format!("{label}.{label}.{label}.{}.", &label[..61]));
    small.lame(documentation(1), &longest, 0);
    assert_eq!(small.len(), 1);
}

/// The `n`th address of the documentation prefix, RFC 3849.
fn documentation(n: u16) -> SocketAddr {
    SocketAddr::new(
        IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, n)),
        53,
    )
}
