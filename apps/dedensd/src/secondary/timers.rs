//! When a secondary zone is refreshed, retried and expired, from its SOA (RFC 1034 §4.3.5, RFC 1035 §3.3.13):
//! each SOA timer clamped to a bound (D115) and jittered, pure so that a test or the simulator sets the clock and
//! the draw (D215). Times are Unix seconds.

use dedens_proto::rdata::Soa;

/// The shortest refresh interval: 2 s, Knot's `refresh-min-interval` (`src/knot/conf/schema.c`). An SOA asking
/// for less makes the secondary query its primary in a loop. NSD's `min-refresh-time` is 0
/// (`pattern_options_create`, `options.c`), BIND's `min-refresh-time` 300 s.
pub(super) const MIN_REFRESH: u64 = 2;

/// The longest refresh interval: 28 days, NSD's `max-refresh-time` (`pattern_options_create`, `options.c`) and
/// BIND's `max-refresh-time`; Knot's `refresh-max-interval` is unbounded (`schema.c`). An SOA asking for more
/// leaves a secondary that missed a NOTIFY behind for longer than a zone is worth.
pub(super) const MAX_REFRESH: u64 = 28 * DAY;

/// The shortest retry interval: 1 s, Knot's `retry-min-interval` (`schema.c`); NSD's `min-retry-time` is 0
/// (`options.c`), BIND's `min-retry-time` 500 s.
pub(super) const MIN_RETRY: u64 = 1;

/// The longest retry interval: 14 days, NSD's `max-retry-time` (`options.c`) and BIND's `max-retry-time`; Knot's
/// `retry-max-interval` is unbounded (`schema.c`).
pub(super) const MAX_RETRY: u64 = 14 * DAY;

/// The shortest expire interval: 3 s, Knot's `expire-min-interval` (`schema.c`), so a zone is never dropped
/// before a refresh could renew it; NSD and BIND have none. No longest: the SOA's expire, up to 136 years, is what
/// the zone's owner promises its data holds that long.
pub(super) const MIN_EXPIRE: u64 = 3;

/// The longest wait between two tries of a zone that has no version yet: 2 hours, as Knot's `zone_bootstrap_next`
/// (`src/knot/zone/zone.c`) grows it, 5 s × tries², until it reaches its cap of 7200 s. NSD and BIND retry such a
/// zone at the retry interval of a default SOA, which there is none of.
pub(super) const MAX_BOOTSTRAP: u64 = 7200;

/// A day, in seconds.
const DAY: u64 = 86_400;

/// The intervals of a zone's SOA, clamped to the bounds above.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct Intervals {
    refresh: u64,
    retry: u64,
    expire: u64,
}

impl Intervals {
    /// The intervals of `soa`, clamped.
    pub(super) fn of(soa: &Soa<'_>) -> Self {
        Self {
            refresh: u64::from(soa.refresh).clamp(MIN_REFRESH, MAX_REFRESH),
            retry: u64::from(soa.retry).clamp(MIN_RETRY, MAX_RETRY),
            expire: u64::from(soa.expire).max(MIN_EXPIRE),
        }
    }

    /// When a zone refreshed at `refreshed` is refreshed next, `draw` a random number for the jitter.
    pub(super) const fn refresh_at(&self, refreshed: u64, draw: u64) -> u64 {
        refreshed.saturating_add(jitter(self.refresh, draw))
    }

    /// When a refresh that failed at `now` is tried again.
    pub(super) const fn retry_at(&self, now: u64, draw: u64) -> u64 {
        now.saturating_add(jitter(self.retry, draw))
    }

    /// When a zone refreshed at `refreshed` expires: never jittered, so that a zone never expires late.
    pub(super) const fn expire_at(&self, refreshed: u64) -> u64 {
        refreshed.saturating_add(self.expire)
    }
}

/// When a zone that has no version is tried again after its `tries`-th try in a row failed at `now`: Knot's
/// `zone_bootstrap_next` (`src/knot/zone/zone.c`), 5 s × tries², at most [`MAX_BOOTSTRAP`], plus a draw below
/// 5 s × (tries + 1), at most 30 s, so that many zones of a restarted server do not try together.
pub(super) const fn bootstrap_at(now: u64, tries: u32, draw: u64) -> u64 {
    let tries = tries as u64;
    let wait = tries.saturating_mul(tries).saturating_mul(5);
    let wait = if wait < MAX_BOOTSTRAP {
        wait
    } else {
        MAX_BOOTSTRAP
    };
    let spread = 5 * tries.saturating_add(1);
    let spread = if spread < 30 { spread } else { 30 };
    now.saturating_add(wait).saturating_add(draw % spread)
}

/// `seconds` less up to a tenth, as `draw` says, when over 10 s: NSD's `xfrd_set_timer` (`xfrd.c`), whose zones,
/// loaded together, would otherwise query their primaries together at each refresh. Shorter, never longer, so
/// that a zone is refreshed before it expires. Knot jitters by `refresh-jitter`, off by default; BIND up to 25 %
/// less.
const fn jitter(seconds: u64, draw: u64) -> u64 {
    if seconds <= 10 {
        return seconds;
    }
    let base = seconds / 10 * 9 + seconds % 10 * 9 / 10;
    base + draw % (seconds - base)
}

#[cfg(test)]
mod tests {
    use dedens_proto::Name;

    use super::*;

    fn soa(refresh: u32, retry: u32, expire: u32) -> Soa<'static> {
        Soa {
            mname: Name::root(),
            rname: Name::root(),
            serial: 1,
            refresh,
            retry,
            expire,
            minimum: 0,
        }
    }

    #[test]
    fn each_interval_is_clamped_to_its_bounds() {
        let short = Intervals::of(&soa(0, 0, 0));
        assert_eq!(short.refresh_at(100, 0), 100 + MIN_REFRESH);
        assert_eq!(short.retry_at(100, 0), 100 + MIN_RETRY);
        assert_eq!(short.expire_at(100), 100 + MIN_EXPIRE);
        let long = Intervals::of(&soa(u32::MAX, u32::MAX, u32::MAX));
        assert_eq!(long.refresh_at(0, 0), MAX_REFRESH / 10 * 9);
        assert_eq!(long.retry_at(0, MAX_RETRY / 10 - 1), MAX_RETRY - 1);
        assert_eq!(long.expire_at(0), u64::from(u32::MAX));
    }

    #[test]
    fn the_jitter_shortens_by_a_tenth_at_most_and_never_the_expire() {
        // The root's SOA: refresh 1800, retry 900, expire 604800.
        let root = Intervals::of(&soa(1800, 900, 604_800));
        assert_eq!(root.refresh_at(0, 0), 1620);
        assert_eq!(root.refresh_at(0, 179), 1799);
        assert_eq!(root.refresh_at(0, 180), 1620);
        assert_eq!(root.retry_at(0, 89), 899);
        assert_eq!(root.expire_at(0), 604_800);
        // 10 s and below: as written.
        assert_eq!(Intervals::of(&soa(10, 7, 3)).refresh_at(0, 5), 10);
        assert_eq!(jitter(11, 0), 9);
        assert_eq!(jitter(11, 1), 10);
    }

    #[test]
    fn a_zone_without_a_version_is_tried_again_sooner_then_every_two_hours() {
        let waits: Vec<_> = [0, 1, 2, 10, 37, 38, u32::MAX]
            .into_iter()
            .map(|tries| bootstrap_at(0, tries, 0))
            .collect();
        assert_eq!(waits, [0, 5, 20, 500, 6845, 7200, MAX_BOOTSTRAP]);
        assert_eq!(bootstrap_at(0, 1, 9), 5 + 9);
        assert_eq!(bootstrap_at(0, 1, 10), 5);
        assert_eq!(bootstrap_at(0, 100, 29), MAX_BOOTSTRAP + 29);
        assert_eq!(bootstrap_at(u64::MAX, 3, 7), u64::MAX);
    }
}
