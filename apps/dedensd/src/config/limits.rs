//! The guard around the pipeline: the rate limit (`rrl`, D113), DNS cookies (`cookies`, RFC 7873), the
//! validation and `ODoH` budgets (D117), and the count of serving threads (D42).

use std::num::{NonZeroU32, NonZeroUsize};
use std::sync::{Arc, OnceLock};

use anyhow::{Context, ensure};
use dedens_server::{
    Access, Budget, Cookies, Denial, MAX_BURST, Network, Pipeline, Rate, RateLimit,
    RateLimitConfig, Secret, Secrets, Stage,
};
use serde::Deserialize;

use super::access::AccessFile;
use super::{MAX_THREADS, unix_seconds};

/// The rate limit, as written (D113). A field left out is the library's default.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct RrlFile {
    /// `false` limits nothing.
    #[serde(default = "yes")]
    enabled: bool,
    /// One in `slip` limited queries is answered with TC=1; none when 0.
    slip: Option<u8>,
    /// Buckets in the table.
    table_size: Option<usize>,
    /// Limits of IPv4 networks.
    ipv4: Option<RateFile>,
    /// Limits of IPv6 networks.
    ipv6: Option<RateFile>,
    /// Networks never limited. Default: loopback.
    exempt: Option<Vec<Network>>,
}

impl Default for RrlFile {
    fn default() -> Self {
        Self {
            enabled: true,
            slip: None,
            table_size: None,
            ipv4: None,
            ipv6: None,
            exempt: None,
        }
    }
}

/// The limit of one address family, as written (D113).
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RateFile {
    /// The bits of the address that name a network.
    prefix: Option<u8>,
    /// Queries a second of a network.
    rate: Option<u32>,
    /// Queries at once: 2.5 times the rate if left out.
    burst: Option<u32>,
}

/// 2.5 times `rate`, at least 1 and at most [`MAX_BURST`].
fn two_and_a_half(rate: u32) -> u32 {
    u32::try_from((u64::from(rate) * 5 / 2).clamp(1, u64::from(MAX_BURST)))
        .expect("clamped to MAX_BURST, below 2^32")
}

impl RateFile {
    /// The limit with the fields written, the others from `default`.
    fn over(file: Option<Self>, default: Rate) -> Rate {
        let Some(file) = file else {
            return default;
        };
        let per_second = file.rate.unwrap_or(default.per_second);
        Rate {
            prefix: file.prefix.unwrap_or(default.prefix),
            per_second,
            burst: file.burst.unwrap_or_else(|| {
                if file.rate.is_none() {
                    default.burst
                } else {
                    two_and_a_half(per_second)
                }
            }),
        }
    }
}

impl RrlFile {
    /// The rate limit, `None` when disabled. That of `previous` is kept, table and all, when its settings are the
    /// same: a reload must not hand every source a full bucket.
    fn into_limit(self, previous: &Pipeline) -> anyhow::Result<Option<Arc<RateLimit>>> {
        if !self.enabled {
            return Ok(None);
        }
        let default = RateLimitConfig::default();
        let config = RateLimitConfig {
            ipv4: RateFile::over(self.ipv4, default.ipv4),
            ipv6: RateFile::over(self.ipv6, default.ipv6),
            slip: self.slip.unwrap_or(default.slip),
            table: self.table_size.unwrap_or(default.table),
            exempt: self.exempt.unwrap_or(default.exempt),
        };
        if let Some(kept) = previous
            .rate_limit()
            .filter(|limit| limit.config() == &config)
        {
            return Ok(Some(Arc::clone(kept)));
        }
        RateLimit::new(config)
            .map(|limit| Some(Arc::new(limit)))
            .context("`rrl`")
    }
}

/// What a client network may spend, as written (D117): a field left out is the default's.
#[derive(Debug, Clone, Copy, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct BudgetFile {
    /// Units a second of a network, a /24 of IPv4 or a /48 of IPv6.
    rate: Option<NonZeroU32>,
    /// Units at once.
    burst: Option<NonZeroU32>,
}

impl BudgetFile {
    /// The budget with the fields written, the others from `default`.
    pub(super) fn over(file: Option<Self>, default: Budget) -> Budget {
        let file = file.unwrap_or_default();
        Budget {
            per_second: file.rate.map_or(default.per_second, NonZeroU32::get),
            burst: file.burst.map_or(default.burst, NonZeroU32::get),
            table: default.table,
        }
    }
}

/// Server Cookies, as written (D113).
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct CookiesFile {
    /// `false` makes and checks none.
    #[serde(default = "yes")]
    enabled: bool,
    /// The secret cookies are made with; one made at start if left out.
    secret: Option<Secret>,
    /// The secrets, besides `secret`, cookies are accepted under.
    #[serde(default)]
    accept: Vec<Secret>,
}

impl Default for CookiesFile {
    fn default() -> Self {
        Self {
            enabled: true,
            secret: None,
            accept: Vec::new(),
        }
    }
}

impl CookiesFile {
    /// The cookies, `None` when disabled. With no `secret` it is one made at start, the same at every reload so
    /// that cookies given stay good.
    fn into_cookies(self) -> anyhow::Result<Option<Cookies>> {
        if !self.enabled {
            return Ok(None);
        }
        let secrets = if let Some(current) = self.secret {
            Secrets::new(current, self.accept)
        } else {
            ensure!(
                self.accept.is_empty(),
                "`cookies`: `accept` needs a `secret`"
            );
            Secrets::new(random_secret()?, Vec::new())
        };
        Ok(Some(Cookies::new(secrets, Arc::new(unix_seconds))))
    }
}

/// The secret made at start: drawn once, for every configuration read.
fn random_secret() -> anyhow::Result<Secret> {
    static SECRET: OnceLock<Secret> = OnceLock::new();
    if let Some(secret) = SECRET.get() {
        return Ok(secret.clone());
    }
    let mut bytes = [0; 16];
    getrandom::fill(&mut bytes).context("`cookies`: no randomness for a secret")?;
    // A reload racing the first read keeps whichever secret was set first.
    Ok(SECRET.get_or_init(|| Secret::new(bytes)).clone())
}

/// What stands before the stages: who is answered, how fast, and the cookies (D91, D113).
pub(super) struct Guard {
    pub(super) access: Option<AccessFile>,
    pub(super) rrl: RrlFile,
    pub(super) cookies: CookiesFile,
}

impl Guard {
    /// The pipeline of `stages` behind it; the rate limit of `previous` is kept when its settings are.
    pub(super) fn around(
        self,
        stages: Vec<Stage>,
        previous: &Pipeline,
    ) -> anyhow::Result<Pipeline> {
        let access = self
            .access
            .map_or_else(|| Access::local(Denial::default()), AccessFile::into_access);
        let mut pipeline = Pipeline::new(stages).with_access(access);
        if let Some(limit) = self.rrl.into_limit(previous)? {
            pipeline = pipeline.with_rate_limit(limit);
        }
        if let Some(cookies) = self.cookies.into_cookies()? {
            pipeline = pipeline.with_cookies(cookies);
        }
        Ok(pipeline)
    }
}

/// `true`, the default of what is on unless turned off.
const fn yes() -> bool {
    true
}

/// The serving threads from `threads` as written: that many, or one per core of `cores` on Linux and one elsewhere,
/// where `SO_REUSEPORT` does not spread queries across the sockets of threads and a second would serve none (D42).
///
/// # Errors
///
/// Above [`MAX_THREADS`], or above one off Linux.
pub(super) fn serving_threads(
    written: Option<NonZeroUsize>,
    linux: bool,
    cores: usize,
) -> anyhow::Result<usize> {
    let Some(written) = written.map(NonZeroUsize::get) else {
        return Ok(if linux { cores } else { 1 });
    };
    ensure!(written <= MAX_THREADS, "`threads` is above {MAX_THREADS}");
    ensure!(
        linux || written == 1,
        "`threads` is above 1, and only on Linux does `SO_REUSEPORT` spread queries across threads"
    );
    Ok(written)
}

#[cfg(test)]
mod tests {
    use std::net::IpAddr;

    use dedens_server::Standing;

    use super::*;
    use crate::config::tests::*;

    /// Whether a source outside loopback is limited within the default burst of 4000 queries at once.
    fn limited(pipeline: &Pipeline) -> bool {
        let from = "198.51.100.1".parse().unwrap();
        (0..5000).any(|_| pipeline.limits(from, 0))
    }

    #[test]
    fn rate_limiting_and_cookies_are_on_by_default() {
        let config = read(MINIMAL, env, &Pipeline::default()).unwrap();
        assert!(limited(&config.pipeline));
        assert!(config.pipeline.cookies().is_some());
    }

    #[test]
    fn rate_limiting_and_cookies_can_be_turned_off() {
        let text = format!("rrl: {{enabled: false}}\ncookies: {{enabled: false}}\n{MINIMAL}");
        let config = read(&text, env, &Pipeline::default()).unwrap();
        assert!(!limited(&config.pipeline));
        assert!(config.pipeline.cookies().is_none());
    }

    #[test]
    fn rate_limit_settings_are_checked() {
        for refused in [
            "rrl: {ipv4: {prefix: 33}}",
            "rrl: {ipv6: {prefix: 0}}",
            "rrl: {ipv4: {rate: 0}}",
            "rrl: {slip: 11}",
            "rrl: {table_size: 0}",
            "rrl: {ipv4: {burst: 0}}",
            "rrl: {rate: 5}",
            "rrl: {ipv4: {per_second: 5}}",
        ] {
            let text = format!("{refused}\n{MINIMAL}");
            assert!(read(&text, env, &Pipeline::default()).is_err(), "{refused}");
        }
        let text = format!("rrl: {{slip: 0, ipv4: {{prefix: 16, rate: 10}}}}\n{MINIMAL}");
        assert!(read(&text, env, &Pipeline::default()).is_ok());
    }

    #[test]
    fn a_rate_without_a_burst_has_two_and_a_half_times_the_rate() {
        let default = Rate {
            prefix: 24,
            per_second: 1600,
            burst: 4000,
        };
        let file = |rate| {
            Some(RateFile {
                prefix: None,
                rate,
                burst: None,
            })
        };
        assert_eq!(RateFile::over(None, default), default);
        assert_eq!(RateFile::over(file(None), default), default);
        // Odd rates round down, never to a burst below the rate (that is an error); 1 gives 2.
        for (rate, burst) in [(1, 2), (2, 5), (3, 7), (10, 25), (1_000_000, 2_500_000)] {
            assert_eq!(RateFile::over(file(Some(rate)), default).burst, burst);
        }
        // A rate of 4 billion would overflow a `u32` doubled and a half over: it stops at the limit of a burst,
        // which `rrl` then refuses as below the rate.
        assert_eq!(
            RateFile::over(file(Some(u32::MAX)), default).burst,
            MAX_BURST
        );
        let text = format!("rrl: {{ipv4: {{rate: {}}}}}\n{MINIMAL}", u32::MAX);
        assert!(read(&text, env, &Pipeline::default()).is_err());
    }

    #[test]
    fn the_exempt_networks_are_not_limited() {
        let from: IpAddr = "203.0.113.7".parse().unwrap();
        let default = read(MINIMAL, env, &Pipeline::default()).unwrap();
        assert!((0..5000).any(|_| default.pipeline.limits(from, 0)));
        let text = format!("rrl: {{exempt: ['203.0.113.0/24']}}\n{MINIMAL}");
        let config = read(&text, env, &Pipeline::default()).unwrap();
        assert!(!(0..5000).any(|_| config.pipeline.limits(from, 0)));
        // Loopback is no longer exempt once the list is written.
        assert!((0..5000).any(|_| config.pipeline.limits("127.0.0.1".parse().unwrap(), 0)));
    }

    #[test]
    fn a_reload_keeps_the_rate_limit_while_its_settings_stay() {
        let first = read(MINIMAL, env, &Pipeline::default()).unwrap();
        let same = read(MINIMAL, env, &first.pipeline).unwrap();
        let kept = |a: &Pipeline, b: &Pipeline| match (a.rate_limit(), b.rate_limit()) {
            (Some(a), Some(b)) => Arc::ptr_eq(a, b),
            _ => false,
        };
        assert!(kept(&first.pipeline, &same.pipeline));
        let text = format!("rrl: {{slip: 1}}\n{MINIMAL}");
        let changed = read(&text, env, &first.pipeline).unwrap();
        assert!(!kept(&first.pipeline, &changed.pipeline));
    }

    #[test]
    fn a_cookie_secret_is_32_hex_digits_and_hidden() {
        let ok = format!("cookies: {{secret: '{}'}}\n{MINIMAL}", "ab".repeat(16));
        let config = read(&ok, env, &Pipeline::default()).unwrap();
        let shown = format!("{:?}", config.pipeline.cookies());
        assert!(!shown.contains("abab"), "{shown}");
        // Quoted, a secret of digits only stays a string, in the file or through `${VAR}` (YAML reads 1234 as a number).
        for text in [
            "cookies: {secret: '12345678901234567890123456789012'}",
            "cookies: {secret: '${DIGITS}'}",
        ] {
            read(&format!("{text}\n{MINIMAL}"), env, &Pipeline::default()).unwrap();
        }
        for refused in ["cookies: {secret: 'abcd'}", "cookies: {secret: zz}"] {
            let text = format!("{refused}\n{MINIMAL}");
            let error = read(&text, env, &Pipeline::default()).unwrap_err();
            assert!(!error.to_string().contains("zz"), "{error}");
        }
        let text = format!("cookies: {{accept: ['{}']}}\n{MINIMAL}", "ab".repeat(16));
        let error = read(&text, env, &Pipeline::default()).unwrap_err();
        assert!(error.to_string().contains("`accept` needs a `secret`"));
    }

    /// How the cookies of `of` take a cookie the cookies of `by` made.
    fn standing(by: &Pipeline, of: &Pipeline) -> Standing {
        let from: IpAddr = "192.0.2.9".parse().unwrap();
        let cookie = by.cookies().unwrap().issue([7; 8], from);
        of.cookies().unwrap().verify(Some(&cookie), from)
    }

    #[test]
    fn a_reload_keeps_the_random_cookie_secret() {
        let first = read(MINIMAL, env, &Pipeline::default()).unwrap();
        let second = read(MINIMAL, env, &first.pipeline).unwrap();
        assert_eq!(standing(&first.pipeline, &second.pipeline), Standing::Valid);
    }

    #[test]
    fn a_cookie_of_a_secret_is_accepted_only_where_it_is_listed() {
        let (a, b) = ("aa".repeat(16), "bb".repeat(16));
        let with =
            |text: String| read(&format!("{text}\n{MINIMAL}"), env, &Pipeline::default()).unwrap();
        let old = with(format!("cookies: {{secret: '{a}'}}"));
        let new = with(format!("cookies: {{secret: '{b}'}}"));
        let rolling = with(format!("cookies: {{secret: '{b}', accept: ['{a}']}}"));
        assert_eq!(standing(&old.pipeline, &new.pipeline), Standing::Invalid);
        assert_eq!(standing(&old.pipeline, &rolling.pipeline), Standing::Valid);
        assert_eq!(standing(&rolling.pipeline, &new.pipeline), Standing::Valid);
    }

    /// E5: `threads` is a count from 1 to 1024.
    #[test]
    fn threads_are_bounded() {
        for (extra, message) in [
            ("threads: 0", "nonzero"),
            ("threads: 1025", "`threads` is above 1024"),
            ("threads: -1", "invalid"),
        ] {
            let refused = error(&format!("{extra}\n{MINIMAL}"));
            assert!(refused.contains(message), "{extra}: {refused}");
        }
        assert!(read(&format!("threads: 1\n{MINIMAL}"), env, &Pipeline::default()).is_ok());
    }

    /// E5: without `threads`, one per core on Linux and one elsewhere; more than one is refused off Linux.
    #[test]
    fn threads_default_to_the_cores_on_linux() {
        let threads = |written: Option<usize>, linux, cores| {
            serving_threads(written.and_then(NonZeroUsize::new), linux, cores)
                .map_err(|error| error.to_string())
        };
        assert_eq!(threads(None, true, 8), Ok(8));
        assert_eq!(threads(None, false, 8), Ok(1));
        assert_eq!(threads(Some(3), true, 8), Ok(3));
        assert_eq!(threads(Some(1024), true, 8), Ok(1024));
        assert_eq!(threads(Some(1), false, 8), Ok(1));
        assert!(threads(Some(2), false, 8).is_err_and(|e| e.contains("Linux")));
    }
}
