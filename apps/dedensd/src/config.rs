//! The configuration file (D24, D44, D115): YAML, `${VAR}` replaced first, then read into named stages run in the
//! order `pipeline` lists them. A value of `${VAR}` is one value, never YAML: left as it is when plain (letters,
//! digits, `_./:@+=%~#-`), single-quoted when alone as a value, escaped between the template's own quotes, refused
//! anywhere else. A TLS or `ODoH` key file readable by others is refused, by its group warned about. After the drop
//! (D122) a reload reads as `user`: the files it reads (the certificate and its key, lists, `upstream_ca`, saved
//! downloads) must be readable by it, and `downloads.dir` writable. The start reads the configuration again as `user`
//! right after the drop, and ends if it cannot. A reload warns of a change to `user` or `group` as written: `user: 990`
//! for `user: dedens` warns too.
//!
//! ```yaml
//! listen: ["127.0.0.1:53", "[::1]:53", "tls://0.0.0.0", "quic://0.0.0.0", "https://0.0.0.0/dns-query"]
//! threads: 4                       # serving threads, fixed at start, 1 to 1024; default: a core each on Linux, else 1 (D42)
//! user: dedens                     # Linux, started as root: run as this user, a name or an id, once the sockets are bound (D122)
//! group: dedens                    # default: the user's primary group; supplementary groups: those listing the user, plus this one
//! tls:
//!   certificate: /etc/dedensd/tls/fullchain.pem
//!   key: /etc/dedensd/tls/key.pem
//! odoh:                              # Oblivious DoH target on the https:// addresses (D79); needs the odoh feature
//!   key: /etc/dedensd/odoh.key         # 64 hex digits; default: a key made at each start
//!   proxy:                           # also the proxy of RFC 9230 §4 (D94): forwards to these targets only
//!     targets: [odoh.cloudflare-dns.com, "odoh-target.example:8443"]   # HOST[:PORT], port 443 by default
//!     timeout_ms: 5000
//! access:                           # who is answered (D91); default: loopback, private and link-local networks
//!   allow: ["10.0.0.0/8", "2001:db8::/32"]
//!   deny: ["10.9.0.0/16"]            # the longest network holding the client decides; deny wins a tie
//!   action: refuse                   # refuse (default) answers REFUSED with EDE 18, drop answers nothing
//! rrl:                              # response rate limiting over UDP and DoC (D113); on by default, these are the defaults
//!   enabled: true
//!   slip: 2                          # of the queries over the rate, one in `slip` gets TC=1; 0 answers none, 1 all
//!   table_size: 65536                # buckets; memory is 8 bytes each, fixed
//!   ipv4: {prefix: 24, rate: 1600, burst: 4000}   # per second and network of `prefix` bits; burst: 2.5 x rate
//!   ipv6: {prefix: 56, rate: 150, burst: 375}   # a burst is at least the rate
//!   exempt: ["127.0.0.0/8", "::1/128"]   # never limited: a proxy or a monitor, not a source that can be spoofed
//! cookies:                          # Server Cookies, RFC 7873 and RFC 9018 (D113); on by default
//!   enabled: true
//!   secret: '${COOKIE_SECRET}'       # 32 hex digits, quoted so that a secret of digits only stays a string; default: random at
//!                                    # start. Set it, and `accept`, to share among anycast servers
//!   accept: ['${OLD_COOKIE_SECRET}'] # other secrets cookies are accepted under (RFC 9018 §5)
//! downloads:
//!   dir: /var/cache/dedensd
//!   refresh_minutes: 1440
//! pipeline: [hosts, ads, cache, upstream]
//! stages:
//!   ads:
//!     type: blocklist
//!     file: /etc/dedensd/blocklist.hosts
//!     urls: ["https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/wildcard/pro-onlydomains.txt"]
//!     allow:
//!       entries: ["*.example.org"]
//!   hosts:
//!     type: hosts
//!     entries: ["192.0.2.10 printer.lan"]
//!     file: /etc/hosts
//!   cache:
//!     type: cache
//!     capacity: 67108864               # bytes of memory, entries and what holds them (D116)
//!     max_entry_bytes: 8192            # a response stored larger is answered, not cached; unset: 8 KiB (D116)
//!   upstream:
//!     type: forward
//!     servers: ["tls://9.9.9.9#dns.quad9.net", "149.112.112.112:53"]
//!     timeout_ms: 3000                 # per try, up to 30000
//!     tries: 2                         # per server, up to 5
//!     dnssec: validate                 # off (default) or validate (D77)
//!     trust_anchors: /etc/dedensd/anchors.zone   # DS or DNSKEY records; default: the root's, bundled
//!     insecure: [corp.example]         # names not validated, with what is below them (RFC 7646)
//!     client_share: {rate: 1000, burst: 2000}  # validation units a client network may spend (D117)
//! ```

use std::collections::BTreeMap;
use std::net::{IpAddr, SocketAddr};
use std::num::{NonZeroU8, NonZeroU32, NonZeroU64, NonZeroUsize};
use std::path::{Path, PathBuf};
use std::sync::{Arc, OnceLock};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use std::{fmt, fs, io, thread};

use anyhow::{Context, anyhow, bail, ensure};
use compio::rustls::pki_types::pem::PemObject as _;
use compio::rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName};
use dedens_cache::Cache;
use dedens_dnssec::anchor::TrustAnchors;
use dedens_dnssec::validator::{Limits, Validator};
use dedens_net::doh::DEFAULT_PATH;
use dedens_net::tls::{Presented, Trust};
use dedens_plugins::{Action, Blocklist, Hosts, ListError, Lists, Merged, Tlds};
use dedens_proto::{Name, Ttl};
use dedens_server::{
    Access, Budget, Budgets, Cookies, DEFAULT_SHARE, Denial, Forward, MAX_BURST, Network, Pipeline,
    Rate, RateLimit, RateLimitConfig, Secret, Secrets, Stage, Validating, Via,
};
use http::uri::PathAndQuery;
use serde::Deserialize;

use crate::download;
use crate::lists::Store;
use crate::privileges::{Account, Identity};

/// The configuration file, as written.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct File {
    /// Addresses answered on, over UDP and TCP, or TLS or QUIC.
    listen: Vec<Listen>,
    /// The certificate presented over TLS and QUIC (D66).
    tls: Option<TlsFile>,
    /// Serving as an Oblivious `DoH` target at the paths of the `https://` addresses (D79).
    odoh: Option<OdohFile>,
    /// The clients answered (D91). Default: those of loopback, private and link-local networks.
    access: Option<AccessFile>,
    /// Response rate limiting over UDP and `DoC` (D113). Default: on.
    #[serde(default)]
    rrl: RrlFile,
    /// Server Cookies (D113). Default: on, with a secret made at start.
    #[serde(default)]
    cookies: CookiesFile,
    /// Where downloaded lists are kept, and how often they are fetched again (D57).
    #[serde(default)]
    downloads: DownloadsFile,
    /// A PEM file of the certificate authorities upstream servers over TLS and QUIC are checked against,
    /// instead of the system's (D65).
    upstream_ca: Option<PathBuf>,
    /// The serving threads (D115). Default: one per core on Linux, one elsewhere.
    threads: Option<NonZeroUsize>,
    /// The user to run as once the sockets are bound (D122).
    user: Option<Account>,
    /// Its group, instead of the user's own (D122).
    group: Option<Account>,
    /// The names of the stages, in the order a query goes through them.
    pipeline: Vec<String>,
    /// The stages, by name.
    stages: BTreeMap<String, StageFile>,
}

/// The rate limit, as written (D113). A field left out is the library's default.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RrlFile {
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
struct BudgetFile {
    /// Units a second of a network, a /24 of IPv4 or a /48 of IPv6.
    rate: Option<NonZeroU32>,
    /// Units at once.
    burst: Option<NonZeroU32>,
}

impl BudgetFile {
    /// The budget with the fields written, the others from `default`.
    fn over(file: Option<Self>, default: Budget) -> Budget {
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
struct CookiesFile {
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
struct Guard {
    access: Option<AccessFile>,
    rrl: RrlFile,
    cookies: CookiesFile,
}

impl Guard {
    /// The pipeline of `stages` behind it; the rate limit of `previous` is kept when its settings are.
    fn around(self, stages: Vec<Stage>, previous: &Pipeline) -> anyhow::Result<Pipeline> {
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

/// Seconds since the Unix epoch, 0 with a clock before it.
fn unix_seconds() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map_or_else(
        |error| {
            // Time 0 fails closed for signatures: none is valid yet. Cookies stamped 0 stay good; they prove
            // an address, not a time of day.
            tracing::error!(%error, "the system clock is before the Unix epoch");
            0
        },
        |elapsed| elapsed.as_secs(),
    )
}

/// The access lists, as written (D91).
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct AccessFile {
    /// Networks answered; none answers nobody.
    #[serde(default)]
    allow: Vec<Network>,
    /// Networks refused, inside an allowed one or not.
    #[serde(default)]
    deny: Vec<Network>,
    /// What a denied client gets.
    #[serde(default)]
    action: Denial,
}

impl AccessFile {
    fn into_access(self) -> Access {
        Access::new(self.allow, self.deny, self.action)
    }
}

/// Where the access lists of a configuration come from (D91).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum AccessSource {
    /// `access` is left out: only the local networks are answered.
    Unset,
    /// `access` allows some networks.
    Written,
    /// `access` allows no network: nobody is answered.
    NoAllow,
}

impl AccessSource {
    /// Where `access`, as written or left out, comes from.
    fn of(access: Option<&AccessFile>) -> Self {
        match access {
            None => Self::Unset,
            Some(access) if access.allow.is_empty() => Self::NoAllow,
            Some(_) => Self::Written,
        }
    }
}

impl Config {
    /// Warns of access lists that answer little or nothing, for a server on `listen`: unset lists on a listen
    /// address outside the local networks (a wildcard address listens on every interface, public ones included),
    /// and written ones allowing nothing.
    pub(crate) fn warn_access(&self, listen: &[Listen]) {
        match self.access {
            AccessSource::Unset => {
                let local = Access::local(Denial::default());
                for listen in listen.iter().filter(|l| !local.permits(l.addr().ip())) {
                    tracing::warn!(
                        ?listen,
                        "no `access` configured: only loopback, private and link-local clients are answered (D91)"
                    );
                }
            }
            AccessSource::NoAllow => {
                tracing::warn!("`access` allows no network: no client is answered (D91)");
            }
            AccessSource::Written => {}
        }
    }
}

/// The certificate `dedensd` presents, as written: PEM files, read again on each reload.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct TlsFile {
    /// The certificate chain, the server's first.
    certificate: PathBuf,
    /// Its private key.
    key: PathBuf,
}

/// The Oblivious `DoH` target `dedensd` serves as (D79).
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct OdohFile {
    /// A file with the target's secret, 64 hexadecimal digits. Default: a new random secret at each start.
    #[cfg_attr(
        not(feature = "odoh"),
        expect(dead_code, reason = "read by the target, built with the odoh feature")
    )]
    key: Option<PathBuf>,
    /// Forwarding queries to other targets too (D94).
    #[cfg_attr(
        not(feature = "odoh"),
        expect(dead_code, reason = "read by the proxy, built with the odoh feature")
    )]
    proxy: Option<ProxyFile>,
    /// What all clients may open together: `rate` decapsulations a second and `burst` at once, 10 000 and 20 000
    /// by default (D117); past them, 503 before the request is parsed or opened.
    #[cfg_attr(
        not(feature = "odoh"),
        expect(dead_code, reason = "read by the target, built with the odoh feature")
    )]
    budget: Option<BudgetFile>,
    /// What a client network may open, as `dedensd` sees it (a proxy's, D91): `rate` a second and `burst` at once,
    /// 1000 and 2000 by default (D117); past them, 503 before the request is parsed or opened. Sources on the
    /// `rrl.exempt` list (D113) have none.
    #[cfg_attr(
        not(feature = "odoh"),
        expect(dead_code, reason = "read by the target, built with the odoh feature")
    )]
    client_budget: Option<BudgetFile>,
}

/// The Oblivious `DoH` proxy `dedensd` serves as (D94).
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ProxyFile {
    /// The targets forwarded to, `HOST[:PORT]` each: any other is refused.
    #[cfg_attr(
        not(feature = "odoh"),
        expect(dead_code, reason = "read by the proxy, built with the odoh feature")
    )]
    targets: Vec<String>,
    /// How long a forward may take, in milliseconds. Default: 5000.
    #[cfg_attr(
        not(feature = "odoh"),
        expect(dead_code, reason = "read by the proxy, built with the odoh feature")
    )]
    timeout_ms: Option<NonZeroU32>,
}

/// An address `dedensd` answers on (D66, D84): `IP:PORT` over UDP and TCP; behind `tls://` over TLS, behind `quic://`
/// over QUIC, on port 853 unless `:PORT` follows (RFC 7858 §3.1, RFC 9250 §4.1.1); behind `https://` over HTTP/3, on
/// port 443 unless `:PORT` follows, at `/PATH` (`/dns-query` unless set; RFC 8484 §3, RFC 9114 §3.1); behind `coap://`
/// over CoAP, unprotected, on UDP port 5683 unless `:PORT` follows, at `/PATH` (`/` unless set; RFC 9953, D81; the `doc`
/// feature).
#[derive(Clone, PartialEq, Eq, Deserialize)]
#[serde(try_from = "String")]
pub(crate) enum Listen {
    Plain(SocketAddr),
    Tls(SocketAddr),
    Quic(SocketAddr),
    Https(SocketAddr, Arc<str>),
    #[cfg(feature = "doc")]
    Coap(SocketAddr, Arc<str>),
}

impl Listen {
    /// The address listened on.
    pub(crate) const fn addr(&self) -> SocketAddr {
        match self {
            Self::Plain(addr) | Self::Tls(addr) | Self::Quic(addr) | Self::Https(addr, _) => *addr,
            #[cfg(feature = "doc")]
            Self::Coap(addr, _) => *addr,
        }
    }

    /// Whether queries come encrypted, with the certificate of `tls`.
    const fn encrypted(&self) -> bool {
        match self {
            Self::Plain(_) => false,
            #[cfg(feature = "doc")]
            Self::Coap(..) => false,
            Self::Tls(_) | Self::Quic(_) | Self::Https(..) => true,
        }
    }
}

/// As written, for the logs: `[tls://127.0.0.1:853]` rather than `[Tls(127.0.0.1:853)]`.
impl fmt::Debug for Listen {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Plain(addr) => write!(f, "{addr}"),
            Self::Tls(addr) => write!(f, "tls://{addr}"),
            Self::Quic(addr) => write!(f, "quic://{addr}"),
            Self::Https(addr, path) => write!(f, "https://{addr}{path}"),
            #[cfg(feature = "doc")]
            Self::Coap(addr, path) => write!(f, "coap://{addr}{path}"),
        }
    }
}

impl TryFrom<String> for Listen {
    type Error = String;

    fn try_from(text: String) -> Result<Self, String> {
        let encrypted = |rest: &str| address(rest, ENCRYPTED_PORT);
        let listen = match text.split_once("://") {
            None => text.parse().ok().map(Self::Plain),
            Some(("tls", rest)) => encrypted(rest).map(Self::Tls),
            Some(("quic", rest)) => encrypted(rest).map(Self::Quic),
            Some(("https", rest)) => {
                let (rest, path) =
                    split_path(rest).map_err(|error| format!("`{text}`: {error}"))?;
                address(rest, HTTPS_PORT).map(|addr| Self::Https(addr, path))
            }
            #[cfg(feature = "doc")]
            Some(("coap", rest)) => {
                let (rest, path) =
                    split_coap_path(rest).map_err(|error| format!("`{text}`: {error}"))?;
                address(rest, COAP_PORT).map(|addr| Self::Coap(addr, path))
            }
            Some(_) => None,
        };
        listen.ok_or_else(|| {
            format!(
                "`{text}` is neither IP:PORT nor tls://, quic://, https:// or coap:// (built with the `doc` feature) before IP[:PORT]"
            )
        })
    }
}

/// `ADDR[/PATH]` split in `ADDR` and the path, `/dns-query` unless set (RFC 8484 §3): a path of a request target
/// without query, which a template's `{?dns}` fills (RFC 6570 §3.2.8).
fn split_path(text: &str) -> Result<(&str, Arc<str>), String> {
    let Some(start) = text.find('/') else {
        return Ok((text, Arc::from(DEFAULT_PATH)));
    };
    let (rest, path) = text.split_at(start);
    let valid = path
        .parse::<PathAndQuery>()
        .is_ok_and(|parsed| parsed.query().is_none())
        && !path.contains(['{', '}']);
    if valid {
        Ok((rest, Arc::from(path)))
    } else {
        Err(format!("`{path}` is not a path without query"))
    }
}

/// `ADDR[/PATH]` split in `ADDR` and the path of a CoAP URI, `/` unless set (RFC 9953 §3.2): without query, fragment
/// or percent-encoding, which segments are read as written;
/// no `.` or `..` segment, and not `/.well-known/core`, which lists the resource (D95).
#[cfg(feature = "doc")]
fn split_coap_path(text: &str) -> Result<(&str, Arc<str>), String> {
    let Some(start) = text.find('/') else {
        return Ok((text, Arc::from("/")));
    };
    let (rest, path) = text.split_at(start);
    if path.contains(['?', '#', '%']) {
        Err(format!(
            "`{path}` is not a path without query, fragment or %"
        ))
    } else if path == "/.well-known/core" {
        Err(format!("`{path}` is where the resources are listed"))
    } else if path.split('/').any(|segment| matches!(segment, "." | "..")) {
        // A Uri-Path is never one (RFC 7252 §5.10.1): no request could reach it.
        Err(format!("`{path}` has a segment `.` or `..`"))
    } else {
        Ok((rest, Arc::from(path)))
    }
}

/// `IP:PORT`, or an IP address, on `port`; an IPv6 address in brackets or not.
fn address(text: &str, port: u16) -> Option<SocketAddr> {
    let bare = text
        .strip_prefix('[')
        .and_then(|rest| rest.strip_suffix(']'))
        .unwrap_or(text);
    text.parse()
        .or_else(|_| bare.parse().map(|ip: IpAddr| SocketAddr::new(ip, port)))
        .ok()
}

/// A stage, as written: its settings under its `type`.
#[derive(Debug, Deserialize)]
#[serde(tag = "type", rename_all = "lowercase", deny_unknown_fields)]
enum StageFile {
    /// Settings of `dedens_cache::Config`, each defaulting to the RFCs' recommendation.
    Cache(dedens_cache::Config),
    /// Upstream servers, asked in order, each `tries` times waiting `timeout_ms` for a response.
    ///
    /// `dnssec: validate` (D77) validates what they answer: AD is set for authentic answers only, a bogus one is
    /// SERVFAIL with an extended error. `trust_anchors` is a file of DS or DNSKEY records in zone file format, the
    /// root's bundled ones unless set; `insecure` lists names answered as they are, with their subdomains (RFC 7646).
    /// `client_share` is what a client network may spend of the validation allowance, in `rate` units a second and
    /// `burst` at once (D117): a unit is a question upstream or a signature check, about 10 µs.
    Forward {
        servers: Vec<Server>,
        timeout_ms: Option<NonZeroU32>,
        tries: Option<NonZeroU8>,
        #[serde(default)]
        dnssec: Dnssec,
        trust_anchors: Option<PathBuf>,
        #[serde(default)]
        insecure: Vec<Insecure>,
        client_share: Option<BudgetFile>,
    },
    /// Names and addresses (D54): `entries`, lines in the format of `/etc/hosts`, then those of `file`, read
    /// at start and on reload; each record with `ttl` seconds, 3600 unless set; `fallthrough` passing a listed name's
    /// other types to the next stage.
    Hosts {
        #[serde(default)]
        entries: Vec<String>,
        file: Option<PathBuf>,
        ttl: Option<u32>,
        #[serde(default)]
        fallthrough: bool,
    },
    /// Names blocked with their subdomains (D54, D56): `entries`, one name, `*.name` or a line in the format of
    /// `/etc/hosts` each, then those of `file`, read at start and on reload, then those of `urls`, downloaded (D57),
    /// unless they or a parent are in `allow`; answered as `action` says, `nxdomain` unless set, the addresses of
    /// `null` with `ttl` seconds, 3600 unless set. A plain line of one label (`zip`) is refused as a mistake, unless
    /// `tlds` is set: then it blocks, or allows, the whole top-level domain, in each list of the stage (D118).
    Blocklist {
        #[serde(default)]
        entries: Vec<String>,
        file: Option<PathBuf>,
        #[serde(default)]
        urls: Vec<Url>,
        #[serde(default)]
        allow: Sources,
        action: Option<Action>,
        ttl: Option<u32>,
        #[serde(default)]
        tlds: bool,
    },
}

/// Names of a list, as written: `entries`, then those of `file`, then the saved copies of `urls` (D57).
#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct Sources {
    #[serde(default)]
    entries: Vec<String>,
    file: Option<PathBuf>,
    #[serde(default)]
    urls: Vec<Url>,
}

/// The URL of a list: `https://`, or `http://` for a server of one's own.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(try_from = "String")]
struct Url(String);

impl TryFrom<String> for Url {
    type Error = String;

    fn try_from(text: String) -> Result<Self, String> {
        if text.starts_with("https://") || text.starts_with("http://") {
            Ok(Self(text))
        } else {
            // Logged at start and on each reload, and a URL may hold credentials (D104).
            Err(format!(
                "`{}` is not an http:// or https:// URL",
                download::redacted(&text)
            ))
        }
    }
}

/// The `downloads` settings, as written.
#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct DownloadsFile {
    dir: Option<PathBuf>,
    refresh_minutes: Option<NonZeroU64>,
}

/// Downloaded lists: their URLs, where their copies are kept, how often they are fetched again (D57).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Downloads {
    pub(crate) urls: Vec<String>,
    pub(crate) dir: PathBuf,
    pub(crate) refresh: Duration,
}

impl Sources {
    fn new(entries: Vec<String>, file: Option<PathBuf>, urls: Vec<Url>) -> Self {
        Self {
            entries,
            file,
            urls,
        }
    }
}

impl Downloads {
    /// No list yet, as `settings` say.
    ///
    /// # Errors
    ///
    /// `refresh_minutes` above a year.
    fn new(settings: DownloadsFile) -> anyhow::Result<Self> {
        Ok(Self {
            urls: Vec::new(),
            dir: settings.dir.unwrap_or_else(|| DOWNLOADS_DIR.into()),
            refresh: refresh(settings.refresh_minutes)?,
        })
    }

    /// Adds `urls`, once each: the downloads run together, two of one URL would save one copy at once (D104).
    fn add(&mut self, urls: impl Iterator<Item = Url>) {
        for Url(url) in urls {
            if !self.urls.contains(&url) {
                self.urls.push(url);
            }
        }
    }
}

/// An upstream server (D65, D84): an IP address, on port 53 unless `:PORT` follows (an IPv6 address then in
/// brackets); behind `tls://` or `quic://`, asked over TLS or QUIC, on port 853 unless set; behind `https://`, asked
/// over HTTP/3 at `/PATH` (`/dns-query` unless set), on port 443 unless set; and `#NAME` after it for the name its
/// certificate must hold, else its address.
#[derive(Debug, Clone, Deserialize)]
#[serde(try_from = "String")]
pub(crate) struct Server(pub(crate) dedens_server::Server);

/// The port of DNS over TLS (RFC 7858 §3.1) and over QUIC (RFC 9250 §4.1.1).
const ENCRYPTED_PORT: u16 = 853;

/// The port of DNS over HTTPS (RFC 8484 §3, RFC 9110 §4.2.2).
const HTTPS_PORT: u16 = 443;

/// The port of CoAP (RFC 7252 §6.1; RFC 9953 §3).
#[cfg(feature = "doc")]
const COAP_PORT: u16 = 5683;

impl TryFrom<String> for Server {
    type Error = String;

    fn try_from(text: String) -> Result<Self, String> {
        let (rest, scheme) = match text.split_once("://") {
            Some((scheme, rest)) => (rest, Some(scheme)),
            None => (text.as_str(), None),
        };
        let (rest, name) = match rest.split_once('#') {
            Some((rest, name)) if scheme.is_some() => (rest, Some(name)),
            _ => (rest, None),
        };
        let (rest, path) = match scheme {
            Some("https") => {
                let (rest, path) =
                    split_path(rest).map_err(|error| format!("`{text}`: {error}"))?;
                (rest, Some(path))
            }
            _ => (rest, None),
        };
        let port = match scheme {
            None => 53,
            Some("https") => HTTPS_PORT,
            Some(_) => ENCRYPTED_PORT,
        };
        let addr = address(rest, port)
            .ok_or_else(|| format!("`{text}`: `{rest}` is neither IP:PORT nor IP"))?;
        if let Some(name) = name
            && ServerName::try_from(name).is_err()
        {
            return Err(format!("`{text}`: `{name}` is not a name for TLS"));
        }
        if let Some(path) = &path {
            let probe = dedens_net::client::Server {
                addr,
                name: name
                    .and_then(|name| ServerName::try_from(name).ok().map(|name| name.to_owned())),
                doh: None,
                docpath: Vec::new(),
            };
            probe
                .template_at(path)
                .map_err(|error| format!("`{text}`: {error}"))?;
        }
        let name = name.map(Arc::from);
        let via = match scheme {
            None => Via::Plain,
            Some("tls") => Via::Tls(name),
            Some("quic") => Via::Quic(name),
            Some("https") => Via::Https {
                name,
                path: path.unwrap_or_else(|| Arc::from(DEFAULT_PATH)),
            },
            Some(scheme) => {
                return Err(format!(
                    "`{text}`: `{scheme}://` is not tls://, quic:// or https://"
                ));
            }
        };
        Ok(Self(dedens_server::Server { addr, via }))
    }
}

/// A configuration ready to serve.
#[derive(Debug)]
pub(crate) struct Config {
    pub(crate) listen: Vec<Listen>,
    /// The certificate presented over TLS and QUIC: there when `listen` has such an address.
    pub(crate) presented: Option<Presented>,
    /// The serving threads, each with its own sockets on every `listen` address (D42, D115).
    pub(crate) threads: usize,
    /// Who to run as once the sockets are bound (D122).
    pub(crate) user: Option<Identity>,
    /// The Oblivious `DoH` target's settings, there when `odoh` is: the key is read at start only.
    #[cfg(feature = "odoh")]
    pub(crate) odoh: Option<crate::odoh::Section>,
    pub(crate) pipeline: Pipeline,
    /// Where the access lists come from (D91).
    pub(crate) access: AccessSource,
    pub(crate) downloads: Downloads,
    /// What upstream servers over TLS and QUIC are checked against.
    pub(crate) trust: Trust,
}

/// The stage of a hosts file and entries (`file` is read at start, `entries` are inline).
fn hosts(
    name: &str,
    entries: &[String],
    file: Option<&Path>,
    ttl: Option<u32>,
    fallthrough: bool,
) -> anyhow::Result<Stage> {
    let ttl = Ttl::from_wire(ttl.unwrap_or(PLUGIN_TTL));
    let hosts = local(entries, file, |text| {
        Ok(Hosts::new(text, ttl, fallthrough)?)
    })
    .with_context(|| format!("stage `{name}`"))?;
    Ok(Stage::Plugin(Box::new(hosts)))
}

/// Reads `text`, a configuration file, taking `${VAR}` from `env`. The cache stage of `previous`, the pipeline a
/// reload replaces, is kept when its settings are unchanged, so its answers stay.
///
/// # Errors
///
/// A variable without a value, YAML that does not fit the model (an unknown field, a duplicate name), a stage
/// listed but not defined, defined but not listed, listed twice or after a forward stage, which never passes a
/// query on; a second cache stage, which would never be filled; a hosts or blocklist stage after a cache stage,
/// whose answers a reload keeps; `refresh_minutes` above a year; `threads` above 1024, or above 1 off Linux; `timeout_ms`
/// above 30 s or `tries` above 5 on a forward stage; a TLS key file others can access ([`guard_key`]); a variable
/// that is neither plain nor alone as a value ([`written`]); a saved list that cannot be read ([`lists`]); settings
/// a stage refuses; an `access` network that is malformed or has bits set past its length, an unknown `action`;
/// `rrl` settings out of bounds, a cookie `secret` that is not 32 hexadecimal digits, `accept` without a `secret`;
/// a `group` without a `user`, a `user` off Linux (D122).
pub(crate) fn read(
    text: &str,
    env: impl Fn(&str) -> Option<String>,
    previous: &Pipeline,
    store: &mut Store,
) -> anyhow::Result<Config> {
    store.begin();
    let config = build(text, env, previous, store)?;
    store.end();
    Ok(config)
}

/// [`read`], the lists it reads taken from `store`, and put there.
fn build(
    text: &str,
    env: impl Fn(&str) -> Option<String>,
    previous: &Pipeline,
    store: &mut Store,
) -> anyhow::Result<Config> {
    let text = interpolate(text, env)?;
    // No snippet of the YAML in an error: it could echo the `urls` (D104). The line and column stay.
    let file: File =
        serde_saphyr::from_str_with_options(&text, serde_saphyr::options! { with_snippet: false })?;
    ensure!(!file.listen.is_empty(), "`listen` has no address");
    let threads = serving_threads(
        file.threads,
        cfg!(target_os = "linux"),
        thread::available_parallelism().map_or(1, usize::from),
    )?;
    let user = Identity::new(file.user, file.group, cfg!(target_os = "linux"))?;
    let presented = presented(&file.listen, file.tls.as_ref())?;
    #[cfg(feature = "odoh")]
    let odoh = section(file.odoh.as_ref(), &file.listen)?;
    #[cfg(not(feature = "odoh"))]
    ensure!(
        file.odoh.is_none(),
        "`odoh` needs a dedensd built with the odoh feature"
    );
    ensure!(!file.pipeline.is_empty(), "`pipeline` has no stage");
    let source = AccessSource::of(file.access.as_ref());
    let guard = Guard {
        access: file.access,
        rrl: file.rrl,
        cookies: file.cookies,
    };
    let mut stages = file.stages;
    let mut built = Vec::with_capacity(file.pipeline.len());
    let mut downloads = Downloads::new(file.downloads)?;
    for (index, name) in file.pipeline.iter().enumerate() {
        let Some(stage) = stages.remove(name) else {
            if file.pipeline[..index].contains(name) {
                bail!("stage `{name}` is listed twice in `pipeline`");
            }
            bail!("stage `{name}` is listed in `pipeline` but not defined in `stages`");
        };
        placed(name, &stage, &built)?;
        built.push(match stage {
            StageFile::Cache(config) => cache(name, config, previous)?,
            StageFile::Forward {
                servers,
                timeout_ms,
                tries,
                dnssec,
                trust_anchors,
                insecure,
                client_share,
            } => {
                let validation = Validation {
                    dnssec,
                    trust_anchors,
                    insecure,
                    client_share,
                };
                Stage::Forward(forward(
                    name, servers, timeout_ms, tries, validation, previous,
                )?)
            }
            StageFile::Hosts {
                entries,
                file,
                ttl,
                fallthrough,
            } => hosts(name, &entries, file.as_deref(), ttl, fallthrough)?,
            StageFile::Blocklist {
                entries,
                file,
                urls,
                allow,
                action,
                ttl,
                tlds,
            } => {
                let block = Sources::new(entries, file, urls);
                blocklist(
                    name,
                    (block, allow),
                    (action, ttl, tlds),
                    (&mut downloads, store),
                )?
            }
        });
    }
    if let Some(name) = stages.keys().next() {
        bail!("stage `{name}` is defined but not listed in `pipeline`");
    }
    // Answers kept across a reload carry the verdict of the validator that made them, AD included: another
    // validator, or none, does not stand behind them (D77).
    flush(&mut built, previous)?;
    let pipeline = guard.around(built, previous)?;
    Ok(Config {
        listen: file.listen,
        presented,
        threads,
        user,
        #[cfg(feature = "odoh")]
        odoh,
        pipeline,
        access: source,
        downloads,
        trust: trusted(file.upstream_ca.as_deref())?,
    })
}

/// The blocklist stage `name` of the lists `block` and `allow`, with its `action` and `ttl`; the URLs it downloads are
/// added to `downloads`.
///
/// # Errors
///
/// A list that does not read, or a saved copy that exists but cannot be read (D115).
fn blocklist(
    name: &str,
    (block, allow): (Sources, Sources),
    (action, ttl, tlds): (Option<Action>, Option<u32>, bool),
    (downloads, store): (&mut Downloads, &mut Store),
) -> anyhow::Result<Stage> {
    let tlds = if tlds { Tlds::Allow } else { Tlds::Refuse };
    let lists = lists(name, &block, &allow, tlds, (&downloads.dir, store))
        .with_context(|| format!("stage `{name}`"))?;
    downloads.add(block.urls.into_iter().chain(allow.urls));
    let ttl = Ttl::from_wire(ttl.unwrap_or(PLUGIN_TTL));
    Ok(Stage::Plugin(Box::new(Blocklist::new(
        lists,
        action.unwrap_or_default(),
        ttl,
    ))))
}

/// Replaces the cache stages of `built` that are those of `previous` with empty ones when the forward stages
/// validate differently.
fn flush(built: &mut [Stage], previous: &Pipeline) -> anyhow::Result<()> {
    if validations(previous.stages()) == validations(built) {
        return Ok(());
    }
    for stage in built {
        if let Stage::Cache(kept) = stage
            && previous
                .stages()
                .iter()
                .any(|old| matches!(old, Stage::Cache(old) if Arc::ptr_eq(old, kept)))
        {
            *kept = Arc::new(Cache::new(kept.config().clone()).context("the cache stage")?);
        }
    }
    Ok(())
}

/// How each forward stage of `stages` validates, in order: a cache stage built before is only good for the verdicts
/// it was filled with.
fn validations(stages: &[Stage]) -> Vec<Option<&str>> {
    stages
        .iter()
        .filter_map(|stage| match stage {
            Stage::Forward(forward) => Some(forward.validation_tag()),
            _ => None,
        })
        .collect()
}

/// The cache stage `name` of `config`: the one of `previous` while its settings stay, so that a reload keeps the
/// entries.
///
/// # Errors
///
/// Settings the cache refuses.
fn cache(name: &str, config: dedens_cache::Config, previous: &Pipeline) -> anyhow::Result<Stage> {
    let kept = previous.stages().iter().find_map(|stage| match stage {
        Stage::Cache(cache) if *cache.config() == config => Some(Arc::clone(cache)),
        _ => None,
    });
    Ok(match kept {
        Some(cache) => Stage::Cache(cache),
        None => Stage::Cache(Arc::new(
            Cache::new(config).with_context(|| format!("stage `{name}`"))?,
        )),
    })
}

/// The forward stage `name` of `servers`, with the timeout and tries it sets, validating as `validation` says; with the
/// validator of `previous` when a forward stage of it validated the same way, so that a reload keeps the keys it
/// cached (D86).
///
/// # Errors
///
/// A stage without a server, a `timeout_ms` above [`MAX_TIMEOUT_MS`] or `tries` above [`MAX_TRIES`].
fn forward(
    name: &str,
    servers: Vec<Server>,
    timeout_ms: Option<NonZeroU32>,
    tries: Option<NonZeroU8>,
    validation: Validation,
    previous: &Pipeline,
) -> anyhow::Result<Forward> {
    let mut forward = Forward::new(servers.into_iter().map(|server| server.0))
        .with_context(|| format!("stage `{name}` has no server"))?;
    match validation.dnssec {
        Dnssec::Off => ensure!(
            validation.trust_anchors.is_none()
                && validation.insecure.is_empty()
                && validation.client_share.is_none(),
            "stage `{name}`: `trust_anchors`, `insecure` and `client_share` need `dnssec: validate`"
        ),
        Dnssec::Validate => {
            let validating = validating(validation.trust_anchors.as_deref(), validation.insecure)?;
            let kept = previous.stages().iter().find_map(|stage| match stage {
                Stage::Forward(old) => old.validation().filter(|old| old.tag() == validating.tag()),
                _ => None,
            });
            let mut validating = kept.cloned().unwrap_or(validating);
            // The shares are not part of what the keys were validated by: a reload that changes them keeps the
            // key cache and starts the shares' buckets again.
            let share = BudgetFile::over(validation.client_share, DEFAULT_SHARE);
            if validating.share() != share {
                validating = validating.sharing(
                    Budgets::new(share)
                        .with_context(|| format!("stage `{name}`: `client_share`"))?,
                );
            }
            forward = forward.validating(validating);
        }
    }
    if let Some(ms) = timeout_ms {
        ensure!(
            ms.get() <= MAX_TIMEOUT_MS,
            "stage `{name}`: `timeout_ms` is above {MAX_TIMEOUT_MS}, 30 s"
        );
        forward = forward.with_timeout(Duration::from_millis(u64::from(ms.get())));
    }
    if let Some(tries) = tries {
        ensure!(
            tries.get() <= MAX_TRIES,
            "stage `{name}`: `tries` is above {MAX_TRIES}"
        );
        forward = forward.with_tries(tries);
    }
    Ok(forward)
}

/// A name `insecure` leaves unvalidated (RFC 7646): in presentation format, the root's `.` included.
#[derive(Debug, Clone, Deserialize)]
#[serde(try_from = "String")]
struct Insecure(Name<'static>);

impl TryFrom<String> for Insecure {
    type Error = String;

    fn try_from(text: String) -> Result<Self, String> {
        text.parse()
            .map(Self)
            .map_err(|error| format!("`{text}` is not a name: {error}"))
    }
}

/// What a forward stage says of validation (D77).
struct Validation {
    dnssec: Dnssec,
    trust_anchors: Option<PathBuf>,
    insecure: Vec<Insecure>,
    client_share: Option<BudgetFile>,
}

/// Whether a forward stage validates (D77): `off` or `validate`. The YAML reader takes an unquoted `off` for the
/// boolean `false` once the stage's fields are buffered for the `type` tag, so that is read as `off` too.
#[derive(Debug, Default, Clone, Copy, Deserialize)]
#[serde(try_from = "DnssecText")]
enum Dnssec {
    #[default]
    Off,
    Validate,
}

#[derive(Deserialize)]
#[serde(untagged)]
enum DnssecText {
    Flag(bool),
    Name(String),
}

impl TryFrom<DnssecText> for Dnssec {
    type Error = String;

    fn try_from(text: DnssecText) -> Result<Self, String> {
        match text {
            DnssecText::Flag(false) => Ok(Self::Off),
            DnssecText::Name(name) if name == "off" => Ok(Self::Off),
            DnssecText::Name(name) if name == "validate" => Ok(Self::Validate),
            DnssecText::Flag(true) => Err("`dnssec` is `off` or `validate`, not `true`".to_owned()),
            DnssecText::Name(name) => Err(format!("`dnssec` is `off` or `validate`, not `{name}`")),
        }
    }
}

/// The validator of a forward stage: the anchors of `trust_anchors`, the root's unless set, and a negative anchor
/// for each name of `insecure` (RFC 7646), checked against the clock of the system (D77).
///
/// # Errors
///
/// A `trust_anchors` file that does not read or holds no anchor.
fn validating(trust_anchors: Option<&Path>, insecure: Vec<Insecure>) -> anyhow::Result<Validating> {
    let mut tag = String::from("validate");
    let mut anchors = match trust_anchors {
        None => TrustAnchors::root(),
        Some(path) => {
            let text = fs::read_to_string(path)
                .with_context(|| format!("`trust_anchors`: cannot read {}", path.display()))?;
            tag.push_str("\nanchors ");
            tag.push_str(&text);
            TrustAnchors::read(&text)
                .with_context(|| format!("`trust_anchors`: {}", path.display()))?
        }
    };
    for Insecure(name) in insecure {
        tag.push_str("\ninsecure ");
        tag.push_str(&name.to_string());
        anchors.add_negative(name);
    }
    Ok(Validating::new(
        Validator::new(anchors, Limits::default()),
        Arc::new(unix_seconds),
    )
    .tagged(&tag))
}

/// The Oblivious `DoH` target settings of `odoh`, if any (D79, D94). The key is not read: a reload builds this again,
/// and the key is read at start (D79).
///
/// # Errors
///
/// `odoh` without an `https://` address in `listen`, or a proxy without a target or with one that is not `HOST[:PORT]`.
#[cfg(feature = "odoh")]
fn section(
    odoh: Option<&OdohFile>,
    listen: &[Listen],
) -> anyhow::Result<Option<crate::odoh::Section>> {
    let Some(odoh) = odoh else {
        return Ok(None);
    };
    ensure!(
        listen
            .iter()
            .any(|listen| matches!(listen, Listen::Https(..))),
        "`odoh` is served over HTTP/3: `listen` has no https:// address"
    );
    let proxy = odoh
        .proxy
        .as_ref()
        .map(|proxy| crate::odoh::proxy::Settings::new(&proxy.targets, proxy.timeout_ms))
        .transpose()?;
    let default = crate::odoh::Limits::default();
    let limits = crate::odoh::Limits {
        client: BudgetFile::over(odoh.client_budget, default.client),
        global: BudgetFile::over(odoh.budget, default.global),
    };
    Ok(Some(crate::odoh::Section::new(
        odoh.key.as_deref(),
        proxy,
        limits,
    )))
}

/// The certificate of `tls`, read from its files, when `listen` has an address over TLS, QUIC or HTTP/3.
///
/// # Errors
///
/// A certificate without such an address or the reverse, a file that does not read, a chain without a certificate,
/// a file without a key, a key file others can access ([`guard_key`]), or a key that is not the certificate's.
fn presented(listen: &[Listen], tls: Option<&TlsFile>) -> anyhow::Result<Option<Presented>> {
    let encrypted = listen.iter().any(Listen::encrypted);
    let tls = match (tls, encrypted) {
        (Some(tls), true) => tls,
        (None, false) => return Ok(None),
        (None, true) => {
            bail!("`listen` has a tls://, quic:// or https:// address, and `tls` no certificate")
        }
        (Some(_), false) => {
            bail!("`tls` has a certificate, and `listen` no tls://, quic:// or https:// address")
        }
    };
    let path = tls.certificate.display();
    let chain = CertificateDer::pem_file_iter(&tls.certificate)
        .and_then(Iterator::collect::<Result<Vec<_>, _>>)
        .with_context(|| format!("`tls`: cannot read certificates from {path}"))?;
    ensure!(!chain.is_empty(), "`tls`: no certificate in {path}");
    let unreadable = || {
        format!(
            "`tls`: cannot read a private key from {}",
            tls.key.display()
        )
    };
    let file = fs::File::open(&tls.key).with_context(unreadable)?;
    guard_key(&file, "`tls`", &tls.key)?;
    let key = PrivateKeyDer::from_pem_reader(io::BufReader::new(file)).with_context(unreadable)?;
    let presented = Presented::new(chain, key)
        .with_context(|| format!("`tls`: the key does not fit {path}"))?;
    Ok(Some(presented))
}

/// Checks the private key file `file`, opened from `path` for `setting` (`tls` or `odoh`), on the file itself, so that
/// no swap of the path comes between the check and the read: the key stays unused when others can access it, and
/// is warned about when its group can (D115). `ssh` and PostgreSQL refuse a key others can access; the group is
/// allowed, as PostgreSQL allows a root-owned key its group: quietly for a root-owned key whose group the process is
/// in (`root:dedens` 0640 read by the user `dedens` after the drop of D122, which is read again as that user, or a key
/// shared through Debian's `ssl-cert`), with a warning otherwise. A process that is root is in no such group, and
/// reads any key: a root-owned key is not warned about then, the read after the drop is the check. Off Unix, where
/// the mode says nothing, nothing is checked.
///
/// # Errors
///
/// A mode that cannot be read, or any permission for others.
#[cfg(unix)]
pub(crate) fn guard_key(file: &fs::File, setting: &str, path: &Path) -> anyhow::Result<()> {
    use std::os::unix::fs::MetadataExt as _;

    use nix::unistd::{Uid, geteuid};
    let shown = path.display();
    let metadata = file
        .metadata()
        .with_context(|| format!("{setting}: cannot read the key {shown}"))?;
    let mode = metadata.mode() & 0o777;
    let (group, others) = (mode & 0o070, mode & 0o007);
    ensure!(
        others == 0,
        "{setting}: the key {shown} can be accessed by others (mode {mode:03o}): chmod 600"
    );
    let shared = metadata.uid() == 0
        && (geteuid() == Uid::from_raw(0) || crate::privileges::in_group(metadata.gid()));
    if group != 0 && !shared {
        tracing::warn!(key = %shown, mode = format!("{mode:03o}"), "{setting}: the key can be accessed by its group: chmod 600 unless the group is meant to");
    }
    Ok(())
}

/// [`guard_key`] off Unix: nothing to check.
#[cfg(not(unix))]
#[expect(clippy::unnecessary_wraps, reason = "the signature of the Unix one")]
pub(crate) fn guard_key(_file: &fs::File, _setting: &str, _path: &Path) -> anyhow::Result<()> {
    Ok(())
}

/// The certificate authorities of the PEM file `path`, the system's without one.
///
/// # Errors
///
/// A file that does not read, or holds no certificate.
fn trusted(path: Option<&Path>) -> anyhow::Result<Trust> {
    let Some(path) = path else {
        return Ok(Trust::System);
    };
    let certificates = CertificateDer::pem_file_iter(path)
        .and_then(Iterator::collect::<Result<Vec<_>, _>>)
        .with_context(|| {
            format!(
                "`upstream_ca`: cannot read certificates from {}",
                path.display()
            )
        })?;
    ensure!(
        !certificates.is_empty(),
        "`upstream_ca`: no certificate in {}",
        path.display()
    );
    Ok(Trust::Roots(certificates))
}

/// The TTL of plugin records unless set, as the hosts plugin of `CoreDNS` gives them.
const PLUGIN_TTL: u32 = 3600;

/// Where downloaded lists are kept unless set, as the FHS places a program's cache.
const DOWNLOADS_DIR: &str = "/var/cache/dedensd";

/// How often downloaded lists are fetched again unless set: once a day, as numa and Pi-hole do.
const REFRESH_MINUTES: u64 = 1440;

/// The longest `timeout_ms` of a forward stage, 30 s: the cap of the `timeout` option of the system resolver
/// (`resolv.conf(5)`), between the 4 s a BIND stub resolver starts at and the 45 s ceiling of BIND's backoff
/// (RFC 1536 §1), and far above the 3 s default. The bound stops a typo (`timeout_ms: 300000000` is 3.5 days)
/// holding a query, its task and its socket (D115).
const MAX_TIMEOUT_MS: u32 = 30_000;

/// The most `tries` of a forward stage: the cap of the `attempts` option of the system resolver (`resolv.conf(5)`),
/// and the default of `outbound-msg-retry` in Unbound. A stage with several servers asks each `tries` times, so
/// the longest wait for a query is servers × `tries` × `timeout_ms` (D115).
const MAX_TRIES: u8 = 5;

/// The most `threads` that may be written: each holds a buffer pool of about 1 MiB and, per UDP socket, a
/// 4 MiB receive buffer, so the bound stops a typo, not a machine (D115).
const MAX_THREADS: usize = 1024;

/// The longest `refresh_minutes`: a year, far below the overflow of a `Duration` or an `Instant`.
const MAX_REFRESH_MINUTES: u64 = 366 * 1440;

/// The serving threads from `threads` as written: that many, or one per core of `cores` on Linux and one elsewhere,
/// where `SO_REUSEPORT` does not spread queries across the sockets of threads and a second would serve none (D42).
///
/// # Errors
///
/// Above [`MAX_THREADS`], or above one off Linux.
fn serving_threads(
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

/// Checks that stage `name`, `stage`, may follow the stages `built`.
///
/// # Errors
///
/// Any stage after a forward stage, which answers every query; a second cache stage, which would never be
/// filled; a hosts or blocklist stage after a cache stage, whose answers a reload keeps (D64).
fn placed(name: &str, stage: &StageFile, built: &[Stage]) -> anyhow::Result<()> {
    if let Some(Stage::Forward(_)) = built.last() {
        bail!("stage `{name}` comes after a forward stage, which answers every query");
    }
    let cached = built.iter().any(|stage| matches!(stage, Stage::Cache(_)));
    match stage {
        StageFile::Cache(_) if cached => {
            bail!("stage `{name}` is a second cache stage, which upstream answers would never fill")
        }
        StageFile::Hosts { .. } | StageFile::Blocklist { .. } if cached => bail!(
            "stage `{name}` comes after a cache stage, whose answers, kept across reloads, would bypass it"
        ),
        _ => Ok(()),
    }
}

/// How often downloaded lists are fetched again, from `refresh_minutes`.
///
/// # Errors
///
/// Above [`MAX_REFRESH_MINUTES`].
fn refresh(minutes: Option<NonZeroU64>) -> anyhow::Result<Duration> {
    let minutes = minutes.map_or(REFRESH_MINUTES, u64::from);
    ensure!(
        minutes <= MAX_REFRESH_MINUTES,
        "`refresh_minutes` is above {MAX_REFRESH_MINUTES}, a year"
    );
    Ok(Duration::from_mins(minutes))
}

/// What `read` makes of `entries`, then the lines of the file at `path`, its byte order mark left out, as one
/// text; its errors locate the line.
fn local<P>(
    entries: &[String],
    path: Option<&Path>,
    read: impl FnOnce(&str) -> Result<P, ListError>,
) -> anyhow::Result<P> {
    let mut text = String::new();
    for entry in entries {
        text.push_str(entry);
        text.push('\n');
    }
    let before = text.lines().count();
    if let Some(path) = path {
        let file =
            fs::read_to_string(path).with_context(|| format!("reading `{}`", path.display()))?;
        text.push_str(file.strip_prefix('\u{feff}').unwrap_or(&file));
    }
    read(&text).map_err(|error| {
        let ListError::Line(error) = error else {
            return anyhow!(error);
        };
        match (
            error.line.checked_sub(before).filter(|&line| line > 0),
            path,
        ) {
            (Some(line), Some(path)) => anyhow!("`{}` line {line}: {}", path.display(), error.kind),
            _ => anyhow!("entry {}: {}", error.line, error.kind),
        }
    })
}

/// The lists of the blocklist stage `stage`, `block` and `allow` taken from `store`, which reads them when they
/// changed (D120), their downloaded ones from their copies in `dir`; logs the counts. A list not downloaded yet is
/// empty until it is, so a blocklist fails open until the first fetch, and a copy that is not a list is left out
/// with a warning: neither stops the server (D115).
///
/// # Errors
///
/// A copy that exists but cannot be read (permissions, a directory): the start or the reload is refused rather
/// than serving without the list, which the next fetch would not mend.
fn lists(
    stage: &str,
    block: &Sources,
    allow: &Sources,
    tlds: Tlds,
    (dir, store): (&Path, &mut Store),
) -> anyhow::Result<Lists> {
    let block = side(stage, block, tlds, (dir, store))?;
    let allow = side(stage, allow, tlds, (dir, store))?;
    tracing::info!(
        stage,
        blocked = block.len(),
        allowed = allow.len(),
        duplicates = block.duplicates() + allow.duplicates(),
        "blocklist read"
    );
    Ok(Lists::from_merged(tlds, block, allow))
}

/// The names of `sources` as one set, in the order entries, file, URLs, as [`lists`] says.
fn side(
    stage: &str,
    sources: &Sources,
    tlds: Tlds,
    (dir, store): (&Path, &mut Store),
) -> anyhow::Result<Merged> {
    let mut names = Vec::from_iter(store.entries(&sources.entries, tlds)?);
    if let Some(path) = &sources.file {
        names.push(store.file(path, tlds)?);
    }
    for Url(url) in &sources.urls {
        let copy = download::copy(dir, url);
        match store.saved(&copy, &download::redacted(url)) {
            Ok(saved) => match saved.check(tlds) {
                Ok(_) => names.push(saved),
                Err(error) => {
                    tracing::warn!(stage, url = download::redacted(url), %error, "the saved copy is not a list");
                }
            },
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                tracing::info!(
                    stage,
                    url = download::redacted(url),
                    "list not downloaded yet"
                );
            }
            Err(error) => {
                return Err(error).with_context(|| format!("reading `{}`", copy.display()));
            }
        }
    }
    store.merged(tlds, &names)
}

/// `text` with each `${VAR}` replaced by the variable's value, written so that it is one value, never YAML
/// ([`written`], D115), `${VAR:-default}` by `default` as written when it is unset or empty, and `$$` by `$`; any
/// other `$` stays, and so does a line whose first non-blank character is `#`, a comment.
///
/// # Errors
///
/// A variable without a value or default, one whose value [`written`] refuses, or a `${` left open on its line.
fn interpolate(text: &str, env: impl Fn(&str) -> Option<String>) -> anyhow::Result<String> {
    let mut out = String::with_capacity(text.len());
    for line in text.split_inclusive('\n') {
        if line.trim_start().starts_with('#') {
            out.push_str(line);
        } else {
            interpolate_line(line, &env, &mut out)?;
        }
    }
    Ok(out)
}

/// How the value of variable `name` is written where `${name}` stands between `before` and `after`, the rest of its
/// line in the template: a value cannot add YAML of its own (D44, D115).
/// - A plain value, made of letters, digits and `_./:@+=%~#-` that YAML cannot read as syntax (it does not start
///   with `#`, `@`, `%`, `---`, `...` or end with `:`, and is not `-` or `?`), is written as it is: ports,
///   addresses, paths and URLs stay usable anywhere, in a number or in a quoted text.
/// - Between quotes of the template, it is escaped for them.
/// - Alone as a value (a whole scalar: after `key:`, `-`, `,` or `[` in a flow, before a `,`, a `]`, a `}`, a
///   comment or the end of the line), it is written in single quotes.
///
/// # Errors
///
/// A value spanning lines (`\n` or `\r`), with another control character or a Unicode line separator, which a
/// YAML reader may take for a line break; one that is not plain and is part of a larger value, for which no
/// quoting is right.
fn written(name: &str, value: &str, before: &str, after: &str) -> anyhow::Result<String> {
    ensure!(
        !value.contains(['\n', '\r']),
        "variable `{name}` spans several lines"
    );
    ensure!(
        !value
            .chars()
            .any(|c| c.is_control() || matches!(c, '\u{2028}' | '\u{2029}')),
        "variable `{name}` has a control character"
    );
    let plain = value
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || "_./:@+=%~#-".contains(c))
        && !value.starts_with(['#', '@', '%'])
        && !value.starts_with("---")
        && !value.starts_with("...")
        && !value.ends_with(':')
        && !matches!(value, "-" | "?");
    if plain {
        return Ok(value.to_owned());
    }
    if before.ends_with('\'') && after.starts_with('\'') {
        return Ok(value.replace('\'', "''"));
    }
    if before.ends_with('"') && after.starts_with('"') {
        return Ok(value.replace('\\', "\\\\").replace('"', "\\\""));
    }
    ensure!(
        alone(before, after),
        "variable `{name}` is not alone as a value and holds text YAML could read as syntax: put `${{{name}}}` alone, or between quotes"
    );
    Ok(format!("'{}'", value.replace('\'', "''")))
}

/// Whether a placeholder between `before` and `after` makes a whole YAML scalar, a mapping's key or value or an
/// entry of a sequence or of a flow collection. Reads the line of the template only: it is the template author's.
fn alone(before: &str, after: &str) -> bool {
    let flow = before.matches(['[', '{']).count() > before.matches([']', '}']).count();
    let head = before.trim_end();
    let spaced = head.len() < before.len();
    let starts = head.is_empty()
        || (flow && head.ends_with(['[', '{', ',']))
        || (spaced && head.ends_with(':'))
        || (spaced && head.chars().all(|c| c == '-' || c.is_whitespace()));
    let tail = after.trim_start();
    let ends = tail.is_empty()
        || (tail.len() < after.len() && tail.starts_with('#'))
        || (flow && tail.starts_with([',', ']', '}']))
        || tail
            .strip_prefix(':')
            .is_some_and(|rest| rest.is_empty() || rest.starts_with(char::is_whitespace));
    starts && ends
}

/// [`interpolate`] for one line, not a comment, appended to `out`.
fn interpolate_line(
    line: &str,
    env: impl Fn(&str) -> Option<String>,
    out: &mut String,
) -> anyhow::Result<()> {
    let mut rest = line;
    while let Some(at) = rest.find('$') {
        out.push_str(&rest[..at]);
        rest = &rest[at..];
        if let Some(after) = rest.strip_prefix("$$") {
            out.push('$');
            rest = after;
        } else if let Some(after) = rest.strip_prefix("${") {
            let end = after.find('}').context("a `${` is not closed by `}`")?;
            let (name, default) = match after[..end].split_once(":-") {
                Some((name, default)) => (name, Some(default)),
                None => (&after[..end], None),
            };
            ensure!(
                !name.is_empty() && name.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_'),
                "`${{{}}}` does not name a variable",
                &after[..end]
            );
            let after = &after[end + 1..];
            match (env(name).filter(|value| !value.is_empty()), default) {
                (Some(value), _) => {
                    let before = &line[..line.len() - rest.len()];
                    out.push_str(&written(name, &value, before, after)?);
                }
                (None, Some(default)) => out.push_str(default),
                (None, None) => bail!("variable `{name}` is not set"),
            }
            rest = after;
        } else {
            out.push('$');
            rest = &rest[1..];
        }
    }
    out.push_str(rest);
    Ok(())
}

#[cfg(test)]
mod tests {
    use dedens_plugins::List;
    use dedens_server::Standing;

    use super::*;

    /// [`super::read`] with a store of its own.
    fn read(
        text: &str,
        env: impl Fn(&str) -> Option<String>,
        previous: &Pipeline,
    ) -> anyhow::Result<Config> {
        super::read(text, env, previous, &mut Store::default())
    }

    fn env(name: &str) -> Option<String> {
        match name {
            "PORT" => Some("5353".to_owned()),
            "TEXT" => Some("a: b #c".to_owned()),
            "QUOTE" => Some("it's".to_owned()),
            "DOUBLE" => Some(r#"say "hi"\"#.to_owned()),
            "HASH" => Some("#x".to_owned()),
            "TAB" => Some("a\tb".to_owned()),
            "NEL" => Some("a\u{85}b".to_owned()),
            "SEPARATOR" => Some("a\u{2028}b".to_owned()),
            "URL" => Some("tls://9.9.9.9#dns.quad9.net".to_owned()),
            "EMPTY" => Some(String::new()),
            "LINES" => Some("a\nb".to_owned()),
            "RETURN" => Some("a\rb: c".to_owned()),
            "DIGITS" => Some("12345678901234567890123456789012".to_owned()),
            _ => None,
        }
    }

    fn error(text: &str) -> String {
        format!(
            "{:#}",
            read(text, env, &Pipeline::default()).expect_err("refused")
        )
    }

    const MINIMAL: &str = "listen: ['127.0.0.1:53']\npipeline: [up]\nstages:\n  up:\n    type: forward\n    servers: ['192.0.2.1']\n";

    #[test]
    fn variables_are_replaced() {
        assert_eq!(interpolate("a ${PORT} b", env).unwrap(), "a 5353 b");
        assert_eq!(interpolate("${NOPE:-53}${EMPTY:-x}", env).unwrap(), "53x");
        assert_eq!(interpolate("$$ $PORT $", env).unwrap(), "$ $PORT $");
        // Comments are left as written, even with a variable unset or a `${` left open.
        let comments = "# ${NOPE}\n  # ${PORT\nport: ${PORT} # ${PORT}\n";
        assert_eq!(
            interpolate(comments, env).unwrap(),
            "# ${NOPE}\n  # ${PORT\nport: 5353 # 5353\n"
        );
    }

    #[test]
    fn variables_without_a_value_are_refused() {
        for (text, message) in [
            ("${NOPE}", "variable `NOPE` is not set"),
            ("${EMPTY}", "variable `EMPTY` is not set"),
            ("${LINES}", "variable `LINES` spans several lines"),
            ("${RETURN}", "variable `RETURN` spans several lines"),
            ("a: ${PORT\n}", "a `${` is not closed by `}`"),
            ("${PORT", "a `${` is not closed by `}`"),
            ("${}", "`${}` does not name a variable"),
            ("${A B}", "`${A B}` does not name a variable"),
        ] {
            let refused = interpolate(text, env).expect_err(text);
            assert_eq!(refused.to_string(), message);
        }
    }

    #[test]
    fn upstream_servers_take_port_53_by_default_853_encrypted_and_443_over_https() {
        let server =
            |text: &str| Server::try_from(text.to_owned()).map(|server| server.0.to_string());
        for (written, read) in [
            ("192.0.2.1", "192.0.2.1:53"),
            ("[2001:db8::1]:5353", "[2001:db8::1]:5353"),
            ("2001:db8::1", "[2001:db8::1]:53"),
            ("[2001:db8::1]", "[2001:db8::1]:53"),
            (
                "tls://1.1.1.1#one.one.one.one",
                "tls://1.1.1.1:853#one.one.one.one",
            ),
            ("tls://[2001:db8::1]:8853", "tls://[2001:db8::1]:8853"),
            (
                "quic://94.140.14.140#dns.adguard-dns.com",
                "quic://94.140.14.140:853#dns.adguard-dns.com",
            ),
            ("tls://192.0.2.1#192.0.2.1", "tls://192.0.2.1:853#192.0.2.1"),
            (
                "https://9.9.9.9#dns.quad9.net",
                "https://9.9.9.9:443/dns-query#dns.quad9.net",
            ),
            (
                "https://[2001:db8::1]:8443/doh/query",
                "https://[2001:db8::1]:8443/doh/query",
            ),
        ] {
            assert_eq!(server(written).as_deref(), Ok(read), "{written}");
        }
        for refused in [
            "example.com",
            "tls://dns.google",
            "https://dns.quad9.net/dns-query",
            "https://192.0.2.1/dns-query?dns=",
            "https://192.0.2.1/{?dns}",
            "https://192.0.2.1/a b",
            "192.0.2.1#dns.example",
            "https://192.0.2.1#",
            "tls://192.0.2.1#",
            "tls://192.0.2.1#not a name",
        ] {
            assert!(server(refused).is_err(), "{refused}");
        }
    }

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

    #[test]
    fn upstream_certificate_authorities_are_read() {
        let refused = read(
            &format!("upstream_ca: /nonexistent.pem\n{MINIMAL}"),
            env,
            &Pipeline::default(),
        );
        assert!(refused.unwrap_err().to_string().contains("`upstream_ca`"));
        assert_eq!(
            read(MINIMAL, env, &Pipeline::default()).unwrap().trust,
            Trust::System
        );
    }

    #[test]
    fn listen_addresses_take_port_853_encrypted_and_443_over_https() {
        for (text, listen) in [
            (
                "127.0.0.1:53",
                Listen::Plain("127.0.0.1:53".parse().unwrap()),
            ),
            (
                "tls://127.0.0.1",
                Listen::Tls("127.0.0.1:853".parse().unwrap()),
            ),
            (
                "tls://[::1]:8853",
                Listen::Tls("[::1]:8853".parse().unwrap()),
            ),
            ("quic://[::1]", Listen::Quic("[::1]:853".parse().unwrap())),
            (
                "https://127.0.0.1",
                Listen::Https("127.0.0.1:443".parse().unwrap(), "/dns-query".into()),
            ),
            (
                "https://[::1]:8443/doh",
                Listen::Https("[::1]:8443".parse().unwrap(), "/doh".into()),
            ),
        ] {
            assert_eq!(Listen::try_from(text.to_owned()), Ok(listen), "{text}");
        }
        for text in [
            "127.0.0.1",
            "https://dns.example",
            "https://127.0.0.1/dns-query?dns=",
            "https://127.0.0.1/{?dns}",
            "https://127.0.0.1#dns.example",
            "https://127.0.0.1:0x1",
            "tls://dns.example",
            "tls://127.0.0.1#dns.example",
        ] {
            assert!(Listen::try_from(text.to_owned()).is_err(), "{text}");
        }
    }

    /// `coap://` takes port 5683 and the path `/` unless set, a path without query, fragment or `%`, with no `.` or
    /// `..` segment, and not the one where the resources are listed (D95).
    #[cfg(feature = "doc")]
    #[test]
    fn coap_listen_addresses_take_port_5683_and_the_root_path() {
        for (text, listen) in [
            (
                "coap://127.0.0.1",
                Listen::Coap("127.0.0.1:5683".parse().unwrap(), "/".into()),
            ),
            (
                "coap://[::1]:5684/dns/query",
                Listen::Coap("[::1]:5684".parse().unwrap(), "/dns/query".into()),
            ),
        ] {
            assert_eq!(Listen::try_from(text.to_owned()), Ok(listen), "{text}");
        }
        for text in [
            "coap://dns.example",
            "coap://127.0.0.1/dns?dns=",
            "coap://127.0.0.1/a#b",
            "coap://127.0.0.1/a%20b",
            "coap://127.0.0.1/.well-known/core",
            "coap://127.0.0.1/a/./b",
            "coap://127.0.0.1/a/..",
        ] {
            assert!(Listen::try_from(text.to_owned()).is_err(), "{text}");
        }
    }

    /// `odoh` needs an `https://` address and a dedensd built for it, and takes a `key` and nothing else (D79).
    #[test]
    fn odoh_needs_an_https_listener() {
        let odoh = |section: &str| format!("odoh:\n{section}{MINIMAL}");
        let error = read(&odoh("  key: /nonexistent\n"), env, &Pipeline::default()).unwrap_err();
        let message = format!("{error:#}");
        #[cfg(feature = "odoh")]
        assert!(
            message.contains("`listen` has no https:// address"),
            "{message}"
        );
        #[cfg(not(feature = "odoh"))]
        assert!(message.contains("built with the odoh feature"), "{message}");
        let error = read(&odoh("  keys: 1\n"), env, &Pipeline::default()).unwrap_err();
        assert!(format!("{error:#}").contains("keys"), "{error:#}");
        let error = read(
            &odoh("  proxy:\n    target: 1\n"),
            env,
            &Pipeline::default(),
        )
        .unwrap_err();
        assert!(format!("{error:#}").contains("target"), "{error:#}");
    }

    /// A proxy lists the targets it forwards to, `HOST[:PORT]` each, and at least one (D94).
    #[cfg(feature = "odoh")]
    #[test]
    fn a_proxy_needs_targets() {
        let listen = [Listen::Https(
            "127.0.0.1:443".parse().unwrap(),
            "/dns-query".into(),
        )];
        let section = |text: &str| {
            let odoh: OdohFile = serde_saphyr::from_str(text).unwrap();
            section(Some(&odoh), &listen)
        };
        assert!(
            section("proxy:\n  targets: [odoh.example, '127.0.0.1:8443']\n  timeout_ms: 100\n")
                .is_ok()
        );
        assert!(section("key: /a\n").is_ok());
        for bad in [
            "proxy:\n  targets: []\n",
            "proxy:\n  targets: ['a b']\n",
            "proxy:\n  targets: ['a:0']\n",
        ] {
            assert!(section(bad).is_err(), "{bad}");
        }
        assert!(serde_saphyr::from_str::<OdohFile>("proxy:\n  timeout_ms: 100\n").is_err());
    }

    /// D117: the target's limits are the defaults unless `budget` and `client_budget` say; zero is refused.
    #[cfg(feature = "odoh")]
    #[test]
    fn an_odoh_target_has_limits() {
        let listen = [Listen::Https(
            "127.0.0.1:443".parse().unwrap(),
            "/dns-query".into(),
        )];
        let section = |text: &str| {
            let odoh: OdohFile = serde_saphyr::from_str(text).unwrap();
            section(Some(&odoh), &listen).unwrap().unwrap()
        };
        let default = crate::odoh::Section::new(None, None, crate::odoh::Limits::default());
        assert_eq!(section("{}"), default);
        let defaults = crate::odoh::Limits::default();
        let limits = crate::odoh::Limits {
            client: Budget {
                per_second: 10,
                burst: 20,
                table: defaults.client.table,
            },
            global: Budget {
                per_second: 99,
                ..defaults.global
            },
        };
        assert_eq!(
            section("budget: {rate: 99}\nclient_budget: {rate: 10, burst: 20}\n"),
            crate::odoh::Section::new(None, None, limits)
        );
        // A reload compares sections, and warns that a change of `odoh` takes a restart: the limits are part of it.
        assert_ne!(section("client_budget: {rate: 10}\n"), default);
        assert_ne!(section("budget: {rate: 10}\n"), default);
        for bad in ["budget: {burst: 0}\n", "client_budget: {rate: 0}\n"] {
            assert!(serde_saphyr::from_str::<OdohFile>(bad).is_err(), "{bad}");
        }
    }

    /// A certificate goes with an address over TLS or QUIC, and the reverse.
    #[test]
    fn tls_listeners_and_a_certificate_go_together() {
        let encrypted = MINIMAL.replace("'127.0.0.1:53'", "'tls://127.0.0.1'");
        let tls = "tls:\n  certificate: /nonexistent.pem\n  key: /nonexistent.pem\n";
        for (text, message) in [
            (encrypted.clone(), "`tls` no certificate"),
            (format!("{tls}{MINIMAL}"), "`listen` no tls://"),
            (format!("{tls}{encrypted}"), "cannot read certificates"),
        ] {
            let error = read(&text, env, &Pipeline::default()).unwrap_err();
            assert!(format!("{error:#}").contains(message), "{error:#}");
        }
        assert!(
            read(MINIMAL, env, &Pipeline::default())
                .unwrap()
                .presented
                .is_none()
        );
    }

    #[test]
    fn a_caching_forwarder_reads() {
        let text = "listen: ['127.0.0.1:${PORT}']\npipeline: [cache, up]\nstages:\n  cache:\n    type: cache\n    min_ttl: 120\n    max_ttl: 3600\n    max_insecure_ttl: 600\n    max_entry_bytes: 4096\n    stale_answer_after_ms: 0\n  up:\n    type: forward\n    servers: ['192.0.2.1', '192.0.2.2:5353']\n    timeout_ms: 500\n    tries: 1\n";
        let config = read(text, env, &Pipeline::default()).unwrap();
        assert_eq!(
            config.listen,
            [Listen::Plain("127.0.0.1:5353".parse().unwrap())]
        );
        let [Stage::Cache(cache), _] = config.pipeline.stages() else {
            panic!("a cache stage, then a forward stage")
        };
        assert_eq!(cache.config().min_ttl, 120);
        assert_eq!(cache.config().max_insecure_ttl, Some(600));
        assert_eq!(cache.config().max_entry_bytes, Some(4096));
        assert!(read(MINIMAL, env, &Pipeline::default()).is_ok());
    }

    /// D91: `access` is optional, and its lists and action read; what does not read is refused with the network
    /// meant.
    #[test]
    fn access_reads() {
        let with = |access: &str| format!("access:\n  {access}\n{MINIMAL}");
        let source = |text: &str| read(text, env, &Pipeline::default()).unwrap().access;
        assert_eq!(source(MINIMAL), AccessSource::Unset);
        for (access, expected) in [
            (
                "allow: ['10.0.0.0/8', '2001:db8::/32']",
                AccessSource::Written,
            ),
            ("allow: ['::/0']", AccessSource::Written),
            (
                "allow: []\n  deny: ['10.9.0.0/16']\n  action: drop",
                AccessSource::NoAllow,
            ),
            ("{}", AccessSource::NoAllow),
        ] {
            assert_eq!(source(&with(access)), expected, "{access}");
        }
        for (access, error) in [
            ("allow: ['192.0.2.1/24']", "`192.0.2.0/24`"),
            (
                "deny: ['192.0.2.0/24', 'nope']",
                "`nope` is not ADDRESS/LENGTH",
            ),
            ("action: Drop", "unknown variant `Drop`"),
            ("allow: '10.0.0.0/8'", "expected sequence"),
        ] {
            let refused = read(&with(access), env, &Pipeline::default()).unwrap_err();
            assert!(
                format!("{refused:#}").contains(error),
                "{access}: {refused:#}"
            );
        }
    }

    #[test]
    fn mistakes_are_errors() {
        for (text, message) in [
            (
                "listen: []\npipeline: [up]\nstages: {}\n",
                "`listen` has no address",
            ),
            (
                "listen: ['127.0.0.1:53']\npipeline: []\nstages: {}\n",
                "`pipeline` has no stage",
            ),
            (
                "listen: ['127.0.0.1:53']\npipeline: [up]\nstages: {}\n",
                "stage `up` is listed in `pipeline` but not defined in `stages`",
            ),
            (
                "listen: ['127.0.0.1:53']\npipeline: [c, c]\nstages:\n  c:\n    type: cache\n",
                "stage `c` is listed twice in `pipeline`",
            ),
            (
                "listen: ['127.0.0.1:53']\npipeline: [c, d]\nstages:\n  c:\n    type: cache\n  d:\n    type: cache\n",
                "stage `d` is a second cache stage, which upstream answers would never fill",
            ),
            (
                "listen: ['127.0.0.1:53']\npipeline: [up, c]\nstages:\n  c:\n    type: cache\n  up:\n    type: forward\n    servers: ['192.0.2.1']\n",
                "stage `c` comes after a forward stage, which answers every query",
            ),
            (
                "listen: ['127.0.0.1:53']\npipeline: [up]\nstages:\n  c:\n    type: cache\n  up:\n    type: forward\n    servers: ['192.0.2.1']\n",
                "stage `c` is defined but not listed in `pipeline`",
            ),
            (
                "listen: ['127.0.0.1:53']\npipeline: [up]\nstages:\n  up:\n    type: forward\n    servers: []\n",
                "stage `up` has no server",
            ),
            (
                "listen: ['127.0.0.1:53']\npipeline: [c]\nstages:\n  c:\n    type: cache\n    shards: 3\n",
                "stage `c`: the shard count must be a power of two up to 65536, not 3",
            ),
            (
                "listen: ['127.0.0.1:53']\npipeline: [c]\nstages:\n  c:\n    type: cache\n    max_ttl: 3600\n    max_insecure_ttl: 3601\n",
                "stage `c`: the insecure TTL must lie within 1 second and `max_ttl`",
            ),
            (
                "listen: ['127.0.0.1:53']\npipeline: [c]\nstages:\n  c:\n    type: cache\n    max_ttl: 3600\n    min_ttl: 3601\n",
                "stage `c`: the minimum TTL must be at most 3600, the least of `max_ttl`, `max_negative_ttl` and the insecure TTL",
            ),
            (
                "listen: ['127.0.0.1:53']\npipeline: [c]\nstages:\n  c:\n    type: cache\n    max_negative_ttl: 59\n",
                "stage `c`: the minimum TTL must be at most 59, the least of `max_ttl`, `max_negative_ttl` and the insecure TTL",
            ),
            (
                "listen: ['127.0.0.1:53']\npipeline: [c]\nstages:\n  c:\n    type: cache\n    max_insecure_ttl: 59\n",
                "stage `c`: the minimum TTL must be at most 59, the least of `max_ttl`, `max_negative_ttl` and the insecure TTL",
            ),
            (
                "listen: ['127.0.0.1:53']\npipeline: [c, h, up]\nstages:\n  c:\n    type: cache\n  h:\n    type: hosts\n  up:\n    type: forward\n    servers: ['192.0.2.1']\n",
                "stage `h` comes after a cache stage, whose answers, kept across reloads, would bypass it",
            ),
            (
                "listen: ['127.0.0.1:53']\npipeline: [c, b]\nstages:\n  c:\n    type: cache\n  b:\n    type: blocklist\n",
                "stage `b` comes after a cache stage, whose answers, kept across reloads, would bypass it",
            ),
            (
                &format!("downloads:\n  refresh_minutes: 18446744073709551615\n{MINIMAL}"),
                "`refresh_minutes` is above 527040, a year",
            ),
        ] {
            assert_eq!(error(text), message);
        }
    }

    /// A hosts stage before the forward stage: entries, then a file, its lines counted from its first.
    #[test]
    fn hosts_read_entries_then_their_file() {
        let path = std::env::temp_dir().join(format!("dedensd-hosts-{}", std::process::id()));
        let stage = |file: &str| {
            format!(
                "listen: ['127.0.0.1:53']\npipeline: [hosts, up]\nstages:\n  hosts:\n    type: hosts\n    entries: ['192.0.2.1 printer.lan', '{{ENTRY}}']\n    file: {}\n    ttl: 60\n    fallthrough: true\n  up:\n    type: forward\n    servers: ['192.0.2.1']\n",
                path.join(file).display()
            )
        };
        std::fs::create_dir_all(&path).unwrap();
        std::fs::write(path.join("good"), "127.0.0.1 localhost\n").unwrap();
        std::fs::write(
            path.join("bad"),
            "# fine\n127.0.0.1 localhost\nnope localhost\n",
        )
        .unwrap();
        let ok = stage("good").replace("{ENTRY}", "192.0.2.2 scanner.lan");
        assert!(read(&ok, env, &Pipeline::default()).is_ok());
        for (text, message) in [
            (
                stage("bad").replace("{ENTRY}", "192.0.2.2 scanner.lan"),
                "line 3: `nope` is not an IP address",
            ),
            (
                stage("good").replace("{ENTRY}", "192.0.2.2"),
                "entry 2: an address without a name",
            ),
            (
                stage("none").replace("{ENTRY}", "192.0.2.2 scanner.lan"),
                "reading",
            ),
        ] {
            let message_read = error(&text);
            assert!(message_read.contains(message), "{message}: {message_read}");
        }
        std::fs::remove_dir_all(&path).unwrap();
    }

    #[test]
    fn a_reload_keeps_the_cache_while_its_settings_stay() {
        let text = |cache: &str| {
            format!(
                "listen: ['127.0.0.1:53']\npipeline: [cache, up]\nstages:\n  cache:\n    type: cache\n{cache}  up:\n    type: forward\n    servers: ['192.0.2.1']\n"
            )
        };
        let cache = |pipeline: &Pipeline| match pipeline.stages().first() {
            Some(Stage::Cache(cache)) => Arc::clone(cache),
            stage => unreachable!("{stage:?}"),
        };
        let first = read(&text(""), env, &Pipeline::default()).unwrap().pipeline;
        let same = read(&text("    max_ttl: 172800\n"), env, &first)
            .unwrap()
            .pipeline;
        assert!(Arc::ptr_eq(&cache(&first), &cache(&same)));
        let changed = read(&text("    max_ttl: 3600\n"), env, &same)
            .unwrap()
            .pipeline;
        assert!(!Arc::ptr_eq(&cache(&same), &cache(&changed)));
    }

    /// D77: answers kept across a reload were stored under the old verdicts: the cache is kept only while the
    /// forward stages validate the same way.
    #[test]
    fn a_reload_flushes_the_cache_when_validation_changes() {
        let text = |forward: &str| {
            format!(
                "listen: ['127.0.0.1:53']\npipeline: [cache, up]\nstages:\n  cache:\n    type: cache\n  up:\n    type: forward\n    servers: ['192.0.2.1']\n{forward}"
            )
        };
        let cache = |pipeline: &Pipeline| match pipeline.stages().first() {
            Some(Stage::Cache(cache)) => Arc::clone(cache),
            stage => unreachable!("{stage:?}"),
        };
        let off = read(&text(""), env, &Pipeline::default()).unwrap().pipeline;
        let validate = read(&text("    dnssec: validate\n"), env, &off)
            .unwrap()
            .pipeline;
        assert!(
            !Arc::ptr_eq(&cache(&off), &cache(&validate)),
            "off to validate"
        );
        let same = read(&text("    dnssec: validate\n"), env, &validate)
            .unwrap()
            .pipeline;
        assert!(Arc::ptr_eq(&cache(&validate), &cache(&same)), "unchanged");
        let insecure = read(
            &text("    dnssec: validate\n    insecure: [corp.example]\n"),
            env,
            &same,
        )
        .unwrap()
        .pipeline;
        assert!(
            !Arc::ptr_eq(&cache(&same), &cache(&insecure)),
            "negative anchor added"
        );
        let back = read(&text(""), env, &insecure).unwrap().pipeline;
        assert!(
            !Arc::ptr_eq(&cache(&insecure), &cache(&back)),
            "validate to off"
        );
    }

    /// D117: a client network's share of the validation allowance is the default's unless `client_share` says; a
    /// reload that changes it keeps the key cache (D86); without `dnssec: validate` it is refused, and so are a zero,
    /// a burst the table cannot hold and a field it does not know.
    #[test]
    fn a_client_share_is_set_per_stage_and_reload_keeps_the_keys() {
        let text = |share: &str| format!("{MINIMAL}    dnssec: validate\n{share}");
        let validating = |pipeline: &Pipeline| match pipeline.stages().first() {
            Some(Stage::Forward(forward)) => forward.validation().expect("validating").clone(),
            stage => unreachable!("{stage:?}"),
        };
        let first = read(&text(""), env, &Pipeline::default()).unwrap().pipeline;
        assert_eq!(validating(&first).share(), DEFAULT_SHARE);
        let wider = read(&text("    client_share: {rate: 50}\n"), env, &first)
            .unwrap()
            .pipeline;
        let share = validating(&wider).share();
        assert_eq!(
            (share.per_second, share.burst, share.table),
            (50, DEFAULT_SHARE.burst, DEFAULT_SHARE.table)
        );
        assert!(
            validating(&first)
                .validator()
                .shares_cache(validating(&wider).validator())
        );
        for (extra, needle) in [
            ("client_share: {rate: 0}", "nonzero"),
            ("client_share: {burst: 2000000000}", "client_share"),
            ("client_share: {speed: 1}", "speed"),
        ] {
            let message = error(&text(&format!("    {extra}\n")));
            assert!(message.contains(needle), "{extra}: {message}");
        }
        let message = error(&format!("{MINIMAL}    client_share: {{rate: 1}}\n"));
        assert!(message.contains("need `dnssec: validate`"), "{message}");
    }

    /// D86: the keys a validator cached stay valid across a reload while its trust anchors and negative anchors
    /// stay; another set starts a new cache.
    #[test]
    fn a_reload_keeps_the_key_cache_while_validation_stays() {
        let text = |forward: &str| {
            format!(
                "listen: ['127.0.0.1:53']\npipeline: [up]\nstages:\n  up:\n    type: forward\n    servers: ['192.0.2.1']\n    dnssec: validate\n{forward}"
            )
        };
        let validator = |pipeline: &Pipeline| match pipeline.stages().first() {
            Some(Stage::Forward(forward)) => forward
                .validation()
                .expect("a validating stage")
                .validator()
                .clone(),
            stage => unreachable!("{stage:?}"),
        };
        let first = read(&text(""), env, &Pipeline::default()).unwrap().pipeline;
        let same = read(&text(""), env, &first).unwrap().pipeline;
        assert!(
            validator(&first).shares_cache(&validator(&same)),
            "unchanged"
        );
        let insecure = read(&text("    insecure: [corp.example]\n"), env, &same)
            .unwrap()
            .pipeline;
        assert!(
            !validator(&same).shares_cache(&validator(&insecure)),
            "negative anchor added"
        );
    }

    /// D118: a plain line of one label is refused unless the stage says `tlds`.
    #[test]
    fn blocklists_take_top_level_domains_when_told() {
        let text = |tlds: &str| {
            format!(
                "listen: ['127.0.0.1:53']\npipeline: [block, up]\nstages:\n  block:\n    type: blocklist\n    entries: [zip, ads.example]\n{tlds}  up:\n    type: forward\n    servers: ['192.0.2.1']\n"
            )
        };
        assert!(error(&text("")).contains("entry 1"));
        assert!(error(&text("    tlds: false\n")).contains("entry 1"));
        assert!(read(&text("    tlds: true\n"), env, &Pipeline::default()).is_ok());
    }

    #[test]
    fn blocklists_read_their_action() {
        let text = |action: &str| {
            format!(
                "listen: ['127.0.0.1:53']\npipeline: [block, up]\nstages:\n  block:\n    type: blocklist\n    entries: [ads.example, '0.0.0.0 tracker.example']\n{action}  up:\n    type: forward\n    servers: ['192.0.2.1']\n"
            )
        };
        for action in [
            "",
            "    action: nxdomain\n",
            "    action: null\n    ttl: 60\n",
        ] {
            assert!(
                read(&text(action), env, &Pipeline::default()).is_ok(),
                "{action}"
            );
        }
        assert!(error(&text("    action: drop\n")).contains("drop"));
        let allow = "    allow:\n      entries: [ok.ads.example, '*.fine.example', 'bad..name']\n";
        assert!(error(&text(allow)).contains("entry 3"), "{allow}");
        let allow = allow.replace(", 'bad..name'", "");
        assert!(read(&text(&allow), env, &Pipeline::default()).is_ok());
        assert!(error(&text("    allow:\n      urls: ['ftp://x']\n")).contains("ftp://x"));
        // D104: a mistyped URL is echoed without its credentials and query, and no YAML snippet repeats them.
        let typo = error(&text("    urls: ['ftp://user:secret@x/list?token=t']\n"));
        assert!(
            typo.contains("ftp://x/list") && !typo.contains("secret") && !typo.contains("token"),
            "{typo}"
        );
        let urls = "    urls: [https://a.example/list, http://b.example/list]\n    allow:\n      urls: [https://a.example/list]\n";
        let config = read(&text(urls), env, &Pipeline::default()).unwrap();
        assert_eq!(
            config.downloads,
            Downloads {
                urls: vec![
                    "https://a.example/list".into(),
                    "http://b.example/list".into()
                ],
                dir: DOWNLOADS_DIR.into(),
                refresh: Duration::from_hours(24),
            }
        );
    }

    /// A forward stage validates with `dnssec: validate`, with the root's trust anchor or the file's, and `insecure`
    /// names; by default it does not (D77).
    #[test]
    fn a_forward_stage_validates_when_asked() {
        let validates = |text: &str| match read(text, env, &Pipeline::default())
            .unwrap()
            .pipeline
            .stages()
            .first()
        {
            Some(Stage::Forward(forward)) => forward.validates(),
            stage => unreachable!("{stage:?}"),
        };
        assert!(!validates(MINIMAL));
        assert!(!validates(&format!("{MINIMAL}    dnssec: off\n")));
        assert!(validates(&format!("{MINIMAL}    dnssec: validate\n")));
        assert!(validates(&format!(
            "{MINIMAL}    dnssec: validate\n    insecure: [corp.example, internal]\n"
        )));

        let path = std::env::temp_dir().join(format!("dedensd-anchors-{}", std::process::id()));
        std::fs::write(
            &path,
            ". 172800 IN DS 20326 8 2 E06D44B80B8F1D39A95C0B0D7C65D08458E880409BBC683457104237C7F8EC8D\n",
        )
        .unwrap();
        let text = format!(
            "{MINIMAL}    dnssec: validate\n    trust_anchors: {}\n",
            path.display()
        );
        assert!(validates(&text));
        std::fs::write(&path, "").unwrap();
        let message = error(&text);
        assert!(message.contains("`trust_anchors`"), "{message}");
        std::fs::remove_file(&path).unwrap();
        let message = error(&text);
        assert!(message.contains("cannot read"), "{message}");
    }

    #[test]
    fn dnssec_settings_outside_the_model_are_refused() {
        for (extra, needle) in [
            ("dnssec: sometimes", "sometimes"),
            ("dnssec: true", "not `true`"),
            (
                "dnssec: off\n    insecure: [a.example]",
                "need `dnssec: validate`",
            ),
            ("insecure: [a.example]", "need `dnssec: validate`"),
            ("trust_anchors: /nonexistent", "need `dnssec: validate`"),
            ("dnssec: validate\n    insecure: ['bad..name']", "bad..name"),
            (
                "dnssec: validate\n    trust_anchors: /nonexistent/anchors",
                "cannot read",
            ),
        ] {
            let message = error(&format!("{MINIMAL}    {extra}\n"));
            assert!(message.contains(needle), "{extra}: {message}");
        }
    }

    #[test]
    fn yaml_outside_the_model_is_refused() {
        for (text, needle) in [
            (format!("{MINIMAL}workers: 2\n"), "workers"),
            (MINIMAL.replace("servers:", "upstreams:"), "upstreams"),
            (MINIMAL.replace("forward", "rewrite"), "rewrite"),
            (format!("{MINIMAL}  up:\n    type: cache\n"), "up"),
            ("listen: ['127.0.0.1:53']\npipeline: [c]\nstages:\n  c:\n    type: cache\n    size: 1\n".to_owned(), "size"),
            (MINIMAL.replace("192.0.2.1", "example.com"), "example.com"),
            (format!("{MINIMAL}    tries: 0\n"), "nonzero"),
            (format!("{MINIMAL}    timeout_ms: 0\n"), "nonzero"),
            (format!("downloads:\n  refresh_minutes: 0\n{MINIMAL}"), "nonzero"),
            (format!("downloads:\n  path: /tmp\n{MINIMAL}"), "path"),
        ] {
            let message = error(&text);
            assert!(message.contains(needle), "{needle}: {message}");
        }
    }

    /// D115: a forward stage waits at most 30 s a try and tries at most 5 times a server, the limits of the system
    /// resolver (`resolv.conf`: `timeout` and `attempts`); the bounds themselves are allowed.
    #[test]
    fn forward_patience_is_bounded() {
        for (extra, message) in [
            (
                "timeout_ms: 30001",
                "stage `up`: `timeout_ms` is above 30000, 30 s",
            ),
            ("timeout_ms: 4294967295", "`timeout_ms` is above 30000"),
            ("tries: 6", "stage `up`: `tries` is above 5"),
            ("tries: 255", "`tries` is above 5"),
        ] {
            let refused = error(&format!("{MINIMAL}    {extra}\n"));
            assert!(refused.contains(message), "{extra}: {refused}");
        }
        let text = format!("{MINIMAL}    timeout_ms: 30000\n    tries: 5\n");
        assert!(read(&text, env, &Pipeline::default()).is_ok());
    }

    /// D115: a value is YAML text, not YAML: unless it is plain (letters, digits and `_./:@+=%~#-`), `${VAR}` must
    /// stand alone as a value, and is quoted there.
    #[test]
    fn a_variable_cannot_inject_yaml() {
        for (text, replaced) in [
            // Plain values go in as they are, in numbers, addresses and paths.
            ("port: ${PORT}", "port: 5353"),
            (
                "[${URL}, '${URL}']",
                "[tls://9.9.9.9#dns.quad9.net, 'tls://9.9.9.9#dns.quad9.net']",
            ),
            ("'a:${PORT}'", "'a:5353'"),
            // Anything else is quoted where it stands alone.
            ("key: ${TEXT}", "key: 'a: b #c'"),
            ("key: ${TEXT} # note", "key: 'a: b #c' # note"),
            (
                "servers: [${TEXT}, ${QUOTE}]",
                "servers: ['a: b #c', 'it''s']",
            ),
            ("{k: ${TEXT}}", "{k: 'a: b #c'}"),
            ("  - ${HASH}", "  - '#x'"),
            ("${TEXT}: v", "'a: b #c': v"),
            ("${TEXT}", "'a: b #c'"),
            // Inside quotes, escaped for them.
            ("key: '${QUOTE}'", "key: 'it''s'"),
            (r#"key: "${QUOTE}""#, r#"key: "it's""#),
            (r#"key: "${DOUBLE}""#, r#"key: "say \"hi\"\\""#),
            (r"key: '${DOUBLE}'", r#"key: 'say "hi"\'"#),
            // A default is the template's own text.
            ("key: ${NOPE:-a: b}", "key: a: b"),
        ] {
            assert_eq!(interpolate(text, env).unwrap(), replaced, "{text}");
        }
        for text in [
            "key: x${TEXT}",
            "key: ${TEXT}x",
            "key: 'x ${TEXT}'",
            "key: ${TEXT}${PORT}",
            "key: ${QUOTE}'",
        ] {
            let refused = interpolate(text, env).expect_err(text).to_string();
            assert!(refused.contains("not alone"), "{text}: {refused}");
        }
        for name in ["TAB", "NEL", "SEPARATOR"] {
            let refused = interpolate(&format!("k: ${{{name}}}"), env).unwrap_err();
            assert!(
                refused.to_string().contains("a control character"),
                "{name}: {refused}"
            );
        }
        // The injection this stops: two servers from one variable.
        let injected = MINIMAL.replace("'192.0.2.1'", "${TEXT}");
        assert!(error(&injected).contains("a: b #c"), "{}", error(&injected));
    }

    /// D115: whatever the value, `key: ${VAR}` and its quoted and flow forms read as the mapping `key` to exactly
    /// that text, or are refused: every text of up to three characters from those YAML gives a meaning to.
    #[test]
    fn a_value_is_the_text_it_stands_for() {
        const ALPHABET: [char; 17] = [
            'a', '\'', '"', '\\', '#', ' ', ':', '-', ',', '[', ']', '{', '}', '!', '&', '*', '?',
        ];
        let mut values = vec![String::new()];
        let mut start = 0;
        for _ in 0..3 {
            let end = values.len();
            for at in start..end {
                for c in ALPHABET {
                    values.push(format!("{}{c}", values[at]));
                }
            }
            start = end;
        }
        let mut read = 0;
        for value in values.iter().filter(|value| !value.is_empty()) {
            let env = |_: &str| Some(value.clone());
            for (template, flow) in [
                ("k: ${V}\n", false),
                ("k: '${V}'\n", false),
                ("k: \"${V}\"\n", false),
                ("k: [${V}]\n", true),
                ("{k: ${V}}\n", false),
            ] {
                let Ok(text) = interpolate(template, env) else {
                    continue;
                };
                let parsed = if flow {
                    serde_saphyr::from_str::<BTreeMap<String, Vec<String>>>(&text)
                        .map(|map| map.into_iter().map(|(k, v)| (k, v.concat())).collect())
                } else {
                    serde_saphyr::from_str::<BTreeMap<String, String>>(&text)
                };
                if let Ok(map) = parsed {
                    assert_eq!(
                        map,
                        BTreeMap::from([("k".to_owned(), value.clone())]),
                        "{text}"
                    );
                    read += 1;
                }
            }
        }
        // Most of them read: the check is no refusal of everything.
        assert!(read > values.len(), "{read} of {}", values.len() * 5);
    }

    /// D115: a downloaded list not fetched yet is empty, and a saved copy that does not read stops the start.
    #[cfg(unix)]
    #[test]
    fn an_unreadable_saved_list_refuses_the_start() {
        let dir = tempfile::tempdir().unwrap();
        let url = "https://lists.example/ads.txt";
        let text = format!(
            "listen: ['127.0.0.1:53']\ndownloads:\n  dir: '{}'\npipeline: [block, up]\nstages:\n  block:\n    type: blocklist\n    urls: ['{url}']\n  up:\n    type: forward\n    servers: ['192.0.2.1']\n",
            dir.path().display()
        );
        assert!(
            read(&text, env, &Pipeline::default()).is_ok(),
            "no copy yet"
        );
        let copy = download::copy(dir.path(), url);
        std::fs::write(&copy, "not a list: ?\n").unwrap();
        assert!(read(&text, env, &Pipeline::default()).is_ok(), "no list");
        std::fs::remove_file(&copy).unwrap();
        std::fs::create_dir(&copy).unwrap();
        let refused = error(&text);
        assert!(refused.contains("reading `"), "{refused}");
    }

    /// D120: a list named twice in a stage is one set, its names counted once and listed twice.
    #[test]
    fn a_list_named_twice_in_a_stage_is_held_once() {
        let dir = tempfile::tempdir().unwrap();
        let url = "https://lists.example/ads.txt";
        std::fs::write(
            download::copy(dir.path(), url),
            "ads.example\ntrack.example\n",
        )
        .unwrap();
        let twice = Sources::new(Vec::new(), None, vec![Url(url.into()), Url(url.into())]);
        let mut store = Store::default();
        let lists = lists(
            "block",
            &twice,
            &Sources::default(),
            Tlds::Refuse,
            (dir.path(), &mut store),
        )
        .unwrap();
        assert_eq!(lists.names(List::Block), 2);
        assert_eq!(lists.duplicates(List::Block), 2);
    }

    /// D120: a file read as one `tlds` says is not the file read as the other says.
    #[test]
    fn a_file_is_read_as_the_stage_says_tlds() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("list.txt");
        std::fs::write(&file, "zip\nads.example\n").unwrap();
        let sources = Sources::new(Vec::new(), Some(file), Vec::new());
        let mut store = Store::default();
        let mut read = |tlds| {
            lists(
                "block",
                &sources,
                &Sources::default(),
                tlds,
                (dir.path(), &mut store),
            )
        };
        assert_eq!(read(Tlds::Allow).unwrap().names(List::Block), 2);
        let refused = read(Tlds::Refuse).unwrap_err();
        assert!(
            format!("{refused:#}").contains("list.txt` line 1"),
            "{refused:#}"
        );
        assert_eq!(read(Tlds::Allow).unwrap().names(List::Block), 2);
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

    /// D122: `user` and `group` are a name or an id, `group` goes with `user`, and a `user` off Linux is refused.
    #[test]
    fn a_user_and_a_group_are_read() {
        let read = |extra: &str| read(&format!("{MINIMAL}{extra}"), env, &Pipeline::default());
        assert_eq!(read("").unwrap().user, None);
        assert!(
            format!("{:#}", read("group: dedens\n").unwrap_err())
                .contains("`group` needs a `user`")
        );
        for (text, user, group) in [
            ("user: dedens\n", Account::Name("dedens".into()), None),
            ("user: 1000\n", Account::Id(1000), None),
            ("user: \'1000\'\n", Account::Id(1000), None),
            (
                "user: dedens\ngroup: ssl-cert\n",
                Account::Name("dedens".into()),
                Some(Account::Name("ssl-cert".into())),
            ),
            (
                "user: 1000\ngroup: 1001\n",
                Account::Id(1000),
                Some(Account::Id(1001)),
            ),
        ] {
            if cfg!(target_os = "linux") {
                let expected = Identity::new(Some(user), group, true).unwrap();
                assert_eq!(read(text).unwrap().user, expected, "{text}");
            } else {
                let error = format!("{:#}", read(text).unwrap_err());
                assert!(error.contains("on Linux only"), "{error}");
            }
        }
        for text in [
            "user: \'\'\n",
            "user: 4294967295\n",
            "user: [a]\n",
            "user: dedens\ngroup: \'\'\n",
        ] {
            assert!(read(text).is_err(), "{text}");
        }
    }
}
