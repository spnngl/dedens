//! The configuration file (D24, D44, D115): YAML, `${VAR}` replaced first, then read into named stages run in the
//! order `pipeline` lists them. A value of `${VAR}` is one value, never YAML: left as it is when plain (letters,
//! digits, `_./:@+=%~#-`), single-quoted when alone as a value, escaped between the template's own quotes, refused
//! anywhere else. A TLS, `ODoH` or `DNSCrypt` key file readable by others is refused, by its group warned about. After the drop
//! (D122) a reload reads as `user`: the files it reads (the certificate and its key, lists, `upstream_ca`, saved
//! downloads) must be readable by it, and `downloads.dir` writable. The start reads the configuration again as `user`
//! right after the drop, and ends if it cannot. A reload warns of a change to `user` or `group` as written: `user: 990`
//! for `user: dedens` warns too.
//!
//! ```yaml
//! listen: ["127.0.0.1:53", "[::1]:53", "tls://0.0.0.0", "quic://0.0.0.0", "https://0.0.0.0/dns-query", "dnscrypt://0.0.0.0"]
//! threads: 4                       # serving threads, fixed at start, 1 to 1024; default: a core each on Linux, else 1 (D42)
//! user: dedens                     # Linux, started as root: run as this user, a name or an id, once the sockets are bound (D122);
//!                                  # a musl build looks a name up in /etc/passwd only, no NSS (D151)
//! group: dedens                    # default: the user's primary group; supplementary groups: those listing the user, plus this one
//! tls:
//!   certificate: /etc/dedensd/tls/fullchain.pem
//!   key: /etc/dedensd/tls/key.pem
//! odoh:                              # Oblivious DoH target on the https:// addresses (D79); needs the odoh feature
//!   key: /etc/dedensd/odoh.key         # 64 hex digits; default: a key made at each start
//!   proxy:                           # also the proxy of RFC 9230 §4 (D94): forwards to these targets only
//!     targets: [odoh.cloudflare-dns.com, "odoh-target.example:8443"]   # HOST[:PORT], port 443 by default
//!     timeout_ms: 5000
//! dnscrypt:                          # DNSCrypt resolver on the dnscrypt:// addresses (D99); needs the dnscrypt feature
//!   provider_name: 2.dnscrypt-cert.dns.example   # certificates are asked under this name
//!   secret_key: /etc/dedensd/dnscrypt.key        # the provider's Ed25519 seed, 64 hex digits; `dedensd dnscrypt-keygen` makes one
//!   systems: [xchacha20, xsalsa20]               # both by default
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
//!     prewarm:                         # names kept answered with no client, asked through the stages (D96)
//!       entries: [www.example.com]     # then `file`, one name a line as a plain blocklist; up to 1000 names
//!       types: [A, AAAA]               # both by default
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

mod access;
#[cfg_attr(
    not(feature = "dnscrypt"),
    expect(
        dead_code,
        reason = "read by the resolver, built with the dnscrypt feature"
    )
)]
mod dnscrypt;
mod env;
mod keys;
mod limits;
mod listen;
#[cfg(any(feature = "odoh", feature = "dnscrypt"))]
mod secret;
mod sources;
mod upstream;

use std::collections::BTreeMap;
use std::num::NonZeroUsize;
use std::path::PathBuf;
use std::thread;
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{bail, ensure};
use dedens_net::tls::{Presented, Trust};
use dedens_proto::Question;
use dedens_server::{Pipeline, Stage};
use serde::Deserialize;

use self::access::{AccessFile, AccessSource};
use self::dnscrypt::DnscryptFile;
#[cfg(feature = "dnscrypt")]
pub(crate) use self::dnscrypt::provider;
#[cfg(feature = "dnscrypt")]
use self::dnscrypt::section as dnscrypt_section;
use self::env::interpolate;
#[cfg(feature = "odoh")]
use self::keys::section;
use self::keys::{OdohFile, trusted};
use self::limits::{CookiesFile, Guard, RrlFile, serving_threads};
pub(crate) use self::listen::Listen;
#[cfg(feature = "dnscrypt")]
pub(crate) use self::listen::address;
use self::listen::{TlsFile, presented};
#[cfg(all(test, feature = "odoh"))]
pub(crate) use self::secret::KEY_FILE_MAX;
#[cfg(any(feature = "odoh", feature = "dnscrypt"))]
pub(crate) use self::secret::{SECRET_LEN, read_secret};
pub(crate) use self::sources::Downloads;
use self::sources::{
    CacheFile, DownloadsFile, Sources, StageFile, blocklist, cache, flush, hosts, prewarm,
};
use self::upstream::{Validation, forward};
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
    dnscrypt: Option<DnscryptFile>,
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
    /// The `DNSCrypt` resolver's settings, there when `dnscrypt` is: the key is read at start only (D99).
    #[cfg(feature = "dnscrypt")]
    pub(crate) dnscrypt: Option<crate::dnscrypt::Section>,
    pub(crate) pipeline: Pipeline,
    /// Where the access lists come from (D91).
    access: AccessSource,
    pub(crate) downloads: Downloads,
    /// What upstream servers over TLS and QUIC are checked against.
    pub(crate) trust: Trust,
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
/// above 30 s or `tries` above 5 on a forward stage; a TLS key file others can access ([`keys::guard_key`]); a variable
/// that is neither plain nor alone as a value (`env::written`); a saved list that cannot be read (`sources::lists`); settings
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
    let config = build(parse(text, env)?, previous, store)?;
    store.end();
    Ok(config)
}

/// [`read`] of `text`, built only when it names no file to read: the entry of `fuzz/` (D181), which must not open
/// the paths an input names, as a TLS key or a list.
///
/// # Errors
///
/// As [`read`].
pub(crate) fn read_without_files(
    text: &str,
    env: impl Fn(&str) -> Option<String>,
) -> anyhow::Result<()> {
    let file = parse(text, env)?;
    if !file.names_files() {
        build(file, &Pipeline::default(), &mut Store::default())?;
    }
    Ok(())
}

/// `text` with its variables taken from `env`, read into the model.
///
/// # Errors
///
/// A variable without a value or that is not plain nor alone as a value; YAML that does not fit the model.
fn parse(text: &str, env: impl Fn(&str) -> Option<String>) -> anyhow::Result<File> {
    let text = interpolate(text, env)?;
    // No snippet of the YAML in an error: it could echo the `urls` (D104). The line and column stay.
    Ok(serde_saphyr::from_str_with_options(
        &text,
        serde_saphyr::options! { with_snippet: false },
    )?)
}

impl File {
    /// Whether building it reads a file it names: the TLS certificate and key, the upstream authorities, a stage's
    /// file, trust anchors or saved downloads.
    fn names_files(&self) -> bool {
        self.tls.is_some()
            || self.upstream_ca.is_some()
            || self.stages.values().any(StageFile::names_files)
    }
}

/// [`read`] of `file`, the lists it reads taken from `store`, and put there.
fn build(file: File, previous: &Pipeline, store: &mut Store) -> anyhow::Result<Config> {
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
    #[cfg(feature = "dnscrypt")]
    let dnscrypt = dnscrypt_section(file.dnscrypt.as_ref(), &file.listen)?;
    #[cfg(not(feature = "dnscrypt"))]
    ensure!(
        file.dnscrypt.is_none(),
        "`dnscrypt` needs a dedensd built with the dnscrypt feature"
    );
    ensure!(!file.pipeline.is_empty(), "`pipeline` has no stage");
    let source = AccessSource::of(file.access.as_ref());
    let guard = Guard {
        access: file.access,
        rrl: file.rrl,
        cookies: file.cookies,
    };
    let mut downloads = Downloads::new(file.downloads)?;
    let (mut built, warmed) = stages(&file.pipeline, file.stages, previous, &mut downloads, store)?;
    // Answers kept across a reload carry the verdict of the validator that made them, AD included: another
    // validator, or none, does not stand behind them (D77).
    flush(&mut built, previous)?;
    let pipeline = guard.around(built, previous)?.with_prewarm(warmed);
    Ok(Config {
        listen: file.listen,
        presented,
        threads,
        user,
        #[cfg(feature = "odoh")]
        odoh,
        #[cfg(feature = "dnscrypt")]
        dnscrypt,
        pipeline,
        access: source,
        downloads,
        trust: trusted(file.upstream_ca.as_deref())?,
    })
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

/// The stages of `order`, built from `defined` after those of `previous`, and the questions their cache stage keeps
/// answered (D96).
///
/// # Errors
///
/// As [`read`] lists for the stages.
fn stages(
    order: &[String],
    mut defined: BTreeMap<String, StageFile>,
    previous: &Pipeline,
    downloads: &mut Downloads,
    store: &mut Store,
) -> anyhow::Result<(Vec<Stage>, Vec<Question<'static>>)> {
    let mut built = Vec::with_capacity(order.len());
    // The cache stage that keeps names answered, its place in `built` and its questions (D96).
    let mut warm = None;
    for (index, name) in order.iter().enumerate() {
        let Some(stage) = defined.remove(name) else {
            if order[..index].contains(name) {
                bail!("stage `{name}` is listed twice in `pipeline`");
            }
            bail!("stage `{name}` is listed in `pipeline` but not defined in `stages`");
        };
        placed(name, &stage, &built)?;
        built.push(match stage {
            StageFile::Cache(CacheFile {
                settings,
                prewarm: names,
            }) => {
                if let Some(names) = names {
                    warm = Some((name.as_str(), built.len(), prewarm(name, &names)?));
                }
                cache(name, settings, previous)?
            }
            StageFile::Forward {
                servers,
                relays,
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
                    name,
                    (servers, relays),
                    timeout_ms,
                    tries,
                    validation,
                    previous,
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
                    (&mut *downloads, store),
                )?
            }
        });
    }
    if let Some(name) = defined.keys().next() {
        bail!("stage `{name}` is defined but not listed in `pipeline`");
    }
    let questions = match warm {
        Some((name, at, _))
            if !built[at..]
                .iter()
                .any(|stage| matches!(stage, Stage::Forward(_))) =>
        {
            bail!("stage `{name}`: `prewarm` has no forward stage after the cache to ask")
        }
        Some((_, _, questions)) => questions,
        None => Vec::new(),
    };
    Ok((built, questions))
}

/// The most names a cache stage's `prewarm` lists: each is asked for each type and, with `dnssec: validate`, with and
/// without DO, and kept scheduled, so the bound stops a list of a whole zone, not a machine (D96, D115).
const MAX_PREWARM_NAMES: usize = 1000;

/// The longest `refresh_minutes`: a year, far below the overflow of a `Duration` or an `Instant`.
const MAX_REFRESH_MINUTES: u64 = 366 * 1440;

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

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use dedens_proto::RecordType;

    use super::*;

    /// [`super::read`] with a store of its own.
    pub(super) fn read(
        text: &str,
        env: impl Fn(&str) -> Option<String>,
        previous: &Pipeline,
    ) -> anyhow::Result<Config> {
        super::read(text, env, previous, &mut Store::default())
    }

    pub(super) fn env(name: &str) -> Option<String> {
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

    pub(super) fn error(text: &str) -> String {
        format!(
            "{:#}",
            read(text, env, &Pipeline::default()).expect_err("refused")
        )
    }

    pub(super) const MINIMAL: &str = "listen: ['127.0.0.1:53']\npipeline: [up]\nstages:\n  up:\n    type: forward\n    servers: ['192.0.2.1']\n";

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

    /// D96: the names to keep answered, from `entries` then `file`, each for the types asked, once.
    #[test]
    fn a_cache_stage_reads_the_names_it_keeps_answered() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("names");
        std::fs::write(&path, "# popular\nwww.example.org\nExample.COM\n").unwrap();
        let text = |prewarm: &str| {
            format!(
                "listen: ['127.0.0.1:53']\npipeline: [c, up]\nstages:\n  c:\n    type: cache\n    min_ttl: 120\n    prewarm:\n{prewarm}  up:\n    type: forward\n    servers: ['192.0.2.1']\n"
            )
        };
        let asked = |text: &str| -> Vec<(String, RecordType)> {
            let config = read(text, env, &Pipeline::default()).unwrap();
            config
                .pipeline
                .warmed()
                .iter()
                .map(|warm| (warm.question().name.to_string(), warm.question().qtype))
                .collect()
        };
        let both = asked(&text(&format!(
            "      entries: [example.com, 'EXAMPLE.com.']\n      file: {}\n",
            path.display()
        )));
        assert_eq!(
            both,
            [
                ("example.com.".to_owned(), RecordType::A),
                ("example.com.".to_owned(), RecordType::AAAA),
                ("www.example.org.".to_owned(), RecordType::A),
                ("www.example.org.".to_owned(), RecordType::AAAA),
            ]
        );
        assert_eq!(
            asked(&text(
                "      entries: [example.com]\n      types: [AAAA, AAAA]\n"
            )),
            [("example.com.".to_owned(), RecordType::AAAA)]
        );
        assert_eq!(asked(&text("      entries: []\n")), []);
        // A stage with no `prewarm` asks for nothing, and a one-label name is a name to ask for.
        assert_eq!(asked(&text("      entries: [com]\n")).len(), 2);
        let config = read(MINIMAL, env, &Pipeline::default()).unwrap();
        assert_eq!(config.pipeline.warmed(), []);
    }

    /// D96: at most `MAX_PREWARM_NAMES` distinct names, however many entries repeat them.
    #[test]
    fn the_names_kept_answered_are_bounded_once_distinct() {
        let text = |entries: &str| {
            format!(
                "listen: ['127.0.0.1:53']\npipeline: [c, up]\nstages:\n  c:\n    type: cache\n    prewarm:\n      entries: [{entries}]\n  up:\n    type: forward\n    servers: ['192.0.2.1']\n"
            )
        };
        let names = |count: usize| {
            (0..count)
                .map(|n| format!("n{n}.example"))
                .collect::<Vec<_>>()
                .join(", ")
        };
        let full = read(
            &text(&format!("{}, n0.example", names(MAX_PREWARM_NAMES))),
            env,
            &Pipeline::default(),
        )
        .unwrap();
        assert_eq!(full.pipeline.warmed().len(), 2 * MAX_PREWARM_NAMES);
        assert_eq!(
            error(&text(&names(MAX_PREWARM_NAMES + 1))),
            "stage `c`: `prewarm` names more than 1000 names"
        );
    }

    /// D55, D96: the names are beside the cache settings, so a change of the names keeps the cache.
    #[test]
    fn a_reload_changing_the_names_keeps_the_cache() {
        let text = |prewarm: &str| {
            format!(
                "listen: ['127.0.0.1:53']\npipeline: [c, up]\nstages:\n  c:\n    type: cache\n{prewarm}  up:\n    type: forward\n    servers: ['192.0.2.1']\n"
            )
        };
        let cache = |pipeline: &Pipeline| match pipeline.stages().first() {
            Some(Stage::Cache(cache)) => Arc::clone(cache),
            stage => unreachable!("{stage:?}"),
        };
        let first = read(
            &text("    prewarm:\n      entries: [a.example]\n"),
            env,
            &Pipeline::default(),
        )
        .unwrap()
        .pipeline;
        let second = read(
            &text("    prewarm:\n      entries: [a.example, b.example]\n"),
            env,
            &first,
        )
        .unwrap()
        .pipeline;
        assert_eq!(first.warmed().len(), 2);
        assert_eq!(second.warmed().len(), 4);
        assert!(Arc::ptr_eq(&cache(&first), &cache(&second)));
    }

    /// D96: an unreadable file is a failed read, which a reload leaves the running pipeline for (D55).
    #[test]
    fn a_names_file_that_is_missing_fails_the_read() {
        let text = "listen: ['127.0.0.1:53']\npipeline: [c, up]\nstages:\n  c:\n    type: cache\n    prewarm:\n      file: /nonexistent/names\n  up:\n    type: forward\n    servers: ['192.0.2.1']\n";
        let message = error(text);
        assert!(
            message.contains("stage `c`, `prewarm`") && message.contains("/nonexistent/names"),
            "{message}"
        );
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
                "listen: ['127.0.0.1:53']\npipeline: [c, up]\nstages:\n  c:\n    type: cache\n    prewarm:\n      entries: ['*.example']\n  up:\n    type: forward\n    servers: ['192.0.2.1']\n",
                "stage `c`, `prewarm`: entry 1: `*.example` is a wildcard, which cannot be asked",
            ),
            (
                "listen: ['127.0.0.1:53']\npipeline: [c, up]\nstages:\n  c:\n    type: cache\n    prewarm:\n      entries: [a.example, 'b.example c.example']\n  up:\n    type: forward\n    servers: ['192.0.2.1']\n",
                "stage `c`, `prewarm`: entry 2: `c.example` after the name",
            ),
            (
                "listen: ['127.0.0.1:53']\npipeline: [c, up]\nstages:\n  c:\n    type: cache\n    prewarm:\n      entries: [a.example]\n      types: []\n  up:\n    type: forward\n    servers: ['192.0.2.1']\n",
                "stage `c`: `prewarm` has no type",
            ),
            (
                "listen: ['127.0.0.1:53']\npipeline: [c]\nstages:\n  c:\n    type: cache\n    prewarm:\n      entries: [a.example]\n",
                "stage `c`: `prewarm` has no forward stage after the cache to ask",
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

    #[test]
    fn yaml_outside_the_model_is_refused() {
        for (text, needle) in [
            (format!("{MINIMAL}workers: 2\n"), "workers"),
            (MINIMAL.replace("servers:", "upstreams:"), "upstreams"),
            (MINIMAL.replace("forward", "rewrite"), "rewrite"),
            (format!("{MINIMAL}  up:\n    type: cache\n"), "up"),
            ("listen: ['127.0.0.1:53']\npipeline: [c]\nstages:\n  c:\n    type: cache\n    size: 1\n".to_owned(), "size"),
            ("listen: ['127.0.0.1:53']\npipeline: [c]\nstages:\n  c:\n    type: cache\n    prewarm:\n      urls: []\n".to_owned(), "urls"),
            ("listen: ['127.0.0.1:53']\npipeline: [c]\nstages:\n  c:\n    type: cache\n    prewarm:\n      types: [MX]\n".to_owned(), "MX"),
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
