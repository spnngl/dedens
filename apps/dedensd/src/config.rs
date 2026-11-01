//! The configuration file (D24, D44): YAML, `${VAR}` replaced first, then read into named stages run in the order
//! `pipeline` lists them.
//!
//! ```yaml
//! listen: ["127.0.0.1:53", "[::1]:53", "tls://0.0.0.0", "quic://0.0.0.0", "https://0.0.0.0/dns-query"]
//! tls:
//!   certificate: /etc/dedensd/tls/fullchain.pem
//!   key: /etc/dedensd/tls/key.pem
//! odoh:                              # Oblivious DoH target on the https:// addresses (D79); needs the odoh feature
//!   key: /etc/dedensd/odoh.key         # 64 hex digits; default: a key made at each start
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
//!     capacity: 67108864
//!   upstream:
//!     type: forward
//!     servers: ["tls://9.9.9.9#dns.quad9.net", "149.112.112.112:53"]
//!     timeout_ms: 3000
//!     tries: 2
//!     dnssec: validate                 # off (default) or validate (D77)
//!     trust_anchors: /etc/dedensd/anchors.zone   # DS or DNSKEY records; default: the root's, bundled
//!     insecure: [corp.example]         # names not validated, with what is below them (RFC 7646)
//! ```

use std::collections::BTreeMap;
use std::net::{IpAddr, SocketAddr};
use std::num::{NonZeroU8, NonZeroU32, NonZeroU64};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use std::{fmt, fs, io};

use anyhow::{Context, anyhow, bail, ensure};
use compio::rustls::pki_types::pem::PemObject as _;
use compio::rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName};
use dedens_cache::Cache;
use dedens_dnssec::anchor::TrustAnchors;
use dedens_dnssec::validator::{Limits, Validator};
use dedens_net::doh::DEFAULT_PATH;
use dedens_net::tls::{Presented, Trust};
use dedens_plugins::{Action, Blocklist, Hosts, List, ListError, Lists, Origin, Read};
use dedens_proto::{Name, Ttl};
use dedens_server::{Forward, Pipeline, Stage, Validating, Via};
use http::uri::PathAndQuery;
use serde::Deserialize;

use crate::download;

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
    /// Where downloaded lists are kept, and how often they are fetched again (D57).
    #[serde(default)]
    downloads: DownloadsFile,
    /// A PEM file of the certificate authorities upstream servers over TLS and QUIC are checked against,
    /// instead of the system's (D65).
    upstream_ca: Option<PathBuf>,
    /// The names of the stages, in the order a query goes through them.
    pipeline: Vec<String>,
    /// The stages, by name.
    stages: BTreeMap<String, StageFile>,
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
/// or percent-encoding, which segments are read as written.
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
    Forward {
        servers: Vec<Server>,
        timeout_ms: Option<NonZeroU32>,
        tries: Option<NonZeroU8>,
        #[serde(default)]
        dnssec: Dnssec,
        trust_anchors: Option<PathBuf>,
        #[serde(default)]
        insecure: Vec<Insecure>,
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
    /// `null` with `ttl` seconds, 3600 unless set.
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
            Err(format!("`{text}` is not an http:// or https:// URL"))
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
    /// The Oblivious `DoH` target's settings, there when `odoh` is: the key is read at start only.
    #[cfg(feature = "odoh")]
    pub(crate) odoh: Option<crate::odoh::Section>,
    pub(crate) pipeline: Pipeline,
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
/// whose answers a reload keeps; `refresh_minutes` above a year; settings a stage refuses.
pub(crate) fn read(
    text: &str,
    env: impl Fn(&str) -> Option<String>,
    previous: &Pipeline,
) -> anyhow::Result<Config> {
    let text = interpolate(text, env)?;
    let file: File = serde_saphyr::from_str(&text)?;
    ensure!(!file.listen.is_empty(), "`listen` has no address");
    let presented = presented(&file.listen, file.tls.as_ref())?;
    #[cfg(feature = "odoh")]
    let odoh = section(file.odoh.as_ref(), &file.listen)?;
    #[cfg(not(feature = "odoh"))]
    ensure!(
        file.odoh.is_none(),
        "`odoh` needs a dedensd built with the odoh feature"
    );
    ensure!(!file.pipeline.is_empty(), "`pipeline` has no stage");
    let mut stages = file.stages;
    let mut built = Vec::with_capacity(file.pipeline.len());
    let mut downloads = Downloads {
        urls: Vec::new(),
        dir: file.downloads.dir.unwrap_or_else(|| DOWNLOADS_DIR.into()),
        refresh: refresh(file.downloads.refresh_minutes)?,
    };
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
            } => {
                let validation = Validation {
                    dnssec,
                    trust_anchors,
                    insecure,
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
            } => {
                let block = Sources {
                    entries,
                    file,
                    urls,
                };
                let lists = lists(name, &block, &allow, &downloads.dir)
                    .with_context(|| format!("stage `{name}`"))?;
                for Url(url) in block.urls.into_iter().chain(allow.urls) {
                    if !downloads.urls.contains(&url) {
                        downloads.urls.push(url);
                    }
                }
                let ttl = Ttl::from_wire(ttl.unwrap_or(PLUGIN_TTL));
                Stage::Plugin(Box::new(Blocklist::new(
                    lists,
                    action.unwrap_or_default(),
                    ttl,
                )))
            }
        });
    }
    if let Some(name) = stages.keys().next() {
        bail!("stage `{name}` is defined but not listed in `pipeline`");
    }
    // Answers kept across a reload carry the verdict of the validator that made them, AD included: another
    // validator, or none, does not stand behind them (D77).
    flush(&mut built, previous)?;
    Ok(Config {
        listen: file.listen,
        presented,
        #[cfg(feature = "odoh")]
        odoh,
        pipeline: Pipeline::new(built),
        downloads,
        trust: trusted(file.upstream_ca.as_deref())?,
    })
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
/// A stage without a server.
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
            validation.trust_anchors.is_none() && validation.insecure.is_empty(),
            "stage `{name}`: `trust_anchors` and `insecure` need `dnssec: validate`"
        ),
        Dnssec::Validate => {
            let validating = validating(validation.trust_anchors.as_deref(), validation.insecure)?;
            let kept = previous.stages().iter().find_map(|stage| match stage {
                Stage::Forward(old) => old.validation().filter(|old| old.tag() == validating.tag()),
                _ => None,
            });
            forward = forward.validating(kept.cloned().unwrap_or(validating));
        }
    }
    if let Some(ms) = timeout_ms {
        forward = forward.with_timeout(Duration::from_millis(u64::from(ms.get())));
    }
    if let Some(tries) = tries {
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
    let clock = || {
        SystemTime::now().duration_since(UNIX_EPOCH).map_or_else(
            |error| {
                // Time 0 fails closed: no signature is valid yet.
                tracing::error!(%error, "the system clock is before the Unix epoch");
                0
            },
            |elapsed| elapsed.as_secs(),
        )
    };
    Ok(Validating::new(Validator::new(anchors, Limits::default()), Arc::new(clock)).tagged(&tag))
}

/// The Oblivious `DoH` target settings of `odoh`, if any (D79). The key is not read: a reload builds this again, and
/// the key is read at start (D79).
///
/// # Errors
///
/// `odoh` without an `https://` address in `listen`.
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
    Ok(Some(crate::odoh::Section::new(odoh.key.as_deref())))
}

/// The certificate of `tls`, read from its files, when `listen` has an address over TLS, QUIC or HTTP/3.
///
/// # Errors
///
/// A certificate without such an address or the reverse, a file that does not read, a chain without a certificate,
/// a file without a key, or a key that is not the certificate's.
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
    let key = PrivateKeyDer::from_pem_file(&tls.key).with_context(|| {
        format!(
            "`tls`: cannot read a private key from {}",
            tls.key.display()
        )
    })?;
    let presented = Presented::new(chain, key)
        .with_context(|| format!("`tls`: the key does not fit {path}"))?;
    Ok(Some(presented))
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

/// The lists of the blocklist stage `stage`, `block` and `allow` read, their downloaded ones from their copies in
/// `dir`; logs the counts. A list not downloaded yet is empty until it is, and a copy that does not read is left
/// out with a warning: neither stops the server.
fn lists(stage: &str, block: &Sources, allow: &Sources, dir: &Path) -> anyhow::Result<Lists> {
    let mut lists = Lists::new();
    let mut duplicates = 0;
    for (list, sources) in [(List::Block, block), (List::Allow, allow)] {
        let read = local(&sources.entries, sources.file.as_deref(), |text| {
            lists.read(list, Origin::Local, text)
        })?;
        duplicates += read.duplicates;
        for Url(url) in &sources.urls {
            let copy = download::copy(dir, url);
            match fs::read_to_string(&copy) {
                Ok(text) => match lists.read(list, Origin::Downloaded, &text) {
                    Ok(Read {
                        duplicates: dups, ..
                    }) => duplicates += dups,
                    Err(error) => {
                        tracing::warn!(stage, url, %error, "the saved copy is not a list");
                    }
                },
                Err(error) if error.kind() == io::ErrorKind::NotFound => {
                    tracing::info!(stage, url, "list not downloaded yet");
                }
                Err(error) => {
                    return Err(error).with_context(|| format!("reading `{}`", copy.display()));
                }
            }
        }
    }
    tracing::info!(
        stage,
        blocked = lists.names(List::Block),
        allowed = lists.names(List::Allow),
        duplicates,
        "blocklist read"
    );
    Ok(lists)
}

/// `text` with each `${VAR}` replaced by the variable's value, `${VAR:-default}` by `default` when it is unset or
/// empty, and `$$` by `$`; any other `$` stays, and so does a line whose first non-blank character is `#`, a
/// comment.
///
/// # Errors
///
/// A variable without a value or default, one whose value spans lines (`\n` or `\r`: it would add YAML of its
/// own), or a `${` left open on its line.
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
            let value = match (env(name).filter(|value| !value.is_empty()), default) {
                (Some(value), _) => value,
                (None, Some(default)) => default.to_owned(),
                (None, None) => bail!("variable `{name}` is not set"),
            };
            ensure!(
                !value.contains(['\n', '\r']),
                "variable `{name}` spans several lines"
            );
            out.push_str(&value);
            rest = &after[end + 1..];
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
    use super::*;

    fn env(name: &str) -> Option<String> {
        match name {
            "PORT" => Some("5353".to_owned()),
            "EMPTY" => Some(String::new()),
            "LINES" => Some("a\nb".to_owned()),
            "RETURN" => Some("a\rb: c".to_owned()),
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

    /// `coap://` takes port 5683 and the path `/` unless set, a path without query, fragment or `%`.
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
        let text = "listen: ['127.0.0.1:${PORT}']\npipeline: [cache, up]\nstages:\n  cache:\n    type: cache\n    max_ttl: 3600\n    max_insecure_ttl: 600\n    stale_answer_after_ms: 0\n  up:\n    type: forward\n    servers: ['192.0.2.1', '192.0.2.2:5353']\n    timeout_ms: 500\n    tries: 1\n";
        let config = read(text, env, &Pipeline::default()).unwrap();
        assert_eq!(
            config.listen,
            [Listen::Plain("127.0.0.1:5353".parse().unwrap())]
        );
        let [Stage::Cache(cache), _] = config.pipeline.stages() else {
            panic!("a cache stage, then a forward stage")
        };
        assert_eq!(cache.config().max_insecure_ttl, Some(600));
        assert!(read(MINIMAL, env, &Pipeline::default()).is_ok());
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
        let same = read(&text("    max_ttl: 604800\n"), env, &first)
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
            (format!("{MINIMAL}threads: 2\n"), "threads"),
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
}
