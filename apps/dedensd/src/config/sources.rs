//! The stages as written and their data: hosts entries, blocklists and the lists they read (D54, D57, D104, D118,
//! D120), and the cache stage a reload keeps or flushes (D77).

use std::collections::{BTreeMap, HashSet};
use std::num::{NonZeroU8, NonZeroU32, NonZeroU64};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;
use std::{fs, io};

use anyhow::{Context, anyhow, ensure};
use dedens_cache::Cache;
use dedens_dnssec::{ROOT_SIGNED_AT, RootAnchors, TrustAnchors};
use dedens_plugins::{Action, Blocklist, Hosts, ListError, Lists, Merged, Tlds, host_names};
use dedens_proto::{Question, RecordType, Ttl};
use dedens_server::{Pipeline, Stage};
use serde::Deserialize;
use serde::de::IgnoredAny;

use super::limits::BudgetFile;
use super::roots::RootsFile;
use super::upstream::{Dnssec, Insecure, OdohProxy, Relay, Server};
use super::{
    DOWNLOADS_DIR, MAX_PREWARM_NAMES, MAX_REFRESH_MINUTES, PLUGIN_TTL, REFRESH_MINUTES, STATE_DIR,
    unix_seconds,
};
use crate::download;
use crate::lists::{Store, Unsaved};
use crate::roots::{self, AnchorsUsed, TldsUsed, Used};

/// A stage, as written: its settings under its `type`.
#[derive(Debug, Deserialize)]
#[serde(tag = "type", rename_all = "lowercase", deny_unknown_fields)]
pub(super) enum StageFile {
    /// Settings of `dedens_cache::Config`, each defaulting to the RFCs' recommendation, and the names to keep
    /// answered (D96).
    Cache(CacheFile),
    /// Upstream servers, asked in order, each `tries` times waiting `timeout_ms` for a response.
    ///
    /// `random_case: false` sends the question to a plain server over UDP in the client's case: on by default, its
    /// letters go in a random case that the response must repeat, else it is dropped as forged (`0x20`, D184).
    ///
    /// `dnssec: validate` (D77) validates what they answer: AD is set for authentic answers only, a bogus one is
    /// SERVFAIL with an extended error. `trust_anchors` is a file of DS or DNSKEY records in zone file format, the
    /// root's bundled ones unless set; `insecure` lists names answered as they are, with their subdomains (RFC 7646).
    /// `client_share` is what a client network may spend of the validation allowance, in `rate` units a second and
    /// `burst` at once (D117): a unit is a question upstream or a signature check, about 10 µs.
    /// `relays` are Anonymized `DNSCrypt` relays (D100), relay stamps or addresses: every `sdns://` server of the stage
    /// is asked through one of them, drawn for each query; the stage needs such a server.
    /// `odoh_proxy` is an Oblivious `DoH` proxy (D185), `https://IP[:PORT][/PATH][#NAME]` as a server is written: every
    /// `https://` server of the stage is a target asked through it (RFC 9230); the stage needs such a server.
    Forward {
        servers: Vec<Server>,
        #[serde(default)]
        relays: Vec<Relay>,
        odoh_proxy: Option<OdohProxy>,
        timeout_ms: Option<NonZeroU32>,
        tries: Option<NonZeroU8>,
        random_case: Option<bool>,
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
    /// Answers, with no upstream query, the special-use top-level domains as their RFCs ask and the names of TLDs
    /// not in the root zone (D128), from IANA's list kept fresh as `roots` says. It goes before a cache stage.
    Tlds {},
}

/// A cache stage, as written: the settings of `dedens_cache::Config` and, beside them, the names to keep answered
/// (D96). Beside, not in: a change of the names runs prewarm again and keeps the cache, which D55 replaces when its
/// settings change.
///
/// The settings are flattened, which makes serde ignore `deny_unknown_fields`, so a map takes what no field reads
/// and the conversion refuses it.
#[derive(Debug, Deserialize)]
#[serde(try_from = "CacheRaw")]
pub(super) struct CacheFile {
    pub(super) settings: dedens_cache::Config,
    pub(super) prewarm: Option<PrewarmFile>,
}

#[derive(Deserialize)]
struct CacheRaw {
    #[serde(flatten)]
    settings: dedens_cache::Config,
    prewarm: Option<PrewarmFile>,
    #[serde(flatten)]
    #[expect(
        clippy::zero_sized_map_values,
        reason = "a map takes the keys no field reads: serde has no other way to see them next to a flatten"
    )]
    unknown: BTreeMap<String, IgnoredAny>,
}

impl TryFrom<CacheRaw> for CacheFile {
    type Error = String;

    fn try_from(raw: CacheRaw) -> Result<Self, String> {
        match raw.unknown.into_keys().next() {
            Some(key) => Err(format!("unknown field `{key}`")),
            None => Ok(Self {
                settings: raw.settings,
                prewarm: raw.prewarm,
            }),
        }
    }
}

/// The names a cache stage keeps answered, as written (D96): `entries`, one name a line, then those of `file`, each
/// asked for `types`, A and AAAA unless set.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct PrewarmFile {
    #[serde(default)]
    entries: Vec<String>,
    file: Option<PathBuf>,
    types: Option<Vec<PrewarmType>>,
}

/// A type a name is kept answered for.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Deserialize)]
enum PrewarmType {
    A,
    #[serde(rename = "AAAA")]
    Aaaa,
}

/// Names of a list, as written: `entries`, then those of `file`, then the saved copies of `urls` (D57).
#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Sources {
    #[serde(default)]
    entries: Vec<String>,
    file: Option<PathBuf>,
    #[serde(default)]
    urls: Vec<Url>,
}

/// The URL of a list: `https://`, or `http://` for a server of one's own.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(try_from = "String")]
pub(super) struct Url(String);

impl Url {
    /// One of IANA's, written here.
    pub(super) fn iana(url: &'static str) -> Self {
        Self(url.to_owned())
    }

    pub(super) fn as_str(&self) -> &str {
        &self.0
    }
}

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
pub(super) struct DownloadsFile {
    dir: Option<PathBuf>,
    refresh_minutes: Option<NonZeroU64>,
}

/// Downloaded lists: their URLs, where their copies are kept, how often they are fetched again (D57); and the root
/// files used, fetched as often: the TLD list kept in `dir` too, the root anchors in `state_dir` (D128).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Downloads {
    pub(crate) urls: Vec<String>,
    pub(crate) dir: PathBuf,
    pub(crate) refresh: Duration,
    pub(crate) state_dir: PathBuf,
    pub(crate) roots: Used,
    /// Where the root files come from.
    sources: RootsFile,
}

impl StageFile {
    /// Whether building it reads a file: its `file`, its `prewarm` `file`, its `trust_anchors`, the saved copies of
    /// its `urls`, or of those of its `allow`.
    pub(super) fn names_files(&self) -> bool {
        match self {
            Self::Cache(CacheFile { prewarm, .. }) => prewarm
                .as_ref()
                .is_some_and(|prewarm| prewarm.file.is_some()),
            Self::Forward { trust_anchors, .. } => trust_anchors.is_some(),
            Self::Hosts { file, .. } => file.is_some(),
            Self::Blocklist {
                file, urls, allow, ..
            } => {
                file.is_some() || !urls.is_empty() || allow.file.is_some() || !allow.urls.is_empty()
            }
            Self::Tlds {} => false,
        }
    }
}

impl Sources {
    pub(super) fn new(entries: Vec<String>, file: Option<PathBuf>, urls: Vec<Url>) -> Self {
        Self {
            entries,
            file,
            urls,
        }
    }
}

impl Downloads {
    /// No list nor root file yet, as `settings` say, root files fetched as `roots` says, the anchors kept in
    /// `state_dir`.
    ///
    /// # Errors
    ///
    /// `refresh_minutes` above a year.
    pub(super) fn new(
        settings: DownloadsFile,
        roots: RootsFile,
        state_dir: Option<PathBuf>,
    ) -> anyhow::Result<Self> {
        Ok(Self {
            urls: Vec::new(),
            dir: settings.dir.unwrap_or_else(|| DOWNLOADS_DIR.into()),
            refresh: refresh(settings.refresh_minutes)?,
            state_dir: state_dir.unwrap_or_else(|| STATE_DIR.into()),
            roots: Used::default(),
            sources: roots,
        })
    }

    /// Whether nothing is downloaded: no list, no root file.
    pub(crate) fn is_empty(&self) -> bool {
        self.urls.is_empty() && self.roots.is_empty()
    }

    /// The directory `user` must write once root is dropped: `dir`, if the configuration downloads lists (D122).
    pub(crate) fn written_dir(&self) -> Option<&Path> {
        (!self.urls.is_empty()).then_some(self.dir.as_path())
    }

    /// The directories of the root files used, made for `user` when root is dropped; not writing them only keeps
    /// the copies there, or the bundled ones (D128).
    pub(crate) fn roots_dirs(&self) -> Vec<&Path> {
        let mut dirs = Vec::new();
        if self.roots.tlds.is_some() {
            dirs.push(self.dir.as_path());
        }
        if self.roots.anchors.is_some() {
            dirs.push(self.state_dir.as_path());
        }
        dirs
    }

    /// The TLD list of a `tlds` stage: the saved copy in `dir`, held in `store`, and fetched from now on, unless
    /// `roots` is `off`; else, or with no copy, the bundled one. Warned of when older than 30 days.
    ///
    /// # Errors
    ///
    /// A saved copy that cannot be read (D115).
    pub(super) fn tlds(&mut self, store: &mut Store) -> anyhow::Result<Arc<dedens_roots::Tlds>> {
        let tlds = match &self.sources {
            RootsFile::Off => roots::bundled(),
            RootsFile::Fetched(urls) => {
                let tlds = store.roots.tlds(&self.dir, urls.tlds())?;
                self.roots.tlds = Some(TldsUsed {
                    url: urls.tlds().to_owned(),
                    generated: tlds.generated(),
                });
                tlds
            }
        };
        if roots::stale(&tlds, unix_seconds()) {
            tracing::warn!(
                generated = tlds.generated(),
                "the TLD list is older than 30 days: TLDs outside it are passed on, not answered NXDOMAIN"
            );
        }
        Ok(tlds)
    }

    /// The root's anchors of a validating forward stage without `trust_anchors`, valid now: those kept in
    /// `state_dir`, held in `store`, fetched from now on, unless `roots` is `off`; `None` for the bundled ones.
    ///
    /// # Errors
    ///
    /// A kept file that cannot be read (D115), or with no key valid now.
    pub(super) fn root_anchors(
        &mut self,
        store: &mut Store,
    ) -> anyhow::Result<Option<TrustAnchors>> {
        let RootsFile::Fetched(urls) = &self.sources else {
            return Ok(None);
        };
        if self.roots.anchors.is_none() {
            let kept = store.roots.anchors(&self.state_dir)?;
            self.roots.anchors = Some(AnchorsUsed {
                url: urls.anchors().to_owned(),
                signature: urls.signature(),
                signed_at: kept.map_or(ROOT_SIGNED_AT, RootAnchors::signed_at),
                valid: roots::valid(kept, unix_seconds())?,
            });
        }
        Ok(self.roots.anchors.as_ref().map(|used| used.valid.clone()))
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

/// The stage of a hosts file and entries (`file` is read at start, `entries` are inline).
pub(super) fn hosts(
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

/// The blocklist stage `name` of the lists `block` and `allow`, with its `action` and `ttl`; the URLs it downloads are
/// added to `downloads`.
///
/// # Errors
///
/// A list that does not read, or a saved copy that exists but cannot be read (D115).
pub(super) fn blocklist(
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
pub(super) fn flush(built: &mut [Stage], previous: &Pipeline) -> anyhow::Result<()> {
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

/// The questions a cache stage keeps answered, from `prewarm` (D96): each distinct name, in order, once for each of
/// the types.
///
/// # Errors
///
/// A file that cannot be read, a line that is not a name, or a wildcard; more than [`MAX_PREWARM_NAMES`] names; no
/// type.
pub(super) fn prewarm(name: &str, prewarm: &PrewarmFile) -> anyhow::Result<Vec<Question<'static>>> {
    let mut names = local(&prewarm.entries, prewarm.file.as_deref(), |text| {
        Ok(host_names(text)?)
    })
    .with_context(|| format!("stage `{name}`, `prewarm`"))?;
    let mut seen = HashSet::new();
    names.retain(|name| seen.insert(name.clone()));
    ensure!(
        names.len() <= MAX_PREWARM_NAMES,
        "stage `{name}`: `prewarm` names more than {MAX_PREWARM_NAMES} names"
    );
    let mut types = prewarm
        .types
        .clone()
        .unwrap_or_else(|| vec![PrewarmType::A, PrewarmType::Aaaa]);
    types.sort_unstable();
    types.dedup();
    ensure!(!types.is_empty(), "stage `{name}`: `prewarm` has no type");
    Ok(names
        .into_iter()
        .flat_map(|name| {
            types.iter().map(move |kind| {
                let qtype = match kind {
                    PrewarmType::A => RecordType::A,
                    PrewarmType::Aaaa => RecordType::AAAA,
                };
                Question::new(name.clone(), qtype)
            })
        })
        .collect())
}

/// The cache stage `name` of `config`: the one of `previous` while its settings stay, so that a reload keeps the
/// entries.
///
/// # Errors
///
/// Settings the cache refuses.
pub(super) fn cache(
    name: &str,
    config: dedens_cache::Config,
    previous: &Pipeline,
) -> anyhow::Result<Stage> {
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
        let not_a_list = |error: &dyn std::fmt::Display| {
            tracing::warn!(stage, url = download::redacted(url), %error, "the saved copy is not a list");
        };
        match store.saved(&copy, &download::redacted(url)) {
            Ok(saved) => match saved.check(tlds) {
                Ok(_) => names.push(saved),
                Err(error) => not_a_list(&error),
            },
            Err(Unsaved::NotText(error)) => not_a_list(&error),
            Err(Unsaved::Io(error)) if error.kind() == io::ErrorKind::NotFound => {
                tracing::info!(
                    stage,
                    url = download::redacted(url),
                    "list not downloaded yet"
                );
            }
            Err(Unsaved::Io(error)) => {
                return Err(error).with_context(|| format!("reading `{}`", copy.display()));
            }
        }
    }
    store.merged(tlds, &names)
}

#[cfg(test)]
mod tests {
    use dedens_plugins::List;

    use super::*;
    use crate::config::tests::*;

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

    /// D128: the anchors kept in `state_dir`, read without their signature, are those the validator trusts; a kept
    /// set other than the one in use builds a new validator, whose keys are proven again, and flushes the cache
    /// filled under the old one. The kept text is the captured pair's, verified (`dedens-dnssec`'s test
    /// `the_kept_anchors_read_back_as_written_with_each_keys_validity`), then edited: KSK-2017 given an end, as a
    /// rollover would, gone from the root's anchors since; or a line of another format.
    #[test]
    fn kept_root_anchors_key_the_validator_and_a_new_set_flushes_the_cache() {
        const KEPT: &str = "dedens root anchors 1\nsigned-at 1742934302\n\
            ds 19036 8 2 49aac11d7b6f6446702e54a1607371607a1a41855200fd2ce1cdde32f24e8fb5 from 1279152000 until 1547164800\n\
            ds 20326 8 2 e06d44b80b8f1d39a95c0b0d7c65d08458e880409bbc683457104237c7f8ec8d from 1485993600\n\
            ds 38696 8 2 683d2d0acb8c9b712a1948b27f741219298d0a450d612c483af444a4c0fb2b16 from 1721260800\n";
        let state = tempfile::tempdir().unwrap();
        let file = state.path().join(roots::ANCHORS);
        let text = format!(
            "listen: ['127.0.0.1:53']\nstate_dir: '{}'\npipeline: [cache, up]\nstages:\n  cache:\n    type: cache\n  up:\n    type: forward\n    servers: ['192.0.2.1']\n    dnssec: validate\n",
            state.path().display()
        );
        let mut store = Store::default();
        let mut build = |previous: &Pipeline| {
            crate::config::read(&text, env, previous, &mut store).map(|config| config.pipeline)
        };
        let parts = |pipeline: &Pipeline| match pipeline.stages() {
            [Stage::Cache(cache), Stage::Forward(forward)] => (
                Arc::clone(cache),
                forward.validation().unwrap().validator().clone(),
                forward.validation_tag().unwrap().to_owned(),
            ),
            stages => unreachable!("{stages:?}"),
        };
        let bundled = build(&Pipeline::default()).unwrap();
        assert_eq!(
            parts(&bundled).2,
            format!("validate\n{}", TrustAnchors::root())
        );

        // The captured keys valid now are the bundled ones: nothing to flush.
        fs::write(&file, KEPT).unwrap();
        let captured = build(&bundled).unwrap();
        assert!(Arc::ptr_eq(&parts(&bundled).0, &parts(&captured).0));
        assert!(parts(&bundled).1.shares_cache(&parts(&captured).1));

        let rolled = KEPT.replace("from 1485993600", "from 1485993600 until 1735689600");
        fs::write(&file, rolled).unwrap();
        let new = build(&captured).unwrap();
        let (cache, validator, tag) = parts(&new);
        assert!(!tag.contains("20326") && tag.contains("38696"), "{tag}");
        assert!(!Arc::ptr_eq(&parts(&captured).0, &cache), "flushed");
        assert!(!parts(&captured).1.shares_cache(&validator), "proven again");
        let same = build(&new).unwrap();
        assert!(
            Arc::ptr_eq(&cache, &parts(&same).0),
            "kept while the set stays"
        );

        // A kept file that does not read keeps the anchors in use on reload, and refuses a start (D115).
        fs::write(&file, "dedens root anchors 2\n").unwrap();
        assert_eq!(parts(&build(&same).unwrap()).2, tag);
        let error = crate::config::read(&text, env, &Pipeline::default(), &mut Store::default())
            .unwrap_err();
        assert!(format!("{error:#}").contains("line 1"), "{error:#}");
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
                state_dir: STATE_DIR.into(),
                roots: Used::default(),
                sources: RootsFile::default(),
            }
        );
    }

    /// D115: a downloaded list not fetched yet is empty, a saved copy that is not a list, text or not, is left out,
    /// and a saved copy that does not read stops the start.
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
        // A DNS response, saved in its place: not UTF-8.
        std::fs::write(&copy, dedens_testkit::captured("a")).unwrap();
        assert!(read(&text, env, &Pipeline::default()).is_ok(), "no text");
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
}
