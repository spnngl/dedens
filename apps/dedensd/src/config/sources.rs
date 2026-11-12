//! The stages as written and their data: hosts entries, blocklists and the lists they read (D54, D57, D104, D118,
//! D120), and the cache stage a reload keeps or flushes (D77).

use std::num::{NonZeroU8, NonZeroU32, NonZeroU64};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;
use std::{fs, io};

use anyhow::{Context, anyhow, ensure};
use dedens_cache::Cache;
use dedens_plugins::{Action, Blocklist, Hosts, ListError, Lists, Merged, Tlds};
use dedens_proto::Ttl;
use dedens_server::{Pipeline, Stage};
use serde::Deserialize;

use super::limits::BudgetFile;
use super::upstream::{Dnssec, Insecure, Server};
use super::{DOWNLOADS_DIR, MAX_REFRESH_MINUTES, PLUGIN_TTL, REFRESH_MINUTES};
use crate::download;
use crate::lists::Store;

/// A stage, as written: its settings under its `type`.
#[derive(Debug, Deserialize)]
#[serde(tag = "type", rename_all = "lowercase", deny_unknown_fields)]
pub(super) enum StageFile {
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

/// Downloaded lists: their URLs, where their copies are kept, how often they are fetched again (D57).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Downloads {
    pub(crate) urls: Vec<String>,
    pub(crate) dir: PathBuf,
    pub(crate) refresh: Duration,
}

impl StageFile {
    /// Whether building it reads a file: its `file`, its `trust_anchors`, the saved copies of its `urls`, or of those
    /// of its `allow`.
    pub(super) fn names_files(&self) -> bool {
        match self {
            Self::Cache(_) => false,
            Self::Forward { trust_anchors, .. } => trust_anchors.is_some(),
            Self::Hosts { file, .. } => file.is_some(),
            Self::Blocklist {
                file, urls, allow, ..
            } => {
                file.is_some() || !urls.is_empty() || allow.file.is_some() || !allow.urls.is_empty()
            }
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
    /// No list yet, as `settings` say.
    ///
    /// # Errors
    ///
    /// `refresh_minutes` above a year.
    pub(super) fn new(settings: DownloadsFile) -> anyhow::Result<Self> {
        Ok(Self {
            urls: Vec::new(),
            dir: settings.dir.unwrap_or_else(|| DOWNLOADS_DIR.into()),
            refresh: refresh(settings.refresh_minutes)?,
        })
    }

    /// The directory `user` must write once root is dropped: `dir`, if the configuration downloads lists (D122).
    pub(crate) fn written_dir(&self) -> Option<&Path> {
        (!self.urls.is_empty()).then_some(self.dir.as_path())
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
}
