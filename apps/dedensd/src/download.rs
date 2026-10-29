//! Downloaded lists (D57): fetched over HTTP(S) off the serving threads, each kept on disk with its version tag
//! (`ETag`), so a start serves the last copy at once and an unchanged list is neither downloaded nor read again.

use std::fs;
use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::{Context, ensure};
use dedens_plugins::{List, Lists, Origin, Read};
use ureq::tls::{RootCerts, TlsConfig};

/// The largest list downloaded, as text: four times the largest published list read, 2M names in 36 MB.
const MAX_LIST_LEN: u64 = 256 << 20;

/// The time a download may take, connecting included.
const TIMEOUT: Duration = Duration::from_secs(30);

/// Downloads by result: `changed`, `unchanged` or `error`.
const FETCHES: &str = "dedensd_list_fetches_total";

/// The saved copy of the list at `url` in `dir`, named by a hash of the URL that stays the same across versions
/// and platforms (64-bit FNV-1a).
pub(crate) fn copy(dir: &Path, url: &str) -> PathBuf {
    let hash = url.bytes().fold(0xcbf2_9ce4_8422_2325_u64, |hash, byte| {
        (hash ^ u64::from(byte)).wrapping_mul(0x0100_0000_01b3)
    });
    dir.join(format!("{hash:016x}.list"))
}

/// The version tag of the saved copy `copy`.
fn tag(copy: &Path) -> PathBuf {
    copy.with_extension("etag")
}

/// The HTTP client of the downloads: certificates checked against the OS trust store, host names resolved by the
/// system resolver, gzip bodies inflated.
#[derive(Debug)]
pub(crate) struct Fetcher {
    agent: ureq::Agent,
}

/// What [`Fetcher::fetch`] found.
#[derive(Debug, Clone, Copy, Default)]
pub(crate) struct Fetched {
    /// A saved copy was replaced by a new version.
    pub(crate) changed: bool,
    /// A download failed, its previous copy kept.
    pub(crate) failed: bool,
}

impl Fetcher {
    pub(crate) fn new() -> Self {
        let tls = TlsConfig::builder()
            .root_certs(RootCerts::PlatformVerifier)
            .build();
        let agent = ureq::Agent::config_builder()
            .timeout_global(Some(TIMEOUT))
            .tls_config(tls)
            .build()
            .new_agent();
        Self { agent }
    }

    /// Downloads each list of `urls` into `dir`, logging and counting each result.
    pub(crate) fn fetch(&self, urls: &[String], dir: &Path) -> Fetched {
        let mut fetched = Fetched::default();
        for url in urls {
            match self.one(url, dir) {
                Ok(Some(read)) => {
                    fetched.changed = true;
                    metrics::counter!(FETCHES, "result" => "changed").increment(1);
                    tracing::info!(
                        url,
                        names = read.names,
                        skipped = read.skipped,
                        "list downloaded"
                    );
                }
                Ok(None) => {
                    metrics::counter!(FETCHES, "result" => "unchanged").increment(1);
                    tracing::info!(url, "list unchanged");
                }
                Err(error) => {
                    fetched.failed = true;
                    metrics::counter!(FETCHES, "result" => "error").increment(1);
                    tracing::warn!(
                        url,
                        error = format!("{error:#}"),
                        "list download failed, keeping the saved copy"
                    );
                }
            }
        }
        fetched
    }

    /// Downloads the list at `url` unless its saved copy in `dir` is the latest version: what it read, or `None`
    /// when unchanged. The copy is replaced only by a text that reads as a list.
    fn one(&self, url: &str, dir: &Path) -> anyhow::Result<Option<Read>> {
        let copy = copy(dir, url);
        let tag = tag(&copy);
        let mut request = self.agent.get(url);
        if copy.exists()
            && let Ok(version) = fs::read_to_string(&tag)
        {
            request = request.header("If-None-Match", version.trim());
        }
        let mut response = request.call()?;
        if response.status() == 304 {
            return Ok(None);
        }
        ensure!(response.status() == 200, "status {}", response.status());
        let version = response
            .headers()
            .get("etag")
            .and_then(|value| value.to_str().ok())
            .map(str::to_owned);
        let text = response
            .body_mut()
            .with_config()
            .limit(MAX_LIST_LEN)
            .read_to_string()?;
        // Block or allow, a list reads the same way.
        let read = Lists::new().read(List::Block, Origin::Downloaded, &text)?;
        fs::create_dir_all(dir).with_context(|| format!("creating `{}`", dir.display()))?;
        // A copy is written whole or not at all: a start after a crash reads the previous copy or this one.
        let part = copy.with_extension("part");
        fs::write(&part, &text).with_context(|| format!("writing `{}`", part.display()))?;
        fs::rename(&part, &copy).with_context(|| format!("writing `{}`", copy.display()))?;
        match version {
            Some(version) => fs::write(&tag, version),
            None => fs::remove_file(&tag).or_else(|error| match error.kind() {
                std::io::ErrorKind::NotFound => Ok(()),
                _ => Err(error),
            }),
        }
        .with_context(|| format!("writing `{}`", tag.display()))?;
        Ok(Some(read))
    }
}
