//! Downloaded lists (D57): fetched over HTTP(S) off the serving threads, each kept on disk with its version tag
//! (`ETag`), so a start serves the last copy at once and an unchanged list is neither downloaded nor read again.

use std::fs;
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::{Context, ensure};
use dedens_plugins::{Lists, Read};
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
        // A redirect never takes an `https://` list to `http://`, where anyone on the path could change it.
        let mut request = self
            .agent
            .get(url)
            .config()
            .https_only(url.starts_with("https://"))
            .build();
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
        let read = Lists::check(&text)?;
        fs::create_dir_all(dir).with_context(|| format!("creating `{}`", dir.display()))?;
        save(&copy, &text, version.as_deref())?;
        Ok(Some(read))
    }
}

/// Saves `text` as the copy `copy`, then `version` as its tag, so that they never disagree, even across a crash:
/// the old tag is removed first, and each file is written whole or not at all. A tag that cannot be written is
/// logged, not an error: the copy is saved, and fetched whole next time.
///
/// # Errors
///
/// The old tag or the copy not replaced; the previous copy is then kept, without a tag.
fn save(copy: &Path, text: &str, version: Option<&str>) -> anyhow::Result<()> {
    let tag = tag(copy);
    let dir = copy.parent().unwrap_or(Path::new("."));
    match fs::remove_file(&tag) {
        Err(error) if error.kind() != io::ErrorKind::NotFound => Err(error),
        _ => sync_dir(dir),
    }
    .with_context(|| format!("removing `{}`", tag.display()))?;
    replace(copy, text).with_context(|| format!("writing `{}`", copy.display()))?;
    if let Some(version) = version
        && let Err(error) = replace(&tag, version)
    {
        tracing::warn!(tag = %tag.display(), %error, "version tag not saved, the list will be fetched whole");
    }
    Ok(())
}

/// Writes `contents` to `path` whole or not at all: to `path` with `.part` appended, flushed to disk, then renamed
/// over `path`, the directory flushed too.
fn replace(path: &Path, contents: &str) -> io::Result<()> {
    let mut part = path.as_os_str().to_owned();
    part.push(".part");
    let part = PathBuf::from(part);
    let mut file = fs::File::create(&part)?;
    file.write_all(contents.as_bytes())?;
    file.sync_all()?;
    fs::rename(&part, path)?;
    sync_dir(path.parent().unwrap_or(Path::new(".")))
}

/// Flushes the entries of `dir` to disk, so a rename or removal in it survives a crash; a no-op where a directory
/// cannot be opened as a file.
fn sync_dir(dir: &Path) -> io::Result<()> {
    if cfg!(unix) {
        fs::File::open(dir)?.sync_all()
    } else {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_copy_is_saved_without_a_stale_tag_when_its_tag_cannot_be() {
        let dir = std::env::temp_dir().join(format!("dedensd-save-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        let copy = copy(&dir, "https://a.example/list");
        save(&copy, "a.example\n", Some("\"v1\"")).unwrap();
        assert_eq!(fs::read_to_string(tag(&copy)).unwrap(), "\"v1\"");
        // The new tag cannot be written: a directory stands where it would be.
        let mut part = tag(&copy).into_os_string();
        part.push(".part");
        fs::create_dir(&part).unwrap();
        save(&copy, "b.example\n", Some("\"v2\"")).unwrap();
        assert_eq!(fs::read_to_string(&copy).unwrap(), "b.example\n");
        assert!(!tag(&copy).exists(), "the tag of the previous copy is gone");
        fs::remove_dir_all(&dir).unwrap();
    }
}
