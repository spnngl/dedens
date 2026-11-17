//! IANA's root files kept fresh (D128): the TLD list of the `tlds` stage and the root's trust anchors of the
//! validating forward stages without `trust_anchors`. Fetched with the downloaded lists (D104) into `downloads.dir`,
//! each refresh, and read from there at start and on each reload, as the user (D122); with no saved copy, or one that
//! does not read or verify, the bundled one serves.
//!
//! The anchors and their signature are fetched whole, about 10 KB, and kept once verified (RFC 9718 §3), with the
//! signing time of the pair in its own file: the floor the next pair is checked against, so a server cannot roll
//! the anchors back to an older signed set. A refresh that fails leaves the files, and the anchors in use, as they
//! are.

use std::fs;
use std::fs::File;
use std::io::{self, Read as _};
use std::path::Path;
use std::sync::{Arc, LazyLock};
use std::time::SystemTime;

use anyhow::{Context, anyhow};
use dedens_dnssec::{MAX_P7S, MAX_XML, TrustAnchors};
use dedens_roots::{Kind, Tlds};

use crate::download::{self, Fetched, Fetcher, Outcome, failure, redacted, replace};
use crate::lists::Stamp;

/// The saved TLD list.
const TLDS: &str = "tlds.json";

/// Its version tag (`download::save`).
const TLDS_TAG: &str = "tlds.etag";

/// The saved `root-anchors.xml`.
const ANCHORS: &str = "root-anchors.xml";

/// Its detached signature.
const SIGNATURE: &str = "root-anchors.p7s";

/// When ICANN signed the saved pair, in seconds since 1970, as decimal text: written last, once both are.
const SIGNED_AT: &str = "root-anchors.signed_at";

/// The files kept in `downloads.dir`, whose `.part` leftovers the start sweeps (D104).
pub(crate) const FILES: [&str; 5] = [TLDS, TLDS_TAG, ANCHORS, SIGNATURE, SIGNED_AT];

/// The largest TLD list fetched, 32 MiB: ten times IANA's, 2.9 MB in 2026.
const MAX_TLDS_LEN: u64 = 32 << 20;

/// The age of each saved file, by `file`, `tlds` or `anchors`: seconds since its source last confirmed it, set at
/// each refresh.
const AGE: &str = "dedensd_roots_age_seconds";

/// The bundled TLD list, shared by every `tlds` stage that has no fresher one.
static BUNDLED: LazyLock<Arc<Tlds>> = LazyLock::new(|| Arc::new(Tlds::bundled().clone()));

/// The bundled TLD list.
pub(crate) fn bundled() -> Arc<Tlds> {
    Arc::clone(&BUNDLED)
}

/// The URLs of the root files the configuration uses: none with `roots: off`, the TLD list for a `tlds` stage, the
/// anchors and their signature for a validating forward stage without `trust_anchors`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct Used {
    pub(crate) tlds: Option<String>,
    pub(crate) anchors: Option<(String, String)>,
}

impl Used {
    /// Whether no root file is fetched.
    pub(crate) fn is_empty(&self) -> bool {
        self.tlds.is_none() && self.anchors.is_none()
    }
}

/// The TLD list read last, kept across reloads while its saved copy is unchanged, as the lists are (D120).
#[derive(Debug, Default)]
pub(crate) struct Held {
    tlds: Option<(Stamp, Arc<Tlds>)>,
}

impl Held {
    /// The TLD list in `dir`: the saved copy, or the bundled one when there is none, or it does not read as a list
    /// at least half the bundled one's length, which is warned of.
    ///
    /// # Errors
    ///
    /// A saved copy that is there but cannot be read, as a saved list (D115).
    pub(crate) fn tlds(&mut self, dir: &Path) -> anyhow::Result<Arc<Tlds>> {
        let path = dir.join(TLDS);
        let mut file = match File::open(&path) {
            Ok(file) => file,
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                return Ok(Arc::clone(&BUNDLED));
            }
            Err(error) => {
                return Err(anyhow!(error).context(format!("reading `{}`", path.display())));
            }
        };
        let stamp = Stamp::of(&file).with_context(|| format!("reading `{}`", path.display()))?;
        if let Some((held, tlds)) = &self.tlds
            && *held == stamp
        {
            return Ok(Arc::clone(tlds));
        }
        let mut json = Vec::new();
        file.read_to_end(&mut json)
            .with_context(|| format!("reading `{}`", path.display()))?;
        let tlds = match Tlds::read(&json) {
            Ok(tlds) => {
                unknown_special_use(&tlds);
                Arc::new(tlds)
            }
            Err(error) => {
                tracing::warn!(path = %path.display(), %error, "the saved TLD list does not read, using the bundled one");
                Arc::clone(&BUNDLED)
            }
        };
        self.tlds = Some((stamp, Arc::clone(&tlds)));
        Ok(tlds)
    }
}

/// Warns of each special-use TLD of `tlds` the `tlds` stage has no row for: it is answered as its status says.
fn unknown_special_use(tlds: &Tlds) {
    for tld in tlds {
        if matches!(tld.kind(), Kind::SpecialUse { .. })
            && let Some(label) = tld.name().labels().last()
            && dedens_plugins::special(label).is_none()
        {
            tracing::warn!(
                tld = %tld.name(),
                "a special-use TLD the tlds stage has no rule for, answered as its status says"
            );
        }
    }
}

/// Root anchors verified from the saved copy in `dir` at `now`, with when they were signed; `None` for the bundled
/// ones: no saved pair, one that does not verify, which is warned of, or one holding the bundled anchors.
///
/// # Errors
///
/// A saved file that is there but cannot be read.
pub(crate) fn anchors(dir: &Path, now: u64) -> anyhow::Result<Option<(TrustAnchors, u64)>> {
    let (Some(xml), Some(p7s)) = (saved(&dir.join(ANCHORS))?, saved(&dir.join(SIGNATURE))?) else {
        return Ok(None);
    };
    match TrustAnchors::verified(&xml, &p7s, now, signed_at(dir)?) {
        Ok(signed) => {
            tracing::info!(
                signed_at = signed.signed_at(),
                "root trust anchors from the saved copy"
            );
            let at = signed.signed_at();
            let anchors = signed.into_anchors();
            Ok((anchors != TrustAnchors::root()).then_some((anchors, at)))
        }
        Err(error) => {
            tracing::warn!(%error, "the saved root trust anchors do not verify, using the bundled ones");
            Ok(None)
        }
    }
}

/// The bytes of `path`; `None` when it is not there.
fn saved(path: &Path) -> anyhow::Result<Option<Vec<u8>>> {
    match fs::read(path) {
        Ok(bytes) => Ok(Some(bytes)),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(anyhow!(error).context(format!("reading `{}`", path.display()))),
    }
}

/// The signing time of the last pair kept in `dir`, the floor of the next; `None` when not there, or not a number,
/// which is warned of: the bundled floor still holds.
fn signed_at(dir: &Path) -> anyhow::Result<Option<u64>> {
    let path = dir.join(SIGNED_AT);
    let Some(text) = saved(&path)? else {
        return Ok(None);
    };
    let at = String::from_utf8(text)
        .ok()
        .and_then(|text| text.trim().parse().ok());
    if at.is_none() {
        tracing::warn!(path = %path.display(), "not a signing time, ignored");
    }
    Ok(at)
}

/// When the source last confirmed each saved file, for [`AGE`]: kept by the thread of the downloads.
#[derive(Debug, Default)]
pub(crate) struct Refresh {
    tlds: Option<SystemTime>,
    anchors: Option<SystemTime>,
}

impl Refresh {
    /// Fetches the files of `used` into `dir`, anchors verified at `now`, in seconds since 1970, logging each result.
    pub(crate) fn fetch(&mut self, client: &Fetcher, used: &Used, dir: &Path, now: u64) -> Fetched {
        let mut fetched = Fetched::default();
        if let Some(url) = &used.tlds {
            let shown = redacted(url);
            let outcome = match fetch_tlds(client, url, dir) {
                Ok(true) => {
                    tracing::info!(url = shown, "TLD list downloaded");
                    Outcome::Changed
                }
                Ok(false) => {
                    tracing::info!(url = shown, "TLD list unchanged");
                    Outcome::Unchanged
                }
                Err(error) => {
                    tracing::warn!(
                        url = shown,
                        error = failure(&error),
                        "TLD list download failed, keeping the one in use"
                    );
                    Outcome::Failed
                }
            };
            note(
                &mut fetched,
                &mut self.tlds,
                outcome,
                "tlds",
                &dir.join(TLDS),
            );
        }
        if let Some(urls) = &used.anchors {
            let shown = redacted(&urls.0);
            let outcome = match fetch_anchors(client, urls, dir, now) {
                Ok(Some(at)) => {
                    tracing::info!(url = shown, signed_at = at, "root trust anchors downloaded");
                    Outcome::Changed
                }
                Ok(None) => {
                    tracing::info!(url = shown, "root trust anchors unchanged");
                    Outcome::Unchanged
                }
                Err(error) => {
                    tracing::warn!(
                        url = shown,
                        error = failure(&error),
                        "root trust anchors download failed, keeping the ones in use"
                    );
                    Outcome::Failed
                }
            };
            note(
                &mut fetched,
                &mut self.anchors,
                outcome,
                "anchors",
                &dir.join(SIGNED_AT),
            );
        }
        fetched
    }
}

/// Adds `outcome` to `fetched` and sets the [`AGE`] of `file`, `saved`: from `confirmed`, when the source last
/// confirmed it, taken from the modification time of `saved` while not known.
fn note(
    fetched: &mut Fetched,
    confirmed: &mut Option<SystemTime>,
    outcome: Outcome,
    file: &'static str,
    saved: &Path,
) {
    fetched.changed |= outcome == Outcome::Changed;
    fetched.failed |= outcome == Outcome::Failed;
    if outcome != Outcome::Failed {
        *confirmed = Some(SystemTime::now());
    } else if confirmed.is_none() {
        *confirmed = fs::metadata(saved).and_then(|meta| meta.modified()).ok();
    }
    if let Some(at) = confirmed {
        let age = SystemTime::now().duration_since(*at).unwrap_or_default();
        metrics::gauge!(AGE, "file" => file).set(age.as_secs_f64());
    }
}

/// Fetches the TLD list at `url` unless the copy in `dir` is the latest, keeping a new one only once it reads:
/// whether it changed.
fn fetch_tlds(client: &Fetcher, url: &str, dir: &Path) -> anyhow::Result<bool> {
    let copy = dir.join(TLDS);
    let Some((json, version)) =
        client.get(url, download::saved_tag(&copy).as_deref(), MAX_TLDS_LEN)?
    else {
        return Ok(false);
    };
    Tlds::read(&json)?;
    fs::create_dir_all(dir).with_context(|| format!("creating `{}`", dir.display()))?;
    download::save(&copy, &json, version.as_deref())?;
    Ok(true)
}

/// Fetches the anchors and their signature at `urls`, keeping them once verified at `now` against the floor of the
/// pair in `dir`: their signing time when new, `None` when they are the pair kept.
fn fetch_anchors(
    client: &Fetcher,
    (xml_url, p7s_url): &(String, String),
    dir: &Path,
    now: u64,
) -> anyhow::Result<Option<u64>> {
    let whole = |url: &str, limit: usize| -> anyhow::Result<Vec<u8>> {
        let limit = u64::try_from(limit).unwrap_or(u64::MAX);
        client
            .get(url, None, limit)?
            .map(|(body, _)| body)
            .ok_or_else(|| anyhow!("no body"))
    };
    let xml = whole(xml_url, MAX_XML)?;
    let p7s = whole(p7s_url, MAX_P7S)?;
    let floor = signed_at(dir)?;
    let at = TrustAnchors::verified(&xml, &p7s, now, floor)?.signed_at();
    if floor == Some(at)
        && saved(&dir.join(ANCHORS))?.is_some_and(|saved| saved == xml)
        && saved(&dir.join(SIGNATURE))?.is_some_and(|saved| saved == p7s)
    {
        return Ok(None);
    }
    fs::create_dir_all(dir).with_context(|| format!("creating `{}`", dir.display()))?;
    for (name, bytes) in [
        (ANCHORS, xml),
        (SIGNATURE, p7s),
        (SIGNED_AT, format!("{at}\n").into_bytes()),
    ] {
        let path = dir.join(name);
        replace(&path, bytes).with_context(|| format!("writing `{}`", path.display()))?;
    }
    Ok(Some(at))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// When the captured pair was fetched, in seconds since 1970.
    fn captured_at() -> u64 {
        fs::read_to_string(dedens_testkit::path("dnssec/root-anchors.captured_at"))
            .unwrap()
            .trim()
            .parse()
            .unwrap()
    }

    fn captured(name: &str) -> Vec<u8> {
        fs::read(dedens_testkit::path(&format!("dnssec/{name}"))).unwrap()
    }

    /// A directory holding the captured pair, and `signed_at` if given.
    fn pair(signed_at: Option<&str>) -> tempfile::TempDir {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join(ANCHORS), captured("root-anchors.xml")).unwrap();
        fs::write(dir.path().join(SIGNATURE), captured("root-anchors.p7s")).unwrap();
        if let Some(at) = signed_at {
            fs::write(dir.path().join(SIGNED_AT), at).unwrap();
        }
        dir
    }

    /// The captured pair holds the bundled anchors: verified, it is the bundled set, `None`.
    #[test]
    fn a_saved_pair_of_the_bundled_anchors_reads_as_them() {
        assert_eq!(anchors(pair(None).path(), captured_at()).unwrap(), None);
        assert_eq!(
            anchors(pair(Some("garbage")).path(), captured_at()).unwrap(),
            None
        );
    }

    /// RFC 9718 §3: no saved pair, or one under a floor later than its signing time, or a signature that is not
    /// the XML's, leaves the bundled anchors, and is no error.
    #[test]
    fn a_pair_that_does_not_verify_leaves_the_bundled_anchors() {
        let empty = tempfile::tempdir().unwrap();
        assert_eq!(anchors(empty.path(), captured_at()).unwrap(), None);
        assert_eq!(
            anchors(pair(Some("99999999999\n")).path(), captured_at()).unwrap(),
            None
        );
        let dir = pair(None);
        fs::write(dir.path().join(SIGNATURE), b"not a signature").unwrap();
        assert_eq!(anchors(dir.path(), captured_at()).unwrap(), None);
    }

    /// D115: a saved file that is there but cannot be read is an error, not the bundled set.
    #[cfg(unix)]
    #[test]
    fn an_unreadable_saved_file_is_an_error() {
        let dir = pair(None);
        fs::remove_file(dir.path().join(ANCHORS)).unwrap();
        fs::create_dir(dir.path().join(ANCHORS)).unwrap();
        assert!(anchors(dir.path(), captured_at()).is_err());
        let mut held = Held::default();
        fs::create_dir(dir.path().join(TLDS)).unwrap();
        assert!(held.tlds(dir.path()).is_err());
        // Not a directory: an error other than not found.
        assert!(held.tlds(&dir.path().join(SIGNATURE)).is_err());
    }

    /// No saved list, or one that does not read, is the bundled one; a saved one is read once while unchanged.
    #[test]
    fn the_saved_tld_list_is_read_once_and_falls_back_to_the_bundled_one() {
        let dir = tempfile::tempdir().unwrap();
        let mut held = Held::default();
        assert!(Arc::ptr_eq(&held.tlds(dir.path()).unwrap(), &BUNDLED));
        fs::write(dir.path().join(TLDS), b"{}").unwrap();
        assert!(Arc::ptr_eq(&held.tlds(dir.path()).unwrap(), &BUNDLED));
        replace(
            &dir.path().join(TLDS),
            include_bytes!("../../../crates/dedens-roots/src/tlds.json"),
        )
        .unwrap();
        let first = held.tlds(dir.path()).unwrap();
        assert!(!Arc::ptr_eq(&first, &BUNDLED));
        assert_eq!(*first, **BUNDLED);
        assert!(Arc::ptr_eq(&held.tlds(dir.path()).unwrap(), &first));
    }

    /// RFC 9718 §3: a fetched pair is kept once verified, with its signing time, and fetched again it is unchanged;
    /// under a later floor it is refused and the files stay.
    #[test]
    fn fetched_anchors_are_kept_once_verified_and_never_rolled_back() {
        let (xml, p7s) = (captured("root-anchors.xml"), captured("root-anchors.p7s"));
        let addr = download::tests::serve(move |path| {
            download::tests::ok("", if path.ends_with("p7s") { &p7s } else { &xml })
        });
        let urls = (
            format!("http://{addr}/root-anchors.xml"),
            format!("http://{addr}/root-anchors.p7s"),
        );
        let used = Used {
            tlds: None,
            anchors: Some(urls),
        };
        let dir = tempfile::tempdir().unwrap();
        let client = Fetcher::new();
        let mut refresh = Refresh::default();
        let fetched = refresh.fetch(&client, &used, dir.path(), captured_at());
        assert!(fetched.changed && !fetched.failed);
        let at = fs::read_to_string(dir.path().join(SIGNED_AT)).unwrap();
        assert_eq!(at, "1742934302\n");
        let fetched = refresh.fetch(&client, &used, dir.path(), captured_at());
        assert!(!fetched.changed && !fetched.failed);
        fs::write(dir.path().join(SIGNED_AT), "1742934303\n").unwrap();
        let fetched = refresh.fetch(&client, &used, dir.path(), captured_at());
        assert!(!fetched.changed && fetched.failed);
        assert_eq!(
            fs::read_to_string(dir.path().join(SIGNED_AT)).unwrap(),
            "1742934303\n"
        );
        assert_eq!(
            fs::read(dir.path().join(ANCHORS)).unwrap(),
            captured("root-anchors.xml")
        );
    }

    /// D104: a TLD list is kept, with its version tag, only once it reads: a cut one is refused.
    #[test]
    fn a_fetched_tld_list_is_kept_only_once_it_reads() {
        let addr = download::tests::serve(|path| {
            let body: &[u8] = if path == "/full" {
                include_bytes!("../../../crates/dedens-roots/src/tlds.json")
            } else {
                include_bytes!("../../../crates/dedens-roots/tests/data/tlds.json")
            };
            download::tests::ok("ETag: \"v1\"\r\n", body)
        });
        let dir = tempfile::tempdir().unwrap();
        let client = Fetcher::new();
        let mut refresh = Refresh::default();
        let mut used = Used {
            tlds: Some(format!("http://{addr}/cut")),
            anchors: None,
        };
        assert!(refresh.fetch(&client, &used, dir.path(), 0).failed);
        assert!(!dir.path().join(TLDS).exists());
        used.tlds = Some(format!("http://{addr}/full"));
        assert!(refresh.fetch(&client, &used, dir.path(), 0).changed);
        assert_eq!(
            fs::read_to_string(dir.path().join(TLDS_TAG)).unwrap(),
            "\"v1\""
        );
    }
}
