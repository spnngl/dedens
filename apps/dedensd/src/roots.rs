//! IANA's root files kept fresh (D128): the TLD list of the `tlds` stage, kept in `downloads.dir`, and the root's
//! trust anchors of the validating forward stages without `trust_anchors`, kept in `state_dir`. Fetched at each
//! refresh (D104), read at start and on each reload: as the starting user, then as `user` once dropped (D122); a
//! regular file of a capped length, itself no symbolic link (`O_NOFOLLOW`: the directories above it may be).
//! A kept anchors file with no key valid now, by a clock likelier wrong than every key ended, has every key trusted.
//!
//! The anchors and their signature are fetched whole, about 10 KB, and verified (RFC 9718 §3) against the signing
//! time of the anchors kept, the floor: a server cannot roll them back to an older signed set. Of a pair that
//! verifies, one file is kept, written whole or not at all: its keys with their validity, and its signing time
//! ([`RootAnchors`]). It is read back without the signature, as trusted as `state_dir`. With no such file the
//! bundled anchors serve; one that does not read refuses the start (D115), and a reload keeps the anchors read last.
//! The validators take the keys valid at the load, compared with those valid at each refresh: a key ending or
//! starting reloads the configuration.
//!
//! A directory that cannot be written is warned of, and its file not fetched: the copy there, or the bundled one,
//! serves. A TLD list older than [`MAX_LIST_AGE`] is warned of at each load: the stage passes on the TLDs outside it.

use std::fs::{self, File};
use std::io::{self, Read as _};
use std::path::{Path, PathBuf};
use std::sync::{Arc, LazyLock};

use anyhow::Context;
use dedens_dnssec::{MAX_P7S, MAX_XML, ROOT_SIGNED_AT, RootAnchors, TrustAnchors};
use dedens_plugins::MAX_LIST_AGE;
use dedens_roots::{Kind, Tlds};

use crate::download::{self, Fetched, Fetcher, Outcome, failure, redacted};
use crate::lists::Stamp;

/// The kept root anchors, in `state_dir`.
pub(crate) const ANCHORS: &str = "root-anchors";

/// The largest TLD list fetched or read, 32 MiB: ten times IANA's, 2.9 MB in 2026.
const MAX_TLDS_LEN: u64 = 32 << 20;

/// The age of each root file in use, by `file`, `tlds` or `anchors`: seconds since IANA generated the TLD list,
/// since ICANN signed the anchors; set at each refresh.
const AGE: &str = "dedensd_roots_age_seconds";

/// The bundled TLD list, shared by every `tlds` stage that has no saved one.
static BUNDLED: LazyLock<Arc<Tlds>> = LazyLock::new(|| Arc::new(Tlds::bundled().clone()));

/// The bundled TLD list.
pub(crate) fn bundled() -> Arc<Tlds> {
    Arc::clone(&BUNDLED)
}

/// The saved copy in `dir` of the TLD list at `url`, named by the URL: a copy of another URL is not taken for it,
/// nor its version tag sent there.
pub(crate) fn tlds_copy(dir: &Path, url: &str) -> PathBuf {
    dir.join(format!("tlds-{:016x}.json", download::hash(url)))
}

/// The root files the configuration uses, as its last load found them: none with `roots: off`, the TLD list for a
/// `tlds` stage, the anchors for a validating forward stage without `trust_anchors`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct Used {
    pub(crate) tlds: Option<TldsUsed>,
    pub(crate) anchors: Option<AnchorsUsed>,
}

/// The TLD list of the `tlds` stages.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct TldsUsed {
    pub(crate) url: String,
    /// When IANA generated the list in use, in seconds since 1970.
    pub(crate) generated: u64,
}

/// The root's anchors of the validators.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct AnchorsUsed {
    pub(crate) url: String,
    pub(crate) signature: String,
    /// The keys valid at the load, which the validators trust.
    pub(crate) valid: TrustAnchors,
}

impl Used {
    /// Whether no root file is fetched.
    pub(crate) fn is_empty(&self) -> bool {
        self.tlds.is_none() && self.anchors.is_none()
    }
}

/// The root files read last, kept across reloads while their file is unchanged, as the lists are (D120).
#[derive(Debug, Default)]
pub(crate) struct Held {
    tlds: Option<(PathBuf, Stamp, Arc<Tlds>)>,
    anchors: Option<(Stamp, RootAnchors)>,
}

impl Held {
    /// The TLD list of `url` saved in `dir`: the saved copy, or the bundled one when there is none, IANA generated
    /// it later, or the copy does not read as a list at least half the bundled one's length, which is warned of: its
    /// version tag is then removed, so that the next refresh fetches it whole.
    ///
    /// # Errors
    ///
    /// A saved copy that is there but cannot be read, as a saved list (D115).
    pub(crate) fn tlds(&mut self, dir: &Path, url: &str) -> anyhow::Result<Arc<Tlds>> {
        let path = tlds_copy(dir, url);
        let reading = || format!("reading `{}`", path.display());
        let Some((file, stamp)) = open(&path).with_context(reading)? else {
            return Ok(bundled());
        };
        if let Some((held_path, held, tlds)) = &self.tlds
            && (held_path, held) == (&path, &stamp)
        {
            return Ok(Arc::clone(tlds));
        }
        let json = read_capped(file, MAX_TLDS_LEN).with_context(reading)?;
        let tlds = match Tlds::read(&json) {
            Ok(tlds) if tlds.generated() < BUNDLED.generated() => {
                tracing::info!(
                    path = %path.display(),
                    "the saved TLD list is older than the bundled one, using the bundled one"
                );
                bundled()
            }
            Ok(tlds) => {
                unknown_special_use(&tlds);
                Arc::new(tlds)
            }
            Err(error) => {
                tracing::warn!(path = %path.display(), %error, "the saved TLD list does not read, using the bundled one");
                if let Err(error) = download::untag(&path) {
                    let error = format!("{error:#}");
                    tracing::warn!(error, "the version tag of the saved TLD list not removed");
                }
                bundled()
            }
        };
        self.tlds = Some((path, stamp, Arc::clone(&tlds)));
        Ok(tlds)
    }

    /// The root anchors kept in `dir`; `None` when there are none: the bundled ones serve.
    ///
    /// # Errors
    ///
    /// A file there that cannot be read, or not as [`RootAnchors`] (D115); unless anchors read before are held:
    /// those stay, which is warned of, so that a reload keeps the anchors in use.
    pub(crate) fn anchors(&mut self, dir: &Path) -> anyhow::Result<Option<&RootAnchors>> {
        let path = dir.join(ANCHORS);
        match read_anchors(&path, self.anchors.take()) {
            Ok(read) => self.anchors = read,
            Err((error, None)) => return Err(error),
            Err((error, held)) => {
                tracing::warn!(
                    error = format!("{error:#}"),
                    "the kept root trust anchors do not read, keeping the ones in use"
                );
                self.anchors = held;
            }
        }
        Ok(self.anchors.as_ref().map(|(_, root)| root))
    }

    /// The root anchors held, read or fetched last.
    fn kept_anchors(&self) -> Option<&RootAnchors> {
        self.anchors.as_ref().map(|(_, root)| root)
    }
}

/// The root anchors at `path`, and its stamp; `None` when not there. Not read again while its stamp is that of
/// `held`.
///
/// # Errors
///
/// A file that cannot be read, or not as [`RootAnchors`], with `held`.
#[expect(
    clippy::type_complexity,
    reason = "the anchors held go back with the error"
)]
fn read_anchors(
    path: &Path,
    held: Option<(Stamp, RootAnchors)>,
) -> Result<Option<(Stamp, RootAnchors)>, (anyhow::Error, Option<(Stamp, RootAnchors)>)> {
    let read = || -> anyhow::Result<Option<(File, Stamp)>> {
        open(path).with_context(|| format!("reading `{}`", path.display()))
    };
    let (file, stamp) = match read() {
        Ok(Some(opened)) => opened,
        Ok(None) => return Ok(None),
        Err(error) => return Err((error, held)),
    };
    if let Some((held_stamp, _)) = &held
        && *held_stamp == stamp
    {
        return Ok(held);
    }
    let max = u64::try_from(RootAnchors::MAX_LEN).unwrap_or(u64::MAX);
    let root = read_capped(file, max)
        .map_err(anyhow::Error::from)
        .and_then(|bytes| Ok(String::from_utf8(bytes)?))
        .and_then(|text| Ok(RootAnchors::read(&text)?))
        .with_context(|| format!("reading `{}`", path.display()));
    match root {
        Ok(root) => {
            tracing::info!(
                signed_at = root.signed_at(),
                "root trust anchors from the kept copy"
            );
            Ok(Some((stamp, root)))
        }
        Err(error) => Err((error, held)),
    }
}

/// The saved file at `path` opened for reading, with its stamp: a regular file, itself no symbolic link (its
/// directories may be); `None` when not there.
fn open(path: &Path) -> io::Result<Option<(File, Stamp)>> {
    let mut options = File::options();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;

        use nix::fcntl::OFlag;
        // A FIFO in its place opens without waiting for a writer, then is refused as not a file.
        options.custom_flags((OFlag::O_NOFOLLOW | OFlag::O_NONBLOCK).bits());
    }
    let file = match options.open(path) {
        Ok(file) => file,
        // A path under a file is not there either: the directory warned of when it cannot be written.
        Err(error)
            if matches!(
                error.kind(),
                io::ErrorKind::NotFound | io::ErrorKind::NotADirectory
            ) =>
        {
            return Ok(None);
        }
        Err(error) => return Err(error),
    };
    if !file.metadata()?.is_file() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "not a regular file",
        ));
    }
    let stamp = Stamp::of(&file)?;
    Ok(Some((file, stamp)))
}

/// The bytes of `file`, at most `max`: a longer file is an error.
pub(crate) fn read_capped(file: File, max: u64) -> io::Result<Vec<u8>> {
    let mut bytes = Vec::new();
    file.take(max.saturating_add(1)).read_to_end(&mut bytes)?;
    if u64::try_from(bytes.len()).unwrap_or(u64::MAX) > max {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("longer than {max} bytes"),
        ));
    }
    Ok(bytes)
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

/// Whether `tlds` is older than [`MAX_LIST_AGE`] at `now`: the `tlds` stage then passes on the TLDs outside it.
pub(crate) fn stale(tlds: &Tlds, now: u64) -> bool {
    now >= tlds.generated().saturating_add(MAX_LIST_AGE)
}

/// The root anchors of the validators at `now`: the keys of `kept` valid then, or every key of it when none is, by
/// a clock likelier wrong than every key ended (the load warns of it); the bundled ones without `kept`.
pub(crate) fn valid(kept: Option<&RootAnchors>, now: u64) -> TrustAnchors {
    kept.map_or_else(TrustAnchors::root, |kept| {
        kept.at(now).unwrap_or_else(|| kept.undated())
    })
}

/// Fetches the root files at each refresh; kept by the thread of the downloads, and made again at each reload.
#[derive(Debug, Default)]
pub(crate) struct Refresh {
    /// The directories found not writable, warned of once.
    unwritable: Vec<PathBuf>,
}

impl Refresh {
    /// Fetches the files of `used` into `dir`, the TLD list, and `state_dir`, the anchors, verified at `now`, in
    /// seconds since 1970, and logs each result; keeps in `held` what it fetched. The anchors valid at `now` other
    /// than those in use are a change too.
    pub(crate) fn fetch(
        &mut self,
        client: &Fetcher,
        used: &Used,
        (dir, state_dir): (&Path, &Path),
        held: &mut Held,
        now: u64,
    ) -> Fetched {
        let mut fetched = Fetched::default();
        if let Some(tlds) = &used.tlds {
            if self.writable(dir) {
                let shown = redacted(&tlds.url);
                let outcome = match fetch_tlds(client, &tlds.url, dir, held) {
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
                note(&mut fetched, outcome);
            }
            age("tlds", tlds.generated, now);
        }
        if let Some(anchors) = &used.anchors {
            if self.writable(state_dir) {
                let shown = redacted(&anchors.url);
                let outcome = match fetch_anchors(client, anchors, state_dir, held, now) {
                    Ok(Some(at)) => {
                        tracing::info!(
                            url = shown,
                            signed_at = at,
                            "root trust anchors downloaded"
                        );
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
                note(&mut fetched, outcome);
            }
            if valid(held.kept_anchors(), now) != anchors.valid {
                tracing::info!("the root trust anchors valid now are not those in use");
                fetched.changed = true;
            }
            let signed_at = held
                .kept_anchors()
                .map_or(ROOT_SIGNED_AT, RootAnchors::signed_at);
            age("anchors", signed_at, now);
        }
        fetched
    }

    /// Whether `dir` can be written, made if missing; warned of once when it cannot.
    fn writable(&mut self, dir: &Path) -> bool {
        let written = fs::create_dir_all(dir).and_then(|()| tempfile::tempfile_in(dir).map(drop));
        let warned = self.unwritable.iter().any(|seen| seen == dir);
        match written {
            Ok(()) => true,
            Err(_) if warned => false,
            Err(error) => {
                tracing::warn!(
                    dir = %dir.display(),
                    %error,
                    "cannot write the directory: its root file is not fetched, the copy there or the bundled one serves"
                );
                self.unwritable.push(dir.to_owned());
                false
            }
        }
    }
}

/// Adds `outcome` to `fetched`.
fn note(fetched: &mut Fetched, outcome: Outcome) {
    fetched.changed |= outcome == Outcome::Changed;
    fetched.failed |= outcome == Outcome::Failed;
}

/// Sets the [`AGE`] of `file`, made at `at`, at `now`.
#[expect(
    clippy::cast_precision_loss,
    reason = "seconds below 2^53, exact as a float"
)]
fn age(file: &'static str, at: u64, now: u64) {
    metrics::gauge!(AGE, "file" => file).set(now.saturating_sub(at) as f64);
}

/// Fetches the TLD list at `url` unless the copy in `dir` is the latest, keeping a new one only once it reads, and
/// holding it in `held`: whether it changed.
fn fetch_tlds(client: &Fetcher, url: &str, dir: &Path, held: &mut Held) -> anyhow::Result<bool> {
    let copy = tlds_copy(dir, url);
    let Some((json, version)) =
        client.get(url, download::saved_tag(&copy).as_deref(), MAX_TLDS_LEN)?
    else {
        return Ok(false);
    };
    let tlds = Arc::new(Tlds::read(&json)?);
    unknown_special_use(&tlds);
    download::save(&copy, &json, version.as_deref())?;
    held.tlds = open(&copy)?.map(|(_, stamp)| (copy, stamp, tlds));
    Ok(true)
}

/// Fetches the anchors and their signature of `used`, verified at `now` against the floor of the anchors `held`,
/// and keeps them in `dir` and `held` unless they are those held: their signing time when their keys are new,
/// `None` when they are the keys held, signed again or not.
fn fetch_anchors(
    client: &Fetcher,
    used: &AnchorsUsed,
    dir: &Path,
    held: &mut Held,
    now: u64,
) -> anyhow::Result<Option<u64>> {
    let xml = client.whole(&used.url, MAX_XML.try_into().unwrap_or(u64::MAX))?;
    let p7s = client.whole(&used.signature, MAX_P7S.try_into().unwrap_or(u64::MAX))?;
    let kept = held.kept_anchors();
    let signed = TrustAnchors::verified(&xml, &p7s, now, kept.map(RootAnchors::signed_at))?;
    let root = signed.root();
    if kept == Some(root) {
        return Ok(None);
    }
    let new = kept.is_none_or(|kept| kept.keys() != root.keys());
    let path = dir.join(ANCHORS);
    download::replace(&path, root.to_string().as_bytes())
        .with_context(|| format!("writing `{}`", path.display()))?;
    held.anchors = open(&path)?.map(|(_, stamp)| (stamp, root.clone()));
    Ok(new.then_some(root.signed_at()))
}

#[cfg(test)]
mod tests {
    use std::sync::Mutex;

    use metrics_util::debugging::{DebugValue, DebuggingRecorder};

    use super::*;
    use crate::download::tests::{ok, serve, serve_head};

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

    /// The text kept of the captured pair, verified: `dedens-dnssec`'s test
    /// `the_kept_anchors_read_back_as_written_with_each_keys_validity`.
    const KEPT: &str = "dedens root anchors 1\nsigned-at 1742934302\n\
        ds 19036 8 2 49aac11d7b6f6446702e54a1607371607a1a41855200fd2ce1cdde32f24e8fb5 from 1279152000 until 1547164800\n\
        ds 20326 8 2 e06d44b80b8f1d39a95c0b0d7c65d08458e880409bbc683457104237c7f8ec8d from 1485993600\n\
        ds 38696 8 2 683d2d0acb8c9b712a1948b27f741219298d0a450d612c483af444a4c0fb2b16 from 1721260800\n";

    /// A response of no body and `status`.
    fn status(status: &str) -> Vec<u8> {
        format!("HTTP/1.1 {status}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n").into_bytes()
    }

    /// The anchors of the configuration, from the loopback server at `addr`, the bundled ones in use.
    fn anchors_used(addr: std::net::SocketAddr) -> Used {
        Used {
            tlds: None,
            anchors: Some(AnchorsUsed {
                url: format!("http://{addr}/root-anchors.xml"),
                signature: format!("http://{addr}/root-anchors.p7s"),
                valid: TrustAnchors::root(),
            }),
        }
    }

    /// D128: no kept file is the bundled anchors; a kept one is read once while unchanged; one that does not read
    /// is an error with nothing held, and leaves the anchors held otherwise.
    #[test]
    fn kept_anchors_are_read_once_and_one_that_does_not_read_keeps_those_held() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(ANCHORS);
        let mut held = Held::default();
        assert_eq!(held.anchors(dir.path()).unwrap(), None);
        fs::write(&path, KEPT).unwrap();
        let kept = held.anchors(dir.path()).unwrap().cloned().unwrap();
        assert_eq!(kept, RootAnchors::read(KEPT).unwrap());
        assert_eq!(valid(Some(&kept), captured_at()), TrustAnchors::root());
        assert_eq!(
            valid(Some(&kept), 1_000_000_000),
            kept.undated(),
            "no key valid in 2001: every one"
        );
        fs::write(&path, KEPT.replace("signed-at", "signed")).unwrap();
        assert_eq!(held.anchors(dir.path()).unwrap(), Some(&kept));
        assert!(Held::default().anchors(dir.path()).is_err());
        fs::remove_file(&path).unwrap();
        assert_eq!(held.anchors(dir.path()).unwrap(), None);
    }

    /// D128, D122: a root file is read as a regular file of a capped length, itself no symbolic link.
    #[cfg(unix)]
    #[test]
    fn root_files_are_read_through_no_link_and_of_a_capped_length() {
        let dir = tempfile::tempdir().unwrap();
        let elsewhere = dir.path().join("elsewhere");
        fs::write(&elsewhere, KEPT).unwrap();
        std::os::unix::fs::symlink(&elsewhere, dir.path().join(ANCHORS)).unwrap();
        assert!(Held::default().anchors(dir.path()).is_err(), "a link");
        fs::remove_file(dir.path().join(ANCHORS)).unwrap();
        fs::create_dir(dir.path().join(ANCHORS)).unwrap();
        assert!(Held::default().anchors(dir.path()).is_err(), "a directory");
        fs::remove_dir(dir.path().join(ANCHORS)).unwrap();
        fs::write(dir.path().join(ANCHORS), "abc").unwrap();
        let capped = |max| read_capped(File::open(dir.path().join(ANCHORS)).unwrap(), max);
        assert_eq!(capped(3).unwrap(), b"abc");
        assert!(capped(2).is_err());
        let long = format!("{KEPT}{}", "x".repeat(RootAnchors::MAX_LEN));
        fs::write(dir.path().join(ANCHORS), long).unwrap();
        let error = Held::default().anchors(dir.path()).unwrap_err();
        assert!(format!("{error:#}").contains("longer than"), "{error:#}");
        let url = "https://data.iana.org/TLD/v1/tlds.json";
        fs::create_dir(tlds_copy(dir.path(), url)).unwrap();
        assert!(Held::default().tlds(dir.path(), url).is_err());
    }

    /// No saved list is the bundled one; a saved one is read once while unchanged; one that does not read is the
    /// bundled one, its version tag removed so that the next refresh fetches it whole; one generated before the
    /// bundled one is the bundled one too. The saved list is the bundled one, captured from IANA, and that list
    /// with its `meta.generated` in 2020.
    #[test]
    fn the_saved_tld_list_is_read_once_and_one_that_does_not_read_is_fetched_whole() {
        let dir = tempfile::tempdir().unwrap();
        let url = "https://data.iana.org/TLD/v1/tlds.json";
        let copy = tlds_copy(dir.path(), url);
        let mut held = Held::default();
        assert!(Arc::ptr_eq(&held.tlds(dir.path(), url).unwrap(), &BUNDLED));
        download::save(
            &copy,
            include_bytes!("../../../crates/dedens-roots/src/tlds.json"),
            Some("\"v1\""),
        )
        .unwrap();
        let first = held.tlds(dir.path(), url).unwrap();
        assert!(!Arc::ptr_eq(&first, &BUNDLED));
        assert_eq!(*first, **BUNDLED);
        assert!(Arc::ptr_eq(&held.tlds(dir.path(), url).unwrap(), &first));
        assert_eq!(download::saved_tag(&copy).as_deref(), Some("\"v1\""));
        fs::write(&copy, b"{}").unwrap();
        assert!(Arc::ptr_eq(&held.tlds(dir.path(), url).unwrap(), &BUNDLED));
        assert_eq!(download::saved_tag(&copy), None);

        let mut older: serde_json::Value =
            serde_json::from_slice(include_bytes!("../../../crates/dedens-roots/src/tlds.json"))
                .unwrap();
        older["meta"]["generated"] = "2020-01-01T00:00:00Z".into();
        fs::write(&copy, serde_json::to_vec(&older).unwrap()).unwrap();
        assert!(Arc::ptr_eq(&held.tlds(dir.path(), url).unwrap(), &BUNDLED));
    }

    /// RFC 9718 §3, D128: a fetched pair is kept once verified, as the text of its keys and signing time; fetched
    /// again it is unchanged; signed again with the same keys, its text is written, its signing time the new floor,
    /// and nothing reloads; under a later floor it is refused and the file stays.
    #[test]
    fn fetched_anchors_are_kept_once_verified_and_never_rolled_back() {
        let (xml, p7s) = (captured("root-anchors.xml"), captured("root-anchors.p7s"));
        let addr = serve(move |path| ok("", if path.ends_with("p7s") { &p7s } else { &xml }));
        let used = anchors_used(addr);
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(ANCHORS);
        let (client, mut held, mut refresh) = (Fetcher::new(), Held::default(), Refresh::default());
        let mut fetch = |held: &mut Held| {
            refresh.fetch(
                &client,
                &used,
                (dir.path(), dir.path()),
                held,
                captured_at(),
            )
        };
        assert_eq!(
            fetch(&mut held),
            Fetched {
                changed: true,
                failed: false
            }
        );
        assert_eq!(fs::read_to_string(&path).unwrap(), KEPT);
        assert_eq!(fetch(&mut held), Fetched::default());

        // As a reload reads them: an older signing time, the same keys.
        fs::write(&path, KEPT.replace("1742934302", "1742934301")).unwrap();
        held.anchors(dir.path()).unwrap();
        assert_eq!(fetch(&mut held), Fetched::default());
        assert_eq!(fs::read_to_string(&path).unwrap(), KEPT);

        // Other keys, signed earlier: the fetched ones replace them.
        let other = KEPT
            .replace("1742934302", "1742934301")
            .replace("from 1721260800", "from 1721260801");
        fs::write(&path, other).unwrap();
        held.anchors(dir.path()).unwrap();
        assert_eq!(
            fetch(&mut held),
            Fetched {
                changed: true,
                failed: false
            }
        );
        assert_eq!(fs::read_to_string(&path).unwrap(), KEPT);

        let later = KEPT.replace("1742934302", "1742934303");
        fs::write(&path, &later).unwrap();
        held.anchors(dir.path()).unwrap();
        assert_eq!(
            fetch(&mut held),
            Fetched {
                changed: false,
                failed: true
            }
        );
        assert_eq!(fs::read_to_string(&path).unwrap(), later);
    }

    /// D128: the keys valid at each refresh are compared with those in use: one that ends reloads, without a
    /// restart, even when the anchors cannot be fetched.
    #[test]
    fn a_key_that_ends_between_two_refreshes_reloads() {
        let addr = serve(|_| status("404 Not Found"));
        let ends = 1_800_000_000;
        let dir = tempfile::tempdir().unwrap();
        fs::write(
            dir.path().join(ANCHORS),
            KEPT.replace("from 1485993600", &format!("from 1485993600 until {ends}")),
        )
        .unwrap();
        let mut held = Held::default();
        let kept = held.anchors(dir.path()).unwrap().cloned();
        let mut used = anchors_used(addr);
        if let Some(anchors) = &mut used.anchors {
            anchors.valid = valid(kept.as_ref(), ends - 1);
        }
        let (client, mut refresh) = (Fetcher::new(), Refresh::default());
        let dirs = (dir.path(), dir.path());
        let before = refresh.fetch(&client, &used, dirs, &mut held, ends - 1);
        assert_eq!(
            before,
            Fetched {
                changed: false,
                failed: true
            }
        );
        let after = refresh.fetch(&client, &used, dirs, &mut held, ends);
        assert_eq!(
            after,
            Fetched {
                changed: true,
                failed: true
            }
        );
    }

    /// D128: a directory that cannot be written is warned of, once, and its file not fetched: no failure, the copy
    /// there or the bundled one serves.
    #[test]
    fn a_directory_that_cannot_be_written_is_not_fetched_into() {
        let asked = Arc::new(Mutex::new(0));
        let counted = Arc::clone(&asked);
        let addr = serve(move |_| {
            *counted.lock().unwrap() += 1;
            status("404 Not Found")
        });
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("file");
        fs::write(&file, "").unwrap();
        let unwritable = file.join("dir");
        let mut used = anchors_used(addr);
        used.tlds = Some(TldsUsed {
            url: format!("http://{addr}/tlds.json"),
            generated: BUNDLED.generated(),
        });
        let mut refresh = Refresh::default();
        for _ in 0..2 {
            let fetched = refresh.fetch(
                &Fetcher::new(),
                &used,
                (&unwritable, &unwritable),
                &mut Held::default(),
                captured_at(),
            );
            assert_eq!(fetched, Fetched::default());
        }
        assert_eq!(*asked.lock().unwrap(), 0);
        assert_eq!(refresh.unwritable, [unwritable]);
    }

    /// D104, D128: a TLD list is kept, with its version tag, only once it reads, and handed to the next load
    /// without reading it again; a copy is named by its URL, so that the tag of one URL is never sent to another.
    #[test]
    fn a_fetched_tld_list_is_kept_once_it_reads_and_its_tag_stays_with_its_url() {
        let tags = Arc::new(Mutex::new(Vec::new()));
        let seen = Arc::clone(&tags);
        let addr = serve_head(move |path, headers| {
            let tag = headers
                .iter()
                .find(|line| line.to_ascii_lowercase().starts_with("if-none-match"));
            seen.lock().unwrap().push((path.to_owned(), tag.cloned()));
            let body: &[u8] = if path == "/cut" {
                include_bytes!("../../../crates/dedens-roots/tests/data/tlds.json")
            } else {
                include_bytes!("../../../crates/dedens-roots/src/tlds.json")
            };
            ok("ETag: \"v1\"\r\n", body)
        });
        let dir = tempfile::tempdir().unwrap();
        let (client, mut held, mut refresh) = (Fetcher::new(), Held::default(), Refresh::default());
        let url = |path: &str| format!("http://{addr}{path}");
        let mut fetch = |path: &str, held: &mut Held| {
            let used = Used {
                tlds: Some(TldsUsed {
                    url: url(path),
                    generated: 0,
                }),
                anchors: None,
            };
            refresh.fetch(&client, &used, (dir.path(), dir.path()), held, 0)
        };
        assert!(fetch("/cut", &mut held).failed);
        assert!(!tlds_copy(dir.path(), &url("/cut")).exists());
        assert!(fetch("/full", &mut held).changed);
        let fetched = Arc::clone(&held.tlds.as_ref().unwrap().2);
        assert!(Arc::ptr_eq(
            &held.tlds(dir.path(), &url("/full")).unwrap(),
            &fetched
        ));
        assert!(fetch("/other", &mut held).changed);
        let tags = tags.lock().unwrap();
        let sent: Vec<_> = tags.iter().map(|(_, tag)| tag.is_some()).collect();
        assert_eq!(sent, [false, false, false], "{tags:?}");
    }

    /// D128: a TLD list is stale from 30 days after IANA generated it.
    #[test]
    fn a_tld_list_is_stale_from_30_days_after_it_was_generated() {
        let generated = BUNDLED.generated();
        assert!(!stale(&BUNDLED, generated + 30 * 86_400 - 1));
        assert!(stale(&BUNDLED, generated + 30 * 86_400));
    }

    /// The age of each root file in use is that of its copy: since IANA generated the TLD list, since ICANN signed
    /// the anchors; fetched or not.
    #[test]
    fn the_age_of_a_root_file_is_that_of_the_copy_in_use() {
        let mut used = anchors_used(serve(|_| status("404 Not Found")));
        used.tlds = Some(TldsUsed {
            url: "http://127.0.0.1:9/tlds.json".to_owned(),
            generated: 1_000,
        });
        let dir = tempfile::tempdir().unwrap();
        let unwritable = dir.path().join(ANCHORS);
        fs::write(&unwritable, "").unwrap();
        let ages = ages(|| {
            let dirs = (unwritable.as_path(), dir.path());
            Refresh::default().fetch(
                &Fetcher::new(),
                &used,
                dirs,
                &mut Held::default(),
                5_000_000_000,
            )
        });
        assert_eq!(
            ages,
            [
                ("anchors".to_owned(), since(ROOT_SIGNED_AT, 5_000_000_000)),
                ("tlds".to_owned(), since(1_000, 5_000_000_000)),
            ]
        );
    }

    /// D128: the same keys signed again are written with their new signing time, which the age of the anchors
    /// follows from that refresh on, though nothing reloads.
    #[test]
    fn the_age_of_the_anchors_follows_their_signing_again() {
        let (xml, p7s) = (captured("root-anchors.xml"), captured("root-anchors.p7s"));
        let addr = serve(move |path| ok("", if path.ends_with("p7s") { &p7s } else { &xml }));
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(ANCHORS);
        fs::write(&path, KEPT.replace("1742934302", "1742934301")).unwrap();
        let mut held = Held::default();
        held.anchors(dir.path()).unwrap();
        let ages = ages(|| {
            let dirs = (dir.path(), dir.path());
            let used = anchors_used(addr);
            Refresh::default().fetch(&Fetcher::new(), &used, dirs, &mut held, captured_at())
        });
        assert_eq!(fs::read_to_string(&path).unwrap(), KEPT);
        assert_eq!(
            ages,
            [("anchors".to_owned(), since(1_742_934_302, captured_at()))]
        );
    }

    /// The [`AGE`] gauges `fetch` sets, by `file`, and that it reloads nothing.
    fn ages(fetch: impl FnOnce() -> Fetched) -> Vec<(String, f64)> {
        let recorder = DebuggingRecorder::new();
        let snapshotter = recorder.snapshotter();
        let fetched = metrics::with_local_recorder(&recorder, fetch);
        assert!(!fetched.changed, "reloaded");
        let mut ages: Vec<_> = (snapshotter.snapshot().into_vec().into_iter())
            .filter_map(|(key, _, _, value)| match value {
                DebugValue::Gauge(age) if key.key().name() == AGE => Some((
                    key.key().labels().next()?.value().to_owned(),
                    age.into_inner(),
                )),
                _ => None,
            })
            .collect();
        ages.sort_by(|a, b| a.0.cmp(&b.0));
        ages
    }

    /// Seconds from `at` to `now`, as a gauge holds them.
    #[expect(clippy::cast_precision_loss, reason = "exact below 2^53")]
    fn since(at: u64, now: u64) -> f64 {
        (now - at) as f64
    }
}
