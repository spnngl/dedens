//! Downloaded lists (D57): fetched over HTTP(S) off the serving threads, each kept on disk with its version tag
//! (`ETag`), so a start serves the last copy at once and an unchanged list is neither downloaded nor read again.

use std::io::{self, Write};
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;
use std::panic::{self, AssertUnwindSafe};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::time::Duration;
use std::{fs, thread};

use anyhow::{Context, ensure};
use dedens_plugins::{Names, Read, Tlds};
use ureq::tls::{RootCerts, TlsConfig};

use crate::lists::Store;

/// The largest list downloaded, as text, 256 MiB: four times the largest published list read, 2M names in 36 MB.
const MAX_LIST_LEN: u64 = 256 << 20;

/// The time a download may take, connecting included.
const TIMEOUT: Duration = Duration::from_secs(30);

/// The most lists downloaded at once (D104): a slow server delays only its own list, and the lists in memory at
/// once stay within 4 × [`MAX_LIST_LEN`].
const PARALLEL: usize = 4;

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

/// What [`redacted`] shows of a text that does not parse as a URL: nothing of it, as it may hold a secret.
const NOT_A_URL: &str = "(not a URL)";

/// The URL of a list as logged (D104): `scheme://host[:port]path`, parsed as the HTTP client parses it, without the
/// credentials, query and fragment a URL may carry, which can be secrets (one in the path stays). A text that does
/// not parse is not echoed.
pub(crate) fn redacted(url: &str) -> String {
    let Ok(uri) = url.parse::<ureq::http::Uri>() else {
        return NOT_A_URL.to_owned();
    };
    let (Some(scheme), Some(host)) = (uri.scheme_str(), uri.host()) else {
        return NOT_A_URL.to_owned();
    };
    let port = uri
        .port_u16()
        .map(|port| format!(":{port}"))
        .unwrap_or_default();
    format!("{scheme}://{host}{port}{}", uri.path())
}

/// `message` with each `scheme://...` token [`redacted`]: an error may quote the URL asked, a redirect target or a
/// header, in any form. A token runs to the closing quote or bracket around it, else to the end of the message, a
/// header quoted raw being able to hold spaces: what follows is hidden, a text that is no URL not echoed.
/// Hiding too much is the safe way to fail.
fn redact_urls(message: &str) -> String {
    let mut out = String::with_capacity(message.len());
    let mut rest = message;
    while let Some(at) = rest.find("://") {
        let start = rest[..at]
            .char_indices()
            .rev()
            .find(|(_, c)| !(c.is_ascii_alphanumeric() || matches!(c, '+' | '-' | '.')))
            .map_or(0, |(i, c)| i + c.len_utf8());
        let end = rest[at..]
            .find(['"', '\'', '`', '<', '>', ')'])
            .map_or(rest.len(), |len| at + len);
        out.push_str(&rest[..start]);
        out.push_str(&redacted(&rest[start..end]));
        rest = &rest[end..];
    }
    out.push_str(rest);
    out
}

/// `error` as logged: with each URL it quotes redacted.
fn failure(error: &anyhow::Error) -> String {
    redact_urls(&format!("{error:#}"))
}

/// The HTTP client of the downloads: certificates checked against the OS trust store, host names resolved by the
/// system resolver, bodies read as sent (D104: `Accept-Encoding: identity`, no inflating, so [`MAX_LIST_LEN`] bounds
/// what is held).
#[derive(Debug)]
pub(crate) struct Fetcher {
    agent: ureq::Agent,
    /// The largest list read, as text.
    max_len: u64,
}

/// What the download of one list found.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Outcome {
    /// The saved copy was replaced by a new version.
    Changed,
    /// The saved copy is the latest version.
    Unchanged,
    /// The download failed, its previous copy kept.
    Failed,
}

/// A new copy with the names it holds.
type Saved = (PathBuf, Names);

/// What [`Fetcher::fetch`] found in all its lists.
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
            // Without the `gzip` feature ureq sends none, which RFC 9110 §12.5.3 reads as no preference.
            .accept_encoding("identity")
            .tls_config(tls)
            .build()
            .new_agent();
        Self {
            agent,
            max_len: MAX_LIST_LEN,
        }
    }

    /// Downloads each list of `urls` into `dir`, [`PARALLEL`] at a time, logging and counting each result. Returns
    /// when all are done. A download that panics is logged and counts as failed and as changed (it may have saved
    /// its copy first, and a reload that finds nothing new is cheap); the others go on. What each new copy holds
    /// goes to `store`, so that the reload reads no copy again (D120).
    pub(crate) fn fetch(&self, urls: &[String], dir: &Path, store: &mut Store) -> Fetched {
        let mut saved = Vec::new();
        let next = AtomicUsize::new(0);
        let changed = AtomicBool::new(false);
        let failed = AtomicBool::new(false);
        thread::scope(|scope| {
            let workers: Vec<_> = (0..PARALLEL.min(urls.len()))
                .filter_map(|n| {
                    thread::Builder::new()
                        .name(format!("list-download-{n}"))
                        .spawn_scoped(scope, || {
                            let mut saved = Vec::new();
                            while let Some(url) = urls.get(next.fetch_add(1, Ordering::Relaxed)) {
                                // Recorded as each list is done, so a later panic cannot lose a list already saved.
                                if let Ok((outcome, copy)) =
                                    panic::catch_unwind(AssertUnwindSafe(|| self.report(url, dir)))
                                {
                                    saved.extend(copy);
                                    match outcome {
                                        Outcome::Changed => {
                                            changed.store(true, Ordering::Relaxed);
                                        }
                                        Outcome::Unchanged => {}
                                        Outcome::Failed => {
                                            failed.store(true, Ordering::Relaxed);
                                        }
                                    }
                                } else {
                                    metrics::counter!(FETCHES, "result" => "error").increment(1);
                                    tracing::error!(url = redacted(url), "list download panicked");
                                    changed.store(true, Ordering::Relaxed);
                                    failed.store(true, Ordering::Relaxed);
                                }
                            }
                            saved
                        })
                        .inspect_err(|error| {
                            tracing::error!(%error, "list download thread not started");
                            failed.store(true, Ordering::Relaxed);
                        })
                        .ok()
                })
                .collect();
            for worker in workers {
                if let Ok(copies) = worker.join() {
                    saved.extend(copies);
                } else {
                    changed.store(true, Ordering::Relaxed);
                    failed.store(true, Ordering::Relaxed);
                }
            }
        });
        for (copy, names) in saved {
            store.keep(&copy, names);
        }
        Fetched {
            changed: changed.load(Ordering::Relaxed),
            failed: failed.load(Ordering::Relaxed),
        }
    }

    /// Downloads the list at `url` into `dir`, logging and counting the result: with a new copy, what it holds.
    fn report(&self, url: &str, dir: &Path) -> (Outcome, Option<Saved>) {
        let shown = redacted(url);
        match self.one(url, dir) {
            Ok(Some((read, names))) => {
                metrics::counter!(FETCHES, "result" => "changed").increment(1);
                tracing::info!(
                    url = shown,
                    names = read.names + read.duplicates,
                    skipped = read.skipped,
                    "list downloaded"
                );
                (Outcome::Changed, Some((copy(dir, url), names)))
            }
            Ok(None) => {
                metrics::counter!(FETCHES, "result" => "unchanged").increment(1);
                tracing::info!(url = shown, "list unchanged");
                (Outcome::Unchanged, None)
            }
            Err(error) => {
                metrics::counter!(FETCHES, "result" => "error").increment(1);
                tracing::warn!(
                    url = shown,
                    error = failure(&error),
                    "list download failed, keeping the saved copy"
                );
                (Outcome::Failed, None)
            }
        }
    }

    /// Downloads the list at `url` unless its saved copy in `dir` is the latest version: what it read, or `None`
    /// when unchanged, and the names of the new copy, read once, here. The copy is replaced only by a text that
    /// reads as a list.
    fn one(&self, url: &str, dir: &Path) -> anyhow::Result<Option<(Read, Names)>> {
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
            .limit(self.max_len)
            .read_to_string()?;
        // Block or allow, a list reads the same way; one-label names are for the lists that take them (D118).
        let names = Names::downloaded(&text);
        let read = names.check(Tlds::Allow)?;
        fs::create_dir_all(dir).with_context(|| format!("creating `{}`", dir.display()))?;
        save(&copy, &text, version.as_deref())?;
        Ok(Some((read, names)))
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
    save_with(copy, text, version, replace)
}

/// [`save`], writing the tag with `write_tag`.
fn save_with(
    copy: &Path,
    text: &str,
    version: Option<&str>,
    write_tag: impl FnOnce(&Path, &str) -> io::Result<()>,
) -> anyhow::Result<()> {
    let tag = tag(copy);
    let dir = copy.parent().unwrap_or(Path::new("."));
    match fs::remove_file(&tag) {
        Err(error) if error.kind() != io::ErrorKind::NotFound => Err(error),
        _ => sync_dir(dir),
    }
    .with_context(|| format!("removing `{}`", tag.display()))?;
    replace(copy, text).with_context(|| format!("writing `{}`", copy.display()))?;
    if let Some(version) = version
        && let Err(error) = write_tag(&tag, version)
    {
        tracing::warn!(tag = %tag.display(), %error, "version tag not saved, the list will be fetched whole");
    }
    Ok(())
}

/// Writes `contents` to `path` whole or not at all: to a `.part` file beside it, flushed to disk, then renamed over
/// `path`, the directory flushed too. The `.part` file is created exclusively (D104) under a random name that
/// starts with the file name of `path`, so a file or symlink another user left in the directory is neither written
/// through nor reused, and a leftover is known by [`sweep`]; it is removed when the write fails. Its mode is `0o666`
/// less the umask, as a file created in the usual way.
fn replace(path: &Path, contents: &str) -> io::Result<()> {
    let dir = path.parent().unwrap_or(Path::new("."));
    let mut prefix = path.file_name().unwrap_or_default().to_owned();
    prefix.push(".");
    let mut builder = tempfile::Builder::new();
    builder.prefix(&prefix).suffix(".part");
    #[cfg(unix)]
    builder.permissions(fs::Permissions::from_mode(0o666));
    let mut part = builder.tempfile_in(dir)?;
    part.write_all(contents.as_bytes())?;
    part.as_file().sync_all()?;
    part.persist(path).map_err(|error| error.error)?;
    sync_dir(dir)
}

/// Removes from `dir` the `.part` files of the copies and tags of `urls` that a killed process left (D104): once at
/// start, while only the thread of the downloads writes there. The `.part` file of an old version, a copy's name
/// and `.part`, is one too.
pub(crate) fn sweep(urls: &[String], dir: &Path) {
    let Ok(entries) = fs::read_dir(dir) else {
        return;
    };
    let owners: Vec<_> = urls
        .iter()
        .flat_map(|url| {
            let copy = copy(dir, url);
            [tag(&copy), copy]
        })
        .filter_map(|file| Some(format!("{}.", file.file_name()?.to_string_lossy())))
        .collect();
    for entry in entries.flatten() {
        let name = entry.file_name();
        let name = name.to_string_lossy();
        if name.ends_with(".part") && owners.iter().any(|owner| name.starts_with(owner.as_str())) {
            match fs::remove_file(entry.path()) {
                Ok(()) => tracing::info!(file = %name, "removed a leftover of a download"),
                Err(error) => {
                    tracing::warn!(file = %name, %error, "leftover of a download not removed");
                }
            }
        }
    }
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
    use std::io::{BufRead, BufReader};
    use std::net::{SocketAddr, TcpListener};
    use std::sync::atomic::AtomicUsize;
    use std::sync::{Arc, Condvar, Mutex, PoisonError};

    use super::*;

    /// A loopback HTTP/1.1 server, a thread to each connection: `respond` takes the request target and returns the
    /// whole response.
    fn serve(respond: impl Fn(&str) -> Vec<u8> + Send + Sync + 'static) -> SocketAddr {
        serve_head(move |target, _| respond(target))
    }

    /// [`serve`], `respond` taking the request's header lines too.
    fn serve_head(
        respond: impl Fn(&str, &[String]) -> Vec<u8> + Send + Sync + 'static,
    ) -> SocketAddr {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let respond = Arc::new(respond);
        thread::spawn(move || {
            for mut stream in listener.incoming().flatten() {
                let respond = Arc::clone(&respond);
                thread::spawn(move || {
                    let (target, headers) = {
                        let mut lines = BufReader::new(&stream).lines().map_while(Result::ok);
                        let request = lines.next().unwrap_or_default();
                        let headers: Vec<_> =
                            lines.by_ref().take_while(|line| !line.is_empty()).collect();
                        let target = request
                            .split_whitespace()
                            .nth(1)
                            .unwrap_or_default()
                            .to_owned();
                        (target, headers)
                    };
                    let _ = stream.write_all(&respond(&target, &headers));
                });
            }
        });
        addr
    }

    /// A 200 response of `body`, with `headers` (each ending in CRLF) added.
    fn ok(headers: &str, body: &[u8]) -> Vec<u8> {
        let mut response = format!(
            "HTTP/1.1 200 OK\r\n{headers}Content-Length: {}\r\nConnection: close\r\n\r\n",
            body.len()
        )
        .into_bytes();
        response.extend_from_slice(body);
        response
    }

    /// A list of `lines` lines, each `ads.example`.
    fn list(lines: usize) -> String {
        "ads.example\n".repeat(lines)
    }

    fn gzip(text: &str) -> Vec<u8> {
        let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        encoder.write_all(text.as_bytes()).unwrap();
        encoder.finish().unwrap()
    }

    fn url(addr: SocketAddr, path: &str) -> String {
        format!("http://{addr}/{path}")
    }

    /// S4: the size cap counts what the server sent, never an inflated body: a list of 120 KB that gzip packs below
    /// the cap is not inflated, so no gzip bomb outgrows the cap in memory.
    #[test]
    fn a_gzip_body_is_not_inflated() {
        let text = list(10_000);
        let packed = gzip(&text);
        assert!(packed.len() < 1024 && text.len() > 100 * 1024);
        let addr = serve(move |_| ok("Content-Encoding: gzip\r\n", &packed));
        let dir = tempfile::tempdir().unwrap();
        let mut client = Fetcher::new();
        client.max_len = 1024;
        let fetched = client.fetch(&[url(addr, "list")], dir.path(), &mut Store::default());
        assert!(fetched.failed && !fetched.changed, "{fetched:?}");
        assert_eq!(fs::read_dir(dir.path()).unwrap().count(), 0);
    }

    #[test]
    fn a_list_over_the_cap_is_refused_and_one_within_it_saved() {
        let text = list(100);
        let body = text.clone();
        let addr = serve(move |_| ok("", body.as_bytes()));
        let dir = tempfile::tempdir().unwrap();
        let mut client = Fetcher::new();
        client.max_len = u64::try_from(text.len()).unwrap();
        let urls = [url(addr, "list")];
        let fetched = client.fetch(&urls, dir.path(), &mut Store::default());
        assert!(fetched.failed && !fetched.changed, "{fetched:?}");
        // The limit is exclusive: ureq refuses a body of `max_len` bytes.
        client.max_len += 1;
        let fetched = client.fetch(&urls, dir.path(), &mut Store::default());
        assert!(fetched.changed && !fetched.failed, "{fetched:?}");
        assert_eq!(
            fs::read_to_string(copy(dir.path(), &urls[0])).unwrap(),
            text
        );
    }

    /// L16: each request waits for the other to arrive, so the lists are downloaded together or not at all (the
    /// first would time out waiting).
    #[test]
    fn lists_are_downloaded_together() {
        let arrived = Arc::new((Mutex::new(0_usize), Condvar::new()));
        let addr = serve(move |_| {
            let (count, changed) = &*arrived;
            let mut count = count.lock().unwrap_or_else(PoisonError::into_inner);
            *count += 1;
            changed.notify_all();
            let (count, timeout) = changed
                .wait_timeout_while(count, Duration::from_secs(5), |count| *count < 2)
                .unwrap_or_else(PoisonError::into_inner);
            if timeout.timed_out() {
                drop(count);
                return b"HTTP/1.1 500 X\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
                    .to_vec();
            }
            drop(count);
            ok("", list(10).as_bytes())
        });
        let dir = tempfile::tempdir().unwrap();
        let urls = [url(addr, "a"), url(addr, "b")];
        let fetched = Fetcher::new().fetch(&urls, dir.path(), &mut Store::default());
        assert!(fetched.changed && !fetched.failed, "{fetched:?}");
        assert!(urls.iter().all(|url| copy(dir.path(), url).exists()));
    }

    /// L16: more lists than [`PARALLEL`] are all downloaded, never more than [`PARALLEL`] at once.
    #[test]
    fn at_most_a_few_lists_are_downloaded_at_once() {
        let now = Arc::new(AtomicUsize::new(0));
        let most = Arc::new(AtomicUsize::new(0));
        let (seen, peak) = (Arc::clone(&now), Arc::clone(&most));
        let addr = serve(move |_| {
            peak.fetch_max(seen.fetch_add(1, Ordering::SeqCst) + 1, Ordering::SeqCst);
            thread::sleep(Duration::from_millis(100));
            seen.fetch_sub(1, Ordering::SeqCst);
            ok("", list(10).as_bytes())
        });
        let dir = tempfile::tempdir().unwrap();
        let urls: Vec<_> = (0..3 * PARALLEL)
            .map(|n| url(addr, &n.to_string()))
            .collect();
        let fetched = Fetcher::new().fetch(&urls, dir.path(), &mut Store::default());
        assert!(fetched.changed && !fetched.failed, "{fetched:?}");
        assert!(urls.iter().all(|url| copy(dir.path(), url).exists()));
        assert_eq!(most.load(Ordering::SeqCst), PARALLEL);
    }

    /// RFC 9110 §12.5.3: a request without `Accept-Encoding` lets the server send gzip, which is no list here.
    #[test]
    fn the_request_asks_for_no_content_coding() {
        let seen = Arc::new(Mutex::new(Vec::new()));
        let heard = Arc::clone(&seen);
        let addr = serve_head(move |_, headers| {
            heard.lock().unwrap().extend_from_slice(headers);
            ok("", list(1).as_bytes())
        });
        let dir = tempfile::tempdir().unwrap();
        Fetcher::new().fetch(&[url(addr, "list")], dir.path(), &mut Store::default());
        let seen = seen.lock().unwrap();
        let asked: Vec<_> = seen
            .iter()
            .filter(|line| line.to_ascii_lowercase().starts_with("accept-encoding:"))
            .map(|line| line.split_once(':').unwrap().1.trim())
            .collect();
        assert_eq!(asked, ["identity"], "{seen:?}");
    }

    /// S15.c: credentials, query and fragment of a URL stay out of the logs.
    #[test]
    fn a_logged_url_has_a_scheme_a_host_a_port_and_a_path_only() {
        for (url, shown) in [
            ("https://u:p@h/x?token=t", "https://h/x"),
            ("https://h/x/y.txt#frag", "https://h/x/y.txt"),
            ("http://u@127.0.0.1:8080/a?b=c#d", "http://127.0.0.1:8080/a"),
            ("http://[::1]:8080/a", "http://[::1]:8080/a"),
            ("https://u:p@h?token=t", "https://h/"),
            ("https://h", "https://h/"),
            ("https://u:p@h:9/x@y", "https://h:9/x@y"),
            ("secret", NOT_A_URL),
            ("", NOT_A_URL),
            ("/path?token=t", NOT_A_URL),
        ] {
            assert_eq!(redacted(url), shown, "{url}");
        }
    }

    /// S15.c: a password holding `/`, `?` or `#` does not end the userinfo where a cut at the first of them would.
    #[test]
    fn a_password_with_a_delimiter_is_not_logged() {
        for url in ["https://u:pa?ss@h.example/x", "https://u:pa#ss@h.example/x"] {
            let shown = redacted(url);
            assert!(!shown.contains("ss"), "{url} -> {shown}");
        }
        // The client reads the host `u` and the path `/ss@h/x`, which is what is shown: a secret in a path stays.
        assert_eq!(redacted("https://u:pa/ss@h/x"), "https://u/ss@h/x");
    }

    /// S15.c: each URL in a message is redacted, whatever follows it.
    #[test]
    fn every_url_in_a_message_is_redacted() {
        assert_eq!(
            redact_urls(
                "reaching `https://u:p@h/a?t=1`: refused by <http://[bad?token=s>, not \"ftp://v:w@z/q\" (u:p@h)"
            ),
            format!("reaching `https://h/a`: refused by <{NOT_A_URL}>, not \"ftp://z/q\" (u:p@h)")
        );
        // A raw header may hold spaces: all that follows the scheme is hidden.
        assert_eq!(
            redact_urls("location header is malformed: http://h /x?token=s"),
            format!("location header is malformed: {NOT_A_URL}")
        );
        assert_eq!(redact_urls("nothing to hide"), "nothing to hide");
        assert_eq!(redact_urls("\u{e9}ftp://v:w@z"), "\u{e9}ftp://z/");
    }

    /// S15.c: an error that quotes a URL other than the one asked, as one about a redirect target does, is logged
    /// with it redacted.
    #[test]
    fn an_error_quoting_a_redirect_target_is_redacted() {
        let addr = serve(|_| {
            b"HTTP/1.1 302 Found\r\nLocation: http://h /x?token=secret\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
                .to_vec()
        });
        let dir = tempfile::tempdir().unwrap();
        let error = Fetcher::new()
            .one(&url(addr, "list"), dir.path())
            .unwrap_err();
        assert!(
            format!("{error:#}").contains("secret"),
            "not quoted: {error:#}"
        );
        let shown = failure(&error);
        assert!(!shown.contains("secret"), "{shown}");
        assert!(shown.contains(NOT_A_URL), "{shown}");
    }

    /// L13: a symlink left at the old, predictable `.part` name is not written through.
    #[cfg(unix)]
    #[test]
    fn a_copy_is_not_written_through_a_symlink() {
        let dir = tempfile::tempdir().unwrap();
        let victim = dir.path().join("victim");
        fs::write(&victim, "precious").unwrap();
        let path = dir.path().join("a.list");
        std::os::unix::fs::symlink(&victim, dir.path().join("a.list.part")).unwrap();
        replace(&path, "a.example\n").unwrap();
        assert_eq!(fs::read_to_string(&victim).unwrap(), "precious");
        assert_eq!(fs::read_to_string(&path).unwrap(), "a.example\n");
    }

    /// A copy is created as any file is: its mode is the umask's to decide, not 0600.
    #[cfg(unix)]
    #[test]
    fn a_copy_has_the_mode_of_a_file_created_in_the_usual_way() {
        let dir = tempfile::tempdir().unwrap();
        let usual = dir.path().join("usual");
        fs::write(&usual, "").unwrap();
        let path = dir.path().join("a.list");
        replace(&path, "a.example\n").unwrap();
        let mode = |path: &Path| fs::metadata(path).unwrap().permissions().mode();
        assert_eq!(mode(&path), mode(&usual));
    }

    /// D104: the leftovers of a killed download beside the copies and tags of the lists in use are removed, and
    /// nothing else.
    #[test]
    fn leftover_part_files_of_known_copies_are_swept() {
        let dir = tempfile::tempdir().unwrap();
        let urls = ["https://a.example/list".to_owned()];
        let copy = copy(dir.path(), &urls[0]);
        let name = copy.file_name().unwrap().to_string_lossy().into_owned();
        let tag_name = tag(&copy)
            .file_name()
            .unwrap()
            .to_string_lossy()
            .into_owned();
        let leftovers = [
            format!("{name}.Ab12Cd.part"),
            format!("{tag_name}.Ef34Gh.part"),
            format!("{name}.part"),
        ];
        let kept = [
            name.clone(),
            tag_name,
            "other.list.Ab12Cd.part".to_owned(),
            "x.part".to_owned(),
        ];
        for file in leftovers.iter().chain(&kept) {
            fs::write(dir.path().join(file), "x").unwrap();
        }
        sweep(&urls, dir.path());
        assert!(leftovers.iter().all(|file| !dir.path().join(file).exists()));
        assert!(kept.iter().all(|file| dir.path().join(file).exists()));
        // A directory that is not there is no error.
        sweep(&urls, &dir.path().join("missing"));
    }

    /// L13: nothing but the copy stays, nor is a `.part` file left when the rename fails.
    #[test]
    fn no_part_file_is_left() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("a.list");
        replace(&path, "a.example\n").unwrap();
        assert_eq!(fs::read_dir(dir.path()).unwrap().count(), 1);
        // The rename fails, a non-empty directory standing at `path`.
        let blocked = dir.path().join("b.list");
        fs::create_dir(&blocked).unwrap();
        fs::write(blocked.join("file"), "").unwrap();
        assert!(replace(&blocked, "b.example\n").is_err());
        assert_eq!(fs::read_dir(dir.path()).unwrap().count(), 2);
    }

    #[test]
    fn a_copy_is_saved_without_a_stale_tag_when_its_tag_cannot_be() {
        let dir = tempfile::tempdir().unwrap();
        let copy = copy(dir.path(), "https://a.example/list");
        save(&copy, "a.example\n", Some("\"v1\"")).unwrap();
        assert_eq!(fs::read_to_string(tag(&copy)).unwrap(), "\"v1\"");
        save_with(&copy, "b.example\n", Some("\"v2\""), |_, _| {
            Err(io::Error::other("no space left"))
        })
        .unwrap();
        assert_eq!(fs::read_to_string(&copy).unwrap(), "b.example\n");
        assert!(!tag(&copy).exists(), "the tag of the previous copy is gone");
    }
}
