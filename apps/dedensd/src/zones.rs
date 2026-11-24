//! The zones of the `authoritative` stage, kept across reloads (D208).
//!
//! A zone is loaded again only when its file, or a file it includes, changed, as the lists are (D120's [`Stamp`]).
//! Once the server serves, a zone whose files fail to load keeps its last version (D55), the error logged and
//! counted; before, at the start, the failure fails the start.

use std::collections::HashMap;
use std::fs::File;
use std::io::{self, Read as _};
use std::path::{Path, PathBuf};
use std::sync::Arc;

use anyhow::{Context as _, anyhow, ensure};
use dedens_proto::{Name, Ttl};
use dedens_zone::{Include, Limits, Source, Zone};

use crate::lists::Stamp;

/// The most bytes a zone file, or a file it includes, holds: 1 GiB (2³⁰), the most RDATA a zone may hold
/// (`dedens_zone::Limits::rdata_bytes`). The text is read whole before it is parsed, so a bound on it is a bound on
/// that memory: the file's size is checked before it is read, and the buffer is that size. The files open at once
/// are the zone file and the chain of `$INCLUDE`s below it, [`Limits::include_depth`] deep. Knot
/// (`zs_set_input_file`, `src/libzscanner/scanner.rl`), NSD (`zonec_read`, `zonec.c`) and BIND (`isc_lex_openfile`,
/// `lib/isc/lex.c`) read the file as a stream, with no bound.
pub(crate) const MAX_ZONE_FILE_BYTES: u64 = 1 << 30;

/// The TTL of a record before any `$TTL` or TTL of its own (RFC 2308 §4): 3600 seconds, Knot's `default-ttl`
/// (`src/knot/conf/schema.c`) and NSD's `DEFAULT_TTL` (`dns.h`); the answers they gave from the zones of
/// `testdata/authoritative/` were captured with it. BIND takes the SOA's minimum, with a warning.
const DEFAULT_TTL: Ttl = Ttl::from_wire(3600);

/// Loads counted by result, `ok` or `error`.
const LOADS: &str = "dedensd_authoritative_loads_total";
/// The SOA serial of each zone served, by `zone`.
const SERIAL: &str = "dedensd_authoritative_serial";
/// The zones served.
const ZONES: &str = "dedensd_authoritative_zones";

/// Describes the metrics of the zones.
pub(crate) fn describe() {
    metrics::describe_counter!(
        LOADS,
        "Zone loads of the authoritative stage, by result: ok, or error (the zone keeps its last version) (D208)."
    );
    metrics::describe_gauge!(
        SERIAL,
        "The SOA serial of each zone the authoritative stage serves, by zone (D208)."
    );
    metrics::describe_gauge!(ZONES, "The zones the authoritative stage serves (D208).");
}

/// The files a load read, with their stamps: the zone file, then each it includes, a link it followed as well as
/// its target. `None` for a file that could not be read, whatever the cause: it is tried again at each load.
type Files = Vec<(PathBuf, Option<Stamp>)>;

/// A zone loaded, and what tells whether its files changed since.
#[derive(Debug)]
struct Kept {
    zone: Arc<Zone>,
    /// The files read.
    files: Files,
    /// The files a later load that failed read: while they are unchanged, loading again would fail the same, and the
    /// last version is served without trying.
    failed: Option<Files>,
    /// Whether the reading under way used it: what is not is dropped at its end.
    used: bool,
}

/// The version of a secondary zone the secondaries' thread gave last (D215).
#[derive(Debug)]
struct Version {
    zone: Arc<Zone>,
    /// Whether the reading under way used it: what is not is dropped at its end.
    used: bool,
}

/// The zones loaded so far, by apex and file, and the versions of the secondary zones, by apex. Part of the
/// [`Store`](crate::lists::Store).
#[derive(Debug, Default)]
pub(crate) struct Held {
    zones: HashMap<(Name<'static>, PathBuf), Kept>,
    secondaries: HashMap<Name<'static>, Version>,
    /// Whether the server serves: a zone failing to load keeps its last version then.
    serving: bool,
}

impl Held {
    /// Starts a reading of the configuration: no zone is used yet.
    pub(crate) fn begin(&mut self) {
        for kept in self.zones.values_mut() {
            kept.used = false;
        }
        for version in self.secondaries.values_mut() {
            version.used = false;
        }
    }

    /// Ends a reading that succeeded: the zones it did not use are dropped, and the gauges describe those kept.
    /// The series of a zone dropped stays in the recorder, which has no way to remove one: it reads 0.
    pub(crate) fn end(&mut self) {
        for ((apex, _), kept) in &self.zones {
            if !kept.used {
                metrics::gauge!(SERIAL, "zone" => apex.to_string()).set(0.0);
            }
        }
        for (apex, version) in &self.secondaries {
            if !version.used {
                metrics::gauge!(SERIAL, "zone" => apex.to_string()).set(0.0);
            }
        }
        self.zones.retain(|_, kept| kept.used);
        self.secondaries.retain(|_, version| version.used);
        let served = (self
            .zones
            .iter()
            .map(|((apex, _), kept)| (apex, &kept.zone)))
        .chain(
            self.secondaries
                .iter()
                .map(|(apex, version)| (apex, &version.zone)),
        );
        for (apex, zone) in served {
            metrics::gauge!(SERIAL, "zone" => apex.to_string()).set(f64::from(zone.soa().serial));
        }
        #[expect(
            clippy::cast_precision_loss,
            reason = "a gauge is a float; the zones number far below 2⁵²"
        )]
        metrics::gauge!(ZONES).set((self.zones.len() + self.secondaries.len()) as f64);
    }

    /// The version of the secondary zone of apex `apex` to serve, `None` while it has none (D215).
    pub(crate) fn secondary(&mut self, apex: &Name<'static>) -> Option<Arc<Zone>> {
        let version = self.secondaries.get_mut(apex)?;
        version.used = true;
        Some(Arc::clone(&version.zone))
    }

    /// Sets the version of the secondary zone of apex `apex`, as the secondaries' thread gave it: `None` once it
    /// expired. The next reading serves it.
    pub(crate) fn transferred(&mut self, apex: Name<'static>, zone: Option<Arc<Zone>>) {
        if let Some(zone) = zone {
            self.secondaries.insert(apex, Version { zone, used: false });
        } else {
            metrics::gauge!(SERIAL, "zone" => apex.to_string()).set(0.0);
            self.secondaries.remove(&apex);
        }
    }

    /// From now on, a zone failing to load keeps its last version: the server serves (D55).
    pub(crate) const fn serve(&mut self) {
        self.serving = true;
    }

    /// The zone of apex `apex` in the file at `path`: the one loaded before while none of its files changed, else
    /// loaded again; when that fails and the server serves, the last version.
    ///
    /// # Errors
    ///
    /// A file that cannot be read, an `$INCLUDE` outside the directory of the zone file, a zone the loader refuses,
    /// and no version to keep: at the start, or a zone new to the configuration.
    pub(crate) fn zone(&mut self, apex: &Name<'static>, path: &Path) -> anyhow::Result<Arc<Zone>> {
        let key = (apex.clone(), path.to_owned());
        if let Some(kept) = self.zones.get_mut(&key) {
            if unchanged(&kept.files) {
                kept.used = true;
                return Ok(Arc::clone(&kept.zone));
            }
            // Neither is this load tried again, nor counted or logged: it failed, and nothing changed since.
            if self.serving && kept.failed.as_deref().is_some_and(unchanged) {
                tracing::debug!(zone = %apex, file = %path.display(), "zone files unchanged since a load failed");
                kept.used = true;
                return Ok(Arc::clone(&kept.zone));
            }
        }
        let file = path.display();
        let mut files = Files::new();
        match load(apex, path, MAX_ZONE_FILE_BYTES, &mut files) {
            Ok(zone) => {
                metrics::counter!(LOADS, "result" => "ok").increment(1);
                tracing::info!(
                    zone = %apex,
                    %file,
                    serial = zone.soa().serial,
                    records = zone.record_count(),
                    "zone loaded"
                );
                let zone = Arc::new(zone);
                let kept = Kept {
                    zone: Arc::clone(&zone),
                    files,
                    failed: None,
                    used: true,
                };
                self.zones.insert(key, kept);
                Ok(zone)
            }
            Err(error) => {
                metrics::counter!(LOADS, "result" => "error").increment(1);
                let Some(kept) = self.zones.get_mut(&key).filter(|_| self.serving) else {
                    return Err(error);
                };
                tracing::error!(
                    zone = %apex,
                    %file,
                    serial = kept.zone.soa().serial,
                    error = format!("{error:#}"),
                    "zone failed to load, serving its last version"
                );
                kept.failed = Some(files);
                kept.used = true;
                Ok(Arc::clone(&kept.zone))
            }
        }
    }
}

/// Whether each of `files` is in the state it was read in, as its stamp shows: a file that no longer opens has
/// changed, unless it did not when read.
fn unchanged(files: &[(PathBuf, Option<Stamp>)]) -> bool {
    files.iter().all(|(path, stamp)| stamp_of(path) == *stamp)
}

/// A regular file at `path` opened for reading, a link followed. Opened without waiting: a FIFO in its place is
/// refused as not a file, not waited on for a writer (the model is `roots::open`, D128).
fn open(path: &Path) -> io::Result<File> {
    let mut options = File::options();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;

        use nix::fcntl::OFlag;
        options.custom_flags(OFlag::O_NONBLOCK.bits());
    }
    let file = options.open(path)?;
    if !file.metadata()?.is_file() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "not a regular file",
        ));
    }
    Ok(file)
}

/// The stamp of the regular file at `path`, `None` if there is none.
fn stamp_of(path: &Path) -> Option<Stamp> {
    open(path).and_then(|file| Stamp::of(&file)).ok()
}

/// The zone of apex `apex` in the file at `path`, each file read at most `max` bytes, the files read pushed with
/// their stamps on `files`, which a failure leaves with those read until then. An `$INCLUDE` names a file in the
/// directory of the zone file or below it (D208), its depth bounded by [`Limits::include_depth`].
fn load(apex: &Name<'static>, path: &Path, max: u64, files: &mut Files) -> anyhow::Result<Zone> {
    let text = read(path, max, files)?;
    let dir = path
        .parent()
        .filter(|dir| !dir.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    let inside = dir
        .canonicalize()
        .with_context(|| format!("reading `{}`", dir.display()))?;
    let mut include = |name: &str| -> Result<Vec<u8>, String> {
        // Resolved, links and `..` included, before it is compared: no way out of the directory. The check and
        // the open are two steps: a link swapped between them gets out (D208).
        let link = inside.join(name);
        let target = link.canonicalize().map_err(|error| {
            files.push((link.clone(), None));
            error.to_string()
        })?;
        // A link retargeted changes the file its path opens, which the stamp of its target does not show.
        if link != target {
            files.push((link.clone(), stamp_of(&link)));
        }
        if !target.starts_with(&inside) {
            return Err(format!(
                "outside `{}`, the directory of the zone file",
                inside.display()
            ));
        }
        read(&target, max, files).map_err(|error| format!("{error:#}"))
    };
    parse(apex, path, &text, &mut include)
}

/// The zone of apex `apex` a secondary keeps in the file at `path` (D215): read as a zone file is, with no
/// `$INCLUDE`, which the server never writes.
///
/// # Errors
///
/// A file that cannot be read, or a zone the loader refuses.
pub(crate) fn stored(apex: &Name<'static>, path: &Path) -> anyhow::Result<Zone> {
    let text = read(path, MAX_ZONE_FILE_BYTES, &mut Files::new())?;
    parse(apex, path, &text, &mut |_| {
        Err("a zone a secondary keeps has no $INCLUDE".to_owned())
    })
}

/// The zone of apex `apex` in `text`, read from `path`, its `$INCLUDE`s from `include`; its warnings logged.
fn parse(
    apex: &Name<'static>,
    path: &Path,
    text: &[u8],
    include: &mut Include<'_>,
) -> anyhow::Result<Zone> {
    let name = path.display().to_string();
    let source = Source {
        name: &name,
        text,
        default_ttl: Some(DEFAULT_TTL),
    };
    let loaded = Zone::load(apex.clone(), source, include, &Limits::default())
        .map_err(|report| anyhow!("{report}"))
        .with_context(|| format!("loading zone `{apex}`"))?;
    if !loaded.report.warnings.is_empty() {
        tracing::warn!(zone = %apex, report = %loaded.report, "zone loaded with warnings");
    }
    Ok(loaded.zone)
}

/// The bytes of the regular file at `path`, at most `max`: its size is checked before the file is read, and the
/// buffer is that size. Its stamp, taken before it is read, is pushed on `files` once it was read, `None` when
/// any step failed: a read that failed for a reason of the moment, as an I/O error or a file that changed under
/// it, must not make the zone skipped until the file changes.
fn read(path: &Path, max: u64, files: &mut Files) -> anyhow::Result<Vec<u8>> {
    let reading = || format!("reading `{}`", path.display());
    let read = || {
        let file = open(path).with_context(reading)?;
        let stamp = Stamp::of(&file).with_context(reading)?;
        let len = file.metadata().with_context(reading)?.len();
        ensure!(len <= max, "`{}` is over {max} bytes", path.display());
        let mut text = Vec::with_capacity(usize::try_from(len).with_context(reading)?);
        // The file may have grown since: the bound holds for what is read.
        file.take(max.saturating_add(1))
            .read_to_end(&mut text)
            .with_context(reading)?;
        ensure!(
            u64::try_from(text.len()).is_ok_and(|len| len <= max),
            "`{}` is over {max} bytes",
            path.display()
        );
        anyhow::Ok((text, stamp))
    };
    let read = read();
    files.push((path.to_owned(), read.as_ref().ok().map(|(_, stamp)| *stamp)));
    read.map(|(text, _)| text)
}

#[cfg(test)]
mod tests {
    use std::fs;

    use super::*;

    /// The zone of RFC 1035 §5.3, its mailboxes in the file it includes, both from `testdata/zones/`.
    fn isi(dir: &Path) -> PathBuf {
        let zones = dedens_testkit::path("zones");
        let text = fs::read_to_string(zones.join("rfc1035_isi.zone")).unwrap();
        let text = text.replace("<SUBSYS>ISI-MAILBOXES.TXT", "mailboxes.zone");
        let path = dir.join("isi.zone");
        fs::write(&path, text).unwrap();
        fs::copy(
            zones.join("rfc1035_isi_mailboxes.zone"),
            dir.join("mailboxes.zone"),
        )
        .unwrap();
        path
    }

    fn apex() -> Name<'static> {
        "ISI.EDU.".parse().unwrap()
    }

    #[test]
    fn the_zones_are_counted_and_a_reading_drops_those_it_did_not_use() {
        use metrics_util::debugging::{DebugValue, DebuggingRecorder};

        let dir = tempfile::tempdir().unwrap();
        let path = isi(dir.path());
        let recorder = DebuggingRecorder::new();
        let snapshotter = recorder.snapshotter();
        // Each metric: its name, whether it is described, its value.
        let read = || {
            let mut metrics: Vec<_> = (snapshotter.snapshot().into_vec().into_iter())
                .map(|(key, _, description, value)| {
                    let value = match value {
                        DebugValue::Counter(count) => format!("{count}"),
                        DebugValue::Gauge(gauge) => format!("{gauge}"),
                        DebugValue::Histogram(_) => String::new(),
                    };
                    (key.key().name().to_owned(), description.is_some(), value)
                })
                .collect();
            metrics.sort();
            metrics
        };
        let mut held = Held::default();
        metrics::with_local_recorder(&recorder, || {
            describe();
            held.begin();
            held.zone(&apex(), &path).unwrap();
            held.end();
        });
        let metric = |name: &str, value: &str| (name.to_owned(), true, value.to_owned());
        assert_eq!(
            read(),
            [metric(LOADS, "1"), metric(SERIAL, "20"), metric(ZONES, "1")]
        );
        // A reading that does not name the zone drops it: its series reads 0, none is left to remove. A snapshot
        // of the recorder resets its gauges, so the zone is named again, and the next reading, the one read, drops it.
        metrics::with_local_recorder(&recorder, || {
            held.begin();
            held.zone(&apex(), &path).unwrap();
            held.end();
            held.begin();
            held.end();
        });
        assert_eq!(read()[1], metric(SERIAL, "0"));
        assert_eq!(read()[2], metric(ZONES, "0"));
        assert!(held.zones.is_empty());

        // A secondary zone's version the same (D215).
        let zone = Held::default().zone(&apex(), &path).unwrap();
        metrics::with_local_recorder(&recorder, || {
            held.transferred(apex(), Some(zone));
            held.begin();
            assert!(held.secondary(&apex()).is_some());
            held.end();
            held.begin();
            held.end();
        });
        assert_eq!(read()[1], metric(SERIAL, "0"));
        assert_eq!(read()[2], metric(ZONES, "0"));
        assert!(held.secondaries.is_empty());
    }

    /// D208: the gauges describe what is served, so a reload that fails as a whole, after its zones were read,
    /// leaves them as they were: the zones it did not name are still served.
    #[test]
    fn the_gauges_stay_after_a_reload_that_failed() {
        use metrics_util::debugging::{DebugValue, DebuggingRecorder};

        let dir = tempfile::tempdir().unwrap();
        let isi = isi(dir.path());
        let example = dir.path().join("example.zone");
        fs::copy(
            dedens_testkit::path("zones/rfc4035_appendix_a.zone"),
            &example,
        )
        .unwrap();
        let config = |zones: &str, tries: u8| {
            format!(
                "listen: ['127.0.0.1:53']\npipeline: [zones, up]\nstages:\n  zones:\n    type: authoritative\n    zones:\n{zones}  up:\n    type: forward\n    servers: ['192.0.2.1']\n    tries: {tries}\n"
            )
        };
        let zone = |name: &str, file: &Path| {
            format!("      - {{name: {name}, file: '{}'}}\n", file.display())
        };
        let both = zone("ISI.EDU", &isi) + &zone("example", &example);
        let one = zone("ISI.EDU", &isi);
        let recorder = DebuggingRecorder::new();
        let snapshotter = recorder.snapshotter();
        let mut store = crate::lists::Store::default();
        let read = |text: String, store: &mut crate::lists::Store| {
            metrics::with_local_recorder(&recorder, || {
                crate::config::read(
                    &text,
                    |_| None,
                    (&dedens_server::Pipeline::default(), None),
                    store,
                )
            })
        };
        read(config(&both, 1), &mut store).unwrap();
        // The zones are read, and the forward stage after them is refused: `tries` is above 5.
        read(config(&one, 9), &mut store).unwrap_err();
        assert!(store.zones.zones.values().any(|kept| kept.used));
        let gauges: Vec<_> = (snapshotter.snapshot().into_vec().into_iter())
            .filter(|(key, ..)| key.key().name() == SERIAL || key.key().name() == ZONES)
            .map(|(key, _, _, value)| match value {
                DebugValue::Gauge(gauge) => (key.key().name().to_owned(), gauge.into_inner()),
                other => panic!("{other:?}"),
            })
            .collect();
        assert_eq!(
            gauges.iter().filter(|(name, _)| name == SERIAL).count(),
            2,
            "{gauges:?}"
        );
        assert!(gauges.iter().all(|(_, value)| *value >= 2.0), "{gauges:?}");
        assert!(gauges.contains(&(ZONES.to_owned(), 2.0)), "{gauges:?}");
    }

    #[test]
    fn a_zone_is_loaded_again_only_when_a_file_it_reads_changed() {
        let dir = tempfile::tempdir().unwrap();
        let path = isi(dir.path());
        let mut held = Held::default();
        let first = held.zone(&apex(), &path).unwrap();
        assert_eq!(first.soa().serial, 20);
        let again = held.zone(&apex(), &path).unwrap();
        assert!(Arc::ptr_eq(&first, &again), "kept");
        // The included file changes, longer: its stamp shows it.
        let mut mailboxes = fs::read_to_string(dir.path().join("mailboxes.zone")).unwrap();
        mailboxes.push_str("ADDED MB F.ISI.ARPA.\n");
        fs::write(dir.path().join("mailboxes.zone"), mailboxes).unwrap();
        let changed = held.zone(&apex(), &path).unwrap();
        assert!(!Arc::ptr_eq(&first, &changed), "loaded again");
        assert_eq!(changed.record_count(), first.record_count() + 1);
    }

    #[test]
    fn a_zone_failing_keeps_its_last_version_once_serving() {
        let dir = tempfile::tempdir().unwrap();
        let path = isi(dir.path());
        let mut held = Held::default();
        let first = held.zone(&apex(), &path).unwrap();
        fs::write(&path, "this is not a zone\n").unwrap();
        let error = held.zone(&apex(), &path).unwrap_err();
        assert!(
            format!("{error:#}").contains("loading zone `ISI.EDU.`"),
            "{error:#}"
        );
        held.serve();
        held.begin();
        let kept = held.zone(&apex(), &path).unwrap();
        assert!(Arc::ptr_eq(&first, &kept));
        held.end();
        assert_eq!(held.zones.len(), 1);
        // A zone new to the configuration has no version to keep.
        let other: Name<'static> = "other.example.".parse().unwrap();
        assert!(held.zone(&other, &path).is_err());
    }

    #[test]
    fn an_include_outside_the_directory_of_the_zone_file_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let zones = dir.path().join("zones");
        fs::create_dir(&zones).unwrap();
        let path = isi(&zones);
        fs::rename(
            zones.join("mailboxes.zone"),
            dir.path().join("mailboxes.zone"),
        )
        .unwrap();
        let text = fs::read_to_string(&path).unwrap();
        for name in [
            "../mailboxes.zone",
            &dir.path().join("mailboxes.zone").display().to_string(),
        ] {
            fs::write(&path, text.replace("mailboxes.zone", name)).unwrap();
            let error = Held::default().zone(&apex(), &path).unwrap_err();
            assert!(
                format!("{error:#}").contains("the directory of the zone file"),
                "{error:#}"
            );
        }
        // A link inside that leads outside is the same.
        #[cfg(unix)]
        {
            std::os::unix::fs::symlink(dir.path().join("mailboxes.zone"), zones.join("link.zone"))
                .unwrap();
            fs::write(&path, text.replace("mailboxes.zone", "link.zone")).unwrap();
            let error = Held::default().zone(&apex(), &path).unwrap_err();
            assert!(
                format!("{error:#}").contains("the directory of the zone file"),
                "{error:#}"
            );
        }
    }

    #[cfg(unix)]
    #[test]
    fn a_link_retargeted_loads_the_zone_again() {
        let dir = tempfile::tempdir().unwrap();
        let path = isi(dir.path());
        let (link, one, two) = ("link.zone", "one.zone", "two.zone");
        let mailboxes = fs::read_to_string(dir.path().join("mailboxes.zone")).unwrap();
        fs::write(dir.path().join(one), &mailboxes).unwrap();
        fs::write(
            dir.path().join(two),
            format!("{mailboxes}ADDED MB F.ISI.ARPA.\n"),
        )
        .unwrap();
        std::os::unix::fs::symlink(one, dir.path().join(link)).unwrap();
        let text = fs::read_to_string(&path).unwrap();
        fs::write(&path, text.replace("mailboxes.zone", link)).unwrap();
        let mut held = Held::default();
        let first = held.zone(&apex(), &path).unwrap();
        // The files the link and its target are both stamped.
        assert!(held.zones.values().next().unwrap().files.len() >= 3);
        fs::remove_file(dir.path().join(link)).unwrap();
        std::os::unix::fs::symlink(two, dir.path().join(link)).unwrap();
        let again = held.zone(&apex(), &path).unwrap();
        assert_eq!(again.record_count(), first.record_count() + 1);
    }

    #[test]
    fn a_file_over_the_most_bytes_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let path = isi(dir.path());
        let len = fs::metadata(&path).unwrap().len();
        assert!(load(&apex(), &path, len, &mut Files::new()).is_ok());
        let mut files = Files::new();
        let error = load(&apex(), &path, len - 1, &mut files).unwrap_err();
        assert!(
            format!("{error:#}").contains(&format!("is over {} bytes", len - 1)),
            "{error:#}"
        );
        // A file that was not read has no stamp, so the zone is tried again at the next load, however it failed.
        assert_eq!(files.len(), 1);
        assert!(files[0].1.is_none());
    }

    #[cfg(unix)]
    #[test]
    fn a_file_that_is_not_a_regular_one_is_refused_without_waiting() {
        let dir = tempfile::tempdir().unwrap();
        let path = isi(dir.path());
        fs::remove_file(&path).unwrap();
        nix::unistd::mkfifo(&path, nix::sys::stat::Mode::S_IRWXU).unwrap();
        let error = load(&apex(), &path, MAX_ZONE_FILE_BYTES, &mut Files::new()).unwrap_err();
        assert!(
            format!("{error:#}").contains("not a regular file"),
            "{error:#}"
        );
        // A directory is no file either.
        let error = load(&apex(), dir.path(), MAX_ZONE_FILE_BYTES, &mut Files::new()).unwrap_err();
        assert!(
            format!("{error:#}").contains("not a regular file"),
            "{error:#}"
        );
    }

    #[test]
    fn a_zone_that_failed_is_not_loaded_again_until_its_files_change() {
        let dir = tempfile::tempdir().unwrap();
        let path = isi(dir.path());
        let recorder = metrics_util::debugging::DebuggingRecorder::new();
        let snapshotter = recorder.snapshotter();
        // The loads that failed, counted.
        let errors = || {
            (snapshotter.snapshot().into_vec().into_iter())
                .filter(|(key, ..)| key.key().name() == LOADS)
                .filter(|(key, ..)| key.key().labels().any(|label| label.value() == "error"))
                .count()
        };
        let mut held = Held::default();
        let first = held.zone(&apex(), &path).unwrap();
        held.serve();
        // The included file goes: a failure, recorded with the state of the file that is not there.
        let mailboxes = dir.path().join("mailboxes.zone");
        let text = fs::read_to_string(&mailboxes).unwrap();
        fs::remove_file(&mailboxes).unwrap();
        metrics::with_local_recorder(&recorder, || {
            for _ in 0..3 {
                assert!(Arc::ptr_eq(&first, &held.zone(&apex(), &path).unwrap()));
            }
        });
        assert_eq!(errors(), 1, "tried once, the others skipped");
        // The file is back: its state is not the one that failed, the zone loads.
        fs::write(&mailboxes, text).unwrap();
        let again = held.zone(&apex(), &path).unwrap();
        assert!(!Arc::ptr_eq(&first, &again), "loaded again");
        assert!(held.zones.values().next().unwrap().failed.is_none());
    }
}
