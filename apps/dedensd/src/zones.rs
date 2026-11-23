//! The zones of the `authoritative` stage, kept across reloads (D208).
//!
//! A zone is loaded again only when its file, or a file it includes, changed, as the lists are (D120's [`Stamp`]).
//! Once the server serves, a zone whose files fail to load keeps its last version (D55), the error logged and
//! counted; before, at the start, the failure fails the start.

use std::collections::HashMap;
use std::fs::File;
use std::io::Read as _;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use anyhow::{Context as _, anyhow, ensure};
use dedens_proto::{Name, Ttl};
use dedens_zone::{Limits, Source, Zone};

use crate::lists::Stamp;

/// The most bytes a zone file, or a file it includes, holds: 4 GiB (2³²). The text is read whole before it is
/// parsed, so a bound on it is a bound on that memory; the zone it may hold is bounded first by its records and their
/// data (`dedens_zone::Limits`: 2²⁴ records, 1 GiB of RDATA), which this leaves room for in base64. Knot (`zs_set_input_file`,
/// `src/libzscanner/scanner.rl`), NSD (`zonec_read`, `zonec.c`) and BIND (`isc_lex_openfile`, `lib/isc/lex.c`) read
/// the file as a stream, with no bound.
pub(crate) const MAX_ZONE_FILE_BYTES: u64 = 1 << 32;

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

/// A zone loaded, and what tells whether its files changed since.
#[derive(Debug)]
struct Kept {
    zone: Arc<Zone>,
    /// The files read, with their stamps: the zone file, then each it includes.
    files: Vec<(PathBuf, Stamp)>,
    /// Whether the reading under way used it: what is not is dropped at its end.
    used: bool,
}

/// The zones loaded so far, by apex and file. Part of the [`Store`](crate::lists::Store).
#[derive(Debug, Default)]
pub(crate) struct Held {
    zones: HashMap<(Name<'static>, PathBuf), Kept>,
    /// Whether the server serves: a zone failing to load keeps its last version then.
    serving: bool,
}

impl Held {
    /// Starts a reading of the configuration: no zone is used yet.
    pub(crate) fn begin(&mut self) {
        for kept in self.zones.values_mut() {
            kept.used = false;
        }
    }

    /// Ends a reading that succeeded: the zones it did not use are dropped.
    pub(crate) fn end(&mut self) {
        self.zones.retain(|_, kept| kept.used);
        #[expect(
            clippy::cast_precision_loss,
            reason = "a gauge is a float; the zones number far below 2⁵²"
        )]
        metrics::gauge!(ZONES).set(self.zones.len() as f64);
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
        if let Some(kept) = self.zones.get_mut(&key)
            && unchanged(&kept.files)
        {
            kept.used = true;
            return Ok(Arc::clone(&kept.zone));
        }
        let file = path.display();
        match load(apex, path, MAX_ZONE_FILE_BYTES) {
            Ok((zone, files)) => {
                metrics::counter!(LOADS, "result" => "ok").increment(1);
                metrics::gauge!(SERIAL, "zone" => apex.to_string())
                    .set(f64::from(zone.soa().serial));
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
                kept.used = true;
                Ok(Arc::clone(&kept.zone))
            }
        }
    }
}

/// Whether each of `files` is still the one read, as its stamp shows: a file that no longer opens has changed.
fn unchanged(files: &[(PathBuf, Stamp)]) -> bool {
    files.iter().all(|(path, stamp)| {
        File::open(path)
            .and_then(|file| Stamp::of(&file))
            .is_ok_and(|now| now == *stamp)
    })
}

/// The zone of apex `apex` in the file at `path`, each file read at most `max` bytes, and the files read with their
/// stamps. An `$INCLUDE` names a file in the directory of the zone file or below it (D208), its depth bounded by
/// [`Limits::include_depth`].
fn load(
    apex: &Name<'static>,
    path: &Path,
    max: u64,
) -> anyhow::Result<(Zone, Vec<(PathBuf, Stamp)>)> {
    let mut files = Vec::new();
    let text = read(path, max, &mut files)?;
    let dir = path
        .parent()
        .filter(|dir| !dir.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    let inside = dir
        .canonicalize()
        .with_context(|| format!("reading `{}`", dir.display()))?;
    let mut include = |name: &str| -> Result<Vec<u8>, String> {
        // Resolved, links and `..` included, before it is compared: no way out of the directory.
        let target = inside
            .join(name)
            .canonicalize()
            .map_err(|error| error.to_string())?;
        if !target.starts_with(&inside) {
            return Err(format!(
                "outside `{}`, the directory of the zone file",
                inside.display()
            ));
        }
        read(&target, max, &mut files).map_err(|error| format!("{error:#}"))
    };
    let name = path.display().to_string();
    let source = Source {
        name: &name,
        text: &text,
        default_ttl: Some(DEFAULT_TTL),
    };
    let loaded = Zone::load(apex.clone(), source, &mut include, &Limits::default())
        .map_err(|report| anyhow!("{report}"))
        .with_context(|| format!("loading zone `{apex}`"))?;
    if !loaded.report.warnings.is_empty() {
        tracing::warn!(zone = %apex, report = %loaded.report, "zone loaded with warnings");
    }
    Ok((loaded.zone, files))
}

/// The bytes of the file at `path`, at most `max`, its stamp pushed on `files`.
fn read(path: &Path, max: u64, files: &mut Vec<(PathBuf, Stamp)>) -> anyhow::Result<Vec<u8>> {
    let reading = || format!("reading `{}`", path.display());
    let file = File::open(path).with_context(reading)?;
    let stamp = Stamp::of(&file).with_context(reading)?;
    let mut text = Vec::new();
    file.take(max.saturating_add(1))
        .read_to_end(&mut text)
        .with_context(reading)?;
    ensure!(
        u64::try_from(text.len()).is_ok_and(|len| len <= max),
        "`{}` is over {max} bytes",
        path.display()
    );
    files.push((path.to_owned(), stamp));
    Ok(text)
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
        // A reading that does not name the zone drops it.
        metrics::with_local_recorder(&recorder, || {
            held.begin();
            held.end();
        });
        assert_eq!(read()[2], metric(ZONES, "0"));
        assert!(held.zones.is_empty());
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

    #[test]
    fn a_file_over_the_most_bytes_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let path = isi(dir.path());
        let len = fs::metadata(&path).unwrap().len();
        assert!(load(&apex(), &path, len).is_ok());
        let error = load(&apex(), &path, len - 1).unwrap_err();
        assert!(
            format!("{error:#}").contains(&format!("is over {} bytes", len - 1)),
            "{error:#}"
        );
    }
}
