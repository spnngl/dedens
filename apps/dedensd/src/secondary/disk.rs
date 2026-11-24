//! What a secondary keeps of a zone across restarts, in its directory `state_dir/zones/<zone>/` (D215): the zone
//! as text (`zone`, RFC 1035 §5), written whole at each full transfer; the changesets since (`journal`, D207),
//! appended at each incremental one; and its timers (`timers`). The text is written again when the journal no
//! longer starts at its version, a changeset too big or the oldest dropped. Knot keeps the same three, its journal
//! and timers in LMDB (`zone-in-journal`, `src/knot/journal/`, `src/knot/zone/timers.c`); NSD its zone in
//! `zonefile` and its timers in `xfrd.state` (`xfrd.c`, `xfrd_write_state`).
//!
//! Blocking file I/O, on the secondaries' thread (D215).

use std::fmt::Write as _;
use std::fs;
use std::io::{self, BufWriter, Write as _};
use std::path::{Path, PathBuf};

use anyhow::{Context as _, bail};
use dedens_proto::{Name, Record, RecordType, Serial};
use dedens_zone::journal::{Journal, JournalLimits};
use dedens_zone::{Changeset, Limits, Report, Zone};

use crate::download;

/// The file of the zone's text.
const ZONE: &str = "zone";
/// The file of its journal.
const JOURNAL: &str = "journal";
/// The file of its timers.
const TIMERS: &str = "timers";

/// The directory of the zone of `apex` below `zones`: its labels lowercased, each byte outside `[a-z0-9_-]` written
/// `%xx`, joined by dots and ended by one; the root's is `root`, which no other zone's can be. One file name per
/// zone, whatever bytes its labels hold, and none that climbs out of `zones` or hides as a dot file.
pub(super) fn dir_of(zones: &Path, apex: &Name<'_>) -> PathBuf {
    if apex.is_root() {
        return zones.join("root");
    }
    let mut name = String::new();
    for label in apex.labels() {
        for byte in label.iter().map(u8::to_ascii_lowercase) {
            if byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-' || byte == b'_' {
                name.push(char::from(byte));
            } else {
                let _ = write!(name, "%{byte:02x}");
            }
        }
        name.push('.');
    }
    zones.join(name)
}

/// The timers a zone keeps across restarts (Unix seconds): when it was last refreshed, and when it expires.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct Kept {
    pub(super) refreshed: u64,
    pub(super) expires: u64,
}

impl Kept {
    /// The text of the `timers` file.
    fn text(self) -> String {
        format!("refreshed {}\nexpires {}\n", self.refreshed, self.expires)
    }

    /// The timers of `text`, `None` when it is not what [`Kept::text`] writes.
    fn parse(text: &str) -> Option<Self> {
        let mut lines = text.lines();
        let mut field = |key: &str| {
            let value = lines.next()?.strip_prefix(key)?.strip_prefix(' ')?;
            value.parse().ok()
        };
        let kept = Self {
            refreshed: field("refreshed")?,
            expires: field("expires")?,
        };
        lines.next().is_none().then_some(kept)
    }
}

/// The files of one zone.
#[derive(Debug)]
pub(super) struct Disk {
    dir: PathBuf,
    /// Opened at the first changeset, or at [`Disk::load`].
    journal: Option<Journal>,
    /// The serial of the version the text holds; `None` before one is written or read.
    text: Option<Serial>,
}

impl Disk {
    pub(super) const fn new(dir: PathBuf) -> Self {
        Self {
            dir,
            journal: None,
            text: None,
        }
    }

    /// The version of `apex` kept, and its timers: the text with the journal's changesets applied. `None` when
    /// there is no text. A journal that does not apply is emptied, and the text's version served.
    ///
    /// # Errors
    ///
    /// A text that does not load, or timers that do not read: the zone is then transferred again.
    pub(super) fn load(&mut self, apex: &Name<'static>) -> anyhow::Result<Option<(Zone, Kept)>> {
        let path = self.dir.join(ZONE);
        if !path.try_exists()? {
            return Ok(None);
        }
        download::sweep(&[path.clone(), self.dir.join(TIMERS)], &self.dir);
        let timers = self.dir.join(TIMERS);
        let text = fs::read_to_string(&timers)
            .with_context(|| format!("reading `{}`", timers.display()))?;
        let Some(kept) = Kept::parse(&text) else {
            bail!("`{}` is not a timers file", timers.display());
        };
        let mut zone = crate::zones::stored(apex, &path)?;
        self.text = Some(Serial::new(zone.soa().serial));
        let journal = self.journal()?;
        let applied = (journal.changes_since(Serial::new(zone.soa().serial))).map(|changes| {
            let mut newer = None::<Zone>;
            for changeset in changes {
                let from = newer.as_ref().unwrap_or(&zone);
                newer = Some(from.apply(changeset, &Limits::default())?.zone);
            }
            Ok::<_, Report>(newer)
        });
        match applied {
            Some(Ok(newer)) => zone = newer.unwrap_or(zone),
            Some(Err(report)) => {
                tracing::warn!(zone = %apex, %report, "journal does not apply, emptied");
                journal.clear()?;
            }
            None if journal.is_empty() => {}
            None => {
                tracing::warn!(zone = %apex, "journal does not start at the zone file, emptied");
                journal.clear()?;
            }
        }
        Ok(Some((zone, kept)))
    }

    /// Keeps `zone`, transferred whole, refreshed as `kept` says: its text, an empty journal, the timers.
    ///
    /// # Errors
    ///
    /// A directory or a file that cannot be written.
    pub(super) fn full(&mut self, zone: &Zone, kept: Kept) -> anyhow::Result<()> {
        self.write_text(zone)?;
        self.journal()?.clear()?;
        self.timers(kept)
    }

    /// Keeps `changesets`, which took the version kept to `zone`, refreshed as `kept` says: appended to the
    /// journal, the text written again when the journal no longer starts at it.
    ///
    /// # Errors
    ///
    /// A directory or a file that cannot be written.
    pub(super) fn incremental(
        &mut self,
        changesets: &[Changeset],
        zone: &Zone,
        kept: Kept,
    ) -> anyhow::Result<()> {
        let text = self.text;
        let journal = self.journal()?;
        let mut appended = changesets.iter().try_for_each(|changeset| {
            journal.append(changeset)?;
            anyhow::Ok(())
        });
        if appended.is_ok() && text.is_none_or(|text| journal.changes_since(text).is_none()) {
            appended = self.write_text(zone);
        }
        if let Err(error) = appended {
            // The journal is in an unknown state: the text, then an empty journal, keep the version.
            tracing::warn!(dir = %self.dir.display(), error = format!("{error:#}"), "journal not written, writing the zone file");
            self.journal = None;
            self.write_text(zone)?;
            self.journal()?.clear()?;
        }
        self.timers(kept)
    }

    /// Writes the timers `kept`.
    ///
    /// # Errors
    ///
    /// A directory or a file that cannot be written.
    pub(super) fn timers(&self, kept: Kept) -> anyhow::Result<()> {
        self.made()?;
        let path = self.dir.join(TIMERS);
        download::replace(&path, kept.text())
            .with_context(|| format!("writing `{}`", path.display()))
    }

    /// The journal, opened if it is not.
    fn journal(&mut self) -> anyhow::Result<&mut Journal> {
        if self.journal.is_none() {
            self.made()?;
            let path = self.dir.join(JOURNAL);
            let journal = Journal::open(&path, JournalLimits::default())
                .with_context(|| format!("opening `{}`", path.display()))?;
            self.journal = Some(journal);
        }
        self.journal.as_mut().context("the journal was just opened")
    }

    /// Writes `zone` as text, whole or not at all.
    fn write_text(&mut self, zone: &Zone) -> anyhow::Result<()> {
        self.made()?;
        let path = self.dir.join(ZONE);
        download::replace_with(&path, |out| write_zone(zone, out))
            .with_context(|| format!("writing `{}`", path.display()))?;
        self.text = Some(Serial::new(zone.soa().serial));
        Ok(())
    }

    /// Makes the directory, readable by its owner only, as the zone may be a private one.
    fn made(&self) -> anyhow::Result<()> {
        let mut builder = fs::DirBuilder::new();
        builder.recursive(true);
        #[cfg(unix)]
        std::os::unix::fs::DirBuilderExt::mode(&mut builder, 0o700);
        builder
            .create(&self.dir)
            .with_context(|| format!("making `{}`", self.dir.display()))
    }
}

/// Writes `zone` to `out` in the presentation format (RFC 1035 §5), a record a line, names absolute, the SOA
/// first, as [`crate::zones::stored`] reads it back.
fn write_zone(zone: &Zone, out: &mut dyn io::Write) -> io::Result<()> {
    let mut out = BufWriter::new(out);
    let record = |name: &Name<'static>, ttl, rdata: &_| Record {
        name: name.clone(),
        class: zone.class(),
        ttl,
        rdata: Clone::clone(rdata),
    };
    let soa = zone.soa_rrset().map(|set| (zone.apex(), set));
    let others = zone.nodes().flat_map(|(name, node)| {
        let sets = node.rrsets().filter(|(rtype, _)| *rtype != RecordType::SOA);
        let sets = sets.map(|(_, set)| set).chain(node.signature_sets());
        sets.map(move |set| (name, set))
    });
    for (name, set) in soa.into_iter().chain(others) {
        {
            for rdata in set.rdatas() {
                writeln!(out, "{}", record(name, set.ttl(), rdata))?;
            }
        }
    }
    out.flush()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_zone_directory_is_one_file_name_whatever_its_labels() {
        let zones = Path::new("/state/zones");
        let cases = [
            (".", "root"),
            ("Example.COM.", "example.com."),
            ("_tcp.my-zone.", "_tcp.my-zone."),
            (r"a\.b.\..", "a%2eb.%2e."),
            (r"\000\/\032.", "%00%2f%20."),
        ];
        for (apex, dir) in cases {
            let apex: Name<'static> = apex.parse().unwrap();
            assert_eq!(dir_of(zones, &apex), zones.join(dir), "{apex}");
        }
    }

    #[test]
    fn the_timers_read_back_and_nothing_else_does() {
        let kept = Kept {
            refreshed: 1_700_000_000,
            expires: u64::MAX,
        };
        assert_eq!(Kept::parse(&kept.text()), Some(kept));
        for text in [
            "",
            "refreshed 1\n",
            "refreshed 1\nexpires x\n",
            "expires 1\nrefreshed 1\n",
        ] {
            assert_eq!(Kept::parse(text), None, "{text:?}");
        }
        assert_eq!(Kept::parse("refreshed 1\nexpires 2\nmore\n"), None);
    }

    /// The zone in `testdata/authoritative/zones/<file>`, of apex `apex`.
    fn captured(apex: &str, file: &str) -> Zone {
        let path = dedens_testkit::path("authoritative/zones").join(file);
        crate::zones::stored(&apex.parse().unwrap(), &path).unwrap()
    }

    #[test]
    fn a_zone_written_reads_back_the_same() {
        let dir = tempfile::tempdir().unwrap();
        for (apex, file) in [
            (".", "root.zone"),
            ("zonetransfer.me.", "zonetransfer.me.zone"),
            ("example.", "nsec3_signed.zone"),
        ] {
            let zone = captured(apex, file);
            let mut disk = Disk::new(dir.path().join(file));
            let kept = Kept {
                refreshed: 1,
                expires: 2,
            };
            disk.full(&zone, kept).unwrap();
            let (read, timers) = Disk::new(dir.path().join(file))
                .load(&apex.parse().unwrap())
                .unwrap()
                .unwrap();
            assert_eq!(timers, kept);
            assert!(read == zone, "{file}");
        }
    }

    /// The zone of RFC 4035 Appendix A at serial `serial`, read from a copy in `dir`.
    fn example(dir: &Path, serial: u32) -> Zone {
        let text =
            fs::read_to_string(dedens_testkit::path("zones/rfc4035_appendix_a.zone")).unwrap();
        let text = text.replace("1081539377", &serial.to_string());
        let path = dir.join(format!("example-{serial}.zone"));
        fs::write(&path, text).unwrap();
        crate::zones::stored(&"example.".parse().unwrap(), &path).unwrap()
    }

    /// RFC 1995 §4: an IXFR's changesets are journaled and the text stays while the journal starts at it; the
    /// version read back is the text with the journal applied. A text the journal does not start at empties it.
    #[test]
    fn rfc1995_4_the_journal_brings_the_text_up_to_date() {
        let dir = tempfile::tempdir().unwrap();
        let (copies, files) = (dir.path().join("copies"), dir.path().join("zone"));
        fs::create_dir(&copies).unwrap();
        let apex: Name<'static> = "example.".parse().unwrap();
        let first = example(&copies, 1);
        let second = example(&copies, 2);
        let kept = Kept {
            refreshed: 0,
            expires: 1,
        };
        let mut disk = Disk::new(files.clone());
        disk.full(&first, kept).unwrap();
        let changeset = Zone::diff(&first, &second).unwrap();
        disk.incremental(&[changeset], &second, kept).unwrap();
        let text = crate::zones::stored(&apex, &files.join(ZONE)).unwrap();
        assert_eq!(text.soa().serial, 1, "the journal starts at the text");
        let (read, _) = Disk::new(files.clone()).load(&apex).unwrap().unwrap();
        assert!(read == second, "the text with the journal applied");

        let third = example(&copies, 3);
        disk.full(&third, kept).unwrap();
        drop(disk);
        let journal = || Journal::open(files.join(JOURNAL), JournalLimits::default()).unwrap();
        assert!(journal().is_empty(), "a full transfer empties the journal");
        let mut disk = Disk::new(files.clone());
        disk.full(&first, kept).unwrap();
        let changeset = Zone::diff(&first, &second).unwrap();
        disk.incremental(&[changeset], &second, kept).unwrap();
        drop(disk);
        fs::copy(copies.join("example-3.zone"), files.join(ZONE)).unwrap();
        let (read, _) = Disk::new(files.clone()).load(&apex).unwrap().unwrap();
        assert!(read == third, "the text alone");
        assert!(
            journal().is_empty(),
            "a journal not starting at the text is emptied"
        );
    }
}
