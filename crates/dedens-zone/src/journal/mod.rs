//! [`Journal`]: the changesets of one zone, kept in a file that survives a crash (RFC 1995 §4, D207).
//!
//! The file is append-only: a record is framed with its length and CRC ([`mod@format`]), written, and synced before
//! [`Journal::append`] says it is done. A crash leaves at worst a torn last record, which [`Journal::open`] cuts;
//! the changesets before it are whole. Dropping the oldest changesets, when a limit is reached, writes the kept
//! ones to a new file and renames it over the old, so a crash leaves the old file or the new one.
//!
//! Blocking file I/O, a few calls per zone version: the caller runs it off the thread that serves queries.

mod crc;
pub mod format;

use std::collections::VecDeque;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};

use dedens_proto::{EncodeError, Serial};

use self::format::{MAGIC, Scan, Tail};
use crate::Changeset;

/// The largest journal file [`Journal::open`] reads.
///
/// The whole file is read into memory, so a file this size is read, a larger one refused as it is not a journal of
/// this program's: the default byte limit is a tenth of it. Knot's `journal-max-usage` is capped by its LMDB map
/// size (`src/knot/conf/schema.c`, a `YP_SSIZE` integer), BIND's by `DNS_JOURNAL_SIZE_MAX`, `INT32_MAX`
/// (`lib/dns/include/dns/journal.h`); this is lower than either, as nothing here pages.
pub const MAX_FILE: u64 = 1 << 30;

/// Why a journal could not be read or written.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum JournalError {
    /// The file system refused.
    #[error("journal file: {0}")]
    Io(#[from] io::Error),
    /// A file that does not start with the journal's header: not overwritten.
    #[error("the file is not a journal of this program (wrong header)")]
    NotAJournal,
    /// A file over [`MAX_FILE`]: not read.
    #[error("the journal file is {size} bytes, over {MAX_FILE}")]
    TooLarge {
        /// Its size.
        size: u64,
    },
    /// A changeset that starts from another serial than the journal ends at: the journal has a hole, which a
    /// changeset after it could not fill (RFC 1995 §4: a sequence is of consecutive versions).
    #[error("the journal ends at serial {tip}, the changeset starts from {from}")]
    NotConsecutive {
        /// The serial the last changeset of the journal ends at.
        tip: Serial,
        /// The serial the one offered starts from.
        from: Serial,
    },
    /// A record whose RDATA is over what a record can carry (RFC 1035 §3.2.1).
    #[error("changeset not encodable: {0}")]
    Encode(#[from] EncodeError),
    /// An earlier write failed, so what is on disk is not known: open the journal again, which reads the file.
    #[error("an earlier write failed: open the journal again")]
    Poisoned,
}

/// What [`Journal::append`] did with a changeset.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Stored {
    /// Written and synced; `dropped` of the oldest changesets made room.
    Kept {
        /// How many were dropped.
        dropped: usize,
    },
    /// Not kept: alone it is over a limit, so the journal is now empty. The versions it spans are served by
    /// AXFR (RFC 1995 §4: a server that cannot give the differences sends the whole zone).
    TooBig,
}

/// How much a [`Journal`] keeps: the oldest changesets go first (RFC 1995 §4 lets a server keep a limited number).
///
/// Knot keeps both limits at once, `journal-max-usage` 100 MiB and `journal-max-depth` 20
/// (`src/knot/conf/schema.c`); NSD does as well, `ixfr-size` 1 MiB and `ixfr-number` 5, and drops the oldest
/// until the new one fits, or does not keep one that is over the size alone (`zone_ixfr_make_space` in
/// `ixfr.c`; `IXFR_SIZE_DEFAULT`, `IXFR_NUMBER_DEFAULT` in `ixfr.h`); BIND has a size only, the zone's twice
/// (`max-journal-size`, `lib/dns/zone.c`), at least 4096 bytes (`DNS_JOURNAL_SIZE_MIN`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct JournalLimits {
    /// Bytes of the file, header included. Default: Knot's 100 MiB, as the differences of a zone worth it are
    /// far smaller than the zone, and a client that is further behind than this is better sent the zone.
    pub bytes: usize,
    /// How many changesets. Default: Knot's 20, between NSD's 5 and the many a size limit alone allows: a
    /// secondary that polls every few minutes is a few versions behind, one that is a day behind transfers
    /// the zone.
    pub changesets: usize,
}

impl Default for JournalLimits {
    fn default() -> Self {
        Self {
            bytes: 100 << 20,
            changesets: 20,
        }
    }
}

/// One changeset and the size of its record in the file.
#[derive(Debug)]
struct Entry {
    changeset: Changeset,
    size: usize,
}

/// The journal of one zone: a file and its changesets, oldest first, in memory too.
///
/// The memory is that of the file, which [`JournalLimits::bytes`] bounds.
#[derive(Debug)]
pub struct Journal {
    path: PathBuf,
    limits: JournalLimits,
    entries: VecDeque<Entry>,
    /// Appends to `path`.
    file: File,
    /// The bytes the open cut off the end of the file.
    discarded: usize,
    /// A write failed: the file may hold anything.
    poisoned: bool,
}

impl Journal {
    /// The journal in `path`, made if the file is not there.
    ///
    /// Reads the file, cuts a torn or bad tail (syncing), and drops the oldest changesets down to `limits`. A
    /// journal of a crashed write is thus whole again, with every changeset that [`append`](Self::append) said
    /// was written. The directory of `path` must be there and writable: a rewrite goes through `path` with
    /// `.tmp` added.
    ///
    /// # Errors
    ///
    /// [`JournalError::NotAJournal`] for a file that is not a journal, which is left as it is,
    /// [`JournalError::TooLarge`] for one over [`MAX_FILE`], [`JournalError::Io`] otherwise.
    pub fn open(path: impl Into<PathBuf>, limits: JournalLimits) -> Result<Self, JournalError> {
        let path = path.into();
        let bytes = match read(&path) {
            Ok(bytes) => bytes,
            Err(JournalError::Io(e)) if e.kind() == io::ErrorKind::NotFound => Vec::new(),
            Err(e) => return Err(e),
        };
        let Scan {
            changesets,
            sizes,
            valid,
            tail,
        } = format::scan(&bytes)?;
        let discarded = bytes.len().saturating_sub(valid);
        if valid == 0 {
            replace(&path, &MAGIC)?;
        } else if tail != Tail::Clean {
            let file = OpenOptions::new().write(true).open(&path)?;
            file.set_len(u64::try_from(valid).unwrap_or(u64::MAX))?;
            file.sync_all()?;
        }
        let entries = changesets
            .into_iter()
            .zip(sizes)
            .map(|(changeset, size)| Entry { changeset, size })
            .collect();
        let mut journal = Self {
            file: OpenOptions::new().append(true).open(&path)?,
            path,
            limits,
            entries,
            discarded,
            poisoned: false,
        };
        let drop = journal.drops(0, 0);
        if drop > 0 {
            journal.rewrite(drop, None)?;
        }
        Ok(journal)
    }

    /// Adds `changeset` after the last one, and returns when it is on disk.
    ///
    /// The oldest changesets are dropped to make room under the limits. A changeset that is over a limit alone
    /// empties the journal and is not kept ([`Stored::TooBig`]), as NSD does (`zone_ixfr_make_space`).
    ///
    /// # Errors
    ///
    /// [`JournalError::NotConsecutive`] when the journal is not empty and `changeset` does not start from where
    /// it ends, [`JournalError::Encode`], [`JournalError::Io`]; after an I/O error [`JournalError::Poisoned`]
    /// until the journal is opened again.
    pub fn append(&mut self, changeset: &Changeset) -> Result<Stored, JournalError> {
        if self.poisoned {
            return Err(JournalError::Poisoned);
        }
        if let Some(tip) = self.tip()
            && tip != changeset.from_serial()
        {
            return Err(JournalError::NotConsecutive {
                tip,
                from: changeset.from_serial(),
            });
        }
        let mut record = Vec::new();
        format::encode(changeset, &mut record)?;
        if MAGIC.len() + record.len() > self.limits.bytes || self.limits.changesets == 0 {
            self.clear()?;
            return Ok(Stored::TooBig);
        }
        let drop = self.drops(record.len(), 1);
        if drop == 0 {
            self.poison_on_error(|journal| {
                journal.file.write_all(&record)?;
                journal.file.sync_data()
            })?;
        } else {
            self.rewrite(drop, Some(&record))?;
        }
        self.entries.push_back(Entry {
            changeset: changeset.clone(),
            size: record.len(),
        });
        Ok(Stored::Kept { dropped: drop })
    }

    /// The changesets that take a copy at `serial` to the journal's last version, oldest first: empty when
    /// `serial` is the last. `None` when the journal cannot say, as the serial is older than its first changeset,
    /// is not one it has seen, or is ahead; the caller sends the whole zone then (RFC 1995 §4).
    #[must_use]
    pub fn changes_since(
        &self,
        serial: Serial,
    ) -> Option<impl ExactSizeIterator<Item = &Changeset>> {
        let from = if self.tip() == Some(serial) {
            self.entries.len()
        } else {
            self.entries
                .iter()
                .position(|e| e.changeset.from_serial() == serial)?
        };
        Some(self.entries.iter().skip(from).map(|e| &e.changeset))
    }

    /// Empties the journal: a zone that was replaced whole has no differences from before.
    ///
    /// # Errors
    ///
    /// [`JournalError::Io`], and then [`JournalError::Poisoned`] until the journal is opened again.
    pub fn clear(&mut self) -> Result<(), JournalError> {
        let all = self.entries.len();
        self.rewrite(all, None)
    }

    /// The serial the last changeset ends at; `None` for an empty journal.
    #[must_use]
    pub fn tip(&self) -> Option<Serial> {
        self.entries.back().map(|e| e.changeset.to_serial())
    }

    /// How many changesets.
    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether there are no changesets.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// The size of the file.
    #[must_use]
    pub fn bytes(&self) -> usize {
        MAGIC.len() + self.entries.iter().map(|e| e.size).sum::<usize>()
    }

    /// How many bytes of the file [`open`](Self::open) cut: a torn or refused tail.
    #[must_use]
    pub const fn discarded(&self) -> usize {
        self.discarded
    }

    /// How many of the oldest changesets go for `extra` more bytes and `extra_count` more changesets to fit
    /// the limits.
    fn drops(&self, extra: usize, extra_count: usize) -> usize {
        let mut bytes = self.bytes() + extra;
        let mut count = self.entries.len() + extra_count;
        let mut dropped = 0;
        for entry in &self.entries {
            if bytes <= self.limits.bytes && count <= self.limits.changesets {
                break;
            }
            bytes -= entry.size;
            count -= 1;
            dropped += 1;
        }
        dropped
    }

    /// Replaces the file by the changesets without the oldest `drop`, then `extra` (a record), and forgets the
    /// dropped ones.
    fn rewrite(&mut self, drop: usize, extra: Option<&[u8]>) -> Result<(), JournalError> {
        let mut content = MAGIC.to_vec();
        for entry in self.entries.iter().skip(drop) {
            format::encode(&entry.changeset, &mut content)?;
        }
        content.extend_from_slice(extra.unwrap_or_default());
        self.poison_on_error(|journal| {
            replace(&journal.path, &content)?;
            journal.file = OpenOptions::new().append(true).open(&journal.path)?;
            Ok(())
        })?;
        self.entries.drain(..drop);
        Ok(())
    }

    /// Runs a write; a failure poisons the journal, as what is on disk is then unknown.
    fn poison_on_error(
        &mut self,
        write: impl FnOnce(&mut Self) -> io::Result<()>,
    ) -> Result<(), JournalError> {
        write(self).map_err(|e| {
            self.poisoned = true;
            JournalError::Io(e)
        })
    }
}

/// The bytes of the file at `path`.
fn read(path: &Path) -> Result<Vec<u8>, JournalError> {
    let file = File::open(path)?;
    let size = file.metadata()?.len();
    if size > MAX_FILE {
        return Err(JournalError::TooLarge { size });
    }
    let mut bytes = Vec::with_capacity(usize::try_from(size).unwrap_or_default());
    // The file may have grown since `metadata`: read no more than the bound.
    file.take(MAX_FILE + 1).read_to_end(&mut bytes)?;
    if u64::try_from(bytes.len()).is_ok_and(|n| n > MAX_FILE) {
        return Err(JournalError::TooLarge {
            size: u64::try_from(bytes.len()).unwrap_or(u64::MAX),
        });
    }
    Ok(bytes)
}

/// Makes `path` hold `content` and nothing else, whole or not at all: writes `path` with `.tmp` added, syncs it,
/// renames it over `path`, and syncs the directory so the rename is on disk.
fn replace(path: &Path, content: &[u8]) -> io::Result<()> {
    let mut temporary = path.as_os_str().to_owned();
    temporary.push(".tmp");
    let temporary = PathBuf::from(temporary);
    let mut file = File::create(&temporary)?;
    file.write_all(content)?;
    file.sync_all()?;
    drop(file);
    fs::rename(&temporary, path)?;
    sync_directory(path)
}

/// Syncs the directory that holds `path`: a rename or a new file is in it, and not on disk before this.
#[cfg(unix)]
fn sync_directory(path: &Path) -> io::Result<()> {
    let directory = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    File::open(directory)?.sync_all()
}

/// Windows opens no directory as a file; NTFS orders a rename's metadata itself.
#[cfg(not(unix))]
fn sync_directory(_path: &Path) -> io::Result<()> {
    Ok(())
}
