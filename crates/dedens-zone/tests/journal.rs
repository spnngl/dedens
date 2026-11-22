//! The journal file: changesets kept across restarts and crashes (RFC 1995 §4, D207).
//!
//! The changesets are the differences of small versions of a zone, found by [`Zone::diff`]. A crash is a file cut
//! at each byte of its last record, a disk fault a byte flipped in each place.

use std::fs;
use std::path::PathBuf;

use dedens_proto::Serial;
use dedens_zone::journal::format::{self, FRAME, MAGIC, Tail};
use dedens_zone::journal::{Journal, JournalError, JournalLimits, MAX_FILE, Stored};
use dedens_zone::{Changeset, Limits, Zone};
use tempfile::TempDir;

use crate::util::{APEX, load, load_files, zone_file};

/// [`APEX`] at `serial`, then `extra`, loaded.
fn version(serial: u32, extra: &str) -> Zone {
    let apex = APEX.replace(" hostmaster 1 ", &format!(" hostmaster {serial} "));
    load(&format!("{apex}{extra}")).expect("a valid zone").zone
}

/// The changesets of five versions of a zone, serial 1 to 5, each from the one before.
fn chain() -> Vec<Changeset> {
    let versions = [
        version(1, "www A 192.0.2.10\n"),
        version(2, "www A 192.0.2.10\nmail A 192.0.2.20\n"),
        version(3, "www A 192.0.2.11\nmail A 192.0.2.20\n"),
        version(4, "www A 192.0.2.11\nwww TXT \"v=1\"\n"),
        version(
            5,
            "www A 192.0.2.11\nwww TXT \"v=1\"\nsub NS ns.sub\nns.sub A 192.0.2.30\n",
        ),
    ];
    versions
        .windows(2)
        .map(|pair| Zone::diff(&pair[0], &pair[1]).expect("ahead"))
        .collect()
}

/// The bytes of a journal file of `changesets`, and where each record starts.
fn file_of(changesets: &[Changeset]) -> (Vec<u8>, Vec<usize>) {
    let mut bytes = MAGIC.to_vec();
    let mut starts = Vec::new();
    for changeset in changesets {
        starts.push(bytes.len());
        format::encode(changeset, &mut bytes).expect("encodes");
    }
    (bytes, starts)
}

/// The zone of RFC 4035 appendix A at `serial`, `edit` applied to its text.
fn signed(serial: u32, edit: impl Fn(String) -> String) -> Zone {
    let text = zone_file("rfc4035_appendix_a.zone").replace("1081539377", &serial.to_string());
    load_files("example.", &edit(text), None, &[], &Limits::default())
        .expect("a valid zone")
        .zone
}

/// The journal file the fuzz target `journal_read` starts from (`fuzz/seeds/example.journal`): three versions of
/// the zone of RFC 4035 appendix A, one with its signatures renewed, one with a name added. With
/// `DEDENS_WRITE_SEED` set the test writes the file first, which is how it is made again when the format changes.
#[test]
fn the_fuzz_seed_is_the_journal_of_three_versions_of_an_example_zone() {
    let versions = [
        signed(1_081_539_377, |t| t),
        signed(1_081_539_378, |t| t.replace("38519", "38520")),
        signed(1_081_539_379, |t| {
            format!(
                "{}\nextra.example. 3600 IN TXT \"added\"\n",
                t.replace("38519", "38520")
            )
        }),
    ];
    let changesets: Vec<_> = versions
        .windows(2)
        .map(|pair| Zone::diff(&pair[0], &pair[1]).expect("ahead"))
        .collect();
    let (bytes, _) = file_of(&changesets);
    let path =
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../fuzz/seeds/example.journal");
    if std::env::var_os("DEDENS_WRITE_SEED").is_some() {
        fs::write(&path, &bytes).expect("writes the seed");
    }
    assert!(
        fs::read(&path).expect("the seed") == bytes,
        "fuzz/seeds/example.journal is not what the journal writes: DEDENS_WRITE_SEED=1 cargo test -p dedens-zone"
    );
}

fn directory() -> (TempDir, PathBuf) {
    let dir = tempfile::tempdir().expect("a temporary directory");
    let path = dir.path().join("example.journal");
    (dir, path)
}

fn open(path: &PathBuf) -> Journal {
    Journal::open(path, JournalLimits::default()).expect("opens")
}

fn serials(journal: &Journal, since: u32) -> Option<Vec<(u32, u32)>> {
    journal.changes_since(Serial::new(since)).map(|changes| {
        changes
            .map(|c| (c.from_serial().get(), c.to_serial().get()))
            .collect()
    })
}

// --- the file ---

#[test]
fn a_new_journal_is_a_file_of_its_header() {
    let (_dir, path) = directory();
    let journal = open(&path);
    assert!(journal.is_empty());
    assert_eq!(journal.tip(), None);
    assert_eq!(journal.bytes(), MAGIC.len());
    assert_eq!(fs::read(&path).expect("the file"), MAGIC);
}

#[test]
fn what_was_appended_is_there_after_opening_again() {
    let (_dir, path) = directory();
    let changesets = chain();
    let mut journal = open(&path);
    for changeset in &changesets {
        assert_eq!(
            journal.append(changeset).expect("appends"),
            Stored::Kept { dropped: 0 }
        );
    }
    assert_eq!(fs::read(&path).expect("the file"), file_of(&changesets).0);
    assert_eq!(journal.bytes(), file_of(&changesets).0.len());

    let again = open(&path);
    assert_eq!(again.len(), 4);
    assert_eq!(again.tip(), Some(Serial::new(5)));
    assert_eq!(again.discarded(), 0);
    let got: Vec<_> = again.changes_since(Serial::new(1)).expect("kept").collect();
    assert_eq!(got, changesets.iter().collect::<Vec<_>>());
}

#[test]
fn a_changeset_must_start_where_the_journal_ends() {
    let (_dir, path) = directory();
    let changesets = chain();
    let mut journal = open(&path);
    journal.append(&changesets[0]).expect("appends");
    let error = journal.append(&changesets[2]).expect_err("a hole");
    assert!(
        matches!(error, JournalError::NotConsecutive { tip, from }
            if tip == Serial::new(2) && from == Serial::new(3)),
        "{error:?}"
    );
    assert_eq!(
        journal.len(),
        1,
        "a refused changeset leaves the journal as it was"
    );
    assert_eq!(
        fs::read(&path).expect("the file"),
        file_of(&changesets[..1]).0
    );
}

/// What a client at a serial is told: the changesets from there, none for the last version, nothing when the
/// journal cannot say (RFC 1995 §4).
#[test]
fn changes_since_tells_the_changesets_from_a_serial() {
    let (_dir, path) = directory();
    let mut journal = open(&path);
    assert_eq!(
        serials(&journal, 1),
        None,
        "an empty journal knows no serial"
    );
    for changeset in chain() {
        journal.append(&changeset).expect("appends");
    }
    assert_eq!(
        serials(&journal, 1),
        Some(vec![(1, 2), (2, 3), (3, 4), (4, 5)])
    );
    assert_eq!(serials(&journal, 3), Some(vec![(3, 4), (4, 5)]));
    assert_eq!(
        serials(&journal, 5),
        Some(vec![]),
        "the last version has nothing to add"
    );
    assert_eq!(serials(&journal, 0), None, "older than the journal");
    assert_eq!(serials(&journal, 6), None, "ahead of the journal");
}

#[test]
fn clearing_leaves_the_header_and_a_free_start() {
    let (_dir, path) = directory();
    let changesets = chain();
    let mut journal = open(&path);
    journal.append(&changesets[0]).expect("appends");
    journal.clear().expect("clears");
    assert!(journal.is_empty());
    assert_eq!(fs::read(&path).expect("the file"), MAGIC);
    journal
        .append(&changesets[2])
        .expect("an empty journal takes any start");
    assert_eq!(open(&path).tip(), Some(Serial::new(4)));
}

// --- a crash in the middle of a write ---

/// The file is cut at every byte of its last record, as a crash in the write leaves it: the changesets before are
/// kept, the stub is cut off the file, and the journal takes the changeset again.
#[test]
fn a_file_cut_in_the_last_record_keeps_the_ones_before() {
    let changesets = chain();
    let (bytes, starts) = file_of(&changesets);
    let last = *starts.last().expect("records");
    for cut in last..bytes.len() {
        let (_dir, path) = directory();
        fs::write(&path, &bytes[..cut]).expect("writes");
        let mut journal = open(&path);
        assert_eq!(journal.len(), 3, "cut at {cut}");
        assert_eq!(journal.discarded(), cut - last, "cut at {cut}");
        assert_eq!(
            fs::read(&path).expect("the file").len(),
            last,
            "the stub of a torn record is cut off the file, cut at {cut}"
        );
        journal.append(&changesets[3]).expect("appends again");
        let again = open(&path);
        assert_eq!(again.len(), 4, "cut at {cut}");
        assert_eq!(fs::read(&path).expect("the file"), bytes);
    }
}

/// A crash while the file was made: shorter than the header, or at least its start.
#[test]
fn a_file_cut_in_the_header_is_made_again() {
    let (bytes, _) = file_of(&chain()[..1]);
    for cut in 0..MAGIC.len() {
        let (_dir, path) = directory();
        fs::write(&path, &bytes[..cut]).expect("writes");
        let journal = open(&path);
        assert!(journal.is_empty(), "cut at {cut}");
        assert_eq!(journal.discarded(), cut);
        assert_eq!(fs::read(&path).expect("the file"), MAGIC, "cut at {cut}");
    }
}

/// Each byte of the last record flipped, as a bad sector does: the record is refused (CRC-32 finds any burst of
/// up to 32 bits, a flipped length is a length the CRC covers), the ones before are kept.
#[test]
fn a_flipped_byte_in_the_last_record_refuses_it_and_keeps_the_ones_before() {
    let changesets = chain();
    let (bytes, starts) = file_of(&changesets);
    let last = *starts.last().expect("records");
    for at in last..bytes.len() {
        let mut flipped = bytes.clone();
        flipped[at] ^= 0xFF;
        let scan = format::scan(&flipped).expect("a journal");
        assert_eq!(scan.changesets.len(), 3, "byte {at}");
        assert_eq!(scan.valid, last, "byte {at}");
        assert!(
            matches!(scan.tail, Tail::BadCrc | Tail::Torn),
            "byte {at}: {:?}",
            scan.tail
        );

        let (_dir, path) = directory();
        fs::write(&path, &flipped).expect("writes");
        let journal = open(&path);
        assert_eq!(journal.len(), 3, "byte {at}");
        assert_eq!(journal.discarded(), bytes.len() - last, "byte {at}");
        assert_eq!(fs::read(&path).expect("the file").len(), last, "byte {at}");
    }
}

/// A flip in a record with others after it ends the journal there: what follows a record that cannot be trusted
/// cannot be told from noise, and a changeset after a hole is no use (RFC 1995 §4).
#[test]
fn a_flipped_byte_in_the_middle_ends_the_journal_there() {
    let changesets = chain();
    let (bytes, starts) = file_of(&changesets);
    for (n, &start) in starts.iter().enumerate() {
        let end = starts.get(n + 1).copied().unwrap_or(bytes.len());
        for at in start..end {
            let mut flipped = bytes.clone();
            flipped[at] ^= 0x01;
            let scan = format::scan(&flipped).expect("a journal");
            assert_eq!(scan.changesets.len(), n, "byte {at} of record {n}");
            assert_eq!(scan.valid, start);
        }
    }
}

#[test]
fn a_header_with_other_bytes_is_no_journal_and_the_file_is_left() {
    let (_dir, path) = directory();
    let other = b"not a journal at all, but somebody's file";
    fs::write(&path, other).expect("writes");
    let error = Journal::open(&path, JournalLimits::default()).expect_err("refused");
    assert!(matches!(error, JournalError::NotAJournal), "{error:?}");
    assert_eq!(fs::read(&path).expect("the file"), other);
}

#[test]
fn a_file_over_the_bound_is_not_read_and_is_left() {
    let (_dir, path) = directory();
    let file = fs::File::create(&path).expect("creates");
    file.set_len(MAX_FILE + 1).expect("a sparse file");
    drop(file);
    let error = Journal::open(&path, JournalLimits::default()).expect_err("refused");
    assert!(
        matches!(error, JournalError::TooLarge { size } if size == MAX_FILE + 1),
        "{error:?}"
    );
    assert_eq!(fs::metadata(&path).expect("the file").len(), MAX_FILE + 1);
}

/// The rewrite goes through a file beside the journal and a rename: a crash before the rename leaves the old file
/// whole and a leftover that the next rewrite replaces.
#[test]
fn a_leftover_of_a_crashed_rewrite_is_ignored_and_replaced() {
    let (_dir, path) = directory();
    let changesets = chain();
    let (bytes, _) = file_of(&changesets[..2]);
    fs::write(&path, &bytes).expect("writes");
    let mut leftover = path.as_os_str().to_owned();
    leftover.push(".tmp");
    fs::write(&leftover, b"half a rewrite").expect("writes");

    let mut journal = Journal::open(
        &path,
        JournalLimits {
            changesets: 2,
            ..JournalLimits::default()
        },
    )
    .expect("opens");
    assert_eq!(journal.len(), 2);
    assert_eq!(
        journal.append(&changesets[2]).expect("appends"),
        Stored::Kept { dropped: 1 }
    );
    assert_eq!(
        fs::read(&path).expect("the file"),
        file_of(&changesets[1..3]).0
    );
    assert!(
        !fs::exists(&leftover).expect("checks"),
        "renamed over the journal"
    );
}

/// A write that fails leaves the file in a state the journal cannot know: it refuses until it is opened again.
#[cfg(unix)]
#[test]
fn a_failed_write_poisons_the_journal_until_it_is_opened_again() {
    let (dir, path) = directory();
    let changesets = chain();
    let mut journal = Journal::open(
        &path,
        JournalLimits {
            changesets: 1,
            ..JournalLimits::default()
        },
    )
    .expect("opens");
    journal.append(&changesets[0]).expect("appends");
    // The directory is gone, so the file for a rewrite cannot be made: the second changeset needs one.
    fs::remove_dir_all(dir.path()).expect("removes");
    let error = journal.append(&changesets[1]).expect_err("fails");
    assert!(matches!(error, JournalError::Io(_)), "{error:?}");
    assert_eq!(journal.len(), 1, "the failed changeset is not in");
    let error = journal.append(&changesets[1]).expect_err("refuses");
    assert!(matches!(error, JournalError::Poisoned), "{error:?}");
    drop(dir);
}

// --- limits ---

#[test]
fn past_the_count_the_oldest_changeset_is_dropped() {
    let (_dir, path) = directory();
    let changesets = chain();
    let limits = JournalLimits {
        changesets: 2,
        ..JournalLimits::default()
    };
    let mut journal = Journal::open(&path, limits).expect("opens");
    let mut stored = Vec::new();
    for changeset in &changesets {
        stored.push(journal.append(changeset).expect("appends"));
    }
    assert_eq!(
        stored,
        [
            Stored::Kept { dropped: 0 },
            Stored::Kept { dropped: 0 },
            Stored::Kept { dropped: 1 },
            Stored::Kept { dropped: 1 },
        ]
    );
    assert_eq!(serials(&journal, 3), Some(vec![(3, 4), (4, 5)]));
    assert_eq!(
        serials(&journal, 2),
        None,
        "gone: the caller sends the zone"
    );
    assert_eq!(
        fs::read(&path).expect("the file"),
        file_of(&changesets[2..]).0
    );
}

#[test]
fn past_the_bytes_the_oldest_changesets_are_dropped_until_the_new_one_fits() {
    let (_dir, path) = directory();
    let changesets = chain();
    let (bytes, starts) = file_of(&changesets);
    // Room for the header and the last two records, not for a third.
    let limits = JournalLimits {
        bytes: bytes.len() - starts[2] + MAGIC.len(),
        ..JournalLimits::default()
    };
    let mut journal = Journal::open(&path, limits).expect("opens");
    let mut dropped = Vec::new();
    for changeset in &changesets {
        let Stored::Kept { dropped: n } = journal.append(changeset).expect("appends") else {
            panic!("fits alone");
        };
        dropped.push(n);
        assert!(journal.bytes() <= limits.bytes);
    }
    assert!(dropped.iter().sum::<usize>() >= 2);
    assert_eq!(journal.tip(), Some(Serial::new(5)));
    assert_eq!(serials(&journal, 3), Some(vec![(3, 4), (4, 5)]));
    assert_eq!(
        fs::read(&path).expect("the file"),
        file_of(&changesets[2..]).0
    );
}

/// NSD does not keep an IXFR that is over the size alone (`zone_ixfr_make_space`): the journal is emptied, as its
/// older changesets would lead to a version that is not kept.
#[test]
fn a_changeset_over_a_limit_alone_empties_the_journal() {
    let changesets = chain();
    for limits in [
        JournalLimits {
            bytes: MAGIC.len() + FRAME,
            ..JournalLimits::default()
        },
        JournalLimits {
            changesets: 0,
            ..JournalLimits::default()
        },
    ] {
        let (_dir, path) = directory();
        let mut journal = Journal::open(&path, limits).expect("opens");
        assert_eq!(
            journal.append(&changesets[0]).expect("appends"),
            Stored::TooBig
        );
        assert!(journal.is_empty());
        assert_eq!(fs::read(&path).expect("the file"), MAGIC);
    }
}

#[test]
fn a_file_over_the_limits_is_cut_down_when_it_is_opened() {
    let (_dir, path) = directory();
    let changesets = chain();
    fs::write(&path, file_of(&changesets).0).expect("writes");
    let journal = Journal::open(
        &path,
        JournalLimits {
            changesets: 3,
            ..JournalLimits::default()
        },
    )
    .expect("opens");
    assert_eq!(serials(&journal, 2), Some(vec![(2, 3), (3, 4), (4, 5)]));
    assert_eq!(
        fs::read(&path).expect("the file"),
        file_of(&changesets[1..]).0
    );
}

#[test]
fn several_of_the_oldest_go_when_the_limit_on_opening_is_far_below_the_file() {
    let (_dir, path) = directory();
    let changesets = chain();
    fs::write(&path, file_of(&changesets).0).expect("writes");
    let journal = Journal::open(
        &path,
        JournalLimits {
            changesets: 2,
            ..JournalLimits::default()
        },
    )
    .expect("opens");
    assert_eq!(serials(&journal, 3), Some(vec![(3, 4), (4, 5)]));
    assert_eq!(journal.len(), 2);
}

#[test]
fn several_of_the_oldest_go_when_the_bytes_on_opening_are_far_below_the_file() {
    let (_dir, path) = directory();
    let changesets = chain();
    let (bytes, starts) = file_of(&changesets);
    fs::write(&path, &bytes).expect("writes");
    let journal = Journal::open(
        &path,
        JournalLimits {
            bytes: bytes.len() - starts[2] + MAGIC.len(),
            ..JournalLimits::default()
        },
    )
    .expect("opens");
    assert_eq!(serials(&journal, 3), Some(vec![(3, 4), (4, 5)]));
    assert_eq!(journal.len(), 2);
}

/// A changeset that fills the bytes to the last one is kept; one byte less room and it is over.
#[test]
fn a_changeset_that_fits_the_bytes_exactly_is_kept() {
    let changesets = chain();
    let (_, starts) = file_of(&changesets);
    let first = starts[1];
    for (room, kept) in [(first, true), (first - 1, false)] {
        let (_dir, path) = directory();
        let limits = JournalLimits {
            bytes: room,
            ..JournalLimits::default()
        };
        let mut journal = Journal::open(&path, limits).expect("opens");
        let stored = journal.append(&changesets[0]).expect("appends");
        assert_eq!(stored == (Stored::Kept { dropped: 0 }), kept, "{room}");
        assert_eq!(journal.is_empty(), !kept);
    }
}

/// A journal within its limits is opened without rewriting it: the leftover of a rewrite stays.
#[test]
fn a_journal_within_its_limits_is_not_rewritten_when_it_is_opened() {
    let (_dir, path) = directory();
    let changesets = chain();
    fs::write(&path, file_of(&changesets).0).expect("writes");
    let leftover = path.with_extension("journal.tmp");
    fs::write(&leftover, b"left by a crash").expect("writes");
    let journal = open(&path);
    assert_eq!(journal.len(), changesets.len());
    assert_eq!(
        fs::read(&leftover).expect("still there"),
        b"left by a crash"
    );
}

/// Only a missing file is a new journal: another error is the caller'"'"'s to see.
#[test]
fn a_path_that_cannot_be_read_is_an_error_and_a_missing_one_is_a_new_journal() {
    let (dir, path) = directory();
    fs::create_dir(&path).expect("a directory where the file should be");
    assert!(matches!(
        Journal::open(&path, JournalLimits::default()),
        Err(JournalError::Io(_))
    ));
    assert!(path.is_dir());
    let missing = dir.path().join("none").join("example.journal");
    assert!(matches!(
        Journal::open(&missing, JournalLimits::default()),
        Err(JournalError::Io(_))
    ));
}

/// A file that cannot be read is not a new journal to write over: the error is the caller'"'"'s and the file stays.
#[cfg(unix)]
#[test]
fn a_file_that_is_not_readable_is_an_error_and_is_left() {
    use std::os::unix::fs::PermissionsExt;

    let (_dir, path) = directory();
    let content = file_of(&chain()).0;
    fs::write(&path, &content).expect("writes");
    fs::set_permissions(&path, fs::Permissions::from_mode(0o000)).expect("chmod");
    if fs::read(&path).is_ok() {
        return; // root reads it anyway: nothing to show
    }
    assert!(matches!(
        Journal::open(&path, JournalLimits::default()),
        Err(JournalError::Io(e)) if e.kind() == std::io::ErrorKind::PermissionDenied
    ));
    fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).expect("chmod");
    assert_eq!(fs::read(&path).expect("the file"), content);
}

/// The bound is on the size: a file of exactly [`MAX_FILE`] bytes is read (and is no journal), one longer says
/// how long it is.
#[test]
fn a_file_of_the_bound_is_read_and_a_longer_one_says_its_size() {
    let (_dir, path) = directory();
    let file = fs::File::create(&path).expect("creates");
    file.set_len(MAX_FILE).expect("a sparse file");
    drop(file);
    assert!(matches!(
        Journal::open(&path, JournalLimits::default()),
        Err(JournalError::NotAJournal)
    ));
    let file = fs::OpenOptions::new()
        .write(true)
        .open(&path)
        .expect("opens");
    file.set_len(MAX_FILE + 10).expect("a sparse file");
    drop(file);
    let error = Journal::open(&path, JournalLimits::default()).expect_err("refused");
    assert!(
        matches!(error, JournalError::TooLarge { size } if size == MAX_FILE + 10),
        "{error:?}"
    );
}

#[test]
fn a_journal_with_a_changeset_is_not_empty() {
    let (_dir, path) = directory();
    let mut journal = open(&path);
    assert!(journal.is_empty());
    journal.append(&chain()[0]).expect("appends");
    assert!(!journal.is_empty());
}

// --- reading bytes ---

#[test]
fn nothing_is_a_clean_journal_and_a_cut_header_a_torn_one() {
    let empty = format::scan(&[]).expect("scans");
    assert_eq!((empty.valid, empty.tail), (0, Tail::Clean));
    let cut = format::scan(&MAGIC[..3]).expect("scans");
    assert_eq!((cut.valid, cut.tail), (0, Tail::Torn));
    let header = format::scan(&MAGIC).expect("scans");
    assert_eq!((header.valid, header.tail), (MAGIC.len(), Tail::Clean));
}

#[test]
fn a_record_that_does_not_follow_the_one_before_ends_the_file() {
    let changesets = chain();
    // 1→2, then 3→4: a hole.
    let (bytes, starts) = file_of(&[changesets[0].clone(), changesets[2].clone()]);
    let scan = format::scan(&bytes).expect("a journal");
    assert_eq!(scan.changesets.len(), 1);
    assert_eq!(scan.valid, starts[1]);
    assert_eq!(scan.tail, Tail::NotConsecutive);
}

/// A record with a good CRC whose payload is no changeset: cut short by one byte, so a record's RDATA is.
#[test]
fn a_payload_that_is_no_changeset_ends_the_file() {
    let changesets = chain();
    let (bytes, starts) = file_of(&changesets[..2]);
    let payload = &bytes[starts[1] + FRAME..];
    let mut forged = bytes[..starts[1]].to_vec();
    format::frame(&payload[..payload.len() - 1], &mut forged).expect("frames");
    let scan = format::scan(&forged).expect("a journal");
    assert_eq!((scan.changesets.len(), scan.tail), (1, Tail::Undecodable));
    assert_eq!(scan.valid, starts[1]);

    let mut empty = bytes[..starts[1]].to_vec();
    format::frame(&[], &mut empty).expect("frames");
    assert_eq!(
        format::scan(&empty).expect("a journal").tail,
        Tail::Undecodable
    );
}

#[test]
fn a_length_past_the_end_of_the_file_is_a_torn_record() {
    let (bytes, starts) = file_of(&chain()[..2]);
    let mut huge = bytes[..starts[1]].to_vec();
    huge.extend_from_slice(&[0xFF; FRAME]);
    let scan = format::scan(&huge).expect("a journal");
    assert_eq!((scan.changesets.len(), scan.tail), (1, Tail::Torn));
}

#[test]
fn what_the_scan_reads_is_what_the_encoding_wrote() {
    let changesets = chain();
    let (bytes, starts) = file_of(&changesets);
    let scan = format::scan(&bytes).expect("a journal");
    assert_eq!(scan.changesets, changesets);
    assert_eq!(scan.valid, bytes.len());
    assert_eq!(scan.tail, Tail::Clean);
    let ends = starts.iter().skip(1).copied().chain([bytes.len()]);
    let sizes: Vec<_> = starts.iter().zip(ends).map(|(s, e)| e - s).collect();
    assert_eq!(scan.sizes, sizes);
}
