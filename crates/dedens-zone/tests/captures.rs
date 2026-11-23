//! Differences and the journal on the root zone as captured (RFC 1995 §4, §6, D203, D207).
//!
//! `testdata/authoritative/` holds the root zone at two serials, `root-previous.zone` (2026111401) and `root.zone`
//! (2026112201), and the IXFR Knot DNS 3.6.2 sent between them, loaded from the first and then the second as a
//! difference (`recordings/root-ixfr.yaml`). A server's own zone files are the answer to "what does the other
//! side do": the second serial must come out of the first by Knot's changeset, applied here, and by the
//! difference of the two zones, found here.

use std::fs;
use std::sync::LazyLock;

use dedens_proto::{Message, Record, RecordType, Serial};
use dedens_testkit::authoritative::{Peer, Recording};
use dedens_testkit::dns;
use dedens_zone::journal::{Journal, JournalLimits, Stored};
use dedens_zone::{Changeset, Limits, Place, Source, Zone};

/// A root zone file of `testdata/authoritative/zones/`, loaded once for all the tests (a debug build takes seconds).
fn root(file: &str) -> Zone {
    static PREVIOUS: LazyLock<Zone> = LazyLock::new(|| load("root-previous.zone"));
    static CURRENT: LazyLock<Zone> = LazyLock::new(|| load("root.zone"));
    match file {
        "root-previous.zone" => PREVIOUS.clone(),
        _ => CURRENT.clone(),
    }
}

fn load(file: &str) -> Zone {
    let text =
        fs::read(dedens_testkit::path("authoritative/zones").join(file)).expect("a zone file");
    let source = Source {
        name: file,
        text: &text,
        default_ttl: None,
    };
    let mut include = |_: &str| Err("the root zone has no $INCLUDE".to_owned());
    Zone::load(dns("."), source, &mut include, &Limits::default())
        .map_err(|report| report.to_string())
        .expect(file)
        .zone
}

/// The changesets of the IXFR of `recordings/root-ixfr.yaml` (RFC 1995 §4): the answer records of the server's
/// messages are the new SOA, then for each difference the old SOA with the records deleted and the new SOA with
/// those added, then the new SOA again.
fn ixfr() -> Vec<Changeset> {
    let recording = Recording::read("root-ixfr");
    let answers: Vec<Record<'static>> = recording
        .messages
        .iter()
        .filter(|packet| packet.from == Peer::Server)
        .flat_map(|packet| {
            Message::decode(&packet.message)
                .expect("a message")
                .message
                .into_owned()
                .answer
        })
        .collect();
    let (closing, rest) = answers.split_last().expect("records");
    let (opening, differences) = rest.split_first().expect("records");
    assert_eq!(
        opening, closing,
        "the sequence ends as it began (RFC 1995 §4)"
    );
    let mut parts: Vec<Vec<Record<'static>>> = Vec::new();
    for record in differences {
        if record.rtype() == RecordType::SOA {
            parts.push(Vec::new());
        }
        parts.last_mut().expect("an SOA first").push(record.clone());
    }
    assert_eq!(parts.len() % 2, 0, "a difference is two parts");
    parts
        .chunks(2)
        .map(|pair| {
            let [deleted, added] = pair else {
                unreachable!("chunks of two")
            };
            let (from, deleted) = deleted.split_first().expect("an SOA");
            let (to, added) = added.split_first().expect("an SOA");
            Changeset::new(from.clone(), to.clone(), deleted.to_vec(), added.to_vec())
                .expect("a changeset")
        })
        .collect()
}

/// The root zone's records in the order Knot transferred them make the zone its file loads (D210).
#[test]
fn from_records_of_the_root_is_its_zone() {
    let records = dedens_testkit::authoritative::zone("root.zone");
    let loaded = Zone::from_records(dns("."), records, &Limits::default())
        .map_err(|report| report.to_string())
        .expect("the root zone");
    assert_eq!(loaded.zone, root("root.zone"));
    assert_eq!(loaded.report.warnings, []);
}

/// A record refused by [`Zone::from_records`] is placed at its number, from 1; past the errors' limit, the load
/// stops (D210).
#[test]
fn from_records_places_an_error_at_the_record_number() {
    let records = dedens_testkit::authoritative::zone("root.zone");
    let limits = Limits {
        errors: 2,
        ..Limits::default()
    };
    let report = Zone::from_records(dns("zonetransfer.me."), records, &limits)
        .expect_err("the root's records are outside zonetransfer.me.");
    let places: Vec<_> = report.errors.iter().map(|error| error.at).collect();
    let at = |line| {
        Some(Place {
            file: 0,
            line,
            column: 1,
        })
    };
    assert_eq!(places, [at(1), at(2), None]);
    assert_eq!(report.files, ["transfer"]);
}

/// A changeset's records as sorted lines, to compare as sets.
fn lines(changeset: &Changeset) -> (Vec<String>, Vec<String>) {
    let sorted = |records: &[Record<'static>]| {
        let mut lines: Vec<_> = records.iter().map(ToString::to_string).collect();
        lines.sort();
        lines
    };
    (sorted(changeset.removed()), sorted(changeset.added()))
}

/// Knot's changeset taken to the previous root zone makes the current one: every check of a load holds on the
/// result, and the result is the zone the second file loads.
#[test]
fn s4_the_ixfr_of_knot_takes_the_previous_root_zone_to_the_current_one() {
    let previous = root("root-previous.zone");
    let current = root("root.zone");
    let changesets = ixfr();
    assert_eq!(
        changesets.first().map(Changeset::from_serial),
        Some(Serial::new(2_026_111_401))
    );
    assert_eq!(
        changesets.last().map(Changeset::to_serial),
        Some(Serial::new(2_026_112_201))
    );
    let mut zone = previous;
    for changeset in &changesets {
        zone = zone
            .apply(changeset, &Limits::default())
            .map_err(|report| report.to_string())
            .expect("applies")
            .zone;
    }
    assert_eq!(zone, current);
}

/// The difference of the two zones, found here, is Knot's: the same records removed and added.
#[test]
fn s4_the_difference_of_the_two_root_zones_is_the_one_knot_sent() {
    let previous = root("root-previous.zone");
    let current = root("root.zone");
    let diff = Zone::diff(&previous, &current).expect("the current serial is ahead");
    let sent = ixfr()
        .into_iter()
        .reduce(|a, b| a.condense(b).expect("consecutive"))
        .expect("a changeset");
    assert_eq!(lines(&diff), lines(&sent));
    assert_eq!(
        previous
            .apply(&diff, &Limits::default())
            .expect("applies")
            .zone,
        current
    );
}

/// RFC 1982 §3.2: the older serial is no changeset's end. The difference of the zones the wrong way round is
/// refused.
#[test]
fn rfc1982_s3_2_the_difference_back_to_the_previous_zone_is_refused() {
    let previous = root("root-previous.zone");
    let current = root("root.zone");
    Zone::diff(&current, &previous).expect_err("the previous serial is behind");
}

/// A journal of the changeset Knot sent: reopened, it takes a secondary at the previous serial to the current zone,
/// and says it has nothing for one at the current serial or an older one.
#[test]
fn the_journal_of_the_root_zone_serves_what_it_was_given_after_a_restart() {
    let previous = root("root-previous.zone");
    let current = root("root.zone");
    let dir = tempfile::tempdir().expect("a directory");
    let path = dir.path().join("root.journal");
    let mut journal = Journal::open(&path, JournalLimits::default()).expect("opens");
    for changeset in ixfr() {
        assert_eq!(
            journal.append(&changeset).expect("appends"),
            Stored::Kept { dropped: 0 }
        );
    }
    drop(journal);

    let journal = Journal::open(&path, JournalLimits::default()).expect("opens again");
    assert_eq!(journal.discarded(), 0);
    let mut zone = previous;
    for changeset in journal
        .changes_since(Serial::new(2_026_111_401))
        .expect("the serial is in the journal")
    {
        zone = zone
            .apply(changeset, &Limits::default())
            .expect("applies")
            .zone;
    }
    assert_eq!(zone, current);
    assert_eq!(
        journal
            .changes_since(Serial::new(2_026_112_201))
            .expect("the last version")
            .count(),
        0
    );
    assert!(journal.changes_since(Serial::new(2_026_111_301)).is_none());
}
