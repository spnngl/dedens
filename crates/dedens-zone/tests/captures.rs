//! Differences and the journal on the root zone as captured (RFC 1995 §4, §6, D203, D207).
//!
//! `testdata/authoritative/` holds the root zone at two serials, `root-previous.zone` (2026111401) and `root.zone`
//! (2026112201), and the IXFR Knot DNS 3.6.2 sent between them, loaded from the first and then the second as a
//! difference (`recordings/root-ixfr.yaml`). A server's own zone files are the answer to "what does the other
//! side do": the second serial must come out of the first by Knot's changeset, applied here, and by the
//! difference of the two zones, found here.

use std::fs;
use std::sync::LazyLock;

use dedens_proto::rdata::{Opaque, RData};
use dedens_proto::{Class, Message, Record, RecordType, Serial, Ttl};
use dedens_testkit::authoritative::{Peer, Recording};
use dedens_testkit::dns;
use dedens_zone::journal::{Journal, JournalLimits, Stored};
use dedens_zone::{Changeset, ErrorKind, Limits, Place, Source, WarningKind, Zone};

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

/// A record of a type no zone holds, as a transfer can carry it.
fn meta(rtype: RecordType, class: Class) -> Record<'static> {
    let data = Opaque::new(rtype, &[]).expect("a type without RDATA");
    Record::new(dns("."), class, Ttl::from_wire(0), &RData::Opaque(data))
}

fn at(line: usize) -> Place {
    Place {
        file: 0,
        line,
        column: 1,
    }
}

/// A record refused by [`Zone::from_records`] is placed at its number, from 1; past the errors' limit, the load
/// stops (D210).
#[test]
fn from_records_places_an_error_at_the_record_number() {
    let mut records = vec![
        meta(RecordType::TKEY, Class::IN),
        meta(RecordType::ANY, Class::IN),
        meta(RecordType(254), Class::IN),
    ];
    records.extend(dedens_testkit::authoritative::zone("root.zone"));
    let limits = Limits {
        errors: 2,
        ..Limits::default()
    };
    let report = Zone::from_records(dns("."), records, &limits).expect_err("meta types");
    let places: Vec<_> = report.errors.iter().map(|error| error.at).collect();
    assert_eq!(places, [Some(at(1)), Some(at(2)), None]);
    assert_eq!(report.files, ["transfer"]);
}

/// RFC 6895 §3.1, §3.2: a record of a transfer whose type or class is no data (OPT, TSIG, TKEY, a QTYPE, a QCLASS)
/// refuses the zone, as in a zone file; a changeset's too (D210).
#[test]
fn rfc6895_a_meta_type_or_class_is_refused_in_a_transfer_and_a_changeset() {
    let root = dedens_testkit::authoritative::zone("root.zone");
    for (rtype, class) in [
        (RecordType::OPT, Class::IN),
        (RecordType::TSIG, Class::ANY),
        (RecordType::TKEY, Class::IN),
        (RecordType::IXFR, Class::IN),
        (RecordType::AXFR, Class::IN),
        (RecordType(253), Class::IN),
        (RecordType::TXT, Class::NONE),
        (RecordType::TXT, Class::ANY),
    ] {
        let mut records = root.clone();
        records.push(meta(rtype, class));
        let number = records.len();
        let report =
            Zone::from_records(dns("."), records, &Limits::default()).expect_err("a meta record");
        let found: Vec<_> = report
            .errors
            .iter()
            .map(|error| (error.at, error.kind.clone()))
            .collect();
        assert_eq!(
            found,
            [(Some(at(number)), ErrorKind::NotData { rtype, class })],
            "{rtype} {class}"
        );

        let changeset = Changeset::new(
            root.iter()
                .find(|r| r.rtype() == RecordType::SOA)
                .expect("an SOA")
                .clone(),
            next_soa(&root),
            Vec::new(),
            vec![meta(rtype, class)],
        )
        .expect("a changeset");
        let report = root_zone()
            .apply(&changeset, &Limits::default())
            .expect_err("a meta record");
        assert_eq!(
            report.errors.iter().map(|e| &e.kind).collect::<Vec<_>>(),
            [&ErrorKind::NotData { rtype, class }],
            "{rtype} {class}"
        );
    }
}

/// A record of a transfer outside the zone is dropped with a warning, as Knot does, and the zone is the rest;
/// beyond [`Limits::errors`] the drops are counted in one last warning (D210).
/// `a_zone_file_and_an_ixfr_changeset_still_refuse_a_record_outside_the_zone` is the other side.
#[test]
fn from_records_drops_a_record_outside_the_zone_with_a_warning() {
    let apex = dns("zonetransfer.me.");
    let own = dedens_testkit::authoritative::zone("zonetransfer.me.zone");
    let kept = Zone::from_records(apex.clone(), own.clone(), &Limits::default())
        .map_err(|report| report.to_string())
        .expect("the zone");
    assert_eq!(kept.report.warnings, []);

    let mut records = own.clone();
    for name in ["a.example.", "b.example.", "c.example."] {
        let mut stranger = own.last().expect("a record").clone();
        stranger.name = dns(name);
        records.push(stranger);
    }
    let loaded = Zone::from_records(apex.clone(), records.clone(), &Limits::default())
        .map_err(|report| report.to_string())
        .expect("the strangers are dropped");
    assert_eq!(loaded.zone, kept.zone);
    let warned: Vec<_> = loaded
        .report
        .warnings
        .iter()
        .map(|w| (w.at, w.kind.clone()))
        .collect();
    let warning = |line, name| {
        let place = at(line);
        (place, WarningKind::OutsideZone { owner: dns(name) })
    };
    let n = own.len();
    assert_eq!(
        warned,
        [
            warning(n + 1, "a.example."),
            warning(n + 2, "b.example."),
            warning(n + 3, "c.example."),
        ]
    );

    let limits = Limits {
        errors: 2,
        ..Limits::default()
    };
    let loaded = Zone::from_records(apex, records, &limits)
        .map_err(|report| report.to_string())
        .expect("the strangers are dropped");
    assert_eq!(loaded.zone, kept.zone);
    let warned: Vec<_> = loaded
        .report
        .warnings
        .iter()
        .map(|w| (w.at, w.kind.clone()))
        .collect();
    assert_eq!(
        warned,
        [
            warning(n + 1, "a.example."),
            warning(n + 2, "b.example."),
            // The first one past the limit is the place, the count of those past it.
            (at(n + 3), WarningKind::OutsideZoneMore { count: 1 }),
        ]
    );
}

/// A zone file, and an IXFR changeset applied to a zone, refuse a record outside the zone: only a full transfer
/// drops it (D210), so step 13 keeps the asymmetry on purpose.
#[test]
fn a_zone_file_and_an_ixfr_changeset_still_refuse_a_record_outside_the_zone() {
    let owner = dns("stranger.example.");
    let outside = |report: &dedens_zone::Report| {
        report
            .errors
            .iter()
            .map(|error| error.kind.clone())
            .collect::<Vec<_>>()
    };
    let expected = [ErrorKind::OutsideZone {
        owner: owner.clone(),
    }];

    let mut text =
        fs::read(dedens_testkit::path("authoritative/zones").join("zonetransfer.me.zone"))
            .expect("a zone file");
    text.extend_from_slice(b"\nstranger.example. 300 IN A 192.0.2.1\n");
    let source = Source {
        name: "zonetransfer.me.zone",
        text: &text,
        default_ttl: None,
    };
    let mut include = |_: &str| Err("no $INCLUDE".to_owned());
    let report = Zone::load(
        dns("zonetransfer.me."),
        source,
        &mut include,
        &Limits::default(),
    )
    .expect_err("a record outside the zone");
    assert_eq!(outside(&report), expected);

    let own = dedens_testkit::authoritative::zone("zonetransfer.me.zone");
    let zone = Zone::from_records(dns("zonetransfer.me."), own.clone(), &Limits::default())
        .map_err(|report| report.to_string())
        .expect("the zone")
        .zone;
    let mut stranger = own.last().expect("a record").clone();
    stranger.name = owner;
    let changeset = Changeset::new(
        own.iter()
            .find(|r| r.rtype() == RecordType::SOA)
            .expect("an SOA")
            .clone(),
        next_soa(&own),
        Vec::new(),
        vec![stranger],
    )
    .expect("a changeset");
    let report = zone
        .apply(&changeset, &Limits::default())
        .expect_err("a record outside the zone");
    assert_eq!(outside(&report), expected);
}

/// A changeset's SOA of the zone, one serial ahead.
fn next_soa(records: &[Record<'static>]) -> Record<'static> {
    let soa = records
        .iter()
        .find(|r| r.rtype() == RecordType::SOA)
        .expect("an SOA");
    let RData::Soa(data) = soa.data() else {
        unreachable!("an SOA")
    };
    let mut data = data.clone();
    data.serial = data.serial.wrapping_add(1);
    Record::new(soa.name.clone(), soa.class, soa.ttl, &RData::Soa(data))
}

fn root_zone() -> Zone {
    root("root.zone")
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
