//! The zone readers compared in `benches/zone.rs` read the same zone.

use dedens_bench::zone;
use dedens_proto::{Name, ZoneEntry, ZoneReader};
use dedens_zone::{Limits, Source, WarningKind, Zone};
use domain::zonefile::inplace::Zonefile;
use hickory_proto::serialize::txt::Parser;

/// The three readers agree on the number of records.
#[test]
fn readers_count_the_same_records() {
    let text = zone(1_000);
    let dedens = ZoneReader::new(text.as_bytes(), None)
        .map(|e| e.expect("reads"))
        .filter(|e| matches!(e, ZoneEntry::Record(_)))
        .count();
    let mut zonefile = Zonefile::with_capacity(text.len());
    zonefile.extend_from_slice(text.as_bytes());
    let domain = zonefile
        .collect::<Result<Vec<_>, _>>()
        .expect("reads")
        .len();
    let (_, sets) = Parser::new(text.as_str(), None, None)
        .parse()
        .expect("parses");
    let hickory: usize = sets
        .values()
        .map(|set| set.records_without_rrsigs().count())
        .sum();
    assert_eq!((dedens, domain), (hickory, hickory));
    assert!(dedens > 2_500, "about three records per host: {dedens}");
}

/// The loader of `benches/zone.rs` accepts the generated zone and keeps every record the reader yields.
#[test]
fn the_loader_keeps_the_records_the_reader_yields() {
    let text = zone(1_000);
    let read = ZoneReader::new(text.as_bytes(), None)
        .map(|e| e.expect("reads"))
        .filter(|e| matches!(e, ZoneEntry::Record(_)))
        .count();
    let origin = Name::from_labels([b"example".as_slice()]).expect("a name");
    let source = Source {
        name: "zone",
        text: text.as_bytes(),
        default_ttl: None,
    };
    let loaded = Zone::load(origin, source, &mut |_| Err(String::new()), &Limits::default())
        .expect("loads");
    assert_eq!(loaded.zone.record_count(), read);
    // Each owner-less record after a record with its own TTL is an `RRset` of two TTLs: a warning, not an error.
    assert!(loaded.report.warnings.iter().all(|w| matches!(w.kind, WarningKind::DifferentTtls { .. })));
}
