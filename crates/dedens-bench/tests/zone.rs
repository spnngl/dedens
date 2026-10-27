//! The zone readers compared in `benches/zone.rs` read the same zone.

use dedens_bench::zone;
use dedens_proto::text::{Entry, ZoneReader};
use domain::zonefile::inplace::Zonefile;
use hickory_proto::serialize::txt::Parser;

/// The three readers agree on the number of records.
#[test]
fn readers_count_the_same_records() {
    let text = zone(1_000);
    let dedens = ZoneReader::new(text.as_bytes(), None)
        .map(|e| e.expect("reads"))
        .filter(|e| matches!(e, Entry::Record(_)))
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
