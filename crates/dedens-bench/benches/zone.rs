//! Zone file reading and loading: a generated zone of about 100 000 records, read against `domain` and hickory-proto,
//! and loaded into a checked `dedens_zone::Zone`.
//!
//! dedens and `domain` yield one typed record at a time. hickory-proto has no such reader: its `Parser` also
//! files every record into a map of record sets, so it does more work than the other two.

use std::hint::black_box;

use dedens_bench::{ZONE_HOSTS, zone};
use dedens_proto::{Name, ZoneEntry, ZoneReader};
use dedens_zone::{Limits, Source, Zone};
use divan::Bencher;
use domain::zonefile::inplace::Zonefile;
use hickory_proto::serialize::txt::Parser;

#[global_allocator]
static ALLOC: divan::AllocProfiler = divan::AllocProfiler::system();

fn main() {
    divan::main();
}

#[divan::bench]
fn read_dedens(bencher: Bencher<'_, '_>) {
    let text = zone(ZONE_HOSTS);
    bencher.bench_local(|| {
        let mut records = 0_usize;
        for entry in ZoneReader::new(black_box(text.as_bytes()), None) {
            if let ZoneEntry::Record(record) = entry.expect("reads") {
                black_box(record);
                records += 1;
            }
        }
        records
    });
}

/// The reader of `read_dedens` and the checks of D204: every record filed into its name and `RRset`, the nodes in
/// canonical order, the cuts marked. `AllocProfiler`'s `max alloc` is the peak memory of the load.
#[divan::bench]
fn load_dedens(bencher: Bencher<'_, '_>) {
    let text = zone(ZONE_HOSTS);
    let origin = Name::from_labels([b"example".as_slice()]).expect("a name");
    let limits = Limits::default();
    bencher.bench_local(|| {
        let source = Source {
            name: "zone",
            text: black_box(text.as_bytes()),
            default_ttl: None,
        };
        Zone::load(origin.clone(), source, &mut |_| Err(String::new()), &limits).expect("loads")
    });
}

#[divan::bench]
fn read_domain(bencher: Bencher<'_, '_>) {
    let text = zone(ZONE_HOSTS);
    bencher.bench_local(|| {
        let mut zonefile = Zonefile::with_capacity(text.len());
        zonefile.extend_from_slice(black_box(text.as_bytes()));
        let mut records = 0_usize;
        for entry in zonefile {
            black_box(entry.expect("reads"));
            records += 1;
        }
        records
    });
}

#[divan::bench]
fn parse_hickory(bencher: Bencher<'_, '_>) {
    let text = zone(ZONE_HOSTS);
    bencher.bench_local(|| {
        Parser::new(black_box(text.as_str()), None, None)
            .parse()
            .expect("parses")
    });
}
