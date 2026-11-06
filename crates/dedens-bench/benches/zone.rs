//! Zone file reading: a generated zone of about 100 000 records, against `domain` and hickory-proto.
//!
//! dedens and `domain` yield one typed record at a time. hickory-proto has no such reader: its `Parser` also
//! files every record into a map of record sets, so it does more work than the other two.

use std::hint::black_box;

use dedens_bench::{ZONE_HOSTS, zone};
use dedens_proto::text::{Entry, ZoneReader};
use divan::Bencher;
use domain::zonefile::inplace::Zonefile;
use hickory_proto::serialize::txt::Parser;

#[global_allocator]
static ALLOC: dedens_bench::alloc::Profiled = dedens_bench::alloc::profiled();

fn main() {
    divan::main();
}

#[divan::bench]
fn read_dedens(bencher: Bencher<'_, '_>) {
    let text = zone(ZONE_HOSTS);
    bencher.bench_local(|| {
        let mut records = 0_usize;
        for entry in ZoneReader::new(black_box(text.as_bytes()), None) {
            if let Entry::Record(record) = entry.expect("reads") {
                black_box(record);
                records += 1;
            }
        }
        records
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
