//! The bundled root hints and TLD list (D126): what reading each costs at start, `Tlds::read` being the bundled
//! `tlds.json` read once into a sorted table, and a lookup in that table: a TLD, a name below one in another case, a
//! TLD not listed.

use std::hint::black_box;

use dedens_proto::Name;
use dedens_roots::{RootHints, Tlds};

#[global_allocator]
static ALLOC: divan::AllocProfiler = divan::AllocProfiler::system();

/// What `just roots` bundles.
const NAMED_ROOT: &[u8] = include_bytes!("../../dedens-roots/src/named.root");
const TLDS: &[u8] = include_bytes!("../../dedens-roots/src/tlds.json");

fn main() {
    divan::main();
}

#[divan::bench]
fn read_hints(bencher: divan::Bencher<'_, '_>) {
    bencher.bench_local(|| RootHints::read(black_box(NAMED_ROOT)).expect("the hints"));
}

#[divan::bench]
fn read_tlds(bencher: divan::Bencher<'_, '_>) {
    let _ = Tlds::bundled();
    bencher.bench_local(|| Tlds::read(black_box(TLDS)).expect("the TLDs"));
}

/// Names looked up: a TLD, a name below one in upper case, a TLD not listed.
const NAMES: [(&str, bool); 3] = [
    ("fr.", true),
    ("WWW.EXAMPLE.FR.", true),
    ("example.nosuchtld.", false),
];

#[divan::bench(args = NAMES)]
fn get(bencher: divan::Bencher<'_, '_>, (name, listed): (&str, bool)) {
    let tlds = Tlds::bundled();
    let name: Name<'static> = name.parse().expect("a name");
    bencher.bench_local(|| assert_eq!(tlds.get(black_box(&name)).is_some(), listed));
}
