//! Zone file reading and loading: a generated zone of about 100 000 records, read against `domain` and hickory-proto,
//! and loaded into a checked `dedens_zone::Zone`; and the answers that zone and the root zone give (D206).
//!
//! dedens and `domain` yield one typed record at a time. hickory-proto has no such reader: its `Parser` also
//! files every record into a map of record sets, so it does more work than the other two.

use std::collections::BTreeMap;
use std::hint::black_box;

use dedens_bench::{ZONE_HOSTS, zone};
use dedens_proto::{Flags, Header, Message, Name, Question, RecordType, ZoneEntry, ZoneReader};
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

/// A zone loaded for the answer benches: `text` under `origin`.
fn loaded(origin: Name<'static>, text: &str) -> Zone {
    let source = Source {
        name: "zone",
        text: text.as_bytes(),
        default_ttl: None,
    };
    Zone::load(
        origin,
        source,
        &mut |_| Err(String::new()),
        &Limits::default(),
    )
    .expect("loads")
    .zone
}

/// `d DNAME b.d.example.` in the generic form (RFC 3597 §5) the loader reads it in: a target below its own owner,
/// which makes each name it leads to one label longer.
const GROWING_DNAME: &str = "d DNAME \\# 13 01620164076578616d706c6500\n";

/// The generated zone with a wildcard and a DNAME that grows names.
fn answered_zone() -> Zone {
    let mut text = zone(ZONE_HOSTS);
    text.push_str("*.wild TXT \"wildcard\"\n");
    text.push_str(GROWING_DNAME);
    let origin = Name::from_labels([b"example".as_slice()]).expect("a name");
    loaded(origin, &text)
}

/// The captured root zone: about 1 500 delegations.
fn root_zone() -> Zone {
    let text = std::fs::read_to_string(dedens_testkit::path("authoritative/zones/root.zone"))
        .expect("the captured root zone");
    loaded(Name::root(), &text)
}

/// What a query costs the zone: the answer, the message it fills, the reply encoded.
fn reply(zone: &Zone, question: &Question<'_>, buf: &mut [u8]) -> usize {
    let answer = zone.answer(question);
    let mut message = Message {
        header: Header {
            flags: Flags::QR,
            ..Header::default()
        },
        ..Message::default()
    };
    let glue = answer.fill(zone, &mut message);
    glue.encode(&message, buf).expect("encodes")
}

const DATA: &str = "h4000.example.";
const MISSING: &str = "nothing.example.";
const WILD: &str = "anything.wild.example.";
const ALIAS: &str = "www.h4002.example.";
const REFERRAL: &str = "www.example.com.";
const ROOT_MISSING: &str = "nothing.invalid.";
/// The longest name under `example.`, 122 labels, that is not there: the closest encloser is the apex.
const LONG: &str = "long";
/// 100 labels below `d.example.`: the DNAME makes it 11 links of a name one label longer each.
const GROWTH: &str = "growth";
/// The longest name of all, 127 labels, under the root zone.
const ROOT_LONG: &str = "root_long";

/// The name a bench argument stands for: the long ones are built, the others are the argument.
fn asked(arg: &str) -> Name<'static> {
    let text = match arg {
        LONG => format!("{}example.", "a.".repeat(122)),
        GROWTH => format!("{}d.example.", "a.".repeat(100)),
        ROOT_LONG => "a.".repeat(127),
        name => name.to_owned(),
    };
    text.parse().expect("a name")
}

/// `Zone::answer` alone, no message: finding the answer in the zone of 100 000 records.
#[divan::bench(args = [DATA, MISSING, WILD, ALIAS, LONG, GROWTH])]
fn answer_zone(bencher: Bencher<'_, '_>, name: &str) {
    let zone = answered_zone();
    let question = Question::new(asked(name), RecordType::A);
    bencher.bench_local(|| zone.answer(black_box(&question)).chain.len());
}

/// One lookup of a name present, in the zone's sorted `Vec` (binary search) and in a `BTreeMap` of the same names,
/// D204's first layout: why the zone keeps its nodes in a `Vec`.
#[divan::bench]
fn lookup_sorted_vec(bencher: Bencher<'_, '_>) {
    let zone = answered_zone();
    let name: Name<'static> = DATA.parse().expect("a name");
    bencher.bench_local(|| zone.node(black_box(&name)).is_some());
}

#[divan::bench]
fn lookup_btree_map(bencher: Bencher<'_, '_>) {
    let zone = answered_zone();
    let map: BTreeMap<Name<'static>, usize> = zone
        .nodes()
        .enumerate()
        .map(|(i, (name, _))| (name.clone(), i))
        .collect();
    let name: Name<'static> = DATA.parse().expect("a name");
    bencher.bench_local(|| map.contains_key(black_box(&name)));
}

/// The answer, the message and its encoding: the whole of what a query costs the zone.
#[divan::bench(args = [DATA, MISSING, WILD, ALIAS, LONG, GROWTH])]
fn reply_zone(bencher: Bencher<'_, '_>, name: &str) {
    let zone = answered_zone();
    let question = Question::new(asked(name), RecordType::A);
    let mut buf = [0_u8; 1232];
    bencher.bench_local(|| reply(&zone, black_box(&question), &mut buf));
}

/// A referral from the root zone, a name under no delegation of it, and one of 127 labels.
#[divan::bench(args = [REFERRAL, ROOT_MISSING, ROOT_LONG])]
fn reply_root(bencher: Bencher<'_, '_>, name: &str) {
    let zone = root_zone();
    let question = Question::new(asked(name), RecordType::A);
    let mut buf = [0_u8; 1232];
    bencher.bench_local(|| reply(&zone, black_box(&question), &mut buf));
}
