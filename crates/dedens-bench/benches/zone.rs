//! Zone file reading and loading: a generated zone of about 100 000 records, read against `domain` and hickory-proto,
//! and loaded into a checked `dedens_zone::Zone`; and the answers that zone and the root zone give (D206).
//!
//! dedens and `domain` yield one typed record at a time. hickory-proto has no such reader: its `Parser` also
//! files every record into a map of record sets, so it does more work than the other two.

use std::collections::BTreeMap;
use std::fmt::Write;
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

/// The deep names, the delegation they hide under, and the hosts of the MX sets, to add to the generated zone.
fn deep_text() -> String {
    // A name of 120 labels with an address, then a delegation with names 120 labels deep below it and 100
    // below it: occluded names, the addresses of which are optional glue.
    let mut text = format!("{}example. A 192.0.2.77\n", "a.".repeat(119));
    text.push_str("cut NS ns.elsewhere.\n");
    writeln!(text, "{}cut A 192.0.2.78", "a.".repeat(118)).expect("writes");
    for host in 0..100 {
        writeln!(text, "mx-cut MX 10 t{host}.{}cut.example.", "a.".repeat(97)).expect("writes");
        writeln!(text, "t{host}.{}cut A 192.0.2.{host}", "a.".repeat(97)).expect("writes");
        // The same hosts in the zone itself, with one address each, and with 100 A and 100 AAAA records each.
        writeln!(text, "mx-auth MX 10 ta{host}").expect("writes");
        writeln!(text, "ta{host} A 192.0.2.{host}").expect("writes");
        writeln!(text, "mx-many MX 10 tm{host}").expect("writes");
        for address in 0..100 {
            writeln!(text, "tm{host} A 192.0.2.{address}").expect("writes");
            writeln!(text, "tm{host} AAAA 2001:db8::{address:x}").expect("writes");
        }
    }
    text
}

/// The generated zone with a wildcard, a DNAME that grows names, and the deep names.
fn answered_zone() -> Zone {
    let mut text = zone(ZONE_HOSTS);
    text.push_str("*.wild TXT \"wildcard\"\n");
    text.push_str(GROWING_DNAME);
    text.push_str(&deep_text());
    let origin = Name::from_labels([b"example".as_slice()]).expect("a name");
    loaded(origin, &text)
}

/// The name of the PTR for an address of IPv6: 31 zero nibbles and `last`, below `ip6.arpa.`.
fn ptr_name(last: char) -> String {
    format!("{}{last}.ip6.arpa.", "0.".repeat(31))
}

/// A reverse zone for IPv6 with one PTR, 32 labels below the apex.
fn ptr_zone() -> Zone {
    let text = format!(
        "$TTL 1h\n@ SOA ns hostmaster 1 1d 2h 4w 1h\n@ NS ns\nns A 192.0.2.1\n{} PTR host.example.\n",
        ptr_name('1')
    );
    loaded("ip6.arpa.".parse().expect("a name"), &text)
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
    let glue = answer.fill(zone, &mut message, buf.len());
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
/// An exact name of 120 labels, a node with an address.
const DEEP: &str = "deep";
/// One label below `DEEP`: it is not there, its closest encloser is 119 labels from the apex.
const BELOW_DEEP: &str = "below_deep";
/// An exact name of 120 labels below a delegation: occluded.
const DEEP_CUT: &str = "deep_cut";
/// An MX of 100 hosts 100 labels deep below a delegation, each with an address: optional glue.
const MX_CUT: &str = "mx-cut.example.";
/// An MX of 100 hosts of the zone, one address each.
const MX_AUTH: &str = "mx-auth.example.";
/// An MX of 100 hosts of the zone with 100 A and 100 AAAA records each: 20 000 addresses.
const MX_MANY: &str = "mx-many.example.";
/// A PTR of an IPv6 address, 34 labels, in a reverse zone.
const PTR: &str = "ptr";
/// The same name but for its last nibble: not there.
const PTR_MISSING: &str = "ptr_missing";

/// The name a bench argument stands for: the long ones are built, the others are the argument.
fn asked(arg: &str) -> Name<'static> {
    let text = match arg {
        LONG => format!("{}example.", "a.".repeat(122)),
        GROWTH => format!("{}d.example.", "a.".repeat(100)),
        ROOT_LONG => "a.".repeat(127),
        DEEP => format!("{}example.", "a.".repeat(119)),
        BELOW_DEEP => format!("b.{}example.", "a.".repeat(119)),
        DEEP_CUT => format!("{}cut.example.", "a.".repeat(118)),
        PTR => ptr_name('1'),
        PTR_MISSING => ptr_name('2'),
        name => name.to_owned(),
    };
    text.parse().expect("a name")
}

/// `Zone::answer` alone, no message: finding the answer in the zone of 100 000 records.
#[divan::bench(args = [DATA, MISSING, WILD, ALIAS, LONG, GROWTH, DEEP, BELOW_DEEP, DEEP_CUT])]
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
#[divan::bench(args = [DATA, MISSING, WILD, ALIAS, LONG, GROWTH, DEEP, BELOW_DEEP, DEEP_CUT])]
fn reply_zone(bencher: Bencher<'_, '_>, name: &str) {
    let zone = answered_zone();
    let question = Question::new(asked(name), RecordType::A);
    let mut buf = [0_u8; 1232];
    bencher.bench_local(|| reply(&zone, black_box(&question), &mut buf));
}

/// An MX answer and the addresses of its hosts: occluded ones, ones of the zone, and ones with 20 000 addresses.
#[divan::bench(args = [MX_AUTH, MX_CUT, MX_MANY])]
fn reply_mx(bencher: Bencher<'_, '_>, name: &str) {
    let zone = answered_zone();
    let question = Question::new(asked(name), RecordType::MX);
    let mut buf = [0_u8; 1232];
    bencher.bench_local(|| reply(&zone, black_box(&question), &mut buf));
}

/// A PTR of 34 labels in a reverse zone for IPv6, present and missing.
#[divan::bench(args = [PTR, PTR_MISSING])]
fn reply_ptr(bencher: Bencher<'_, '_>, name: &str) {
    let zone = ptr_zone();
    let question = Question::new(asked(name), RecordType::PTR);
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
