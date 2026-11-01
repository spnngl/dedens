//! The blocklist plugin (D56, D58, D110) on the heads of published lists: reading them, `Pipeline::query` for a
//! blocked name, an allowed one under a blocked parent, and one in no list, which goes upstream, and the lookup
//! alone (`Plugin::answer`) for names of 1 to 127 labels.

use std::hint::black_box;
use std::net::{Ipv4Addr, SocketAddr};

use dedens_plugins::{Action, Blocklist, List, Lists, Origin};
use dedens_proto::{Message, Query, Question, RecordType, Ttl};
use dedens_server::{Forward, Pipeline, Plugin, Stage, Step, Transport};

#[global_allocator]
static ALLOC: divan::AllocProfiler = divan::AllocProfiler::system();

const BLOCK: [&str; 3] = [
    include_str!("../../dedens-plugins/tests/testdata/stevenblack.hosts"),
    include_str!("../../dedens-plugins/tests/testdata/hagezi-light.txt"),
    include_str!("../../dedens-plugins/tests/testdata/hagezi-pro-wildcard.txt"),
];
const ALLOW: &str = include_str!("../../dedens-plugins/tests/testdata/hagezi-referral-allow.txt");

fn main() {
    divan::main();
}

fn lists() -> Lists {
    let mut lists = Lists::new();
    for text in BLOCK {
        lists
            .read(List::Block, Origin::Downloaded, text)
            .expect("a list");
    }
    lists
        .read(List::Allow, Origin::Downloaded, ALLOW)
        .expect("a list");
    lists
}

#[divan::bench]
fn read() -> Lists {
    lists()
}

/// A downloaded list checked before it is saved, its names counted, not stored.
#[divan::bench]
fn check() -> usize {
    BLOCK
        .into_iter()
        .map(|text| Lists::check(text).expect("a list").names)
        .sum()
}

/// Names: blocked under a listed parent, allowed under a blocked one, in no list.
const NAMES: [&str; 3] = ["x.b.adform.net.", "x.track.adform.net.", "www.example.com."];

#[divan::bench(args = NAMES)]
fn query(bencher: divan::Bencher<'_, '_>, name: &str) {
    query_pipeline(bencher, name);
}

fn query_pipeline(bencher: divan::Bencher<'_, '_>, name: &str) {
    let upstream = SocketAddr::from(([192, 0, 2, 53], 53));
    let pipeline = Pipeline::new(vec![
        Stage::Plugin(Box::new(Blocklist::new(
            lists(),
            Action::Nxdomain,
            Ttl::ZERO,
        ))),
        Stage::Forward(Forward::new([upstream]).expect("a server")),
    ]);
    let blocked = name.starts_with("x.b.");
    let name = name.parse().expect("a name");
    let query = Message::query(7, Question::new(name, RecordType::A))
        .to_vec()
        .expect("a query fits");
    let mut out = vec![0; 1232];
    bencher.bench_local(|| {
        let step = pipeline.query(
            black_box(&query),
            Transport::Udp,
            Ipv4Addr::LOCALHOST.into(),
            0,
            &mut out,
        );
        assert_eq!(matches!(step, Step::Reply(_)), blocked);
    });
}

/// A name in no list of `labels` one-byte labels (127 of them are the longest name, 255 bytes on the wire), the
/// whole `Pipeline::query`: decoding the query and the name is in the cost, as is the lookup.
#[divan::bench(args = [1, 3, 10, 127])]
fn query_labels(bencher: divan::Bencher<'_, '_>, labels: usize) {
    query_pipeline(bencher, &"a.".repeat(labels));
}

/// The lookup alone (D110): `Plugin::answer` on a query read once, for a name in no list of `labels` labels:
/// the lowercase key, the label walk and the hashes of the labels up to the longest listed name.
#[divan::bench(args = [1, 3, 10, 127])]
fn lookup(bencher: divan::Bencher<'_, '_>, labels: usize) {
    lookup_answer(bencher, &"a.".repeat(labels), lists(), false);
}

/// The lookup alone for a name `labels` labels deep under the listed `adform.net.`, so that the allowlist is
/// looked up too: 123 labels, two of them `adform.net`, are the longest name.
#[divan::bench(args = [10, 123])]
fn lookup_blocked(bencher: divan::Bencher<'_, '_>, labels: usize) {
    let name = format!("{}adform.net.", "a.".repeat(labels - 2));
    lookup_answer(bencher, &name, lists(), true);
}

/// The lookup alone against lists that hold nothing: what the walk costs by itself.
#[divan::bench(args = [1, 3, 10, 127])]
fn lookup_empty(bencher: divan::Bencher<'_, '_>, labels: usize) {
    lookup_answer(bencher, &"a.".repeat(labels), Lists::new(), false);
}

fn lookup_answer(bencher: divan::Bencher<'_, '_>, name: &str, lists: Lists, blocked: bool) {
    let blocklist = Blocklist::new(lists, Action::Nxdomain, Ttl::ZERO);
    let name = name.parse().expect("a name");
    let wire = Message::query(7, Question::new(name, RecordType::A))
        .to_vec()
        .expect("a query fits");
    let query = Query::read(&wire).expect("a query");
    bencher.bench_local(|| {
        assert_eq!(blocklist.answer(black_box(&query)).is_some(), blocked);
    });
}
