//! The blocklist plugin (D56, D58, D110) on the heads of published lists: reading them, `Pipeline::query` for a
//! blocked name, an allowed one under a blocked parent, and one in no list, which goes upstream, and the lookup
//! alone (`Plugin::answer`) for names of 1 to 127 labels. D118: the review of a response (`Reviewer::review`) on
//! CNAME chains of 1 to 16 hops, and a cache hit with and without the blocklist reviewing it.

use std::hint::black_box;
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;

use dedens_cache::{Cache, Config};
use dedens_plugins::{Action, Blocklist, List, Lists, Merged, Names, Origin, Tlds};
use dedens_proto::{Class, Message, Name, Query, Question, RData, Record, RecordType, Ttl};
use dedens_server::{Forward, Pipeline, Plugin, Stage, Step, Transport};

#[global_allocator]
static ALLOC: dedens_bench::alloc::Profiled = dedens_bench::alloc::profiled();

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

/// A downloaded list read once (D120), as the download does before it saves the copy: hashed, sorted and
/// deduplicated, then judged for a list, its names counted.
#[divan::bench]
fn parse() -> usize {
    BLOCK
        .into_iter()
        .map(|text| {
            Names::downloaded(text)
                .check(Tlds::Allow)
                .expect("a list")
                .names
        })
        .sum()
}

/// A side of lists built from names read already (D120), as a reload builds a stage side one of whose sources
/// changed: the sources merged into one set, each name once.
#[divan::bench]
fn merge(bencher: divan::Bencher<'_, '_>) {
    let names: Vec<Names> = BLOCK.into_iter().map(Names::downloaded).collect();
    bencher.bench_local(|| Merged::new(Tlds::Allow, &names).expect("a list"));
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

/// A response to `n0.chain.test. A` made of a chain of `hops` CNAME records, none of them listed: every target is
/// looked up.
fn chain(hops: usize) -> Message<'static> {
    let name = |i: usize| -> Name<'static> { format!("n{i}.chain.test.").parse().expect("a name") };
    Message {
        questions: vec![Question::new(name(0), RecordType::A)],
        answer: (0..hops)
            .map(|i| {
                Record::new(
                    name(i),
                    Class::IN,
                    Ttl::from_wire(60),
                    &RData::Cname(name(i + 1)),
                )
            })
            .collect(),
        ..Message::default()
    }
}

/// The review (D118) of a response with a chain of `hops` CNAME records, against the lists of the heads: the
/// cost a response from upstream, or a hit, pays on top of its decoding. 16 are the most checked.
#[divan::bench(args = [1, 4, 16])]
fn review(bencher: divan::Bencher<'_, '_>, hops: usize) {
    let blocklist = Blocklist::new(lists(), Action::Nxdomain, Ttl::ZERO);
    let reviewer = blocklist.reviewer().expect("names to block");
    let response = chain(hops);
    let wire = response.questions[0].clone();
    let query = Message::query(7, wire).to_vec().expect("a query fits");
    let query = Query::read(&query).expect("a query");
    bencher.bench_local(|| {
        assert!(
            reviewer
                .review(black_box(&query), black_box(&response))
                .is_none()
        );
    });
}

/// A cache hit on the captured `www.ripe.net. A` (a chain of two CNAME records, their signature and two
/// addresses), `Pipeline::query` whole: with the blocklist before the cache, which decodes the reply and reviews
/// it, and without (a pipeline of the cache alone).
#[divan::bench(args = [true, false])]
fn hit(bencher: divan::Bencher<'_, '_>, reviewed: bool) {
    let upstream = SocketAddr::from(([192, 0, 2, 53], 53));
    let mut stages = Vec::new();
    if reviewed {
        let blocklist = Blocklist::new(lists(), Action::Nxdomain, Ttl::ZERO);
        stages.push(Stage::Plugin(Box::new(blocklist)));
    }
    let cache = Arc::new(Cache::new(Config::default()).expect("the default settings"));
    stages.push(Stage::Cache(cache));
    stages.push(Stage::Forward(Forward::new([upstream]).expect("a server")));
    let pipeline = Pipeline::new(stages);
    let name = "www.ripe.net.".parse().expect("a name");
    let query = Message::query(7, Question::new(name, RecordType::A))
        .to_vec()
        .expect("a query fits");
    let response = include_bytes!("../../dedens-dnssec/tests/testdata/cname_to_insecure.bin");
    let mut out = vec![0; 1232];
    let client = Ipv4Addr::LOCALHOST.into();
    let Step::Upstream(asked) = pipeline.query(&query, Transport::Udp, client, 0, &mut out) else {
        unreachable!("a cache miss")
    };
    assert!(matches!(
        pipeline.receive(asked, Some(&response[..]), 0, &mut out),
        Step::Reply(_)
    ));
    bencher.bench_local(|| {
        let step = pipeline.query(black_box(&query), Transport::Udp, client, 0, &mut out);
        assert!(matches!(step, Step::Reply(_)));
    });
}
