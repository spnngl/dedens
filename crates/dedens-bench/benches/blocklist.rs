//! The blocklist plugin (D56, D58) on the heads of published lists: reading them, and `Pipeline::query` for a
//! blocked name, an allowed one under a blocked parent, and one in no list, which goes upstream.

use std::hint::black_box;
use std::net::SocketAddr;

use dedens_plugins::{Action, Blocklist, List, Lists, Origin};
use dedens_proto::{Message, Question, RecordType, Ttl};
use dedens_server::{Forward, Pipeline, Stage, Step, Transport};

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

/// Names: blocked under a listed parent, allowed under a blocked one, in no list.
const NAMES: [&str; 3] = ["x.b.adform.net.", "x.track.adform.net.", "www.example.com."];

#[divan::bench(args = NAMES)]
fn query(bencher: divan::Bencher<'_, '_>, name: &str) {
    let upstream = SocketAddr::from(([192, 0, 2, 53], 53));
    let pipeline = Pipeline::new(vec![
        Stage::Plugin(Box::new(Blocklist::new(
            lists(),
            Action::Nxdomain,
            Ttl::ZERO,
        ))),
        Stage::Forward(Forward::new(&[upstream]).expect("a server")),
    ]);
    let blocked = name.starts_with("x.b.");
    let name = name.parse().expect("a name");
    let query = Message::query(7, Question::new(name, RecordType::A))
        .to_vec()
        .expect("a query fits");
    let mut out = vec![0; 1232];
    bencher.bench_local(|| {
        let step = pipeline.query(black_box(&query), Transport::Udp, 0, &mut out);
        assert_eq!(matches!(step, Step::Reply(_)), blocked);
    });
}
