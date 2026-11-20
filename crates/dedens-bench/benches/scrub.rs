//! The resolver's scrubber (D192) on captured responses of `testdata/recursion` (D188): `scrub` sorts a decoded
//! response, `ranked` groups what it kept into the `RRsets` the cache takes, the two steps of each response a
//! resolution reads.
//!
//! The responses, each to an A question: `referral`, the root's referral to `com.` with its DS and glue
//! (`signed-com`); `answer`, `example.com.`'s signed A records (`signed-com`); `nxdomain`, `nl.`'s signed NXDOMAIN
//! with its NSEC3 records (`nxdomain-nsec3`); `dname`, `dns.netmeister.org.`'s signed answer through a DNAME
//! (`dname`).

use std::hint::black_box;

use dedens_proto::{Message, Name, Question, RecordType};
use dedens_resolver::scrub;
use dedens_testkit::recursion::Resolution;
use divan::Bencher;

#[global_allocator]
static ALLOC: divan::AllocProfiler = divan::AllocProfiler::system();

fn main() {
    divan::main();
}

const RESPONSES: &[&str] = &["referral", "answer", "nxdomain", "dname"];

/// The response named `name` in [`RESPONSES`], with its question and the zone it was asked as.
fn captured(name: &str) -> (Vec<u8>, Question<'static>, Name<'static>) {
    let (id, zone, asked) = match name {
        "referral" => ("signed-com", ".", "example.com."),
        "answer" => ("signed-com", "example.com.", "example.com."),
        "nxdomain" => ("nxdomain-nsec3", "nl.", "dedens-nxdomain.nl."),
        _ => (
            "dname",
            "dns.netmeister.org.",
            "www.dname.dns.netmeister.org.",
        ),
    };
    let zone: Name<'static> = zone.parse().expect("a name");
    let asked: Name<'static> = asked.parse().expect("a name");
    let exchange = (Resolution::read(id).exchanges.into_iter())
        .find(|e| e.zone == zone && e.name == asked && e.rtype == RecordType::A)
        .expect("a captured exchange");
    (exchange.response, Question::new(asked, RecordType::A), zone)
}

#[divan::bench(args = RESPONSES)]
fn sort(bencher: Bencher<'_, '_>, name: &str) {
    let (bytes, question, zone) = captured(name);
    let message = Message::decode(&bytes)
        .expect("a captured response")
        .message;
    bencher.bench_local(|| black_box(scrub(black_box(&message), &question, &zone)));
}

#[divan::bench(args = RESPONSES)]
fn ranked(bencher: Bencher<'_, '_>, name: &str) {
    let (bytes, question, zone) = captured(name);
    let message = Message::decode(&bytes)
        .expect("a captured response")
        .message;
    let scrubbed = scrub(&message, &question, &zone);
    bencher.bench_local(|| black_box(black_box(&scrubbed).ranked()));
}
