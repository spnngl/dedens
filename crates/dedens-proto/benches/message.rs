//! D14: decode and encode of real responses (`tests/testdata/`), against hickory-proto and `domain`.
//!
//! Every library does the same work: decode the whole message into typed records, or encode typed records
//! into a buffer (dedens: a caller buffer it reuses; the others: their builder into a fresh `Vec`).

use std::hint::black_box;

use dedens_proto::Message;
use divan::Bencher;
use domain::base::{Message as DomainMessage, MessageBuilder};
use domain::rdata::AllRecordData;
use hickory_proto::op::Message as HickoryMessage;

fn main() {
    divan::main();
}

/// Captured responses, smallest to largest: one A record; MX records with their A glue; a TXT answer of
/// 1.2 kB.
const CASES: [&str; 3] = ["a", "mx", "txt_large"];

fn wire(case: &str) -> Vec<u8> {
    let path = format!("{}/tests/testdata/{case}.bin", env!("CARGO_MANIFEST_DIR"));
    std::fs::read(path).expect("captured response")
}

#[divan::bench(args = CASES)]
fn decode_dedens(bencher: Bencher<'_, '_>, case: &str) {
    let wire = wire(case);
    bencher.bench_local(|| Message::decode(black_box(&wire)).expect("decodes"));
}

#[divan::bench(args = CASES)]
fn decode_hickory(bencher: Bencher<'_, '_>, case: &str) {
    let wire = wire(case);
    bencher.bench_local(|| HickoryMessage::from_vec(black_box(&wire)).expect("decodes"));
}

#[divan::bench(args = CASES)]
fn decode_domain(bencher: Bencher<'_, '_>, case: &str) {
    let wire = wire(case);
    bencher.bench_local(|| {
        let message = DomainMessage::from_octets(black_box(wire.as_slice())).expect("decodes");
        let mut records = 0;
        for section in [
            message.answer().expect("answer"),
            message.authority().expect("authority"),
            message.additional().expect("additional"),
        ] {
            for record in section.limit_to::<AllRecordData<_, _>>() {
                black_box(record.expect("record"));
                records += 1;
            }
        }
        records
    });
}

#[divan::bench(args = CASES)]
fn encode_dedens(bencher: Bencher<'_, '_>, case: &str) {
    let message = Message::decode(&wire(case)).expect("decodes").message;
    let mut buf = vec![0; 4096];
    bencher.bench_local(|| message.encode(black_box(&mut buf)).expect("encodes"));
}

#[divan::bench(args = CASES)]
fn encode_hickory(bencher: Bencher<'_, '_>, case: &str) {
    let message = HickoryMessage::from_vec(&wire(case)).expect("decodes");
    bencher.bench_local(|| black_box(&message).to_vec().expect("encodes"));
}

#[divan::bench(args = CASES)]
fn encode_domain(bencher: Bencher<'_, '_>, case: &str) {
    let wire = wire(case);
    let message = DomainMessage::from_octets(wire.as_slice()).expect("decodes");
    let questions: Vec<_> = message.question().map(|q| q.expect("question")).collect();
    let answer: Vec<_> = message
        .answer()
        .expect("answer")
        .limit_to::<AllRecordData<_, _>>()
        .map(|r| r.expect("record"))
        .collect();
    let authority: Vec<_> = message
        .authority()
        .expect("authority")
        .limit_to::<AllRecordData<_, _>>()
        .map(|r| r.expect("record"))
        .collect();
    let additional: Vec<_> = message
        .additional()
        .expect("additional")
        .limit_to::<AllRecordData<_, _>>()
        .map(|r| r.expect("record"))
        .collect();
    bencher.bench_local(|| {
        let mut builder = MessageBuilder::new_vec().question();
        for question in &questions {
            builder.push(question).expect("question");
        }
        let mut builder = builder.answer();
        for record in &answer {
            builder.push(record).expect("record");
        }
        let mut builder = builder.authority();
        for record in &authority {
            builder.push(record).expect("record");
        }
        let mut builder = builder.additional();
        for record in &additional {
            builder.push(record).expect("record");
        }
        builder.finish()
    });
}
