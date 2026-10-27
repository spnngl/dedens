//! D14: decode and encode of real responses, against hickory-proto and `domain`.
//!
//! Every library does the same work: decode the whole message into typed records, or encode typed records
//! with name compression. `encode_dedens` writes into a buffer it reuses; every `*_to_vec` encodes into a
//! fresh `Vec`, as the others always do. The `*_owned` variants measure `into_owned()`: decoding copies out of
//! the input, encoding writes names that no longer point into it.

use std::hint::black_box;

use dedens_bench::{CASES, wire};
use dedens_proto::{Decoded, Message};
use divan::Bencher;
use domain::base::message_builder::StaticCompressor;
use domain::base::{Message as DomainMessage, MessageBuilder};
use domain::rdata::AllRecordData;
use hickory_proto::op::Message as HickoryMessage;

// Counts allocations next to time: borrowing exists to remove them (D7a).
#[global_allocator]
static ALLOC: divan::AllocProfiler = divan::AllocProfiler::system();

fn main() {
    divan::main();
}

#[divan::bench(args = CASES)]
fn decode_dedens(bencher: Bencher<'_, '_>, case: &str) {
    let wire = wire(case);
    bencher.bench_local(|| Message::decode(black_box(&wire)).expect("decodes"));
}

/// Decode into the vectors of the previous message, as a server does; dropping the records is timed too.
#[divan::bench(args = CASES)]
fn decode_dedens_reusing(bencher: Bencher<'_, '_>, case: &str) {
    let wire = wire(case);
    let mut spare = Decoded::default();
    bencher.bench_local(|| {
        let decoded = Message::decode_reusing(black_box(&wire), &mut spare).expect("decodes");
        spare = black_box(decoded).recycle();
    });
}

/// Decode and drop the message, timing the drop too: the baseline of `decode_dedens_reusing`.
#[divan::bench(args = CASES)]
fn decode_dedens_dropped(bencher: Bencher<'_, '_>, case: &str) {
    let wire = wire(case);
    bencher.bench_local(|| {
        drop(black_box(
            Message::decode(black_box(&wire)).expect("decodes"),
        ));
    });
}

/// Decode then copy out of the input, as a cache storing the message does.
#[divan::bench(args = CASES)]
fn decode_dedens_owned(bencher: Bencher<'_, '_>, case: &str) {
    let wire = wire(case);
    bencher.bench_local(|| {
        Message::decode(black_box(&wire))
            .expect("decodes")
            .into_owned()
    });
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
    let wire = wire(case);
    let message = Message::decode(&wire).expect("decodes").message;
    let mut buf = vec![0; 4096];
    bencher.bench_local(|| message.encode(black_box(&mut buf)).expect("encodes"));
}

/// Encode a message owning its bytes: no name to rebuild from compression pointers.
#[divan::bench(args = CASES)]
fn encode_dedens_owned(bencher: Bencher<'_, '_>, case: &str) {
    let message = Message::decode(&wire(case))
        .expect("decodes")
        .message
        .into_owned();
    let mut buf = vec![0; 4096];
    bencher.bench_local(|| message.encode(black_box(&mut buf)).expect("encodes"));
}

#[divan::bench(args = CASES)]
fn encode_dedens_to_vec(bencher: Bencher<'_, '_>, case: &str) {
    let wire = wire(case);
    let message = Message::decode(&wire).expect("decodes").message;
    bencher.bench_local(|| black_box(&message).to_vec().expect("encodes"));
}

#[divan::bench(args = CASES)]
fn encode_hickory_to_vec(bencher: Bencher<'_, '_>, case: &str) {
    let message = HickoryMessage::from_vec(&wire(case)).expect("decodes");
    bencher.bench_local(|| black_box(&message).to_vec().expect("encodes"));
}

#[divan::bench(args = CASES)]
fn encode_domain_to_vec(bencher: Bencher<'_, '_>, case: &str) {
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
        // At most 24 names, which these responses do not reach.
        let target = StaticCompressor::new(Vec::new());
        let mut builder = MessageBuilder::from_target(target)
            .expect("header")
            .question();
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
