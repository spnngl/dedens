//! D14: decode and encode of real responses, against hickory-proto and `domain`.
//!
//! Decoding checks every RDATA everywhere; dedens keeps it as bytes (D28), the others build typed records, which
//! `decode_typed_dedens` adds. Encoding compresses names everywhere. `encode_dedens` writes into a buffer it reuses; every `*_to_vec` encodes into a
//! fresh `Vec`, as the others always do. The `*_owned` variants measure `into_owned()`: decoding copies out of
//! the input, encoding writes names that no longer point into it.

use std::hint::black_box;
use std::net::Ipv4Addr;

use dedens_bench::{CASES, wire};
use dedens_proto::edns::{Cookie, EdnsOption};
use dedens_proto::{
    Class, Decoded, Message, Name, Query, Question, RData, Record, RecordType, Ttl,
};
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

/// A typical query: `www.example.com. A`, RD, EDNS with a client cookie, as resolvers send it.
fn query() -> Vec<u8> {
    let name = Name::from_labels([&b"www"[..], b"example", b"com"]).expect("valid name");
    let mut message = Message::query(0x1234, Question::new(name, RecordType::A));
    let cookie = Cookie::new([1, 2, 3, 4, 5, 6, 7, 8], None).expect("client cookie");
    if let Some(edns) = message.edns.as_mut() {
        edns.options.push(EdnsOption::Cookie(cookie));
    }
    message.to_vec().expect("encodes")
}

/// Read a query in place (D21): header, question, EDNS fields, all of it checked.
#[divan::bench]
fn query_dedens(bencher: Bencher<'_, '_>) {
    let wire = query();
    bencher.bench_local(|| {
        let query = Query::read(black_box(&wire)).expect("reads");
        black_box((
            query.question().cloned(),
            query.edns().map(|e| e.udp_payload),
        ));
    });
}

/// Decode a query into a `Message`, its EDNS options in a vector.
#[divan::bench]
fn query_decode_dedens(bencher: Bencher<'_, '_>) {
    let wire = query();
    bencher.bench_local(|| Message::decode(black_box(&wire)).expect("decodes"));
}

/// Parse a query with `domain`: the question and the OPT record.
#[divan::bench]
fn query_domain(bencher: Bencher<'_, '_>) {
    let wire = query();
    bencher.bench_local(|| {
        let message = DomainMessage::from_octets(black_box(wire.as_slice())).expect("parses");
        let question = message.first_question().expect("question");
        let opt = message.opt().expect("OPT");
        black_box((
            question,
            opt.udp_payload_size(),
            opt.opt()
                .iter::<domain::base::opt::AllOptData<_, _>>()
                .count(),
        ));
    });
}

/// Decode, then read every record as its type: the work the other libraries do in their decode.
#[divan::bench(args = CASES)]
fn decode_typed_dedens(bencher: Bencher<'_, '_>, case: &str) {
    let wire = wire(case);
    let mut spare = Decoded::default();
    bencher.bench_local(|| {
        let decoded = Message::decode_reusing(black_box(&wire), &mut spare).expect("decodes");
        let message = &decoded.message;
        let records = message.answer.iter().chain(&message.authority);
        for record in records.chain(&message.additional) {
            black_box(record.data());
        }
        spare = decoded.recycle();
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

/// Truncation that keeps whole additional `RRsets` (RFC 2181 §9), from 3000 records of distinct owners, as a
/// hostile upstream may send, into 16 KiB: about 800 fit.
#[divan::bench]
fn encode_truncated_dedens(bencher: Bencher<'_, '_>) {
    let ttl = Ttl::new(60).expect("in range");
    let mut message = Message::query(1, Question::new(Name::root(), RecordType::A));
    message.additional = (0..3000)
        .map(|i| {
            let owner = Name::from_labels([format!("n{i}").as_bytes()]).expect("valid name");
            Record::new(owner, Class::IN, ttl, &RData::A(Ipv4Addr::LOCALHOST))
        })
        .collect();
    let mut buf = vec![0; 16 * 1024];
    bencher.bench_local(|| {
        message
            .encode_truncated(black_box(&mut buf))
            .expect("encodes")
    });
}
