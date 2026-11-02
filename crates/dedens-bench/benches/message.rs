//! D14: decode and encode of real responses, against hickory-proto and `domain`.
//!
//! Decoding checks every RDATA everywhere; dedens keeps it as bytes (D28), the others build typed records, which
//! `decode_typed_dedens` adds. Encoding compresses names everywhere. `encode_dedens` writes into a buffer it reuses; every `*_to_vec` encodes into a
//! fresh `Vec`, as the others always do. The `*_owned` variants measure `into_owned()`: decoding copies out of
//! the input, encoding writes names that no longer point into it.

use std::collections::HashMap;
use std::hash::{BuildHasher, RandomState};
use std::hint::black_box;
use std::net::Ipv4Addr;

use dedens_bench::{CASES, wire};
use dedens_proto::edns::{Cookie, EdnsOption};
use dedens_proto::rdata::Mx;
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

/// Owner and target of record `i`, `(i, 0)` and `(i, 1)`: how a message's names are shaped.
type Names = fn(usize, u8) -> Name<'static>;

/// Names of different owners, as a zone with a thousand hosts has them.
fn spread(i: usize, which: u8) -> Name<'static> {
    let host = if which == 0 { "host" } else { "mail" };
    let labels = [
        format!("{host}{i}"),
        format!("zone{}", i % 64),
        "example".into(),
        "com".into(),
    ];
    Name::from_labels(labels.iter().map(String::as_bytes)).expect("valid name")
}

/// Names of the same first label and length, differing one label further: a hostile upstream's, which share a
/// slot of the name table if it hashes only a name's start (D10, D112).
fn collisions(i: usize, which: u8) -> Name<'static> {
    let unique = format!("{:08}", i * 2 + usize::from(which));
    let labels = ["www", unique.as_str(), "zone", "example", "com"];
    Name::from_labels(labels.iter().map(|l| l.as_bytes())).expect("valid name")
}

/// Names of 100 one-byte labels before a differing one: a search that looked up each of the 100 suffixes would
/// hash and probe a hundred times for each name (D112).
fn chains(i: usize, which: u8) -> Name<'static> {
    let unique = format!("{:08}", i * 2 + usize::from(which));
    let labels = std::iter::repeat_n("a", 100).chain([unique.as_str(), "example", "com"]);
    Name::from_labels(labels.map(str::as_bytes)).expect("valid name")
}

/// Names whose first label is one of 128 of 63 bytes that hashed alike under any seed in a hash that multiplies
/// the words of a name by a constant: flipping bit 63 of a word and bit 4 of the next cancels (D112). A table that
/// trusted its hash would compare each with all the others.
fn flips(i: usize, which: u8) -> Name<'static> {
    let variant = (i * 2 + usize::from(which)) % 128;
    let mut label = [b'x'; 63];
    for pair in (0..7).filter(|pair| variant >> pair & 1 == 1) {
        label[8 * pair + 6] ^= 0x80;
        label[8 * pair + 7] ^= 0x10;
    }
    Name::from_labels([label.as_slice(), b"example", b"com"]).expect("valid name")
}

/// Names of 9 labels of their own, then the 100 one-byte labels and `com` that all the others have: the
/// longest suffix held is found a hundred labels in, by a search over the labels.
fn deep_fresh(i: usize, which: u8) -> Name<'static> {
    let unique = format!("{:018}", i * 2 + usize::from(which));
    let labels = unique
        .as_bytes()
        .chunks(2)
        .chain(std::iter::repeat_n(b"a".as_slice(), 100))
        .chain([b"com".as_slice()]);
    Name::from_labels(labels).expect("valid name")
}

/// Names of one label of their own, then the 100 one-byte labels and `com` that all the others have: the
/// longest suffix held is the rest of the name, a hundred labels from the root.
fn deep_hit(i: usize, which: u8) -> Name<'static> {
    let unique = format!("{:08}", i * 2 + usize::from(which));
    let labels = std::iter::once(unique.as_bytes())
        .chain(std::iter::repeat_n(b"a".as_slice(), 100))
        .chain([b"com".as_slice()]);
    Name::from_labels(labels).expect("valid name")
}

/// The most CNAME and MX records, alternating, that `names` fills 64 KiB with: both ends of each record are
/// compressed names (RFC 1035 §3.3).
fn full_message(names: Names) -> Message<'static> {
    let ttl = Ttl::new(60).expect("in range");
    let mut buf = vec![0; 65535];
    let mut message = Message::query(1, Question::new(Name::root(), RecordType::A));
    let mut i = 0;
    loop {
        let mut next = message.clone();
        next.answer.extend((i..i + 8).map(|i| {
            let target = names(i, 1);
            let data = if i % 2 == 0 {
                RData::Cname(target)
            } else {
                RData::Mx(Mx {
                    preference: 10,
                    exchange: target,
                })
            };
            Record::new(names(i, 0), Class::IN, ttl, &data)
        }));
        if next.encode(&mut buf).is_err() {
            return message;
        }
        message = next;
        i += 8;
    }
}

/// Encode 64 KiB of records: `spread` names, then hostile shapes of the name table: `collisions`, `chains` and
/// `flips` must stay within 2x of the first, and the `deep` ones (a suffix of a hundred labels to look up in
/// each name) within what hashing a name of that length costs (D112).
#[divan::bench(args = ["spread", "collisions", "chains", "flips", "deep_fresh", "deep_hit"])]
fn encode_64k(bencher: Bencher<'_, '_>, shape: &str) {
    let names: Names = match shape {
        "collisions" => collisions,
        "chains" => chains,
        "flips" => flips,
        "deep_fresh" => deep_fresh,
        "deep_hit" => deep_hit,
        _ => spread,
    };
    let message = full_message(names);
    let mut buf = vec![0; 65535];
    bencher.bench_local(|| message.encode(black_box(&mut buf)).expect("encodes"));
}

/// A name of about 200 bytes: `i` and three labels of 63.
fn long(i: usize) -> Name<'static> {
    let labels = [
        i.to_string(),
        "a".repeat(63),
        "b".repeat(63),
        "c".repeat(63),
    ];
    Name::from_labels(labels.iter().map(String::as_bytes)).expect("valid name")
}

/// The hash of a name, as the validator's `HashMap` keys are hashed: a short name, one of about 200 bytes, and
/// a name decoded from a message, as a pointer to labels written before it.
#[divan::bench(args = ["short", "long", "packed"])]
fn name_hash(bencher: Bencher<'_, '_>, shape: &str) {
    let hasher = RandomState::new();
    let encoded = full_message(spread).to_vec().expect("encodes");
    let decoded = Message::decode(&encoded).expect("decodes").message;
    let name = match shape {
        "short" => spread(1, 0),
        "long" => long(1),
        _ => decoded.answer[5].name.clone(),
    };
    bencher.bench_local(|| hasher.hash_one(black_box(&name)));
}

/// A lookup by name in a `HashMap`, a hit: what the validator's key cache does for each table it asks.
#[divan::bench(args = ["short", "long"])]
fn name_map_get(bencher: Bencher<'_, '_>, shape: &str) {
    let name: fn(usize) -> Name<'static> = if shape == "short" {
        |i| spread(i, 0)
    } else {
        long
    };
    let names: Vec<Name<'static>> = (0..1000).map(name).collect();
    let map: HashMap<Name<'static>, usize> = names.iter().cloned().zip(0..).collect();
    let mut next = 0;
    bencher.bench_local(|| {
        next = (next + 1) % names.len();
        map.get(black_box(&names[next]))
    });
}
