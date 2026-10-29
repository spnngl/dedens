//! Fuzz entry points: one function per parser of outside data, each fed arbitrary bytes and required never
//! to panic.
//!
//! `cargo-fuzz` (nightly) reaches them through the shims in `fuzz_targets/`; `cargo test --lib` (stable,
//! `just fuzz-smoke`) replays the captured responses plus mutated variants through [`TARGETS`].

#![forbid(unsafe_code)]
#![expect(
    clippy::panic,
    reason = "a fuzz target, and the smoke test replaying it, report a bug by panicking"
)]

use core::ops::RangeInclusive;
use std::net::SocketAddr;
use std::sync::Arc;

use dedens_cache::{Cache, Config, Lookup, StalePolicy};
use dedens_net::resolv_conf::ResolvConf;
use dedens_plugins::{Action, Blocklist, Hosts, List, Lists, Origin};
use dedens_proto::rdata::{RData, SvcParam};
use dedens_proto::text::{Entry as ZoneEntry, ZoneReader};
use dedens_proto::wire::MAX_MESSAGE_LEN;
use dedens_proto::{
    DecodeErrorKind, DecodedRecord, EdnsView, EncodeError, Flags, Header, Message, Name, Query,
    Question, Record, RecordType, Ttl, message,
};
use dedens_scenario::QueryFile;
use dedens_server::{Forward, Pipeline, Stage, Step, Transport};
use hickory_proto::op::{Message as HickoryMessage, OpCode};
use hickory_proto::rr::rdata::opt::{EdnsCode, EdnsOption};
use hickory_proto::rr::{RData as HickoryRData, RecordType as HickoryRecordType};
use hickory_proto::serialize::binary::DecodeError as HickoryDecodeError;

#[cfg(test)]
mod smoke;

/// A fuzz entry point.
pub type Entry = fn(&[u8]);

/// Every target by name; `fuzz_targets/<name>.rs` and this list stay in step (checked by the smoke test).
pub const TARGETS: &[(&str, Entry)] = &[
    ("decode_message", decode_message),
    ("read_query", read_query),
    ("parse_zone", parse_zone),
    ("cache_insert", cache_insert),
    ("serve_query", serve_query),
    ("parse_name", parse_name),
    ("differential_hickory", differential_hickory),
    ("parse_query_file", parse_query_file),
    ("parse_resolv_conf", parse_resolv_conf),
    ("parse_lists", parse_lists),
];

/// A DNS message read by both dedens and hickory-proto: they agree on whether it is valid, and what each one
/// writes reads back in the other as the message it read. Our own round trips cannot catch a misreading of an
/// RFC that the reader and the writer share; a second implementation can.
///
/// # Panics
///
/// On a disagreement.
pub fn differential_hickory(data: &[u8]) {
    let ours = Message::decode(data);
    let theirs = HickoryMessage::from_vec(data);
    let (ours, theirs) = match (ours, theirs) {
        // A message breaking a rule we report but read (D9) is outside what the two can agree on.
        (Ok(decoded), _) if !decoded.violations.is_empty() => return,
        (Ok(decoded), Ok(theirs)) => (decoded.message, theirs),
        (Err(_), Err(_)) => return,
        (Ok(decoded), Err(error)) if hickory_refuses(&decoded.message, &error) => return,
        (Err(_), Ok(theirs)) if names_unchecked(&theirs) => return,
        // RFC 2136 §2.5 allows empty RDATA of any type in UPDATE; dedens reads UPDATE with the authoritative
        // phase (docs/TODECIDE.md).
        (Err(_), Ok(theirs)) if theirs.metadata.op_code == OpCode::Update => return,
        // dedens refuses a pointer into the header and one to labels running into the bytes that point to them
        // (RFC 1035 §4.1.4: a pointer goes to a prior name); hickory-proto checks neither.
        (Err(error), Ok(_)) if error.kind == DecodeErrorKind::BadPointer => return,
        // hickory-proto drops EDNS options whose framing is broken; dedens refuses the message (D9).
        (Err(error), Ok(_)) if opt_rdata(data).is_some_and(|r| r.contains(&error.offset)) => return,
        (ours, theirs) => panic!("dedens {ours:?}\nhickory {theirs:?}"),
    };
    // hickory-proto keeps names of those types compressed, pointing into the message it read: dedens expands
    // them, and hickory-proto writes the pointers back unchanged where the offsets they point to have moved.
    if names_unchecked(&theirs) {
        return;
    }
    let theirs = as_dedens_reads(theirs);
    if let Ok(wire) = ours.to_vec() {
        let read = HickoryMessage::from_vec(&wire).map(as_dedens_reads);
        assert_eq!(
            read.as_ref().ok(),
            Some(&theirs),
            "hickory reads what dedens writes: {read:?}"
        );
    }
    if let Ok(wire) = theirs.to_vec() {
        let ours = as_hickory_keeps(ours);
        let read = Message::decode(&wire);
        let read = read.as_ref().map(|d| (&d.message, d.violations.as_slice()));
        assert_eq!(
            read,
            Ok((&ours, [].as_slice())),
            "dedens reads what hickory writes"
        );
    }
}

/// Whether hickory-proto refuses `ours` where the RFCs let it through, so the disagreement is no dedens bug.
fn hickory_refuses(ours: &Message<'_>, error: &HickoryDecodeError) -> bool {
    let mut records = ours
        .answer
        .iter()
        .chain(&ours.authority)
        .chain(&ours.additional);
    match error {
        // Empty RDATA outside UPDATE: RFC 1035 and RFC 3597 §4 allow RDLENGTH 0 for a type without fields.
        HickoryDecodeError::InvalidEmptyRecord => true,
        // hickory-proto reads type 0, reserved (RFC 6895 §3.1), as always empty, and reads the fields of types
        // dedens keeps as bytes without reading them (D11), such as HINFO, and wants ALPN IDs in UTF-8 where
        // RFC 9460 §7.1.1 allows any bytes.
        _ => records.any(|r| {
            r.rtype() == RecordType(0) || matches!(r.data(), RData::Opaque(_)) || non_utf8_alpn(r)
        }),
    }
}

/// Whether `record` is an SVCB or HTTPS record with an ALPN ID that is not UTF-8.
fn non_utf8_alpn(record: &Record<'_>) -> bool {
    let (RData::Svcb(svcb) | RData::Https(svcb)) = record.data() else {
        return false;
    };
    svcb.params().iter().any(|param| {
        matches!(param, SvcParam::Alpn(ids) if ids.iter().any(|id| str::from_utf8(id).is_err()))
    })
}

/// Where the RDATA of the OPT record lies in `data`, a message hickory-proto read.
fn opt_rdata(data: &[u8]) -> Option<RangeInclusive<usize>> {
    let u16_at = |at: usize| {
        Some(usize::from(u16::from_be_bytes([
            *data.get(at)?,
            *data.get(at + 1)?,
        ])))
    };
    let skip_name = |mut at: usize| loop {
        match *data.get(at)? {
            0 => return Some(at + 1),
            len if len >= 0xC0 => return Some(at + 2),
            len => at += 1 + usize::from(len),
        }
    };
    let mut at = 12;
    for _ in 0..u16_at(4)? {
        at = skip_name(at)? + 4;
    }
    for _ in 0..u16_at(6)? + u16_at(8)? + u16_at(10)? {
        let fixed = skip_name(at)?;
        let start = fixed + 10;
        let end = start + u16_at(fixed + 8)?;
        if u16_at(fixed)? == usize::from(RecordType::OPT.0) {
            return Some(start..=end);
        }
        at = end;
    }
    None
}

/// `ours` without what hickory-proto does not keep and dedens keeps, to write a message as it was read.
fn as_hickory_keeps(mut ours: Message<'_>) -> Message<'_> {
    // The reserved header bit.
    ours.header.flags = ours.header.flags.without(Flags::Z);
    // A UDP payload under 512, which means 512 (RFC 6891 §6.2.5).
    if let Some(edns) = &mut ours.edns {
        edns.udp_payload = edns.udp_payload.max(512);
    }
    ours
}

/// Whether hickory-proto and dedens part ways on names in some RDATA: hickory-proto keeps as bytes a record of a
/// type whose RDATA holds names (RFC 3597 §4), which dedens reads and refuses when broken (D9), or reads names in
/// ANAME, a draft parked on 65305 in the private-use range (RFC 6895 §3.1), whose RDATA dedens keeps as bytes.
fn names_unchecked(message: &HickoryMessage) -> bool {
    message
        .answers
        .iter()
        .chain(&message.authorities)
        .chain(&message.additionals)
        .any(|record| {
            let rtype = record.record_type();
            rtype == HickoryRecordType::ANAME
                || matches!(record.data, HickoryRData::Unknown { .. })
                    && RData::may_hold_compressed_names(RecordType(u16::from(rtype)))
        })
}

/// `message` as dedens reads it: TTLs whose top bit is set as zero (RFC 2181 §8), padding as zeros, since dedens
/// keeps only its length (RFC 7830 §3 lets the sender pick the bytes).
fn as_dedens_reads(mut message: HickoryMessage) -> HickoryMessage {
    if let Some(edns) = &mut message.edns {
        for (code, option) in &mut edns.options_mut().options {
            if *code == EdnsCode::Padding
                && let EdnsOption::Unknown(_, data) = option
            {
                data.fill(0);
            }
        }
    }
    for record in message
        .answers
        .iter_mut()
        .chain(&mut message.authorities)
        .chain(&mut message.additionals)
    {
        if record.ttl > 0x7FFF_FFFF {
            record.ttl = 0;
        }
    }
    message
}

/// A response off the wire, stored in the cache as the answer to a query for its question, then served again into
/// a buffer whose size comes from the response's ID (at least [`Cache::MIN_OUT`]): the hit must decode without
/// violations and carry the ID and question of the query it answers.
///
/// # Panics
///
/// On a bug in the cache, or in the encoder or decoder it relies on.
pub fn cache_insert(data: &[u8]) {
    let Ok(decoded) = Message::decode(data) else {
        return;
    };
    let Some(question) = decoded.message.questions.first() else {
        return;
    };
    let cache = Cache::new(Config {
        capacity: 1 << 20,
        shards: 1,
        ..Config::default()
    })
    .expect("a valid config");
    // Asked with the response's RD, CD and AD bits, under an ID of its own.
    let id = !decoded.message.header.id;
    let mut query = Message::query(id, question.clone());
    query.header.flags = decoded.message.header.flags.without(Flags::QR);
    let query = query.to_vec().expect("a query fits");
    let query = Query::read(&query).expect("an encoded query reads");
    if cache.insert(&query, &decoded, 0).is_err() {
        return;
    }
    let size = usize::from(decoded.message.header.id).max(Cache::MIN_OUT);
    let mut out = vec![0; size];
    let Lookup::Hit(hit) = cache.lookup(&query, 0, StalePolicy::Never, &mut out) else {
        panic!("a response just stored is served");
    };
    let served = out.get(..hit.len).expect("the hit is within the buffer");
    let served = Message::decode(served).expect("a hit decodes");
    assert_eq!(served.violations, [], "a hit is conforming");
    assert_eq!(served.message.header.id, id, "a hit carries the query's ID");
    assert_eq!(
        served.message.questions,
        std::slice::from_ref(question),
        "a hit answers the question asked"
    );
}

/// Arbitrary bytes as a client's query, and as the upstream response to a query for their question, then that query
/// again, from the cache: whatever the server sends back is a conforming reply under the query's ID, within the
/// client's UDP payload.
///
/// # Panics
///
/// On a reply that breaks this.
pub fn serve_query(data: &[u8]) {
    let server = SocketAddr::from(([192, 0, 2, 1], 53));
    let mut out = vec![0; MAX_MESSAGE_LEN];
    for transport in [Transport::Udp, Transport::Tcp] {
        let pipeline = Pipeline::new(vec![
            Stage::Cache(Arc::new(
                Cache::new(Config::default()).expect("the default settings"),
            )),
            Stage::Forward(Forward::new([server]).expect("one server")),
        ]);
        if let Step::Reply(len) = pipeline.query(data, transport, 0, &mut out) {
            let id = Header::peek(data).expect("a reply goes to a header").id;
            check_reply(&out[..len], id, transport);
        }
        let Ok(decoded) = Message::decode(data) else {
            continue;
        };
        let Some(question) = decoded.message.questions.first() else {
            continue;
        };
        let id = !decoded.message.header.id;
        let query = Message::query(id, question.clone())
            .to_vec()
            .expect("a query fits");
        let Step::Upstream(upstream) = pipeline.query(&query, transport, 0, &mut out) else {
            continue;
        };
        let Step::Reply(len) = pipeline.receive(upstream, Some(data), 0, &mut out) else {
            panic!("the only server's response is answered");
        };
        check_reply(&out[..len], id, transport);
        // Asked again, from the cache when it stored the response.
        if let Step::Reply(len) = pipeline.query(&query, transport, 1, &mut out) {
            check_reply(&out[..len], id, transport);
        }
    }
}

/// Checks a reply of `serve_query`.
fn check_reply(reply: &[u8], id: u16, transport: Transport) {
    let decoded = Message::decode(reply).expect("a reply decodes");
    assert_eq!(decoded.violations, [], "a reply is conforming");
    assert_eq!(
        decoded.message.header.id, id,
        "a reply carries the query's ID"
    );
    if transport == Transport::Udp {
        assert!(reply.len() <= 1232, "a UDP reply fits the largest payload");
    }
}

/// A domain name in presentation format: what reads displays as text that reads back to the same name, byte for
/// byte.
///
/// # Panics
///
/// On a disagreement, or a bug in the reader or display.
pub fn parse_name(data: &[u8]) {
    let Ok(text) = std::str::from_utf8(data) else {
        return;
    };
    let Ok(name) = text.parse::<Name<'_>>() else {
        return;
    };
    let shown = name.to_string();
    let again: Name<'_> = shown
        .parse()
        .unwrap_or_else(|e| panic!("`{shown}` from `{text}` reads back: {e}"));
    assert_eq!(again, name, "`{shown}` from `{text}`");
    // `Debug` shows names as written, so this also catches a change of case, which `==` ignores.
    assert_eq!(
        format!("{again:?}"),
        format!("{name:?}"),
        "`{shown}` from `{text}`"
    );
}

/// A zone file: every record it yields is written as text and read back to the same record, names byte for
/// byte, and its generic form (RFC 3597 §5) reads back to it too.
///
/// # Panics
///
/// On a disagreement, or a bug in the reader or writer.
pub fn parse_zone(data: &[u8]) {
    // A default TTL, so that files without one, like the example of RFC 1035 §5.3, still yield records.
    for entry in ZoneReader::new(data, Some(Name::root())).with_ttl(Ttl::ZERO) {
        let Ok(ZoneEntry::Record(DecodedRecord {
            record,
            invalid_rdata,
        })) = entry
        else {
            continue;
        };
        for text in [record.to_string(), record.generic().to_string()] {
            let again = if invalid_rdata.is_some() {
                // RDATA its type refuses: a lone record is refused, a zone keeps it opaque (D9, D25).
                assert!(text.parse::<Record<'_>>().is_err(), "`{text}` is refused");
                match ZoneReader::new(text.as_bytes(), None).next() {
                    Some(Ok(ZoneEntry::Record(decoded))) => decoded.record,
                    other => panic!("`{text}` reads back in a zone: {other:?}"),
                }
            } else {
                text.parse()
                    .unwrap_or_else(|e| panic!("`{text}` reads back: {e}"))
            };
            // `Debug` shows names as written, so this also catches a change of case, which `==` ignores.
            assert_eq!(format!("{again:?}"), format!("{record:?}"), "`{text}`");
        }
    }
}

/// A query file (D34): what reads builds its queries and exchange options.
///
/// # Panics
///
/// On a bug in the reader or in building a query.
pub fn parse_query_file(data: &[u8]) {
    let Ok(text) = std::str::from_utf8(data) else {
        return;
    };
    let Ok(file) = QueryFile::parse(text) else {
        return;
    };
    for query in &file.queries {
        let options = query.options.or(file.options);
        let _ = options.check();
        let _ = options.exchange();
        let message = options.query(Question::new(query.name.clone(), query.qtype));
        message
            .to_vec()
            .unwrap_or_else(|e| panic!("{} encodes: {e}", query.id()));
    }
}

/// Arbitrary text as `/etc/resolv.conf`: `ndots` stays at most 15, and any of its words has the name itself and at
/// most one candidate per search domain.
///
/// # Panics
///
/// On a bug in the reader.
pub fn parse_resolv_conf(data: &[u8]) {
    let Ok(text) = std::str::from_utf8(data) else {
        return;
    };
    let conf = ResolvConf::parse(text);
    assert!(conf.ndots <= 15, "ndots {} above 15", conf.ndots);
    for word in text.split_ascii_whitespace() {
        if let Some(candidates) = conf.candidates(word) {
            assert!(
                !candidates.is_empty() && candidates.len() <= conf.search.len() + 1,
                "{word}: {} candidates",
                candidates.len()
            );
        }
    }
}

/// A DNS query off the wire, read in place: it accepts what [`Message::decode`] accepts, and reads the same
/// header, first question, EDNS and violations.
///
/// # Panics
///
/// On a disagreement, or a bug in the reader.
pub fn read_query(data: &[u8]) {
    let read = Query::read(data).map(|q| {
        (
            q.header(),
            q.question().cloned(),
            q.edns().map(EdnsView::to_edns),
            q.violations().to_vec(),
        )
    });
    let decoded = Message::decode(data).map(|d| {
        (
            d.message.header,
            d.message.questions.into_iter().next(),
            d.message.edns,
            d.violations,
        )
    });
    // `Debug` shows names as written, so this also catches a change of case, which `==` ignores.
    assert_eq!(
        format!("{read:?}"),
        format!("{decoded:?}"),
        "query reader and decoder agree"
    );
}

/// A DNS message off the wire.
///
/// Whatever decodes reads the same once owned, has a TTL offset per record, and must encode (unless pointers
/// expanded it past 65535 bytes) and decode again to the same message, names byte for byte; `Debug` reads every
/// RDATA as its type (D28). Without violations, the encoding is conforming, and truncating it at any size keeps a
/// conforming prefix of it.
///
/// # Panics
///
/// On a bug in the decoder or encoder: that is what fuzzing looks for.
pub fn decode_message(data: &[u8]) {
    let Ok(decoded) = Message::decode(data) else {
        return;
    };
    // `Debug` shows names as written, so this also catches a change of case, which `==` ignores.
    let shown = format!("{:?}", decoded.message);
    assert_eq!(
        format!("{:?}", decoded.message.clone().into_owned()),
        shown,
        "an owned copy reads the same"
    );
    let records = [
        &decoded.message.answer,
        &decoded.message.authority,
        &decoded.message.additional,
    ];
    assert_eq!(
        {
            let mut offsets = 0;
            message::ttl_offsets(data, |_| offsets += 1).map(|()| offsets)
        },
        Ok(records
            .iter()
            .flat_map(|r| r.iter())
            .filter(|r| r.rtype() != RecordType::OPT)
            .count()),
        "one TTL offset per record but a stray OPT record"
    );
    let wire = match decoded.message.to_vec() {
        Ok(wire) => wire,
        Err(EncodeError::BufferFull) => return,
        Err(e) => panic!("a decoded message must encode: {e}"),
    };
    let again = Message::decode(&wire).expect("what the encoder wrote decodes");
    assert_eq!(format!("{:?}", again.message), shown, "round trip");
    if !decoded.violations.is_empty() {
        return;
    }
    assert_eq!(again.violations, [], "what the encoder wrote is conforming");
    let size = usize::from(data.first().copied().unwrap_or_default()) * wire.len() / 255;
    truncate(&decoded.message, size);
}

/// Encodes `message` into `size` bytes, dropping records: what is written must be a conforming prefix.
fn truncate(message: &Message<'_>, size: usize) {
    let mut buf = vec![0; size];
    let Ok(encoded) = message.encode_truncated(&mut buf) else {
        return;
    };
    let wire = buf
        .get(..encoded.len)
        .expect("the length is within the buffer");
    let cut = Message::decode(wire).expect("a truncated message decodes");
    assert_eq!(cut.violations, [], "a truncated message is conforming");
    let cut = cut.message;
    let tc = message.header.flags.contains(Flags::TC) || encoded.truncated;
    assert_eq!(cut.header.flags.contains(Flags::TC), tc);
    assert_eq!(cut.edns, message.edns, "the OPT record is kept");
    let sections = [
        (&cut.answer, &message.answer),
        (&cut.authority, &message.authority),
        (&cut.additional, &message.additional),
    ];
    let mut kept = 0;
    for (cut, whole) in sections {
        assert!(whole.starts_with(cut), "each section is a prefix");
        kept += cut.len();
    }
    let total = message.answer.len() + message.authority.len() + message.additional.len();
    assert_eq!(kept + encoded.dropped, total);
}

/// Arbitrary text as a hosts file, as a downloaded blocklist, and its odd lines as an allowlist: when the hosts
/// file and the blocklist read, queries for its words get replies that decode, whatever the plugins answer.
///
/// # Panics
///
/// On a bug in the readers or in the replies of plugins.
pub fn parse_lists(data: &[u8]) {
    let Ok(text) = std::str::from_utf8(data) else {
        return;
    };
    let mut lists = Lists::new();
    let (Ok(hosts), Ok(_)) = (
        Hosts::new(text, Ttl::ZERO, false),
        lists.read(List::Block, Origin::Downloaded, text),
    ) else {
        return;
    };
    let allowed: String = text
        .lines()
        .skip(1)
        .step_by(2)
        .flat_map(|line| [line, "\n"])
        .collect();
    // Refused or not, the blocklist answers as before.
    let _ = lists.read(List::Allow, Origin::Downloaded, &allowed);
    let pipeline = Pipeline::new(vec![
        Stage::Plugin(Box::new(Blocklist::new(lists, Action::Null, Ttl::ZERO))),
        Stage::Plugin(Box::new(hosts)),
    ]);
    let mut out = vec![0; MAX_MESSAGE_LEN];
    for word in text.split_ascii_whitespace().take(8) {
        let Ok(name) = word.parse::<Name<'static>>() else {
            continue;
        };
        for qtype in [RecordType::A, RecordType::AAAA, RecordType::PTR] {
            let Ok(query) = Message::query(1, Question::new(name.clone(), qtype)).to_vec() else {
                continue;
            };
            if let Step::Reply(len) = pipeline.query(&query, Transport::Udp, 0, &mut out)
                && let Err(error) = Message::decode(&out[..len])
            {
                panic!("{word} {qtype}: the reply does not decode: {error}");
            }
        }
    }
}
