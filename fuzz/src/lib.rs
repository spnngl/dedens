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
use std::sync::{Arc, LazyLock};

use dedens_cache::{Cache, Config, Lookup, StalePolicy};
use dedens_dnssec::anchor::TrustAnchors;
use dedens_dnssec::crypto::{self, Budget};
use dedens_dnssec::denial::{self, MaxIterations};
use dedens_dnssec::rrsig::{self, Key, RrSet, Signature};
use dedens_dnssec::validator::{Limits, Next, Validator};
use dedens_net::coap::block::{Block, BlockSize, slice};
use dedens_net::coap::exchange::{Exchange, Params, Request};
use dedens_net::coap::{Code, Message as CoapMessage};
use dedens_net::doh::{self, Method, Template};
use dedens_net::resolv_conf::ResolvConf;
use dedens_odoh::rand_core::{TryCryptoRng, TryRng};
use dedens_odoh::{
    MessageType, ObliviousDoHConfigs, ObliviousDoHMessage, ObliviousDoHMessagePlaintext,
    QueryContext, TargetKey, decrypt_query, decrypt_response, encrypt_query,
};
use dedens_plugins::{Action, Blocklist, Hosts, List, Lists, Origin};
use dedens_proto::rdata::{RData, SvcParam};
use dedens_proto::text::{Entry as ZoneEntry, ZoneReader};
use dedens_proto::wire::MAX_MESSAGE_LEN;
use dedens_proto::{
    DecodeErrorKind, DecodedRecord, DigestType, EdnsView, EncodeError, Flags, Header, Message,
    Name, Nsec3HashAlgorithm, Query, Question, Record, RecordType, SecAlgorithm, Ttl, message,
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
    ("parse_doh_template", parse_doh_template),
    ("server_request", server_request),
    ("read_doh_response", read_doh_response),
    ("dnssec_crypto", dnssec_crypto),
    ("parse_odoh_configs", parse_odoh_configs),
    ("parse_odoh_message", parse_odoh_message),
    ("odoh_decrypt", odoh_decrypt),
    ("rrsig_verify", rrsig_verify),
    ("denial", denial),
    ("validate", validate),
    ("parse_coap", parse_coap),
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
        let options = query.options.clone().or(file.options.clone());
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

/// Arbitrary text as a `DoH` URI Template (RFC 8484 §3, RFC 9461 §5): what is accepted reads back from its own
/// text, and the requests it makes are read back by a server as the query.
///
/// # Panics
///
/// On a bug in the reader.
pub fn parse_doh_template(data: &[u8]) {
    let Ok(text) = std::str::from_utf8(data) else {
        return;
    };
    let Ok(template) = Template::parse(text) else {
        return;
    };
    let shown = template.to_string();
    assert_eq!(
        Template::parse(&shown).ok().as_ref(),
        Some(&template),
        "{shown}: does not read back"
    );
    let query = [0, 0, 1, 0, 0, 1];
    for method in [Method::Get, Method::Post] {
        // A template of a path nearly as long as `http` allows has no room for the query.
        let Ok(request) = doh::request(&template, &query, method) else {
            continue;
        };
        assert_eq!(
            doh::server_request(&request, request.body()),
            Ok(query.to_vec()),
            "{shown}: {method:?}"
        );
    }
}

/// Arbitrary bytes as the request of a `DoH` client: the first byte picks the method and the content type, the
/// rest is the `dns` parameter of a GET or the body of a POST. A query read is never empty nor above 65535
/// bytes, and any error is one of the statuses RFC 8484 §4.1 and §6 give.
///
/// # Panics
///
/// On a bug in the reader.
pub fn server_request(data: &[u8]) {
    let Some((&shape, rest)) = data.split_first() else {
        return;
    };
    let method = match shape & 3 {
        0 => http::Method::GET,
        1 => http::Method::POST,
        2 => http::Method::PUT,
        _ => http::Method::HEAD,
    };
    let mut builder = http::Request::builder().method(method.clone());
    if shape & 4 != 0 {
        builder = builder.header(http::header::CONTENT_TYPE, doh::MEDIA_TYPE);
    }
    let (uri, body) = if method == http::Method::GET {
        let query = String::from_utf8_lossy(rest);
        (format!("https://doh.example/dns-query?{query}"), &[][..])
    } else {
        ("https://doh.example/dns-query".to_owned(), rest)
    };
    let Ok(request) = builder.uri(uri).body(()) else {
        return;
    };
    match doh::server_request(&request, body) {
        Ok(query) => {
            assert!(
                !query.is_empty() && query.len() <= MAX_MESSAGE_LEN,
                "a query of {} bytes",
                query.len()
            );
            if method == http::Method::GET {
                let parameter = format!("dns={}", dedens_proto::text::encode_base64url(&query));
                assert!(
                    request
                        .uri()
                        .query()
                        .is_some_and(|q| q.split('&').any(|p| p == parameter)),
                    "{parameter} is not in the URI"
                );
            } else {
                assert_eq!(query, body);
            }
        }
        Err(status) => assert!(
            [400, 405, 413, 415].contains(&status.as_u16()),
            "status {status}"
        ),
    }
}

/// Arbitrary bytes as the HTTP response of a `DoH` server: `meta`, `Age`, `Date` and the body, apart by NUL bytes;
/// the first byte of `meta` picks the status and whether the content type is the DNS one. The `Age` and the
/// `Date` only ever lower TTLs (RFC 8484 §5.1) and do not change whether the response is one.
///
/// # Panics
///
/// On a bug in the reader.
pub fn read_doh_response(data: &[u8]) {
    const STATUSES: [u16; 6] = [200, 203, 204, 301, 404, 503];
    let mut parts = data.splitn(4, |&byte| byte == 0);
    let (Some(meta), Some(age), Some(stamp), Some(body)) =
        (parts.next(), parts.next(), parts.next(), parts.next())
    else {
        return;
    };
    let shape = usize::from(meta.first().copied().unwrap_or(0));
    let Ok(status) = http::StatusCode::from_u16(STATUSES[shape % STATUSES.len()]) else {
        return;
    };
    let plain = || {
        let mut builder = http::Response::builder().status(status);
        if shape & 0x80 != 0 {
            builder = builder.header(http::header::CONTENT_TYPE, doh::MEDIA_TYPE);
        }
        builder
    };
    let (Ok(age), Ok(stamp)) = (
        http::HeaderValue::from_bytes(age),
        http::HeaderValue::from_bytes(stamp),
    ) else {
        return;
    };
    let Ok(with) = plain()
        .header(http::header::AGE, age)
        .header(http::header::DATE, stamp)
        .body(())
    else {
        return;
    };
    let Ok(without) = plain().body(()) else {
        return;
    };
    let now = std::time::UNIX_EPOCH + std::time::Duration::from_secs(1_793_522_455);
    match (
        doh::response(&with, body, now),
        doh::response(&without, body, now),
    ) {
        (Ok(aged), Ok(fresh)) => {
            let ttls = |m: &Message<'_>| -> Vec<u32> {
                [&m.answer, &m.authority, &m.additional]
                    .into_iter()
                    .flatten()
                    .map(|record| record.ttl.get())
                    .collect()
            };
            let (aged, fresh) = (ttls(&aged.message), ttls(&fresh.message));
            assert_eq!(aged.len(), fresh.len(), "the records differ");
            assert!(
                aged.iter().zip(&fresh).all(|(aged, fresh)| aged <= fresh),
                "a TTL grew: {aged:?} from {fresh:?}"
            );
        }
        (Err(_), Err(_)) => {}
        (aged, fresh) => panic!("Age and Date change the result: {aged:?}, {fresh:?}"),
    }
}

/// The DNSSEC cryptography (D71) on bytes from outside: arbitrary keys, signatures, signed data, digests and
/// salts through `verify`, `key_tag`, `ds_digest` and `nsec3_hash`; and the DNSKEY, RRSIG and DS records of a
/// message, so the captured zones reach the key parsers as real keys. The functions answer with an error on any
/// input, and the policy they state about each algorithm holds.
///
/// # Panics
///
/// On a panic of `dedens-dnssec`, or on an answer that contradicts `supported` or `supported_digest`.
pub fn dnssec_crypto(data: &[u8]) {
    // Bytes as a key, a signature and signed data: the first three octets are the algorithm and two lengths.
    if let [algorithm, key_len, sig_len, rest @ ..] = data {
        let (key, rest) = rest.split_at(usize::from(*key_len).min(rest.len()));
        let (signature, signed) = rest.split_at(usize::from(*sig_len).min(rest.len()));
        verify_checked(SecAlgorithm(*algorithm), key, signed, signature);
        let _ = crypto::key_tag(key);
        let owner: Name<'_> = "Example.COM.".parse().expect("a name");
        for digest in 0..=u8::MAX {
            digest_checked(DigestType(digest), &owner, key);
        }
        let hash = crypto::nsec3_hash(Nsec3HashAlgorithm::SHA1, key, u16::from(*sig_len), &owner);
        assert!(hash.is_ok(), "SHA-1 hashes any salt");
    }
    let Ok(decoded) = Message::decode(data) else {
        return;
    };
    let records: Vec<&Record<'_>> = [
        &decoded.message.answer,
        &decoded.message.authority,
        &decoded.message.additional,
    ]
    .into_iter()
    .flatten()
    .collect();
    for key in &records {
        let RData::Dnskey(dnskey) = key.data() else {
            continue;
        };
        let mut rdata = dnskey.flags().to_be_bytes().to_vec();
        rdata.extend([3, dnskey.algorithm().into()]);
        rdata.extend(dnskey.public_key());
        let _ = crypto::key_tag(&rdata);
        for other in &records {
            match other.data() {
                RData::Rrsig(rrsig) => verify_checked(
                    dnskey.algorithm(),
                    dnskey.public_key(),
                    &rrsig.signed_rdata(),
                    rrsig.signature(),
                ),
                RData::Ds(ds) => digest_checked(ds.digest_type(), &key.name, &rdata),
                _ => {}
            }
        }
    }
}

/// `verify`, whose `UnsupportedAlgorithm` answer is exactly `supported`'s refusal.
fn verify_checked(algorithm: SecAlgorithm, key: &[u8], signed: &[u8], signature: &[u8]) {
    let answer = crypto::verify(algorithm, key, signed, signature);
    assert_eq!(
        answer == Err(crypto::VerifyError::UnsupportedAlgorithm(algorithm)),
        !crypto::supported(algorithm),
        "{algorithm}"
    );
}

/// `ds_digest`, whose `UnsupportedDigest` answer is exactly `supported_digest`'s refusal.
fn digest_checked(digest: DigestType, owner: &Name<'_>, dnskey_rdata: &[u8]) {
    let answer = crypto::ds_digest(digest, owner, dnskey_rdata);
    assert_eq!(
        answer.as_ref().err() == Some(&crypto::UnsupportedDigest(digest)),
        !crypto::supported_digest(digest),
        "{digest}"
    );
}

/// `ObliviousDoHConfigs` read from arbitrary bytes (RFC 9230 §5): the configs written back read as the same
/// configs, and every key ID is the length RFC 9230 §6.1 gives.
///
/// # Panics
///
/// When a list does not read back as itself.
pub fn parse_odoh_configs(data: &[u8]) {
    let Ok(configs) = ObliviousDoHConfigs::parse(data) else {
        return;
    };
    assert!(
        configs
            .configs()
            .iter()
            .all(|config| config.key_id().len() == dedens_odoh::KEY_ID_LEN)
    );
    // A list of configs this crate cannot use has nothing to write (D78).
    if let Ok(written) = configs.encode() {
        assert_eq!(ObliviousDoHConfigs::parse(&written), Ok(configs));
    }
}

/// `ObliviousDoHMessage` and `ObliviousDoHMessagePlaintext` read from arbitrary bytes (RFC 9230 §6.1): what
/// reads writes back to the same bytes.
///
/// # Panics
///
/// When a structure does not write back to the bytes it was read from.
pub fn parse_odoh_message(data: &[u8]) {
    if let Ok(message) = ObliviousDoHMessage::parse(data) {
        assert_eq!(message.encode(), data);
    }
    if let Ok(plaintext) = ObliviousDoHMessagePlaintext::parse(data) {
        assert_eq!(plaintext.encode(), data);
    }
}

/// Bytes the "randomness" of a fuzz run repeats: the exchange stays deterministic.
struct Fixed(u8);

impl TryRng for Fixed {
    type Error = core::convert::Infallible;

    fn try_next_u32(&mut self) -> Result<u32, Self::Error> {
        Ok(u32::from_ne_bytes([self.0; 4]))
    }

    fn try_next_u64(&mut self) -> Result<u64, Self::Error> {
        Ok(u64::from_ne_bytes([self.0; 8]))
    }

    fn try_fill_bytes(&mut self, dst: &mut [u8]) -> Result<(), Self::Error> {
        dst.fill(self.0);
        Ok(())
    }
}

impl TryCryptoRng for Fixed {}

/// The target of the `odoh-go` vector (`crates/dedens-odoh/tests/testdata/README.md`): its `public_key_seed`, so
/// that the captured query below decrypts.
static ODOH_KEY: LazyLock<TargetKey> = LazyLock::new(|| {
    TargetKey::derive(&[
        0xc9, 0xd8, 0x4d, 0x04, 0xe6, 0x36, 0x9f, 0xcc, 0xb8, 0xa4, 0xd5, 0xa2, 0x64, 0x00, 0x14,
        0x91, 0x22, 0x1f, 0x1b, 0x97, 0xd9, 0xb8, 0x0d, 0xd3, 0x2c, 0x35, 0x83, 0x4b, 0xb4, 0x46,
        0x23, 0x83,
    ])
});

/// A query `odoh-go` encrypted for [`ODOH_KEY`].
const ODOH_QUERY: &[u8] =
    include_bytes!("../../crates/dedens-odoh/tests/testdata/odoh-go-query.bin");

/// The context of a query of our own: no response of the fuzzer can authenticate under it. Made once, since
/// the key exchange is slow unoptimized.
static ODOH_CLIENT: LazyLock<QueryContext> = LazyLock::new(|| {
    encrypt_query(ODOH_KEY.config(), b"q", 0, &mut Fixed(1))
        .expect("the key of a target is a good public key")
        .1
});

/// Arbitrary bytes as an `ODoH` query and as a response (RFC 9230 §7, §8): a forged message is refused, never a
/// panic. A parsed query is also given the target key ID, so that it reaches the key exchange; only the
/// ciphertext of `odoh-go` may authenticate. The exchange of well-formed messages is tested in
/// `crates/dedens-odoh/tests/rfc9230.rs`.
///
/// # Panics
///
/// When a forged message is accepted.
pub fn odoh_decrypt(data: &[u8]) {
    let Ok(message) = ObliviousDoHMessage::parse(data) else {
        return;
    };
    let key = &*ODOH_KEY;
    let _ = decrypt_query(key, &message);
    if message.message_type() == MessageType::Query
        && let Ok(grafted) = ObliviousDoHMessage::new(
            MessageType::Query,
            key.config().key_id().to_vec(),
            message.encrypted_message().to_vec(),
        )
        && decrypt_query(key, &grafted).is_ok()
    {
        let known = ObliviousDoHMessage::parse(ODOH_QUERY).expect("the captured query parses");
        assert_eq!(message.encrypted_message(), known.encrypted_message());
    }
    assert!(decrypt_response(&ODOH_CLIENT, &message).is_err());
}
/// The `RRset` checks of `dedens_dnssec::rrsig` (D73) on the records of a message: every `RRset` against every
/// RRSIG and DNSKEY the message holds, and every DNSKEY `RRset` against every DS `RRset`, at the time of the
/// first RRSIG's inception (the captured zones verify) and at one taken from the input. Whatever the input, the
/// canonical form is sorted without duplicates, an `RRset` kept for no longer than it came with, an error
/// is never the "unsupported" of a DS (an RRSIG of an unknown algorithm must not make data insecure), and the
/// Extended DNS Error has text.
///
/// # Panics
///
/// On a panic of `dedens-dnssec`, or on an answer that breaks one of those rules.
pub fn rrsig_verify(data: &[u8]) {
    let Ok(decoded) = Message::decode(data) else {
        return;
    };
    let message = &decoded.message;
    let sets: Vec<RrSet<'_>> = [&message.answer, &message.authority, &message.additional]
        .into_iter()
        .flat_map(|section| RrSet::group(section))
        .collect();
    let of_type = |rtype: RecordType| sets.iter().filter(move |set| set.rtype() == rtype);
    let sigs: Vec<Signature<'_>> = of_type(RecordType::RRSIG)
        .flat_map(|set| Signature::all(set))
        .collect();
    let keys: Vec<Key<'_>> = of_type(RecordType::DNSKEY)
        .flat_map(|set| Key::all(set))
        .collect();
    let times = [
        sigs.first().map_or(0, |sig| sig.rrsig().inception),
        data.first_chunk()
            .map_or(0, |bytes| u32::from_be_bytes(*bytes)),
    ];
    for set in &sets {
        let canonical = set.canonical_rdatas();
        assert!(
            canonical.is_sorted_by(|a, b| a < b),
            "canonical RDATA not strictly sorted"
        );
        assert!(canonical.len() <= set.rdatas().len(), "canonical form grew");
        for now in times {
            match rrsig::verify_any(set, &sigs, &keys, now, &mut Budget::default()) {
                Ok(verified) => assert!(verified.ttl <= set.ttl(), "kept longer than it came"),
                Err(error) => {
                    assert!(
                        !error.is_unsupported(),
                        "an RRSIG made data insecure: {error}"
                    );
                    assert!(!error.ede(set).text.is_empty(), "no text for {error}");
                }
            }
            if set.rtype() == RecordType::DNSKEY {
                for ds in of_type(RecordType::DS) {
                    let _ = rrsig::trusted_keys(set, &sigs, ds, now, &mut Budget::default());
                }
            }
        }
    }
}

/// The NSEC and NSEC3 records of a message, or of a zone file, as the proof of denial of existence of a question
/// the message asks, or of a name the records are about: `prove` and `prove_wildcard_answer` under every ancestor
/// of the name as the apex, so that records of any zone, shape and parameters reach every path. Whatever the
/// records, the functions answer, and a proof lasts as long as one of the records does (RFC 9077 §3).
///
/// # Panics
///
/// On a panic of `dedens-dnssec`, or on a proof with a TTL no record has.
pub fn denial(data: &[u8]) {
    let (records, question, labels): (Vec<Record<'static>>, Question<'static>, u8) =
        if let Ok(decoded) = Message::decode(data) {
            let message = decoded.message.into_owned();
            let labels = message
                .answer
                .iter()
                .find_map(|r| match r.data() {
                    RData::Rrsig(rrsig) => Some(rrsig.labels),
                    _ => None,
                })
                .unwrap_or(1);
            let question = message.questions.first().cloned();
            let records = [message.answer, message.authority, message.additional].concat();
            let question = question.or_else(|| {
                records
                    .first()
                    .map(|r| Question::new(r.name.clone(), r.rtype()))
            });
            let Some(question) = question else {
                return;
            };
            (records, question, labels)
        } else {
            let records: Vec<Record<'static>> = ZoneReader::new(data, Some(Name::root()))
                .with_ttl(Ttl::ZERO)
                .filter_map(|entry| match entry {
                    Ok(ZoneEntry::Record(decoded)) => Some(decoded.record),
                    _ => None,
                })
                .collect();
            let Some(first) = records.first() else {
                return;
            };
            // The type is any of those a zone proves things about, picked by the input's length.
            let qtypes = [
                RecordType::A,
                RecordType::MX,
                RecordType::DS,
                RecordType::SOA,
            ];
            let qtype = qtypes[data.len() % qtypes.len()];
            let question = Question::new(first.name.clone(), qtype);
            (records, question, u8::try_from(data.len() % 8).unwrap_or(0))
        };
    let ttls: Vec<Ttl> = records.iter().map(|r| r.ttl).collect();
    let labels_of_name: Vec<&[u8]> = question.name.labels().collect();
    for skip in 0..=labels_of_name.len() {
        let Ok(apex) = Name::from_labels(labels_of_name.iter().skip(skip).copied()) else {
            continue;
        };
        let proofs = [
            denial::prove(
                &apex,
                &question,
                &records,
                MaxIterations::default(),
                &mut Budget::default(),
            ),
            denial::prove_wildcard_answer(
                &apex,
                &question.name,
                labels,
                &records,
                MaxIterations::default(),
                &mut Budget::default(),
            ),
        ];
        for proof in proofs.into_iter().flatten() {
            assert!(
                ttls.contains(&proof.ttl),
                "{proof:?}: no record has the TTL"
            );
        }
    }
}

/// The Unix time of the capture run, "now" for the signatures of the captured seeds.
const CAPTURED_AT: &str = include_str!("../../crates/dedens-dnssec/tests/testdata/captured_at");

/// The validator with the root anchors and the default limits, built once.
static VALIDATOR: LazyLock<Validator> =
    LazyLock::new(|| Validator::new(TrustAnchors::root(), Limits::default()));

/// A captured response, as the bytes it was saved as and as a message.
type Captured = (Vec<u8>, Message<'static>);

/// The captured responses a validation is answered from: the real chains of `tests/testdata/`.
static POOL: LazyLock<Vec<Captured>> = LazyLock::new(|| {
    let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../crates/dedens-dnssec/tests/testdata");
    let mut pool: Vec<Captured> = std::fs::read_dir(dir)
        .into_iter()
        .flatten()
        .filter_map(|entry| std::fs::read(entry.ok()?.path()).ok())
        .filter_map(|wire| {
            let message = Message::decode(&wire).ok()?.message.into_owned();
            Some((wire, message))
        })
        .collect();
    pool.sort_by(|a, b| a.0.cmp(&b.0));
    pool
});

/// `message` as a response to `question`, whatever it answered.
fn answering(message: &Message<'static>, question: &Question<'static>) -> Message<'static> {
    let mut message = message.clone();
    message.questions = vec![question.clone()];
    message
}

/// The captured response to `ask`, when there is one.
fn captured(ask: &Question<'static>) -> Option<&'static Captured> {
    POOL.iter().find(|(_, message)| {
        message
            .questions
            .first()
            .is_some_and(|q| q.name == ask.name && q.qtype == ask.qtype)
    })
}

/// A response read from the input, validated, its questions answered from the captured chains: each answer is
/// picked by a byte of the input, as the input's own message, none, the captured response to the question, that
/// response with a bit of it flipped, or a captured response to another question. Whatever the bytes, the
/// validation asks only for DS and DNSKEY, asks at most the limit, ends, and a verdict that is not secure and has
/// an extended error gives it text.
///
/// # Panics
///
/// On a panic of `dedens-dnssec`, or on a validation that breaks one of those rules.
pub fn validate(data: &[u8]) {
    let Ok(decoded) = Message::decode(data) else {
        return;
    };
    let response = decoded.message.into_owned();
    let Some(question) = response.questions.first().cloned() else {
        return;
    };
    let now = CAPTURED_AT.trim().parse().unwrap_or(0);
    let limit = Limits::default().questions;
    let mut validation = VALIDATOR.start(&question, &response, now);
    for asked in 0..=limit {
        match validation.step() {
            Next::Ask(ask) => {
                assert!(
                    matches!(ask.qtype, RecordType::DS | RecordType::DNSKEY),
                    "asked for {}",
                    ask.qtype
                );
                assert!(asked < limit, "asked past the limit");
                let pick = data.get(asked.wrapping_add(12)).copied().unwrap_or(2);
                let answer = match pick % 5 {
                    0 => None,
                    1 => Some(answering(&response, &ask)),
                    2 => captured(&ask).map(|(_, message)| message.clone()),
                    3 => captured(&ask).and_then(|(wire, _)| {
                        let mut wire = wire.clone();
                        let at = usize::from(pick).saturating_mul(asked + 7) % wire.len().max(1);
                        *wire.get_mut(at)? ^= 1 << (pick % 8);
                        Some(Message::decode(&wire).ok()?.message.into_owned())
                    }),
                    _ => POOL
                        .get(usize::from(pick) % POOL.len().max(1))
                        .map(|(_, message)| answering(message, &ask)),
                };
                validation.answer(answer.as_ref());
            }
            Next::Done(verdict) => {
                if let Some(ede) = verdict.ede() {
                    assert!(!ede.text.is_empty(), "no text for {verdict:?}");
                }
                return;
            }
        }
    }
    unreachable!("a validation asks at most the limit, then ends");
}

/// A CoAP datagram (RFC 7252 §3) read, written back and read again, and given to a client exchange as the
/// response, with the Block option read from it and a body sliced by it: never a panic, and what is read is
/// written as a message that reads the same.
///
/// # Panics
///
/// On a bug in the codec.
pub fn parse_coap(data: &[u8]) {
    let Ok(message) = CoapMessage::parse(data) else {
        return;
    };
    let wire = message.to_vec().expect("a message that was read writes");
    assert_eq!(
        CoapMessage::parse(&wire).as_ref(),
        Ok(&message),
        "read back differently"
    );
    let _ = message.unknown_critical().count();
    let _ = (message.options.block1(), message.options.block2());
    let _ = (
        message.options.content_format(),
        message.options.accept(),
        message.options.max_age(),
        message.options.size1(),
        message.options.size2(),
    );
    // As the response to a request of that token and message ID, so that the exchange takes it for its own.
    let server = SocketAddr::from(([127, 0, 0, 1], 5683));
    let request = Request {
        code: Code::FETCH,
        options: dedens_net::coap::Options::new(),
        payload: data.to_vec(),
        token: message.token,
    };
    let now = std::time::Instant::now();
    let step = Exchange::start(request, server, Params::default(), message.id, 1, now);
    if let dedens_net::coap::exchange::Next::Wait(exchange) = step.next {
        let _ = exchange.receive(server, data, now);
    }
    let body = [0_u8; 3000];
    let requested = message.options.block2().ok().flatten();
    if let Ok(sliced) = slice(&body, requested, BlockSize::MAX) {
        assert!(sliced.payload.len() <= BlockSize::MAX.bytes());
    }
    let value = message.payload.get(..3).unwrap_or(&message.payload);
    if let Ok(block) = Block::from_value(value) {
        assert_eq!(Block::from_value(&block.to_value()), Ok(block));
    }
}
