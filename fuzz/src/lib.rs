//! Fuzz entry points: one function per parser of outside data, each fed arbitrary bytes and required never
//! to panic.
//!
//! `cargo-fuzz` (nightly) reaches them through the shims in `fuzz_targets/`; `cargo test --lib` (stable,
//! `just fuzz-smoke`) replays the captured responses plus mutated variants through [`TARGETS`].

#![expect(
    clippy::panic,
    reason = "a fuzz target, and the smoke test replaying it, report a bug by panicking"
)]

use dedens_cache::{Cache, Config, Lookup, StalePolicy};
use dedens_proto::text::{Entry as ZoneEntry, ZoneReader};
use dedens_proto::{
    DecodedRecord, EdnsView, EncodeError, Flags, Message, Name, Query, Record, RecordType, Ttl,
    message,
};

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
    ("parse_name", parse_name),
];

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
        message::ttl_offsets(data).map(|offsets| offsets.len()),
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
