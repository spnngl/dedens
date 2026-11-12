//! Targets of dedens-proto, and of the dedens-scenario query files built on it: messages and queries off the
//! wire, read by hickory-proto too; names, zone files and query files from text.

use dedens_proto::edns::EdnsView;
use dedens_proto::rdata::{RData, SvcParam};
use dedens_proto::{
    DecodeErrorKind, DecodedRecord, EncodeError, Flags, Message, Name, Query, Question, Record,
    RecordType, Section, Ttl, Violation, ZoneEntry, ZoneReader, ttl_offsets,
};
use dedens_scenario::QueryFile;
use hickory_proto::op::{Message as HickoryMessage, OpCode};
use hickory_proto::rr::rdata::opt::{EdnsCode, EdnsOption};
use hickory_proto::rr::{RData as HickoryRData, RecordType as HickoryRecordType};
use hickory_proto::serialize::binary::DecodeError as HickoryDecodeError;

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
/// byte, and its generic form (RFC 3597 §5) reads back to it too. The text read as one record, as `FromStr` does,
/// is written and read back to the same record.
///
/// # Panics
///
/// On a disagreement, or a bug in the reader or writer.
pub fn parse_zone(data: &[u8]) {
    if let Ok(text) = std::str::from_utf8(data)
        && let Ok(record) = text.parse::<Record<'_>>()
    {
        let shown = record.to_string();
        let again: Record<'_> = shown
            .parse()
            .unwrap_or_else(|e| panic!("`{shown}` from `{text}` reads back: {e}"));
        // `Debug` shows names as written, so this also catches a change of case, which `==` ignores.
        assert_eq!(
            format!("{again:?}"),
            format!("{record:?}"),
            "`{shown}` from `{text}`"
        );
    }
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
/// RDATA as its type (D28). Each record a zone can hold is written as text and read back to itself, RDATA its type
/// refuses for the same reason. Without violations, the encoding is conforming, and truncating it at any size keeps
/// a conforming prefix of it.
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
            ttl_offsets(data, |_| offsets += 1).map(|()| offsets)
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
    for (section, records) in [Section::Answer, Section::Authority, Section::Additional]
        .into_iter()
        .zip(records)
    {
        for (index, record) in records.iter().enumerate() {
            let invalid = decoded
                .violations
                .iter()
                .find_map(|violation| match violation {
                    Violation::InvalidRdata {
                        section: s,
                        index: i,
                        error,
                    } if (*s, *i) == (section, index) => Some(error.kind),
                    _ => None,
                });
            reads_back_from_text(record, invalid);
        }
    }
    if !decoded.violations.is_empty() {
        return;
    }
    assert_eq!(again.violations, [], "what the encoder wrote is conforming");
    let size = usize::from(data.first().copied().unwrap_or_default()) * wire.len() / 255;
    truncate(&decoded.message, size);
}

/// A record off the wire, its RDATA refused by its type for `invalid`, written as text and read back by a zone
/// reader: the same record, names byte for byte, and the same reason. Types and classes no zone holds, a query or
/// meta one, OPT among them, are skipped (RFC 6895 §3.1, §3.2), as the text reader refuses them.
fn reads_back_from_text(record: &Record<'_>, invalid: Option<DecodeErrorKind>) {
    let (rtype, class) = (u16::from(record.rtype()), u16::from(record.class));
    if record.rtype() == RecordType::OPT
        || matches!(rtype, 0 | 128..=255 | 65535)
        || matches!(class, 0 | 128..=255 | 0xE000..=0xFEFF | 65535)
    {
        return;
    }
    let text = record.to_string();
    match ZoneReader::new(text.as_bytes(), None).next() {
        Some(Ok(ZoneEntry::Record(read))) => {
            // `Debug` shows names as written, so this also catches a change of case, which `==` ignores.
            assert_eq!(
                format!("{:?}", read.record),
                format!("{record:?}"),
                "`{text}`"
            );
            assert_eq!(read.invalid_rdata.map(|e| e.kind), invalid, "`{text}`");
        }
        other => panic!("`{text}` reads back: {other:?}"),
    }
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
