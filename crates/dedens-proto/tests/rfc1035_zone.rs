//! RFC 1035 §5: zone files (`$ORIGIN`, `$INCLUDE`, owner, TTL and class defaults), and `$TTL` of RFC 2308 §4.

mod common;

use std::fmt::Write as _;
use std::fs;
use std::path::Path;

use common::{dns, record};
use dedens_proto::rdata::Soa;
use dedens_proto::text::{Entry, ZoneReader};
use dedens_proto::{Class, RData, Record, RecordType, TextError, TextErrorKind, Ttl};
use proptest::prelude::*;

/// Every record of `reader`, `$INCLUDE`s read from `tests/zones/` through `files`, which maps their names.
fn read(
    reader: &mut ZoneReader<'_>,
    files: &[(&str, &str)],
) -> Result<Vec<Record<'static>>, TextError> {
    let mut records = Vec::new();
    while let Some(entry) = reader.next() {
        match entry? {
            Entry::Record(r) => records.push(r),
            Entry::Include { file, origin } => {
                let (_, local) = files
                    .iter()
                    .find(|(name, _)| *name == file)
                    .expect("known include");
                let text = zone_file(local);
                records.extend(read(&mut reader.include(&text, origin), files)?);
            }
            _ => unreachable!("records and includes only"),
        }
    }
    Ok(records)
}

fn zone_file(name: &str) -> Vec<u8> {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/zones")
        .join(name);
    fs::read(path).expect("zone file")
}

fn zone(text: &str) -> Result<Vec<Record<'static>>, TextError> {
    read(
        &mut ZoneReader::new(text.as_bytes(), Some(dns("example."))),
        &[],
    )
}

fn lines(records: &[Record<'_>]) -> Vec<String> {
    records.iter().map(ToString::to_string).collect()
}

fn error(text: &str) -> (usize, usize, TextErrorKind) {
    let e = zone(text).expect_err("refused");
    (e.line, e.column, e.kind)
}

#[test]
fn s5_3_master_file_example() {
    let text = zone_file("rfc1035_isi.zone");
    let mut reader =
        ZoneReader::new(&text, Some(dns("ISI.EDU."))).with_ttl(Ttl::new(3600).unwrap());
    let files = [("<SUBSYS>ISI-MAILBOXES.TXT", "rfc1035_isi_mailboxes.zone")];
    let records = read(&mut reader, &files).unwrap();
    assert_eq!(
        lines(&records),
        [
            "ISI.EDU.\t3600\tIN\tSOA\tVENERA.ISI.EDU. Action\\.domains.ISI.EDU. 20 7200 600 3600000 60",
            "ISI.EDU.\t3600\tIN\tNS\tA.ISI.EDU.",
            "ISI.EDU.\t3600\tIN\tNS\tVENERA.ISI.EDU.",
            "ISI.EDU.\t3600\tIN\tNS\tVAXA.ISI.EDU.",
            "ISI.EDU.\t3600\tIN\tMX\t10 VENERA.ISI.EDU.",
            "ISI.EDU.\t3600\tIN\tMX\t20 VAXA.ISI.EDU.",
            "A.ISI.EDU.\t3600\tIN\tA\t26.3.0.103",
            "VENERA.ISI.EDU.\t3600\tIN\tA\t10.1.0.52",
            "VENERA.ISI.EDU.\t3600\tIN\tA\t128.9.0.32",
            "VAXA.ISI.EDU.\t3600\tIN\tA\t10.2.0.27",
            "VAXA.ISI.EDU.\t3600\tIN\tA\t128.9.0.33",
            "MOE.ISI.EDU.\t3600\tIN\tMB\tA.ISI.EDU.",
            "LARRY.ISI.EDU.\t3600\tIN\tMB\tA.ISI.EDU.",
            "CURLEY.ISI.EDU.\t3600\tIN\tMB\tA.ISI.EDU.",
            "STOOGES.ISI.EDU.\t3600\tIN\tMG\tMOE.ISI.EDU.",
            "STOOGES.ISI.EDU.\t3600\tIN\tMG\tLARRY.ISI.EDU.",
            "STOOGES.ISI.EDU.\t3600\tIN\tMG\tCURLEY.ISI.EDU.",
        ]
    );
    let RData::Soa(Soa { rname, .. }) = &records[0].data else {
        unreachable!("the first record is the SOA")
    };
    // "Action.domains@E.ISI.EDU": the escaped dot stays in the first label.
    assert_eq!(rname.labels().next(), Some(&b"Action.domains"[..]));
    // Without a default, the file has no TTL at all.
    let mut reader = ZoneReader::new(&text, Some(dns("ISI.EDU.")));
    let e = read(&mut reader, &files).unwrap_err();
    assert_eq!((e.line, e.kind), (3, TextErrorKind::NoTtl));
}

#[test]
fn s5_1_origin_resets_relative_names() {
    let records = zone(
        "$ORIGIN sub\nwww 60 A 192.0.2.1\n$ORIGIN other.\n@ 60 A 192.0.2.2\nx.y. 60 CNAME z\n",
    )
    .unwrap();
    assert_eq!(
        lines(&records),
        [
            "www.sub.example.\t60\tIN\tA\t192.0.2.1",
            "other.\t60\tIN\tA\t192.0.2.2",
            "x.y.\t60\tIN\tCNAME\tz.other.",
        ]
    );
    let mut reader = ZoneReader::new(b"$origin a.b.\n", None);
    assert_eq!(reader.next(), None);
    assert_eq!(reader.origin(), Some(&dns("a.b.")));
}

#[test]
fn s5_1_relative_names_need_an_origin() {
    let mut reader = ZoneReader::new(b"www 60 A 192.0.2.1", None);
    let e = reader.next().unwrap().unwrap_err();
    assert_eq!(
        (e.line, e.column, e.kind),
        (1, 1, TextErrorKind::RelativeName)
    );
    let mut reader = ZoneReader::new(b"www. 60 CNAME @", None);
    let e = reader.next().unwrap().unwrap_err();
    assert_eq!(
        (e.line, e.column, e.kind),
        (1, 15, TextErrorKind::RelativeName)
    );
}

#[test]
fn s5_1_blank_entries_repeat_the_owner() {
    let records = zone("a 60 A 192.0.2.1\n\t60 A 192.0.2.2\n  ; comment\n\n\t60 TXT x\n").unwrap();
    let owners: Vec<String> = records.iter().map(|r| r.name.to_string()).collect();
    assert_eq!(owners, ["a.example.", "a.example.", "a.example."]);
    assert_eq!(error(" 60 A 192.0.2.1"), (1, 2, TextErrorKind::NoOwner));
}

/// RFC 1035 §5.1: omitted TTL and class are the last ones written; RFC 2308 §4: `$TTL` wins over the last TTL.
#[test]
fn ttl_and_class_defaults() {
    let records = zone(concat!(
        "a CH 60 TXT x\n",
        "b TXT y\n",
        "$TTL 1h\n",
        "c IN TXT z\n",
        "d 30 TXT w\n",
        "e TXT v\n",
    ))
    .unwrap();
    let defaults: Vec<(u32, Class)> = records.iter().map(|r| (r.ttl.get(), r.class)).collect();
    assert_eq!(
        defaults,
        [
            (60, Class::CH),
            (60, Class::CH),
            (3600, Class::IN),
            (30, Class::IN),
            (3600, Class::IN),
        ]
    );
    let records = zone("a TXT x\n").map_err(|e| e.kind);
    assert_eq!(records, Err(TextErrorKind::NoTtl));
    assert_eq!(
        error("$TTL 2147483648\n"),
        (1, 6, TextErrorKind::Invalid("TTL"))
    );
}

#[test]
fn s5_1_include_is_handed_to_the_caller() {
    let text = b"$ORIGIN a.\n$INCLUDE \"my file.zone\" sub ; comment\n$INCLUDE other.zone\n$TTL 5\nx TXT y\n";
    let mut reader = ZoneReader::new(text, None);
    assert_eq!(
        reader.next(),
        Some(Ok(Entry::Include {
            file: "my file.zone".to_owned(),
            origin: Some(dns("sub.a.")),
        }))
    );
    assert_eq!(
        reader.next(),
        Some(Ok(Entry::Include {
            file: "other.zone".to_owned(),
            origin: Some(dns("a.")),
        }))
    );
    // The included file has its own origin; nothing in it changes the parent's.
    let child: Vec<_> = reader
        .include(
            b"$ORIGIN elsewhere.\n$TTL 9\nw 1 TXT v\n",
            Some(dns("sub.a.")),
        )
        .collect();
    assert_eq!(child.len(), 1);
    assert_eq!(reader.origin(), Some(&dns("a.")));
    let Some(Ok(Entry::Record(rec))) = reader.next() else {
        unreachable!("a record follows")
    };
    assert_eq!((rec.name, rec.ttl.get()), (dns("x.a."), 5));
}

#[test]
fn included_files_keep_the_defaults() {
    let mut reader = ZoneReader::new(b"$TTL 7\na CH TXT x\n", Some(dns("p.")));
    reader.next();
    let child: Vec<_> = reader.include(b"b TXT y\n", Some(dns("q."))).collect();
    let Some(Ok(Entry::Record(rec))) = child.into_iter().next() else {
        unreachable!("one record")
    };
    assert_eq!((rec.ttl.get(), rec.class), (7, Class::CH));
}

#[test]
fn directive_errors() {
    assert_eq!(
        error("$GENERATE 1-2 a$ A 192.0.2.$"),
        (1, 1, TextErrorKind::UnknownDirective)
    );
    assert_eq!(
        error("$ORIGIN"),
        (1, 8, TextErrorKind::Missing("$ORIGIN name"))
    );
    assert_eq!(error("$ORIGIN a. b."), (1, 12, TextErrorKind::Trailing));
    assert_eq!(error("$TTL x"), (1, 6, TextErrorKind::Invalid("TTL")));
    assert_eq!(
        error("$INCLUDE"),
        (1, 9, TextErrorKind::Missing("$INCLUDE file name"))
    );
}

#[test]
fn the_reader_stops_at_the_first_error() {
    let mut reader = ZoneReader::new(b"a 60 A 1\nb 60 A 192.0.2.1\n", Some(dns("p.")));
    assert!(matches!(reader.next(), Some(Err(_))));
    assert_eq!(reader.next(), None);
    assert_eq!(reader.next(), None);
}

#[test]
fn types_without_text_need_the_generic_form() {
    let records = zone("a 60 RP mbox txt\nb 60 AFSDB 1 db\nc 60 HINFO \\# 0\n").unwrap();
    assert_eq!(
        lines(&records),
        [
            "a.example.\t60\tIN\tRP\tmbox.example. txt.example.",
            "b.example.\t60\tIN\tAFSDB\t1 db.example.",
            "c.example.\t60\tIN\tHINFO\t\\# 0",
        ]
    );
    assert_eq!(records[2].rtype(), RecordType::HINFO);
    assert_eq!(
        error("a 60 HINFO cpu os"),
        (1, 18, TextErrorKind::NeedsGeneric)
    );
}

proptest! {
    #[test]
    fn written_records_read_back_as_a_zone(records in prop::collection::vec(record(), 0..8)) {
        let text = records.iter().fold(String::new(), |mut text, r| {
            writeln!(text, "{r}").expect("writes to a String");
            text
        });
        let read: Result<Vec<_>, _> = ZoneReader::new(text.as_bytes(), None)
            .map(|e| match e {
                Ok(Entry::Record(r)) => Ok(r),
                Ok(_) => unreachable!("no directive written"),
                Err(e) => Err(e),
            })
            .collect();
        prop_assert_eq!(read, Ok(records));
    }
}
