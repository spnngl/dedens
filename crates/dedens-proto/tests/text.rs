//! Presentation format of names, codes and records (RFC 1035 §5.1, RFC 3597 §5, RFC 4343 §2.1), and zone files.

use dedens_proto::rdata::RData;
use dedens_proto::{
    Class, DecodeErrorKind, DecodedRecord, Name, NameError, Record, RecordType, TextError,
    TextErrorKind, Ttl, ZoneEntry, ZoneReader,
};
use dedens_testkit::dns;
use proptest::prelude::*;

use crate::util::{data_class, data_type, decode_record, record_wire, zone_record};

fn parse(text: &str) -> Result<Record<'static>, TextError> {
    text.parse()
}

/// Where and why `text` is refused.
fn error(text: &str) -> (usize, usize, TextErrorKind) {
    let e = parse(text).expect_err("refused");
    (e.line, e.column, e.kind)
}

/// One record of each supported type, as written.
const EVERY_TYPE: &str = r#"
a.example.	300	IN	A	192.0.2.1
aaaa.example.	300	IN	AAAA	2001:db8::1
example.	86400	IN	NS	ns1.example.
www.example.	300	IN	CNAME	web.example.
1.2.0.192.in-addr.arpa.	300	IN	PTR	a.example.
example.	3600	IN	SOA	ns1.example. host\.master.example. 2026102701 7200 3600 1209600 300
example.	300	IN	MX	10 mail.example.
example.	300	IN	TXT	"v=spf1 -all" "a \"quoted\" \\ \009\255"
_sip._udp.example.	300	IN	SRV	10 60 5060 sip.example.
example.	300	IN	CAA	128 issue "ca.example; account=1"
_dns.example.	300	IN	SVCB	1 dns.example. alpn="dot,h2" port=853 dohpath="/q{?dns}"
example.	300	IN	HTTPS	1 . alpn="h3,h2" ipv4hint=192.0.2.1,192.0.2.2 ech=AQID ipv6hint=2001:db8::1
example.	86400	IN	DNSKEY	256 3 5 AQPSKmynfzW4kyBv015MUG2DeIQ3Cbl+BBZH4b/0PY1kxkmvHjcZc8nokfzj31GajIQKY+5CptLr3buXA10hWqTkF7H6RfoRqXQeogmMHfpftf6zMv1LyBUgia7za6ZEzOJBOztyvhjL742iU/TpPSEDhm2SNKLijfUppn1UaNvv4w==
example.	300	IN	CDNSKEY	0 3 0 AA==
dskey.example.	86400	IN	DS	60485 5 1 2bb183af5f22588179a53b0a98631fad1a292118
example.	300	IN	CDS	0 0 0 00
host.example.	86400	IN	RRSIG	A 5 3 86400 20030322173103 20030220173103 2642 example. oJB1W6WNGv+ldvQ3WDG0MQkg5IEhjRip8WTrPYGv07h108dUKGMeDPKijVCHX3DDKdfb+v6oB9wfuh3DTJXUAfI/M0zmO/zz8bW0RznlGNazPwQKkRN20XPXV6nwwfoXmJQbsLNrLfkGJ5D6fwFm8nN+6pBzeDQfsS3Ap3o=
alfa.example.	86400	IN	NSEC	host.example. A MX RRSIG NSEC TYPE1234
0p9mhaveqvm6t7vbl5lop2u3t2rp3tom.example.	3600	IN	NSEC3	1 1 12 aabbccdd 2t7b4g4vsa5smi47k61mv5bv1a22bojr NS SOA MX RRSIG DNSKEY NSEC3PARAM
example.	3600	IN	NSEC3PARAM	1 0 12 aabbccdd
example.	300	IN	TYPE65280	\# 3 abcdef
"#;

fn every_type() -> Vec<Record<'static>> {
    EVERY_TYPE
        .lines()
        .filter(|l| !l.is_empty())
        .map(|l| parse(l).unwrap_or_else(|e| unreachable!("{l}: {e}")))
        .collect()
}

#[test]
fn every_type_writes_back_as_read() {
    let records = every_type();
    let written: Vec<String> = records.iter().map(ToString::to_string).collect();
    let read: Vec<&str> = EVERY_TYPE.lines().filter(|l| !l.is_empty()).collect();
    assert_eq!(written, read);
}

#[test]
fn every_type_in_generic_form() {
    let generic: Vec<String> = every_type()
        .iter()
        .map(|r| r.generic().to_string())
        .collect();
    insta::assert_snapshot!(generic.join("\n"));
}

#[test]
fn ttl_and_class_in_either_order_class_defaults_to_in() {
    let expected = parse("x. 60 IN A 192.0.2.1").unwrap();
    for text in [
        "x. IN 60 A 192.0.2.1",
        "x. 60 A 192.0.2.1",
        "x 1m a 192.0.2.1",
    ] {
        assert_eq!(parse(text).unwrap(), expected, "{text}");
    }
    let chaos = parse("x. 60 CH TXT a").unwrap();
    assert_eq!(chaos.class, Class::CH);
}

#[test]
fn ttl_takes_units_and_is_written_in_seconds() {
    let rec = parse("x. 1w2d3h4m5s A 192.0.2.1").unwrap();
    assert_eq!(rec.ttl, Ttl::new(788_645).unwrap());
    assert!(rec.to_string().starts_with("x.\t788645\t"));
    // RFC 2181 §8: at most 2^31 - 1.
    assert_eq!(
        error("x. 2147483648 A 192.0.2.1"),
        (1, 4, TextErrorKind::Invalid("TTL"))
    );
    assert_eq!(error("x. A 192.0.2.1"), (1, 4, TextErrorKind::NoTtl));
}

/// RFC 6895 §3.1-3.2: records have data types and classes only; `ANY` is refused as either.
#[test]
fn query_and_meta_codes_are_refused() {
    let class = TextErrorKind::Invalid("class: a query or meta class");
    let rtype = TextErrorKind::Invalid("record type: a query or meta type");
    assert_eq!(error(r"x. 60 ANY TYPE731 \# 0"), (1, 7, class));
    assert_eq!(error(r"x. 60 NONE A 192.0.2.1"), (1, 7, class));
    assert_eq!(error(r"x. 60 CLASS0 A 192.0.2.1"), (1, 7, class));
    assert_eq!(error(r"x. 60 CLASS57344 A 192.0.2.1"), (1, 7, class));
    for meta in [
        "ANY",
        "OPT",
        "AXFR",
        "IXFR",
        "TYPE0",
        "TYPE250",
        "TYPE65535",
    ] {
        assert_eq!(
            error(&format!(r"x. 60 {meta} \# 0")),
            (1, 7, rtype),
            "{meta}"
        );
    }
    assert!(parse(r"x. 60 CLASS65280 TYPE65280 \# 0").is_ok());
}

#[test]
fn codes_read_mnemonics_any_case_and_generic_forms() {
    assert_eq!("aaaa".parse::<RecordType>(), Ok(RecordType::AAAA));
    assert_eq!("type28".parse::<RecordType>(), Ok(RecordType::AAAA));
    assert_eq!("TYPE65280".parse::<RecordType>(), Ok(RecordType(65280)));
    assert_eq!("in".parse::<Class>(), Ok(Class::IN));
    assert_eq!("CLASS65535".parse::<Class>(), Ok(Class(65535)));
    for bad in ["TYPE", "TYPE65536", "TYPE+1", "TYPE 1", "AAAAA", "CLASS1x"] {
        assert!(bad.parse::<RecordType>().is_err(), "{bad}");
        assert!(bad.parse::<Class>().is_err(), "{bad}");
    }
}

/// RFC 1035 §5.1: `\X` is X, `\DDD` the byte of that value; RFC 4343 §2.1: escapes keep their case.
#[test]
fn names_read_escapes_and_keep_case() {
    let name: Name<'_> = r"A\.b\065\032c.Ex\\ample.".parse().unwrap();
    let labels: Vec<&[u8]> = name.labels().collect();
    assert_eq!(labels, [&b"A.bA c"[..], b"Ex\\ample"]);
    assert_eq!(name.to_string(), r"A\.bA\032c.Ex\\ample.");
    assert_eq!("example".parse::<Name<'_>>().unwrap(), dns("example."));
    assert_eq!(".".parse::<Name<'_>>().unwrap(), Name::root());
    assert_eq!("@".parse::<Name<'_>>().unwrap(), Name::root());
    for bad in ["a..b.", ".a.", r"a\256.", r"a\1.", r"a\"] {
        assert!(bad.parse::<Name<'_>>().is_err(), "{bad}");
    }
    let kind = |text: String| text.parse::<Name<'_>>().map(|_| ()).map_err(|e| e.kind);
    let label_too_long = Err(TextErrorKind::Name(NameError::LabelTooLong));
    assert_eq!(kind(format!("{}.", "a".repeat(64))), label_too_long);
    // Over the 255 bytes of a name too, but the label is what breaks first.
    assert_eq!(kind(format!("{}.", "a".repeat(300))), label_too_long);
    assert_eq!(
        kind(format!("{}.", vec!["a".repeat(63); 4].join("."))),
        Err(TextErrorKind::Name(NameError::NameTooLong))
    );
}

#[test]
fn errors_say_where() {
    assert_eq!(
        error("x. 60 A 192.0.2.256"),
        (1, 9, TextErrorKind::Invalid("IPv4 address"))
    );
    assert_eq!(
        error("x. 60 MX 10"),
        (1, 12, TextErrorKind::Missing("MX exchange"))
    );
    assert_eq!(
        error("x. 60 A 192.0.2.1 extra"),
        (1, 19, TextErrorKind::Trailing)
    );
    assert_eq!(
        error("x. 60 ( A\n 192.0.2.1 ) y"),
        (2, 14, TextErrorKind::Trailing)
    );
    assert_eq!(
        error("x. 60 BOGUS 1"),
        (1, 7, TextErrorKind::Invalid("record type"))
    );
    assert_eq!(
        error("x. 60 TYPE731 ab"),
        (1, 15, TextErrorKind::NeedsGeneric)
    );
    // After the last field, on the line where it ends.
    assert_eq!(
        error("x. 60 CAA 0 \"is\\\nsue\""),
        (2, 5, TextErrorKind::Missing("CAA value"))
    );
    assert_eq!(error(" 60 A 192.0.2.1"), (1, 2, TextErrorKind::NoOwner));
    assert_eq!(
        error("x. 60 A 192.0.2.1\ny. 60 A 192.0.2.1"),
        (2, 1, TextErrorKind::Trailing)
    );
    assert_eq!(error(""), (1, 1, TextErrorKind::Missing("record")));
}

#[test]
fn txt_strings_are_at_most_255_bytes() {
    let ok = format!("x. 60 TXT {}", "a".repeat(255));
    assert!(parse(&ok).is_ok());
    let long = format!("x. 60 TXT b {}", "a".repeat(256));
    assert_eq!(
        error(&long),
        (
            1,
            13,
            TextErrorKind::Txt(dedens_proto::rdata::TxtError::StringTooLong)
        )
    );
}

/// RFC 1035 §3.2.1: RDLENGTH is 16 bits, so text that holds more RDATA is refused rather than failing to write.
#[test]
fn rdata_over_65535_bytes_is_refused() {
    let string = format!("\"{}\"", "a".repeat(255));
    let fits = vec![string.as_str(); 255].join(" ");
    assert!(parse(&format!("x. 60 TXT {fits}")).is_ok());
    let over = vec![string.as_str(); 257].join(" ");
    let e = parse(&format!("x. 60 TXT {over}")).expect_err("refused");
    assert_eq!(
        e.kind,
        TextErrorKind::Txt(dedens_proto::rdata::TxtError::TooLong)
    );
    assert_eq!(
        error(r"x. 60 TYPE731 \# 65536 00"),
        (1, 15, TextErrorKind::Invalid("\\# length, over 65535"))
    );
    let value = "a".repeat(65535);
    let e = parse(&format!("x. 60 CAA 0 issue {value}")).expect_err("refused");
    assert_eq!(
        e.kind,
        TextErrorKind::Invalid("CAA value: RDATA over 65535 bytes")
    );
    let alpn = vec!["a".repeat(255); 230].join(",");
    let key9 = "b".repeat(10_000);
    let e = parse(&format!("x. 60 SVCB 1 . alpn={alpn} key9={key9}")).expect_err("refused");
    assert_eq!(
        e.kind,
        TextErrorKind::SvcParams(dedens_proto::rdata::SvcParamsError::TooLong)
    );
}

/// RFC 1035 §5.1: only a token that starts with `"` is quoted; names are never quoted.
#[test]
fn quotes_start_tokens_and_never_names() {
    let rec = parse(r#"x. 60 TXT a"b c"d"#).unwrap();
    assert_eq!(rec.data().to_string(), r#""a\"b" "c\"d""#);
    // Only SVCB parameters quote after `=` (RFC 9460 §2.1).
    let rec = parse(r#"x. 60 TXT k="v w""#).unwrap();
    assert_eq!(rec.data().to_string(), r#""k=\"v" "w\"""#);
    assert_eq!(
        error(r#""a b". 60 A 192.0.2.1"#),
        (
            1,
            1,
            TextErrorKind::Invalid("domain name: a quote must be escaped")
        )
    );
    assert_eq!(
        error(r#"x. 60 CAA 0 "issue" "ca""#),
        (
            1,
            13,
            TextErrorKind::Invalid("CAA tag: 1 to 15 letters or digits, unquoted")
        )
    );
}

/// One record of a zone, kept with why its RDATA is opaque, if it is.
fn zone_entry(text: &str) -> Result<DecodedRecord<'static>, TextError> {
    match ZoneReader::new(text.as_bytes(), None).next() {
        Some(Ok(ZoneEntry::Record(decoded))) => Ok(decoded),
        Some(Err(e)) => Err(e),
        other => unreachable!("not one record: {other:?}"),
    }
}

/// D9: RDATA invalid for its type is kept opaque by a zone reader, with the reason, read from text as from the
/// wire; a lone record has nowhere to put the reason and refuses it.
#[test]
fn invalid_generic_rdata_of_a_known_type_stays_opaque() {
    let decoded = zone_entry(r"x. 60 A \# 3 c00002").unwrap();
    assert!(decoded.invalid_rdata.is_some());
    let rec = decoded.record;
    assert!(matches!(&rec.data(), RData::Opaque(o) if o.rtype() == RecordType::A));
    assert_eq!(rec.to_string(), "x.\t60\tIN\tA\t\\# 3 c00002");
    assert_eq!(
        error(r"x. 60 A \# 3 c00002"),
        (1, 1, TextErrorKind::Rdata(DecodeErrorKind::RdataLength))
    );
    assert!(matches!(
        error(r"x. 60 NS \# 1 01").2,
        TextErrorKind::Rdata(_)
    ));
}

proptest! {
    /// Whatever a record of a data type and class decoded from the wire holds, its text reads back the same (D9,
    /// RFC 3597 §5). Zone files refuse the other types and classes (RFC 6895 §3.1-3.2).
    #[test]
    fn wire_records_read_back_from_text(
        rtype in prop_oneof![
            Just(RecordType::A),
            Just(RecordType::AAAA),
            Just(RecordType::TXT),
            Just(RecordType::CAA),
            Just(RecordType::SVCB),
            Just(RecordType::HTTPS),
            Just(RecordType::MX),
            Just(RecordType::SOA),
            data_type(),
        ],
        class in data_class(),
        data in prop::collection::vec(any::<u8>(), 0..40),
    ) {
        let mut wire = record_wire(rtype, &data);
        // After the root owner and the type.
        wire[3..5].copy_from_slice(&class.0.to_be_bytes());
        let Ok(decoded) = decode_record(&wire) else {
            return Err(TestCaseError::reject("invalid RDATA of a type with names"));
        };
        let text = decoded.record.to_string();
        let read = zone_entry(&text).map_err(|e| TestCaseError::fail(format!("{text}: {e}")))?;
        // The offsets of the reasons differ: in the message, and in the RDATA.
        prop_assert_eq!(read.invalid_rdata.map(|e| e.kind), decoded.invalid_rdata.map(|e| e.kind));
        prop_assert_eq!(read.record, decoded.record);
    }

    #[test]
    fn records_read_back_as_written(rec in zone_record()) {
        let text = rec.to_string();
        let read = parse(&text).map_err(|e| TestCaseError::fail(format!("{text}: {e}")))?;
        prop_assert_eq!(&read, &rec);
        prop_assert_eq!(read.to_string(), text);
    }

    #[test]
    fn generic_records_read_back_typed(rec in zone_record()) {
        let text = rec.generic().to_string();
        let read = parse(&text).map_err(|e| TestCaseError::fail(format!("{text}: {e}")))?;
        prop_assert_eq!(read, rec);
    }

    #[test]
    fn reading_never_panics(text in "[ -~\t\n\r]{0,400}") {
        let _ = parse(&text);
    }

    #[test]
    fn rdata_text_is_one_line(data in crate::util::rdata()) {
        prop_assert!(!data.to_string().contains('\n'));
        prop_assert!(!matches!(data, RData::Opaque(_)) || data.to_string().starts_with("\\#"));
    }
}

mod zone {
    //! RFC 1035 §5: zone files (`$ORIGIN`, `$INCLUDE`, owner, TTL and class defaults), and `$TTL` of RFC 2308 §4.

    use std::fmt::Write as _;
    use std::fs;

    use dedens_proto::rdata::{RData, Soa};
    use dedens_proto::{
        Class, DecodedRecord, Record, RecordType, TextError, TextErrorKind, Ttl, ZoneEntry,
        ZoneReader,
    };
    use dedens_testkit::dns;
    use proptest::prelude::*;

    use crate::util::zone_record;

    /// Every record of `reader`, `$INCLUDE`s read from `testdata/zones/` through `files`, which maps their names.
    fn read(
        reader: &mut ZoneReader<'_>,
        files: &[(&str, &str)],
    ) -> Result<Vec<Record<'static>>, TextError> {
        let mut records = Vec::new();
        while let Some(entry) = reader.next() {
            match entry? {
                ZoneEntry::Record(r) => records.push(r.record),
                ZoneEntry::Include { file, origin } => {
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
        fs::read(dedens_testkit::path("zones").join(name)).expect("zone file")
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
        let RData::Soa(Soa { rname, .. }) = &records[0].data() else {
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
    fn s5_1_line_is_where_the_last_entry_ends() {
        let text =
            "; comment\n\nwww 60 A 192.0.2.1\n\n$ORIGIN a.\nsoa 60 SOA ns h (\n 1 2 3\n 4 5 )\n";
        let mut reader = ZoneReader::new(text.as_bytes(), Some(dns("example.")));
        assert_eq!(reader.line(), 1);
        let mut ends = Vec::new();
        while let Some(entry) = reader.next() {
            entry.unwrap();
            ends.push(reader.line());
        }
        // The `$ORIGIN` is no entry; a parenthesized record ends on the line of its last token.
        assert_eq!(ends, [3, 8]);
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
        let records =
            zone("a 60 A 192.0.2.1\n\t60 A 192.0.2.2\n  ; comment\n\n\t60 TXT x\n").unwrap();
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
            Some(Ok(ZoneEntry::Include {
                file: "my file.zone".to_owned(),
                origin: Some(dns("sub.a.")),
            }))
        );
        assert_eq!(
            reader.next(),
            Some(Ok(ZoneEntry::Include {
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
        let Some(Ok(ZoneEntry::Record(DecodedRecord { record: rec, .. }))) = reader.next() else {
            unreachable!("a record follows")
        };
        assert_eq!((rec.name, rec.ttl.get()), (dns("x.a."), 5));
    }

    #[test]
    fn included_files_keep_the_defaults() {
        let mut reader = ZoneReader::new(b"$TTL 7\na CH TXT x\n", Some(dns("p.")));
        reader.next();
        let child: Vec<_> = reader.include(b"b TXT y\n", Some(dns("q."))).collect();
        let Some(Ok(ZoneEntry::Record(DecodedRecord { record: rec, .. }))) =
            child.into_iter().next()
        else {
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
            error("a 60 NXT b 0102"),
            (1, 10, TextErrorKind::NeedsGeneric)
        );
    }

    /// Character-strings in types without a typed form: HINFO (RFC 1035 §3.3.2), NAPTR (RFC 3403 §4.1), both as
    /// written by BIND and read back.
    #[test]
    fn character_strings_of_hinfo_and_naptr_read_back() {
        let text = "a 60 HINFO \"Intel i9\" Linux\n\
                    b 60 NAPTR 100 10 \"S\" \"SIP+D2U\" \"\" _sip._udp\n";
        let records = zone(text).unwrap();
        let written = lines(&records);
        assert_eq!(
            written,
            [
                "a.example.\t60\tIN\tHINFO\t\"Intel i9\" \"Linux\"",
                "b.example.\t60\tIN\tNAPTR\t100 10 \"S\" \"SIP+D2U\" \"\" _sip._udp.example.",
            ]
        );
        assert_eq!(zone(&written.join("\n")).unwrap(), records);
        assert!(matches!(
            error(&format!("a 60 HINFO {} os", "x".repeat(256))).2,
            TextErrorKind::Invalid(_)
        ));
    }

    /// D9: `\#` bytes invalid for their type are kept opaque, and the reader says why.
    #[test]
    fn invalid_generic_rdata_is_reported() {
        let mut reader = ZoneReader::new(
            b"a 60 A \\# 3 c00002\nb 60 A \\# 4 c0000201\n",
            Some(dns("p.")),
        );
        let Some(Ok(ZoneEntry::Record(invalid))) = reader.next() else {
            unreachable!("a record")
        };
        assert!(matches!(invalid.record.data(), RData::Opaque(_)));
        assert!(invalid.invalid_rdata.is_some());
        let Some(Ok(ZoneEntry::Record(valid))) = reader.next() else {
            unreachable!("a record")
        };
        assert!(matches!(valid.record.data(), RData::A(_)));
        assert_eq!(valid.invalid_rdata, None);
    }

    /// RFC 1035 §5.1: a line end outside quotes and parentheses ends the entry, even after a `="` or a `\`.
    #[test]
    fn entries_never_join() {
        let records = zone("x 60 TXT a=\"b\ny 60 TXT \"c\"\n").unwrap();
        assert_eq!(
            lines(&records),
            [
                "x.example.\t60\tIN\tTXT\t\"a=\\\"b\"",
                "y.example.\t60\tIN\tTXT\t\"c\"",
            ]
        );
        assert_eq!(
            error("x 60 TXT a\\\ny 60 A 192.0.2.1\n"),
            (
                1,
                11,
                TextErrorKind::Invalid("escape: a \\ that ends a line outside quotes")
            )
        );
    }

    proptest! {
        #[test]
        fn written_records_read_back_as_a_zone(records in prop::collection::vec(zone_record(), 0..8)) {
            let text = records.iter().fold(String::new(), |mut text, r| {
                writeln!(text, "{r}").expect("writes to a String");
                text
            });
            let read: Result<Vec<_>, _> = ZoneReader::new(text.as_bytes(), None)
                .map(|e| match e {
                    Ok(ZoneEntry::Record(r)) => Ok(r.record),
                    Ok(_) => unreachable!("no directive written"),
                    Err(e) => Err(e),
                })
                .collect();
            prop_assert_eq!(read, Ok(records));
        }
    }

    /// Files written on Windows read the same.
    #[test]
    fn crlf_line_ends() {
        let records =
            zone("$TTL 60\r\na A 192.0.2.1\r\n  TXT ( \"x\"\r\n  \"y\" )\r\n").expect("reads");
        assert_eq!(
            lines(&records),
            [
                "a.example.\t60\tIN\tA\t192.0.2.1",
                "a.example.\t60\tIN\tTXT\t\"x\" \"y\""
            ]
        );
    }

    /// RFC 6895 §3.1-3.2: query and meta types and classes are not record types or classes.
    #[test]
    fn query_and_meta_codes_are_refused() {
        let meta_type = TextErrorKind::Invalid("record type: a query or meta type");
        for (text, column) in [
            ("a 60 ANY \\# 0", 6),
            ("a 60 AXFR \\# 0", 6),
            ("a 60 OPT \\# 0", 6),
            ("a 60 TYPE0 \\# 0", 6),
            ("a 60 TYPE65535 \\# 0", 6),
        ] {
            assert_eq!(error(text), (1, column, meta_type), "{text}");
        }
        let meta_class = TextErrorKind::Invalid("class: a query or meta class");
        for text in [
            "a 60 NONE A 192.0.2.1",
            "a 60 ANY A 192.0.2.1",
            "a 60 CLASS0 A 192.0.2.1",
        ] {
            assert_eq!(error(text), (1, 6, meta_class), "{text}");
        }
        assert!(zone("a 60 CH A 192.0.2.1").is_ok());
    }

    /// Names are never quoted; a quote in a name must be escaped (as BIND requires).
    #[test]
    fn quoted_names_are_refused() {
        assert_eq!(
            error("\"a b\" 60 A 192.0.2.1"),
            (
                1,
                1,
                TextErrorKind::Invalid("domain name: a quote must be escaped")
            )
        );
        let records = zone("a\\\"b 60 A 192.0.2.1").expect("reads");
        assert_eq!(lines(&records), ["a\\\"b.example.\t60\tIN\tA\t192.0.2.1"]);
    }

    /// RDATA over 65535 bytes cannot be encoded, so it is refused when read.
    #[test]
    fn rdata_over_65535_bytes_is_refused() {
        let strings = vec![format!("\"{}\"", "a".repeat(255)); 300].join(" ");
        assert!(zone(&format!("a 60 TXT {strings}")).is_err());
        let strings = vec![format!("\"{}\"", "a".repeat(255)); 250].join(" ");
        assert!(zone(&format!("a 60 TXT {strings}")).is_ok());
    }

    /// Zone-file tokens, so that random entries get past the lexer.
    const TOKENS: &[&str] = &[
        "$ORIGIN",
        "$TTL",
        "$INCLUDE",
        "@",
        ".",
        "a",
        "a.b.",
        "\\#",
        "0",
        "1",
        "60",
        "1w2d",
        "IN",
        "CH",
        "ANY",
        "A",
        "AAAA",
        "NS",
        "SOA",
        "MX",
        "TXT",
        "SRV",
        "CAA",
        "SVCB",
        "HTTPS",
        "TYPE731",
        "192.0.2.1",
        "::1",
        "\"x y\"",
        "\"",
        "(",
        ")",
        ";c",
        "\n",
        "\r\n",
        " ",
        "\\",
        "\\0",
        "\\255",
        "alpn=h2",
        "port=53",
        "ech=AQID",
        "mandatory=alpn",
        "key9=\"a\"",
        "abcd",
        "AQID",
    ];

    proptest! {
        #[test]
        fn reading_bytes_never_panics(data in prop::collection::vec(any::<u8>(), 0..2048)) {
            for entry in ZoneReader::new(&data, Some(dns("example."))) {
                if entry.is_err() {
                    break;
                }
            }
        }

        #[test]
        fn reading_tokens_never_panics(tokens in prop::collection::vec(prop::sample::select(TOKENS), 0..60)) {
            let text = tokens.join(" ");
            for entry in ZoneReader::new(text.as_bytes(), Some(dns("example."))) {
                let Ok(ZoneEntry::Record(DecodedRecord { record: r, .. })) = entry else {
                    continue;
                };
                let again: Record<'_> = r.to_string().parse().map_err(|e| TestCaseError::fail(format!("{r}: {e}")))?;
                prop_assert_eq!(again, r);
            }
        }
    }

    /// The fuzzing seed with every type reads in full, so that fuzzing starts from valid entries.
    #[test]
    fn the_fuzzing_seed_reads() {
        let text = zone_file("every_type.zone");
        let records = read(&mut ZoneReader::new(&text, None), &[]).expect("reads");
        assert_eq!(records.len(), 40);
    }
}
