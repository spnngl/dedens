//! Presentation format of names, codes and records (RFC 1035 §5.1, RFC 3597 §5, RFC 4343 §2.1).

mod common;

use common::{data_class, data_type, decode_record, dns, record_wire, zone_record};
use dedens_proto::{
    Class, Name, NameError, RData, Record, RecordType, TextError, TextErrorKind, Ttl,
};
use proptest::prelude::*;

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
        error("x. 60 CAA 0 \"is\nsue\""),
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

/// D9: RDATA invalid for its type is kept opaque, read from text as from the wire.
#[test]
fn invalid_generic_rdata_of_a_known_type_stays_opaque() {
    let rec = parse(r"x. 60 A \# 3 c00002").unwrap();
    assert!(matches!(&rec.data(), RData::Opaque(o) if o.rtype() == RecordType::A));
    assert_eq!(rec.to_string(), "x.\t60\tIN\tA\t\\# 3 c00002");
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
        let read = parse(&text).map_err(|e| TestCaseError::fail(format!("{text}: {e}")))?;
        prop_assert_eq!(read, decoded.record);
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
    fn rdata_text_is_one_line(data in common::rdata()) {
        prop_assert!(!data.to_string().contains('\n'));
        prop_assert!(!matches!(data, RData::Opaque(_)) || data.to_string().starts_with("\\#"));
    }
}
