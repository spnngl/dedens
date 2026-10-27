//! Presentation format of names, codes and records (RFC 1035 §5.1, RFC 3597 §5, RFC 4343 §2.1).

mod common;

use common::{dns, record};
use dedens_proto::{Class, Name, RData, Record, RecordType, TextError, TextErrorKind, Ttl};
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

/// `ANY` is both a class and a type mnemonic: a class only before a TTL or a type.
#[test]
fn any_is_a_class_only_before_a_ttl_or_a_type() {
    let rec = parse(r"x. 60 ANY TYPE731 \# 0").unwrap();
    assert_eq!((rec.class, rec.rtype()), (Class::ANY, RecordType(731)));
    let rec = parse(r"x. 60 ANY \# 0").unwrap();
    assert_eq!((rec.class, rec.rtype()), (Class::IN, RecordType::ANY));
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
    let long = format!("{}.", "a".repeat(64));
    assert!(long.parse::<Name<'_>>().is_err());
    let too_long = format!("{}.", vec!["a".repeat(63); 4].join("."));
    assert!(too_long.parse::<Name<'_>>().is_err());
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
        (1, 17, TextErrorKind::NeedsGeneric)
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

proptest! {
    #[test]
    fn records_read_back_as_written(rec in record()) {
        let text = rec.to_string();
        let read = parse(&text).map_err(|e| TestCaseError::fail(format!("{text}: {e}")))?;
        prop_assert_eq!(&read, &rec);
        prop_assert_eq!(read.to_string(), text);
    }

    #[test]
    fn generic_records_read_back_typed(rec in record()) {
        let text = rec.generic().to_string();
        let read = parse(&text).map_err(|e| TestCaseError::fail(format!("{text}: {e}")))?;
        prop_assert_eq!(read, rec);
    }

    #[test]
    fn reading_never_panics(text in "[ -~\t\n]{0,80}") {
        let _ = parse(&text);
    }

    #[test]
    fn rdata_text_is_one_line(data in common::rdata()) {
        prop_assert!(!data.to_string().contains('\n'));
        prop_assert!(!matches!(data, RData::Opaque(_)) || data.to_string().starts_with("\\#"));
    }
}
