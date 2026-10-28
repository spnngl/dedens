//! RFC 9460: SVCB and HTTPS records (§2, §7, §8, §9, Appendix D) and RFC 9461 `dohpath`.

mod common;

use std::net::{Ipv4Addr, Ipv6Addr};

use common::{decode_record, encode_with, name_of, record, record_wire};
use dedens_proto::rdata::{SvcParam, SvcParamKey, SvcParams, SvcParamsError, Svcb};
use dedens_proto::{Class, Name, RData, Record, RecordType, Ttl};
use proptest::prelude::*;

const FOO_EXAMPLE_COM: &[u8] = b"\x03foo\x07example\x03com\x00";
const FOO_EXAMPLE_ORG: &[u8] = b"\x03foo\x07example\x03org\x00";

fn svcb(rdata: &[u8]) -> Svcb<'static> {
    let decoded = decode_record(&record_wire(RecordType::SVCB, rdata)).expect("decodes");
    assert_eq!(decoded.invalid_rdata, None);
    let RData::Svcb(svcb) = decoded.record.data else {
        unreachable!("a SVCB record decodes to SVCB data")
    };
    svcb
}

/// The RDATA is kept opaque and flagged: SVCB has no compressible names (D9).
fn rejected(rdata: &[u8]) {
    let decoded = decode_record(&record_wire(RecordType::SVCB, rdata)).expect("delimited");
    assert!(decoded.invalid_rdata.is_some(), "accepted {rdata:02x?}");
    assert!(matches!(decoded.record.data, RData::Opaque(_)));
}

fn rdata(parts: &[&[u8]]) -> Vec<u8> {
    parts.concat()
}

#[test]
fn d1_alias_mode() {
    let s = svcb(&rdata(&[&[0, 0], FOO_EXAMPLE_COM]));
    assert_eq!(s.priority(), 0);
    assert_eq!(*s.target(), name_of(&[b"foo", b"example", b"com"]));
    assert_eq!(*s.params(), SvcParams::default());
}

#[test]
fn d2_target_is_the_root() {
    let s = svcb(&[0, 1, 0]);
    assert_eq!((s.priority(), s.target().clone()), (1, Name::root()));
}

#[test]
fn d2_port() {
    let s = svcb(&rdata(&[&[0, 16], FOO_EXAMPLE_COM, &[0, 3, 0, 2, 0, 0x35]]));
    assert_eq!(s.params().iter().collect::<Vec<_>>(), [SvcParam::Port(53)]);
}

#[test]
fn d2_generic_keys() {
    let s = svcb(&rdata(&[
        &[0, 1],
        FOO_EXAMPLE_COM,
        &[0x02, 0x9b, 0, 5],
        b"hello",
    ]));
    assert_eq!(
        s.params().iter().collect::<Vec<_>>(),
        [SvcParam::Unknown {
            key: SvcParamKey(667),
            value: (*b"hello").into()
        }]
    );
    let s = svcb(&rdata(&[
        &[0, 1],
        FOO_EXAMPLE_COM,
        &[0x02, 0x9b, 0, 9],
        b"hello\xd2qoo",
    ]));
    assert_eq!(
        s.params().iter().collect::<Vec<_>>(),
        [SvcParam::Unknown {
            key: SvcParamKey(667),
            value: (*b"hello\xd2qoo").into()
        }]
    );
}

#[test]
fn d2_ipv6_hints() {
    let value = [
        0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, //
        0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x53, 0, 1,
    ];
    let s = svcb(&rdata(&[
        &[0, 1],
        FOO_EXAMPLE_COM,
        &[0, 6, 0, 0x20],
        &value,
    ]));
    let hints = vec![
        "2001:db8::1".parse::<Ipv6Addr>().unwrap(),
        "2001:db8::53:1".parse().unwrap(),
    ];
    assert_eq!(
        s.params().iter().collect::<Vec<_>>(),
        [SvcParam::Ipv6Hint(hints)]
    );
}

#[test]
fn d2_ipv6_hint_with_embedded_ipv4() {
    let value = [
        0x20, 0x01, 0x0d, 0xb8, 1, 0x22, 3, 0x44, 0, 0, 0, 0, 0xc0, 0, 2, 0x21,
    ];
    let s = svcb(&rdata(&[
        &[0, 1],
        b"\x07example\x03com\x00",
        &[0, 6, 0, 0x10],
        &value,
    ]));
    let hint = "2001:db8:122:344::192.0.2.33".parse::<Ipv6Addr>().unwrap();
    assert_eq!(
        s.params().iter().collect::<Vec<_>>(),
        [SvcParam::Ipv6Hint(vec![hint])]
    );
}

#[test]
fn d2_mandatory_alpn_and_ipv4hint() {
    let wire = rdata(&[
        &[0, 16],
        FOO_EXAMPLE_ORG,
        &[0, 0, 0, 4, 0, 1, 0, 4], // mandatory=alpn,ipv4hint
        &[0, 1, 0, 9, 2],
        b"h2",
        &[5],
        b"h3-19",
        &[0, 4, 0, 4, 0xc0, 0, 2, 1],
    ]);
    let s = svcb(&wire);
    assert_eq!(
        s.params().iter().collect::<Vec<_>>(),
        [
            SvcParam::Mandatory(vec![SvcParamKey::ALPN, SvcParamKey::IPV4HINT]),
            SvcParam::Alpn(vec![(*b"h2").into(), (*b"h3-19").into()]),
            SvcParam::Ipv4Hint(vec![Ipv4Addr::new(192, 0, 2, 1)]),
        ]
    );
    let encoded = encode_with(|w| {
        Record::new(Name::root(), Class::IN, Ttl::ZERO, RData::Svcb(s.clone())).encode(w)
    });
    assert_eq!(encoded, record_wire(RecordType::SVCB, &wire));
}

#[test]
fn d2_alpn_keeps_backslash_and_comma() {
    let wire = rdata(&[
        &[0, 16],
        FOO_EXAMPLE_ORG,
        &[0, 1, 0, 12, 8],
        b"f\\oo,bar",
        &[2],
        b"h2",
    ]);
    let s = svcb(&wire);
    assert_eq!(
        s.params().iter().collect::<Vec<_>>(),
        [SvcParam::Alpn(vec![
            (*b"f\\oo,bar").into(),
            (*b"h2").into()
        ])]
    );
}

#[test]
fn s9_https_has_the_svcb_format() {
    let wire = rdata(&[
        &[0, 1],
        FOO_EXAMPLE_COM,
        &[0, 1, 0, 3, 2, b'h', b'2', 0, 2, 0, 0],
    ]);
    let decoded = decode_record(&record_wire(RecordType::HTTPS, &wire)).unwrap();
    let RData::Https(s) = decoded.record.data else {
        panic!("not HTTPS")
    };
    assert_eq!(
        s.params().iter().collect::<Vec<_>>(),
        [
            SvcParam::Alpn(vec![(*b"h2").into()]),
            SvcParam::NoDefaultAlpn
        ]
    );
}

#[test]
fn s7_1_1_no_default_alpn_needs_alpn() {
    assert_eq!(
        SvcParams::new(vec![SvcParam::NoDefaultAlpn]),
        Err(SvcParamsError::NoDefaultAlpnWithoutAlpn)
    );
    // Not self-consistent: the record is rejected, kept opaque (RFC 9460 §2.4.3).
    let wire = rdata(&[&[0, 1], FOO_EXAMPLE_COM, &[0, 2, 0, 0]]);
    let decoded = decode_record(&record_wire(RecordType::HTTPS, &wire)).unwrap();
    assert!(decoded.invalid_rdata.is_some());
    assert!(matches!(decoded.record.data, RData::Opaque(_)));
}

#[test]
fn rfc9461_dohpath() {
    let wire = rdata(&[&[0, 1], FOO_EXAMPLE_COM, &[0, 7, 0, 10], b"/dns{?dns}"]);
    let s = svcb(&wire);
    assert_eq!(
        s.params().iter().collect::<Vec<_>>(),
        [SvcParam::DohPath("/dns{?dns}".into())]
    );
    assert_eq!(
        s.params().get(SvcParamKey::DOHPATH),
        s.params().iter().next()
    );
}

#[test]
fn s2_2_the_target_is_never_compressed() {
    // A pointer in the target: the record keeps its bytes opaque rather than following it.
    rejected(&[0, 1, 0xC0, 0]);
}

#[test]
fn d3_duplicate_keys() {
    let wire = rdata(&[
        &[0, 1],
        FOO_EXAMPLE_COM,
        &[0x00, 0x7b, 0, 3],
        b"abc",
        &[0x00, 0x7b, 0, 3],
        b"def",
    ]);
    rejected(&wire);
}

#[test]
fn s2_2_keys_must_increase() {
    rejected(&rdata(&[
        &[0, 1],
        FOO_EXAMPLE_COM,
        &[0, 3, 0, 2, 0, 53, 0, 1, 0, 3, 2, b'h', b'2'],
    ]));
}

#[test]
fn d3_values_that_must_not_be_empty() {
    for key in [0u8, 1, 3, 4, 6] {
        rejected(&rdata(&[&[0, 1], FOO_EXAMPLE_COM, &[0, key, 0, 0]]));
    }
}

#[test]
fn d3_no_default_alpn_must_be_empty() {
    rejected(&rdata(&[&[0, 1], FOO_EXAMPLE_COM, &[0, 2, 0, 3], b"abc"]));
}

#[test]
fn d3_a_mandatory_key_is_missing() {
    rejected(&rdata(&[&[0, 1], FOO_EXAMPLE_COM, &[0, 0, 0, 2, 0, 123]]));
}

#[test]
fn d3_mandatory_lists_itself() {
    rejected(&rdata(&[&[0, 1], FOO_EXAMPLE_COM, &[0, 0, 0, 2, 0, 0]]));
}

#[test]
fn d3_mandatory_lists_a_key_twice() {
    let wire = rdata(&[
        &[0, 1],
        FOO_EXAMPLE_COM,
        &[0, 0, 0, 4, 0, 123, 0, 123, 0, 123, 0, 3],
        b"abc",
    ]);
    rejected(&wire);
}

#[test]
fn s7_port_is_exactly_two_bytes() {
    rejected(&rdata(&[&[0, 1], FOO_EXAMPLE_COM, &[0, 3, 0, 3, 0, 53, 0]]));
}

#[test]
fn s7_3_hints_are_whole_addresses() {
    rejected(&rdata(&[&[0, 1], FOO_EXAMPLE_COM, &[0, 4, 0, 3, 1, 2, 3]]));
    rejected(&rdata(&[
        &[0, 1],
        FOO_EXAMPLE_COM,
        &[0, 6, 0, 4, 1, 2, 3, 4],
    ]));
}

#[test]
fn s7_1_alpn_ids_are_not_empty_and_fill_the_value() {
    rejected(&rdata(&[&[0, 1], FOO_EXAMPLE_COM, &[0, 1, 0, 1, 0]]));
    rejected(&rdata(&[
        &[0, 1],
        FOO_EXAMPLE_COM,
        &[0, 1, 0, 3, 5, b'h', b'2'],
    ]));
}

#[test]
fn key_65535_is_reserved() {
    rejected(&rdata(&[&[0, 1], FOO_EXAMPLE_COM, &[0xFF, 0xFF, 0, 0]]));
}

#[test]
fn building_params_enforces_the_same_rules() {
    let unknown = |key| SvcParam::Unknown {
        key: SvcParamKey(key),
        value: Box::default(),
    };
    assert_eq!(
        SvcParams::new(vec![SvcParam::Port(1), SvcParam::Port(2)]),
        Err(SvcParamsError::Duplicate(SvcParamKey::PORT))
    );
    assert_eq!(
        SvcParams::new(vec![SvcParam::Alpn(vec![])]),
        Err(SvcParamsError::Empty(SvcParamKey::ALPN))
    );
    assert_eq!(
        SvcParams::new(vec![SvcParam::Mandatory(vec![SvcParamKey::PORT])]),
        Err(SvcParamsError::BadMandatory(SvcParamKey::PORT))
    );
    assert_eq!(
        SvcParams::new(vec![
            SvcParam::Mandatory(vec![SvcParamKey::PORT, SvcParamKey::PORT]),
            SvcParam::Port(1)
        ]),
        Err(SvcParamsError::MandatoryTwice(SvcParamKey::PORT))
    );
    assert_eq!(
        SvcParams::new(vec![unknown(3)]),
        Err(SvcParamsError::ReservedKey(SvcParamKey(3)))
    );
    assert_eq!(
        SvcParams::new(vec![unknown(65535)]),
        Err(SvcParamsError::ReservedKey(SvcParamKey(65535)))
    );
    let sorted = SvcParams::new(vec![
        SvcParam::Port(1),
        SvcParam::Ipv4Hint(vec![Ipv4Addr::LOCALHOST]),
    ])
    .unwrap();
    assert_eq!(
        sorted.iter().collect::<Vec<_>>(),
        [
            SvcParam::Port(1),
            SvcParam::Ipv4Hint(vec![Ipv4Addr::LOCALHOST])
        ]
    );
}

proptest! {
    #[test]
    fn svcb_and_https_round_trip(rec in record()) {
        // Every generated record, SVCB and HTTPS included, survives encode then decode.
        let wire = encode_with(|w| rec.encode(w));
        let decoded = decode_record(&wire)?;
        prop_assert_eq!(decoded.invalid_rdata, None);
        prop_assert_eq!(decoded.record, rec);
    }
}

/// Reads `example.com. 3600 <rdata>`, which must be a SVCB or HTTPS record.
fn from_text(rdata: &str) -> Result<Record<'static>, dedens_proto::TextError> {
    format!("example.com. 3600 {rdata}").parse()
}

/// RDATA of a record, encoded alone: after the root owner and the 10 fixed bytes.
fn rdata_wire(rec: &Record<'_>) -> Vec<u8> {
    let alone = Record::new(Name::root(), Class::IN, Ttl::ZERO, rec.data.clone());
    encode_with(|w| alone.encode(w))[11..].to_vec()
}

#[test]
fn appendix_d_in_presentation_format() {
    // Text, generic form and wire form of each vector of D.1 and D.2.
    let vectors: &[(&str, &str, &[u8])] = &[
        (
            "HTTPS 0 foo.example.com.",
            r"HTTPS \# 19 ( 00 00 03 66 6f 6f 07 65 78 61 6d 70 6c 65 03 63 6f 6d 00 )",
            &rdata(&[&[0, 0], FOO_EXAMPLE_COM]),
        ),
        ("SVCB 1 .", r"SVCB \# 3 ( 00 01 00 )", &[0, 1, 0]),
        (
            "SVCB 16 foo.example.com. port=53",
            r"SVCB \# 25 0010 03666f6f076578616d706c6503636f6d00 0003 0002 0035",
            &rdata(&[&[0, 16], FOO_EXAMPLE_COM, &[0, 3, 0, 2, 0, 0x35]]),
        ),
        (
            "SVCB 1 foo.example.com. key667=hello",
            r"SVCB \# 28 0001 03666f6f076578616d706c6503636f6d00 029b 0005 68656c6c6f",
            &rdata(&[&[0, 1], FOO_EXAMPLE_COM, &[0x02, 0x9b, 0, 5], b"hello"]),
        ),
        (
            r#"SVCB 1 foo.example.com. key667="hello\210qoo""#,
            r"SVCB \# 32 0001 03666f6f076578616d706c6503636f6d00 029b 0009 68656c6c6fd2716f6f",
            &rdata(&[
                &[0, 1],
                FOO_EXAMPLE_COM,
                &[0x02, 0x9b, 0, 9],
                b"hello\xd2qoo",
            ]),
        ),
        (
            "SVCB 1 foo.example.com. (\n ipv6hint=\"2001:db8::1,2001:db8::53:1\"\n )",
            concat!(
                r"SVCB \# 55 0001 03666f6f076578616d706c6503636f6d00 0006 0020",
                " 20010db8000000000000000000000001 20010db8000000000000000000530001",
            ),
            &rdata(&[
                &[0, 1],
                FOO_EXAMPLE_COM,
                &[0, 6, 0, 0x20],
                &[0x20, 1, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1],
                &[0x20, 1, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x53, 0, 1],
            ]),
        ),
        (
            "SVCB 1 example.com. ( ipv6hint=\"2001:db8:122:344::192.0.2.33\" )",
            r"SVCB \# 35 0001 076578616d706c6503636f6d00 0006 0010 20010db8012203440000 0000c0000221",
            &rdata(&[
                &[0, 1],
                b"\x07example\x03com\x00",
                &[
                    0, 6, 0, 0x10, 0x20, 1, 0x0d, 0xb8, 1, 0x22, 3, 0x44, 0, 0, 0, 0, 0xc0, 0, 2,
                    0x21,
                ],
            ]),
        ),
        (
            "SVCB 16 foo.example.org. (\n alpn=h2,h3-19 mandatory=ipv4hint,alpn\n ipv4hint=192.0.2.1\n )",
            concat!(
                r"SVCB \# 48 0010 03666f6f076578616d706c65036f726700 0000 0004 0001 0004",
                " 0001 0009 02 6832 05 68332d3139 0004 0004 c0000201",
            ),
            &rdata(&[
                &[0, 16],
                FOO_EXAMPLE_ORG,
                &[0, 0, 0, 4, 0, 1, 0, 4, 0, 1, 0, 9, 2],
                b"h2",
                &[5],
                b"h3-19",
                &[0, 4, 0, 4, 0xc0, 0, 2, 1],
            ]),
        ),
        (
            r#"SVCB 16 foo.example.org. alpn="f\\\\oo\\,bar,h2""#,
            r"SVCB \# 35 0010 03666f6f076578616d706c65036f726700 0001 000c 08 665c6f6f2c626172 02 6832",
            &rdata(&[
                &[0, 16],
                FOO_EXAMPLE_ORG,
                &[0, 1, 0, 12, 8],
                b"f\\oo,bar",
                &[2],
                b"h2",
            ]),
        ),
        (
            r"SVCB 16 foo.example.org. alpn=f\\\092oo\092,bar,h2",
            r"SVCB \# 35 0010 03666f6f076578616d706c65036f726700 0001 000c 08 665c6f6f2c626172 02 6832",
            &rdata(&[
                &[0, 16],
                FOO_EXAMPLE_ORG,
                &[0, 1, 0, 12, 8],
                b"f\\oo,bar",
                &[2],
                b"h2",
            ]),
        ),
    ];
    for &(text, generic, wire) in vectors {
        agrees(text, generic, wire);
    }
}

/// The text and generic forms read as the same record of `wire` RDATA, and the record writes back both.
fn agrees(text: &str, generic: &str, wire: &[u8]) {
    let rec = from_text(text).unwrap_or_else(|e| unreachable!("{text}: {e}"));
    assert_eq!(rdata_wire(&rec), wire, "{text}");
    assert_eq!(
        from_text(generic).expect("generic form reads"),
        rec,
        "{generic}"
    );
    assert_eq!(
        rec.to_string()
            .parse::<Record<'_>>()
            .expect("written form reads"),
        rec,
        "{rec}"
    );
    let written = rec.generic().to_string();
    assert_eq!(
        written.parse::<Record<'_>>().expect("generic form reads"),
        rec
    );
}

#[test]
fn appendix_d3_failures_in_presentation_format() {
    for text in [
        "SVCB 1 foo.example.com. ( key123=abc key123=def )",
        "SVCB 1 foo.example.com. mandatory",
        "SVCB 1 foo.example.com. alpn",
        "SVCB 1 foo.example.com. port",
        "SVCB 1 foo.example.com. ipv4hint",
        "SVCB 1 foo.example.com. ipv6hint",
        "SVCB 1 foo.example.com. no-default-alpn=abc",
        "SVCB 1 foo.example.com. mandatory=key123",
        "SVCB 1 foo.example.com. mandatory=mandatory",
        "SVCB 1 foo.example.com. ( mandatory=key123,key123 key123=abc )",
    ] {
        assert!(from_text(text).is_err(), "accepted {text}");
    }
}

#[test]
fn appendix_a_value_escapes() {
    let rec = from_text(r#"SVCB 1 . dohpath="/q{?dns}" key9="a\"b" ech=AQID"#).unwrap();
    let RData::Svcb(s) = &rec.data else {
        unreachable!("SVCB text reads as SVCB")
    };
    assert_eq!(
        s.params().iter().collect::<Vec<_>>(),
        [
            SvcParam::Ech((*b"\x01\x02\x03").into()),
            SvcParam::DohPath("/q{?dns}".to_owned()),
            SvcParam::Unknown {
                key: SvcParamKey(9),
                value: (*b"a\"b").into()
            },
        ]
    );
    assert_eq!(
        rec.data.to_string(),
        r#"1 . ech=AQID dohpath="/q{?dns}" key9="a\"b""#
    );
    assert!(from_text("SVCB 1 . ech=AQI").is_err());
    assert!(from_text("SVCB 1 . port=x").is_err());
    assert!(from_text("SVCB 1 . bogus=1").is_err());
}

/// §2.1: keys are lowercase names or `key` and a number without leading zeros.
#[test]
fn keys_are_written_one_way() {
    assert!(from_text("SVCB 1 . alpn=h2 key0=alpn").is_ok());
    assert!(from_text("SVCB 1 . key65=x").is_ok());
    for bad in [
        "ALPN=h2",
        "Port=53",
        "key01=x",
        "key=x",
        "key065536=x",
        "key65536=x",
    ] {
        assert!(from_text(&format!("SVCB 1 . {bad}")).is_err(), "{bad}");
    }
}

/// An `ECHConfigList` is never empty; base64 has one text per value (RFC 4648 §3.5).
#[test]
fn ech_is_never_empty_and_base64_is_canonical() {
    let e = from_text("SVCB 1 . ech=\"\"").expect_err("refused");
    assert_eq!(
        e.kind,
        dedens_proto::TextErrorKind::SvcParams(SvcParamsError::Empty(SvcParamKey::ECH))
    );
    assert!(from_text("SVCB 1 . ech=Zg==").is_ok());
    assert!(from_text("SVCB 1 . ech=Zh==").is_err());
    let mut wire = vec![0, 1, 0];
    wire.extend_from_slice(&[0, 5, 0, 0]);
    let decoded = decode_record(&record_wire(RecordType::SVCB, &wire)).expect("kept opaque");
    assert!(decoded.invalid_rdata.is_some());
}

/// A refused parameter list is reported at the parameter it names.
#[test]
fn parameter_errors_point_at_the_parameter() {
    let e = from_text("SVCB 1 . port=53 alpn=h2 no-default-alpn mandatory=ipv4hint")
        .expect_err("refused");
    assert_eq!(
        (e.column, e.kind),
        (
            60,
            dedens_proto::TextErrorKind::SvcParams(SvcParamsError::BadMandatory(
                SvcParamKey::IPV4HINT
            ))
        )
    );
    let e = from_text("SVCB 1 . port=53 port=54").expect_err("refused");
    assert_eq!(e.column, 36);
    let e = from_text("SVCB 1 . alpn=h2 mandatory=alpn,alpn").expect_err("refused");
    assert_eq!(
        (e.column, e.kind),
        (
            36,
            dedens_proto::TextErrorKind::SvcParams(SvcParamsError::MandatoryTwice(
                SvcParamKey::ALPN
            ))
        )
    );
}
