//! SVCB and HTTPS records and their parameters.
//!
//! - RFC 9460: SVCB and HTTPS records (§2, §7, §8, §9, Appendix D) and RFC 9461 `dohpath`.
//! - RFC 9953: the `docpath` `SvcParam` of DNS over CoAP (§3.2, §3.2.1), the part that belongs to the record types.

use std::net::{Ipv4Addr, Ipv6Addr};

use dedens_proto::rdata::{RData, SvcParam, SvcParamKey, SvcParams, SvcParamsError, Svcb};
use dedens_proto::{Class, Name, Record, RecordType, Ttl};
use proptest::prelude::*;

use crate::util::{decode_record, encode_record, name_of, record, record_wire};

// --- RFC 9460 ---

const FOO_EXAMPLE_COM: &[u8] = b"\x03foo\x07example\x03com\x00";
const FOO_EXAMPLE_ORG: &[u8] = b"\x03foo\x07example\x03org\x00";

fn svcb(rdata: &[u8]) -> Svcb<'static> {
    let decoded = decode_record(&record_wire(RecordType::SVCB, rdata)).expect("decodes");
    assert_eq!(decoded.invalid_rdata, None);
    let RData::Svcb(svcb) = decoded.record.data() else {
        unreachable!("a SVCB record decodes to SVCB data")
    };
    svcb.into_owned()
}

/// The RDATA is kept opaque and flagged: SVCB has no compressible names (D9).
fn rejected(rdata: &[u8]) {
    let decoded = decode_record(&record_wire(RecordType::SVCB, rdata)).expect("delimited");
    assert!(decoded.invalid_rdata.is_some(), "accepted {rdata:02x?}");
    assert!(matches!(decoded.record.data(), RData::Opaque(_)));
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
    let encoded = encode_record(&Record::new(
        Name::root(),
        Class::IN,
        Ttl::ZERO,
        &RData::Svcb(s.clone()),
    ));
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
    let RData::Https(s) = decoded.record.data() else {
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
    assert!(matches!(decoded.record.data(), RData::Opaque(_)));
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
        let wire = encode_record(&rec);
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
    let alone = Record::new(Name::root(), Class::IN, Ttl::ZERO, &rec.data());
    encode_record(&alone)[11..].to_vec()
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
    let RData::Svcb(s) = &rec.data() else {
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
        rec.data().to_string(),
        r#"1 . ech=AQID dohpath="/q{?dns}" key9="a\"b""#
    );
    assert!(from_text("SVCB 1 . ech=AQI").is_err());
    assert!(from_text("SVCB 1 . port=x").is_err());
    assert!(from_text("SVCB 1 . bogus=1").is_err());
}

/// §2.1: keys are lowercase names or `key` and a number without leading zeros.
#[test]
fn keys_are_written_one_way() {
    assert!(from_text(r"SVCB 1 . alpn=h2 key0=\000\001").is_ok());
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

/// §8: checking that every key `mandatory` lists is present takes one pass, so a record listing thousands of keys
/// costs a decoder no more than its size (it took a quadratic number of parses before).
#[test]
fn s8_a_long_mandatory_list_is_checked_in_one_pass() {
    let keys = 8..10_008_u16;
    let mut wire = vec![0, 1, 0, 0, 0];
    wire.extend(u16::try_from(keys.len() * 2).expect("fits").to_be_bytes());
    wire.extend(keys.clone().flat_map(u16::to_be_bytes));
    wire.extend(
        keys.clone()
            .flat_map(|k| [k.to_be_bytes(), [0, 0]])
            .flatten(),
    );
    let decoded = decode_record(&record_wire(RecordType::SVCB, &wire)).expect("valid");
    assert_eq!(decoded.invalid_rdata, None);
    // Without the last parameter, the last listed key is missing.
    wire.truncate(wire.len() - 4);
    let decoded = decode_record(&record_wire(RecordType::SVCB, &wire)).expect("delimited");
    assert!(decoded.invalid_rdata.is_some());
}

/// §2.1: a key written `keyNNNNN` takes its value in wire form, even a key with a name (§7.1.1: `key1=\002h2`).
#[test]
fn generic_keys_take_wire_values() {
    for (generic, named) in [
        (r"key1=\002h2", "alpn=h2"),
        (r"key0=\000\003 key3=\000\053", "mandatory=port port=53"),
        (
            "key1=\"\\002h2\\005h3-19\" key2",
            "alpn=h2,h3-19 no-default-alpn",
        ),
        (r"key4=\192\000\002\001", "ipv4hint=192.0.2.1"),
        ("key7=/q{?dns}", "dohpath=/q{?dns}"),
    ] {
        let generic = from_text(&format!("SVCB 1 . {generic}")).expect(generic);
        assert_eq!(
            generic,
            from_text(&format!("SVCB 1 . {named}")).expect(named)
        );
    }
    // Wire values that do not read back the same: odd bytes, a short port, an ALPN length past the end.
    for bad in [
        r"key0=\000\003\000",
        r"key3=\000",
        r"key1=\003h2",
        r"key4=\192\000\002",
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

// --- RFC 9953 ---

/// §3.2.1's records: the binary form, the presentation form (the RFC's parentheses removed, the target made
/// absolute), and the `docpath` and `alpn` they hold.
struct Example {
    wire: &'static [u8],
    text: &'static str,
    docpath: &'static [&'static [u8]],
}

const EXAMPLES: &[Example] = &[
    // The root path: "docpath" alone, an empty list.
    Example {
        wire: &[
            0x04, 0x5f, 0x64, 0x6e, 0x73, 0x07, 0x65, 0x78, 0x61, 0x6d, 0x70, 0x6c, 0x65, 0x03,
            0x6f, 0x72, 0x67, 0x00, 0x00, 0x40, 0x00, 0x01, 0x00, 0x00, 0x06, 0x28, 0x00, 0x1e,
            0x00, 0x01, 0x03, 0x64, 0x6e, 0x73, 0x07, 0x65, 0x78, 0x61, 0x6d, 0x70, 0x6c, 0x65,
            0x03, 0x6f, 0x72, 0x67, 0x00, 0x00, 0x01, 0x00, 0x03, 0x02, 0x63, 0x6f, 0x00, 0x0a,
            0x00, 0x00,
        ],
        text: "_dns.example.org. 1576 IN SVCB 1 dns.example.org. alpn=co docpath",
        docpath: &[],
    },
    // "/dns".
    Example {
        wire: &[
            0x04, 0x5f, 0x64, 0x6e, 0x73, 0x07, 0x65, 0x78, 0x61, 0x6d, 0x70, 0x6c, 0x65, 0x03,
            0x6f, 0x72, 0x67, 0x00, 0x00, 0x40, 0x00, 0x01, 0x00, 0x00, 0x00, 0x55, 0x00, 0x22,
            0x00, 0x01, 0x03, 0x64, 0x6e, 0x73, 0x07, 0x65, 0x78, 0x61, 0x6d, 0x70, 0x6c, 0x65,
            0x03, 0x6f, 0x72, 0x67, 0x00, 0x00, 0x01, 0x00, 0x03, 0x02, 0x63, 0x6f, 0x00, 0x0a,
            0x00, 0x04, 0x03, 0x64, 0x6e, 0x73,
        ],
        text: "_dns.example.org. 85 IN SVCB 1 dns.example.org. alpn=co docpath=dns",
        docpath: &[b"dns"],
    },
    // "/n/s".
    Example {
        wire: &[
            0x04, 0x5f, 0x64, 0x6e, 0x73, 0x07, 0x65, 0x78, 0x61, 0x6d, 0x70, 0x6c, 0x65, 0x03,
            0x6f, 0x72, 0x67, 0x00, 0x00, 0x40, 0x00, 0x01, 0x00, 0x00, 0x06, 0x6b, 0x00, 0x22,
            0x00, 0x01, 0x03, 0x64, 0x6e, 0x73, 0x07, 0x65, 0x78, 0x61, 0x6d, 0x70, 0x6c, 0x65,
            0x03, 0x6f, 0x72, 0x67, 0x00, 0x00, 0x01, 0x00, 0x03, 0x02, 0x63, 0x6f, 0x00, 0x0a,
            0x00, 0x04, 0x01, 0x6e, 0x01, 0x73,
        ],
        text: "_dns.example.org. 1643 IN SVCB 1 dns.example.org. alpn=co docpath=n,s",
        docpath: &[b"n", b"s"],
    },
    // With `dohpath` beside it, the root path.
    Example {
        wire: &[
            0x04, 0x5f, 0x64, 0x6e, 0x73, 0x07, 0x65, 0x78, 0x61, 0x6d, 0x70, 0x6c, 0x65, 0x03,
            0x6f, 0x72, 0x67, 0x00, 0x00, 0x40, 0x00, 0x01, 0x00, 0x00, 0x01, 0xad, 0x00, 0x2c,
            0x00, 0x01, 0x03, 0x64, 0x6e, 0x73, 0x07, 0x65, 0x78, 0x61, 0x6d, 0x70, 0x6c, 0x65,
            0x03, 0x6f, 0x72, 0x67, 0x00, 0x00, 0x01, 0x00, 0x06, 0x02, 0x68, 0x33, 0x02, 0x63,
            0x6f, 0x00, 0x07, 0x00, 0x07, 0x2f, 0x7b, 0x3f, 0x64, 0x6e, 0x73, 0x7d, 0x00, 0x0a,
            0x00, 0x00,
        ],
        text: "_dns.example.org. 429 IN SVCB 1 dns.example.org. alpn=h3,co dohpath=/{?dns} docpath",
        docpath: &[],
    },
];

fn docpath_of(svcb: &Svcb<'_>) -> Option<Vec<Box<[u8]>>> {
    match svcb.params().get(SvcParamKey::DOCPATH)? {
        SvcParam::DocPath(segments) => Some(segments),
        other => unreachable!("key 10 is a DocPath, not {other:?}"),
    }
}

#[test]
fn s3_2_1_the_examples_decode_encode_and_read_from_text() {
    for example in EXAMPLES {
        let decoded = decode_record(example.wire).expect("decodes");
        assert_eq!(decoded.invalid_rdata, None, "{}", example.text);
        let RData::Svcb(svcb) = decoded.record.data() else {
            unreachable!("a SVCB record decodes to SVCB data")
        };
        let segments: Vec<&[u8]> = example.docpath.to_vec();
        assert_eq!(
            docpath_of(&svcb)
                .as_deref()
                .map(|s| s.iter().map(|b| &**b).collect::<Vec<_>>()),
            Some(segments),
            "{}",
            example.text
        );
        assert_eq!(
            encode_record(&decoded.record),
            example.wire,
            "{}",
            example.text
        );

        let read: Record<'static> = example.text.parse().expect("reads");
        assert_eq!(read, decoded.record, "{}", example.text);
        assert_eq!(
            read.to_string()
                .parse::<Record<'static>>()
                .expect("reads back"),
            read
        );
    }
}

#[test]
fn s3_2_the_root_path_prints_as_the_bare_key() {
    let read: Record<'static> = "x. 60 IN SVCB 1 . alpn=co docpath".parse().expect("reads");
    assert!(read.to_string().ends_with("alpn=\"co\" docpath"), "{read}");
}

#[test]
fn s3_2_a_segment_may_hold_commas_and_backslashes() {
    // The presentation format's escapes come first, then the list's (RFC 9460 appendix A.1).
    let read: Record<'static> = r#"x. 60 IN SVCB 1 . docpath="a\\\,b,c\\\\d""#
        .parse()
        .expect("reads");
    let RData::Svcb(svcb) = read.data() else {
        unreachable!("a SVCB record")
    };
    assert_eq!(
        docpath_of(&svcb),
        Some(vec![(*b"a,b").into(), (*b"c\\d").into()])
    );
    assert_eq!(
        read.to_string()
            .parse::<Record<'static>>()
            .expect("reads back"),
        read
    );
}

#[test]
fn s3_2_a_segment_may_be_empty() {
    // "Reuse the decoders and encoders of alpn with the adaption that a length of zero is allowed".
    for (text, segments) in [
        (r#"docpath="a,,b""#, vec![&b"a"[..], b"", b"b"]),
        (r#"docpath=",""#, vec![b"", b""]),
        // One empty segment cannot be told from none in a list: the generic form of RFC 9460 §2.1.
        (r#"key10="\000""#, vec![b""]),
    ] {
        let read: Record<'static> = format!("x. 60 IN SVCB 1 . {text}").parse().expect(text);
        let RData::Svcb(svcb) = read.data() else {
            unreachable!("a SVCB record")
        };
        let expected: Vec<Box<[u8]>> = segments.into_iter().map(Into::into).collect();
        assert_eq!(docpath_of(&svcb), Some(expected), "{text}");
        let decoded = decode_record(&encode_record(&read)).expect("decodes");
        assert_eq!(decoded.record, read, "{text}");
        assert_eq!(
            read.to_string()
                .parse::<Record<'static>>()
                .expect("reads back"),
            read,
            "{text}"
        );
    }
}

#[test]
fn s3_2_values_that_do_not_fill_exactly_are_malformed() {
    // The length octet runs past the value, then a stray byte after a pair.
    for value in [&[3u8, b'd', b'n'][..], &[1, b'a', 7]] {
        let rdata = [
            &[0u8, 1, 0, 0, 0x0a, 0, u8::try_from(value.len()).unwrap()][..],
            value,
        ]
        .concat();
        let decoded = decode_record(&crate::util::record_wire(
            dedens_proto::RecordType::SVCB,
            &rdata,
        ))
        .expect("delimited");
        assert!(decoded.invalid_rdata.is_some(), "accepted {value:02x?}");
    }
}

#[test]
fn s3_2_a_segment_over_255_bytes_cannot_be_carried() {
    let too_long: Box<[u8]> = vec![b'a'; 256].into();
    assert!(SvcParams::new(vec![SvcParam::DocPath(vec![too_long])]).is_err());
}

#[test]
fn key_10_is_typed_so_it_is_no_unknown_parameter() {
    let unknown = SvcParam::Unknown {
        key: SvcParamKey::DOCPATH,
        value: Box::default(),
    };
    assert!(SvcParams::new(vec![unknown]).is_err());
    // Keys 8 and 9 stay unknown here.
    let eight = SvcParam::Unknown {
        key: SvcParamKey(8),
        value: Box::default(),
    };
    assert!(SvcParams::new(vec![eight]).is_ok());
}

proptest! {
    #[test]
    fn docpaths_read_back_in_wire_and_text_form(
        segments in prop::collection::vec(prop::collection::vec(any::<u8>(), 0..=12), 0..=4),
    ) {
        let segments: Vec<Box<[u8]>> = segments.into_iter().map(Vec::into_boxed_slice).collect();
        let params = SvcParams::new(vec![SvcParam::DocPath(segments)]).expect("valid");
        let svcb = Svcb::new(1, Name::root(), params).expect("fits");
        let rec = Record::new(Name::root(), dedens_proto::Class::IN, dedens_proto::Ttl::ZERO, &RData::Svcb(svcb));
        let decoded = decode_record(&encode_record(&rec)).expect("decodes");
        prop_assert_eq!(&decoded.record, &rec);
        let text = rec.to_string();
        let read: Record<'static> = text.parse().map_err(|e| TestCaseError::fail(format!("{text}: {e}")))?;
        prop_assert_eq!(read, rec);
    }
}
