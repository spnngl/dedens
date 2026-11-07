//! RFC 9953: the `docpath` `SvcParam` of DNS over CoAP (§3.2, §3.2.1), the part that belongs to the record types.

mod common;

use common::{decode_record, encode_record};
use dedens_proto::rdata::{RData, SvcParam, SvcParamKey, SvcParams, Svcb};
use dedens_proto::{Name, Record};
use proptest::prelude::*;

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
        let decoded = decode_record(&common::record_wire(dedens_proto::RecordType::SVCB, &rdata))
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
