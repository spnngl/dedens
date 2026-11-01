//! RFC 4034: DNSKEY (§2), RRSIG (§3), NSEC (§4) and DS (§5) records, with the examples of the RFC.

mod common;

use common::{decode_record, encode_record, rdata_wire, record_wire};
use dedens_proto::rdata::{Dnskey, TypeBitmap, TypeBitmapError};
use dedens_proto::{DigestType, RData, Record, RecordType, SecAlgorithm};

/// §2.3.
const DNSKEY: &str = "example.com. 86400 IN DNSKEY 256 3 5 ( AQPSKmynfzW4kyBv015MUG2DeIQ3
    Cbl+BBZH4b/0PY1kxkmvHjcZc8no kfzj31GajIQKY+5CptLr3buXA10h
    WqTkF7H6RfoRqXQeogmMHfpftf6z Mv1LyBUgia7za6ZEzOJBOztyvhjL
    742iU/TpPSEDhm2SNKLijfUppn1U aNvv4w== )";

/// §3.3.
const RRSIG: &str = "host.example.com. 86400 IN RRSIG A 5 3 86400 20030322173103 (
    20030220173103 2642 example.com. oJB1W6WNGv+ldvQ3WDG0MQkg5IEhjRip8WTr
    PYGv07h108dUKGMeDPKijVCHX3DDKdfb+v6o B9wfuh3DTJXUAfI/M0zmO/zz8bW0Rznl8O3t
    GNazPwQKkRN20XPXV6nwwfoXmJQbsLNrLfkG J5D6fwFm8nN+6pBzeDQfsS3Ap3o= )";

/// §4.3.
const NSEC: &str = "alfa.example.com. 86400 IN NSEC host.example.com. (
    A MX RRSIG NSEC TYPE1234 )";

/// The RDATA of [`NSEC`] as the RFC encodes it: the name, then windows 0 and 4 (27 bytes, the last 0x20).
fn nsec_wire() -> Vec<u8> {
    let mut wire = b"\x04host\x07example\x03com\x00".to_vec();
    wire.extend_from_slice(&[0, 6, 0x40, 0x01, 0, 0, 0, 0x03, 4, 0x1b]);
    wire.extend_from_slice(&[0; 26]);
    wire.push(0x20);
    wire
}

/// §5.4: the DS of the DNSKEY of `dskey.example.com.`.
const DS: &str = "dskey.example.com. 86400 IN DS 60485 5 1 ( 2BB183AF5F22588179A53B0A
    98631FAD1A292118 )";

fn parse(text: &str) -> Record<'static> {
    text.parse().expect("an RFC example")
}

/// The record of `text` read back from the text and the wire it writes.
fn round_trips(rec: &Record<'static>) {
    assert_eq!(&rec.to_string().parse::<Record<'_>>().expect("text"), rec);
    assert_eq!(
        &decode_record(&encode_record(rec)).expect("wire").record,
        rec
    );
}

fn dnskey(flags: u16) -> Dnskey<'static> {
    Dnskey::new(flags, SecAlgorithm(5), b"key")
        .expect("a key")
        .into_owned()
}

#[test]
fn s2_3_example_reads_writes_and_reads_again() {
    let rec = parse(DNSKEY);
    let RData::Dnskey(key) = rec.data() else {
        panic!("not DNSKEY")
    };
    assert_eq!(key.flags(), 256);
    assert_eq!(key.algorithm(), SecAlgorithm::RSASHA1);
    assert_eq!(key.public_key().len(), 130);
    assert!(key.is_zone_key() && !key.is_secure_entry_point() && !key.is_revoked());
    // Flags, protocol 3, algorithm 5, then the key.
    assert_eq!(rdata_wire(&rec)[..4], [1, 0, 3, 5]);
    assert_eq!(rdata_wire(&rec)[4..8], [1, 3, 0xD2, 0x2A]);
    round_trips(&rec);
}

#[test]
fn s2_1_1_flags_are_the_zone_key_secure_entry_point_and_revoke_bits() {
    let (zone, sep, revoke) = (0x0100, 0x0001, 0x0080);
    assert!(dnskey(zone).is_zone_key());
    assert!(dnskey(sep).is_secure_entry_point());
    assert!(dnskey(revoke).is_revoked());
    assert!(!dnskey(zone | sep).is_revoked());
    assert!(!dnskey(!(zone | sep | revoke)).is_zone_key());
    assert_eq!(dnskey(0xFFFF).flags(), 0xFFFF);
}

#[test]
fn s2_1_2_a_protocol_other_than_3_is_kept_opaque() {
    for protocol in [0, 2, 4, 255] {
        let wire = [1, 0, protocol, 5, 1, 2, 3];
        let decoded = decode_record(&record_wire(RecordType::DNSKEY, &wire)).unwrap();
        assert!(decoded.invalid_rdata.is_some());
        let RData::Opaque(opaque) = decoded.record.data() else {
            panic!("typed")
        };
        assert_eq!(opaque.data(), wire);
    }
    let decoded = decode_record(&record_wire(RecordType::DNSKEY, &[1, 0, 3, 5, 1])).unwrap();
    assert!(decoded.invalid_rdata.is_none());
}

#[test]
fn s2_1_2_a_protocol_other_than_3_is_not_read_from_text() {
    assert!(
        "example.com. 60 DNSKEY 256 3 5 AQID"
            .parse::<Record<'_>>()
            .is_ok()
    );
    assert!(
        "example.com. 60 DNSKEY 256 2 5 AQID"
            .parse::<Record<'_>>()
            .is_err()
    );
}

#[test]
fn s2_1_3_a_key_is_not_empty() {
    let decoded = decode_record(&record_wire(RecordType::DNSKEY, &[1, 0, 3, 5])).unwrap();
    assert!(decoded.invalid_rdata.is_some());
    assert!(Dnskey::new(256, SecAlgorithm(5), b"").is_err());
}

#[test]
fn s2_2_key_text_is_base64_with_blanks_allowed() {
    let one = parse("example.com. 60 DNSKEY 256 3 5 AQIDBAUG");
    let blanks = parse("example.com. 60 DNSKEY 256 3 5 ( AQID BAUG )");
    assert_eq!(one, blanks);
    // Padding and canonical bits are strict, as the one text of a value.
    assert!(
        "example.com. 60 DNSKEY 256 3 5 AQIDBAU"
            .parse::<Record<'_>>()
            .is_err()
    );
    assert!(
        "example.com. 60 DNSKEY 256 3 5 AQ"
            .parse::<Record<'_>>()
            .is_err()
    );
    assert!(
        "example.com. 60 DNSKEY 256 3 5"
            .parse::<Record<'_>>()
            .is_err()
    );
}

#[test]
fn s3_3_example_reads_writes_and_reads_again() {
    let rec = parse(RRSIG);
    let RData::Rrsig(sig) = rec.data() else {
        panic!("not RRSIG")
    };
    assert_eq!(sig.type_covered, RecordType::A);
    assert_eq!(sig.algorithm, SecAlgorithm::RSASHA1);
    assert_eq!(
        (sig.labels, sig.original_ttl, sig.key_tag),
        (3, 86400, 2642)
    );
    assert_eq!(sig.expiration, 1_048_354_263);
    assert_eq!(sig.signer, common::dns("example.com."));
    assert_eq!(sig.signature().len(), 128);
    assert_eq!(rdata_wire(&rec)[..4], [0, 1, 5, 3]);
    round_trips(&rec);
}

#[test]
fn s3_2_times_are_read_as_dates_or_seconds_and_written_as_dates() {
    let date =
        parse("example.com. 60 RRSIG A 5 2 60 20030322173103 20030220173103 1 example.com. AQID");
    let seconds = parse("example.com. 60 RRSIG A 5 2 60 1048354263 1045762263 1 example.com. AQID");
    assert_eq!(date, seconds);
    let text = date.to_string();
    assert!(text.contains(" 20030322173103 20030220173103 "), "{text}");
    // Not a date and not up to 10 digits; an impossible date.
    for expiration in [
        "200303221731",
        "20030230173103",
        "20031322173103",
        "12345678901",
    ] {
        let text = format!(
            "example.com. 60 RRSIG A 5 2 60 {expiration} 20030220173103 1 example.com. AQID"
        );
        assert!(text.parse::<Record<'_>>().is_err(), "{expiration}");
    }
}

#[test]
fn s3_1_8_1_the_signed_rdata_is_the_fields_and_the_signer_without_the_signature() {
    let rec = parse(RRSIG);
    let RData::Rrsig(sig) = rec.data() else {
        panic!("not RRSIG")
    };
    let wire = rdata_wire(&rec);
    assert_eq!(sig.signed_rdata(), wire[..wire.len() - 128]);
    // The signer is as it came: case is kept.
    let upper = parse("a. 60 RRSIG A 5 1 60 100 50 7 ExAmPle.COM. AQID");
    let RData::Rrsig(sig) = upper.data() else {
        panic!("not RRSIG")
    };
    assert!(sig.signed_rdata().ends_with(b"\x07ExAmPle\x03COM\x00"));
}

#[test]
fn s3_1_7_the_signer_is_never_compressed() {
    let mut wire = vec![0, 1, 5, 0, 0, 0, 0, 60, 0, 0, 0, 100, 0, 0, 0, 50, 0, 7];
    wire.extend_from_slice(&[0xC0, 0x00, 1, 2, 3]);
    let decoded = decode_record(&record_wire(RecordType::RRSIG, &wire)).unwrap();
    assert!(decoded.invalid_rdata.is_some());
    assert!(matches!(decoded.record.data(), RData::Opaque(_)));
}

#[test]
fn s3_1_a_signature_is_not_empty() {
    let mut wire = vec![0, 1, 5, 0, 0, 0, 0, 60, 0, 0, 0, 100, 0, 0, 0, 50, 0, 7, 0];
    let decoded = decode_record(&record_wire(RecordType::RRSIG, &wire)).unwrap();
    assert!(decoded.invalid_rdata.is_some());
    wire.push(1);
    let decoded = decode_record(&record_wire(RecordType::RRSIG, &wire)).unwrap();
    assert!(decoded.invalid_rdata.is_none());
}

#[test]
fn s4_3_example_reads_writes_and_reads_again() {
    let rec = parse(NSEC);
    let RData::Nsec(nsec) = rec.data() else {
        panic!("not NSEC")
    };
    assert_eq!(nsec.next, common::dns("host.example.com."));
    let types: Vec<RecordType> = nsec.types.types().collect();
    assert_eq!(
        types,
        [
            RecordType::A,
            RecordType::MX,
            RecordType::RRSIG,
            RecordType::NSEC,
            RecordType(1234)
        ]
    );
    assert!(nsec.types.contains(RecordType::MX) && !nsec.types.contains(RecordType::AAAA));
    assert_eq!(rdata_wire(&rec), nsec_wire());
    assert!(
        rec.to_string()
            .ends_with("host.example.com. A MX RRSIG NSEC TYPE1234")
    );
    round_trips(&rec);
}

#[test]
fn s4_1_2_a_bitmap_has_windows_in_order_of_1_to_32_bytes_without_trailing_zero() {
    assert!(TypeBitmap::from_wire(&[]).is_ok());
    assert!(TypeBitmap::from_wire(&[0, 1, 0x40, 1, 1, 0x80]).is_ok());
    assert!(
        TypeBitmap::from_wire(&[0, 32].iter().chain(&[1; 32]).copied().collect::<Vec<_>>()).is_ok()
    );
    assert_eq!(
        TypeBitmap::from_wire(&[1, 1, 0x80, 0, 1, 0x40]),
        Err(TypeBitmapError::WindowOrder)
    );
    assert_eq!(
        TypeBitmap::from_wire(&[0, 1, 0x40, 0, 1, 0x40]),
        Err(TypeBitmapError::WindowOrder)
    );
    assert_eq!(
        TypeBitmap::from_wire(&[0, 0]),
        Err(TypeBitmapError::WindowLength)
    );
    assert_eq!(
        TypeBitmap::from_wire(&[0, 33].iter().chain(&[1; 33]).copied().collect::<Vec<_>>()),
        Err(TypeBitmapError::WindowLength)
    );
    assert_eq!(
        TypeBitmap::from_wire(&[0, 2, 0x40, 0]),
        Err(TypeBitmapError::TrailingZero)
    );
    assert_eq!(
        TypeBitmap::from_wire(&[0, 2, 0x40]),
        Err(TypeBitmapError::WindowLength)
    );
    assert_eq!(
        TypeBitmap::from_wire(&[0]),
        Err(TypeBitmapError::WindowLength)
    );
}

#[test]
fn s4_1_2_an_invalid_bitmap_keeps_the_rdata_opaque() {
    let wire = [&b"\x01a\x00"[..], &[0, 2, 0x40, 0]].concat();
    let decoded = decode_record(&record_wire(RecordType::NSEC, &wire)).unwrap();
    assert!(decoded.invalid_rdata.is_some());
    assert!(matches!(decoded.record.data(), RData::Opaque(_)));
}

#[test]
fn s4_1_1_the_next_name_is_never_compressed() {
    let decoded = decode_record(&record_wire(RecordType::NSEC, &[0xC0, 0x00, 0, 1, 0x40])).unwrap();
    assert!(decoded.invalid_rdata.is_some());
    assert!(matches!(decoded.record.data(), RData::Opaque(_)));
}

#[test]
fn s4_1_2_the_types_of_a_set_are_one_bitmap_whatever_the_order() {
    let a = TypeBitmap::from_types([RecordType::MX, RecordType::A, RecordType::MX]);
    let b = TypeBitmap::from_types([RecordType::A, RecordType::MX]);
    assert_eq!(a, b);
    assert_eq!(a.as_wire(), [0, 2, 0x40, 0x01]);
}

#[test]
fn s4_3_an_empty_bitmap_is_a_name_alone() {
    let rec = parse("a.example. 60 NSEC b.example.");
    let RData::Nsec(nsec) = rec.data() else {
        panic!("not NSEC")
    };
    assert!(nsec.types.is_empty());
    assert_eq!(
        rec.to_string().trim_end(),
        "a.example.\t60\tIN\tNSEC\tb.example."
    );
    round_trips(&rec);
}

#[test]
fn s5_4_example_reads_writes_and_reads_again() {
    let rec = parse(DS);
    let RData::Ds(ds) = rec.data() else {
        panic!("not DS")
    };
    assert_eq!(ds.key_tag(), 60485);
    assert_eq!(ds.algorithm(), SecAlgorithm::RSASHA1);
    assert_eq!(ds.digest_type(), DigestType::SHA1);
    assert_eq!(ds.digest().len(), 20);
    assert_eq!(rdata_wire(&rec)[..4], [0xEC, 0x45, 5, 1]);
    assert!(
        rec.to_string()
            .ends_with("DS\t60485 5 1 2bb183af5f22588179a53b0a98631fad1a292118")
    );
    round_trips(&rec);
}

#[test]
fn s5_3_digest_text_is_hex_in_any_case_with_blanks_allowed() {
    let one = parse("a. 60 DS 1 5 1 2BB183AF5F225881");
    let blanks = parse("a. 60 DS 1 5 1 ( 2bb183af 5f225881 )");
    assert_eq!(one, blanks);
    assert!(
        "a. 60 DS 1 5 1 2BB183AF5F22588"
            .parse::<Record<'_>>()
            .is_err()
    );
    assert!("a. 60 DS 1 5 1".parse::<Record<'_>>().is_err());
    assert!("a. 60 DS 70000 5 1 AA".parse::<Record<'_>>().is_err());
}

#[test]
fn s5_3_algorithm_and_digest_type_are_read_by_name_or_number() {
    let by_name = parse("a. 60 DS 1 RSASHA1 SHA-1 AA");
    assert_eq!(by_name, parse("a. 60 DS 1 5 1 AA"));
    assert!(by_name.to_string().ends_with("DS\t1 5 1 aa"));
    let unknown = parse("a. 60 DS 1 200 200 AA");
    round_trips(&unknown);
}
