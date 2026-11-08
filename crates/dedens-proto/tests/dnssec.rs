//! The DNSSEC record types, with the examples of their RFCs.
//!
//! - RFC 4034: DNSKEY (§2), RRSIG (§3), NSEC (§4) and DS (§5) records, with the examples of the RFC.
//! - RFC 5155: NSEC3 (§3) and NSEC3PARAM (§4) records, with the example zone of Appendix A.
//! - RFC 7344 §3: CDS and CDNSKEY records, with the delete form of RFC 8078 §4.

use std::fs;

use dedens_proto::rdata::{
    Dnskey, Nsec3, Nsec3Error, Nsec3Param, RData, TypeBitmap, TypeBitmapError,
};
use dedens_proto::{
    DigestType, Nsec3HashAlgorithm, Record, RecordType, SecAlgorithm, ZoneEntry, ZoneReader,
};

use crate::util::{decode_record, encode_record, rdata_wire, record_wire};

// --- RFC 4034 ---

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
    assert_eq!(sig.signer, dedens_testkit::dns("example.com."));
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
    assert_eq!(nsec.next, dedens_testkit::dns("host.example.com."));
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

// --- RFC 5155 ---

/// The records of Appendix A's signed zone, `testdata/zones/rfc5155_appendix_a.zone`.
fn appendix_a() -> Vec<Record<'static>> {
    let text = fs::read(dedens_testkit::path("zones/rfc5155_appendix_a.zone")).expect("zone file");
    let mut records = Vec::new();
    for entry in ZoneReader::new(&text, None) {
        match entry.expect("a valid zone") {
            ZoneEntry::Record(r) => records.push(r.record),
            _ => unreachable!("records only"),
        }
    }
    records
}

fn nsec3_of(rec: &Record<'_>) -> Option<Nsec3<'static>> {
    match rec.data() {
        RData::Nsec3(nsec3) => Some(nsec3.into_owned()),
        _ => None,
    }
}

#[test]
fn appendix_a_records_round_trip_in_text_and_on_the_wire() {
    let records = appendix_a();
    assert_eq!(records.len(), 70);
    for rec in records {
        assert_eq!(rec.to_string().parse::<Record<'_>>().as_ref(), Ok(&rec));
        let decoded = decode_record(&encode_record(&rec)).unwrap();
        assert!(decoded.invalid_rdata.is_none(), "{rec}");
        assert_eq!(decoded.record, rec);
        // Typed, not kept as opaque bytes, but for the HINFO of the zone.
        assert!(
            rec.rtype() == RecordType::HINFO || !matches!(rec.data(), RData::Opaque(_)),
            "{rec}"
        );
    }
}

#[test]
fn s3_1_appendix_a_nsec3_fields() {
    let nsec3s: Vec<Record<'static>> = appendix_a()
        .into_iter()
        .filter(|r| r.rtype() == RecordType::NSEC3)
        .collect();
    assert_eq!(nsec3s.len(), 12);
    for rec in &nsec3s {
        let nsec3 = nsec3_of(rec).unwrap();
        assert_eq!(nsec3.hash_algorithm, Nsec3HashAlgorithm::SHA1);
        assert_eq!((nsec3.flags, nsec3.iterations), (1, 12));
        assert!(nsec3.is_opt_out());
        assert_eq!(nsec3.salt(), [0xaa, 0xbb, 0xcc, 0xdd]);
        // SHA-1 gives 20 bytes, 32 characters of base32hex.
        assert_eq!(nsec3.next_hashed_owner().len(), 20);
    }
    let first = nsec3_of(&nsec3s[0]).unwrap();
    assert_eq!(
        nsec3s[0].to_string(),
        "0p9mhaveqvm6t7vbl5lop2u3t2rp3tom.example.\t3600\tIN\tNSEC3\t1 1 12 aabbccdd \
         2t7b4g4vsa5smi47k61mv5bv1a22bojr NS SOA MX RRSIG DNSKEY NSEC3PARAM"
    );
    assert!(first.types.contains(RecordType::NSEC3PARAM) && !first.types.contains(RecordType::A));
}

#[test]
fn s3_2_3_a_name_with_no_types_has_an_empty_bitmap() {
    let rec = parse(
        "ji6neoaepv8b5o6k4ev33abha8ht9fgc.example. 60 NSEC3 1 1 12 aabbccdd k8udemvp1j2f7eg6jebps17vp3n8i58h",
    );
    let nsec3 = nsec3_of(&rec).unwrap();
    assert!(nsec3.types.is_empty());
    // The hash algorithm, flags, iterations, the salt, the hash, and no windows.
    let mut wire = vec![1, 1, 0, 12, 4, 0xaa, 0xbb, 0xcc, 0xdd, 20];
    wire.extend_from_slice(nsec3.next_hashed_owner());
    assert_eq!(rdata_wire(&rec), wire);
}

#[test]
fn s3_3_the_salt_is_hex_or_a_dash_for_none() {
    let none = parse("a.example. 60 NSEC3 1 0 0 - 2t7b4g4vsa5smi47k61mv5bv1a22bojr A");
    let nsec3 = nsec3_of(&none).unwrap();
    assert!(nsec3.salt().is_empty() && !nsec3.is_opt_out());
    assert!(none.to_string().contains("\t1 0 0 - 2t7b4g4v"));
    assert_eq!(rdata_wire(&none)[..5], [1, 0, 0, 0, 0]);
    assert_eq!(decode_record(&encode_record(&none)).unwrap().record, none);
    for bad in ["", "a", "zz", "0"] {
        let text = format!("a.example. 60 NSEC3 1 0 0 {bad} 2t7b4g4vsa5smi47k61mv5bv1a22bojr A");
        assert!(text.parse::<Record<'_>>().is_err(), "{bad:?}");
    }
    let long = "ab".repeat(256);
    let text = format!("a.example. 60 NSEC3 1 0 0 {long} 2t7b4g4vsa5smi47k61mv5bv1a22bojr A");
    assert!(text.parse::<Record<'_>>().is_err());
}

#[test]
fn s3_3_the_hash_is_base32hex_without_padding_in_any_case_and_written_in_lowercase() {
    let lower = parse("a.example. 60 NSEC3 1 0 0 - 2t7b4g4vsa5smi47k61mv5bv1a22bojr A");
    let upper = parse("a.example. 60 NSEC3 1 0 0 - 2T7B4G4VSA5SMI47K61MV5BV1A22BOJR A");
    assert_eq!(lower, upper);
    assert!(
        upper
            .to_string()
            .contains("2t7b4g4vsa5smi47k61mv5bv1a22bojr")
    );
    for bad in [
        // Padding, a character out of the alphabet, a length no byte count gives, nothing.
        "2t7b4g4vsa5smi47k61mv5bv1a22bojr====",
        "2t7b4g4vsa5smi47k61mv5bv1a22bojw",
        "2t7b4g4vsa5smi47k61mv5bv1a22bo",
        "-",
    ] {
        let text = format!("a.example. 60 NSEC3 1 0 0 - {bad} A");
        assert!(text.parse::<Record<'_>>().is_err(), "{bad}");
    }
}

#[test]
fn s3_1_the_opt_out_flag_is_the_low_bit_and_the_other_bits_are_kept() {
    let rec = parse("a.example. 60 NSEC3 1 254 0 - 2t7b4g4vsa5smi47k61mv5bv1a22bojr A");
    let nsec3 = nsec3_of(&rec).unwrap();
    assert!(!nsec3.is_opt_out());
    assert_eq!(nsec3.flags, 254);
    assert_eq!(Nsec3::OPT_OUT, 1);
}

#[test]
fn s3_2_a_hash_is_at_least_one_byte_and_at_most_255() {
    let types = TypeBitmap::from_types([]);
    let algorithm = Nsec3HashAlgorithm::SHA1;
    assert_eq!(
        Nsec3::new(algorithm, 0, 0, b"", b"", types.clone()),
        Err(Nsec3Error::HashLength)
    );
    assert!(Nsec3::new(algorithm, 0, 0, b"", &[1; 255], types.clone()).is_ok());
    assert_eq!(
        Nsec3::new(algorithm, 0, 0, b"", &[1; 256], types.clone()),
        Err(Nsec3Error::HashLength)
    );
    assert_eq!(
        Nsec3::new(algorithm, 0, 0, &[1; 256], &[1], types),
        Err(Nsec3Error::SaltLength)
    );
    // An empty hash on the wire: the hash length byte is 0.
    let wire = [1, 0, 0, 0, 0, 0];
    let decoded = decode_record(&record_wire(RecordType::NSEC3, &wire)).unwrap();
    assert!(decoded.invalid_rdata.is_some());
    assert!(matches!(decoded.record.data(), RData::Opaque(_)));
}

#[test]
fn s3_2_a_length_past_the_rdata_is_kept_opaque() {
    for wire in [&[1, 0, 0, 0, 9, 1][..], &[1, 0, 0, 0, 0, 3, 1]] {
        let decoded = decode_record(&record_wire(RecordType::NSEC3, wire)).unwrap();
        assert!(decoded.invalid_rdata.is_some());
    }
}

#[test]
fn s4_appendix_a_nsec3param() {
    let rec = appendix_a()
        .into_iter()
        .find(|r| r.rtype() == RecordType::NSEC3PARAM)
        .unwrap();
    let RData::Nsec3Param(param) = rec.data() else {
        panic!("not NSEC3PARAM")
    };
    assert_eq!(param.hash_algorithm, Nsec3HashAlgorithm::SHA1);
    assert_eq!((param.flags, param.iterations), (0, 12));
    assert_eq!(param.salt(), [0xaa, 0xbb, 0xcc, 0xdd]);
    assert!(rec.to_string().ends_with("NSEC3PARAM\t1 0 12 aabbccdd"));
    assert_eq!(rdata_wire(&rec), [1, 0, 0, 12, 4, 0xaa, 0xbb, 0xcc, 0xdd]);
}

#[test]
fn s4_nsec3param_without_a_salt() {
    let rec = parse("example. 60 NSEC3PARAM 1 0 0 -");
    assert_eq!(rdata_wire(&rec), [1, 0, 0, 0, 0]);
    assert!(rec.to_string().ends_with("NSEC3PARAM\t1 0 0 -"));
    assert_eq!(decode_record(&encode_record(&rec)).unwrap().record, rec);
    assert!(Nsec3Param::new(Nsec3HashAlgorithm::SHA1, 0, 0, &[0; 256]).is_err());
    let decoded = decode_record(&record_wire(RecordType::NSEC3PARAM, &[1, 0, 0, 0, 1])).unwrap();
    assert!(decoded.invalid_rdata.is_some());
}

#[test]
fn s3_3_the_hash_algorithm_is_read_by_name_or_number() {
    let by_name = parse("a.example. 60 NSEC3PARAM SHA-1 0 5 -");
    assert_eq!(by_name, parse("a.example. 60 NSEC3PARAM 1 0 5 -"));
    assert!(by_name.to_string().ends_with("NSEC3PARAM\t1 0 5 -"));
    let rec = parse("a.example. 60 NSEC3PARAM 99 0 5 ab");
    assert_eq!(decode_record(&encode_record(&rec)).unwrap().record, rec);
    assert_eq!(rec.to_string().parse::<Record<'_>>().as_ref(), Ok(&rec));
}

// --- RFC 7344 §3 ---

fn wire_round_trip(rec: &Record<'static>) {
    let decoded = decode_record(&encode_record(rec)).expect("a record");
    assert!(decoded.invalid_rdata.is_none());
    assert_eq!(&decoded.record, rec);
    assert_eq!(rec.to_string().parse::<Record<'_>>().as_ref(), Ok(rec));
}

#[test]
fn s3_1_cds_has_the_fields_of_ds_under_its_own_type() {
    let cds =
        parse("dskey.example.com. 86400 IN CDS 60485 5 1 2BB183AF5F22588179A53B0A98631FAD1A292118");
    let ds =
        parse("dskey.example.com. 86400 IN DS 60485 5 1 2BB183AF5F22588179A53B0A98631FAD1A292118");
    let (RData::Cds(c), RData::Ds(d)) = (cds.data(), ds.data()) else {
        panic!("not CDS and DS")
    };
    assert_eq!(c, d);
    assert_eq!(cds.rtype(), RecordType::CDS);
    assert_ne!(cds, ds);
    assert_eq!(rdata_wire(&cds), rdata_wire(&ds));
    assert_eq!(
        (c.key_tag(), c.algorithm(), c.digest_type()),
        (60485, SecAlgorithm::RSASHA1, DigestType::SHA1)
    );
    assert!(cds.to_string().contains("\tCDS\t60485 5 1 2bb183af"));
    wire_round_trip(&cds);
}

#[test]
fn s3_2_cdnskey_has_the_fields_of_dnskey_under_its_own_type() {
    let cdnskey = parse("example.com. 86400 IN CDNSKEY 257 3 13 AQIDBAUG");
    let dnskey = parse("example.com. 86400 IN DNSKEY 257 3 13 AQIDBAUG");
    let (RData::Cdnskey(c), RData::Dnskey(d)) = (cdnskey.data(), dnskey.data()) else {
        panic!("not CDNSKEY and DNSKEY")
    };
    assert_eq!(c, d);
    assert!(c.is_zone_key() && c.is_secure_entry_point());
    assert_eq!(cdnskey.rtype(), RecordType::CDNSKEY);
    assert_ne!(cdnskey, dnskey);
    assert_eq!(rdata_wire(&cdnskey), [1, 1, 3, 13, 1, 2, 3, 4, 5, 6]);
    wire_round_trip(&cdnskey);
}

#[test]
fn s3_2_a_cdnskey_with_another_protocol_than_3_is_kept_opaque() {
    let decoded = decode_record(&record_wire(RecordType::CDNSKEY, &[1, 1, 2, 13, 1])).unwrap();
    assert!(decoded.invalid_rdata.is_some());
    assert!(matches!(decoded.record.data(), RData::Opaque(_)));
}

#[test]
fn rfc8078_s4_the_cds_delete_form_is_read_as_the_rfc_writes_it_and_written_with_a_byte() {
    for text in ["0 0 0 0", "0 0 0 00"] {
        let rec = parse(&format!("example.com. 60 CDS {text}"));
        let RData::Cds(cds) = rec.data() else {
            panic!("not CDS")
        };
        assert!(cds.is_delete());
        assert_eq!(cds.digest(), [0]);
        assert_eq!(rdata_wire(&rec), [0, 0, 0, 0, 0]);
        assert!(rec.to_string().ends_with("CDS\t0 0 0 00"));
        wire_round_trip(&rec);
    }
}

#[test]
fn rfc8078_s4_the_cdnskey_delete_form_is_read_as_the_rfc_writes_it_and_written_with_a_byte() {
    for text in ["0 3 0 0", "0 3 0 AA=="] {
        let rec = parse(&format!("example.com. 60 CDNSKEY {text}"));
        let RData::Cdnskey(key) = rec.data() else {
            panic!("not CDNSKEY")
        };
        assert!(key.is_delete());
        assert_eq!(key.public_key(), [0]);
        assert_eq!(rdata_wire(&rec), [0, 0, 3, 0, 0]);
        assert!(rec.to_string().ends_with("CDNSKEY\t0 3 0 AA=="));
        wire_round_trip(&rec);
    }
}

#[test]
fn rfc8078_s4_only_the_delete_form_takes_a_lone_zero() {
    for text in [
        "example.com. 60 CDS 1 0 0 0",
        "example.com. 60 CDS 0 0 1 0",
        "example.com. 60 CDS 0 0 0 0 0",
        "example.com. 60 CDNSKEY 256 3 0 0",
        "example.com. 60 CDNSKEY 0 3 1 0",
    ] {
        assert!(text.parse::<Record<'_>>().is_err(), "{text}");
    }
    let not_delete = parse("example.com. 60 CDS 0 0 0 01");
    let RData::Cds(cds) = not_delete.data() else {
        panic!("not CDS")
    };
    assert!(!cds.is_delete());
}
