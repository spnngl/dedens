//! RFC 5155: NSEC3 (§3) and NSEC3PARAM (§4) records, with the example zone of Appendix A.

mod common;

use std::fs;
use std::path::Path;

use common::{decode_record, encode_record, rdata_wire, record_wire};
use dedens_proto::rdata::{Nsec3, Nsec3Error, Nsec3Param, RData, TypeBitmap};
use dedens_proto::{Nsec3HashAlgorithm, Record, RecordType, ZoneEntry, ZoneReader};

/// The records of Appendix A's signed zone, `tests/zones/rfc5155_appendix_a.zone`.
fn appendix_a() -> Vec<Record<'static>> {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/zones/rfc5155_appendix_a.zone");
    let text = fs::read(path).expect("zone file");
    let mut records = Vec::new();
    for entry in ZoneReader::new(&text, None) {
        match entry.expect("a valid zone") {
            ZoneEntry::Record(r) => records.push(r.record),
            _ => unreachable!("records only"),
        }
    }
    records
}

fn parse(text: &str) -> Record<'static> {
    text.parse().expect("valid text")
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
