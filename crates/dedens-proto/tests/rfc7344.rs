//! RFC 7344 §3: CDS and CDNSKEY records, with the delete form of RFC 8078 §4.

mod common;

use common::{decode_record, encode_record, rdata_wire, record_wire};
use dedens_proto::rdata::RData;
use dedens_proto::{DigestType, Record, RecordType, SecAlgorithm};

fn parse(text: &str) -> Record<'static> {
    text.parse().expect("valid text")
}

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
