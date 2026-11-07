//! RFC 2782: SRV records.

mod common;

use common::{decode_record, encode_record, name_of, record, record_wire};
use dedens_proto::RecordType;
use dedens_proto::rdata::RData;
use proptest::prelude::*;

fn srv_rdata(priority: u16, weight: u16, port: u16, target: &[u8]) -> Vec<u8> {
    [
        &priority.to_be_bytes()[..],
        &weight.to_be_bytes(),
        &port.to_be_bytes(),
        target,
    ]
    .concat()
}

#[test]
fn srv_fields_are_priority_weight_port_target() {
    let wire = srv_rdata(1, 2, 5060, b"\x03sip\x07example\x03com\x00");
    let decoded = decode_record(&record_wire(RecordType::SRV, &wire)).unwrap();
    let RData::Srv(srv) = decoded.record.data() else {
        panic!("not SRV")
    };
    assert_eq!((srv.priority, srv.weight, srv.port), (1, 2, 5060));
    assert_eq!(srv.target, name_of(&[b"sip", b"example", b"com"]));
}

#[test]
fn the_root_target_means_no_service() {
    let decoded = decode_record(&record_wire(RecordType::SRV, &srv_rdata(0, 0, 0, &[0]))).unwrap();
    let RData::Srv(srv) = decoded.record.data() else {
        panic!("not SRV")
    };
    assert!(srv.target.is_root());
}

#[test]
fn invalid_rdata_is_an_error() {
    // The target may hold a pointer (RFC 3597 §4), so the bytes cannot be kept opaque (D9).
    assert!(decode_record(&record_wire(RecordType::SRV, &[0, 1, 0, 2, 0, 3])).is_err());
}

proptest! {
    #[test]
    fn round_trip(rec in record()) {
        let wire = encode_record(&rec);
        prop_assert_eq!(decode_record(&wire)?.record, rec);
    }
}
