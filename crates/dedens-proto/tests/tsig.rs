//! RFC 8945 §4.2 (the TSIG record), §5.1 (its place in a message) and §5.2.1 (the MAC covers the message without
//! it).

use dedens_proto::{
    Class, MAX_TIME_SIGNED, Query, RecordType, Tsig, TsigDataError, TsigError, find_tsig,
};
use dedens_testkit::dns;
use proptest::prelude::*;

use crate::util::{name, record_wire};

const HMAC_SHA256: &[u8] = b"\x0bhmac-sha256\x00";

fn tsig<'a>(mac: &'a [u8], other: &'a [u8], error: TsigError) -> Tsig<'a> {
    Tsig::new(
        dns("hmac-sha256."),
        1_700_000_000,
        300,
        mac,
        0x1234,
        error,
        other,
    )
    .expect("fits an RDATA")
}

/// A TSIG record named `key.` with class `ANY` and TTL 0, around `rdata`.
fn tsig_record(rdata: &[u8]) -> Vec<u8> {
    let mut wire = b"\x03key\x00".to_vec();
    wire.extend_from_slice(&RecordType::TSIG.0.to_be_bytes());
    wire.extend_from_slice(&Class::ANY.0.to_be_bytes());
    wire.extend_from_slice(&[0, 0, 0, 0]);
    wire.extend_from_slice(&u16::try_from(rdata.len()).expect("short").to_be_bytes());
    wire.extend_from_slice(rdata);
    wire
}

/// A message of ID 0x1234 and no question holding the records given, as (section, wire) in order.
fn message(answers: &[Vec<u8>], additional: &[Vec<u8>]) -> Vec<u8> {
    let count = |records: &[Vec<u8>]| u16::try_from(records.len()).expect("few").to_be_bytes();
    let mut wire = vec![0x12, 0x34, 0x80, 0, 0, 0];
    wire.extend_from_slice(&count(answers));
    wire.extend_from_slice(&[0, 0]);
    wire.extend_from_slice(&count(additional));
    wire.extend(answers.iter().chain(additional).flatten());
    wire
}

fn a_record() -> Vec<u8> {
    record_wire(RecordType::A, &[192, 0, 2, 1])
}

/// §4.2: the RDATA is the algorithm name, Time Signed on 48 bits, Fudge, the MAC with its size, Original ID,
/// Error, and Other Data with its length.
#[test]
fn s4_2_rdata_layout() {
    let mac: Vec<u8> = (0..32).collect();
    let wire = tsig(&mac, &[], TsigError::NOERROR).to_wire();
    let mut expected = HMAC_SHA256.to_vec();
    expected.extend_from_slice(&[0, 0, 0x65, 0x53, 0xf1, 0x00]); // 1700000000
    expected.extend_from_slice(&[0x01, 0x2c, 0, 32]);
    expected.extend_from_slice(&mac);
    expected.extend_from_slice(&[0x12, 0x34, 0, 0, 0, 0]);
    assert_eq!(wire, expected);
}

/// §4.2: the error is a mnemonic when there is one, the MAC and Other Data are in base64 and left out when empty.
#[test]
fn s4_2_text() {
    let mac: Vec<u8> = (0..32).collect();
    assert_eq!(
        tsig(&mac, &[], TsigError::NOERROR).to_string(),
        "hmac-sha256. 1700000000 300 32 AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8= 4660 NOERROR 0"
    );
    assert_eq!(
        tsig(&[], &[0, 0, 0x65, 0x53, 0xf1, 0x00], TsigError::BADTIME).to_string(),
        "hmac-sha256. 1700000000 300 0 4660 BADTIME 6 AABlU/EA"
    );
}

/// §4.2: Time Signed has 48 bits; a MAC and Other Data are bounded by the RDATA.
#[test]
fn s4_2_limits() {
    let make = |time, mac: &[u8]| {
        Tsig::new(dns("a."), time, 0, mac, 0, TsigError::NOERROR, &[]).map(|_| ())
    };
    assert_eq!(MAX_TIME_SIGNED, 0xFFFF_FFFF_FFFF);
    assert_eq!(make(0xFFFF_FFFF_FFFF, &[]), Ok(()));
    assert_eq!(
        make(0x1_0000_0000_0000, &[]),
        Err(TsigDataError::TimeSigned)
    );
    // "a." is 3 bytes and the fixed fields 16.
    assert_eq!(make(0, &vec![0; 65535 - 19]), Ok(()));
    assert_eq!(make(0, &vec![0; 65535 - 18]), Err(TsigDataError::Length));
}

/// §5.1: the TSIG is the last record of the additional section; it is found with its owner and where it starts.
#[test]
fn s5_1_the_last_additional_record() {
    let mac = [7; 32];
    let rdata = tsig(&mac, &[], TsigError::NOERROR).to_wire();
    let signed = message(&[a_record()], &[a_record(), tsig_record(&rdata)]);
    let found = find_tsig(&signed).expect("well formed").expect("signed");
    assert_eq!(found.name, dns("key."));
    assert_eq!(found.class, Class::ANY);
    assert_eq!(found.ttl, 0);
    assert_eq!(found.tsig.mac(), mac);
    assert_eq!(found.tsig.original_id, 0x1234);
    assert_eq!(found.tsig.time_signed(), 1_700_000_000);
    assert_eq!(found.tsig.other(), b"");
    assert_eq!(found.start, signed.len() - tsig_record(&rdata).len());
}

/// §5.2.3: Other Data comes back as it was written.
#[test]
fn s5_2_3_other_data() {
    let server_time = [0, 0, 0x65, 0x53, 0xf1, 0x2c];
    let rdata = tsig(&[], &server_time, TsigError::BADTIME).to_wire();
    let signed = message(&[], &[tsig_record(&rdata)]);
    let found = find_tsig(&signed).expect("well formed").expect("signed");
    assert_eq!(found.tsig.other(), server_time);
    assert_eq!(found.tsig.error, TsigError::BADTIME);
}

#[test]
fn s5_1_no_tsig_is_none() {
    assert_eq!(find_tsig(&message(&[a_record()], &[a_record()])), Ok(None));
}

/// §5.1: a query read says whether it holds a TSIG, wherever it stands: `find_tsig` judges the place.
#[test]
fn s5_1_a_query_read_knows_it_holds_a_tsig() {
    let rdata = tsig(&[7; 32], &[], TsigError::NOERROR).to_wire();
    let tsig = tsig_record(&rdata);
    let has = |wire: &[u8]| Query::read(wire).expect("reads").has_tsig();
    assert!(!has(&message(&[a_record()], &[a_record()])));
    assert!(has(&message(&[], std::slice::from_ref(&tsig))));
    assert!(has(&message(&[a_record()], &[a_record(), tsig.clone()])));
    assert!(has(&message(std::slice::from_ref(&tsig), &[a_record()])));
    // Twice, as with one: the flag is set, `find_tsig` refuses the message.
    assert!(has(&message(&[], &[tsig.clone(), tsig])));
}

/// §5.1: a TSIG anywhere else, twice, or followed by anything is an error.
#[test]
fn s5_1_misplaced_tsig() {
    let rdata = tsig(&[7; 32], &[], TsigError::NOERROR).to_wire();
    let tsig = tsig_record(&rdata);
    let in_answer = message(std::slice::from_ref(&tsig), &[a_record()]);
    let in_answer_last = message(&[a_record(), tsig.clone()], &[]);
    let not_last = message(&[], &[tsig.clone(), a_record()]);
    let twice = message(&[], &[tsig.clone(), tsig.clone()]);
    let mut trailing = message(&[], &[tsig]);
    trailing.push(0);
    for wire in [in_answer, in_answer_last, not_last, twice, trailing] {
        assert!(find_tsig(&wire).is_err(), "{wire:02x?}");
    }
}

/// §5.1: a TSIG counted in the authority section is misplaced too, whatever the answer section holds.
#[test]
fn s5_1_a_tsig_in_the_authority_section() {
    let rdata = tsig(&[7; 32], &[], TsigError::NOERROR).to_wire();
    let mut wire = message(&[], &[tsig_record(&rdata)]);
    wire[9] = 1; // NSCOUNT
    wire[11] = 0; // ARCOUNT
    assert!(find_tsig(&wire).is_err());
}

/// §4.2: data that is cut, has bytes after Other Data, or compresses the algorithm name is an error.
#[test]
fn s4_2_invalid_data() {
    let good = tsig(&[7; 32], &[], TsigError::NOERROR).to_wire();
    let mut extra = good.clone();
    extra.push(0);
    let cut = good[..good.len() - 1].to_vec();
    let mut compressed = vec![0xc0, 0x0c];
    compressed.extend_from_slice(&good[HMAC_SHA256.len()..]);
    for rdata in [extra, cut, compressed] {
        assert!(find_tsig(&message(&[], &[tsig_record(&rdata)])).is_err());
    }
}

/// A message is at most 65535 bytes (RFC 1035 §4.2.2).
#[test]
fn s5_1_a_message_over_65535_bytes_is_an_error() {
    let mut wire = message(&[a_record()], &[]);
    wire.resize(65535, 0);
    assert_eq!(find_tsig(&wire), Ok(None));
    wire.push(0);
    assert!(find_tsig(&wire).is_err());
}

#[test]
fn s5_1_a_cut_message_is_an_error() {
    let rdata = tsig(&[7; 32], &[], TsigError::NOERROR).to_wire();
    let signed = message(&[], &[tsig_record(&rdata)]);
    for len in 0..signed.len() {
        assert!(find_tsig(&signed[..len]).is_err(), "{len}");
    }
}

proptest! {
    /// §4.2: whatever the fields, the RDATA reads back as written.
    #[test]
    fn s4_2_rdata_round_trips(
        algorithm in name(),
        time in 0..=MAX_TIME_SIGNED,
        fudge: u16,
        id: u16,
        error: u16,
        mac in prop::collection::vec(any::<u8>(), 0..=64),
        other in prop::collection::vec(any::<u8>(), 0..=6),
    ) {
        let tsig = Tsig::new(algorithm, time, fudge, &mac, id, TsigError(error), &other)
            .expect("fits an RDATA");
        let wire = message(&[], &[tsig_record(&tsig.to_wire())]);
        let found = find_tsig(&wire).expect("well formed").expect("signed");
        prop_assert_eq!(found.tsig, tsig);
    }
}
