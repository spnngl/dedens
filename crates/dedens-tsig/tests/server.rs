//! RFC 8945 §5.2 (the server's checks in order), §5.2.2.1 (truncated MACs), §5.3 (the response) and §5.3.2 (error
//! returns), against `ring` alone in `util::Reference`.

use dedens_proto::{Tsig, TsigError, find_tsig};
use dedens_testkit::dns;
use dedens_tsig::{
    Algorithm, FormatError, Key, Keyring, NotAuth, Refusal, SignError, sign_request, verify_request,
};

use crate::util::{Reference, capture_key, keyring, query, reference, strip, tsig, with_tsig};

const T: u64 = 1_700_000_000;

fn signed(mac_len: usize, time: u64) -> (Vec<u8>, Vec<u8>) {
    reference().sign(&[], &query(0x1234, "example.org."), time, 300, mac_len)
}

#[expect(
    clippy::panic,
    reason = "a test helper: any other refusal is the failure"
)]
fn not_auth(refusal: Refusal<'_>) -> NotAuth<'_> {
    match refusal {
        Refusal::NotAuth(not_auth) => not_auth,
        Refusal::Format(format) => panic!("FORMERR: {format}"),
    }
}

fn error_of(wire: &[u8], now: u64) -> (TsigError, bool) {
    let keys = keyring();
    let refusal = verify_request(&keys, wire, now).expect_err("refused");
    let not_auth = not_auth(refusal);
    (not_auth.error(), not_auth.is_signed())
}

#[expect(
    clippy::panic,
    reason = "a test helper: any other refusal is the failure"
)]
fn format_of(wire: &[u8]) -> FormatError {
    match verify_request(&keyring(), wire, T).expect_err("refused") {
        Refusal::Format(format) => format,
        Refusal::NotAuth(not_auth) => panic!("NOTAUTH {}", not_auth.error()),
    }
}

/// §5.2: a message with no TSIG is not for this crate to judge.
#[test]
fn s5_2_no_tsig_is_none() {
    assert!(matches!(
        verify_request(&keyring(), &query(1, "a."), T),
        Ok(None)
    ));
}

/// §5.1, §5.2: what `sign_request` signs verifies, and its MAC is the reference's.
#[test]
fn s5_1_a_signed_request_verifies() {
    let keys = keyring();
    let mut wire = query(0x1234, "example.org.");
    let key = capture_key();
    let verifier = sign_request(&key, &mut wire, T).expect("room");
    let (expected, mac) = signed(32, T);
    assert_eq!(wire, expected);
    let request = verify_request(&keys, &wire, T)
        .expect("valid")
        .expect("signed");
    assert_eq!(request.mac(), mac);
    assert_eq!(request.key().name(), capture_key().name());
    drop(verifier);
}

/// §6: each algorithm signs as the reference does, and its MAC is the full output (20, 32, 48, 64 bytes).
#[test]
fn s6_each_algorithm_matches_the_reference() {
    for algorithm in [
        Algorithm::HmacSha1,
        Algorithm::HmacSha256,
        Algorithm::HmacSha384,
        Algorithm::HmacSha512,
    ] {
        let secret = b"a shared secret for the tests".to_vec();
        let key = Key::new(dns("k."), algorithm, secret.clone()).expect("key");
        let keys = Keyring::new([key.clone()]).expect("one key");
        let mut wire = query(7, "example.org.");
        sign_request(&key, &mut wire, T).expect("room");
        let (expected, mac) = Reference::new(&key, &secret).sign(
            &[],
            &query(7, "example.org."),
            T,
            300,
            algorithm.mac_len(),
        );
        assert_eq!(wire, expected, "{algorithm}");
        assert_eq!(mac.len(), algorithm.mac_len());
        assert!(verify_request(&keys, &wire, T).expect("valid").is_some());
    }
}

/// §4.3.3: the key's name is compared in canonical form, without case, in the MAC and in the keyring.
#[test]
fn s4_3_3_key_names_have_no_case() {
    let upper = Key::new(dns("DEDENS-Test-Key."), Algorithm::HmacSha256, vec![9; 16]).expect("key");
    let lower = Key::new(dns("dedens-test-key."), Algorithm::HmacSha256, vec![9; 16]).expect("key");
    let mut wire = query(1, "a.");
    sign_request(&upper, &mut wire, T).expect("room");
    let keys = Keyring::new([lower]).expect("one key");
    assert!(verify_request(&keys, &wire, T).expect("valid").is_some());
}

/// §4.3.2: the ID of the signed message is the Original ID, so a forwarder may change the header's.
#[test]
fn s4_3_2_a_changed_id_verifies() {
    let (mut wire, _) = signed(32, T);
    wire[..2].copy_from_slice(&0xbeef_u16.to_be_bytes());
    assert!(
        verify_request(&keyring(), &wire, T)
            .expect("valid")
            .is_some()
    );
    assert_eq!(tsig(&wire).tsig.original_id, 0x1234);
}

/// §5.2.3: the time is right within the fudge either side, wrong past it, and the error is signed.
#[test]
fn s5_2_3_the_fudge_is_either_side() {
    let (wire, _) = signed(32, T);
    for now in [T - 300, T, T + 300] {
        assert!(
            verify_request(&keyring(), &wire, now)
                .expect("in time")
                .is_some()
        );
    }
    for now in [T - 301, T + 301, T + 600] {
        assert_eq!(error_of(&wire, now), (TsigError::BADTIME, true), "{now}");
    }
}

/// §5.2.3: a BADTIME response holds the client's time, its fudge and the server's time as 6 bytes of Other Data,
/// and its MAC covers the request MAC; the reference computes it.
#[test]
fn s5_2_3_bad_time_response_layout() {
    let (request, request_mac) = signed(32, T);
    let keys = keyring();
    let not_auth = not_auth(verify_request(&keys, &request, T + 1000).expect_err("late"));
    let mut response = query(0x1234, "example.org.");
    response[2] = 0x80;
    response[3] = 9;
    not_auth.sign(&mut response, T + 1000).expect("room");
    let found = tsig(&response);
    assert_eq!(found.tsig.error, TsigError::BADTIME);
    assert_eq!(found.tsig.time_signed(), T);
    assert_eq!(found.tsig.fudge, 300);
    assert_eq!(found.tsig.other(), &(T + 1000).to_be_bytes()[2..]);
    let mut bare = response.clone();
    bare.truncate(found.start);
    bare[10..12].copy_from_slice(&[0, 0]);
    let mac = reference().mac(
        &crate::util::sized(&request_mac),
        &bare,
        T,
        300,
        18,
        &(T + 1000).to_be_bytes()[2..],
        false,
    );
    assert_eq!(found.tsig.mac(), mac);
}

/// §5.2.2, §5.3.2: a MAC that does not verify is BADSIG, unsigned, whatever the time and truncation.
#[test]
fn s5_2_2_a_wrong_mac_is_badsig() {
    let (mut wire, _) = signed(32, T);
    let start = tsig(&wire).start;
    let mac_at = start + dns("dedens-test-key.").wire_len() + 10 + 13 + 6 + 2 + 2;
    wire[mac_at] ^= 1;
    assert_eq!(error_of(&wire, T), (TsigError::BADSIG, false));
    // The MAC is checked before the time.
    assert_eq!(error_of(&wire, T + 5000), (TsigError::BADSIG, false));
    // And before the truncation policy.
    let (mut short, _) = signed(16, T);
    let at = tsig(&short).start + dns("dedens-test-key.").wire_len() + 10 + 13 + 6 + 2 + 2;
    short[at] ^= 1;
    assert_eq!(error_of(&short, T), (TsigError::BADSIG, false));
}

/// §5.2.1: a key the server does not hold, or an algorithm that is not the key's, is BADKEY, unsigned; so is an
/// algorithm this crate lacks, `hmac-md5` (§6).
#[test]
fn s5_2_1_unknown_key_or_algorithm_is_badkey() {
    let secret = vec![1; 16];
    let other_name =
        Key::new(dns("other-key."), Algorithm::HmacSha256, secret.clone()).expect("key");
    let mut wire = query(1, "a.");
    sign_request(&other_name, &mut wire, T).expect("room");
    assert_eq!(error_of(&wire, T), (TsigError::BADKEY, false));

    let other_algorithm =
        Key::new(dns("dedens-test-key."), Algorithm::HmacSha1, secret).expect("key");
    let mut wire = query(1, "a.");
    sign_request(&other_algorithm, &mut wire, T).expect("room");
    assert_eq!(error_of(&wire, T), (TsigError::BADKEY, false));

    let md5 = Tsig::new(
        dns("hmac-md5.sig-alg.reg.int."),
        T,
        300,
        &[0; 16],
        1,
        TsigError::NOERROR,
        &[],
    )
    .expect("fits");
    let wire = with_tsig(&query(1, "a."), &dns("dedens-test-key."), &md5);
    assert_eq!(error_of(&wire, T), (TsigError::BADKEY, false));
}

/// §5.3.2: an unsigned error has the request's key and algorithm names, an empty MAC, the error code, the request's
/// Time Signed whatever the clock, and the ID of the response.
#[test]
fn s5_3_2_an_unsigned_error_layout() {
    let secret = vec![1; 16];
    let key = Key::new(dns("other-key."), Algorithm::HmacSha512, secret).expect("key");
    let mut wire = query(0x4242, "a.");
    sign_request(&key, &mut wire, T).expect("room");
    let keys = keyring();
    let not_auth = not_auth(verify_request(&keys, &wire, T).expect_err("unknown"));
    let mut response = query(0x4242, "a.");
    not_auth.sign(&mut response, T + 1).expect("room");
    let found = tsig(&response);
    assert_eq!(found.name, dns("other-key."));
    assert_eq!(found.tsig.algorithm, dns("hmac-sha512."));
    assert_eq!(found.tsig.mac(), b"");
    assert_eq!(found.tsig.error, TsigError::BADKEY);
    assert_eq!(found.tsig.original_id, 0x4242);
    assert_eq!(found.tsig.time_signed(), T);
}

/// §5.2.2.1: a MAC cut to a length the RFC allows is compared by its prefix, and then refused by the policy:
/// BADTRUNC, signed; for SHA-256 that is 16 to 31 bytes, for SHA-1 10 to 19.
#[test]
fn s5_2_2_1_truncated_macs_are_badtrunc() {
    for len in [16, 20, 31] {
        let (wire, _) = signed(len, T);
        assert_eq!(error_of(&wire, T), (TsigError::BADTRUNC, true), "{len}");
    }
    // After the time check.
    let (wire, _) = signed(16, T);
    assert_eq!(error_of(&wire, T + 1000), (TsigError::BADTIME, true));

    let secret = b"sha1 secret".to_vec();
    let key = Key::new(dns("dedens-test-key."), Algorithm::HmacSha1, secret.clone()).expect("key");
    let keys = Keyring::new([key.clone()]).expect("one key");
    for len in [10, 12, 19] {
        let (wire, _) = Reference::new(&key, &secret).sign(&[], &query(1, "a."), T, 300, len);
        let refusal = verify_request(&keys, &wire, T).expect_err("truncated");
        assert_eq!(not_auth(refusal).error(), TsigError::BADTRUNC, "{len}");
    }
}

/// §5.2.2.1: a MAC longer than the output, or shorter than the larger of 10 bytes and half of it, is FORMERR.
#[test]
fn s5_2_2_1_mac_sizes_outside_the_rules_are_formerr() {
    let (wire, mac) = signed(32, T);
    let mut long = strip(&wire);
    let mut mac33 = mac.clone();
    mac33.push(0);
    long = reference().record(&long, &mac33, T, 300, 0, &[]);
    assert_eq!(format_of(&long), FormatError::MacSize);
    for len in [0, 1, 10, 15] {
        let wire = reference().record(&strip(&wire), &mac[..len], T, 300, 0, &[]);
        assert_eq!(format_of(&wire), FormatError::MacSize, "{len}");
    }
}

/// §5.2, §4.2: a TSIG that is not last, or twice, or of another class or with a TTL, or unreadable, is FORMERR.
#[test]
fn s5_2_a_malformed_tsig_is_formerr() {
    let (wire, _) = signed(32, T);
    let found = tsig(&wire);
    let record = wire[found.start..].to_vec();

    let mut twice = wire.clone();
    twice[10..12].copy_from_slice(&2_u16.to_be_bytes());
    twice.extend_from_slice(&record);
    assert!(matches!(format_of(&twice), FormatError::Malformed(_)));

    let mut not_last = strip(&wire);
    let mut record_then_a = record.clone();
    record_then_a.extend_from_slice(dns("a.").to_wire(&mut [0; 255]));
    record_then_a.extend_from_slice(&[0, 1, 0, 1, 0, 0, 0, 0, 0, 4, 192, 0, 2, 1]);
    not_last[10..12].copy_from_slice(&2_u16.to_be_bytes());
    not_last.extend_from_slice(&record_then_a);
    assert!(matches!(format_of(&not_last), FormatError::Malformed(_)));

    let class_at = found.start + dns("dedens-test-key.").wire_len() + 2;
    let mut class = wire.clone();
    class[class_at + 1] = 1;
    assert_eq!(format_of(&class), FormatError::ClassOrTtl);
    let mut ttl = wire.clone();
    ttl[class_at + 5] = 1;
    assert_eq!(format_of(&ttl), FormatError::ClassOrTtl);

    assert!(matches!(
        format_of(&wire[..wire.len() - 1]),
        FormatError::Malformed(_)
    ));
}

/// §5.3: the response's MAC takes the request MAC, then the response and the variables: the reference computes
/// the same, and the client's checks hold in `client.rs`.
#[test]
fn s5_3_a_response_is_signed_over_the_request_mac() {
    let keys = keyring();
    let (request, request_mac) = signed(32, T);
    let verified = verify_request(&keys, &request, T)
        .expect("valid")
        .expect("signed");
    let mut response = query(0x1234, "example.org.");
    response[2] = 0x80;
    let bare = response.clone();
    verified.signer().sign(&mut response, T + 2).expect("room");
    let (expected, _) = reference().sign(&request_mac, &bare, T + 2, 300, 32);
    assert_eq!(response, expected);
    assert_eq!(
        find_tsig(&response)
            .expect("ok")
            .expect("signed")
            .tsig
            .error,
        TsigError::NOERROR
    );
}

/// §5.3: the record goes in up to the last byte a message may have: the owner, 10 bytes, the algorithm name, the
/// fixed fields and a full MAC: [`Key::record_len`].
#[test]
fn s5_3_the_record_fits_to_the_last_byte() {
    let keys = keyring();
    let (request, _) = signed(32, T);
    let verified = verify_request(&keys, &request, T)
        .expect("valid")
        .expect("signed");
    let record = dns("dedens-test-key.").wire_len() + 10 + 13 + 16 + 32;
    assert_eq!(verified.key().record_len(), record);
    let mut fits = query(1, "a.");
    fits.resize(65535 - record, 0);
    verified.signer().sign(&mut fits, T).expect("room");
    assert_eq!(fits.len(), 65535);
    let mut over = query(1, "a.");
    over.resize(65535 - record + 1, 0);
    assert_eq!(
        verified.signer().sign(&mut over, T),
        Err(SignError::TooLong)
    );
    assert_eq!(over.len(), 65535 - record + 1);

    // In place: up to the end of the buffer, and never past the longest message whatever the buffer.
    let message = query(1, "a.");
    let mut buffer = message.clone();
    buffer.resize(message.len() + record, 0);
    let len = message.len();
    let signed = verified.signer().sign_in((&mut buffer, len), T);
    assert_eq!(signed, Ok(message.len() + record));
    let short = &mut buffer[..message.len() + record - 1];
    let signed = verified.signer().sign_in((short, len), T);
    assert_eq!(signed, Err(SignError::TooLong));
    let mut wide = fits.clone();
    wide.resize(65535 + record, 0);
    let signed = verified
        .signer()
        .sign_in((&mut wide, 65535 - record + 1), T);
    assert_eq!(signed, Err(SignError::TooLong));
}

/// §5.3: a message with no room for the record, or no header, is an error, and the signer is unchanged.
#[test]
fn s5_3_signing_errors() {
    let keys = keyring();
    let (request, _) = signed(32, T);
    let verified = verify_request(&keys, &request, T)
        .expect("valid")
        .expect("signed");
    let mut signer = verified.signer();
    assert_eq!(signer.sign(&mut vec![0; 11], T), Err(SignError::Header));
    let mut long = query(1, "a.");
    long.resize(65535, 0);
    assert_eq!(signer.sign(&mut long, T), Err(SignError::TooLong));
    let mut full = query(1, "a.");
    full[10..12].copy_from_slice(&u16::MAX.to_be_bytes());
    assert_eq!(signer.sign(&mut full, T), Err(SignError::Count));
    // Still the first message of the response: it takes the request MAC.
    let mut response = query(0x1234, "example.org.");
    signer.sign(&mut response, T).expect("room");
    let (expected, _) =
        reference().sign(verified.mac(), &query(0x1234, "example.org."), T, 300, 32);
    assert_eq!(response, expected);
}
