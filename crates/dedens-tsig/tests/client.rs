//! RFC 8945 §5.1 (the request), §5.4 (the client's checks of a response) and §5.4.3 (a response out of time), with
//! `util::Reference` signing what the crate refuses to.

use std::sync::LazyLock;

use dedens_proto::{Tsig, TsigError};
use dedens_testkit::dns;
use dedens_tsig::{
    Algorithm, Key, ResponseError, ResponseVerifier, Verified, sign_request, verify_request,
};

use crate::util::{Reference, capture_key, keyring, query, reference, strip, tsig, with_tsig};

const T: u64 = 1_700_000_000;

/// A response to a request of MAC `mac`, signed by the reference at `time`, cut to `mac_len`.
fn response(mac: &[u8], time: u64, mac_len: usize) -> Vec<u8> {
    let mut bare = query(0x1234, "example.org.");
    bare[2] = 0x80;
    reference().sign(mac, &bare, time, 300, mac_len).0
}

static KEY: LazyLock<Key> = LazyLock::new(capture_key);

fn verifier(mac: &[u8]) -> ResponseVerifier<'static> {
    ResponseVerifier::new(&KEY, mac)
}

/// §5.1, §5.4: a signed request, its server's response and the client's check make one round trip, through the
/// crate on both sides.
#[test]
fn s5_4_a_round_trip() {
    let keys = keyring();
    let key = capture_key();
    let mut request = query(0x1234, "example.org.");
    let mut verifier = sign_request(&key, &mut request, T).expect("room");
    let accepted = verify_request(&keys, &request, T)
        .expect("valid")
        .expect("signed");
    let mut reply = query(0x1234, "example.org.");
    reply[2] = 0x80;
    accepted.signer().sign(&mut reply, T + 1).expect("room");
    assert_eq!(verifier.verify(&reply, T + 1), Ok(Verified::Signed));
    assert_eq!(verifier.finish(), Ok(()));
}

/// The MAC an exchange keeps for the response of a request is the request'"'"'s own (RFC 8945 §5.3.1).
#[test]
fn s5_3_1_the_request_mac_is_the_one_signed() {
    let key = capture_key();
    let mut request = query(0x1234, "example.org.");
    let verifier = sign_request(&key, &mut request, T).expect("room");
    assert_eq!(verifier.request_mac(), tsig(&request).tsig.mac());
}

/// §5.4: a response that fails verification is not accepted and the client keeps waiting for the real one: every
/// refusal leaves the verifier as it was, so the real response still verifies.
#[test]
fn s5_4_a_refused_message_leaves_the_verifier_as_it_was() {
    let mac = [1; 32];
    let real = response(&mac, T, 32);
    let bare = strip(&real);
    let forged = reference().record(&bare, &[0; 32], T, 300, 0, &[]);
    let unsigned = reference().record(&bare, &[], T, 300, 17, &[]);
    let mut v = verifier(&mac);
    assert_eq!(v.verify(&forged, T), Err(ResponseError::BadSig));
    assert_eq!(
        v.verify(&unsigned, T),
        Err(ResponseError::Refused {
            error: TsigError::BADKEY,
            authenticated: false
        })
    );
    assert_eq!(
        v.verify(&real, T + 1000),
        Err(ResponseError::BadTime {
            time_signed: T,
            now: T + 1000
        })
    );
    assert_eq!(
        v.verify(&query(0x1234, "example.org."), T),
        Err(ResponseError::Missing)
    );
    assert_eq!(v.verify(&real, T), Ok(Verified::Signed));
    assert_eq!(v.finish(), Ok(()));
}

/// §5.4: a response with no TSIG is discarded, and a response that never came is no success either.
#[test]
fn s5_4_no_tsig_is_missing() {
    let mut v = verifier(&[1; 32]);
    assert_eq!(
        v.verify(&query(0x1234, "example.org."), T),
        Err(ResponseError::Missing)
    );
    assert_eq!(verifier(&[1; 32]).finish(), Err(ResponseError::Missing));
}

/// §5.4: the response MAC takes the request MAC: another request MAC, another message, or another time does not
/// verify.
#[test]
fn s5_4_a_response_is_bound_to_its_request() {
    let mac = [1; 32];
    let good = response(&mac, T, 32);
    assert_eq!(verifier(&mac).verify(&good, T), Ok(Verified::Signed));
    assert_eq!(
        verifier(&[2; 32]).verify(&good, T),
        Err(ResponseError::BadSig)
    );
    let mut message = good.clone();
    message[3] ^= 1;
    assert_eq!(
        verifier(&mac).verify(&message, T),
        Err(ResponseError::BadSig)
    );
}

/// §5.4.3: a response whose time is further than its fudge from the client's clock is an error, at the edge not.
#[test]
fn s5_4_3_time_is_within_the_fudge() {
    let mac = [1; 32];
    for now in [T - 300, T, T + 300] {
        assert_eq!(
            verifier(&mac).verify(&response(&mac, T, 32), now),
            Ok(Verified::Signed)
        );
    }
    for now in [T - 301, T + 301] {
        assert_eq!(
            verifier(&mac).verify(&response(&mac, T, 32), now),
            Err(ResponseError::BadTime {
                time_signed: T,
                now
            })
        );
    }
}

/// §5.4.1: a TSIG of another key or algorithm than the request's is refused before its MAC is looked at.
#[test]
fn s5_4_1_another_key_or_algorithm() {
    let mac = [1; 32];
    let other_name = Key::new(dns("other-key."), Algorithm::HmacSha256, vec![5; 16]).expect("key");
    let mut bare = query(0x1234, "example.org.");
    bare[2] = 0x80;
    let wire = Reference::new(&other_name, &[5; 16])
        .sign(&mac, &bare, T, 300, 32)
        .0;
    assert_eq!(verifier(&mac).verify(&wire, T), Err(ResponseError::Key));
    let sha1 = Key::new(dns("dedens-test-key."), Algorithm::HmacSha1, vec![5; 16]).expect("key");
    let wire = Reference::new(&sha1, &[5; 16])
        .sign(&mac, &bare, T, 300, 20)
        .0;
    assert_eq!(verifier(&mac).verify(&wire, T), Err(ResponseError::Key));
}

/// §5.2.2.1, D205: the client accepts a full MAC alone; a server that truncates is refused.
#[test]
fn s5_2_2_1_a_truncated_response_mac() {
    let mac = [1; 32];
    assert_eq!(
        verifier(&mac).verify(&response(&mac, T, 16), T),
        Err(ResponseError::MacSize)
    );
}

/// §4.2: a TSIG of class other than ANY or a TTL is refused; an unreadable message is `Malformed`.
#[test]
fn s4_2_class_ttl_and_garbage() {
    let mac = [1; 32];
    let good = response(&mac, T, 32);
    let class_at = tsig(&good).start + dns("dedens-test-key.").wire_len() + 2;
    let mut class = good.clone();
    class[class_at + 1] = 1;
    assert_eq!(
        verifier(&mac).verify(&class, T),
        Err(ResponseError::ClassOrTtl)
    );
    assert!(matches!(
        verifier(&mac).verify(&good[..good.len() - 1], T),
        Err(ResponseError::Malformed(_))
    ));
}

/// §5.3.2, §5.4: an error the server returns is `Refused`, authenticated only when its MAC verifies: an empty
/// MAC is not, a MAC that is wrong is `BadSig`.
#[test]
fn s5_3_2_refused_responses() {
    let mac = [1; 32];
    let bare = strip(&response(&mac, T, 32));
    for error in [16, 17, 22] {
        let unsigned = reference().record(&bare, &[], T, 300, error, &[]);
        assert_eq!(
            verifier(&mac).verify(&unsigned, T),
            Err(ResponseError::Refused {
                error: TsigError(error),
                authenticated: false
            })
        );
    }
    let forged = reference().record(&bare, &[0; 32], T, 300, 22, &[]);
    assert_eq!(
        verifier(&mac).verify(&forged, T),
        Err(ResponseError::BadSig)
    );
    let tsig =
        Tsig::new(dns("hmac-sha256."), T, 300, &[], 1, TsigError::BADKEY, &[]).expect("fits");
    let wire = with_tsig(&bare, &dns("whatever."), &tsig);
    assert_eq!(
        verifier(&mac).verify(&wire, T),
        Err(ResponseError::Refused {
            error: TsigError::BADKEY,
            authenticated: false
        })
    );
}

/// §5.2.2.1, §5.4.4: a server's BADTRUNC for a truncated request verifies against the request's truncated MAC,
/// which is the one its digest took.
#[test]
fn s5_4_4_a_badtrunc_response_verifies() {
    let keys = keyring();
    let (request, mac) = reference().sign(&[], &query(0x1234, "example.org."), T, 300, 16);
    let refusal = verify_request(&keys, &request, T).expect_err("truncated");
    let dedens_tsig::Refusal::NotAuth(not_auth) = refusal else {
        panic!("not a NOTAUTH");
    };
    let mut reply = query(0x1234, "example.org.");
    reply[2] = 0x80;
    reply[3] = 9;
    not_auth.sign(&mut reply, T + 1).expect("room");
    assert_eq!(
        verifier(&mac).verify(&reply, T + 1),
        Err(ResponseError::Refused {
            error: TsigError::BADTRUNC,
            authenticated: true
        })
    );
    // With the full MAC of the request instead, it does not verify.
    let full = reference().mac(&[], &query(0x1234, "example.org."), T, 300, 0, &[], false);
    assert_eq!(
        verifier(&full).verify(&reply, T + 1),
        Err(ResponseError::BadSig)
    );
}
