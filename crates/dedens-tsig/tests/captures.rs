//! RFC 8945 §4.3, §5.2, §5.3, §5.3.2 and §5.4 against the exchanges Knot 3.6.2 had with `kdig` and `knsupdate`
//! (D203): every request verifies, every response verifies, and what this crate signs for the same request is
//! Knot's response, byte for byte.

use dedens_proto::TsigError;
use dedens_testkit::authoritative::{Packet, Peer, Recording};
use dedens_tsig::{ResponseError, ResponseVerifier, Verified, verify_request};

use crate::util::{capture_key, exchanges, keyring, strip, tsig};

/// The signed exchanges with a NOERROR response: AXFR, IXFR from the current serial, UPDATE and the AXFR after it.
const SIGNED: [&str; 3] = ["axfr-tsig", "ixfr-tsig-uptodate", "update-signed"];

/// §5.2, §5.3: Knot's signed requests verify, and signing its response with the request's MAC gives its bytes.
#[test]
fn s5_3_the_signature_of_knots_response_is_ours() {
    let keys = keyring();
    for id in SIGNED {
        for (request, response) in exchanges(id) {
            let time = tsig(&request.message).tsig.time_signed();
            let verified = verify_request(&keys, &request.message, time)
                .expect("a valid request")
                .expect("signed");
            assert_eq!(verified.mac(), tsig(&request.message).tsig.mac());
            let mut ours = strip(&response.message);
            let response_time = tsig(&response.message).tsig.time_signed();
            verified
                .signer()
                .sign(&mut ours, response_time)
                .expect("room");
            assert_eq!(ours, response.message, "{id}");
        }
    }
}

/// §5.4: the client verifies Knot's signed responses, and the request's own signature is the one Knot checked.
#[test]
fn s5_4_knots_responses_verify() {
    let key = capture_key();
    for id in SIGNED {
        for (request, response) in exchanges(id) {
            let mac = tsig(&request.message).tsig.mac().to_vec();
            let mut verifier = ResponseVerifier::new(&key, &mac);
            let time = tsig(&response.message).tsig.time_signed();
            assert_eq!(
                verifier.verify(&response.message, time),
                Ok(Verified::Signed),
                "{id}"
            );
            assert_eq!(verifier.finish(), Ok(()));
        }
    }
}

/// §5.3.1: a stream of five messages from Knot: the client accepts each, and the server's signer at Knot's times
/// writes Knot's bytes for each: the first over the request's MAC, the next ones over the MAC before and the timers.
#[test]
fn s5_3_1_knots_stream_verifies_and_is_reproduced() {
    let recording = Recording::read("axfr-tsig-stream");
    let request = &recording.messages[0];
    assert_eq!(request.from, Peer::Client);
    let responses: Vec<&Packet> = recording.messages[1..].iter().collect();
    assert!(responses.len() >= 3, "{} messages", responses.len());
    assert!(responses.iter().all(|packet| packet.from == Peer::Server));

    let key = capture_key();
    let mut verifier = ResponseVerifier::new(&key, tsig(&request.message).tsig.mac());
    for packet in &responses {
        let time = tsig(&packet.message).tsig.time_signed();
        assert_eq!(verifier.verify(&packet.message, time), Ok(Verified::Signed));
    }
    assert_eq!(verifier.finish(), Ok(()));

    let keys = keyring();
    let time = tsig(&request.message).tsig.time_signed();
    let mut signer = verify_request(&keys, &request.message, time)
        .expect("a valid request")
        .expect("signed")
        .signer();
    for (i, packet) in responses.iter().enumerate() {
        let mut ours = strip(&packet.message);
        signer
            .sign(&mut ours, tsig(&packet.message).tsig.time_signed())
            .expect("room");
        assert_eq!(ours, packet.message, "message {i}");
    }
}

/// §5.3.1: Knot's stream does not verify with a message dropped, or swapped with the next.
#[test]
fn s5_3_1_knots_stream_detects_a_dropped_or_swapped_message() {
    let recording = Recording::read("axfr-tsig-stream");
    let key = capture_key();
    let mac = tsig(&recording.messages[0].message).tsig.mac().to_vec();
    let responses: Vec<&[u8]> = recording.messages[1..]
        .iter()
        .map(|packet| packet.message.as_slice())
        .collect();
    let run = |order: &[usize]| {
        let mut verifier = ResponseVerifier::new(&key, &mac);
        order.iter().try_for_each(|&i| {
            let time = tsig(responses[i]).tsig.time_signed();
            verifier.verify(responses[i], time).map(drop)
        })
    };
    let all: Vec<usize> = (0..responses.len()).collect();
    assert_eq!(run(&all), Ok(()));
    let mut dropped = all.clone();
    dropped.remove(1);
    assert_eq!(run(&dropped), Err(ResponseError::BadSig));
    let mut swapped = all;
    swapped.swap(1, 2);
    assert_eq!(run(&swapped), Err(ResponseError::BadSig));
}

/// §5.2.1: a response must be of the request's key: Knot's response to another request does not verify.
#[test]
fn s5_4_a_response_to_another_request_does_not_verify() {
    let key = capture_key();
    let (first, _) = &exchanges("axfr-tsig")[0];
    let (_, other) = &exchanges("ixfr-tsig-uptodate")[0];
    let mac = tsig(&first.message).tsig.mac().to_vec();
    let time = tsig(&other.message).tsig.time_signed();
    assert_eq!(
        ResponseVerifier::new(&key, &mac).verify(&other.message, time),
        Err(ResponseError::BadSig)
    );
}

/// §5.2.2, §5.3.2: a wrong secret is BADSIG, answered unsigned: Knot's response has an empty MAC and the request's
/// Time Signed (`knot_tsig_add`), and so has ours, whatever the server's clock says.
#[test]
fn s5_3_2_bad_secret_is_unsigned_badsig() {
    let keys = keyring();
    for id in ["axfr-tsig-bad-secret", "update-bad-secret"] {
        let (request, response) = exchanges(id).remove(0);
        let time = tsig(&request.message).tsig.time_signed();
        let refusal = verify_request(&keys, &request.message, time).expect_err("a wrong secret");
        let dedens_tsig::Refusal::NotAuth(not_auth) = refusal else {
            panic!("{id}: not a NOTAUTH");
        };
        assert_eq!(not_auth.error(), TsigError::BADSIG);
        assert!(!not_auth.is_signed());
        // Knot's response: the request's time, an empty MAC, error 16. The clock is not the request's, to show that
        // the time in the answer is the request's and not the clock's.
        let mut ours = strip(&response.message);
        not_auth.sign(&mut ours, time + 1000).expect("room");
        assert_eq!(ours, response.message, "{id}");

        let key = capture_key();
        let mac = tsig(&request.message).tsig.mac().to_vec();
        assert_eq!(
            ResponseVerifier::new(&key, &mac).verify(&response.message, time),
            Err(ResponseError::Refused {
                error: TsigError::BADSIG,
                authenticated: false
            })
        );
    }
}

/// §5.2.3, §5.3.2: a clock 600 s off is BADTIME, signed with the client's time and the server's as Other Data:
/// what this crate signs for it is Knot's response, byte for byte, and the client verifies it.
#[test]
fn s5_2_3_bad_time_is_signed_with_both_times() {
    let keys = keyring();
    let (request, response) = exchanges("axfr-tsig-bad-time").remove(0);
    let sent = tsig(&request.message).tsig;
    let reply = tsig(&response.message).tsig;
    assert_eq!(reply.error, TsigError::BADTIME);
    assert_eq!(reply.time_signed(), sent.time_signed());
    let mut other = [0; 8];
    other[2..].copy_from_slice(reply.other());
    let server_time = u64::from_be_bytes(other);
    assert!(server_time.abs_diff(sent.time_signed()) > 300);

    let refusal = verify_request(&keys, &request.message, server_time).expect_err("600 s off");
    let dedens_tsig::Refusal::NotAuth(not_auth) = refusal else {
        panic!("not a NOTAUTH");
    };
    assert_eq!(not_auth.error(), TsigError::BADTIME);
    assert!(not_auth.is_signed());
    let mut ours = strip(&response.message);
    not_auth.sign(&mut ours, server_time).expect("room");
    assert_eq!(ours, response.message);

    // The client's clock is the request's time: the response verifies there, as an error of the server.
    let key = capture_key();
    assert_eq!(
        ResponseVerifier::new(&key, sent.mac()).verify(&response.message, sent.time_signed()),
        Err(ResponseError::Refused {
            error: TsigError::BADTIME,
            authenticated: true
        })
    );
}

/// §5.2.1, §5.3.2: an unknown key is BADKEY, unsigned. Knot answers NOTAUTH with no TSIG record at all, which a
/// client takes as a response without TSIG (§5.4).
#[test]
fn s5_2_1_unknown_key_is_badkey() {
    let keys = keyring();
    let (request, response) = exchanges("axfr-tsig-unknown-key").remove(0);
    let time = tsig(&request.message).tsig.time_signed();
    let dedens_tsig::Refusal::NotAuth(not_auth) =
        verify_request(&keys, &request.message, time).expect_err("an unknown key")
    else {
        panic!("not a NOTAUTH");
    };
    assert_eq!(not_auth.error(), TsigError::BADKEY);
    assert!(!not_auth.is_signed());
    assert_eq!(dedens_proto::find_tsig(&response.message), Ok(None));
    let key = capture_key();
    assert_eq!(
        ResponseVerifier::new(&key, &[0; 32]).verify(&response.message, time),
        Err(ResponseError::Missing)
    );
}

/// §5.2: the request of a key the zone's ACL does not allow is valid TSIG; refusing it is the server's policy.
#[test]
fn s5_2_a_key_not_allowed_still_verifies() {
    let (request, _) = exchanges("update-signed-key-not-allowed").remove(0);
    let time = tsig(&request.message).tsig.time_signed();
    assert!(
        verify_request(&keyring(), &request.message, time)
            .expect("valid")
            .is_some()
    );
}
