//! RFC 8945 §5.3.1: TSIG on a TCP stream of responses: the first message as an answer, the later ones chained to the
//! MAC before and signed over the timers alone, up to 99 messages in a row with no TSIG accepted, the first and
//! the last signed. The stream is as long as the root AXFR capture's (D203).

use dedens_proto::find_tsig;
use dedens_testkit::authoritative::{Peer, Recording};
use dedens_tsig::{
    MAX_UNSIGNED, ResponseError, ResponseSigner, ResponseVerifier, Verified, sign_request,
    verify_request,
};

use crate::util::{capture_key, keyring, query, reference, tsig};

const T: u64 = 1_700_000_000;

/// The messages the server sent in the root AXFR capture.
fn root_axfr() -> Vec<Vec<u8>> {
    Recording::read("axfr-root")
        .messages
        .into_iter()
        .filter(|packet| packet.from == Peer::Server)
        .map(|packet| packet.message)
        .collect()
}

/// A signed request for the root's AXFR, the MAC it carries.
fn request() -> (Vec<u8>, Vec<u8>) {
    let mut wire = query(0x1234, ".");
    sign_request(&capture_key(), &mut wire, T).expect("room");
    let mac = tsig(&wire).tsig.mac().to_vec();
    (wire, mac)
}

/// The root AXFR signed by the crate's `ResponseSigner`, message `i` at time `T + i`.
fn signed_stream() -> (Vec<u8>, Vec<Vec<u8>>) {
    let keys = keyring();
    let (wire, mac) = request();
    let verified = verify_request(&keys, &wire, T)
        .expect("valid")
        .expect("signed");
    let mut signer: ResponseSigner<'_> = verified.signer();
    let stream = root_axfr()
        .into_iter()
        .zip(0..)
        .map(|(mut message, i)| {
            signer.sign(&mut message, T + i).expect("room");
            message
        })
        .collect();
    (mac, stream)
}

/// Verifies `stream` in order against a request of MAC `mac`, at time `T + 100`, then ends it.
fn run(mac: &[u8], stream: &[Vec<u8>]) -> Result<(), ResponseError> {
    let key = capture_key();
    let mut verifier = ResponseVerifier::new(&key, mac);
    for message in stream {
        verifier.verify(message, T + 100)?;
    }
    verifier.finish()
}

/// §5.3.1: the capture is a stream of this length, signed message by message and verified message by message.
#[test]
fn s5_3_1_a_stream_as_long_as_the_root_axfr() {
    let (mac, stream) = signed_stream();
    assert!(stream.len() > 50, "{} messages", stream.len());
    assert_eq!(run(&mac, &stream), Ok(()));
}

/// §5.3.1: the first message takes the request MAC and the variables, each later one the MAC before and the timers:
/// the reference signs the same bytes.
#[test]
fn s5_3_1_the_chain_is_the_reference() {
    let (mac, stream) = signed_stream();
    let messages = root_axfr();
    let (first, mut prior) = reference().sign(&mac, &messages[0], T, 300, 32);
    assert_eq!(stream[0], first);
    for (i, message) in messages.iter().enumerate().skip(1) {
        let (expected, next) =
            reference().sign_next(&prior, &[], message, T + u64::try_from(i).expect("small"));
        assert_eq!(stream[i], expected, "message {i}");
        prior = next;
    }
}

/// §5.3.1: the MAC of each message covers the one before, so a message lost, repeated or moved fails the next.
#[test]
fn s5_3_1_the_chain_detects_changes() {
    let (mac, stream) = signed_stream();

    let mut dropped = stream.clone();
    dropped.remove(5);
    assert_eq!(run(&mac, &dropped), Err(ResponseError::BadSig));

    let mut repeated = stream.clone();
    repeated.insert(3, stream[2].clone());
    assert_eq!(run(&mac, &repeated), Err(ResponseError::BadSig));

    let mut swapped = stream.clone();
    swapped.swap(7, 8);
    assert_eq!(run(&mac, &swapped), Err(ResponseError::BadSig));

    let mut altered = stream.clone();
    altered[40][20] ^= 1;
    assert_eq!(run(&mac, &altered), Err(ResponseError::BadSig));

    // Of another request: the first message's MAC covers the request MAC.
    assert_eq!(run(&[7; 32], &stream), Err(ResponseError::BadSig));
}

/// §5.3.1: every message of the stream is signed and so verifies, a stream cut after any of them too: the AXFR
/// layer, which sees the closing SOA, is what notices a cut (RFC 5936 §2.2).
#[test]
fn s5_3_1_a_cut_stream_is_signed_to_its_end() {
    let (mac, stream) = signed_stream();
    assert_eq!(run(&mac, &stream[..stream.len() - 1]), Ok(()));
    assert_eq!(run(&mac, &stream[..1]), Ok(()));
}

/// §5.3.1: the Time Signed of successive messages does not decrease: an equal one passes, an earlier one is refused.
#[test]
fn s5_3_1_time_signed_does_not_decrease() {
    let keys = keyring();
    let (wire, mac) = request();
    let mut signer = verify_request(&keys, &wire, T)
        .expect("valid")
        .expect("signed")
        .signer();
    let messages = root_axfr();
    let times = [T + 10, T + 10, T + 5];
    let stream: Vec<Vec<u8>> = messages
        .into_iter()
        .zip(times)
        .map(|(mut message, time)| {
            signer.sign(&mut message, time).expect("room");
            message
        })
        .collect();
    let key = capture_key();
    let mut verifier = ResponseVerifier::new(&key, &mac);
    assert_eq!(verifier.verify(&stream[0], T + 10), Ok(Verified::Signed));
    assert_eq!(verifier.verify(&stream[1], T + 10), Ok(Verified::Signed));
    assert_eq!(
        verifier.verify(&stream[2], T + 10),
        Err(ResponseError::TimeDecreased {
            time_signed: T + 5,
            previous: T + 10
        })
    );
}

/// A stream of `n` messages, the root AXFR's cycled, of which those with `signed[i]` carry a TSIG signed by the
/// reference over the unsigned ones before them (§5.3.1); `tamper` changes one unsigned message afterwards.
fn mixed(signed: &[bool], tamper: Option<usize>) -> Vec<Vec<u8>> {
    let (_, mac) = request();
    let messages: Vec<Vec<u8>> = root_axfr().into_iter().cycle().take(signed.len()).collect();
    let mut out = Vec::new();
    let mut unsigned: Vec<Vec<u8>> = Vec::new();
    let mut prior = mac.clone();
    let mut first = true;
    for (i, (message, signs)) in messages.iter().zip(signed).enumerate() {
        let time = T + u64::try_from(i).expect("small");
        if *signs {
            let (wire, next) = if first {
                reference().sign(&mac, message, time, 300, 32)
            } else {
                reference().sign_next(&prior, &unsigned, message, time)
            };
            out.push(wire);
            prior = next;
            unsigned.clear();
            first = false;
        } else {
            unsigned.push(message.clone());
            out.push(message.clone());
        }
    }
    if let Some(i) = tamper {
        out[i][30] ^= 1;
    }
    out
}

fn pattern(unsigned_between: usize, last_signed: bool) -> Vec<bool> {
    let mut signed = vec![true];
    signed.extend(std::iter::repeat_n(false, unsigned_between));
    signed.push(last_signed);
    signed
}

/// §5.3.1: a client accepts up to 99 messages in a row without a TSIG between signed ones, and the MAC of the next
/// signed one covers them.
#[test]
fn s5_3_1_up_to_99_unsigned_messages() {
    let (_, mac) = request();
    assert_eq!(MAX_UNSIGNED, 99);
    for between in [1, 50, 99] {
        assert_eq!(
            run(&mac, &mixed(&pattern(between, true), None)),
            Ok(()),
            "{between}"
        );
    }
    assert_eq!(
        run(&mac, &mixed(&pattern(100, true), None)),
        Err(ResponseError::TooManyUnsigned)
    );
    // The count starts again after a signed message.
    let mut signed = pattern(99, true);
    signed.extend(pattern(99, true).into_iter().skip(1));
    assert_eq!(run(&mac, &mixed(&signed, None)), Ok(()));
}

/// §5.3.1: the first and the last message must be signed.
#[test]
fn s5_3_1_the_first_and_last_are_signed() {
    let (_, mac) = request();
    assert_eq!(
        run(&mac, &mixed(&pattern(3, false), None)),
        Err(ResponseError::UnsignedEnd)
    );
    assert_eq!(
        run(&mac, &mixed(&[false, true], None)),
        Err(ResponseError::Missing)
    );
}

/// §5.3.1: an unsigned message in the middle is covered by the next signature: changing it fails that one.
#[test]
fn s5_3_1_unsigned_messages_are_covered() {
    let (_, mac) = request();
    let tampered = mixed(&pattern(5, true), Some(3));
    assert!(find_tsig(&tampered[3]).expect("well formed").is_none());
    assert_eq!(run(&mac, &tampered), Err(ResponseError::BadSig));
}

/// §5.3.1: the verifier says which messages were signed and which were waiting for one.
#[test]
fn s5_3_1_each_message_is_said_signed_or_not() {
    let (_, mac) = request();
    let key = capture_key();
    let mut verifier = ResponseVerifier::new(&key, &mac);
    let got: Vec<_> = mixed(&[true, false, false, true], None)
        .iter()
        .map(|message| verifier.verify(message, T + 100))
        .collect();
    assert_eq!(
        got,
        [
            Ok(Verified::Signed),
            Ok(Verified::Unsigned),
            Ok(Verified::Unsigned),
            Ok(Verified::Signed)
        ]
    );
}
