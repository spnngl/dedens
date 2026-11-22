//! RFC 8945 §4.3: the MAC covers the message and the TSIG variables, so changing one bit of a signed message is
//! caught, except where the RFC says it is not covered: the ID, which the Original ID replaces (§4.3.2), and the
//! case of the key's and algorithm's names (§4.3.3). Also: bytes that are no message never panic.

use std::collections::BTreeSet;

use dedens_testkit::dns;
use dedens_tsig::{ResponseVerifier, sign_request, verify_request};
use proptest::prelude::*;

use crate::util::{capture_key, keyring, query, reference, tsig};

const T: u64 = 1_700_000_000;

/// The bit flips `(byte, bit)` of `wire` that may leave a signed message valid: the ID's, and the case bit of each
/// letter of the TSIG's owner and algorithm names.
fn uncovered(wire: &[u8]) -> BTreeSet<(usize, u8)> {
    let found = tsig(wire);
    let owner = dns("dedens-test-key.").wire_len();
    let algorithm = found.start + owner + 10;
    let mut set: BTreeSet<_> = (0..2)
        .flat_map(|i| (0..8).map(move |bit| (i, bit)))
        .collect();
    let names = (found.start..found.start + owner).chain(algorithm..algorithm + 13);
    for at in names.filter(|at| wire[*at].is_ascii_alphabetic()) {
        set.insert((at, 5));
    }
    set
}

/// §4.3: of the bits of a signed request, only the uncovered ones can change and still verify.
#[test]
fn s4_3_a_flipped_bit_in_a_request_is_caught() {
    let keys = keyring();
    let mut wire = query(0x1234, "example.org.");
    sign_request(&capture_key(), &mut wire, T).expect("room");
    let allowed = uncovered(&wire);
    let mut accepted = BTreeSet::new();
    for at in 0..wire.len() {
        for bit in 0..8 {
            let mut flipped = wire.clone();
            flipped[at] ^= 1 << bit;
            if matches!(verify_request(&keys, &flipped, T), Ok(Some(_))) {
                accepted.insert((at, bit));
            }
        }
    }
    assert_eq!(accepted, allowed);
}

/// §4.3: the same for a response, which the client takes against the request's MAC.
#[test]
fn s4_3_a_flipped_bit_in_a_response_is_caught() {
    let key = capture_key();
    let (request, mac) = reference().sign(&[], &query(0x1234, "example.org."), T, 300, 32);
    drop(request);
    let mut bare = query(0x1234, "example.org.");
    bare[2] = 0x80;
    let (wire, _) = reference().sign(&mac, &bare, T, 300, 32);
    let allowed = uncovered(&wire);
    let mut accepted = BTreeSet::new();
    for at in 0..wire.len() {
        for bit in 0..8 {
            let mut flipped = wire.clone();
            flipped[at] ^= 1 << bit;
            if ResponseVerifier::new(&key, &mac)
                .verify(&flipped, T)
                .is_ok()
            {
                accepted.insert((at, bit));
            }
        }
    }
    assert_eq!(accepted, allowed);
}

proptest! {
    /// §5.2: whatever bytes arrive, the server's check answers and does not panic.
    #[test]
    fn s5_2_arbitrary_bytes_are_answered(bytes in prop::collection::vec(any::<u8>(), 0..300)) {
        let _ = verify_request(&keyring(), &bytes, T);
    }

    /// §5.2: the same for bytes that begin as a signed request.
    #[test]
    fn s5_2_a_changed_signed_request_is_answered(
        at in 0_usize..160,
        byte: u8,
        cut in 0_usize..40,
    ) {
        let mut wire = query(0x1234, "example.org.");
        sign_request(&capture_key(), &mut wire, T).expect("room");
        let at = at % wire.len();
        wire[at] = byte;
        wire.truncate(wire.len() - cut % wire.len().min(40));
        let _ = verify_request(&keyring(), &wire, T);
    }

    /// §5.4: the client's check of arbitrary bytes answers and does not panic.
    #[test]
    fn s5_4_arbitrary_bytes_are_answered(bytes in prop::collection::vec(any::<u8>(), 0..300)) {
        let key = capture_key();
        let _ = ResponseVerifier::new(&key, &[0; 32]).verify(&bytes, T);
    }
}
