//! Target of dedens-tsig: a message on both sides of a TSIG exchange (RFC 8945 §5).

use dedens_proto::{Name, find_tsig};
use dedens_tsig::{
    Algorithm, Key, Keyring, Refusal, ResponseVerifier, Verified, sign_request, verify_request,
};

/// The clock of the exchange, Unix seconds.
const NOW: u64 = 1_700_000_000;

/// Arbitrary bytes as a message of a TSIG exchange, under a fixed key: the server's check and the client's answer
/// each, with no panic; a refusal that can be answered is answered. A message that has no TSIG, signed as a request,
/// is verified by the server, and its response, signed with the request's MAC, by the client, with the same
/// message back.
///
/// # Panics
///
/// On a signature that does not verify, or a bug in the crate.
pub fn tsig_verify(data: &[u8]) {
    let name = Name::from_labels([b"fuzz-key".as_slice()]).expect("a valid name");
    let key = Key::new(name, Algorithm::HmacSha256, vec![7; 32]).expect("a key");
    let keys = Keyring::new([key.clone()]).expect("one key");

    // Raw bytes: answered, and a refusal is signed or not without panic.
    match verify_request(&keys, data, NOW) {
        Ok(Some(request)) => {
            let mut reply = data.to_vec();
            let _ = request.signer().sign(&mut reply, NOW);
        }
        Err(Refusal::NotAuth(not_auth)) => {
            let mut reply = data.to_vec();
            let _ = not_auth.sign(&mut reply, NOW);
        }
        Ok(None) | Err(Refusal::Format(_)) => {}
    }
    let mut verifier = ResponseVerifier::new(&key, &[0; 32]);
    let _ = verifier.verify(data, NOW);
    let _ = verifier.finish();

    // A message with no TSIG goes through the exchange.
    if !matches!(find_tsig(data), Ok(None)) {
        return;
    }
    let mut request = data.to_vec();
    let Ok(mut verifier) = sign_request(&key, &mut request, NOW) else {
        return;
    };
    // Bytes after the counted records hide the appended TSIG: no TSIG found, not signed.
    if !matches!(find_tsig(&request), Ok(Some(_))) {
        return;
    }
    let accepted = verify_request(&keys, &request, NOW)
        .expect("a signed request verifies")
        .expect("it has a TSIG");
    let mut reply = data.to_vec();
    if accepted.signer().sign(&mut reply, NOW).is_ok() {
        assert_eq!(verifier.verify(&reply, NOW), Ok(Verified::Signed));
        assert_eq!(verifier.finish(), Ok(()));
    }
}
