//! RFC 8080 (`EdDSA` for DNSSEC): the §6.1 Ed25519 examples with their key tags and DS digests; Ed448 (§6.2) is
//! unsupported (`ring` has none, D71), so its examples are checked only for key tag and DS digest, which do not
//! depend on the algorithm.
//!
//! The RFC prints the RRSIGs as `MX 3 3600`, leaving out the algorithm, 15 (or 16): the 3 is the label count,
//! though `example.com.` has 2 (RFC 4034 §3.1.3), and the signatures verify only with 3.

mod common;

use common::{check, name, rrset, rrsig_set};
use dedens_dnssec::crypto::{Budget, VerifyError, ds_digest, key_tag, supported, verify};
use dedens_dnssec::rrsig::{self, Key, SigError, Signature};
use dedens_proto::{DigestType, SecAlgorithm};
use dedens_testkit::dnssec::{
    ED25519_KEY_1, ED25519_SIGNATURE_1, Rr, Rrsig, b64, dnskey_rdata, signed_data,
};
use dedens_testkit::hex;

const ED25519_DS_1: &str = "3aa5ab37efce57f737fc1627013fee07bdf241bd10f3b1964ab55c78e79
    a304b";

const ED25519_KEY_2: &str = "zPnZ/QwEe7S8C5SPz2OfS5RR40ATk2/rYnE9xHIEijs=";
const ED25519_DS_2: &str = "401781b934e392de492ec77ae2e15d70f6575a1c0bc59c5275c04ebe80c
    6614c";
const ED25519_SIGNATURE_2: &str = "5LL2obmzdqjWI+Xto5eP5adXt/T5tMhasWvwcyW4L3SzfcRawOle9bodhC+
    oip9ayUGjY9T/rL4rN3bOuESGDA==";

const ED448_KEY: &str = "3kgROaDjrh0H2iuixWBrc8g2EpBBLCdGzHmn+G2MpTPhpj/OiBVHHSfPodx
    1FYYUcJKm1MDpJtIA";
const ED448_DS: &str = "6ccf18d5bc5d7fc2fceb1d59d17321402f2aa8d368048db93dd811f5cb2
    b19c7";
const ED448_SIGNATURE: &str = "Nmc0rgGKpr3GKYXcB1JmqqS4NYwhmechvJTqVzt3jR+Qy/lSLFoIk1L+9e3
    9GPL+5tVzDPN3f9kAwiu8KCuPPjtl227ayaCZtRKZuJax7n9NuYlZJIusX0
    SOIOKBGzG+yWYtz1/jjbzl5GGkWvREUCUA";

/// `example.com. 3600 IN MX 10 mail.example.com.` signed with the RFC's windows.
fn mx_signed(algorithm: u8, key_tag: u16) -> Vec<u8> {
    let mut rdata = 10_u16.to_be_bytes().to_vec();
    rdata.extend(dedens_testkit::dnssec::canonical_name("mail.example.com."));
    let rrsig = Rrsig {
        type_covered: 15,
        algorithm,
        labels: 3,
        original_ttl: 3600,
        expiration: 1_440_021_600,
        inception: 1_438_207_200,
        key_tag,
        signer: "example.com.",
    };
    signed_data(
        &rrsig,
        &[Rr {
            owner: "example.com.",
            rdata,
        }],
    )
}

#[test]
fn ed25519_examples_verify() {
    for (key, signature, tag) in [
        (ED25519_KEY_1, ED25519_SIGNATURE_1, 3613),
        (ED25519_KEY_2, ED25519_SIGNATURE_2, 35217),
    ] {
        assert_eq!(
            verify(
                SecAlgorithm::ED25519,
                &b64(key),
                &mx_signed(15, tag),
                &b64(signature)
            ),
            Ok(()),
            "key tag {tag}"
        );
    }
}

#[test]
fn ed25519_rejects_the_other_key_a_changed_message_and_a_cut_signature() {
    let signed = mx_signed(15, 3613);
    let signature = b64(ED25519_SIGNATURE_1);
    assert_eq!(
        verify(
            SecAlgorithm::ED25519,
            &b64(ED25519_KEY_2),
            &signed,
            &signature
        ),
        Err(VerifyError::BadSignature)
    );
    let mut changed = signed.clone();
    *changed.last_mut().expect("data") ^= 1;
    assert_eq!(
        verify(
            SecAlgorithm::ED25519,
            &b64(ED25519_KEY_1),
            &changed,
            &signature
        ),
        Err(VerifyError::BadSignature)
    );
    assert_eq!(
        verify(
            SecAlgorithm::ED25519,
            &b64(ED25519_KEY_1),
            &signed,
            &signature[..63]
        ),
        Err(VerifyError::BadSignature)
    );
}

#[test]
fn ed25519_key_is_32_octets() {
    let key = b64(ED25519_KEY_1);
    let signature = b64(ED25519_SIGNATURE_1);
    let signed = mx_signed(15, 3613);
    assert_eq!(
        verify(SecAlgorithm::ED25519, &key[..31], &signed, &signature),
        Err(VerifyError::UnusableKey)
    );
    assert_eq!(
        verify(SecAlgorithm::ED25519, &[], &signed, &signature),
        Err(VerifyError::UnusableKey)
    );
    // The 57-octet Ed448 key is not an Ed25519 key.
    assert_eq!(
        verify(SecAlgorithm::ED25519, &b64(ED448_KEY), &signed, &signature),
        Err(VerifyError::UnusableKey)
    );
}

#[test]
fn ed25519_key_that_is_no_point_is_a_bad_signature() {
    // `ring` reports an undecodable or small-order point and a mismatch alike, so a 32-octet key that
    // cannot be a public key is a `BadSignature`, not an `UnusableKey` (D71).
    let signature = b64(ED25519_SIGNATURE_1);
    // y = 2^255 - 1 is above the field prime; the zero key is a small-order point; 0x02... does not decode.
    let mut two = [0_u8; 32];
    two[0] = 2;
    for key in [[0xFF_u8; 32], [0_u8; 32], two] {
        assert_eq!(
            verify(
                SecAlgorithm::ED25519,
                &key,
                &mx_signed(15, 3613),
                &signature
            ),
            Err(VerifyError::BadSignature)
        );
    }
}

#[test]
fn ed448_is_unsupported() {
    assert!(!supported(SecAlgorithm::ED448));
    assert_eq!(
        verify(
            SecAlgorithm::ED448,
            &b64(ED448_KEY),
            &mx_signed(16, 9713),
            &b64(ED448_SIGNATURE)
        ),
        Err(VerifyError::UnsupportedAlgorithm(SecAlgorithm::ED448))
    );
}

#[test]
fn key_tags_are_the_rfcs() {
    assert_eq!(key_tag(&dnskey_rdata(257, 15, ED25519_KEY_1)), 3613);
    assert_eq!(key_tag(&dnskey_rdata(257, 15, ED25519_KEY_2)), 35217);
    assert_eq!(key_tag(&dnskey_rdata(257, 16, ED448_KEY)), 9713);
}

#[test]
fn ds_digests_are_the_rfcs() {
    let owner = name("example.com.");
    for (algorithm, key, ds) in [
        (15, ED25519_KEY_1, ED25519_DS_1),
        (15, ED25519_KEY_2, ED25519_DS_2),
        (16, ED448_KEY, ED448_DS),
    ] {
        let digest = ds_digest(
            DigestType::SHA256,
            &owner,
            &dnskey_rdata(257, algorithm, key),
        )
        .expect("SHA-256");
        assert_eq!(digest.as_ref(), hex(ds), "algorithm {algorithm}");
    }
}

#[test]
fn the_examples_label_count_is_refused_as_an_rrset() {
    // The RRSIG says 3 labels for `example.com.`, which has 2 (RFC 4034 §3.1.3): the signature is valid over
    // the bytes, but RFC 4035 §5.3.1 makes the RRSIG itself invalid, so a validator never reaches it.
    let rrsig = Rrsig {
        type_covered: 15,
        algorithm: 15,
        labels: 3,
        original_ttl: 3600,
        expiration: 1_440_021_600,
        inception: 1_438_207_200,
        key_tag: 3613,
        signer: "example.com.",
    };
    let mut mx = 10_u16.to_be_bytes().to_vec();
    mx.extend(dedens_testkit::dnssec::canonical_name("mail.example.com."));
    let sigs = rrsig_set("example.com.", &rrsig, ED25519_SIGNATURE_1);
    let keys = rrset("example.com.", 48, &[dnskey_rdata(257, 15, ED25519_KEY_1)]);
    assert_eq!(
        check(
            &rrset("example.com.", 15, &[mx]),
            &sigs,
            &keys,
            1_438_207_200
        ),
        Err(SigError::BadLabels {
            labels: 3,
            owner: 2
        })
    );
}

#[test]
fn an_ed448_key_leaves_the_algorithm_unsupported() {
    // D71: `ring` has no Ed448, so the algorithm is unsigned for the validator (RFC 6840 §5.2).
    let rrsig = Rrsig {
        type_covered: 15,
        algorithm: 16,
        labels: 2,
        original_ttl: 3600,
        expiration: 1_440_021_600,
        inception: 1_438_207_200,
        key_tag: 9713,
        signer: "example.com.",
    };
    let mut mx = 10_u16.to_be_bytes().to_vec();
    mx.extend(dedens_testkit::dnssec::canonical_name("mail.example.com."));
    let sigs = rrsig_set("example.com.", &rrsig, ED448_SIGNATURE);
    let keys = rrset("example.com.", 48, &[dnskey_rdata(257, 16, ED448_KEY)]);
    let mx_rdata = mx.clone();
    let error = check(
        &rrset("example.com.", 15, &[mx]),
        &sigs,
        &keys,
        1_438_207_200,
    )
    .unwrap_err();
    // RFC 6840 §5.12: an RRSIG of an unsupported algorithm is disregarded, so a forger cannot make the data
    // insecure by it; the DS records of the zone do (D73).
    assert_eq!(error, SigError::NoSignature);
    assert!(!error.is_unsupported());
    // Checked alone, the pair says why.
    let rrset = rrset("example.com.", 15, &[mx_rdata]);
    let (sig, key) = (Signature::all(&sigs), Key::all(&keys));
    assert_eq!(
        rrsig::verify(
            &rrset,
            &sig[0],
            &key[0],
            1_438_207_200,
            &mut Budget::default()
        )
        .unwrap_err(),
        SigError::UnsupportedAlgorithm {
            algorithm: SecAlgorithm::ED448
        }
    );
}
