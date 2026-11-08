//! RFC 6605 (ECDSA for DNSSEC): the §6 P-256 and P-384 examples, with their key tags and DS digests
//! (SHA-256, and SHA-384 under DS digest type 4, §5).

mod common;

use common::{
    P256_KEY, P256_SIGNATURE, P384_KEY, P384_SIGNATURE, Rr, Rrsig, b64, check, dnskey_rdata, name,
    rrset, rrsig_set, signed_data,
};
use dedens_dnssec::crypto::{VerifyError, ds_digest, key_tag, verify};
use dedens_dnssec::rrsig::{RrSet, SigError};
use dedens_proto::{DigestType, SecAlgorithm};
use dedens_testkit::hex;

const P256_DS: &str = "b4c8c1fe2e7477127b27115656ad6256f424625bf5c1
    e2770ce6d6e37df61d17";

const P384_DS: &str = "72d7b62976ce06438e9c0bf319013cf801f09ecc84b8
    d7e9495f27e305c6a9b0563a9b5f4d288405c3008a94
    6df983d6";

/// `www.example.net. 3600 IN A 192.0.2.1` and its RRSIG's fields (`signature` windows of §6).
fn signed(algorithm: u8, expiration: u32, inception: u32, key_tag: u16) -> Vec<u8> {
    let rrsig = Rrsig {
        type_covered: 1,
        algorithm,
        labels: 3,
        original_ttl: 3600,
        expiration,
        inception,
        key_tag,
        signer: "example.net.",
    };
    signed_data(
        &rrsig,
        &[Rr {
            owner: "www.example.net.",
            rdata: vec![192, 0, 2, 1],
        }],
    )
}

// 2010-09-09T10:04:39Z, 2010-08-12T10:04:39Z; 2010-09-09T10:20:25Z, 2010-08-12T10:20:25Z.
fn p256_signed() -> Vec<u8> {
    signed(13, 1_284_026_679, 1_281_607_479, 55648)
}

fn p384_signed() -> Vec<u8> {
    signed(14, 1_284_027_625, 1_281_608_425, 10771)
}

#[test]
fn p256_example_verifies() {
    let key = b64(P256_KEY);
    assert_eq!(
        verify(
            SecAlgorithm::ECDSAP256SHA256,
            &key,
            &p256_signed(),
            &b64(P256_SIGNATURE)
        ),
        Ok(())
    );
}

#[test]
fn p384_example_verifies() {
    let key = b64(P384_KEY);
    assert_eq!(
        verify(
            SecAlgorithm::ECDSAP384SHA384,
            &key,
            &p384_signed(),
            &b64(P384_SIGNATURE)
        ),
        Ok(())
    );
}

#[test]
fn a_changed_message_or_signature_is_bad() {
    let key = b64(P256_KEY);
    let signature = b64(P256_SIGNATURE);
    let mut signed = p256_signed();
    *signed.last_mut().expect("data") ^= 1;
    assert_eq!(
        verify(SecAlgorithm::ECDSAP256SHA256, &key, &signed, &signature),
        Err(VerifyError::BadSignature)
    );
    let mut signature = signature;
    *signature.get_mut(40).expect("s") ^= 1;
    assert_eq!(
        verify(
            SecAlgorithm::ECDSAP256SHA256,
            &key,
            &p256_signed(),
            &signature
        ),
        Err(VerifyError::BadSignature)
    );
    // r || s must be 64 octets.
    let signature = b64(P256_SIGNATURE);
    for cut in [&signature[..63], &[][..]] {
        assert_eq!(
            verify(SecAlgorithm::ECDSAP256SHA256, &key, &p256_signed(), cut),
            Err(VerifyError::BadSignature)
        );
    }
}

#[test]
fn a_curve_does_not_verify_the_other_curves_key_or_signature() {
    // P-256 key (64 octets) under algorithm 14, which wants 96; and the reverse.
    assert_eq!(
        verify(
            SecAlgorithm::ECDSAP384SHA384,
            &b64(P256_KEY),
            &p256_signed(),
            &b64(P256_SIGNATURE)
        ),
        Err(VerifyError::UnusableKey)
    );
    assert_eq!(
        verify(
            SecAlgorithm::ECDSAP256SHA256,
            &b64(P384_KEY),
            &p384_signed(),
            &b64(P384_SIGNATURE)
        ),
        Err(VerifyError::UnusableKey)
    );
}

#[test]
fn a_key_of_the_wrong_length_is_unusable() {
    let key = b64(P256_KEY);
    let signature = b64(P256_SIGNATURE);
    for cut in [&key[..63], &[][..]] {
        assert_eq!(
            verify(
                SecAlgorithm::ECDSAP256SHA256,
                cut,
                &p256_signed(),
                &signature
            ),
            Err(VerifyError::UnusableKey)
        );
    }
    let mut longer = key;
    longer.push(0);
    assert_eq!(
        verify(
            SecAlgorithm::ECDSAP256SHA256,
            &longer,
            &p256_signed(),
            &signature
        ),
        Err(VerifyError::UnusableKey)
    );
}

#[test]
fn a_point_off_the_curve_is_a_bad_signature() {
    // `ring` reports an invalid point and a mismatch alike, so the error is `BadSignature`, not `UnusableKey`
    // (D71): x = y = 1 is on neither curve, and the all-zero key is not a point.
    let signature = b64(P256_SIGNATURE);
    let mut one = vec![0_u8; 64];
    one[31] = 1;
    one[63] = 1;
    for key in [one, vec![0_u8; 64]] {
        assert_eq!(
            verify(
                SecAlgorithm::ECDSAP256SHA256,
                &key,
                &p256_signed(),
                &signature
            ),
            Err(VerifyError::BadSignature)
        );
    }
    assert_eq!(
        verify(
            SecAlgorithm::ECDSAP384SHA384,
            &[0_u8; 96],
            &p384_signed(),
            &b64(P384_SIGNATURE)
        ),
        Err(VerifyError::BadSignature)
    );
}

#[test]
fn key_tags_are_the_rfcs() {
    assert_eq!(key_tag(&dnskey_rdata(257, 13, P256_KEY)), 55648);
    assert_eq!(key_tag(&dnskey_rdata(257, 14, P384_KEY)), 10771);
}

#[test]
fn ds_digests_are_the_rfcs() {
    let owner = name("example.net.");
    let p256 =
        ds_digest(DigestType::SHA256, &owner, &dnskey_rdata(257, 13, P256_KEY)).expect("SHA-256");
    assert_eq!(p256.as_ref(), hex(P256_DS));
    // §5: digest type 4, SHA-384, for P-384.
    let p384 =
        ds_digest(DigestType::SHA384, &owner, &dnskey_rdata(257, 14, P384_KEY)).expect("SHA-384");
    assert_eq!(p384.as_ref(), hex(P384_DS));
}

/// The example `RRset`, its RRSIG and the DNSKEY `RRset` of `example.net.` holding the RFC key.
fn example(
    algorithm: u8,
    key: &str,
    signature: &str,
    (expiration, inception, key_tag): (u32, u32, u16),
) -> (RrSet<'static>, RrSet<'static>, RrSet<'static>) {
    let rrsig = Rrsig {
        type_covered: 1,
        algorithm,
        labels: 3,
        original_ttl: 3600,
        expiration,
        inception,
        key_tag,
        signer: "example.net.",
    };
    (
        rrset("www.example.net.", 1, &[vec![192, 0, 2, 1]]),
        rrsig_set("www.example.net.", &rrsig, signature),
        rrset("example.net.", 48, &[dnskey_rdata(257, algorithm, key)]),
    )
}

#[test]
fn the_examples_verify_as_an_rrset_in_their_windows() {
    // The DNSKEY flags of the RFC keys are 257, a KSK that signs the data itself (§6).
    for (algorithm, key, signature, window) in [
        (
            13,
            P256_KEY,
            P256_SIGNATURE,
            (1_284_026_679, 1_281_607_479, 55648),
        ),
        (
            14,
            P384_KEY,
            P384_SIGNATURE,
            (1_284_027_625, 1_281_608_425, 10771),
        ),
    ] {
        let (a, sigs, keys) = example(algorithm, key, signature, window);
        let verified = check(&a, &sigs, &keys, window.1).expect("verifies");
        assert_eq!(verified.ttl.get(), 3600);
        assert_eq!(
            check(&a, &sigs, &keys, window.0 + 1),
            Err(SigError::Expired {
                key_tag: window.2,
                expiration: window.0
            })
        );
    }
}

#[test]
fn an_example_with_a_changed_record_is_a_bad_signature() {
    let (_, sigs, keys) = example(
        13,
        P256_KEY,
        P256_SIGNATURE,
        (1_284_026_679, 1_281_607_479, 55648),
    );
    let changed = rrset("www.example.net.", 1, &[vec![192, 0, 2, 2]]);
    assert_eq!(
        check(&changed, &sigs, &keys, 1_281_607_479),
        Err(SigError::BadSignature { key_tag: 55648 })
    );
}
