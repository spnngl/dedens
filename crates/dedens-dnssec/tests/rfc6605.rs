//! RFC 6605 (ECDSA for DNSSEC): the §6 P-256 and P-384 examples, with their key tags and DS digests
//! (SHA-256, and SHA-384 under DS digest type 4, §5).

mod common;

use common::{Rr, Rrsig, b64, dnskey_rdata, hex, name, signed_data};
use dedens_dnssec::crypto::{VerifyError, ds_digest, key_tag, verify};
use dedens_proto::{DigestType, SecAlgorithm};

const P256_KEY: &str = "GojIhhXUN/u4v54ZQqGSnyhWJwaubCvTmeexv7bR6edb
    krSqQpF64cYbcB7wNcP+e+MAnLr+Wi9xMWyQLc8NAA==";
const P256_DS: &str = "b4c8c1fe2e7477127b27115656ad6256f424625bf5c1
    e2770ce6d6e37df61d17";
const P256_SIGNATURE: &str = "qx6wLYqmh+l9oCKTN6qIc+bw6ya+KJ8oMz0YP107epXA
    yGmt+3SNruPFKG7tZoLBLlUzGGus7ZwmwWep666VCw==";

const P384_KEY: &str = "xKYaNhWdGOfJ+nPrL8/arkwf2EY3MDJ+SErKivBVSum1
    w/egsXvSADtNJhyem5RCOpgQ6K8X1DRSEkrbYQ+OB+v8
    /uX45NBwY8rp65F6Glur8I/mlVNgF6W/qTI37m40";
const P384_DS: &str = "72d7b62976ce06438e9c0bf319013cf801f09ecc84b8
    d7e9495f27e305c6a9b0563a9b5f4d288405c3008a94
    6df983d6";
const P384_SIGNATURE: &str = "/L5hDKIvGDyI1fcARX3z65qrmPsVz73QD1Mr5CEqOiLP
    95hxQouuroGCeZOvzFaxsT8Glr74hbavRKayJNuydCuz
    WTSSPdz7wnqXL5bdcJzusdnI0RSMROxxwGipWcJm";

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
