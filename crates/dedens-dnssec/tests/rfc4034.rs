//! RFC 4034: key tags (Appendix B), the SHA-1 DS digest (§5.1.4, §5.4), canonical owner names (§6.2), and the
//! RSASHA1 (5, 7) signatures of RFC 4035 Appendix A, the signed zone `example.`, whose keys are 1024 bits.

mod common;

use common::{DSKEY, Rr, Rrsig, b64, dnskey_rdata, hex, name, signed_data};
use dedens_dnssec::crypto::{VerifyError, ds_digest, key_tag, supported, supported_digest, verify};
use dedens_proto::{DigestType, SecAlgorithm};

// RFC 4035 Appendix A: the zone signing key (tag 38519) and key signing key (tag 9465) of `example.`.
const ZSK: &str = "AQOy1bZVvpPqhg4j7EJoM9rI3ZmyEx2OzDBV
    rZy/lvI5CQePxXHZS4i8dANH4DX3tbHol61e
    k8EFMcsGXxKciJFHyhl94C+NwILQdzsUlSFo
    vBZsyl/NX6yEbtw/xN9ZNcrbYvgjjZ/UVPZI
    ySFNsgEYvh0z2542lzMKR4Dh8uZffQ==";
const KSK: &str = "AQOeX7+baTmvpVHb2CcLnL1dMRWbuscRvHXl
    LnXwDzvqp4tZVKp1sZMepFb8MvxhhW3y/0QZ
    syCjczGJ1qk8vJe52iOhInKROVLRwxGpMfzP
    RLMlGybr51bOV/1se0ODacj3DomyB4QB5gKT
    Yot/K9alk5/j8vfd4jWCWD+E1Sze0Q==";
// ns1.example. 3600 IN A 192.0.2.1, signed by the ZSK.
const NS1_SIGNATURE: &str = "F1C9HVhIcs10cZU09G5yIVfKJy5yRQQ3qVet
    5pGhp82pzhAOMZ3K22JnmK4c+IjUeFp/to06
    im5FVpHtbFisdjyPq84bhTv8vrXt5AB1wNB+
    +iAqvIfdgW4sFNC6oADb1hK8QNauw9VePJhK
    v/iVXSYC0b7mPSU+EOlknFpVECs=";
// The DNSKEY `RRset` of `example.`, signed by the KSK.
const DNSKEY_SIGNATURE: &str = "ZxgauAuIj+k1YoVEOSlZfx41fcmKzTFHoweZ
    xYnz99JVQZJ33wFS0Q0jcP7VXKkaElXk9nYJ
    XevO/7nAbo88iWsMkSpSR6jWzYYKwfrBI/L9
    hjYmyVO9m6FjQ7uwM4dCP/bIuV/DKqOAK9NY
    NC3AHfvCV1Tp4VKDqxqG7R5tTVM=";
// 2004-04-09T18:36:19Z and 2004-05-09T18:36:19Z.
const INCEPTION: u32 = 1_081_535_779;
const EXPIRATION: u32 = 1_084_127_779;

fn rrsig(type_covered: u16, algorithm: u8, labels: u8, key_tag: u16) -> Rrsig<'static> {
    Rrsig {
        type_covered,
        algorithm,
        labels,
        original_ttl: 3600,
        expiration: EXPIRATION,
        inception: INCEPTION,
        key_tag,
        signer: "example.",
    }
}

fn ns1_signed(algorithm: u8) -> Vec<u8> {
    let rdata = vec![192, 0, 2, 1];
    signed_data(
        &rrsig(1, algorithm, 2, 38519),
        &[Rr {
            owner: "ns1.example.",
            rdata,
        }],
    )
}

fn dnskey_signed(algorithm: u8) -> Vec<u8> {
    let rrset = [dnskey_rdata(256, 5, ZSK), dnskey_rdata(257, 5, KSK)]
        .into_iter()
        .map(|rdata| Rr {
            owner: "example.",
            rdata,
        })
        .collect::<Vec<_>>();
    signed_data(&rrsig(48, algorithm, 1, 9465), &rrset)
}

#[test]
fn key_tags_are_the_rfcs() {
    // §5.4: "key id = 60485"; RFC 4035 Appendix A: the tags in the RRSIGs.
    assert_eq!(key_tag(&dnskey_rdata(256, 5, DSKEY)), 60485);
    assert_eq!(key_tag(&dnskey_rdata(256, 5, ZSK)), 38519);
    assert_eq!(key_tag(&dnskey_rdata(257, 5, KSK)), 9465);
}

#[test]
fn key_tag_of_rsamd5_is_the_modulus_octets() {
    // Appendix B.1: the 16 bits above the last 8, whatever the rest of the RDATA sums to. The only RSAMD5
    // key a zone could hold is this one with its algorithm byte changed; its modulus ends 0x96 0x3C 0x2F 0x17.
    assert_eq!(key_tag(&dnskey_rdata(256, 1, DSKEY)), 0x3C2F);
}

#[test]
fn key_tag_of_a_short_rdata_is_defined() {
    // Not a DNSKEY, but never a panic: the sum of what there is (Appendix B), with an odd octet as the high half.
    assert_eq!(key_tag(&[]), 0);
    assert_eq!(key_tag(&[1]), 0x0100);
    assert_eq!(key_tag(&[0, 0, 3, 2]), 3 * 256 + 2);
    // The carry folds: 0xFFFF + 0xFFFF.
    assert_eq!(key_tag(&[0xFF; 4]), 0xFFFF);
}

#[test]
fn ds_digest_sha1_is_the_rfc_example() {
    // §5.4.
    let owner = name("dskey.example.com.");
    let digest = ds_digest(DigestType::SHA1, &owner, &dnskey_rdata(256, 5, DSKEY)).expect("SHA-1");
    assert_eq!(
        digest.as_ref(),
        hex("2BB183AF5F22588179A53B0A98631FAD1A292118")
    );
}

#[test]
fn ds_digest_hashes_the_owner_in_lower_case() {
    // §6.2: canonical form lowercases the owner; the RDATA's octets stay as they are.
    let rdata = dnskey_rdata(256, 5, DSKEY);
    let lower = ds_digest(DigestType::SHA1, &name("dskey.example.com."), &rdata).expect("SHA-1");
    let mixed = ds_digest(DigestType::SHA1, &name("DsKey.EXAMPLE.com."), &rdata).expect("SHA-1");
    assert_eq!(lower, mixed);
}

#[test]
fn ds_digest_types_other_than_sha1_sha256_sha384_are_unsupported() {
    let owner = name("example.");
    for digest in [
        DigestType(0),
        DigestType::GOST,
        DigestType(5),
        DigestType(6),
        DigestType(255),
    ] {
        assert!(!supported_digest(digest), "{digest}");
        assert_eq!(ds_digest(digest, &owner, &[]).unwrap_err().0, digest);
    }
    for digest in [DigestType::SHA1, DigestType::SHA256, DigestType::SHA384] {
        assert!(supported_digest(digest), "{digest}");
    }
}

#[test]
fn rsasha1_example_signature_verifies_under_algorithms_5_and_7() {
    // RFC 4035 Appendix A, signed under 5; 7 verifies as 5 does (RFC 5155 §2), whatever the RRSIG's field says.
    let key = b64(ZSK);
    let signature = b64(NS1_SIGNATURE);
    let signed = ns1_signed(5);
    for algorithm in [SecAlgorithm::RSASHA1, SecAlgorithm::RSASHA1_NSEC3_SHA1] {
        assert_eq!(
            verify(algorithm, &key, &signed, &signature),
            Ok(()),
            "{algorithm}"
        );
    }
}

#[test]
fn rsasha1_dnskey_rrset_verifies_in_canonical_order() {
    // The `RRset` sorts by RDATA (§6.3): the ZSK (flags 256) before the KSK (257).
    let signed = dnskey_signed(5);
    assert_eq!(
        verify(
            SecAlgorithm::RSASHA1,
            &b64(KSK),
            &signed,
            &b64(DNSKEY_SIGNATURE)
        ),
        Ok(())
    );
}

#[test]
fn rsasha1_example_does_not_verify_after_a_change() {
    let key = b64(ZSK);
    let signature = b64(NS1_SIGNATURE);
    let mut signed = ns1_signed(5);
    // The TTL in the RRSIG RDATA, 3600 → 3601.
    *signed.get_mut(7).expect("TTL") ^= 1;
    assert_eq!(
        verify(SecAlgorithm::RSASHA1, &key, &signed, &signature),
        Err(VerifyError::BadSignature)
    );
    // The KSK did not sign the A record.
    assert_eq!(
        verify(SecAlgorithm::RSASHA1, &b64(KSK), &ns1_signed(5), &signature),
        Err(VerifyError::BadSignature)
    );
}

#[test]
fn only_the_algorithms_of_rfc_9904_are_supported() {
    let validated = [5, 7, 8, 10, 13, 14, 15];
    for code in 0..=u8::MAX {
        let algorithm = SecAlgorithm(code);
        assert_eq!(
            supported(algorithm),
            validated.contains(&code),
            "{algorithm}"
        );
        if !validated.contains(&code) {
            // RSAMD5 (1), DSA (3, 6), ECC-GOST (12), Ed448 (16), ECC-GOST12 (23), private and unknown.
            assert_eq!(
                verify(algorithm, &[], &[], &[]),
                Err(VerifyError::UnsupportedAlgorithm(algorithm))
            );
        }
    }
}
