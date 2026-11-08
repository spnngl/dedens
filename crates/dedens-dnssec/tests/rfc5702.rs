//! RFC 5702 (SHA-2 with RSA) and RFC 3110 §2 (RSA public keys): the §6.2 example, and the RSASHA256 (8)
//! signatures of RFC 8976 §A.4 (the URI.ARPA zone), whose keys are 1024 and 2048 bits.
//!
//! The §6.1 example key is 512 bits: RFC 5702 §3.2 allows it, `ring` refuses below 1024 (D71), so that
//! example is checked as an unusable key and its signature is not verified.

mod common;

use common::{check, rrset, rrsig_set};
use dedens_dnssec::crypto::{VerifyError, key_tag, supported, verify};
use dedens_dnssec::rrsig::{RrSet, SigError};
use dedens_proto::SecAlgorithm;
use dedens_testkit::dnssec::{
    Rr, Rrsig, SHA512_KEY, SHA512_SIGNATURE, URI_DNSKEY_SIGNATURE, URI_KSK_1, URI_KSK_2,
    URI_MX_SIGNATURE, URI_ZSK, b64, dnskey_rdata, signed_data,
};

const EXAMPLE_NET_A: [u8; 4] = [192, 0, 2, 91];
// 2000-01-01T00:00:00Z and 2030-01-01T00:00:00Z.
const INCEPTION: u32 = 946_684_800;
const EXPIRATION: u32 = 1_893_456_000;
const A: u16 = 1;

// RFC 5702 §6.1: 512 bits.
const SHA256_KEY: &str = "AwEAAcFcGsaxxdgiuuGmCkVI
    my4h99CqT7jwY3pexPGcnUFtR2Fh36BponcwtkZ4cAgtvd4Qs8P
    kxUdp6p/DlUmObdk=";
const SHA256_SIGNATURE: &str = "kRCOH6u7l0QGy9qpC9
    l1sLncJcOKFLJ7GhiUOibu4teYp5VE9RncriShZNz85mwlMgNEa
    cFYK/lPtPiVYP4bwg==";

fn example_net_a_signed(algorithm: u8, key_tag: u16) -> Vec<u8> {
    let rrsig = Rrsig {
        type_covered: A,
        algorithm,
        labels: 3,
        original_ttl: 3600,
        expiration: EXPIRATION,
        inception: INCEPTION,
        key_tag,
        signer: "example.net.",
    };
    signed_data(
        &rrsig,
        &[Rr {
            owner: "www.example.net.",
            rdata: EXAMPLE_NET_A.to_vec(),
        }],
    )
}

fn uri_mx_signed() -> Vec<u8> {
    let mut rdata = 10_u16.to_be_bytes().to_vec();
    rdata.extend(dedens_testkit::dnssec::canonical_name("pechora.icann.org."));
    let rrsig = Rrsig {
        type_covered: 15,
        algorithm: 8,
        labels: 2,
        original_ttl: 600,
        expiration: 1_613_604_280, // 2021-02-17T23:24:40Z
        inception: 1_611_185_080,  // 2021-01-20T23:24:40Z
        key_tag: 37444,
        signer: "uri.arpa.",
    };
    signed_data(
        &rrsig,
        &[Rr {
            owner: "uri.arpa.",
            rdata,
        }],
    )
}

fn uri_dnskey_signed() -> Vec<u8> {
    let rrsig = Rrsig {
        type_covered: 48,
        algorithm: 8,
        labels: 2,
        original_ttl: 3600,
        expiration: 1_613_604_280,
        inception: 1_611_185_080,
        key_tag: 12670,
        signer: "uri.arpa.",
    };
    let rrset: Vec<Rr<'_>> = [
        dnskey_rdata(256, 8, URI_ZSK),
        dnskey_rdata(257, 8, URI_KSK_1),
        dnskey_rdata(257, 8, URI_KSK_2),
    ]
    .into_iter()
    .map(|rdata| Rr {
        owner: "uri.arpa.",
        rdata,
    })
    .collect();
    signed_data(&rrsig, &rrset)
}

/// The key field of DNSKEY RDATA.
fn public_key(base64: &str) -> Vec<u8> {
    b64(base64)
}

#[test]
fn rsasha512_example_verifies() {
    // RFC 5702 §6.2.
    let key = public_key(SHA512_KEY);
    let signed = example_net_a_signed(10, 3740);
    let signature = b64(SHA512_SIGNATURE);
    assert_eq!(
        verify(SecAlgorithm::RSASHA512, &key, &signed, &signature),
        Ok(())
    );
    assert_eq!(key_tag(&dnskey_rdata(256, 10, SHA512_KEY)), 3740);
}

#[test]
fn rsasha512_signature_does_not_match_other_data_algorithms_or_a_cut_signature() {
    let key = public_key(SHA512_KEY);
    let signed = example_net_a_signed(10, 3740);
    let signature = b64(SHA512_SIGNATURE);

    let mut other = signed.clone();
    *other.last_mut().expect("data") ^= 1;
    assert_eq!(
        verify(SecAlgorithm::RSASHA512, &key, &other, &signature),
        Err(VerifyError::BadSignature)
    );
    // The same key and signature under SHA-256 padding.
    assert_eq!(
        verify(SecAlgorithm::RSASHA256, &key, &signed, &signature),
        Err(VerifyError::BadSignature)
    );
    assert_eq!(
        verify(
            SecAlgorithm::RSASHA512,
            &key,
            &signed,
            signature.get(1..).expect("octets")
        ),
        Err(VerifyError::BadSignature)
    );
    assert_eq!(
        verify(SecAlgorithm::RSASHA512, &key, &signed, &[]),
        Err(VerifyError::BadSignature)
    );
}

#[test]
fn rsasha256_example_key_of_512_bits_is_unusable() {
    // RFC 5702 §6.1; the key tag is the RFC's.
    let key = public_key(SHA256_KEY);
    assert_eq!(key_tag(&dnskey_rdata(256, 8, SHA256_KEY)), 9033);
    let signed = example_net_a_signed(8, 9033);
    let signature = b64(SHA256_SIGNATURE);
    assert_eq!(
        verify(SecAlgorithm::RSASHA256, &key, &signed, &signature),
        Err(VerifyError::UnusableKey)
    );
}

#[test]
fn rsasha256_zone_signing_key_of_1024_bits_verifies() {
    // RFC 8976 §A.4: MX uri.arpa. signed by key 37444.
    let key = public_key(URI_ZSK);
    assert_eq!(key_tag(&dnskey_rdata(256, 8, URI_ZSK)), 37444);
    let signature = b64(URI_MX_SIGNATURE);
    assert_eq!(
        verify(SecAlgorithm::RSASHA256, &key, &uri_mx_signed(), &signature),
        Ok(())
    );
}

#[test]
fn rsasha256_key_signing_key_of_2048_bits_verifies_the_dnskey_rrset() {
    // RFC 8976 §A.4: the DNSKEY `RRset` of three keys, signed by key 12670, one of the two KSKs.
    let signed = uri_dnskey_signed();
    let signature = b64(URI_DNSKEY_SIGNATURE);
    let keys = [URI_KSK_1, URI_KSK_2];
    let tagged: Vec<&str> = keys
        .into_iter()
        .filter(|key| key_tag(&dnskey_rdata(257, 8, key)) == 12670)
        .collect();
    let [ksk] = tagged[..] else {
        panic!("exactly one KSK has the key tag 12670")
    };
    assert_eq!(
        verify(
            SecAlgorithm::RSASHA256,
            &public_key(ksk),
            &signed,
            &signature
        ),
        Ok(())
    );
    // The other KSK is a usable key that did not sign.
    let other = keys.into_iter().find(|key| *key != ksk).expect("two keys");
    assert_eq!(
        verify(
            SecAlgorithm::RSASHA256,
            &public_key(other),
            &signed,
            &signature
        ),
        Err(VerifyError::BadSignature)
    );
}

#[test]
fn rsa_key_with_a_three_octet_exponent_length_is_the_same_key() {
    // RFC 3110 §2 reserves a zero octet and two octets of length for exponents over 255 octets; a short one in
    // that form is accepted (D71).
    let key = public_key(URI_ZSK);
    let (&exponent_len, rest) = key.split_first().expect("a key");
    let (exponent, modulus) = rest.split_at(usize::from(exponent_len));
    let mut long_form = vec![0, 0, exponent_len];
    long_form.extend(exponent);
    long_form.extend(modulus);
    let signature = b64(URI_MX_SIGNATURE);
    assert_eq!(
        verify(
            SecAlgorithm::RSASHA256,
            &long_form,
            &uri_mx_signed(),
            &signature
        ),
        Ok(())
    );
}

#[test]
fn rsa_key_with_leading_zeros_is_the_same_key() {
    // RFC 3110 §2 forbids leading zero octets in the exponent and the modulus; zones carry them, so they are
    // stripped (D71).
    let key = public_key(URI_ZSK);
    let (&exponent_len, rest) = key.split_first().expect("a key");
    let (exponent, modulus) = rest.split_at(usize::from(exponent_len));
    let mut padded = vec![exponent_len + 1, 0];
    padded.extend(exponent);
    padded.push(0);
    padded.extend(modulus);
    assert_eq!(
        verify(
            SecAlgorithm::RSASHA256,
            &padded,
            &uri_mx_signed(),
            &b64(URI_MX_SIGNATURE)
        ),
        Ok(())
    );
}

#[test]
fn rsa_keys_ring_would_refuse_are_unusable() {
    let key = public_key(URI_ZSK);
    let signed = uri_mx_signed();
    let signature = b64(URI_MX_SIGNATURE);
    let unusable = |key: &[u8]| verify(SecAlgorithm::RSASHA256, key, &signed, &signature);

    assert_eq!(unusable(&[]), Err(VerifyError::UnusableKey));
    assert_eq!(unusable(&key[..1]), Err(VerifyError::UnusableKey));
    assert_eq!(
        unusable(&[0, 0]),
        Err(VerifyError::UnusableKey),
        "a cut exponent length"
    );
    assert_eq!(
        unusable(&[0, 1, 0, 1, 0, 1]),
        Err(VerifyError::UnusableKey),
        "an exponent longer than the key"
    );
    // The exponent, 65537 in octets 1 to 3: 65536 (even), then 1.
    let mut even = key.clone();
    *even.get_mut(3).expect("exponent") = 0;
    assert_eq!(unusable(&even), Err(VerifyError::UnusableKey));
    let mut one = key.clone();
    one.splice(1..4, [0, 0, 1]);
    assert_eq!(unusable(&one), Err(VerifyError::UnusableKey));
    // A modulus cut to 1016 bits, and one grown past RFC 3110's 4096 bits.
    assert_eq!(
        unusable(&key[..key.len() - 1]),
        Err(VerifyError::UnusableKey)
    );
    let mut grown = key.clone();
    grown.extend(std::iter::repeat_n(0xFF, 400));
    assert_eq!(unusable(&grown), Err(VerifyError::UnusableKey));
    // An even modulus.
    let mut even_modulus = key.clone();
    *even_modulus.last_mut().expect("modulus") &= 0xFE;
    assert_eq!(unusable(&even_modulus), Err(VerifyError::UnusableKey));
}

#[test]
fn rsa_key_under_an_elliptic_algorithm_is_unusable() {
    let key = public_key(URI_ZSK);
    let signature = b64(URI_MX_SIGNATURE);
    for algorithm in [
        SecAlgorithm::ECDSAP256SHA256,
        SecAlgorithm::ECDSAP384SHA384,
        SecAlgorithm::ED25519,
    ] {
        assert_eq!(
            verify(algorithm, &key, &uri_mx_signed(), &signature),
            Err(VerifyError::UnusableKey)
        );
    }
}

#[test]
fn rsa_algorithms_are_supported() {
    for algorithm in [
        SecAlgorithm::RSASHA1,
        SecAlgorithm::RSASHA1_NSEC3_SHA1,
        SecAlgorithm::RSASHA256,
        SecAlgorithm::RSASHA512,
    ] {
        assert!(supported(algorithm), "{algorithm}");
    }
}

/// RFC 5702 §6 `www.example.net. A`, its RRSIG and the DNSKEY `RRset` of `example.net.` (flags 256).
fn example_net(
    algorithm: u8,
    key: &str,
    signature: &str,
    key_tag: u16,
) -> (RrSet<'static>, RrSet<'static>, RrSet<'static>) {
    let rrsig = Rrsig {
        type_covered: A,
        algorithm,
        labels: 3,
        original_ttl: 3600,
        expiration: EXPIRATION,
        inception: INCEPTION,
        key_tag,
        signer: "example.net.",
    };
    (
        rrset("www.example.net.", A, &[EXAMPLE_NET_A.to_vec()]),
        rrsig_set("www.example.net.", &rrsig, signature),
        rrset("example.net.", 48, &[dnskey_rdata(256, algorithm, key)]),
    )
}

#[test]
fn rsasha512_example_verifies_as_an_rrset() {
    let (a, sigs, keys) = example_net(10, SHA512_KEY, SHA512_SIGNATURE, 3740);
    assert!(check(&a, &sigs, &keys, INCEPTION).is_ok());
    let changed = rrset("www.example.net.", A, &[vec![192, 0, 2, 92]]);
    assert_eq!(
        check(&changed, &sigs, &keys, INCEPTION),
        Err(SigError::BadSignature { key_tag: 3740 })
    );
}

#[test]
fn a_key_of_512_bits_is_no_key() {
    // D71: a key no signature can use is no key, so its RRSIG is disregarded; the RRset is bogus, not insecure
    // (D73: only DS records make a zone insecure, RFC 6840 §5.12).
    let (a, sigs, keys) = example_net(8, SHA256_KEY, SHA256_SIGNATURE, 9033);
    let error = check(&a, &sigs, &keys, INCEPTION).unwrap_err();
    assert_eq!(error, SigError::NoKey { key_tag: 9033 });
    assert!(!error.is_unsupported());
}

#[test]
fn the_uri_arpa_mx_verifies_as_an_rrset() {
    // RFC 8976 §A.4: owner and signer are `uri.arpa.`, two labels.
    let rrsig = Rrsig {
        type_covered: 15,
        algorithm: 8,
        labels: 2,
        original_ttl: 600,
        expiration: 1_613_604_280,
        inception: 1_611_185_080,
        key_tag: 37444,
        signer: "uri.arpa.",
    };
    let mut mx = 10_u16.to_be_bytes().to_vec();
    mx.extend(dedens_testkit::dnssec::canonical_name("pechora.icann.org."));
    let (set, sigs) = (
        rrset("uri.arpa.", 15, &[mx]),
        rrsig_set("uri.arpa.", &rrsig, URI_MX_SIGNATURE),
    );
    let keys = rrset("uri.arpa.", 48, &[dnskey_rdata(256, 8, URI_ZSK)]);
    let verified = check(&set, &sigs, &keys, 1_611_185_080 + 100).expect("verifies");
    assert_eq!(verified.ttl.get(), 600);
}
