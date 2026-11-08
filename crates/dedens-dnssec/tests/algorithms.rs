//! The signing algorithms and DS digests, on the examples of their RFCs.

mod sha256_ds {
    //! RFC 4509 (SHA-256 in DS records) §2.3, and the DS of the root's KSK that RFC 9718 §2 lists (algorithm 8, SHA-256).

    use dedens_dnssec::crypto::{ds_digest, key_tag};
    use dedens_proto::DigestType;
    use dedens_testkit::dnssec::dnskey_rdata;
    use dedens_testkit::hex;

    use crate::util::{DSKEY, name};

    // RFC 9718 §2: `. IN DNSKEY 257 3 8`, the KSK-2017 (key tag 20326).
    const ROOT_KSK: &str = "AwEAAaz/tAm8yTn4Mfeh5eyI96WSVexTBAvkMgJzkKTOiW1vkIbzxeF3
    +/4RgWOq7HrxRixHlFlExOLAJr5emLvN7SWXgnLh4+B5xQlNVz8Og8kv
    ArMtNROxVQuCaSnIDdD5LKyWbRd2n9WGe2R8PzgCmr3EgVLrjyBxWezF
    0jLHwVN8efS3rCj/EWgvIWgb9tarpVUDK/b58Da+sqqls3eNbuv7pr+e
    oZG+SrDK6nWeL3c6H5Apxz7LjVc1uTIdsIXxuOLYA4/ilBmSVIzuDWfd
    RUfhHdY6+cn8HFRm+2hM8AnXGXws9555KrUB5qihylGa8subX2Nn6UwN
    R1AkUTV74bU=";

    #[test]
    fn sha256_ds_of_the_rfc_example() {
        // §2.3: `dskey.example.com. 86400 IN DS 60485 5 2 ( D4B7D520... )`.
        let owner = name("dskey.example.com.");
        let digest =
            ds_digest(DigestType::SHA256, &owner, &dnskey_rdata(256, 5, DSKEY)).expect("SHA-256");
        assert_eq!(
            digest.as_ref(),
            hex("D4B7D520E7BB5F0F67674A0CCEB1E3E0614B93C4F9E99B8383F6A1E4469DA50A")
        );
    }

    #[test]
    fn sha256_ds_of_the_root_ksk() {
        let rdata = dnskey_rdata(257, 8, ROOT_KSK);
        assert_eq!(key_tag(&rdata), 20326);
        let digest = ds_digest(DigestType::SHA256, &name("."), &rdata).expect("SHA-256");
        assert_eq!(
            digest.as_ref(),
            hex("E06D44B80B8F1D39A95C0B0D7C65D08458E880409BBC683457104237C7F8EC8D")
        );
    }

    #[test]
    fn a_digest_of_another_key_differs() {
        let owner = name("dskey.example.com.");
        let one =
            ds_digest(DigestType::SHA256, &owner, &dnskey_rdata(256, 5, DSKEY)).expect("SHA-256");
        let other =
            ds_digest(DigestType::SHA256, &owner, &dnskey_rdata(257, 5, DSKEY)).expect("SHA-256");
        assert_ne!(one, other);
    }
}

mod rsa_sha2 {
    //! RFC 5702 (SHA-2 with RSA) and RFC 3110 §2 (RSA public keys): the §6.2 example, and the RSASHA256 (8)
    //! signatures of RFC 8976 §A.4 (the URI.ARPA zone), whose keys are 1024 and 2048 bits.
    //!
    //! The §6.1 example key is 512 bits: RFC 5702 §3.2 allows it, `ring` refuses below 1024 (D71), so that
    //! example is checked as an unusable key and its signature is not verified.

    use dedens_dnssec::crypto::{VerifyError, key_tag, supported, verify};
    use dedens_dnssec::rrsig::{RrSet, SigError};
    use dedens_proto::SecAlgorithm;
    use dedens_testkit::dnssec::{
        Rr, Rrsig, SHA512_KEY, SHA512_SIGNATURE, URI_DNSKEY_SIGNATURE, URI_KSK_1, URI_KSK_2,
        URI_MX_SIGNATURE, URI_ZSK, b64, dnskey_rdata, signed_data,
    };

    use crate::util::{check, rrset, rrsig_set};

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
}

mod ecdsa {
    //! RFC 6605 (ECDSA for DNSSEC): the §6 P-256 and P-384 examples, with their key tags and DS digests
    //! (SHA-256, and SHA-384 under DS digest type 4, §5).

    use dedens_dnssec::crypto::{VerifyError, ds_digest, key_tag, verify};
    use dedens_dnssec::rrsig::{RrSet, SigError};
    use dedens_proto::{DigestType, SecAlgorithm};
    use dedens_testkit::dnssec::{
        P256_KEY, P256_SIGNATURE, P384_KEY, P384_SIGNATURE, Rr, Rrsig, b64, dnskey_rdata,
        signed_data,
    };
    use dedens_testkit::hex;

    use crate::util::{check, name, rrset, rrsig_set};

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
        let p256 = ds_digest(DigestType::SHA256, &owner, &dnskey_rdata(257, 13, P256_KEY))
            .expect("SHA-256");
        assert_eq!(p256.as_ref(), hex(P256_DS));
        // §5: digest type 4, SHA-384, for P-384.
        let p384 = ds_digest(DigestType::SHA384, &owner, &dnskey_rdata(257, 14, P384_KEY))
            .expect("SHA-384");
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
}

mod eddsa {
    //! RFC 8080 (`EdDSA` for DNSSEC): the §6.1 Ed25519 examples with their key tags and DS digests; Ed448 (§6.2) is
    //! unsupported (`ring` has none, D71), so its examples are checked only for key tag and DS digest, which do not
    //! depend on the algorithm.
    //!
    //! The RFC prints the RRSIGs as `MX 3 3600`, leaving out the algorithm, 15 (or 16): the 3 is the label count,
    //! though `example.com.` has 2 (RFC 4034 §3.1.3), and the signatures verify only with 3.

    use dedens_dnssec::crypto::{Budget, VerifyError, ds_digest, key_tag, supported, verify};
    use dedens_dnssec::rrsig::{self, Key, SigError, Signature};
    use dedens_proto::{DigestType, SecAlgorithm};
    use dedens_testkit::dnssec::{
        ED25519_KEY_1, ED25519_SIGNATURE_1, Rr, Rrsig, b64, dnskey_rdata, signed_data,
    };
    use dedens_testkit::hex;

    use crate::util::{check, name, rrset, rrsig_set};

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
}
