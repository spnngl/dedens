//! Signatures: key tags, digests, canonical forms, the verification of an `RRset`, and its extended errors.

mod key_tags {
    //! RFC 4034: key tags (Appendix B), the SHA-1 DS digest (§5.1.4, §5.4), canonical owner names (§6.2), and the
    //! RSASHA1 (5, 7) signatures of RFC 4035 Appendix A, the signed zone `example.`, whose keys are 1024 bits. RFC 9905
    //! §2: a validator still validates RSASHA1 (D71).

    use dedens_dnssec::crypto::{
        Budget, VerifyError, ds_digest, key_tag, supported, supported_digest, verify,
    };
    use dedens_dnssec::rrsig::{self, Key, MAX_FAILED, RrSet, SigError, Signature};
    use dedens_proto::{DigestType, MAX_LABEL_LEN, SecAlgorithm};
    use dedens_testkit::dnssec::{
        RFC4035_NS1_SIGNATURE, RFC4035_ZSK, Rr, Rrsig, b64, canonical_name, dnskey_rdata,
        signed_data,
    };
    use dedens_testkit::hex;

    use crate::util::{DSKEY, check, name, rrset, rrsig_set};

    const KSK: &str = "AQOeX7+baTmvpVHb2CcLnL1dMRWbuscRvHXl
    LnXwDzvqp4tZVKp1sZMepFb8MvxhhW3y/0QZ
    syCjczGJ1qk8vJe52iOhInKROVLRwxGpMfzP
    RLMlGybr51bOV/1se0ODacj3DomyB4QB5gKT
    Yot/K9alk5/j8vfd4jWCWD+E1Sze0Q==";
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
        let rrset = [dnskey_rdata(256, 5, RFC4035_ZSK), dnskey_rdata(257, 5, KSK)]
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
        assert_eq!(key_tag(&dnskey_rdata(256, 5, RFC4035_ZSK)), 38519);
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
        let digest =
            ds_digest(DigestType::SHA1, &owner, &dnskey_rdata(256, 5, DSKEY)).expect("SHA-1");
        assert_eq!(
            digest.as_ref(),
            hex("2BB183AF5F22588179A53B0A98631FAD1A292118")
        );
    }

    #[test]
    fn ds_digest_hashes_the_owner_in_lower_case() {
        // §6.2: canonical form lowercases the owner; the RDATA's octets stay as they are.
        let rdata = dnskey_rdata(256, 5, DSKEY);
        let lower =
            ds_digest(DigestType::SHA1, &name("dskey.example.com."), &rdata).expect("SHA-1");
        let mixed =
            ds_digest(DigestType::SHA1, &name("DsKey.EXAMPLE.com."), &rdata).expect("SHA-1");
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
        let key = b64(RFC4035_ZSK);
        let signature = b64(RFC4035_NS1_SIGNATURE);
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
        // The `RRset` sorts by RDATA (§6.3): the RFC4035_ZSK (flags 256) before the KSK (257).
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
        let key = b64(RFC4035_ZSK);
        let signature = b64(RFC4035_NS1_SIGNATURE);
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

    /// `ns1.example. A`, RFC 4035 Appendix A: the `RRset`, its RRSIG and the DNSKEY `RRset` of `example.`.
    fn appendix_a() -> (RrSet<'static>, RrSet<'static>, RrSet<'static>) {
        (
            rrset("ns1.example.", 1, &[vec![192, 0, 2, 1]]),
            rrsig_set(
                "ns1.example.",
                &rrsig(1, 5, 2, 38519),
                RFC4035_NS1_SIGNATURE,
            ),
            rrset(
                "example.",
                48,
                &[dnskey_rdata(256, 5, RFC4035_ZSK), dnskey_rdata(257, 5, KSK)],
            ),
        )
    }

    #[test]
    fn canonical_rdata_is_lowercase_sorted_and_without_duplicates() {
        // §6.2 item 3 and §6.3: MX's exchange lowercased, the records ordered by their RDATA bytes, the two that are
        // one record in lower case reduced to one.
        let mx = |preference: u16, exchange: &str| {
            let mut rdata = preference.to_be_bytes().to_vec();
            rdata.extend(name(exchange).to_wire(&mut [0; 255]));
            rdata
        };
        let set = rrset(
            "Host.EXAMPLE.",
            15,
            &[
                mx(20, "Mail.Example."),
                mx(10, "B.example."),
                mx(10, "b.EXAMPLE."),
                mx(9, "z.example."),
            ],
        );
        let lower = |preference: u16, exchange: &str| {
            let mut rdata = preference.to_be_bytes().to_vec();
            rdata.extend(canonical_name(exchange));
            rdata
        };
        assert_eq!(
            set.canonical_rdatas(),
            [
                lower(9, "z.example."),
                lower(10, "b.example."),
                lower(20, "mail.example.")
            ]
        );
    }

    #[test]
    fn canonical_rdata_lowercases_a_name_with_a_longest_label() {
        // §6.2 item 3: a 63-octet label, the longest (RFC 1035 §2.3.4), is a label, not a pointer or an extended one.
        let exchange = format!("{}.EXAMPLE.", "M".repeat(MAX_LABEL_LEN));
        let mut rdata = 10u16.to_be_bytes().to_vec();
        rdata.extend(name(&exchange).to_wire(&mut [0; 255]));
        let set = rrset("Host.EXAMPLE.", 15, &[rdata]);
        let mut lower = 10u16.to_be_bytes().to_vec();
        lower.extend(canonical_name(&exchange));
        assert_eq!(set.canonical_rdatas(), [lower]);
    }

    #[test]
    fn canonical_order_puts_a_shorter_rdata_before_a_longer_one() {
        // §6.3: a missing octet sorts before a zero octet.
        let set = rrset(
            "example.",
            16,
            &[vec![2, b'a', 0], vec![1, b'a'], vec![1, b'a', 0]],
        );
        assert_eq!(
            set.canonical_rdatas(),
            [vec![1, b'a'], vec![1, b'a', 0], vec![2, b'a', 0]]
        );
    }

    #[test]
    fn appendix_a_a_record_verifies_in_its_window() {
        // §3.1.5: both ends of the window are inside it.
        let (a, sigs, keys) = appendix_a();
        for now in [INCEPTION, INCEPTION + 1, EXPIRATION - 1, EXPIRATION] {
            let verified = check(&a, &sigs, &keys, now).expect("verifies");
            assert_eq!(verified.wildcard, None);
            // RFC 4035 §5.3.3: the TTL is capped by the seconds left.
            assert_eq!(verified.ttl.get(), 3600.min(EXPIRATION - now));
        }
    }

    #[test]
    fn appendix_a_a_record_fails_outside_its_window() {
        let (a, sigs, keys) = appendix_a();
        assert_eq!(
            check(&a, &sigs, &keys, INCEPTION - 1),
            Err(SigError::NotYetValid {
                key_tag: 38519,
                inception: INCEPTION
            })
        );
        assert_eq!(
            check(&a, &sigs, &keys, EXPIRATION + 1),
            Err(SigError::Expired {
                key_tag: 38519,
                expiration: EXPIRATION
            })
        );
    }

    #[test]
    fn appendix_a_dnskey_rrset_verifies_by_its_ksk() {
        // The signer is the owner of the `RRset`, `example.`: one label.
        let (_, _, keys) = appendix_a();
        let sigs = rrsig_set("example.", &rrsig(48, 5, 1, 9465), DNSKEY_SIGNATURE);
        assert!(check(&keys, &sigs, &keys, INCEPTION).is_ok());
    }

    #[test]
    fn a_changed_record_does_not_verify() {
        let (_, sigs, keys) = appendix_a();
        let changed = rrset("ns1.example.", 1, &[vec![192, 0, 2, 2]]);
        assert_eq!(
            check(&changed, &sigs, &keys, INCEPTION),
            Err(SigError::BadSignature { key_tag: 38519 })
        );
    }

    #[test]
    fn rrsig_fields_must_match_the_rrset_and_the_key() {
        let (a, sigs, keys) = appendix_a();
        let other_owner = rrset("ns2.example.", 1, &[vec![192, 0, 2, 1]]);
        let other_type = rrset("ns1.example.", 16, &[vec![1, b'a']]);
        for set in [&other_owner, &other_type] {
            assert_eq!(
                check(set, &sigs, &keys, INCEPTION),
                Err(SigError::NoSignature)
            );
        }
        // The signer `example.` must be at or above the owner.
        let elsewhere = rrset("ns1.example.org.", 1, &[vec![192, 0, 2, 1]]);
        let wrong_zone = rrsig_set(
            "ns1.example.org.",
            &rrsig(1, 5, 3, 38519),
            RFC4035_NS1_SIGNATURE,
        );
        assert_eq!(
            check(&elsewhere, &wrong_zone, &keys, INCEPTION),
            Err(SigError::BadSigner)
        );
        // A key tag no DNSKEY has.
        let no_key = rrsig_set("ns1.example.", &rrsig(1, 5, 2, 1), RFC4035_NS1_SIGNATURE);
        assert_eq!(
            check(&a, &no_key, &keys, INCEPTION),
            Err(SigError::NoKey { key_tag: 1 })
        );
        // No RRSIG at all.
        assert_eq!(
            rrsig::verify_any(&a, &[], &Key::all(&keys), INCEPTION, &mut Budget::default()),
            Err(SigError::NoSignature)
        );
    }

    #[test]
    fn a_window_that_ends_before_it_starts_is_its_own_error() {
        let (a, _, keys) = appendix_a();
        let mut sig = rrsig(1, 5, 2, 38519);
        (sig.inception, sig.expiration) = (EXPIRATION, INCEPTION);
        let sigs = rrsig_set("ns1.example.", &sig, RFC4035_NS1_SIGNATURE);
        assert_eq!(
            check(&a, &sigs, &keys, INCEPTION),
            Err(SigError::ExpiredBeforeValid { key_tag: 38519 })
        );
    }

    #[test]
    fn the_window_wraps_in_serial_arithmetic() {
        // RFC 1982: 2^32 - 10 is before 5, so a window from the one to the other holds 0. The signature is for
        // another window and fails, but only once the window check has passed.
        let (a, _, keys) = appendix_a();
        let mut sig = rrsig(1, 5, 2, 38519);
        (sig.inception, sig.expiration) = (u32::MAX - 9, 5);
        let sigs = rrsig_set("ns1.example.", &sig, RFC4035_NS1_SIGNATURE);
        assert_eq!(
            check(&a, &sigs, &keys, 0),
            Err(SigError::BadSignature { key_tag: 38519 })
        );
        assert!(matches!(
            check(&a, &sigs, &keys, 10),
            Err(SigError::Expired { .. })
        ));
        assert!(matches!(
            check(&a, &sigs, &keys, u32::MAX - 20),
            Err(SigError::NotYetValid { .. })
        ));
    }

    #[test]
    fn a_key_signs_only_with_the_zone_bit_and_without_revoke() {
        let (a, sigs, _) = appendix_a();
        let zsk = |flags| rrset("example.", 48, &[dnskey_rdata(flags, 5, RFC4035_ZSK)]);
        // The flags are in the key tag: the RRSIG names the tag the changed key has.
        let tag = |flags| key_tag(&dnskey_rdata(flags, 5, RFC4035_ZSK));
        for (flags, expected) in [
            (0, SigError::NotZoneKey { key_tag: tag(0) }),
            (
                0x0100 | 0x0080,
                SigError::RevokedKey {
                    key_tag: tag(0x0180),
                },
            ),
        ] {
            let sigs = rrsig_set(
                "ns1.example.",
                &rrsig(1, 5, 2, tag(flags)),
                RFC4035_NS1_SIGNATURE,
            );
            assert_eq!(check(&a, &sigs, &zsk(flags), INCEPTION), Err(expected));
        }
        assert!(check(&a, &sigs, &zsk(0x0100), INCEPTION).is_ok());
    }

    #[test]
    fn the_ds_digest_of_the_ksk_vouches_for_the_dnskey_rrset() {
        // The DS records are computed from the KSK (§5.1.4): the Appendix has none for `example.` itself.
        let (_, _, keys) = appendix_a();
        let sigs = rrsig_set("example.", &rrsig(48, 5, 1, 9465), DNSKEY_SIGNATURE);
        let rdata = dnskey_rdata(257, 5, KSK);
        let ds = |digest_type: DigestType, digest: &[u8]| {
            let mut rdata = 9465_u16.to_be_bytes().to_vec();
            rdata.extend([5, digest_type.0]);
            rdata.extend(digest);
            rdata
        };
        let digest = |digest_type| {
            ds_digest(digest_type, &name("example."), &rdata)
                .expect("supported")
                .as_ref()
                .to_vec()
        };
        let (sha1, sha256) = (digest(DigestType::SHA1), digest(DigestType::SHA256));
        let trust = |ds: &RrSet<'_>| {
            rrsig::trusted_keys(
                &keys,
                &Signature::all(&sigs),
                ds,
                INCEPTION,
                &mut Budget::default(),
            )
        };
        for (digest_type, digest) in [(DigestType::SHA1, &sha1), (DigestType::SHA256, &sha256)] {
            let set = rrset("example.", 43, &[ds(digest_type, digest)]);
            assert!(trust(&set).is_ok(), "{digest_type}");
        }
        // RFC 4509 §3: a SHA-1 DS is ignored when a SHA-256 one of the key is there, so a right SHA-1 digest does
        // not save a wrong SHA-256 one.
        let both = rrset(
            "example.",
            43,
            &[
                ds(DigestType::SHA1, &sha1),
                ds(DigestType::SHA256, &[0; 32]),
            ],
        );
        assert_eq!(trust(&both), Err(SigError::NoKeyForDs));
        // A DS of another owner vouches for nothing here.
        let elsewhere = rrset("example.org.", 43, &[ds(DigestType::SHA256, &sha256)]);
        assert_eq!(trust(&elsewhere), Err(SigError::NoKeyForDs));
        // Digest 3 (GOST) is not supported: insecure, not bogus (RFC 6840 §5.2).
        let gost = rrset("example.", 43, &[ds(DigestType::GOST, &[0; 32])]);
        let error = trust(&gost).unwrap_err();
        assert!(error.is_unsupported());
        assert_eq!(
            error,
            SigError::UnsupportedDigest {
                digest: DigestType::GOST
            }
        );
    }

    /// The DS RDATA of the DNSKEY RDATA `key` at `example.`.
    fn ds_of(key: &[u8], digest_type: DigestType) -> Vec<u8> {
        let digest = ds_digest(digest_type, &name("example."), key).expect("supported");
        let mut rdata = key_tag(key).to_be_bytes().to_vec();
        rdata.extend([key[3], digest_type.0]);
        rdata.extend(digest.as_ref());
        rdata
    }

    #[test]
    fn a_sha1_ds_is_ignored_only_beside_a_stronger_digest_of_its_own_key() {
        // RFC 4509 §3 speaks of the same key: a SHA-256 DS of the ZSK does not drop the SHA-1 DS of the KSK.
        let (_, _, keys) = appendix_a();
        let sigs = rrsig_set("example.", &rrsig(48, 5, 1, 9465), DNSKEY_SIGNATURE);
        let ksk = dnskey_rdata(257, 5, KSK);
        let zsk = dnskey_rdata(256, 5, RFC4035_ZSK);
        let ds = rrset(
            "example.",
            43,
            &[
                ds_of(&ksk, DigestType::SHA1),
                ds_of(&zsk, DigestType::SHA256),
            ],
        );
        let trusted = rrsig::trusted_keys(
            &keys,
            &Signature::all(&sigs),
            &ds,
            INCEPTION,
            &mut Budget::default(),
        );
        assert!(trusted.is_ok(), "{trusted:?}");
    }

    /// `count` DNSKEY RDATA with the key tag of `key`, each different: two bytes at distances of two are swapped,
    /// which leaves the sum of the key tag (RFC 4034 Appendix B) as it is.
    fn colliding(key: &[u8], count: usize) -> Vec<Vec<u8>> {
        let mut found: Vec<Vec<u8>> = Vec::new();
        for at in 4..key.len() - 2 {
            let mut other = key.to_vec();
            other.swap(at, at + 2);
            if other != key && !found.contains(&other) {
                assert_eq!(key_tag(&other), key_tag(key));
                found.push(other);
            }
            if found.len() == count {
                break;
            }
        }
        assert_eq!(found.len(), count);
        found
    }

    #[test]
    fn keys_that_share_the_tag_of_a_ds_are_digested_a_few_times_only() {
        // The DNSKEY `RRset` is not authenticated yet, and a zone may publish many keys of one tag: KeyTrap by the
        // DS digests (D73). Up to `MAX_FAILED` keys of the tag may fail to match, then the `RRset` is refused.
        let ksk = dnskey_rdata(257, 5, KSK);
        let ds = rrset("example.", 43, &[ds_of(&ksk, DigestType::SHA256)]);
        let trust = |others: usize| {
            let mut keys = colliding(&ksk, others);
            keys.push(ksk.clone());
            let keys = rrset("example.", 48, &keys);
            rrsig::trusted_keys(&keys, &[], &ds, INCEPTION, &mut Budget::default())
        };
        // The right key is found, and nothing signs the `RRset`.
        assert_eq!(trust(MAX_FAILED), Err(SigError::NoSignature));
        assert_eq!(trust(MAX_FAILED + 1), Err(SigError::TooManyFailures));
    }
}

mod verification {
    //! RFC 4035 §5.3: the checks of an RRSIG over an `RRset`, with the signed zone `example.` of Appendix A (keys of
    //! 1024 bits, RSASHA1): wildcard expansion (§5.3.2, Appendix B.6), the labels field, and the limits on failed
    //! checks that RFC 4035 leaves open (D73).
    //!
    //! RFC 4035 §5.2, §5.4: the denials of existence of Appendix B, from the NSEC records of the example zone of
    //! Appendix A, `testdata/zones/rfc4035_appendix_a.zone` (D74).
    //!
    //! RFC 5011 §7: a key with the REVOKE bit set verifies nothing (D73).

    use dedens_dnssec::crypto::Budget;
    use dedens_dnssec::denial::{Fact, Proof, Unproven};
    use dedens_dnssec::rrsig::{self, Key, MAX_FAILED, RrSet, SigError, Signature};
    use dedens_proto::{Record, RecordType, Ttl};
    use dedens_testkit::dnssec::{RFC4035_NS1_SIGNATURE, RFC4035_ZSK, Rrsig, dnskey_rdata};
    use dedens_testkit::zone;

    use crate::util::denial::{nsec, pick, prove, prove_wildcard};
    use crate::util::{check, name, rrset, rrset_in, rrsig_set};

    // 2004-04-09T18:36:19Z and 2004-05-09T18:36:19Z.
    const INCEPTION: u32 = 1_081_535_779;
    const EXPIRATION: u32 = 1_084_127_779;

    // spellchecker:off
    // `*.w.example. MX 1 ai.example.`, Appendix A, and the same RRSIG in Appendix B.6 over `a.z.w.example.`.
    const WILDCARD_SIGNATURE: &str = "OMK8rAZlepfzLWW75Dxd63jy2wswESzxDKG2
    f9AMN1CytCd10cYISAxfAdvXSZ7xujKAtPbc
    tvOQ2ofO7AZJ+d01EeeQTVBPq4/6KCWhqe2X
    TjnkVLNvvhnc0u28aoSsG0+4InvkkOHknKxw
    4kX18MMR34i8lC36SR5xBni8vHI=";
    // `x.w.example. MX 1 xx.example.`, a name the zone has: no wildcard.
    const X_W_SIGNATURE: &str = "Il2WTZ+Bkv+OytBx4LItNW5mjB4RCwhOO8y1
    XzPHZmZUTVYL7LaA63f6T9ysVBzJRI3KRjAP
    H3U1qaYnDoN1DrWqmi9RJe4FoObkbcdm7P3I
    kx70ePCoFgRz1Yq+bVVXCvGuAU4xALv3W/Y1
    jNSlwZ2mSWKHfxFQxPtLj8s32+k=";
    // spellchecker:on

    fn rrsig(type_covered: u16, labels: u8) -> Rrsig<'static> {
        Rrsig {
            type_covered,
            algorithm: 5,
            labels,
            original_ttl: 3600,
            expiration: EXPIRATION,
            inception: INCEPTION,
            key_tag: 38519,
            signer: "example.",
        }
    }

    fn zsk() -> RrSet<'static> {
        rrset("example.", 48, &[dnskey_rdata(256, 5, RFC4035_ZSK)])
    }

    /// `owner MX 1 exchange`.
    fn mx(owner: &str, exchange: &str) -> RrSet<'static> {
        let mut rdata = 1_u16.to_be_bytes().to_vec();
        rdata.extend(dedens_testkit::dnssec::canonical_name(exchange));
        rrset(owner, 15, &[rdata])
    }

    #[test]
    fn a_wildcard_expansion_verifies_and_names_the_closest_encloser() {
        // §5.3.2: `a.z.w.example.` has 4 labels, the RRSIG says 2: the signed owner is `*.w.example.`.
        let sigs = rrsig_set("a.z.w.example.", &rrsig(15, 2), WILDCARD_SIGNATURE);
        let verified = check(
            &mx("a.z.w.example.", "ai.example."),
            &sigs,
            &zsk(),
            INCEPTION,
        )
        .expect("verifies");
        assert_eq!(verified.wildcard, Some(name("w.example.")));
        // Any other name the wildcard matches has the same signature, whatever its case.
        let sigs = rrsig_set("B.Y.W.example.", &rrsig(15, 2), WILDCARD_SIGNATURE);
        let verified = check(
            &mx("B.Y.W.example.", "AI.example."),
            &sigs,
            &zsk(),
            INCEPTION,
        )
        .expect("verifies");
        assert_eq!(verified.wildcard, Some(name("w.example.")));
    }

    #[test]
    fn a_wildcard_signature_does_not_verify_under_another_encloser() {
        // `a.z.v.example.` would be the expansion of `*.v.example.`, which nothing signed.
        let sigs = rrsig_set("a.z.v.example.", &rrsig(15, 2), WILDCARD_SIGNATURE);
        assert_eq!(
            check(
                &mx("a.z.v.example.", "ai.example."),
                &sigs,
                &zsk(),
                INCEPTION
            ),
            Err(SigError::BadSignature { key_tag: 38519 })
        );
    }

    #[test]
    fn the_wildcard_itself_has_no_encloser() {
        // The leading `*` is not counted (RFC 4034 §3.1.3): `*.w.example.` has 2 labels, as the RRSIG says.
        let sigs = rrsig_set("*.w.example.", &rrsig(15, 2), WILDCARD_SIGNATURE);
        let verified =
            check(&mx("*.w.example.", "ai.example."), &sigs, &zsk(), INCEPTION).expect("verifies");
        assert_eq!(verified.wildcard, None);
    }

    #[test]
    fn a_name_of_the_zone_is_no_wildcard_expansion() {
        let sigs = rrsig_set("x.w.example.", &rrsig(15, 3), X_W_SIGNATURE);
        let verified =
            check(&mx("x.w.example.", "xx.example."), &sigs, &zsk(), INCEPTION).expect("verifies");
        assert_eq!(verified.wildcard, None);
    }

    #[test]
    fn more_labels_than_the_owner_has_is_invalid() {
        // §5.3.1: the labels field is at most the owner's label count.
        let sigs = rrsig_set("w.example.", &rrsig(15, 3), X_W_SIGNATURE);
        assert_eq!(
            check(&mx("w.example.", "xx.example."), &sigs, &zsk(), INCEPTION),
            Err(SigError::BadLabels {
                labels: 3,
                owner: 2
            })
        );
        // `*.w.example.` has 2 labels, not 3.
        let sigs = rrsig_set("*.w.example.", &rrsig(15, 3), X_W_SIGNATURE);
        assert_eq!(
            check(&mx("*.w.example.", "ai.example."), &sigs, &zsk(), INCEPTION),
            Err(SigError::BadLabels {
                labels: 3,
                owner: 2
            })
        );
    }

    #[test]
    fn the_ttl_kept_is_the_least_of_the_rrset_and_the_signature() {
        // §5.3.3: the RRset's TTL 100 is below the original 3600 and the 2^31 seconds left.
        let a = RrSet::group(&crate::util::records(
            "ns1.example.",
            1,
            100,
            &[vec![192, 0, 2, 1]],
        ))
        .pop()
        .expect("one RRset");
        let sigs = rrsig_set("ns1.example.", &rrsig(1, 2), RFC4035_NS1_SIGNATURE);
        let verified = check(&a, &sigs, &zsk(), INCEPTION).expect("verifies");
        assert_eq!(verified.ttl.get(), 100);
    }

    /// 20 copies of the right key, and a record the signature does not cover: every check fails.
    fn keytrap() -> (RrSet<'static>, RrSet<'static>, RrSet<'static>) {
        let rdata = dnskey_rdata(256, 5, RFC4035_ZSK);
        (
            rrset("ns1.example.", 1, &[vec![192, 0, 2, 2]]),
            rrsig_set("ns1.example.", &rrsig(1, 2), RFC4035_NS1_SIGNATURE),
            rrset("example.", 48, &vec![rdata; 20]),
        )
    }

    #[test]
    fn a_rrset_gives_up_after_a_few_failed_checks() {
        // KeyTrap (CVE-2023-50387): many keys of the one tag, none that verifies.
        let (a, sigs, keys) = keytrap();
        let mut budget = Budget::default();
        let before = budget.verifications_left();
        assert_eq!(
            rrsig::verify_any(
                &a,
                &Signature::all(&sigs),
                &Key::all(&keys),
                INCEPTION,
                &mut budget
            ),
            Err(SigError::TooManyFailures)
        );
        let spent = before.0 - budget.verifications_left().0;
        assert_eq!(usize::try_from(spent), Ok(MAX_FAILED));
    }

    #[test]
    fn the_budget_of_the_whole_validation_stops_the_checks() {
        let (a, sigs, keys) = keytrap();
        let mut budget = Budget::new(
            dedens_dnssec::crypto::Verifications(3),
            Budget::DEFAULT_NSEC3_BLOCKS,
        );
        let result = rrsig::verify_any(
            &a,
            &Signature::all(&sigs),
            &Key::all(&keys),
            INCEPTION,
            &mut budget,
        );
        assert!(matches!(result, Err(SigError::BudgetExhausted(_))));
        assert_eq!(budget.verifications_left().0, 0);
    }

    /// `ns1.example.` at an address the signature does not cover.
    fn forged() -> RrSet<'static> {
        rrset("ns1.example.", 1, &[vec![192, 0, 2, 2]])
    }

    fn signatures<'a>(sets: &[&'a RrSet<'static>]) -> Vec<Signature<'a>> {
        sets.iter().flat_map(|set| Signature::all(set)).collect()
    }

    fn verify_any(
        rrset: &RrSet<'_>,
        sigs: &[Signature<'_>],
        keys: &RrSet<'_>,
        now: u32,
    ) -> Result<rrsig::Verified, SigError> {
        rrsig::verify_any(rrset, sigs, &Key::all(keys), now, &mut Budget::default())
    }

    #[test]
    fn an_rrsig_of_an_unknown_algorithm_is_disregarded_not_a_way_to_insecurity() {
        // RFC 6840 §5.12: an RRSIG of an algorithm the validator does not know is as if absent, and which
        // algorithms a zone is signed with is the DS records' to say (§5.11, RFC 4035 §5.2). Otherwise one forged
        // RRSIG of algorithm 200 would turn a forged answer of a signed zone into an insecure one.
        let unknown = rrsig_set(
            "ns1.example.",
            &Rrsig {
                algorithm: 200,
                ..rrsig(1, 2)
            },
            RFC4035_NS1_SIGNATURE,
        );
        let keys = rrset(
            "example.",
            48,
            &[
                dnskey_rdata(256, 5, RFC4035_ZSK),
                dnskey_rdata(256, 200, RFC4035_ZSK),
            ],
        );
        let result = verify_any(&forged(), &signatures(&[&unknown]), &keys, INCEPTION);
        assert_eq!(result, Err(SigError::NoSignature));
        assert!(!result.unwrap_err().is_unsupported());
        // Beside an RRSIG that is known, the known one decides.
        let known = rrsig_set("ns1.example.", &rrsig(1, 2), RFC4035_NS1_SIGNATURE);
        let result = verify_any(
            &forged(),
            &signatures(&[&unknown, &known]),
            &keys,
            INCEPTION,
        );
        assert_eq!(result, Err(SigError::BadSignature { key_tag: 38519 }));
        // The right data is authenticated by the known RRSIG all the same.
        let a = rrset("ns1.example.", 1, &[vec![192, 0, 2, 1]]);
        assert!(verify_any(&a, &signatures(&[&unknown, &known]), &keys, INCEPTION).is_ok());
    }

    #[test]
    fn a_ds_belongs_to_the_parent_and_a_dnskey_to_its_own_zone() {
        // RFC 4035 §2.4: the DS RRset is signed by the parent's keys, so a DS RRSIG whose signer is the owner (the
        // child's, which the attacker may hold) is invalid. §5.2: a DNSKEY RRset is signed by its own zone.
        let ds = rrset(
            "w.example.",
            43,
            &[[vec![0x96, 0x4b, 5, 1], vec![7; 20]].concat()],
        );
        let by_child = rrsig_set(
            "w.example.",
            &Rrsig {
                signer: "w.example.",
                ..rrsig(43, 2)
            },
            RFC4035_NS1_SIGNATURE,
        );
        assert_eq!(
            verify_any(&ds, &signatures(&[&by_child]), &zsk(), INCEPTION),
            Err(SigError::BadSigner)
        );
        // The parent's signature on it passes the checks of the RRSIG, and fails only as a signature.
        let by_parent = rrsig_set("w.example.", &rrsig(43, 2), RFC4035_NS1_SIGNATURE);
        assert_eq!(
            verify_any(&ds, &signatures(&[&by_parent]), &zsk(), INCEPTION),
            Err(SigError::BadSignature { key_tag: 38519 })
        );
        let dnskey = rrset("w.example.", 48, &[dnskey_rdata(257, 5, RFC4035_ZSK)]);
        let by_parent = rrsig_set("w.example.", &rrsig(48, 2), RFC4035_NS1_SIGNATURE);
        assert_eq!(
            verify_any(&dnskey, &signatures(&[&by_parent]), &zsk(), INCEPTION),
            Err(SigError::BadSigner)
        );
    }

    #[test]
    fn a_signer_below_the_owner_is_invalid() {
        let sigs = rrsig_set(
            "example.",
            &Rrsig {
                signer: "w.example.",
                ..rrsig(15, 2)
            },
            X_W_SIGNATURE,
        );
        assert_eq!(
            verify_any(
                &mx("example.", "xx.example."),
                &signatures(&[&sigs]),
                &zsk(),
                INCEPTION
            ),
            Err(SigError::BadSigner)
        );
    }

    #[test]
    fn fewer_labels_than_the_signer_has_is_invalid() {
        // The signer `w.example.` has 2 labels: 1 would be the expansion of `*.example.`, a wildcard of the parent
        // zone, which the signer's keys do not speak for.
        let sigs = rrsig_set(
            "a.z.w.example.",
            &Rrsig {
                signer: "w.example.",
                ..rrsig(15, 1)
            },
            WILDCARD_SIGNATURE,
        );
        assert_eq!(
            verify_any(
                &mx("a.z.w.example.", "ai.example."),
                &signatures(&[&sigs]),
                &zsk(),
                INCEPTION
            ),
            Err(SigError::BadLabels {
                labels: 1,
                owner: 4
            })
        );
    }

    #[test]
    fn the_class_of_the_rrset_signature_and_key_must_be_the_same() {
        let a = rrset("ns1.example.", 1, &[vec![192, 0, 2, 1]]);
        let sigs = rrsig_set("ns1.example.", &rrsig(1, 2), RFC4035_NS1_SIGNATURE);
        let chaos = rrset_in(3, "ns1.example.", 1, &[vec![192, 0, 2, 1]]);
        assert_eq!(
            verify_any(&chaos, &signatures(&[&sigs]), &zsk(), INCEPTION),
            Err(SigError::NoSignature)
        );
        let chaos_keys = rrset_in(3, "example.", 48, &[dnskey_rdata(256, 5, RFC4035_ZSK)]);
        assert_eq!(
            verify_any(&a, &signatures(&[&sigs]), &chaos_keys, INCEPTION),
            Err(SigError::NoKey { key_tag: 38519 })
        );
    }

    #[test]
    fn the_error_returned_is_the_one_closest_to_a_success() {
        // A missing key, a window that has ended, a signature that does not verify: the last is the closest, and
        // the order of the RRSIGs does not matter.
        let bad = rrsig_set("ns1.example.", &rrsig(1, 2), RFC4035_NS1_SIGNATURE);
        let nokey = rrsig_set(
            "ns1.example.",
            &Rrsig {
                key_tag: 1,
                ..rrsig(1, 2)
            },
            RFC4035_NS1_SIGNATURE,
        );
        for sigs in [signatures(&[&nokey, &bad]), signatures(&[&bad, &nokey])] {
            assert_eq!(
                verify_any(&forged(), &sigs, &zsk(), INCEPTION),
                Err(SigError::BadSignature { key_tag: 38519 })
            );
            assert_eq!(
                verify_any(&forged(), &sigs, &zsk(), EXPIRATION + 1),
                Err(SigError::Expired {
                    key_tag: 38519,
                    expiration: EXPIRATION
                })
            );
        }
        let only = signatures(&[&nokey]);
        assert_eq!(
            verify_any(&forged(), &only, &zsk(), INCEPTION),
            Err(SigError::NoKey { key_tag: 1 })
        );
        assert_eq!(
            verify_any(&forged(), &[], &zsk(), INCEPTION),
            Err(SigError::NoSignature)
        );
    }

    #[test]
    fn failures_that_cost_no_verification_count_toward_the_cap_too() {
        // KeyTrap by RRSIGs that fail their cheap checks: each is a pair tried, so a zone cannot make the validator
        // walk thousands of them (D73), and none spends the budget.
        for rrsig in [
            // Ended before `now`.
            Rrsig {
                expiration: INCEPTION + 10,
                ..rrsig(1, 2)
            },
            // More labels than the owner.
            Rrsig {
                labels: 9,
                ..rrsig(1, 2)
            },
        ] {
            let sets: Vec<RrSet<'static>> = (0..MAX_FAILED + 2)
                .map(|_| rrsig_set("ns1.example.", &rrsig, RFC4035_NS1_SIGNATURE))
                .collect();
            let sigs: Vec<Signature<'_>> = sets.iter().flat_map(Signature::all).collect();
            let mut budget = Budget::default();
            let before = budget.verifications_left();
            let result = rrsig::verify_any(
                &forged(),
                &sigs,
                &Key::all(&zsk()),
                INCEPTION + 100,
                &mut budget,
            );
            assert_eq!(result, Err(SigError::TooManyFailures));
            assert_eq!(budget.verifications_left(), before);
        }
    }

    #[test]
    fn rrsigs_without_a_key_do_not_count_toward_the_cap() {
        // Nothing is checked for them, and an attacker has nothing to gain: a zone may well sign with keys the
        // validator was not given.
        let sets: Vec<RrSet<'static>> = (0..MAX_FAILED + 2)
            .map(|_| {
                rrsig_set(
                    "ns1.example.",
                    &Rrsig {
                        key_tag: 1,
                        ..rrsig(1, 2)
                    },
                    RFC4035_NS1_SIGNATURE,
                )
            })
            .collect();
        let sigs: Vec<Signature<'_>> = sets.iter().flat_map(Signature::all).collect();
        assert_eq!(
            verify_any(&forged(), &sigs, &zsk(), INCEPTION),
            Err(SigError::NoKey { key_tag: 1 })
        );
    }

    // Denial of existence (D74).

    const APEX: &str = "example.";
    /// The TTL of every record of Appendix A.
    const TTL: Ttl = Ttl::from_wire(3600);

    fn nsecs(owners: &[&str]) -> Vec<Record<'static>> {
        pick(&zone("rfc4035_appendix_a.zone"), RecordType::NSEC, owners)
    }

    fn proof(fact: Fact) -> Proof {
        Proof {
            fact,
            ttl: TTL,
            opt_out: false,
        }
    }

    const NAME_ERROR: Fact = Fact::NameError { compact: false };

    /// B.2: `ml.example.` is covered by `b.example.`, and `*.example.` by the apex.
    #[test]
    fn b2_name_error() {
        let records = nsecs(&["b.example.", "example."]);
        assert_eq!(
            prove(APEX, "ml.example.", RecordType::A, &records),
            Ok(proof(NAME_ERROR))
        );
        // Without the wildcard's NSEC the response proves less.
        let records = nsecs(&["b.example."]);
        assert_eq!(
            prove(APEX, "ml.example.", RecordType::A, &records),
            Err(Unproven::WildcardNotDenied)
        );
        // Without the name's.
        let records = nsecs(&["example."]);
        assert_eq!(
            prove(APEX, "ml.example.", RecordType::A, &records),
            Err(Unproven::NotCovered)
        );
    }

    /// The last NSEC of the chain wraps to the apex, and a name below an existing name has it as closest encloser.
    #[test]
    fn name_errors_after_the_last_name_and_below_a_name() {
        let records = nsecs(&["xx.example.", "example."]);
        assert_eq!(
            prove(APEX, "zzz.example.", RecordType::A, &records),
            Ok(proof(NAME_ERROR))
        );
        // The wildcard `*.ns1.example.` sorts between `ns1.example.` and `ns2.example.`.
        let records = nsecs(&["ns1.example."]);
        assert_eq!(
            prove(APEX, "a.b.ns1.example.", RecordType::A, &records),
            Ok(proof(NAME_ERROR))
        );
    }

    /// B.3: `ns1.example.` exists and has no MX.
    #[test]
    fn b3_no_data() {
        let records = nsecs(&["ns1.example."]);
        assert_eq!(
            prove(APEX, "ns1.example.", RecordType::MX, &records),
            Ok(proof(Fact::NoData))
        );
        assert_eq!(
            prove(APEX, "ns1.example.", RecordType::A, &records),
            Err(Unproven::TypePresent)
        );
    }

    /// The name of an NSEC and the case of the question do not matter (RFC 4343).
    #[test]
    fn names_compare_without_case() {
        let records = nsecs(&["ns1.example."]);
        assert_eq!(
            prove(APEX, "NS1.Example.", RecordType::MX, &records),
            Ok(proof(Fact::NoData))
        );
    }

    /// Derived: the owner and next names of NSEC records in capitals, as a signer may write them; the shape is the
    /// zone's NSEC of `ns1.example.` and of the apex (RFC 4343, RFC 4034 §6.2 lowercases names to sign, not to send).
    #[test]
    fn nsec_names_compare_without_case() {
        let types = [RecordType::NS, RecordType::RRSIG, RecordType::NSEC];
        let records = [
            nsec("NS1.EXAMPLE.", "NS2.Example.", &types),
            nsec(
                "EXAMPLE.",
                "A.EXAMPLE.",
                &[
                    RecordType::NS,
                    RecordType::SOA,
                    RecordType::RRSIG,
                    RecordType::NSEC,
                ],
            ),
        ];
        assert_eq!(
            prove(APEX, "ns1.example.", RecordType::MX, &records[..1]),
            Err(Unproven::AtDelegation)
        );
        assert_eq!(
            prove(APEX, "ns1a.example.", RecordType::A, &records),
            Ok(proof(NAME_ERROR))
        );
    }

    /// Derived: RFC 4592 §2.2.1: `a.*.w.example.` exists, so `*.w.example.` is an empty non-terminal. It exists, so
    /// `q.w.example.` is answered by it with no data, and an NSEC that lists the wildcard's child as the next name
    /// does not deny the wildcard. The chain is the zone's, with `a.*.w.example.` inserted between `ns2.example.`
    /// and `x.w.example.`.
    #[test]
    fn a_wildcard_that_is_an_empty_non_terminal_is_no_data() {
        let types = [RecordType::A, RecordType::RRSIG, RecordType::NSEC];
        let records = [
            nsec("ns2.example.", "a.*.w.example.", &types),
            nsec("a.*.w.example.", "x.w.example.", &types),
        ];
        assert_eq!(
            prove(APEX, "q.w.example.", RecordType::A, &records),
            Ok(proof(Fact::WildcardNoData))
        );
    }

    /// A name that is an ancestor of names of the zone exists, with no data: the NSEC before it names one below it.
    #[test]
    fn empty_non_terminal_is_no_data() {
        let records = nsecs(&["x.w.example."]);
        assert_eq!(
            prove(APEX, "y.w.example.", RecordType::A, &records),
            Ok(proof(Fact::NoData))
        );
        // `w.example.` is one too: `*.w.example.` is below it.
        assert_eq!(
            prove(APEX, "w.example.", RecordType::A, &nsecs(&["ns2.example."])),
            Ok(proof(Fact::NoData))
        );
    }

    /// B.5: `b.example.` has NS, no DS and no SOA: an unsigned delegation, which is what the NSEC proves of DS.
    #[test]
    fn b5_referral_to_unsigned_zone() {
        let records = nsecs(&["b.example."]);
        assert_eq!(
            prove(APEX, "b.example.", RecordType::DS, &records),
            Ok(proof(Fact::InsecureDelegation))
        );
    }

    /// B.4: `a.example.` has a DS, so no NSEC proves it absent.
    #[test]
    fn b4_referral_to_signed_zone() {
        let records = nsecs(&["a.example."]);
        assert_eq!(
            prove(APEX, "a.example.", RecordType::DS, &records),
            Err(Unproven::TypePresent)
        );
    }

    /// B.6: the RRSIG of `a.z.w.example.` has 2 labels, and the NSEC of `x.y.w.example.` covers `z.w.example.`.
    #[test]
    fn b6_wildcard_expansion() {
        let records = nsecs(&["x.y.w.example."]);
        assert_eq!(
            prove_wildcard(APEX, "a.z.w.example.", 2, &records),
            Ok(proof(Fact::WildcardAnswer))
        );
        // `y.w.example.` is an empty non-terminal: the NSEC of `x.w.example.` leads below it.
        assert_eq!(
            prove_wildcard(APEX, "a.y.w.example.", 2, &nsecs(&["x.w.example."])),
            Err(Unproven::CloserNameExists)
        );
        // `x.w.example.` exists and has an NSEC of its own.
        assert_eq!(
            prove_wildcard(APEX, "a.x.w.example.", 2, &nsecs(&["x.w.example."])),
            Err(Unproven::CloserNameExists)
        );
        // Labels that leave nothing for the wildcard to replace.
        assert_eq!(
            prove_wildcard(APEX, "a.z.w.example.", 4, &records),
            Err(Unproven::NotExpanded)
        );
    }

    /// B.7: `*.w.example.` exists and has no AAAA, and `x.y.w.example.` covers `z.w.example.`.
    #[test]
    fn b7_wildcard_no_data() {
        let records = nsecs(&["x.y.w.example.", "*.w.example."]);
        assert_eq!(
            prove(APEX, "a.z.w.example.", RecordType::AAAA, &records),
            Ok(proof(Fact::WildcardNoData))
        );
        // The wildcard has an MX: the response should have been an answer.
        assert_eq!(
            prove(APEX, "a.z.w.example.", RecordType::MX, &records),
            Err(Unproven::WildcardHasType)
        );
    }

    /// B.8: the NSEC of the apex has SOA, so it is the child's, and says nothing of a delegation.
    #[test]
    fn b8_ds_from_the_child() {
        let records = nsecs(&["example."]);
        assert_eq!(
            prove(APEX, "example.", RecordType::DS, &records),
            Err(Unproven::FromChildApex)
        );
        // At the apex, other types are no data as anywhere.
        assert_eq!(
            prove(APEX, "example.", RecordType::AAAA, &records),
            Ok(proof(Fact::NoData))
        );
        assert_eq!(
            prove(APEX, "example.", RecordType::MX, &records),
            Err(Unproven::TypePresent)
        );
    }

    #[test]
    fn other_questions_prove_nothing() {
        let records = nsecs(&["b.example.", "example."]);
        assert_eq!(
            prove(APEX, "ml.other.", RecordType::A, &records),
            Err(Unproven::OutsideZone)
        );
        assert_eq!(
            prove(APEX, "ml.example.", RecordType::A, &[]),
            Err(Unproven::NoUsableRecords)
        );
        // Records of another zone are ignored.
        assert_eq!(
            prove("other.", "ml.other.", RecordType::A, &records),
            Err(Unproven::NoUsableRecords)
        );
    }
}

mod clarifications {
    //! RFC 6840 §5.1 (the canonical form of RDATA, correcting RFC 4034 §6.2: which names of RDATA a signer
    //! lowercases), §5.4 (any one valid RRSIG is enough), §5.11 (any single valid path from the DS records) and §5.12
    //! (RRSIGs without a corresponding DNSKEY are disregarded).
    //!
    //! RFC 6840 §4.1 (NSEC and NSEC3 at a delegation or a DNAME), §4.3 (the CNAME bit of a no data), §4.4 (what shows
    //! an insecure delegation), on the example zone of RFC 4035 Appendix A (D74). The zone has no DNAME, CNAME or
    //! empty-non-terminal-wildcard case, and no capture does: the tests marked "Derived" build their NSEC records with
    //! `util::denial::nsec`, shaped as the zone's NSEC for `b.example.` (owner, next name, types, RRSIG, NSEC), with
    //! the bitmap the RFC section names.

    use dedens_dnssec::crypto::{Budget, ds_digest, key_tag};
    use dedens_dnssec::denial::{Fact, Proof, Unproven};
    use dedens_dnssec::rrsig::{self, Key, RrSet, SigError, Signature};
    use dedens_proto::{DigestType, Record, RecordType, Ttl};
    use dedens_testkit::dnssec::{
        RFC4035_NS1_SIGNATURE, RFC4035_ZSK, Rrsig, canonical_name, dnskey_rdata,
    };
    use dedens_testkit::zone;

    use crate::util::denial::{nsec, pick, prove};
    use crate::util::{name, rrset, rrsig_set};

    /// A name in wire form, in the case given.
    fn wire(text: &str) -> Vec<u8> {
        name(text).to_wire(&mut [0; 255]).to_vec()
    }

    /// RDATA made of `parts`, joined.
    fn rdata(parts: &[&[u8]]) -> Vec<u8> {
        parts.concat()
    }

    /// The one canonical RDATA of `rtype` at `owner` made of `rdata`.
    fn canonical(rtype: u16, rdata: Vec<u8>) -> Vec<u8> {
        let mut rdatas = rrset("owner.example.", rtype, &[rdata]).canonical_rdatas();
        assert_eq!(rdatas.len(), 1);
        rdatas.pop().expect("one RDATA")
    }

    #[test]
    fn the_names_of_rfc_4034_6_2_are_lowercased() {
        let mixed = wire("Mail.EXAMPLE.");
        let lower = canonical_name("mail.example.");
        let preference = 10_u16.to_be_bytes();
        // (type, RDATA with the name in any case, the same in lower case)
        let cases: Vec<(u16, Vec<u8>, Vec<u8>)> = vec![
            // NS, CNAME, PTR, DNAME (RFC 6672 §2.2 keeps it in §6.2's list).
            (2, mixed.clone(), lower.clone()),
            (5, mixed.clone(), lower.clone()),
            (12, mixed.clone(), lower.clone()),
            (39, mixed.clone(), lower.clone()),
            // MX, and KX (RFC 2230) which has the same layout.
            (
                15,
                rdata(&[&preference, &mixed]),
                rdata(&[&preference, &lower]),
            ),
            (
                36,
                rdata(&[&preference, &mixed]),
                rdata(&[&preference, &lower]),
            ),
            // SOA: two names, then five 32-bit numbers.
            (
                6,
                rdata(&[&mixed, &wire("Admin.EXAMPLE."), &[0; 20]]),
                rdata(&[&lower, &canonical_name("admin.example."), &[0; 20]]),
            ),
            // SRV: priority, weight and port, then the target.
            (
                33,
                rdata(&[&[0, 1, 0, 2, 0, 80], &mixed]),
                rdata(&[&[0, 1, 0, 2, 0, 80], &lower]),
            ),
            // NXT (RFC 2535): the next name and a bitmap.
            (
                30,
                rdata(&[&mixed, &[0b0100_0000]]),
                rdata(&[&lower, &[0b0100_0000]]),
            ),
        ];
        for (rtype, given, expected) in cases {
            assert_eq!(canonical(rtype, given), expected, "type {rtype}");
        }
    }

    #[test]
    fn naptr_replacement_is_lowercased_but_its_strings_are_not() {
        // RFC 4034 §6.2 lists NAPTR; its flags, service and regexp are character strings, not names.
        let strings = b"\x01S\x07SIP+D2U\x05!^.*$";
        let given = rdata(&[&[0, 10, 0, 20], strings, &wire("_SIP._UDP.Example.")]);
        let expected = rdata(&[
            &[0, 10, 0, 20],
            strings,
            &canonical_name("_sip._udp.example."),
        ]);
        assert_eq!(canonical(35, given), expected);
    }

    #[test]
    fn the_next_name_of_an_nsec_keeps_its_case() {
        // RFC 6840 §5.1: RFC 4034 §6.2 listed NSEC, but signers never lowercased it.
        let given = rdata(&[&wire("Next.EXAMPLE."), &[0, 1, 0b0100_0000]]);
        assert_eq!(canonical(47, given.clone()), given);
    }

    #[test]
    fn the_signer_of_an_rrsig_is_lowercased() {
        // RFC 6840 §5.1: the signer's name of an RRSIG, when an `RRset` of RRSIG records is itself signed.
        let fixed = [0_u8; 18];
        let signature = [0xAB_u8; 8];
        let given = rdata(&[&fixed, &wire("Signer.EXAMPLE."), &signature]);
        let expected = rdata(&[&fixed, &canonical_name("signer.example."), &signature]);
        assert_eq!(canonical(46, given), expected);
    }

    #[test]
    fn hinfo_and_txt_have_no_names() {
        // RFC 6840 §5.1: HINFO is two character strings, so letters in them stay as they are.
        let hinfo = b"\x05INTEL\x05Linux".to_vec();
        assert_eq!(canonical(13, hinfo.clone()), hinfo);
        let txt = b"\x09Mail.COM.".to_vec();
        assert_eq!(canonical(16, txt.clone()), txt);
    }

    #[test]
    fn an_unknown_type_is_left_alone() {
        // RFC 3597 §4: no name of an unknown type is lowercased; RFC 6840 §5.11 has the signature cover it all the
        // same.
        let given = wire("Mail.EXAMPLE.");
        assert_eq!(canonical(65400, given.clone()), given);
    }

    #[test]
    fn the_records_are_sorted_after_their_names_are_lowercased() {
        // §6.3: the order is that of the canonical RDATA, `B.Example.` after `a.example.`.
        let set = rrset("WWW.Example.", 2, &[wire("B.Example."), wire("a.example.")]);
        assert_eq!(
            set.canonical_rdatas(),
            [canonical_name("a.example."), canonical_name("b.example.")]
        );
    }

    // RFC 4035 Appendix A, `ns1.example.` signed by the key of tag 38519: 2004-04-09 to 2004-05-09.
    const INCEPTION: u32 = 1_081_535_779;
    const EXPIRATION: u32 = 1_084_127_779;

    fn ns1_rrsig(algorithm: u8, key_tag: u16, expiration: u32) -> Rrsig<'static> {
        Rrsig {
            type_covered: 1,
            algorithm,
            labels: 2,
            original_ttl: 3600,
            expiration,
            inception: INCEPTION,
            key_tag,
            signer: "example.",
        }
    }

    fn zsk() -> RrSet<'static> {
        rrset("example.", 48, &[dnskey_rdata(256, 5, RFC4035_ZSK)])
    }

    #[test]
    fn s5_4_and_s5_12_one_valid_rrsig_is_enough_and_the_others_are_disregarded() {
        let a = rrset("ns1.example.", 1, &[vec![192, 0, 2, 1]]);
        let good = rrsig_set(
            "ns1.example.",
            &ns1_rrsig(5, 38519, EXPIRATION),
            RFC4035_NS1_SIGNATURE,
        );
        let others = [
            // §5.4: gibberish for a key we have, and a window that ended.
            rrsig_set(
                "ns1.example.",
                &ns1_rrsig(5, 38519, INCEPTION + 1),
                RFC4035_NS1_SIGNATURE,
            ),
            // §5.12: no DNSKEY of the tag, and an algorithm the DNSKEY RRset has none of.
            rrsig_set(
                "ns1.example.",
                &ns1_rrsig(5, 1, EXPIRATION),
                RFC4035_NS1_SIGNATURE,
            ),
            rrsig_set(
                "ns1.example.",
                &ns1_rrsig(200, 38519, EXPIRATION),
                RFC4035_NS1_SIGNATURE,
            ),
            rrsig_set(
                "ns1.example.",
                &ns1_rrsig(8, 38519, EXPIRATION),
                RFC4035_NS1_SIGNATURE,
            ),
        ];
        for other in &others {
            for sigs in [[&good, other], [other, &good]] {
                let sigs: Vec<Signature<'_>> =
                    sigs.iter().flat_map(|set| Signature::all(set)).collect();
                let result = rrsig::verify_any(
                    &a,
                    &sigs,
                    &Key::all(&zsk()),
                    INCEPTION + 100,
                    &mut Budget::default(),
                );
                assert!(result.is_ok(), "{result:?}");
            }
        }
    }

    #[test]
    fn s5_11_a_validator_accepts_any_single_valid_path_from_the_ds_records() {
        // A DS RRset that signals a digest we do not support beside one that we do: the supported one is the path.
        let key = dnskey_rdata(256, 5, RFC4035_ZSK);
        let ds = |digest_type: DigestType, digest: &[u8]| {
            let mut rdata = key_tag(&key).to_be_bytes().to_vec();
            rdata.extend([5, digest_type.0]);
            rdata.extend(digest);
            rdata
        };
        let sha256 = ds_digest(DigestType::SHA256, &name("example."), &key).expect("supported");
        let keys = zsk();
        let trust =
            |ds: &RrSet<'_>| rrsig::trusted_keys(&keys, &[], ds, INCEPTION, &mut Budget::default());
        let both = rrset(
            "example.",
            43,
            &[
                ds(DigestType::GOST, &[0; 32]),
                ds(DigestType::SHA256, sha256.as_ref()),
            ],
        );
        // The path is found; nothing signs the DNSKEY RRset here.
        assert_eq!(trust(&both), Err(SigError::NoSignature));
        let gost = rrset("example.", 43, &[ds(DigestType::GOST, &[0; 32])]);
        assert!(trust(&gost).unwrap_err().is_unsupported());
    }

    // Denial of existence (D74).

    const APEX: &str = "example.";
    const AAAA: RecordType = RecordType::AAAA;
    const CNAME: RecordType = RecordType::CNAME;
    const DNAME: RecordType = RecordType::DNAME;
    const MX: RecordType = RecordType::MX;
    const NS: RecordType = RecordType::NS;
    const NSEC: RecordType = RecordType::NSEC;
    const RRSIG: RecordType = RecordType::RRSIG;
    const SOA: RecordType = RecordType::SOA;

    fn nsecs(owners: &[&str]) -> Vec<Record<'static>> {
        pick(&zone("rfc4035_appendix_a.zone"), RecordType::NSEC, owners)
    }

    /// §4.1: `b.example.` is a delegation, so its NSEC is the parent's and proves no name below it.
    #[test]
    fn a_delegation_proves_nothing_below_it() {
        let records = nsecs(&["b.example.", "example."]);
        assert_eq!(
            prove(APEX, "mc.b.example.", RecordType::A, &records),
            Err(Unproven::NotCovered)
        );
        // Nor, but for DS, a type at its owner: the NS set may be the child's.
        assert_eq!(
            prove(APEX, "b.example.", MX, &records),
            Err(Unproven::AtDelegation)
        );
        assert_eq!(
            prove(APEX, "b.example.", RecordType::DS, &records),
            Ok(support_proof(Fact::InsecureDelegation))
        );
    }

    /// §4.1: the NSEC of the apex has NS as well, and is not a delegation: SOA is set.
    #[test]
    fn the_apex_is_not_a_delegation() {
        let records = nsecs(&["example.", "b.example."]);
        assert_eq!(
            prove(APEX, "ml.example.", RecordType::A, &records),
            Ok(support_proof(Fact::NameError { compact: false }))
        );
    }

    /// Derived: §4.1: an NSEC with DNAME proves no subdomain of its owner absent, the DNAME does not apply to its owner.
    #[test]
    fn a_dname_proves_nothing_below_it() {
        let dname = [
            nsec("d.example.", "ns1.example.", &[DNAME, RRSIG, NSEC]),
            nsec("example.", "a.example.", &[NS, SOA, MX, RRSIG, NSEC]),
        ];
        assert_eq!(
            prove(APEX, "x.d.example.", RecordType::A, &dname),
            Err(Unproven::NotCovered)
        );
        // At the owner, the DNAME is an ordinary type.
        assert_eq!(
            prove(APEX, "d.example.", AAAA, &dname),
            Ok(support_proof(Fact::NoData))
        );
        // A name next to it is not below it: the NSEC covers it.
        assert_eq!(
            prove(APEX, "e.example.", RecordType::A, &dname),
            Ok(support_proof(Fact::NameError { compact: false }))
        );
    }

    /// Derived: §4.3: a CNAME at the name answers any type, so an NSEC with CNAME proves no data of none.
    #[test]
    fn a_cname_is_not_no_data() {
        let records = [nsec("c.example.", "ns1.example.", &[CNAME, RRSIG, NSEC])];
        assert_eq!(
            prove(APEX, "c.example.", RecordType::A, &records),
            Err(Unproven::TypePresent)
        );
        // The type of the CNAME itself is no exception.
        assert_eq!(
            prove(APEX, "c.example.", CNAME, &records),
            Err(Unproven::TypePresent)
        );
    }

    /// Derived: §4.4: an insecure delegation shows NS and no DS and no SOA; a DS, or the SOA of the child, does not.
    #[test]
    fn insecure_delegation_needs_ns_without_ds_and_soa() {
        let ds = RecordType::DS;
        let cases = [
            (
                &[NS, RRSIG, NSEC][..],
                Ok(support_proof(Fact::InsecureDelegation)),
            ),
            (&[NS, ds, RRSIG, NSEC][..], Err(Unproven::TypePresent)),
            (&[NS, SOA, RRSIG, NSEC][..], Err(Unproven::FromChildApex)),
            // No NS: nothing delegates, and no DS is no data.
            (
                &[RecordType::A, RRSIG, NSEC][..],
                Ok(support_proof(Fact::NoData)),
            ),
        ];
        for (types, expected) in cases {
            let records = [nsec("b.example.", "ns1.example.", types)];
            assert_eq!(
                prove(APEX, "b.example.", ds, &records),
                expected,
                "{types:?}"
            );
        }
    }

    fn support_proof(fact: Fact) -> Proof {
        Proof {
            fact,
            ttl: Ttl::from_wire(3600),
            opt_out: false,
        }
    }
}

mod extended_errors {
    //! RFC 8914 §4: the Extended DNS Error of each way an `RRset` fails to authenticate (D73).

    use dedens_dnssec::crypto::BudgetExhausted;
    use dedens_dnssec::rrsig::SigError;
    use dedens_proto::edns::InfoCode;
    use dedens_proto::{DigestType, SecAlgorithm};

    use crate::util::rrset;

    #[test]
    fn each_error_has_the_code_of_its_cause_and_a_text_naming_the_rrset() {
        let set = rrset("www.example.net.", 1, &[vec![192, 0, 2, 1]]);
        let cases = [
            (SigError::NoSignature, InfoCode::RRSIGS_MISSING),
            (SigError::NoKey { key_tag: 4242 }, InfoCode::DNSKEY_MISSING),
            (SigError::NoKeyForDs, InfoCode::DNSKEY_MISSING),
            (
                SigError::RevokedKey { key_tag: 4242 },
                InfoCode::DNSKEY_MISSING,
            ),
            (
                SigError::NotZoneKey { key_tag: 4242 },
                InfoCode::NO_ZONE_KEY_BIT_SET,
            ),
            (
                SigError::UnsupportedAlgorithm {
                    algorithm: SecAlgorithm::ED448,
                },
                InfoCode::UNSUPPORTED_DNSKEY_ALGORITHM,
            ),
            (
                SigError::UnsupportedDigest {
                    digest: DigestType::GOST,
                },
                InfoCode::UNSUPPORTED_DS_DIGEST_TYPE,
            ),
            (
                SigError::NotYetValid {
                    key_tag: 4242,
                    inception: 7,
                },
                InfoCode::SIGNATURE_NOT_YET_VALID,
            ),
            (
                SigError::Expired {
                    key_tag: 4242,
                    expiration: 7,
                },
                InfoCode::SIGNATURE_EXPIRED,
            ),
            (
                SigError::ExpiredBeforeValid { key_tag: 4242 },
                InfoCode::SIGNATURE_EXPIRED_BEFORE_VALID,
            ),
            (
                SigError::BadSignature { key_tag: 4242 },
                InfoCode::DNSSEC_BOGUS,
            ),
            (
                SigError::BadLabels {
                    labels: 4,
                    owner: 3,
                },
                InfoCode::DNSSEC_BOGUS,
            ),
            (SigError::BadSigner, InfoCode::DNSSEC_BOGUS),
            (SigError::TooManyFailures, InfoCode::DNSSEC_BOGUS),
            (
                SigError::BudgetExhausted(BudgetExhausted::Verifications),
                InfoCode::DNSSEC_BOGUS,
            ),
        ];
        for (error, code) in cases {
            let ede = error.ede(&set);
            assert_eq!(ede.code, code, "{error:?}");
            assert!(ede.text.starts_with("www.example.net. A: "), "{}", ede.text);
            assert!(ede.text.contains(&error.to_string()), "{}", ede.text);
            // The text of an error that comes from one key names the key tag.
            if format!("{error:?}").contains("key_tag") {
                assert!(ede.text.contains("4242"), "{}", ede.text);
            }
        }
    }

    #[test]
    fn only_an_unsupported_algorithm_or_digest_is_no_proof_of_forgery() {
        // RFC 6840 §5.2: such data is insecure, and any other failure is bogus.
        let unsupported = [
            SigError::UnsupportedAlgorithm {
                algorithm: SecAlgorithm::ED448,
            },
            SigError::UnsupportedDigest {
                digest: DigestType::GOST,
            },
        ];
        assert!(unsupported.iter().all(SigError::is_unsupported));
        for error in [
            SigError::NoSignature,
            SigError::NoKeyForDs,
            SigError::BadSignature { key_tag: 1 },
            SigError::TooManyFailures,
        ] {
            assert!(!error.is_unsupported(), "{error:?}");
        }
    }
}

mod captured {
    //! The signatures and DS records of the captured responses (`testdata/dnssec/README.md`) through
    //! `dedens_dnssec::rrsig`: every signed `RRset` verifies at `captured_at` with the keys of its signer, fails after
    //! its expiration and before its inception, and fails with one byte of its RDATA changed; every zone's DNSKEY
    //! `RRset` is vouched for by its DS records, or not, as the README says. The `RRsets` are grouped from each section
    //! by owner, class and type (RFC 2181 §5), so a wrong grouping fails their signatures.

    use dedens_dnssec::crypto::{self, Budget};
    use dedens_dnssec::rrsig::{self, Key, RrSet, SigError, Signature};
    use dedens_proto::{Message, RecordType};
    use dedens_testkit::dnssec::{captured_at, names, response};

    use crate::util::try_records;

    /// An `RRset` of a capture and the RRSIG `RRset` at its owner.
    struct Signed {
        capture: String,
        data: RrSet<'static>,
        sigs: RrSet<'static>,
    }

    impl Signed {
        /// The RRSIG records that cover the data.
        fn covering(&self) -> Vec<Signature<'_>> {
            Signature::all(&self.sigs)
                .into_iter()
                .filter(|sig| sig.rrsig().type_covered == self.data.rtype())
                .collect()
        }

        fn verify(&self, keys: &RrSet<'_>, data: &RrSet<'_>, now: u32) -> Result<(), SigError> {
            rrsig::verify_any(
                data,
                &self.covering(),
                &Key::all(keys),
                now,
                &mut Budget::default(),
            )
            .map(drop)
        }
    }

    /// The `RRsets` of the answer and authority sections that an RRSIG covers.
    fn signed(name: &str) -> Vec<Signed> {
        let message: Message<'static> = response(name);
        let sets: Vec<RrSet<'static>> = [&message.answer, &message.authority]
            .into_iter()
            .flat_map(|section| RrSet::group(section))
            .collect();
        let (rrsigs, data): (Vec<_>, Vec<_>) = sets
            .into_iter()
            .partition(|set| set.rtype() == RecordType::RRSIG);
        data.into_iter()
            .filter_map(|data| {
                let sigs = rrsigs.iter().find(|sigs| sigs.owner() == data.owner())?;
                let item = Signed {
                    capture: name.to_owned(),
                    data,
                    sigs: sigs.clone(),
                };
                (!item.covering().is_empty()).then_some(item)
            })
            .collect()
    }

    /// Every DNSKEY `RRset` of the captured chains.
    fn zone_keys() -> Vec<RrSet<'static>> {
        names()
            .iter()
            .filter(|name| name.ends_with("_dnskey") || *name == "root_dnskey")
            .flat_map(|name| {
                let message = response(name);
                RrSet::group(&message.answer)
                    .into_iter()
                    .filter(|set| set.rtype() == RecordType::DNSKEY)
                    .map(RrSet::into_owned)
                    .collect::<Vec<_>>()
            })
            .collect()
    }

    /// The DNSKEY `RRset` of the signer of `item`'s first covering RRSIG.
    fn keys_of<'a>(zones: &'a [RrSet<'static>], item: &Signed) -> &'a RrSet<'static> {
        let covering = item.covering();
        let signer = &covering.first().expect("covered").rrsig().signer;
        zones
            .iter()
            .find(|zone| zone.owner() == signer)
            .unwrap_or_else(|| unreachable!("{}: no captured DNSKEY of {signer}", item.capture))
    }

    /// The signed `RRsets` of every capture whose signer's DNSKEY `RRset` is captured (the DS of `rhybar.cz` is signed
    /// by `cz`, which is not).
    fn every_signed_set(zones: &[RrSet<'static>]) -> Vec<Signed> {
        names()
            .iter()
            .flat_map(|name| signed(name))
            .filter(|item| {
                let covering = item.covering();
                let signer = &covering.first().expect("covered").rrsig().signer;
                zones.iter().any(|zone| zone.owner() == signer)
            })
            .collect()
    }

    fn unsupported(item: &Signed) -> bool {
        item.covering()
            .iter()
            .all(|sig| !crypto::supported(sig.rrsig().algorithm))
    }

    #[test]
    fn every_signed_rrset_verifies_at_the_capture_time() {
        let zones = zone_keys();
        let now = captured_at();
        let mut verified = 0;
        for item in every_signed_set(&zones) {
            let result = item.verify(keys_of(&zones, &item), &item.data, now);
            let label = format!(
                "{} {} {}",
                item.capture,
                item.data.owner(),
                item.data.rtype()
            );
            match (item.capture.as_str(), item.data.rtype()) {
                // Ed448: `ring` has none (D71); the RRSIGs of an unsupported algorithm are disregarded, and the
                // zone is insecure by its DS (`a_ds_of_an_unsupported_algorithm_is_insecure_not_bogus`).
                ("alg16_a" | "ed448_nl_dnskey", _) => {
                    assert_eq!(result, Err(SigError::NoSignature), "{label}");
                }
                // The signatures of `rhybar.cz` ended in October 2025, the A of `sigexpired.bad-dnssec.wb.sidnlabs.nl` in
                // December 2019.
                (
                    "bogus_expired"
                    | "bogus_sigexpired"
                    | "sigexpired_wb_sidnlabs_nl_dnskey"
                    | "rhybar_cz_dnskey",
                    _,
                ) => assert!(
                    matches!(result, Err(SigError::Expired { .. })),
                    "{label}: {result:?}"
                ),
                // The A of `sigfail.verteiltesysteme.net`: a signature that does not verify.
                ("bogus_signature", RecordType::A) => assert!(
                    matches!(result, Err(SigError::BadSignature { .. })),
                    "{label}: {result:?}"
                ),
                _ => {
                    assert_eq!(result, Ok(()), "{label}");
                    verified += 1;
                }
            }
        }
        assert!(verified > 100, "{verified} RRsets verified");
    }

    #[test]
    fn every_signed_rrset_fails_one_second_after_its_expiration() {
        let zones = zone_keys();
        for item in every_signed_set(&zones)
            .iter()
            .filter(|item| !unsupported(item))
        {
            let last = item
                .covering()
                .iter()
                .map(|sig| sig.rrsig().expiration)
                .max()
                .expect("covered");
            let result = item.verify(keys_of(&zones, item), &item.data, last + 1);
            assert!(
                matches!(result, Err(SigError::Expired { .. })),
                "{} {}: {result:?}",
                item.capture,
                item.data.owner()
            );
        }
    }

    #[test]
    fn every_signed_rrset_fails_one_second_before_its_inception() {
        let zones = zone_keys();
        for item in every_signed_set(&zones)
            .iter()
            .filter(|item| !unsupported(item))
        {
            let first = item
                .covering()
                .iter()
                .map(|sig| sig.rrsig().inception)
                .min()
                .expect("covered");
            let result = item.verify(keys_of(&zones, item), &item.data, first - 1);
            assert!(
                matches!(result, Err(SigError::NotYetValid { .. })),
                "{} {}: {result:?}",
                item.capture,
                item.data.owner()
            );
        }
    }

    /// `set` with the last byte of its first RDATA that keeps the message decodable inverted in its lowest bit.
    fn mutated(set: &RrSet<'_>) -> Option<RrSet<'static>> {
        let rdatas: Vec<Vec<u8>> = set.rdatas().iter().map(|r| r.wire().into_owned()).collect();
        let len = rdatas.first()?.len();
        (0..len).rev().find_map(|at| {
            let mut changed = rdatas.clone();
            *changed.first_mut()?.get_mut(at)? ^= 1;
            let records = try_records(
                &set.owner().to_string(),
                set.rtype().0,
                set.ttl().get(),
                &changed,
            )?;
            RrSet::group(&records).pop()
        })
    }

    #[test]
    fn every_signed_rrset_fails_with_one_byte_changed() {
        let zones = zone_keys();
        let now = captured_at();
        let mut changed = 0;
        for item in every_signed_set(&zones) {
            let keys = keys_of(&zones, &item);
            if item.verify(keys, &item.data, now).is_err() {
                continue;
            }
            let other = mutated(&item.data).expect("a byte that keeps the RDATA decodable");
            assert_ne!(other.canonical_rdatas(), item.data.canonical_rdatas());
            let result = item.verify(keys, &other, now);
            let label = format!(
                "{} {} {}",
                item.capture,
                item.data.owner(),
                item.data.rtype()
            );
            if item.data.rtype() == RecordType::DNSKEY {
                // A changed key may also change its tag, so that no key is the signer's.
                assert!(result.is_err(), "{label}");
            } else {
                assert!(
                    matches!(result, Err(SigError::BadSignature { .. })),
                    "{label}: {result:?}"
                );
            }
            changed += 1;
        }
        assert!(changed > 100, "{changed} RRsets mutated");
    }

    #[test]
    fn a_wildcard_answer_names_its_closest_encloser() {
        let zones = zone_keys();
        let wildcard = signed("wildcard_answer")
            .into_iter()
            .find(|item| item.data.rtype() == RecordType::MX)
            .expect("an MX RRset");
        let verified = rrsig::verify_any(
            &wildcard.data,
            &wildcard.covering(),
            &Key::all(keys_of(&zones, &wildcard)),
            captured_at(),
            &mut Budget::default(),
        )
        .expect("verifies");
        let encloser = verified.wildcard.expect("expanded from a wildcard");
        assert_eq!(encloser.to_string(), "sidnlabs.nl.");
        assert!(wildcard.data.owner().is_within(&encloser));
        assert_ne!(wildcard.data.owner(), &encloser);
    }

    /// The expansions of the wildcards of `internet.nl` (NSEC), `ph` and `ws` (opt-out NSEC3) name their zone as the
    /// encloser, and `nist.gov`, which signs each name on demand, is no expansion.
    #[test]
    fn the_wildcards_of_other_zones_name_their_closest_encloser() {
        let zones = zone_keys();
        for (id, rtype, encloser) in [
            (
                "wildcard_answer_nsec",
                RecordType::TXT,
                Some("internet.nl."),
            ),
            ("wildcard_answer_optout", RecordType::A, Some("ph.")),
            ("wildcard_answer_optout_ws", RecordType::A, Some("ws.")),
            ("synthesized_nist_gov_txt", RecordType::TXT, None),
        ] {
            let item = signed(id)
                .into_iter()
                .find(|item| item.data.rtype() == rtype)
                .unwrap_or_else(|| panic!("{id}: no {rtype} RRset"));
            let verified = rrsig::verify_any(
                &item.data,
                &item.covering(),
                &Key::all(keys_of(&zones, &item)),
                captured_at(),
                &mut Budget::default(),
            )
            .unwrap_or_else(|e| panic!("{id}: {e:?}"));
            assert_eq!(
                verified.wildcard.map(|name| name.to_string()).as_deref(),
                encloser,
                "{id}"
            );
        }
    }

    /// The signed DNSKEY `RRset` of a zone and its DS `RRset` from the parent.
    fn zone(id: &str) -> (Signed, RrSet<'static>) {
        let dnskey = signed(&format!("{id}_dnskey"))
            .into_iter()
            .find(|item| item.data.rtype() == RecordType::DNSKEY)
            .expect("signed DNSKEY RRset");
        let ds = response(&format!("{id}_ds"));
        let ds = RrSet::group(&ds.answer)
            .into_iter()
            .find(|set| set.rtype() == RecordType::DS)
            .expect("DS RRset");
        (dnskey, ds)
    }

    /// Whether the DS `RRset` vouches for the zone's DNSKEY `RRset` at `now`.
    fn trusted(zone: &Signed, ds: &RrSet<'_>, now: u32) -> Result<(), SigError> {
        rrsig::trusted_keys(
            &zone.data,
            &zone.covering(),
            ds,
            now,
            &mut Budget::default(),
        )
        .map(drop)
    }

    const ZONES: &[&str] = &[
        "com",
        "net",
        "org",
        "nl",
        "cat",
        "la",
        "cr",
        "dev",
        "stream",
        "nlnetlabs_nl",
        "cloudflare_com",
        "sidnlabs_nl",
        "example_nl",
        "icann_org",
        "cloudflare_net",
        "ripe_net",
        "verteiltesysteme_net",
        "fedoraproject_org",
        "ed25519_nl",
        "debian_org",
        "rootcanary_net",
        "ippacket_stream",
        "rsa2048_ippacket_stream",
        "cz",
        "wb_sidnlabs_nl",
        "bad_dnssec_wb_sidnlabs_nl",
        "internet_nl",
        "nist_gov",
        "ph",
        "ws",
    ];

    #[test]
    fn every_dnskey_rrset_is_vouched_for_by_its_ds() {
        for id in ZONES {
            let (dnskey, ds) = zone(id);
            assert_eq!(trusted(&dnskey, &ds, captured_at()), Ok(()), "{id}");
        }
    }

    #[test]
    fn a_zone_whose_keys_signatures_expired_is_not_vouched_for() {
        // `sigexpired.bad-dnssec.wb.sidnlabs.nl`: the DS matches, the DNSKEY set's signature ended in December 2019.
        let (dnskey, ds) = zone("sigexpired_wb_sidnlabs_nl");
        let result = trusted(&dnskey, &ds, captured_at());
        assert!(
            matches!(result, Err(SigError::Expired { .. })),
            "{result:?}"
        );
    }

    #[test]
    fn a_ds_that_matches_no_key_is_bogus_not_insecure() {
        // `dnssec-failed.org` (13) and `rhybar.cz`: the DS names a key the zone does not have.
        for id in ["dnssec_failed_org", "rhybar_cz"] {
            let (dnskey, ds) = zone(id);
            let result = trusted(&dnskey, &ds, captured_at());
            assert_eq!(result, Err(SigError::NoKeyForDs), "{id}");
        }
    }

    #[test]
    fn a_ds_of_an_unsupported_algorithm_is_insecure_not_bogus() {
        // `ed448.nl`: Ed448 (D71); RFC 4035 §5.2, RFC 6840 §5.2.
        let (dnskey, ds) = zone("ed448_nl");
        let error = trusted(&dnskey, &ds, captured_at()).expect_err("not validated");
        assert!(error.is_unsupported(), "{error:?}");
    }

    #[test]
    fn a_changed_digest_is_no_match() {
        // `la` has a SHA-1 and a SHA-256 DS: with SHA-256 present, SHA-1 is ignored (RFC 4509 §3), so changing the
        // SHA-256 digest leaves no key, though the SHA-1 digest is right.
        let (dnskey, ds) = zone("la");
        let mut rdatas: Vec<Vec<u8>> = ds.rdatas().iter().map(|r| r.wire().into_owned()).collect();
        let digest_types: Vec<u8> = rdatas
            .iter()
            .map(|r| r.get(3).copied().unwrap_or(0))
            .collect();
        assert!(
            digest_types.contains(&1) && digest_types.contains(&2),
            "{digest_types:?}"
        );
        for rdata in &mut rdatas {
            if rdata.get(3) == Some(&2) {
                *rdata.last_mut().expect("digest") ^= 1;
            }
        }
        let changed = try_records(&ds.owner().to_string(), 43, 3600, &rdatas).expect("decodes");
        let changed = RrSet::group(&changed).pop().expect("one RRset");
        assert_eq!(
            trusted(&dnskey, &changed, captured_at()),
            Err(SigError::NoKeyForDs)
        );
    }
}
