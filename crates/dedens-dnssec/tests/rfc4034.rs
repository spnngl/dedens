//! RFC 4034: key tags (Appendix B), the SHA-1 DS digest (§5.1.4, §5.4), canonical owner names (§6.2), and the
//! RSASHA1 (5, 7) signatures of RFC 4035 Appendix A, the signed zone `example.`, whose keys are 1024 bits.

mod common;

use common::{DSKEY, check, name, rrset, rrsig_set};
use dedens_dnssec::crypto::{
    Budget, VerifyError, ds_digest, key_tag, supported, supported_digest, verify,
};
use dedens_dnssec::rrsig::{self, Key, MAX_FAILED, RrSet, SigError, Signature};
use dedens_proto::{DigestType, MAX_LABEL_LEN, SecAlgorithm};
use dedens_testkit::dnssec::{
    RFC4035_NS1_SIGNATURE, RFC4035_ZSK, Rr, Rrsig, b64, canonical_name, dnskey_rdata, signed_data,
};
use dedens_testkit::hex;

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
