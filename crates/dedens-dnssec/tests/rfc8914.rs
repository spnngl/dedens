//! RFC 8914 §4: the Extended DNS Error of each way an `RRset` fails to authenticate (D73).

mod common;

use common::rrset;
use dedens_dnssec::crypto::BudgetExhausted;
use dedens_dnssec::rrsig::SigError;
use dedens_proto::edns::InfoCode;
use dedens_proto::{DigestType, SecAlgorithm};

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
