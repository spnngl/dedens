//! Why an `RRset` is not authenticated, and the Extended DNS Error that tells it (RFC 8914 §4).

use dedens_proto::edns::{ExtendedError, InfoCode};
use dedens_proto::{DigestType, SecAlgorithm};

use super::RrSet;
use crate::crypto::BudgetExhausted;

/// Why an `RRset` is not authenticated by a signature or a DS record.
///
/// [`SigError::is_unsupported`] tells the cases that are no proof of forgery: the DS records of a zone name
/// nothing the validator supports, so the zone is insecure, not bogus (RFC 4035 §5.2, RFC 6840 §5.2). Only
/// [`trusted_keys`](super::trusted_keys) gives them: an RRSIG of an unsupported algorithm is disregarded by
/// [`verify_any`](super::verify_any) (RFC 6840 §5.12), or the downgrade of a signed zone would be one forged
/// RRSIG away.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum SigError {
    /// No RRSIG covers the `RRset` (RFC 4035 §5.3.1).
    #[error("no RRSIG covers it")]
    NoSignature,
    /// No DNSKEY has the signer, algorithm and key tag of an RRSIG, or the one that has cannot be used by any
    /// signature (D71) (RFC 4035 §5.3.1).
    #[error("no DNSKEY of key tag {key_tag}")]
    NoKey {
        /// The key tag the RRSIG names.
        key_tag: u16,
    },
    /// No DNSKEY is the one a supported DS record digests (RFC 4035 §5.2).
    #[error("no DNSKEY matches a DS record")]
    NoKeyForDs,
    /// The labels field of the RRSIG is more than the owner has labels (RFC 4035 §5.3.1), or less than the
    /// signer has (the expansion would be of a wildcard above the signer's zone).
    #[error(
        "RRSIG labels field {labels} does not fit the {owner} labels of the owner and the signer"
    )]
    BadLabels {
        /// The labels field.
        labels: u8,
        /// The labels of the owner, without a leading `*`.
        owner: usize,
    },
    /// The signer is not the owner or one of its parents (RFC 4035 §5.3.1), is the owner of a DS (which belongs
    /// to the parent zone, RFC 4035 §2.4) or is not the owner of a DNSKEY (RFC 4035 §5.2).
    #[error("RRSIG signer cannot sign the RRset")]
    BadSigner,
    /// The DNSKEY has the REVOKE bit (RFC 5011 §7).
    #[error("DNSKEY {key_tag} is revoked")]
    RevokedKey {
        /// The key tag.
        key_tag: u16,
    },
    /// The DNSKEY lacks the zone key bit (RFC 4035 §5.3.1).
    #[error("DNSKEY {key_tag} has no zone key bit")]
    NotZoneKey {
        /// The key tag.
        key_tag: u16,
    },
    /// The algorithm of a DS record, or of a signature checked alone with [`verify`](super::verify()), is not
    /// validated (RFC 9904 §3), so the data is unsigned for it (RFC 6840 §5.2).
    #[error("algorithm {algorithm} is not supported")]
    UnsupportedAlgorithm {
        /// The algorithm.
        algorithm: SecAlgorithm,
    },
    /// The digest type of every DS record that could vouch for the key is not supported (RFC 6840 §5.2).
    #[error("DS digest type {digest} is not supported")]
    UnsupportedDigest {
        /// The digest type.
        digest: DigestType,
    },
    /// The signature starts later than now (RFC 4034 §3.1.5).
    #[error("RRSIG of key tag {key_tag} is valid from {inception}")]
    NotYetValid {
        /// The key tag.
        key_tag: u16,
        /// The inception time.
        inception: u32,
    },
    /// The signature ended before now (RFC 4034 §3.1.5).
    #[error("RRSIG of key tag {key_tag} expired at {expiration}")]
    Expired {
        /// The key tag.
        key_tag: u16,
        /// The expiration time.
        expiration: u32,
    },
    /// The signature ends before it starts.
    #[error("RRSIG of key tag {key_tag} expires before it is valid")]
    ExpiredBeforeValid {
        /// The key tag.
        key_tag: u16,
    },
    /// The signature does not verify, or the key is not one the algorithm accepts: `ring` does not tell them
    /// apart in every case (D71).
    #[error("signature of key tag {key_tag} does not verify")]
    BadSignature {
        /// The key tag.
        key_tag: u16,
    },
    /// The validation spent its whole [`Budget`](crate::crypto::Budget) (D73).
    #[error(transparent)]
    BudgetExhausted(#[from] BudgetExhausted),
    /// More checks of this `RRset` failed than [`MAX_FAILED`](super::MAX_FAILED) (D73).
    #[error("gave up after {} failed signature checks", super::MAX_FAILED)]
    TooManyFailures,
}

impl SigError {
    /// Whether the zone counts as unsigned, so insecure, not bogus (RFC 6840 §5.2): what `trusted_keys` says of
    /// DS records that name nothing supported. Not a verdict of `verify_any`, which never gives it (D73).
    #[must_use]
    pub const fn is_unsupported(&self) -> bool {
        matches!(
            self,
            Self::UnsupportedAlgorithm { .. } | Self::UnsupportedDigest { .. }
        )
    }

    /// The Extended DNS Error for `rrset`: the code of RFC 8914 §4 and a text naming the `RRset` and the key tag.
    #[must_use]
    pub fn ede(&self, rrset: &RrSet<'_>) -> ExtendedError<'static> {
        let code = match self {
            Self::NoSignature => InfoCode::RRSIGS_MISSING,
            Self::NoKey { .. } | Self::NoKeyForDs | Self::RevokedKey { .. } => {
                InfoCode::DNSKEY_MISSING
            }
            Self::NotZoneKey { .. } => InfoCode::NO_ZONE_KEY_BIT_SET,
            Self::UnsupportedAlgorithm { .. } => InfoCode::UNSUPPORTED_DNSKEY_ALGORITHM,
            Self::UnsupportedDigest { .. } => InfoCode::UNSUPPORTED_DS_DIGEST_TYPE,
            Self::NotYetValid { .. } => InfoCode::SIGNATURE_NOT_YET_VALID,
            Self::Expired { .. } => InfoCode::SIGNATURE_EXPIRED,
            Self::ExpiredBeforeValid { .. } => InfoCode::SIGNATURE_EXPIRED_BEFORE_VALID,
            Self::BadLabels { .. }
            | Self::BadSigner
            | Self::BadSignature { .. }
            | Self::BudgetExhausted(_)
            | Self::TooManyFailures => InfoCode::DNSSEC_BOGUS,
        };
        ExtendedError {
            code,
            text: format!("{} {}: {self}", rrset.owner(), rrset.rtype()).into(),
        }
    }

    /// How close to success the check got: the error `verify_any` returns is the highest of its attempts.
    pub(super) const fn rank(&self) -> u8 {
        match self {
            Self::NoSignature => 0,
            Self::UnsupportedAlgorithm { .. } | Self::UnsupportedDigest { .. } => 1,
            Self::NoKey { .. } | Self::NoKeyForDs => 2,
            Self::BadLabels { .. }
            | Self::BadSigner
            | Self::RevokedKey { .. }
            | Self::NotZoneKey { .. } => 3,
            Self::NotYetValid { .. } | Self::Expired { .. } | Self::ExpiredBeforeValid { .. } => 4,
            Self::BadSignature { .. } => 5,
            Self::BudgetExhausted(_) | Self::TooManyFailures => 6,
        }
    }
}
