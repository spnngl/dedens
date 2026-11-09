//! What a validation ends in (RFC 4035 §4.3, RFC 4033 §5).

use core::fmt;

use dedens_proto::edns::{ExtendedError, InfoCode};
use dedens_proto::{Name, Ttl};

/// Why data is insecure: not covered by a chain of trust, which is not a failure (RFC 4033 §5).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum InsecureReason {
    /// No trust anchor at or above the name (RFC 4033 §5).
    NoAnchor,
    /// A negative trust anchor covers the name (RFC 7646 §2).
    NegativeAnchor,
    /// A delegation without DS, proven by an NSEC or NSEC3 record of the name: the zone below is unsigned
    /// (RFC 4035 §5.2).
    UnsignedDelegation,
    /// An NSEC3 record with the opt-out flag proves the absence: the name may exist unsigned (RFC 5155 §9.2).
    OptOut,
    /// The zone is signed with algorithms no DS record of the parent names a supported one of (RFC 6840 §5.2).
    UnsupportedAlgorithm,
    /// The parent's DS records are all of an unsupported digest type (RFC 6840 §5.2).
    UnsupportedDigest,
    /// The zone's NSEC3 records use more iterations than the limit (RFC 9276 §3.2).
    Nsec3Iterations,
    /// The question is of type RRSIG: RRSIG records are not signed, so nothing of the answer is verified (RFC 4035
    /// §2.2, D176).
    RrsigQuery,
}

impl fmt::Display for InsecureReason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::NoAnchor => "no trust anchor at or above the name",
            Self::NegativeAnchor => "a negative trust anchor covers the name",
            Self::UnsignedDelegation => "the delegation has no DS record",
            Self::OptOut => "the proof is an opt-out NSEC3 span, the name may be unsigned",
            Self::UnsupportedAlgorithm => "the zone is signed with an unsupported algorithm",
            Self::UnsupportedDigest => "the DS records are of an unsupported digest type",
            Self::Nsec3Iterations => "the NSEC3 records use too many iterations",
            Self::RrsigQuery => "RRSIG records are not signed",
        })
    }
}

impl InsecureReason {
    /// The extended error to attach to an insecure answer, when the reason has one (RFC 8914 §4).
    #[must_use]
    pub const fn info_code(self) -> Option<InfoCode> {
        match self {
            Self::UnsupportedAlgorithm => Some(InfoCode::UNSUPPORTED_DNSKEY_ALGORITHM),
            Self::UnsupportedDigest => Some(InfoCode::UNSUPPORTED_DS_DIGEST_TYPE),
            Self::Nsec3Iterations => Some(InfoCode::UNSUPPORTED_NSEC3_ITERATIONS),
            Self::NoAnchor
            | Self::NegativeAnchor
            | Self::UnsignedDelegation
            | Self::OptOut
            | Self::RrsigQuery => None,
        }
    }
}

/// What a referral says of the delegation it refers to (RFC 4035 §5.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Delegation {
    /// The parent has an authenticated DS record for the child, or the child holds a trust anchor: the child is
    /// signed.
    Signed,
    /// The child is not covered by a chain of trust, for `reason`.
    Unsigned {
        /// Why.
        reason: InsecureReason,
    },
}

/// The most names of a CNAME chain a caller chases for one query (D76, D77).
///
/// Past it the verdict is indeterminate: the chain is the upstream's, untrusted input, and a loop of CNAMEs
/// never ends otherwise, which is an error (RFC 1034 §3.6.2).
pub const MAX_CHASES: u8 = 8;

/// The outcome of a validation: what the caller does with the response (RFC 4035 §4.3, RFC 4033 §5).
///
/// What [`Verdict::Secure`] covers is [`covered()`](crate::covered) of the response, the one definition of it: the
/// `RRsets` on the name path of the answer and the denial of what the answer lacks, if any. The caller must not
/// present the rest as authenticated.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Verdict {
    /// What the response holds, as far as the above, is authenticated and complete for its question: the answer
    /// may carry AD (RFC 4035 §3.2.3).
    Secure {
        /// How long the authenticated data may be kept: the least TTL of what was verified, of the keys it was
        /// verified with, and at most three hours for a denial (RFC 9077 §3.4).
        ttl: Ttl,
    },
    /// What the response holds is authenticated, but the CNAME chain it follows ends before the type asked:
    /// ask for it at `next`. The answer is incomplete, so it never carries AD; the caller that chases the
    /// chain validates each response, bounds the number of links ([`MAX_CHASES`]) and does not
    /// use `next`, which the server chose, as 0x20 entropy.
    Incomplete {
        /// The name the chain leads to and the response does not answer.
        next: Name<'static>,
        /// As for [`Verdict::Secure`].
        ttl: Ttl,
    },
    /// The response is a referral (RFC 1034 §4.3.2) to `child`, judged by `Validator::start_referral`: what the
    /// parent says of the delegation. A referral is no answer: never AD, never kept as data.
    Referral {
        /// The zone referred to.
        child: Name<'static>,
        /// Whether the parent proves the child signed or not.
        delegation: Delegation,
    },
    /// Some of the response is not covered by a chain of trust and nothing in it fails: answer without AD.
    Insecure {
        /// Why.
        reason: InsecureReason,
    },
    /// Something fails that a secure zone must have right: answer SERVFAIL with the extended error (RFC 4035
    /// §5.5, RFC 8914).
    Bogus {
        /// The extended error to attach.
        ede: ExtendedError<'static>,
    },
    /// The caller could not answer a question or a limit stopped the validation, so nothing is known: answer
    /// SERVFAIL, but do not remember the zone as bogus (RFC 4033 §5).
    Indeterminate {
        /// The extended error to attach.
        ede: ExtendedError<'static>,
    },
}

impl Verdict {
    /// A bogus verdict with an extended error of `code` and `text`.
    pub(super) fn bogus(code: InfoCode, text: impl Into<String>) -> Self {
        Self::Bogus {
            ede: ede(code, text),
        }
    }

    /// An indeterminate verdict with an extended error of `code` and `text`.
    pub(super) fn indeterminate(code: InfoCode, text: impl Into<String>) -> Self {
        Self::Indeterminate {
            ede: ede(code, text),
        }
    }

    /// The extended error to attach to the answer, if any (RFC 8914).
    #[must_use]
    pub fn ede(&self) -> Option<ExtendedError<'static>> {
        match self {
            Self::Insecure { reason } => {
                reason.info_code().map(|code| ede(code, reason.to_string()))
            }
            Self::Referral {
                delegation: Delegation::Unsigned { reason },
                ..
            } => reason.info_code().map(|code| ede(code, reason.to_string())),
            Self::Secure { .. } | Self::Incomplete { .. } | Self::Referral { .. } => None,
            Self::Bogus { ede } | Self::Indeterminate { ede } => Some(ede.clone()),
        }
    }

    /// The order in which results of one response win: a failure over an unknown over an insecure part over a
    /// secure one.
    const fn rank(&self) -> u8 {
        match self {
            Self::Secure { .. } | Self::Referral { .. } => 0,
            Self::Incomplete { .. } => 1,
            Self::Insecure { .. } => 2,
            Self::Indeterminate { .. } => 3,
            Self::Bogus { .. } => 4,
        }
    }

    /// The result of two parts of one response: the worse of them, the first when equal; two secure parts keep
    /// the lower TTL.
    pub(super) fn worse(self, other: Self) -> Self {
        match (&self, &other) {
            (Self::Secure { ttl: a }, Self::Secure { ttl: b }) => Self::Secure { ttl: *a.min(b) },
            (Self::Incomplete { next, ttl: a }, Self::Secure { ttl: b })
            | (Self::Secure { ttl: b }, Self::Incomplete { next, ttl: a }) => Self::Incomplete {
                next: next.clone(),
                ttl: *a.min(b),
            },
            _ if other.rank() > self.rank() => other,
            _ => self,
        }
    }
}

/// An extended error of `code` and `text`.
pub(super) fn ede(code: InfoCode, text: impl Into<String>) -> ExtendedError<'static> {
    ExtendedError {
        code,
        text: text.into().into(),
    }
}

/// Why a zone, or a delegation, is unusable: the verdict of anything that depends on it.
#[derive(Debug, Clone)]
pub(super) enum Failure {
    /// The data fails: a signature, a DS or a proof that does not hold, the limit on failed checks (D73), a
    /// DNSKEY `RRset` that no key vouched for or that the answer lacks, or no parent to vouch for the zone. Never
    /// kept in the key cache: an answerer can cause it for a zone that is sound (D92).
    Bogus(ExtendedError<'static>),
    /// Nothing is known: the caller had no answer, or the budget ran out. Never kept anywhere.
    Indeterminate(ExtendedError<'static>),
}

impl Failure {
    pub(super) fn bogus(code: InfoCode, text: impl Into<String>) -> Self {
        Self::Bogus(ede(code, text))
    }

    pub(super) fn indeterminate(code: InfoCode, text: impl Into<String>) -> Self {
        Self::Indeterminate(ede(code, text))
    }
}

/// What keeps a zone's keys, or a name's delegation, from being used: the part of the chain that stops there.
#[derive(Debug, Clone)]
pub(super) enum Unusable {
    /// Insecure for `reason`, as far as `ttl` holds.
    Insecure {
        reason: InsecureReason,
        ttl: Ttl,
    },
    Failed(Failure),
}

impl From<Unusable> for Verdict {
    fn from(unusable: Unusable) -> Self {
        match unusable {
            Unusable::Insecure { reason, .. } => Self::Insecure { reason },
            Unusable::Failed(failure) => failure.into(),
        }
    }
}

impl From<Failure> for Verdict {
    fn from(failure: Failure) -> Self {
        match failure {
            Failure::Bogus(ede) => Self::Bogus { ede },
            Failure::Indeterminate(ede) => Self::Indeterminate { ede },
        }
    }
}
