//! What a validation ends in (RFC 4035 §4.3, RFC 4033 §5).

use dedens_proto::Ttl;
use dedens_proto::edns::{ExtendedError, InfoCode};

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
}

impl InsecureReason {
    /// The extended error to attach to an insecure answer, when the reason has one (RFC 8914 §4).
    #[must_use]
    pub const fn info_code(self) -> Option<InfoCode> {
        match self {
            Self::UnsupportedAlgorithm => Some(InfoCode::UNSUPPORTED_DNSKEY_ALGORITHM),
            Self::UnsupportedDigest => Some(InfoCode::UNSUPPORTED_DS_DIGEST_TYPE),
            Self::Nsec3Iterations => Some(InfoCode::UNSUPPORTED_NSEC3_ITERATIONS),
            Self::NoAnchor | Self::NegativeAnchor | Self::UnsignedDelegation | Self::OptOut => None,
        }
    }
}

/// The outcome of a validation: what the caller does with the response (RFC 4035 §4.3, RFC 4033 §5).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Verdict {
    /// Every `RRset` and denial of the response is authenticated: the answer may carry AD (RFC 4035 §3.2.3).
    Secure {
        /// How long the authenticated data may be kept: the least TTL of what was verified, of the keys it was
        /// verified with, and at most three hours for a denial (RFC 9077 §3.4).
        ttl: Ttl,
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
            Self::Secure { .. } => None,
            Self::Insecure { reason } => reason.info_code().map(|code| ede(code, "")),
            Self::Bogus { ede } | Self::Indeterminate { ede } => Some(ede.clone()),
        }
    }

    /// The order in which results of one response win: a failure over an unknown over an insecure part over a
    /// secure one.
    const fn rank(&self) -> u8 {
        match self {
            Self::Secure { .. } => 0,
            Self::Insecure { .. } => 1,
            Self::Indeterminate { .. } => 2,
            Self::Bogus { .. } => 3,
        }
    }

    /// The result of two parts of one response: the worse of them, the first when equal; two secure parts keep
    /// the lower TTL.
    pub(super) fn worse(self, other: Self) -> Self {
        match (&self, &other) {
            (Self::Secure { ttl: a }, Self::Secure { ttl: b }) => Self::Secure { ttl: *a.min(b) },
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
    Bogus(ExtendedError<'static>),
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
        #[expect(
            dead_code,
            reason = "the key cache of 06b keeps an insecure zone for this long"
        )]
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
