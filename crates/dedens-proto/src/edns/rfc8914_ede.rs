//! Extended DNS Error option (RFC 8914).

use std::borrow::Cow;

use crate::codes::code_type;
use crate::error::{DecodeError, DecodeErrorKind, EncodeError};
use crate::wire::{Reader, Writer};

code_type! {
    /// Extended DNS Error INFO-CODE (RFC 8914 §4, IANA registry).
    InfoCode(u16), "EDE";
    /// Other error (RFC 8914 §4.1).
    OTHER = 0, "Other Error";
    /// Unsupported DNSKEY algorithm.
    UNSUPPORTED_DNSKEY_ALGORITHM = 1, "Unsupported DNSKEY Algorithm";
    /// Unsupported DS digest type.
    UNSUPPORTED_DS_DIGEST_TYPE = 2, "Unsupported DS Digest Type";
    /// Stale answer.
    STALE_ANSWER = 3, "Stale Answer";
    /// Forged answer.
    FORGED_ANSWER = 4, "Forged Answer";
    /// DNSSEC indeterminate.
    DNSSEC_INDETERMINATE = 5, "DNSSEC Indeterminate";
    /// DNSSEC bogus.
    DNSSEC_BOGUS = 6, "DNSSEC Bogus";
    /// Signature expired.
    SIGNATURE_EXPIRED = 7, "Signature Expired";
    /// Signature not yet valid.
    SIGNATURE_NOT_YET_VALID = 8, "Signature Not Yet Valid";
    /// DNSKEY missing.
    DNSKEY_MISSING = 9, "DNSKEY Missing";
    /// RRSIGs missing.
    RRSIGS_MISSING = 10, "RRSIGs Missing";
    /// No zone key bit set.
    NO_ZONE_KEY_BIT_SET = 11, "No Zone Key Bit Set";
    /// NSEC missing.
    NSEC_MISSING = 12, "NSEC Missing";
    /// Cached error.
    CACHED_ERROR = 13, "Cached Error";
    /// Not ready.
    NOT_READY = 14, "Not Ready";
    /// Blocked.
    BLOCKED = 15, "Blocked";
    /// Censored.
    CENSORED = 16, "Censored";
    /// Filtered.
    FILTERED = 17, "Filtered";
    /// Prohibited.
    PROHIBITED = 18, "Prohibited";
    /// Stale NXDOMAIN answer.
    STALE_NXDOMAIN_ANSWER = 19, "Stale NXDOMAIN Answer";
    /// Not authoritative.
    NOT_AUTHORITATIVE = 20, "Not Authoritative";
    /// Not supported.
    NOT_SUPPORTED = 21, "Not Supported";
    /// No reachable authority.
    NO_REACHABLE_AUTHORITY = 22, "No Reachable Authority";
    /// Network error.
    NETWORK_ERROR = 23, "Network Error";
    /// Invalid data.
    INVALID_DATA = 24, "Invalid Data";
    /// Signature expired before valid (IANA registry).
    SIGNATURE_EXPIRED_BEFORE_VALID = 25, "Signature Expired before Valid";
    /// Too early: 0-RTT data refused (RFC 9250 §4.5).
    TOO_EARLY = 26, "Too Early";
    /// Unsupported NSEC3 iterations value (RFC 9276 §3.2).
    UNSUPPORTED_NSEC3_ITERATIONS = 27, "Unsupported NSEC3 Iterations Value";
    /// Invalid query type: a query for a type a resolver refuses, such as NXNAME (RFC 9824 §3.5, §9).
    INVALID_QUERY_TYPE = 30, "Invalid Query Type";
}

/// Why a query failed or what was done to its answer, with optional human-readable text (RFC 8914 §2).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ExtendedError<'a> {
    /// What happened.
    pub code: InfoCode,
    /// Free text for humans, possibly empty; always UTF-8 (RFC 8914 §2).
    pub text: Cow<'a, str>,
}

impl<'a> ExtendedError<'a> {
    /// The same error, owning its text.
    #[must_use]
    pub fn into_owned(self) -> ExtendedError<'static> {
        ExtendedError {
            code: self.code,
            text: Cow::Owned(self.text.into_owned()),
        }
    }

    pub(super) fn decode(r: &mut Reader<'a>) -> Result<Self, DecodeError> {
        let code = InfoCode(r.u16()?);
        let text = str::from_utf8(r.rest())
            .map_err(|_| r.error(DecodeErrorKind::Invalid("EXTRA-TEXT is not UTF-8")))?;
        Ok(Self {
            code,
            text: Cow::Borrowed(text),
        })
    }

    pub(super) fn encode(&self, w: &mut Writer<'_>) -> Result<(), EncodeError> {
        w.put_u16(self.code.0)?;
        w.put_bytes(self.text.as_bytes())
    }
}
