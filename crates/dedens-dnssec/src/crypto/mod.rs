//! Every cryptographic operation DNSSEC validation needs, on `ring` (D71), behind a ring-free API: signature
//! checks, DS digests, key tags, NSEC3 hashes and the work [`Budget`].
//!
//! The functions take wire bytes and the codes of `dedens-proto`; none reads the clock or a message. Which
//! algorithms count as validated is D71's policy (RFC 9904 §3, RFC 9905), kept in [`supported`] and
//! [`supported_digest`]; an unsupported one makes the zone insecure (RFC 6840 §5.2), never bogus.

mod budget;
mod digest;
mod key_tag;
mod verify;

pub use budget::{Budget, BudgetExhausted, Nsec3Hashes, Verifications};
pub use digest::{
    Digest, UnsupportedDigest, UnsupportedNsec3Hash, ds_digest, nsec3_hash, supported_digest,
};
pub use key_tag::key_tag;
pub use verify::{VerifyError, supported, verify};
