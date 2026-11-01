//! Signatures over `RRsets` and the DS records that vouch for a zone's keys (RFC 4034 §3, §6; RFC 4035 §5.2,
//! §5.3; D73). One `RRset` against its RRSIGs and DNSKEYs: walking the chain from the trust anchor is the
//! validator's, and so is the denial of existence.

mod canonical;
mod error;
mod rrset;
mod trust;
mod verify;

pub use error::SigError;
pub use rrset::{Key, RrSet, Signature};
pub use trust::trusted_keys;
pub use verify::{MAX_FAILED, Verified, verify, verify_any};
