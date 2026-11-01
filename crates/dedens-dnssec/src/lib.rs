//! DNSSEC validation, sans-IO: what a validator does with the records it is given (RFC 4033, 4034, 4035).
//! [`crypto`] (D71) is the cryptography on `ring`, [`anchor`] (D72) the trust anchors the chain of trust starts
//! from; the validator comes with the steps of `plan/4-dnssec-experimental`.

#![forbid(unsafe_code)]
#![warn(missing_docs, clippy::missing_errors_doc, clippy::missing_panics_doc)]

pub mod anchor;
pub mod crypto;
