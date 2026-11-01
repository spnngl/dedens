//! DNSSEC validation, sans-IO: what a validator does with the records it is given (RFC 4033, 4034, 4035).
//! [`crypto`] (D71) is the cryptography on `ring`; trust anchors (D72) and the validator come with the steps of
//! `plan/4-dnssec-experimental`.

#![forbid(unsafe_code)]
#![warn(missing_docs, clippy::missing_errors_doc, clippy::missing_panics_doc)]

pub mod crypto;
