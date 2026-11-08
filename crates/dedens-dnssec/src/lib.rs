//! DNSSEC validation, sans-IO: what a validator does with the records it is given (RFC 4033, 4034, 4035).
//! [`crypto`] (D71) is the cryptography on `ring`, [`anchor`] (D72) the trust anchors the chain of trust starts
//! from; [`validator`] (D75) judges a response.

#![forbid(unsafe_code)]

pub mod anchor;
pub mod crypto;
pub mod denial;
pub mod rrsig;
pub mod validator;
