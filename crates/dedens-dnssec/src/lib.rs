//! DNSSEC validation, sans-IO: what a validator does with the records it is given (RFC 4033, 4034, 4035).
//! Signature checks (D71) and trust anchors (D72) come with the steps of `plan/4-dnssec-experimental`.

#![forbid(unsafe_code)]
