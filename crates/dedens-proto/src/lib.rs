//! DNS wire format (RFC 1035 and its updates): messages, names and records, encoded and decoded without I/O.
//!
//! Every item cites the RFC section it implements; `docs/rfc/coverage.md` maps each RFC to its code and tests.

#![forbid(unsafe_code)]
#![warn(
    missing_docs,
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    clippy::print_stdout,
    clippy::print_stderr
)]
