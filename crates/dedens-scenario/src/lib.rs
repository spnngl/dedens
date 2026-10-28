//! Query files: queries, their options and expected results, read from JSON or YAML (D17, D34), and the report of
//! each response that `dedens --json` prints (D35).
//!
//! Shared by the `dedens` CLI and the server's tests.
//!
//! ```
//! use dedens_scenario::{Format, QueryFile};
//!
//! let file = QueryFile::parse(
//!     "queries:\n  - name: example.com\n    type: A\n    expect: {rcode: NOERROR, flags: [qr]}\n",
//!     Format::Yaml,
//! )?;
//! assert_eq!(file.queries[0].id(), "example.com_A");
//! # Ok::<(), dedens_scenario::ParseError>(())
//! ```

#![forbid(unsafe_code)]
#![warn(
    missing_docs,
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    clippy::print_stdout,
    clippy::print_stderr
)]

mod expect;
mod file;
mod options;
mod report;

pub use expect::{Expect, Expected};
pub use file::{Format, ParseError, Query, QueryFile, default_id};
pub use options::{CookieOption, InvalidOption, Options, Timeout};
pub use report::{
    EdnsReport, ExchangeReport, HeaderReport, OptionReport, QuestionReport, RecordReport, Report,
    Transport,
};

/// Reads a field from its text with [`FromStr`](std::str::FromStr), for types of other crates.
fn parsed<'de, D, T>(deserializer: D) -> Result<T, D::Error>
where
    D: serde::Deserializer<'de>,
    T: std::str::FromStr<Err: std::fmt::Display>,
{
    let text = <String as serde::Deserialize>::deserialize(deserializer)?;
    text.parse().map_err(serde::de::Error::custom)
}

/// [`parsed`] for an optional field, which also needs `#[serde(default)]`.
fn parsed_some<'de, D, T>(deserializer: D) -> Result<Option<T>, D::Error>
where
    D: serde::Deserializer<'de>,
    T: std::str::FromStr<Err: std::fmt::Display>,
{
    parsed(deserializer).map(Some)
}

/// Lowercase hex digits of `bytes`.
fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    bytes.iter().fold(String::new(), |mut out, b| {
        let _ = write!(out, "{b:02x}");
        out
    })
}
