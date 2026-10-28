//! Query files: queries, their options and expected results, read from YAML 1.2, and so from JSON too (D34, D36),
//! and the report of each response that `dedens --json` and `--yaml` print (D37).
//!
//! Shared by the `dedens` CLI and the server's tests. The `clap` feature makes [`Options`] command-line flags.
//!
//! ```
//! use dedens_scenario::QueryFile;
//!
//! let file = QueryFile::parse(
//!     "queries:\n  - name: example.com\n    type: A\n    expect: {rcode: NOERROR, flags: [qr]}\n",
//! )?;
//! assert_eq!(file.queries[0].id().as_str(), "example.com_A");
//! # Ok::<(), serde_saphyr::Error>(())
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
pub use file::{Id, InvalidId, Query, QueryFile, server_text};
pub use options::{CookieOption, InvalidOption, Options, Timeout};
pub use report::{
    EdnsReport, ExchangeReport, HeaderReport, Latency, OptionReport, QuestionReport, RecordReport,
    Report, Transport,
};

/// A YAML scalar, which a field reads as text with its [`FromStr`](std::str::FromStr).
#[derive(serde::Deserialize)]
#[serde(untagged)]
enum Scalar {
    Bool(bool),
    Number(u64),
    Text(String),
}

/// Reads a field from its text with [`FromStr`](std::str::FromStr), for types of other crates and scalars that
/// YAML reads as booleans or numbers.
fn parsed<'de, D, T>(deserializer: D) -> Result<T, D::Error>
where
    D: serde::Deserializer<'de>,
    T: std::str::FromStr<Err: std::fmt::Display>,
{
    let text = match <Scalar as serde::Deserialize>::deserialize(deserializer)? {
        Scalar::Bool(b) => b.to_string(),
        Scalar::Number(n) => n.to_string(),
        Scalar::Text(text) => text,
    };
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
