//! The query file (D17, D34): a server and options for all, then the queries, each with its own.

use std::path::Path;
use std::str::FromStr;

use dedens_proto::{Name, RecordType};
use serde::Deserialize;

use crate::{Expect, Options};

/// A query file.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct QueryFile {
    /// The server of the queries without their own: an address, with or without a port, or a host name.
    pub server: Option<String>,
    /// The options of every query, under its own.
    #[serde(default)]
    pub options: Options,
    /// The queries, in order.
    pub queries: Vec<Query>,
}

/// One query of a [`QueryFile`].
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Query {
    /// Its name in reports and the `--save-wire` file name; see [`Query::id`].
    pub id: Option<String>,
    /// The name asked; absolute, with or without its final dot.
    #[serde(deserialize_with = "crate::parsed")]
    pub name: Name<'static>,
    /// The type asked.
    #[serde(rename = "type", deserialize_with = "crate::parsed")]
    pub qtype: RecordType,
    /// Its server, over the file's.
    pub server: Option<String>,
    /// Its options, over the file's.
    #[serde(default)]
    pub options: Options,
    /// What its response must hold.
    pub expect: Option<Expect>,
}

impl Query {
    /// Its `id`, else [`default_id`].
    #[must_use]
    pub fn id(&self) -> String {
        self.id
            .clone()
            .unwrap_or_else(|| default_id(&self.name, self.qtype))
    }
}

/// The name without its final dot (`.` for the root) and the type, joined by `_`: `example.com_A`.
#[must_use]
pub fn default_id(name: &Name<'_>, qtype: RecordType) -> String {
    let name = name.to_string();
    let name = name
        .strip_suffix('.')
        .filter(|n| !n.is_empty())
        .unwrap_or(&name);
    format!("{name}_{qtype}")
}

/// The format of a query file.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Format {
    /// JSON (RFC 8259).
    Json,
    /// YAML 1.2.
    Yaml,
}

impl Format {
    /// The format of a file by its extension: `.json`, `.yaml` or `.yml`.
    #[must_use]
    pub fn of(path: &Path) -> Option<Self> {
        match path.extension()?.to_str()? {
            "json" => Some(Self::Json),
            "yaml" | "yml" => Some(Self::Yaml),
            _ => None,
        }
    }
}

impl FromStr for Format {
    type Err = ParseError;

    fn from_str(text: &str) -> Result<Self, ParseError> {
        match text {
            "json" => Ok(Self::Json),
            "yaml" => Ok(Self::Yaml),
            _ => Err(ParseError::Format),
        }
    }
}

/// Why a query file does not read.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum ParseError {
    /// Not a format of [`Format`].
    #[error("the format is json or yaml")]
    Format,
    /// Invalid JSON, or not a query file.
    #[error(transparent)]
    Json(#[from] serde_json::Error),
    /// Invalid YAML, or not a query file.
    #[error(transparent)]
    Yaml(#[from] serde_saphyr::Error),
}

impl QueryFile {
    /// Reads a query file.
    ///
    /// # Errors
    ///
    /// [`ParseError`] when the text is not a query file in `format`: invalid syntax, a missing or unknown
    /// field, or a value that does not read.
    pub fn parse(text: &str, format: Format) -> Result<Self, ParseError> {
        Ok(match format {
            Format::Json => serde_json::from_str(text)?,
            Format::Yaml => serde_saphyr::from_str(text)?,
        })
    }
}
