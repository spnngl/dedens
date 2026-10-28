//! The query file (D34, D36): a server and options for all, then the queries, each with its own.

use std::fmt;
use std::str::FromStr;

use dedens_proto::{Name, RecordType};
use serde::{Deserialize, Serialize};

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
    /// The queries, in order, their [ids](Query::id) unique.
    #[serde(deserialize_with = "unique_ids")]
    pub queries: Vec<Query>,
}

impl QueryFile {
    /// Reads a query file, YAML 1.2, which JSON is too.
    ///
    /// # Errors
    ///
    /// When the text is not a query file: invalid syntax, a missing or unknown field, a value that does not read,
    /// or two queries with the same id.
    pub fn parse(text: &str) -> Result<Self, serde_saphyr::Error> {
        serde_saphyr::from_str(text)
    }
}

/// One query of a [`QueryFile`].
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Query {
    /// Its name in reports and the `--save-wire` file name; see [`Query::id`].
    pub id: Option<Id>,
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
    /// Its `id`, else [`Id::of`] its name and type.
    #[must_use]
    pub fn id(&self) -> Id {
        self.id
            .clone()
            .unwrap_or_else(|| Id::of(&self.name, self.qtype))
    }
}

/// The name of a query in reports, and of its `--save-wire` file: a file name, so not empty, not `.` or `..`,
/// and without `/`, `\` or NUL.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(try_from = "String")]
pub struct Id(String);

impl Id {
    /// The name asked without its final dot (`root` for the root) and the type, joined by `_`, each `/` or `\` of
    /// the name a `_`: `example.com_A`.
    #[must_use]
    pub fn of(name: &Name<'_>, qtype: RecordType) -> Self {
        let name = name.to_string().replace(['/', '\\'], "_");
        let name = match name.strip_suffix('.') {
            Some("") | None => "root",
            Some(name) => name,
        };
        Self(format!("{name}_{qtype}"))
    }

    /// The id as text.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for Id {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// Text that is not an [`Id`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("an id is a file name: not empty, not . or .., without / \\ or NUL")]
pub struct InvalidId;

impl TryFrom<String> for Id {
    type Error = InvalidId;

    fn try_from(text: String) -> Result<Self, InvalidId> {
        if matches!(text.as_str(), "" | "." | "..") || text.contains(['/', '\\', '\0']) {
            return Err(InvalidId);
        }
        Ok(Self(text))
    }
}

impl FromStr for Id {
    type Err = InvalidId;

    fn from_str(text: &str) -> Result<Self, InvalidId> {
        text.to_owned().try_into()
    }
}

/// Reads the queries, refusing two with the same id.
fn unique_ids<'de, D: serde::Deserializer<'de>>(deserializer: D) -> Result<Vec<Query>, D::Error> {
    let queries = Vec::<Query>::deserialize(deserializer)?;
    let mut ids = std::collections::HashSet::new();
    match queries
        .iter()
        .map(Query::id)
        .find(|id| !ids.insert(id.clone()))
    {
        Some(id) => Err(serde::de::Error::custom(format!(
            "two queries with id {id}"
        ))),
        None => Ok(queries),
    }
}
