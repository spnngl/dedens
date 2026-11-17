//! The `roots` settings (D128): where IANA's TLD list and the root's trust anchors are fetched from, or `off`.

use std::fmt;

use serde::de::value::MapAccessDeserializer;
use serde::de::{self, MapAccess, Visitor};
use serde::{Deserialize, Deserializer};

use super::sources::Url;

/// IANA's TLD list.
const TLDS: &str = "https://data.iana.org/TLD/v1/tlds.json";

/// IANA's root trust anchors, signed by the file at the same URL with `.p7s` for `.xml` (RFC 9718 §3).
const ANCHORS: &str = "https://data.iana.org/root-anchors/root-anchors.xml";

/// The `roots` settings, as written: `off`, or the URLs of the files, each IANA's unless set.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum RootsFile {
    /// The bundled copies only, nothing fetched.
    Off,
    /// Fresh copies fetched from these URLs.
    Fetched(RootUrls),
}

/// Where the root files are fetched from.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct RootUrls {
    #[serde(default = "tlds")]
    tlds: Url,
    #[serde(default = "anchors")]
    anchors: Url,
}

impl<'de> Deserialize<'de> for RootsFile {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        deserializer.deserialize_any(RootsVisitor)
    }
}

/// `roots` as YAML gives it: `off` may read as a boolean, the URLs as a mapping read with its own errors.
struct RootsVisitor;

impl<'de> Visitor<'de> for RootsVisitor {
    type Value = RootsFile;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("`off` or a mapping of `tlds` and `anchors`")
    }

    fn visit_bool<E: de::Error>(self, on: bool) -> Result<RootsFile, E> {
        if on {
            Err(E::custom("`roots` is `off` or a mapping, not `true`"))
        } else {
            Ok(RootsFile::Off)
        }
    }

    fn visit_str<E: de::Error>(self, text: &str) -> Result<RootsFile, E> {
        if text == "off" {
            Ok(RootsFile::Off)
        } else {
            Err(E::custom(format!(
                "`roots` is `off` or a mapping, not `{text}`"
            )))
        }
    }

    fn visit_map<A: MapAccess<'de>>(self, map: A) -> Result<RootsFile, A::Error> {
        let urls = RootUrls::deserialize(MapAccessDeserializer::new(map))?;
        if urls.anchors.as_str().strip_suffix(".xml").is_none() {
            return Err(de::Error::custom(format!(
                "`roots`: `anchors` is the URL of an `.xml` file, its signature beside it as `.p7s`, not `{}`",
                crate::download::redacted(urls.anchors.as_str())
            )));
        }
        Ok(RootsFile::Fetched(urls))
    }
}

impl Default for RootsFile {
    fn default() -> Self {
        Self::Fetched(RootUrls {
            tlds: tlds(),
            anchors: anchors(),
        })
    }
}

impl RootUrls {
    /// The URL of the TLD list.
    pub(crate) fn tlds(&self) -> &str {
        self.tlds.as_str()
    }

    /// The URL of the trust anchors, `root-anchors.xml`.
    pub(crate) fn anchors(&self) -> &str {
        self.anchors.as_str()
    }

    /// The URL of their signature: the anchors' with `.p7s` for `.xml`.
    pub(crate) fn signature(&self) -> String {
        let xml = self.anchors.as_str();
        format!("{}.p7s", xml.strip_suffix(".xml").unwrap_or(xml))
    }
}

fn tlds() -> Url {
    Url::iana(TLDS)
}

fn anchors() -> Url {
    Url::iana(ANCHORS)
}
