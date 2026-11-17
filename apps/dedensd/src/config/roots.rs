//! The `roots` settings (D128): where IANA's TLD list and the root's trust anchors are fetched from, or `off`.

use serde::Deserialize;

use super::sources::Url;

/// IANA's TLD list.
const TLDS: &str = "https://data.iana.org/TLD/v1/tlds.json";

/// IANA's root trust anchors, signed by the file at the same URL with `.p7s` for `.xml` (RFC 9718 §3).
const ANCHORS: &str = "https://data.iana.org/root-anchors/root-anchors.xml";

/// The `roots` settings, as written: `off`, or the URLs of the files, each IANA's unless set.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(try_from = "RootsText")]
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

/// `roots` as YAML gives it: `off` reads as a boolean unless quoted.
#[derive(Deserialize)]
#[serde(untagged)]
enum RootsText {
    Flag(bool),
    Name(String),
    Urls(RootUrls),
}

impl TryFrom<RootsText> for RootsFile {
    type Error = String;

    fn try_from(text: RootsText) -> Result<Self, String> {
        match text {
            RootsText::Flag(false) => Ok(Self::Off),
            RootsText::Name(name) if name == "off" => Ok(Self::Off),
            RootsText::Flag(true) => Err("`roots` is `off` or a mapping, not `true`".to_owned()),
            RootsText::Name(name) => Err(format!("`roots` is `off` or a mapping, not `{name}`")),
            RootsText::Urls(urls) if urls.anchors.as_str().strip_suffix(".xml").is_none() => {
                Err(format!(
                    "`roots`: `anchors` is the URL of an `.xml` file, its signature beside it as `.p7s`, not `{}`",
                    crate::download::redacted(urls.anchors.as_str())
                ))
            }
            RootsText::Urls(urls) => Ok(Self::Fetched(urls)),
        }
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
