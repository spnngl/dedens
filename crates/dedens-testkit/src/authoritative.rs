//! The captures of the authoritative phase (D203): zones transferred from public servers, the answers Knot and NSD
//! give on the same zones, and the transfers, NOTIFYs and UPDATEs Knot's tools exchanged with Knot.
//!
//! Written by `just capture-authoritative` (`examples/capture_authoritative`), read from `testdata/authoritative/`:
//!
//! - [`Recording`]: the DNS messages of one scenario, each with its time, direction and transport (`recordings/`).
//! - [`Reference`]: the responses Knot and NSD gave one query on one zone (`answers/`), in an [`Answers`] file.
//! - The zone text of the transfers (`zones/`), read by [`zone`].

use std::collections::BTreeMap;
use std::fmt;

use dedens_proto::edns::EdnsFlags;
use dedens_proto::{Flags, Message, Name, Question, Record, RecordType, ZoneEntry, ZoneReader};
use serde::{Deserialize, Serialize};

use crate::fields::{base64, text};

/// The ID of every query of [`Reference`]: a server copies it into its response.
pub const QUERY_ID: u16 = 0x1234;

/// The TSIG key of the recordings that are signed: `kdig -y` and `knsupdate -y` take it as
/// `hmac-sha256:dedens-test-key:<secret>`, and Knot's configuration holds it. A test key, public by design.
pub const TSIG_KEY: TsigKey = TsigKey {
    name: "dedens-test-key",
    algorithm: "hmac-sha256",
    secret: "ZGVkZW5zIHRlc3Qga2V5IGZvciBUU0lHIGNhcHR1cmVzCg==",
};

/// The TSIG key of the captures (RFC 8945 §2): its name, algorithm and secret in base64.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TsigKey {
    /// The key's name.
    pub name: &'static str,
    /// The algorithm's name, as `kdig -y` writes it.
    pub algorithm: &'static str,
    /// The secret, in base64 (RFC 4648 §4).
    pub secret: &'static str,
}

/// The transport of a message.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Transport {
    /// UDP (RFC 1035 §4.2.1): one message a datagram.
    Udp,
    /// TCP (RFC 7766): the messages of the stream, each framed by a two-byte length (RFC 1035 §4.2.2) in the
    /// network and unframed here.
    Tcp,
}

/// Who sent a recorded message.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Peer {
    /// The client: a request.
    Client,
    /// The server: a response.
    Server,
}

/// The messages of one scenario, as a recording proxy or a transfer client saw them: one file of
/// `testdata/authoritative/recordings/`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Recording {
    /// What the scenario does, in a line.
    pub description: String,
    /// The server that answered: its address for a public one, its name and version for the local ones.
    pub server: String,
    /// The Unix time of the capture's start.
    pub captured_at: u64,
    /// The zone concerned.
    #[serde(with = "text")]
    pub zone: Name<'static>,
    /// The serial of the zone the server served, where one transfer is the scenario.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub serial: Option<u32>,
    /// The TSIG key the requests were signed with, by name, where they were: [`TSIG_KEY`]'s.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub key: Option<String>,
    /// The messages, in the order the proxy saw them.
    pub messages: Vec<Packet>,
}

/// One message of a [`Recording`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Packet {
    /// Milliseconds since the start of the capture.
    pub at_ms: u64,
    /// The transport.
    pub transport: Transport,
    /// The connection of a TCP message, from 1: messages of one stream share it. Zero over UDP.
    pub connection: u32,
    /// The sender.
    pub from: Peer,
    /// The message, as sent, without a TCP length.
    #[serde(with = "base64")]
    pub message: Vec<u8>,
}

/// A server whose answers are captured.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Server {
    /// Knot DNS.
    Knot,
    /// NSD.
    Nsd,
}

impl fmt::Display for Server {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Knot => "knot",
            Self::Nsd => "nsd",
        })
    }
}

/// The answers of Knot and NSD on one zone: one file of `testdata/authoritative/answers/`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Answers {
    /// The zone served.
    #[serde(with = "text")]
    pub zone: Name<'static>,
    /// The zone's file, in `testdata/zones/` or `testdata/authoritative/zones/`.
    pub file: String,
    /// The Unix time of the capture.
    pub captured_at: u64,
    /// The version line of each server that ran.
    pub versions: BTreeMap<Server, String>,
    /// The servers that refused the zone, with the line they gave: they answered nothing.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub refused: BTreeMap<Server, String>,
    /// The queries and the responses.
    pub answers: Vec<Reference>,
}

/// One query and the response each server gave it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Reference {
    /// The name of the question, in the case asked.
    #[serde(with = "text")]
    pub name: Name<'static>,
    /// The type of the question.
    #[serde(rename = "type", with = "text")]
    pub rtype: RecordType,
    /// DNSSEC OK (RFC 3225 §3).
    #[serde(rename = "do")]
    pub dnssec_ok: bool,
    /// The UDP payload size the EDNS of the query advertises (RFC 6891 §6.2.3); `None` for a query without EDNS,
    /// to which a server answers within 512 bytes over UDP (RFC 1035 §4.2.1).
    pub edns_size: Option<u16>,
    /// The transport of the query.
    pub transport: Transport,
    /// The response of each server, as received.
    #[serde(with = "responses")]
    pub responses: BTreeMap<Server, Vec<u8>>,
}

impl Reference {
    /// The query as it was sent, under [`QUERY_ID`]: RD clear as an iterator asks, EDNS as `edns_size` and
    /// `dnssec_ok` say.
    #[must_use]
    pub fn query(&self) -> Message<'static> {
        let mut query = Message::query(QUERY_ID, Question::new(self.name.clone(), self.rtype));
        query.header.flags = Flags::NONE;
        query.edns = self.edns_size.map(|size| {
            let mut edns = dedens_proto::edns::Edns {
                udp_payload: size,
                ..dedens_proto::edns::Edns::default()
            };
            if self.dnssec_ok {
                edns.flags = edns.flags.with(EdnsFlags::DO);
            }
            edns
        });
        query
    }
}

impl Answers {
    /// The answers of the zone `id` (`root`, `zonetransfer.me`, `rfc4035_appendix_a`...) of
    /// `testdata/authoritative/answers/`.
    ///
    /// # Panics
    ///
    /// When the file cannot be read or is no answers file.
    #[must_use]
    #[track_caller]
    pub fn read(id: &str) -> Self {
        let text =
            std::fs::read_to_string(crate::path(&format!("authoritative/answers/{id}.yaml")))
                .expect("a captured answers file");
        serde_saphyr::from_str(&text).expect("a valid answers file")
    }

    /// The ids of the files of `testdata/authoritative/answers/`, sorted.
    ///
    /// # Panics
    ///
    /// When the directory cannot be read.
    #[must_use]
    pub fn ids() -> Vec<String> {
        ids("authoritative/answers")
    }

    /// The YAML text of the file.
    ///
    /// # Errors
    ///
    /// When the YAML writer fails.
    pub fn to_yaml(&self) -> Result<String, serde_saphyr::ser::Error> {
        serde_saphyr::to_string(self)
    }
}

impl Recording {
    /// The recording `id` of `testdata/authoritative/recordings/`.
    ///
    /// # Panics
    ///
    /// When the file cannot be read or is no recording.
    #[must_use]
    #[track_caller]
    pub fn read(id: &str) -> Self {
        let text =
            std::fs::read_to_string(crate::path(&format!("authoritative/recordings/{id}.yaml")))
                .expect("a captured recording");
        serde_saphyr::from_str(&text).expect("a valid recording")
    }

    /// The ids of the files of `testdata/authoritative/recordings/`, sorted.
    ///
    /// # Panics
    ///
    /// When the directory cannot be read.
    #[must_use]
    pub fn ids() -> Vec<String> {
        ids("authoritative/recordings")
    }

    /// The YAML text of the file.
    ///
    /// # Errors
    ///
    /// When the YAML writer fails.
    pub fn to_yaml(&self) -> Result<String, serde_saphyr::ser::Error> {
        serde_saphyr::to_string(self)
    }
}

/// The `.yaml` files of the directory `relative` of `testdata/`, without the extension, sorted.
fn ids(relative: &str) -> Vec<String> {
    let mut ids: Vec<String> = std::fs::read_dir(crate::path(relative))
        .expect("a capture directory")
        .filter_map(|entry| {
            let name = entry.expect("a directory entry").file_name();
            name.to_str()?.strip_suffix(".yaml").map(str::to_owned)
        })
        .collect();
    ids.sort();
    ids
}

/// The records of the zone file `file` of `testdata/authoritative/zones/` (a zone transferred from a public
/// server, `root.zone`), in the order of the transfer.
///
/// # Panics
///
/// When the file cannot be read or is no valid zone.
#[must_use]
pub fn zone(file: &str) -> Vec<Record<'static>> {
    let text = std::fs::read(crate::path("authoritative/zones").join(file)).expect("a zone file");
    ZoneReader::new(&text, None)
        .filter_map(|entry| match entry.expect("a valid zone") {
            ZoneEntry::Record(decoded) => Some(decoded.record),
            _ => None,
        })
        .collect()
}

/// The servers' responses to one query, in YAML a map from the server's name to base64.
mod responses {
    use std::collections::BTreeMap;

    use data_encoding::BASE64;
    use serde::{Deserialize, Deserializer, Serialize, Serializer};

    use super::Server;

    pub(super) fn serialize<S: Serializer>(
        responses: &BTreeMap<Server, Vec<u8>>,
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        responses
            .iter()
            .map(|(server, bytes)| (server, BASE64.encode(bytes)))
            .collect::<BTreeMap<_, _>>()
            .serialize(serializer)
    }

    pub(super) fn deserialize<'de, D: Deserializer<'de>>(
        deserializer: D,
    ) -> Result<BTreeMap<Server, Vec<u8>>, D::Error> {
        BTreeMap::<Server, String>::deserialize(deserializer)?
            .into_iter()
            .map(|(server, text)| {
                BASE64
                    .decode(text.as_bytes())
                    .map(|bytes| (server, bytes))
                    .map_err(serde::de::Error::custom)
            })
            .collect()
    }
}
