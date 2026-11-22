//! Resolutions captured from the Internet's authoritative servers, and the [`Authorities`] that replay them: the test
//! data of the recursive resolver (D188).
//!
//! A [`Resolution`] is one file of `testdata/recursion/`, written by `just capture-recursion`: every exchange an
//! iterator had with root, TLD and zone servers to resolve one name, from priming (RFC 8109 §3) to the answer,
//! the DS and DNSKEY of each zone on the way included.

use std::collections::{HashMap, HashSet};
use std::net::IpAddr;

use dedens_proto::edns::EdnsFlags;
use dedens_proto::{Flags, Header, Message, Name, Opcode, Question, Rcode, RecordType};
use serde::{Deserialize, Serialize};

use crate::fields::{base64, text};

/// The resolution of one name: its file of `testdata/recursion/`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Resolution {
    /// The Unix time of the capture: the "now" under which the signatures of the responses are valid.
    pub captured_at: u64,
    /// The name resolved.
    #[serde(with = "text")]
    pub name: Name<'static>,
    /// The type resolved.
    #[serde(rename = "type", with = "text")]
    pub rtype: RecordType,
    /// The exchanges, in the order they took place.
    pub exchanges: Vec<Exchange>,
}

/// One query to an authoritative server and the response it got.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Exchange {
    /// The server asked.
    pub server: IpAddr,
    /// The zone the server was asked as: the closest enclosing zone the iterator knew.
    #[serde(with = "text")]
    pub zone: Name<'static>,
    /// The name of the question.
    #[serde(with = "text")]
    pub name: Name<'static>,
    /// The type of the question.
    #[serde(rename = "type", with = "text")]
    pub rtype: RecordType,
    /// The flags of the query.
    pub flags: Vec<QueryFlag>,
    /// The transport the query went over.
    pub transport: Transport,
    /// The response, as received.
    #[serde(with = "base64")]
    pub response: Vec<u8>,
}

/// A flag of a query: of its header, or DO of its EDNS.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum QueryFlag {
    /// Recursion desired (RFC 1035 §4.1.1).
    Rd,
    /// Checking disabled (RFC 4035 §3.2.2).
    Cd,
    /// DNSSEC OK (RFC 3225 §3).
    Do,
}

/// The transport of an exchange: an authoritative server answers over UDP and TCP alone.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Transport {
    /// UDP, the first try (RFC 1035 §4.2.1).
    Udp,
    /// TCP, after a truncated response over UDP (RFC 7766 §5).
    Tcp,
}

impl Resolution {
    /// The resolution `id` of `testdata/recursion/`.
    ///
    /// # Panics
    ///
    /// When the file cannot be read or is no resolution.
    #[must_use]
    #[track_caller]
    pub fn read(id: &str) -> Self {
        let text = std::fs::read_to_string(crate::path(&format!("recursion/{id}.yaml")))
            .expect("a captured resolution");
        Self::parse(&text).expect("a valid resolution")
    }

    /// Every resolution of `testdata/recursion/`, with its id, sorted by id.
    ///
    /// # Panics
    ///
    /// As [`Resolution::read`] does.
    #[must_use]
    pub fn all() -> Vec<(String, Self)> {
        let mut ids: Vec<String> = std::fs::read_dir(crate::path("recursion"))
            .expect("testdata/recursion")
            .filter_map(|entry| {
                let name = entry.expect("a directory entry").file_name();
                name.to_str()?.strip_suffix(".yaml").map(str::to_owned)
            })
            .collect();
        ids.sort();
        ids.into_iter()
            .map(|id| {
                let resolution = Self::read(&id);
                (id, resolution)
            })
            .collect()
    }

    /// The resolution `text` writes.
    ///
    /// # Errors
    ///
    /// When `text` is no YAML resolution.
    pub fn parse(text: &str) -> Result<Self, serde_saphyr::Error> {
        serde_saphyr::from_str(text)
    }

    /// The YAML text of the resolution, as [`Resolution::parse`] reads it.
    ///
    /// # Errors
    ///
    /// When the YAML writer fails.
    pub fn to_yaml(&self) -> Result<String, serde_saphyr::ser::Error> {
        serde_saphyr::to_string(self)
    }
}

impl Exchange {
    /// The query of the exchange under `id`: its question, its header flags and DO, and EDNS advertising the
    /// default UDP payload (D10).
    #[must_use]
    pub fn query(&self, id: u16) -> Message<'static> {
        query(id, &self.name, self.rtype, &self.flags)
    }
}

/// A query under `id` for `name` and `rtype` with `flags`, and EDNS advertising the default UDP payload (D10).
#[must_use]
pub fn query(id: u16, name: &Name<'_>, rtype: RecordType, flags: &[QueryFlag]) -> Message<'static> {
    let mut query = Message::query(id, Question::new(name.clone().into_owned(), rtype));
    query.header.flags = Flags::NONE;
    for flag in flags {
        match flag {
            QueryFlag::Rd => query.header.flags = query.header.flags.with(Flags::RD),
            QueryFlag::Cd => query.header.flags = query.header.flags.with(Flags::CD),
            QueryFlag::Do => {
                if let Some(edns) = &mut query.edns {
                    edns.flags = edns.flags.with(EdnsFlags::DO);
                }
            }
        }
    }
    query
}

/// A server and the question it was asked: the name and type.
type Asked = (IpAddr, Name<'static>, RecordType);

/// The authoritative servers of a set of resolutions, answering in memory as they answered the capture.
#[derive(Debug, Default)]
pub struct Authorities {
    /// The responses by server and question, each with the transport it came over.
    responses: HashMap<Asked, Vec<(Transport, Vec<u8>)>>,
}

impl Authorities {
    /// The servers of `resolutions`. A question two of them hold, of one server over one transport, gets the
    /// response of the first given: captures of one server at different times, each answering as the server did.
    ///
    /// # Panics
    ///
    /// When one resolution holds a question of one server twice over one transport: which response to replay would
    /// be a guess.
    #[must_use]
    pub fn new<'r>(resolutions: impl IntoIterator<Item = &'r Resolution>) -> Self {
        let mut responses: HashMap<_, Vec<(Transport, Vec<u8>)>> = HashMap::new();
        for resolution in resolutions {
            let mut asked = HashSet::new();
            for exchange in &resolution.exchanges {
                let question = (exchange.server, exchange.name.clone(), exchange.rtype);
                assert!(
                    asked.insert((question.clone(), exchange.transport)),
                    "{} {} {} asked twice over {:?} in the capture of {}",
                    exchange.server,
                    exchange.name,
                    exchange.rtype,
                    exchange.transport,
                    resolution.name,
                );
                let held = responses.entry(question).or_default();
                if held.iter().all(|(over, _)| *over != exchange.transport) {
                    held.push((exchange.transport, exchange.response.clone()));
                }
            }
        }
        Self { responses }
    }

    /// The response of `server` to the wire `query` over `transport`: the one captured for its question, over
    /// `transport` if one was, under the query's ID and with its question as written, case included, as a server
    /// copies it. A server or question never captured gets REFUSED (RFC 1035 §4.1.1), as a server not
    /// authoritative for the name would answer: a resolver moves on to another server.
    ///
    /// # Panics
    ///
    /// When `query` does not decode or holds other than one question.
    #[must_use]
    pub fn answer(&self, server: IpAddr, transport: Transport, query: &[u8]) -> Vec<u8> {
        let decoded = Message::decode(query).expect("a query").message;
        let question = match decoded.questions.as_slice() {
            [question] => Some(question),
            _ => None,
        }
        .expect("a query of one question");
        let captured = self
            .responses
            .get(&(server, question.name.clone().into_owned(), question.qtype))
            .and_then(|responses| {
                responses
                    .iter()
                    .find(|(over, _)| *over == transport)
                    .or_else(|| responses.first())
            });
        let Some((_, response)) = captured else {
            let refused = Message {
                header: Header {
                    id: decoded.header.id,
                    flags: Flags::QR.with(if decoded.header.flags.contains(Flags::RD) {
                        Flags::RD
                    } else {
                        Flags::NONE
                    }),
                    opcode: Opcode::QUERY,
                    rcode: Rcode::REFUSED,
                },
                questions: decoded.questions.clone(),
                ..Message::default()
            };
            return refused.to_vec().expect("a REFUSED response");
        };
        // The question follows the header, uncompressed in both: the same length, as the names are equal.
        let end = dedens_proto::HEADER_LEN + question.name.wire_len() + 4;
        let mut response = response.clone();
        response[..2].copy_from_slice(&query[..2]);
        response[dedens_proto::HEADER_LEN..end]
            .copy_from_slice(&query[dedens_proto::HEADER_LEN..end]);
        response
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A capture holding a question twice over one transport, answered differently: `answer` replayed the first
    /// response and the second went unread.
    #[test]
    #[should_panic(expected = "asked twice over Udp")]
    fn a_question_asked_twice_over_one_transport_in_one_capture_is_refused() {
        let mut resolution = Resolution::read("unsigned");
        let mut twice = resolution.exchanges[0].clone();
        twice.response.clone_from(&resolution.exchanges[1].response);
        resolution.exchanges.push(twice);
        let _ = Authorities::new([&resolution]);
    }

    /// The same question in two captures: the first capture given answers it, the second's response unread by design.
    #[test]
    fn a_question_in_two_captures_is_answered_by_the_first() {
        let first = Resolution::read("unsigned");
        let mut second = first.clone();
        second.exchanges[0]
            .response
            .clone_from(&first.exchanges[1].response);
        let exchange = &first.exchanges[0];
        let query = exchange.query(0).to_vec().expect("a query");
        let answered =
            Authorities::new([&first, &second]).answer(exchange.server, exchange.transport, &query);
        assert_eq!(answered[2..], exchange.response[2..]);
    }
}
