//! The report of a response (D35): what `dedens --json` prints, one object per query, and what the server's tests
//! read back.

use std::net::SocketAddr;

use dedens_net::exchange::{self, Response};
use dedens_proto::edns::{EdnsOption, InfoCode};
use dedens_proto::{Edns, EdnsFlags, Message, Question, Record};
use serde::{Deserialize, Serialize};

use crate::hex;

/// A response, with how it came when it came from an exchange.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Report {
    /// The query's id: the `--save-wire` file name.
    pub id: String,
    /// How the response came; absent for a response read from a file.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub exchange: Option<ExchangeReport>,
    /// The size of the response, in bytes.
    pub size: usize,
    /// The header, the rcode extended by EDNS (RFC 6891 §6.1.3).
    pub header: HeaderReport,
    /// The question section.
    pub question: Vec<QuestionReport>,
    /// The answer section.
    pub answer: Vec<RecordReport>,
    /// The authority section.
    pub authority: Vec<RecordReport>,
    /// The additional section, without the OPT record.
    pub additional: Vec<RecordReport>,
    /// The OPT record (RFC 6891 §6).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub edns: Option<EdnsReport>,
    /// The expectations the response breaks, in words (D34).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub failures: Vec<String>,
}

impl Report {
    /// The report of `message`, `size` bytes on the wire.
    #[must_use]
    pub fn new(id: String, message: &Message<'_>, size: usize) -> Self {
        let records = |section: &[Record<'_>]| section.iter().map(RecordReport::new).collect();
        Self {
            id,
            exchange: None,
            size,
            header: HeaderReport {
                id: message.header.id,
                opcode: message.header.opcode.to_string(),
                rcode: message.rcode().to_string(),
                flags: message.header.flags.names().map(str::to_owned).collect(),
            },
            question: message.questions.iter().map(QuestionReport::new).collect(),
            answer: records(&message.answer),
            authority: records(&message.authority),
            additional: records(&message.additional),
            edns: message.edns.as_ref().map(EdnsReport::new),
            failures: Vec::new(),
        }
    }

    /// The report of `response`, decoded as `message`, from `server`.
    #[must_use]
    pub fn exchanged(
        id: String,
        server: SocketAddr,
        response: &Response,
        message: &Message<'_>,
    ) -> Self {
        Self {
            exchange: Some(ExchangeReport {
                server,
                transport: match response.transport {
                    exchange::Transport::Udp => Transport::Udp,
                    exchange::Transport::Tcp => Transport::Tcp,
                },
                rtt_us: u64::try_from(response.rtt.as_micros()).unwrap_or(u64::MAX),
                sends: response.sends,
                query_size: response.query.len(),
            }),
            ..Self::new(id, message, response.wire.len())
        }
    }
}

/// How a response came.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExchangeReport {
    /// The server asked.
    pub server: SocketAddr,
    /// The transport of the response.
    pub transport: Transport,
    /// The time from sending the last query to receiving the response, in microseconds.
    pub rtt_us: u64,
    /// Queries sent in all, over both transports.
    pub sends: u16,
    /// The size of the last query, in bytes.
    pub query_size: usize,
}

/// A transport.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Transport {
    /// UDP.
    Udp,
    /// TCP.
    Tcp,
}

/// The header of a message (RFC 1035 §4.1.1); its counts are the lengths of the sections.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HeaderReport {
    /// The ID.
    pub id: u16,
    /// The opcode mnemonic, such as `QUERY`.
    pub opcode: String,
    /// The rcode mnemonic, such as `NOERROR`, extended by EDNS.
    pub rcode: String,
    /// The names of the set flags, in header order: `qr`, `aa`, `tc`, `rd`, `ra`, `z`, `ad`, `cd`.
    pub flags: Vec<String>,
}

/// A question (RFC 1035 §4.1.2).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct QuestionReport {
    /// The name, absolute.
    pub name: String,
    /// The class mnemonic.
    pub class: String,
    /// The type mnemonic.
    #[serde(rename = "type")]
    pub qtype: String,
}

impl QuestionReport {
    fn new(question: &Question<'_>) -> Self {
        Self {
            name: question.name.to_string(),
            class: question.qclass.to_string(),
            qtype: question.qtype.to_string(),
        }
    }
}

/// A record, each field in presentation format (RFC 1035 §5.1).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecordReport {
    /// The owner, absolute.
    pub name: String,
    /// The TTL, in seconds.
    pub ttl: u32,
    /// The class mnemonic.
    pub class: String,
    /// The type mnemonic.
    #[serde(rename = "type")]
    pub rtype: String,
    /// The RDATA.
    pub data: String,
}

impl RecordReport {
    fn new(record: &Record<'_>) -> Self {
        Self {
            name: record.name.to_string(),
            ttl: record.ttl.get(),
            class: record.class.to_string(),
            rtype: record.rtype().to_string(),
            data: record.rdata.to_string(),
        }
    }
}

/// The OPT record (RFC 6891 §6.1.3).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EdnsReport {
    /// The largest UDP payload the sender takes, in bytes.
    pub payload: u16,
    /// The EDNS version.
    pub version: u8,
    /// `do` when DNSSEC records are wanted (RFC 3225 §3), then any other bit set, in hex.
    pub flags: Vec<String>,
    /// The options, in order.
    pub options: Vec<OptionReport>,
}

impl EdnsReport {
    fn new(edns: &Edns<'_>) -> Self {
        let mut flags = Vec::new();
        if edns.flags.contains(EdnsFlags::DO) {
            flags.push("do".to_owned());
        }
        let rest = edns.flags.without(EdnsFlags::DO).bits();
        if rest != 0 {
            flags.push(format!("{rest:#06x}"));
        }
        Self {
            payload: edns.udp_payload,
            version: edns.version,
            flags,
            options: edns.options.iter().map(OptionReport::new).collect(),
        }
    }
}

/// An EDNS option.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "option", rename_all = "lowercase", deny_unknown_fields)]
pub enum OptionReport {
    /// The server's identifier (RFC 5001 §2.3).
    Nsid {
        /// The identifier in hex.
        hex: String,
        /// The identifier as text, each byte outside printable ASCII a `.`, as dig shows it.
        text: String,
    },
    /// A cookie (RFC 7873 §4).
    Cookie {
        /// The client cookie in hex.
        client: String,
        /// The server cookie in hex, when present.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        server: Option<String>,
    },
    /// An Extended DNS Error (RFC 8914 §2).
    Ede {
        /// The INFO-CODE.
        code: u16,
        /// Its purpose in the IANA registry, when registered.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        purpose: Option<String>,
        /// The EXTRA-TEXT, possibly empty.
        text: String,
    },
    /// Any other option: its name and data in words.
    Other {
        /// The option's mnemonic, or `OPTION` and its code.
        name: String,
        /// Its data in words, or in hex when unknown.
        data: String,
    },
}

impl OptionReport {
    fn new(option: &EdnsOption<'_>) -> Self {
        let other = |data: String| Self::Other {
            name: option.code().to_string(),
            data,
        };
        match option {
            EdnsOption::Nsid(id) => Self::Nsid {
                hex: hex(id),
                text: id
                    .iter()
                    .map(|&b| {
                        if b.is_ascii_graphic() || b == b' ' {
                            char::from(b)
                        } else {
                            '.'
                        }
                    })
                    .collect(),
            },
            EdnsOption::Cookie(cookie) => Self::Cookie {
                client: hex(&cookie.client()),
                server: cookie.server().map(hex),
            },
            EdnsOption::Ede(error) => Self::Ede {
                code: error.code.0,
                purpose: InfoCode::mnemonic(error.code).map(str::to_owned),
                text: error.text.to_string(),
            },
            EdnsOption::ClientSubnet(subnet) => other(format!(
                "{}/{}/{}",
                subnet.address(),
                subnet.source_prefix(),
                subnet.scope_prefix()
            )),
            EdnsOption::Keepalive(Some(units)) => other(format!("{}.{} s", units / 10, units % 10)),
            EdnsOption::Padding(len) => other(format!("{len} bytes")),
            EdnsOption::Unknown(unknown) => other(hex(unknown.data())),
            // A keepalive without its timeout, as in a query, or an option of a later version.
            _ => other(String::new()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Whether a report holds the option a capture is for.
    type HasOption = fn(&OptionReport) -> bool;

    /// Captured responses, each with one kind of option.
    const CAPTURED: [(&str, &[u8], HasOption); 3] = [
        (
            "nsid",
            include_bytes!("../../dedens-proto/tests/testdata/nsid.bin"),
            |o| matches!(o, OptionReport::Nsid { .. }),
        ),
        (
            "cookie",
            include_bytes!("../../dedens-proto/tests/testdata/cookie.bin"),
            |o| {
                matches!(
                    o,
                    OptionReport::Cookie {
                        server: Some(_),
                        ..
                    }
                )
            },
        ),
        (
            "ede",
            include_bytes!("../../dedens-proto/tests/testdata/ede.bin"),
            |o| {
                matches!(
                    o,
                    OptionReport::Ede {
                        purpose: Some(_),
                        ..
                    }
                )
            },
        ),
    ];

    #[test]
    fn reports_read_back_as_written() {
        for (id, wire, has_option) in CAPTURED {
            let message = Message::decode(wire).expect("captured").message;
            let report = Report::new(id.to_owned(), &message, wire.len());
            let json = serde_json::to_string(&report).expect("serializes");
            assert_eq!(
                serde_json::from_str::<Report>(&json).expect("reads"),
                report,
                "{id}"
            );
            let edns = report.edns.expect("an OPT record");
            assert!(edns.options.iter().any(has_option), "{id}: {json}");
        }
    }
}
