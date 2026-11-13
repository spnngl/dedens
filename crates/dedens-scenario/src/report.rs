//! The report of a response (D37): what `dedens --json` and `--yaml` print, one object per query, and what the
//! server's tests read back. Empty lists and strings are left out: an absent field is empty.

use std::fmt;
use std::net::SocketAddr;

use dedens_net::exchange::{CertificateInfo, Response};
use dedens_proto::edns::{Edns, EdnsFlags, EdnsOption, ExtendedError, InfoCode};
use dedens_proto::{Decoded, Hex, Question, Record};
use serde::{Deserialize, Serialize};

use crate::Id;

/// A response, with how it came when it came from an exchange.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Report {
    /// The query's id: the `--save-wire` file name.
    pub id: Id,
    /// How the response came; absent for a response read from a file.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub exchange: Option<ExchangeReport>,
    /// The size of the response, in bytes.
    pub size: usize,
    /// The header, the rcode extended by EDNS (RFC 6891 §6.1.3).
    pub header: HeaderReport,
    /// The question section.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub question: Vec<QuestionReport>,
    /// The answer section.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub answer: Vec<RecordReport>,
    /// The authority section.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub authority: Vec<RecordReport>,
    /// The additional section, without the OPT record.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub additional: Vec<RecordReport>,
    /// The OPT record (RFC 6891 §6).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub edns: Option<EdnsReport>,
    /// What validation made of the response, when asked for (`+validate`, D76); the answer and authority
    /// sections are what it covers.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dnssec: Option<DnssecReport>,
    /// The rules of the protocol the response breaks, in words (D9).
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub violations: Vec<String>,
    /// The expectations the response breaks, in words (D34).
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub failures: Vec<String>,
    /// The round trips of a query asked several times (`dedens --repeat`), this report being of the last answer.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub latency: Option<Latency>,
}

impl Report {
    /// The report of `decoded`, `size` bytes on the wire.
    #[must_use]
    pub fn new(id: Id, decoded: &Decoded<'_>, size: usize) -> Self {
        let message = &decoded.message;
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
            dnssec: None,
            violations: decoded.violations.iter().map(ToString::to_string).collect(),
            failures: Vec::new(),
            latency: None,
        }
    }

    /// The report of `response`, `decoded`, from `server`.
    #[must_use]
    pub fn exchanged(
        id: Id,
        server: SocketAddr,
        response: &Response,
        decoded: &Decoded<'_>,
    ) -> Self {
        Self {
            exchange: Some(ExchangeReport {
                server,
                transport: match response.transport {
                    dedens_proto::Transport::Udp => Transport::Udp,
                    dedens_proto::Transport::Tcp => Transport::Tcp,
                    dedens_proto::Transport::Tls => Transport::Tls,
                    dedens_proto::Transport::Quic => Transport::Quic,
                    dedens_proto::Transport::Https => Transport::Https,
                    dedens_proto::Transport::Odoh => Transport::Odoh,
                    dedens_proto::Transport::Coap => Transport::Coap,
                },
                rtt_us: u64::try_from(response.rtt.as_micros()).unwrap_or(u64::MAX),
                sends: response.sends,
                query_size: response.query.len(),
                http: response.http.map(|http| HttpReport {
                    version: http.version_name(),
                    status: http.status.as_u16(),
                }),
                doc_path: None,
                dnscrypt: response.dnscrypt.map(|info| DnsCryptReport {
                    certificate: Some(CertificateReport::new(info)),
                    certificates: Vec::new(),
                }),
            }),
            ..Self::new(id, decoded, response.wire.len())
        }
    }
}

/// What validation made of a response (RFC 4033 §5), the verdicts of RFC 4035 §4.3.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum DnssecStatus {
    /// Authenticated: signatures and proofs of absence check out from a trust anchor.
    Secure,
    /// Not covered by a chain of trust, which is no failure: an unsigned zone, a negative trust anchor.
    Insecure,
    /// A secure zone's data fails validation.
    Bogus,
    /// Nothing is known: a question went unanswered or a limit stopped the validation.
    Indeterminate,
}

impl fmt::Display for DnssecStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Secure => "secure",
            Self::Insecure => "insecure",
            Self::Bogus => "bogus",
            Self::Indeterminate => "indeterminate",
        })
    }
}

/// The verdict on a response (D76), apart from the server's own AD flag, which is never read.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct DnssecReport {
    /// The verdict.
    pub status: DnssecStatus,
    /// The extended error the verdict comes with (RFC 8914), for a failure or an unsupported algorithm.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ede: Option<EdeReport>,
    /// Why the response is insecure, in words.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

impl DnssecReport {
    /// A verdict of `status` with its extended error and reason, if any.
    #[must_use]
    pub fn new(
        status: DnssecStatus,
        ede: Option<&ExtendedError<'_>>,
        reason: Option<String>,
    ) -> Self {
        Self {
            status,
            ede: ede.map(EdeReport::new),
            reason,
        }
    }
}

/// An Extended DNS Error (RFC 8914 §2).
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct EdeReport {
    /// The INFO-CODE.
    pub code: u16,
    /// Its purpose in the IANA registry, when registered.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub purpose: Option<String>,
    /// The EXTRA-TEXT, its control characters escaped as in Rust.
    #[serde(skip_serializing_if = "String::is_empty")]
    pub text: String,
}

impl EdeReport {
    fn new(error: &ExtendedError<'_>) -> Self {
        Self {
            code: error.code.0,
            purpose: InfoCode::mnemonic(error.code).map(str::to_owned),
            text: printable(&error.text),
        }
    }
}

/// How a response came.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
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
    /// Over HTTPS, the HTTP response.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub http: Option<HttpReport>,
    /// Over CoAP, the path the server's `/.well-known/core` gave for the query (`+doc-discover`, D95), written as a
    /// URI path.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub doc_path: Option<String>,
    /// Over `DNSCrypt`, the certificate the query was sealed under, and with `+dnscrypt-cert` the certificates listed
    /// (D98).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dnscrypt: Option<DnsCryptReport>,
}

/// What a `DNSCrypt` exchange tells of the certificates of the resolver.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct DnsCryptReport {
    /// The certificate the query was sealed under, none for a listing.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub certificate: Option<CertificateReport>,
    /// The certificates the provider's key signed, as `+dnscrypt-cert` lists them, valid or not; empty for a query.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub certificates: Vec<CertificateReport>,
}

/// A certificate of a `DNSCrypt` resolver (draft-denis-dprive-dnscrypt "Certificates").
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct CertificateReport {
    /// The encryption system: `X25519-XSalsa20Poly1305` (`es-version` 1), `X25519-XChaCha20Poly1305` (2), else
    /// `unknown`.
    pub system: &'static str,
    /// The serial, which rises with each certificate of a provider.
    pub serial: u32,
    /// The start of the validity, in seconds since 1970.
    pub valid_from: u32,
    /// The end of the validity, in seconds since 1970.
    pub valid_until: u32,
}

impl CertificateReport {
    /// The report of a certificate `info` tells of.
    #[must_use]
    pub fn new(info: CertificateInfo) -> Self {
        Self {
            system: match info.es_version {
                1 => "X25519-XSalsa20Poly1305",
                2 => "X25519-XChaCha20Poly1305",
                _ => "unknown",
            },
            serial: info.serial,
            valid_from: info.valid_from,
            valid_until: info.valid_until,
        }
    }
}

/// The HTTP response a DNS response came in (RFC 8484 §4.2.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct HttpReport {
    /// The HTTP version, such as `HTTP/3`.
    pub version: &'static str,
    /// The status code.
    pub status: u16,
}

/// The round trips of a query asked `sent` times, in microseconds: those answered, by nearest rank.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct Latency {
    /// The times the query was asked.
    pub sent: u16,
    /// The times it got no response, left out when 0.
    #[serde(skip_serializing_if = "is_zero")]
    pub errors: u16,
    /// The fastest.
    pub min_us: u64,
    /// The median.
    pub p50_us: u64,
    /// The 90th percentile.
    pub p90_us: u64,
    /// The 99th percentile.
    pub p99_us: u64,
    /// The slowest.
    pub max_us: u64,
}

impl Latency {
    /// The latency of `sent` queries whose answered ones took `rtts_us`, in any order; `None` when none was
    /// answered.
    #[must_use]
    pub fn of(sent: u16, rtts_us: &mut [u64]) -> Option<Self> {
        if rtts_us.is_empty() {
            return None;
        }
        rtts_us.sort_unstable();
        let rank = |percent: usize| {
            let rank = (rtts_us.len() * percent).div_ceil(100).max(1);
            rtts_us[rank - 1]
        };
        let answered = u16::try_from(rtts_us.len()).ok()?;
        Some(Self {
            sent,
            errors: sent.checked_sub(answered)?,
            min_us: rtts_us[0],
            p50_us: rank(50),
            p90_us: rank(90),
            p99_us: rank(99),
            max_us: rank(100),
        })
    }
}

/// A transport.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Transport {
    /// UDP.
    Udp,
    /// TCP.
    Tcp,
    /// TLS (RFC 7858).
    Tls,
    /// QUIC (RFC 9250).
    Quic,
    /// DNS over HTTPS (RFC 8484).
    #[serde(rename = "doh")]
    Https,
    /// Oblivious DNS over HTTPS (RFC 9230).
    #[serde(rename = "odoh")]
    Odoh,
    /// DNS over CoAP (RFC 9953).
    Coap,
}

/// The header of a message (RFC 1035 §4.1.1); its counts are the lengths of the sections.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct HeaderReport {
    /// The ID.
    pub id: u16,
    /// The opcode mnemonic, such as `QUERY`.
    pub opcode: String,
    /// The rcode mnemonic, such as `NOERROR`, extended by EDNS.
    pub rcode: String,
    /// The names of the set flags, in header order: `qr`, `aa`, `tc`, `rd`, `ra`, `z`, `ad`, `cd`.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub flags: Vec<String>,
}

/// A question (RFC 1035 §4.1.2).
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
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
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
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
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct EdnsReport {
    /// The largest UDP payload the sender takes, in bytes.
    pub payload: u16,
    /// The EDNS version, left out when 0.
    #[serde(skip_serializing_if = "is_zero")]
    pub version: u8,
    /// `do` when DNSSEC records are wanted (RFC 3225 §3), then any other bit set, in hex.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub flags: Vec<String>,
    /// The options, in order.
    #[serde(skip_serializing_if = "Vec::is_empty")]
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
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "option", rename_all = "lowercase")]
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
        #[serde(skip_serializing_if = "Option::is_none")]
        server: Option<String>,
    },
    /// An Extended DNS Error (RFC 8914 §2).
    Ede {
        /// The INFO-CODE.
        code: u16,
        /// Its purpose in the IANA registry, when registered.
        #[serde(skip_serializing_if = "Option::is_none")]
        purpose: Option<String>,
        /// The EXTRA-TEXT, its control characters escaped as in Rust.
        #[serde(skip_serializing_if = "String::is_empty")]
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
                hex: Hex(id).to_string(),
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
                client: Hex(&cookie.client()).to_string(),
                server: cookie.server().map(|s| Hex(s).to_string()),
            },
            EdnsOption::Ede(error) => {
                let EdeReport {
                    code,
                    purpose,
                    text,
                } = EdeReport::new(error);
                Self::Ede {
                    code,
                    purpose,
                    text,
                }
            }
            EdnsOption::ClientSubnet(subnet) => other(format!(
                "{}/{}/{}",
                subnet.address(),
                subnet.source_prefix(),
                subnet.scope_prefix()
            )),
            EdnsOption::Keepalive(Some(units)) => other(format!("{}.{} s", units / 10, units % 10)),
            EdnsOption::Padding(len) => other(format!("{len} bytes")),
            EdnsOption::Unknown(unknown) => other(Hex(unknown.data()).to_string()),
            // A keepalive without its timeout, as in a query, or an option of a later version.
            _ => other(String::new()),
        }
    }
}

/// `text`, its control characters escaped so that a server cannot drive the terminal.
fn printable(text: &str) -> String {
    text.chars().fold(String::new(), |mut out, c| {
        if c.is_control() {
            out.extend(c.escape_default());
        } else {
            out.push(c);
        }
        out
    })
}

/// Whether `n` is 0, a number left out of a report.
fn is_zero<N: Default + PartialEq>(n: &N) -> bool {
    *n == N::default()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn latency_ranks_the_answered_round_trips() {
        let mut rtts: Vec<u64> = (1..=10).rev().collect();
        let latency = Latency::of(12, &mut rtts).expect("answered");
        assert_eq!(
            [
                latency.min_us,
                latency.p50_us,
                latency.p90_us,
                latency.p99_us,
                latency.max_us
            ],
            [1, 5, 9, 10, 10]
        );
        assert_eq!((latency.sent, latency.errors), (12, 2));
        let one = Latency::of(1, &mut [7]).expect("answered");
        assert_eq!([one.min_us, one.p50_us, one.p99_us, one.max_us], [7; 4]);
        assert_eq!(Latency::of(3, &mut []), None);
    }

    /// Whether a report holds the option a capture is for.
    type HasOption = fn(&OptionReport) -> bool;

    /// Captured responses, each with one kind of option.
    const CAPTURED: [(&str, &[u8], HasOption); 3] = [
        (
            "nsid",
            include_bytes!("../../../testdata/proto/nsid.bin"),
            |o| matches!(o, OptionReport::Nsid { .. }),
        ),
        (
            "cookie",
            include_bytes!("../../../testdata/proto/cookie.bin"),
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
            include_bytes!("../../../testdata/proto/ede.bin"),
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
    fn reports_hold_each_option() {
        for (id, wire, has_option) in CAPTURED {
            let decoded = dedens_proto::Message::decode(wire).expect("captured");
            let report = Report::new(id.parse().expect("an id"), &decoded, wire.len());
            let edns = report.edns.expect("an OPT record");
            assert!(edns.options.iter().any(has_option), "{id}: {edns:?}");
        }
    }

    #[test]
    fn reports_hold_the_violations() {
        // A captured response with a byte past its end (D9).
        let mut wire = CAPTURED[0].1.to_vec();
        wire.push(0);
        let decoded = dedens_proto::Message::decode(&wire).expect("readable");
        let report = Report::new("nsid".parse().expect("an id"), &decoded, wire.len());
        assert_eq!(report.violations.len(), 1, "{:?}", report.violations);
    }

    /// The report of an exchange says how the response came: the server, the transport, the round trip, the queries
    /// sent, the size of the last one and the HTTP response (D37).
    #[test]
    fn an_exchanged_report_says_how_the_response_came() {
        use std::time::{Duration, Instant};

        use dedens_net::exchange::{Exchange, Options, Progress};

        let wire = CAPTURED[0].1;
        let decoded = dedens_proto::Message::decode(wire).expect("captured");
        let question = decoded.message.questions[0].clone();
        let query = dedens_proto::Message::query(decoded.message.header.id, question);
        let server: SocketAddr = "192.0.2.53:53".parse().expect("an address");
        let sent = Instant::now();
        let exchange = Exchange::start(query, server, Options::default(), [1, 2, 3, 4], sent)
            .expect("an encoded query");
        let progress = exchange.receive(
            server,
            dedens_proto::Transport::Udp,
            wire.to_vec(),
            sent + Duration::from_millis(7),
        );
        let Progress::Done(Ok(response)) = progress else {
            panic!("{progress:?}");
        };
        let report = Report::exchanged("nsid".parse().expect("an id"), server, &response, &decoded);
        assert_eq!(
            report.exchange,
            Some(ExchangeReport {
                server,
                transport: Transport::Udp,
                rtt_us: 7000,
                sends: 1,
                query_size: response.query.len(),
                http: None,
                doc_path: None,
                dnscrypt: None,
            })
        );
        assert_eq!(report.size, wire.len());
        assert_eq!(report.header.id, decoded.message.header.id);
    }

    #[test]
    fn control_characters_of_extra_text_are_escaped() {
        assert_eq!(printable("a\u{1b}[2J\r\nb é"), "a\\u{1b}[2J\\r\\nb é");
    }
}
