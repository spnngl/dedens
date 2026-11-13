//! The exchange of one query with one server, without I/O (D26, D27).
//!
//! An [`Exchange`] holds the query and decides what happens next; its caller moves the bytes and keeps time.
//! It starts with a query to send, then takes each received message and each expired deadline, and answers with
//! a [`Progress`]: send the (possibly changed) query again, keep waiting, or done.
//!
//! ```
//! # use std::net::SocketAddr;
//! # use std::time::Instant;
//! # use dedens_net::exchange::{Exchange, Options, Progress};
//! # use dedens_proto::{Message, Name, Question, RecordType, Transport};
//! let server: SocketAddr = "192.0.2.53:53".parse()?;
//! let query = Message::query(0x1234, Question::new(Name::root(), RecordType::NS));
//! let now = Instant::now();
//! let exchange = Exchange::start(query, server, Options::default(), [1, 2, 3, 4], now)?;
//! assert_eq!(exchange.transport(), Transport::Udp);
//! // Send exchange.wire(), wait until exchange.deadline(); nothing came back:
//! let deadline = exchange.deadline();
//! let Progress::Send(exchange) = exchange.time_out(deadline) else { unreachable!() };
//! assert_eq!(exchange.sends(), 2);
//! # Ok::<(), Box<dyn std::error::Error>>(())
//! ```

use std::net::SocketAddr;
use std::num::NonZeroU8;
use std::time::{Duration, Instant};

use dedens_proto::edns::{Cookie, EdnsOption, EdnsView, OptionCode};
use dedens_proto::{
    EncodeError, Flags, Message, Name, Query, Question, Rcode, Transport, Violation,
};

use crate::doh::Method;

/// How an exchange behaves; the default is dig's (D27).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct Options {
    /// The transport of the first query. Default: UDP.
    pub transport: Transport,
    /// Whether a truncated response over UDP sends the query again over TCP (RFC 7766 §5); off, it is the
    /// response, as dig's `+ignore`. Default: on.
    pub tcp_fallback: bool,
    /// Queries sent before giving up when no response comes, the first one included. Default: 3.
    pub tries: NonZeroU8,
    /// How long to wait for a response to each query. Default: 5 s.
    pub timeout: Duration,
    /// Whether to query again without EDNS when a server answers an EDNS query with FORMERR or NOTIMP, its
    /// question repeated and no OPT record (RFC 6891 §7). Never on a timeout (RFC 8906), once the server sent an
    /// OPT record, nor for a response without the question (D114). Default: on.
    pub edns_fallback: bool,
    /// Random bits for `0x20` (draft-vixie-dnsext-dns0x20): when set, the case of each letter of the question
    /// names follows these bits, and a response must repeat the names in the same case. Default: off.
    pub random_case: Option<[u8; 32]>,
    /// Whether [`Client::exchange`](crate::client::Client::exchange) adds a client cookie to a query with EDNS
    /// and none of its own (RFC 7873 §5.1). Default: on.
    pub cookies: bool,
    /// How a query goes over [`Transport::Https`]: by GET, which HTTP caches can keep, or by POST (RFC 8484 §4.1).
    /// Default: GET.
    pub method: Method,
    /// What a `DNSCrypt` server is asked, see [`DnsCryptOptions`].
    pub dnscrypt: DnsCryptOptions,
}

/// How a `DNSCrypt` resolver is asked (D101): the choices of `PQDNSCrypt`.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct DnsCryptOptions {
    /// Whether only a post-quantum certificate (`X-Wing`) is taken: a resolver known to offer one is not to be
    /// downgraded by a stripped certificate (draft "Downgrade Protection"). Off, the PQ certificate is preferred
    /// when offered, any other used otherwise. Default: off.
    pub pq: bool,
    /// With a PQ certificate, whether a query is resumed with the ticket of the last response, with no
    /// encapsulation (draft "Resumption Tickets"). A ticket links the queries it resumes to each other: off, each
    /// query has an encapsulation of its own. Default: off.
    pub resume: bool,
}

impl Default for Options {
    fn default() -> Self {
        Self {
            transport: Transport::Udp,
            tcp_fallback: true,
            tries: NonZeroU8::MIN.saturating_add(2),
            timeout: Duration::from_secs(5),
            edns_fallback: true,
            random_case: None,
            cookies: true,
            method: Method::Get,
            dnscrypt: DnsCryptOptions::default(),
        }
    }
}

/// What to do after an [`Exchange`] step.
#[derive(Debug)]
pub enum Progress {
    /// Send [`Exchange::wire`] over [`Exchange::transport`], then wait until [`Exchange::deadline`].
    Send(Exchange),
    /// Keep waiting until [`Exchange::deadline`]: what came in was not the response.
    Wait(Exchange),
    /// The exchange is over.
    Done(Result<Response, Failure>),
}

/// The response that ended an exchange.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct Response {
    /// The response, as received.
    pub wire: Vec<u8>,
    /// The last query sent, the one this answers.
    pub query: Vec<u8>,
    /// The transport it came over.
    pub transport: Transport,
    /// The time from sending the last query to receiving this.
    pub rtt: Duration,
    /// Queries sent in all, over both transports.
    pub sends: u16,
    /// The cookie the server returned, its client cookie checked: send it in the next query to this server
    /// (RFC 7873 §5.3). Absent when the query had no cookie.
    pub cookie: Option<Cookie>,
    /// Over [`Transport::Https`], the HTTP response the DNS response came in; [`Client::exchange`](crate::client::Client::exchange)
    /// sets it.
    pub http: Option<Http>,
    /// Over `DNSCrypt`, the certificate the query was encrypted under; `Client::exchange_dnscrypt` sets it (D98).
    pub dnscrypt: Option<CertificateInfo>,
}

/// A `DNSCrypt` certificate, as a response or a listing of the resolver's certificates tells it (draft "Certificates",
/// D98).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CertificateInfo {
    /// The `<es-version>`: 1 for `X25519-XSalsa20Poly1305`, 2 for `X25519-XChaCha20Poly1305`, 3 for `X-Wing-XChaCha20Poly1305`.
    pub es_version: u16,
    /// The `<serial>`: a higher one is a newer certificate.
    pub serial: u32,
    /// The `<ts-start>`, in seconds since 1970.
    pub valid_from: u32,
    /// The `<ts-end>`, in seconds since 1970.
    pub valid_until: u32,
}

/// The HTTP response a DNS response came in (RFC 8484 §4.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Http {
    /// The HTTP version: HTTP/3, the one version there is (D83).
    pub version: http::Version,
    /// The status, 2xx for a DNS response.
    pub status: http::StatusCode,
}

impl Http {
    /// The version as HTTP names it: `HTTP/3`, `HTTP/1.1`.
    #[must_use]
    pub fn version_name(&self) -> &'static str {
        [
            (http::Version::HTTP_09, "HTTP/0.9"),
            (http::Version::HTTP_10, "HTTP/1.0"),
            (http::Version::HTTP_11, "HTTP/1.1"),
            (http::Version::HTTP_2, "HTTP/2"),
            (http::Version::HTTP_3, "HTTP/3"),
        ]
        .into_iter()
        .find_map(|(version, name)| (version == self.version).then_some(name))
        .unwrap_or("HTTP")
    }
}

/// Why an exchange ended without a response.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum Failure {
    /// No response to any of the tries.
    #[error("no response after {sends} queries")]
    TimedOut {
        /// Queries sent in all.
        sends: u16,
    },
    /// No response to any of the tries but responses dropped for their cookie (RFC 7873 §5.3), as a packet
    /// cache answering with an earlier client's cookie does.
    #[error(
        "no response after {sends} queries, responses with a wrong cookie dropped (RFC 7873 §5.3)"
    )]
    Forged {
        /// Queries sent in all.
        sends: u16,
    },
    /// A query changed by a fallback could not be encoded.
    #[error("cannot encode the query")]
    Encode(#[from] EncodeError),
}

/// How many queries a fallback changes at most: TC to TCP, EDNS dropped, and two BADCOOKIE (D27).
pub const SPARE_IDS: usize = 4;

/// What an exchange knows of the server's EDNS (RFC 6891 §7, D114).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum EdnsState {
    /// No response yet: a FORMERR or NOTIMP with the question and no OPT record drops EDNS.
    Untested,
    /// A response had an OPT record: the server knows EDNS, and no response drops it.
    Known,
    /// EDNS was dropped from the query.
    Dropped,
}

/// One query to one server: retries, response matching, and the TCP, EDNS and cookie fallbacks (D27).
#[derive(Debug)]
pub struct Exchange {
    server: SocketAddr,
    options: Options,
    query: Message<'static>,
    wire: Vec<u8>,
    transport: Transport,
    sent_at: Instant,
    deadline: Instant,
    sends: u16,
    timeouts: u8,
    edns: EdnsState,
    /// The IDs of the queries changed by a fallback, in the order of use (D114).
    spare_ids: std::array::IntoIter<u16, SPARE_IDS>,
    bad_cookies: u8,
    /// Whether a response was dropped for its cookie.
    forged: bool,
}

impl Exchange {
    /// Starts an exchange: send [`Exchange::wire`] now. The ID, and the cookie when the query has EDNS, are the
    /// caller's, as are the random bits of [`Options::random_case`] and the `spare_ids`, random as well: a query
    /// changed by a fallback goes with the next of them, in place of the ID before (RFC 5452 §9.2, D114). Over
    /// QUIC and HTTPS, the ID is 0, the stream or the HTTP exchange telling the response (RFC 9250 §4.2.1,
    /// RFC 8484 §4.1).
    ///
    /// # Errors
    ///
    /// [`EncodeError`] when the query cannot be encoded.
    pub fn start(
        query: Message<'_>,
        server: SocketAddr,
        options: Options,
        spare_ids: [u16; SPARE_IDS],
        now: Instant,
    ) -> Result<Self, EncodeError> {
        let mut query = query.into_owned();
        if streamed(options.transport) {
            query.header.id = 0;
        }
        if let Some(bits) = &options.random_case {
            for question in &mut query.questions {
                question.name = random_case(&question.name, bits);
            }
        }
        let wire = encode(&mut query, options.transport)?;
        Ok(Self {
            server,
            transport: options.transport,
            deadline: after(now, options.timeout),
            options,
            query,
            wire,
            sent_at: now,
            sends: 1,
            timeouts: 0,
            edns: EdnsState::Untested,
            spare_ids: spare_ids.into_iter(),
            bad_cookies: 0,
            forged: false,
        })
    }

    /// The query to send.
    #[must_use]
    pub fn wire(&self) -> &[u8] {
        &self.wire
    }

    /// The transport to send it over.
    #[must_use]
    pub const fn transport(&self) -> Transport {
        self.transport
    }

    /// The server queried.
    #[must_use]
    pub const fn server(&self) -> SocketAddr {
        self.server
    }

    /// When to give up waiting for a response to the last query sent.
    #[must_use]
    pub const fn deadline(&self) -> Instant {
        self.deadline
    }

    /// Queries sent so far, the one to send included.
    #[must_use]
    pub const fn sends(&self) -> u16 {
        self.sends
    }

    /// The cookie the query sends: the caller's, or the fresh one of a BADCOOKIE response, worth keeping even if
    /// the exchange then fails (RFC 7873 §5.3).
    #[must_use]
    pub fn cookie(&self) -> Option<Cookie> {
        cookie_in(&self.query)
    }

    /// Takes a message received at `now` over `transport` from `from`.
    ///
    /// A message that is not the response is dropped and the wait goes on (RFC 5452 §9.1): over another transport,
    /// from another address over UDP, unreadable, not a response, or with another ID, opcode or question; with
    /// cookies, one without the client cookie sent or, once the server sent a cookie, without one (RFC 7873 §5.3).
    /// The question may be missing from FORMERR and NOTIMP only; such a response is the response, and never drops
    /// EDNS (D114).
    ///
    /// A truncated response moves the query to TCP, FORMERR or NOTIMP with the question and no OPT record drops
    /// EDNS, unless the server sent an OPT record before, and BADCOOKIE with a cookie sends it again with that
    /// cookie. The changed query goes with a spare ID.
    #[must_use]
    pub fn receive(
        mut self,
        from: SocketAddr,
        transport: Transport,
        bytes: Vec<u8>,
        now: Instant,
    ) -> Progress {
        trace!(server = %self.server, %from, ?transport, len = bytes.len(), "received");
        if transport != self.transport || (transport == Transport::Udp && from != self.server) {
            debug!(server = %self.server, %from, ?transport, "dropped: from another address or over another transport");
            return Progress::Wait(self);
        }
        // Checked as `Message::decode` checks, without building the message: the caller decodes it if it wants.
        let Ok(response) = Query::read(&bytes) else {
            debug!(server = %self.server, "dropped: unreadable");
            return Progress::Wait(self);
        };
        let rcode = response.rcode();
        if !self.answers(&response, rcode) {
            debug!(server = %self.server, id = response.header().id, "dropped: not the response (QR, ID, opcode or question)");
            return Progress::Wait(self);
        }
        let Ok(cookie) = self.cookie_of(&response) else {
            debug!(server = %self.server, "dropped: without the client cookie sent, or the server cookie");
            self.forged = true;
            return Progress::Wait(self);
        };
        if response.edns().is_some() && self.edns == EdnsState::Untested {
            self.edns = EdnsState::Known;
        }
        if self.options.tcp_fallback
            && response.header().flags.contains(Flags::TC)
            && self.transport == Transport::Udp
        {
            debug!(server = %self.server, "truncated: asking again over TCP");
            return self.send_changed(Transport::Tcp, now);
        }
        if self.options.edns_fallback
            && self.edns == EdnsState::Untested
            && self.query.edns.is_some()
            && response.question().is_some()
            && (rcode == Rcode::FORMERR || rcode == Rcode::NOTIMP)
        {
            debug!(server = %self.server, %rcode, "no EDNS in the response: asking again without EDNS");
            self.edns = EdnsState::Dropped;
            self.query.edns = None;
            let transport = self.transport;
            return self.send_changed(transport, now);
        }
        if rcode == Rcode::BADCOOKIE
            && self.bad_cookies < 2
            && let Some(fresh) = cookie
        {
            // RFC 7873 §5.3: retry with the fresh server cookie, then over TCP.
            self.bad_cookies += 1;
            self.set_cookie(fresh);
            let transport = if self.bad_cookies == 2 && self.transport == Transport::Udp {
                Transport::Tcp
            } else {
                self.transport
            };
            debug!(server = %self.server, ?transport, "BADCOOKIE: asking again with the server cookie");
            return self.send_changed(transport, now);
        }
        Progress::Done(Ok(Response {
            wire: bytes,
            query: self.wire,
            transport,
            rtt: now.saturating_duration_since(self.sent_at),
            sends: self.sends,
            cookie,
            http: None,
            dnscrypt: None,
        }))
    }

    /// Notes the time: past the deadline, the query is sent again, or the exchange fails once all tries are spent,
    /// [`Failure::Forged`] when a response was dropped for its cookie. EDNS stays (RFC 8906 §3).
    #[must_use]
    pub fn time_out(mut self, now: Instant) -> Progress {
        if now < self.deadline {
            return Progress::Wait(self);
        }
        self.timeouts += 1;
        if self.timeouts >= self.options.tries.get() {
            debug!(server = %self.server, sends = self.sends, "timed out: no try left");
            let sends = self.sends;
            return Progress::Done(Err(if self.forged {
                Failure::Forged { sends }
            } else {
                Failure::TimedOut { sends }
            }));
        }
        debug!(server = %self.server, sends = self.sends, "timed out: asking again");
        self.sent(now);
        Progress::Send(self)
    }

    /// Notes that the try ended at `now` with no response to come, a socket error or a connection slower than the
    /// timeout: as past the deadline.
    #[must_use]
    pub fn lose(mut self, now: Instant) -> Progress {
        self.deadline = self.deadline.min(now);
        self.time_out(now)
    }

    /// Whether `response` answers the query: QR, ID, opcode and questions (RFC 5452 §9.1).
    fn answers(&self, response: &Query<'_>, rcode: Rcode) -> bool {
        let header = response.header();
        if !header.flags.contains(Flags::QR)
            || header.id != self.query.header.id
            || header.opcode != self.query.header.opcode
        {
            return false;
        }
        let several = response
            .violations()
            .contains(&Violation::MultipleQuestions);
        match (response.question(), self.query.questions.as_slice()) {
            (None, []) => true,
            (None, _) => rcode == Rcode::FORMERR || rcode == Rcode::NOTIMP,
            (Some(got), [sent]) => {
                !several && same_question(got, sent, self.options.random_case.is_some())
            }
            (Some(_), _) => false,
        }
    }

    /// The cookie of `response`, or `Err` when it must be dropped (RFC 7873 §5.3): the first COOKIE option counts.
    fn cookie_of(&self, response: &Query<'_>) -> Result<Option<Cookie>, Forged> {
        let Some(sent) = cookie_in(&self.query) else {
            return Ok(None);
        };
        let first = response
            .edns()
            .into_iter()
            .flat_map(EdnsView::options)
            .find(|option| option.code() == OptionCode::COOKIE);
        match first {
            Some(EdnsOption::Cookie(got)) if got.client() == sent.client() => Ok(Some(got)),
            // A wrong client cookie, or an invalid length (kept as an unknown option).
            Some(_) => Err(Forged),
            None if sent.server().is_some() => Err(Forged),
            None => Ok(None),
        }
    }

    /// Replaces the cookie of the query.
    fn set_cookie(&mut self, cookie: Cookie) {
        let options = self
            .query
            .edns
            .iter_mut()
            .flat_map(|edns| &mut edns.options);
        for option in options {
            if let EdnsOption::Cookie(sent) = option {
                *sent = cookie;
            }
        }
    }

    /// Sends the changed query over `transport`, with the next spare ID (RFC 5452 §9.2), so that a late response
    /// to the query before cannot end the exchange: it would not answer the changed query. A spare ID equal to the
    /// one before, or none left, which four changes at most never use up, is the next one after it.
    fn send_changed(mut self, transport: Transport, now: Instant) -> Progress {
        if !streamed(transport) {
            let before = self.query.header.id;
            self.query.header.id = self
                .spare_ids
                .next()
                .filter(|&id| id != before)
                .unwrap_or_else(|| before.wrapping_add(1));
        }
        match encode(&mut self.query, transport) {
            Ok(wire) => {
                self.wire = wire;
                self.transport = transport;
                self.sent(now);
                Progress::Send(self)
            }
            Err(error) => Progress::Done(Err(error.into())),
        }
    }

    /// Notes a query sent at `now`.
    fn sent(&mut self, now: Instant) {
        self.sends = self.sends.saturating_add(1);
        self.sent_at = now;
        self.deadline = after(now, self.options.timeout);
    }
}

/// A response to drop for its cookie.
struct Forged;

/// `wait` after `at`, a wait too long for an [`Instant`] cut to a century: a deadline that never comes.
pub(crate) fn after(at: Instant, wait: Duration) -> Instant {
    const CENTURY: Duration = Duration::from_hours(100 * 365 * 24);
    at + wait.min(CENTURY)
}

/// The block length padded queries fill (RFC 8467 §4.1).
const PADDING_BLOCK: usize = 128;

/// The code and length of an EDNS option, before its data (RFC 6891 §6.1.2).
const OPTION_HEAD: usize = 4;

/// Encodes `query` for `transport`, with the options of a query with EDNS fitted to it; those the caller put in
/// are replaced. Over TCP and TLS, an empty edns-tcp-keepalive, so the server may tell how long to keep the
/// connection; over UDP, QUIC and HTTPS, none (RFC 7828 §3.2.1, RFC 7858 §3.4, RFC 9250 §5.5.2, RFC 8484 §9).
/// Over TLS, QUIC and HTTPS, padding to a multiple of [`PADDING_BLOCK`] bytes, so the length tells less of the name (RFC 7830, RFC 8467
/// §4.1, RFC 9250 §5.4).
fn encode(query: &mut Message<'_>, transport: Transport) -> Result<Vec<u8>, EncodeError> {
    let Some(edns) = &mut query.edns else {
        return query.to_vec();
    };
    edns.options.retain(|option| match option {
        EdnsOption::Keepalive(_) => false,
        EdnsOption::Padding(_) => !padded(transport),
        _ => true,
    });
    if matches!(transport, Transport::Tcp | Transport::Tls) {
        edns.options.push(EdnsOption::Keepalive(None));
    }
    let wire = query.to_vec()?;
    if !padded(transport) {
        return Ok(wire);
    }
    let short = (wire.len() + OPTION_HEAD) % PADDING_BLOCK;
    let padding =
        u16::try_from((PADDING_BLOCK - short) % PADDING_BLOCK).expect("less than PADDING_BLOCK");
    if let Some(edns) = &mut query.edns {
        edns.options.push(EdnsOption::Padding(padding));
    }
    query.to_vec()
}

/// Whether queries over `transport` are padded: those encrypted, but for Oblivious `DoH`, which pads inside its
/// encryption instead (RFC 9230 §6.1, D79).
const fn padded(transport: Transport) -> bool {
    matches!(
        transport,
        Transport::Tls | Transport::Quic | Transport::Https
    )
}

/// Whether each query has a stream, an HTTP exchange or a CoAP token of its own, which tells its response: the ID
/// is 0 (RFC 9250 §4.2.1, RFC 8484 §4.1, RFC 9953 §4.2.2; Oblivious `DoH` follows `DoH`, D79).
const fn streamed(transport: Transport) -> bool {
    matches!(
        transport,
        Transport::Quic | Transport::Https | Transport::Odoh | Transport::Coap
    )
}

/// The cookie `query` sends, if any.
fn cookie_in(query: &Message<'_>) -> Option<Cookie> {
    query
        .edns
        .iter()
        .flat_map(|edns| &edns.options)
        .find_map(|option| match option {
            EdnsOption::Cookie(cookie) => Some(*cookie),
            _ => None,
        })
}

/// Whether `got` repeats `sent`, the name in the same case when `exact`.
fn same_question(got: &Question<'_>, sent: &Question<'_>, exact: bool) -> bool {
    got.qtype == sent.qtype
        && got.qclass == sent.qclass
        && if exact {
            got.name.labels().eq(sent.name.labels())
        } else {
            got.name == sent.name
        }
}

/// `name` with the case of its letters from `bits`, one bit a letter in order.
fn random_case(name: &Name<'_>, bits: &[u8; 32]) -> Name<'static> {
    let mut letter = 0usize;
    let labels: Vec<Vec<u8>> = name
        .labels()
        .map(|label| {
            label
                .iter()
                .map(|&byte| {
                    if !byte.is_ascii_alphabetic() {
                        return byte;
                    }
                    let bit = bits[letter / 8 % 32] >> (letter % 8) & 1;
                    letter += 1;
                    if bit == 1 {
                        byte.to_ascii_uppercase()
                    } else {
                        byte.to_ascii_lowercase()
                    }
                })
                .collect()
        })
        .collect();
    Name::from_labels(labels.iter().map(Vec::as_slice))
        .expect("the labels of a name, case changed, make the same valid name")
}
