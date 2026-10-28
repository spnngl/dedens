//! The exchange of one query with one server, without I/O (D26, D27).
//!
//! An [`Exchange`] holds the query and decides what happens next; its caller moves the bytes and keeps time.
//! It starts with a query to send, then takes each received message and each expired deadline, and answers with
//! a [`Progress`]: send the (possibly changed) query again, keep waiting, or done.
//!
//! ```
//! # use std::net::SocketAddr;
//! # use std::time::Instant;
//! # use dedens_net::exchange::{Exchange, Options, Progress, Transport};
//! # use dedens_proto::{Message, Name, Question, RecordType};
//! let server: SocketAddr = "192.0.2.53:53".parse()?;
//! let query = Message::query(0x1234, Question::new(Name::root(), RecordType::NS));
//! let now = Instant::now();
//! let exchange = Exchange::start(&query, server, Options::default(), now)?;
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

use dedens_proto::edns::{Cookie, EdnsOption, OptionCode};
use dedens_proto::{EncodeError, Flags, Message, Name, Question, Rcode};

/// The transport a query goes over.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Transport {
    /// UDP: a new connected socket on port 0 for each query sent (D27).
    Udp,
    /// TCP, each message behind its two-byte length (RFC 1035 §4.2.2).
    Tcp,
}

/// How an exchange behaves; the default is dig's (D27).
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct Options {
    /// The transport of the first query; UDP falls back to TCP on a truncated response. Default: UDP.
    pub transport: Transport,
    /// Queries sent before giving up when no response comes, the first one included. Default: 3.
    pub tries: NonZeroU8,
    /// How long to wait for a response to each query. Default: 5 s.
    pub timeout: Duration,
    /// Whether to query again without EDNS when a server answers an EDNS query with FORMERR or NOTIMP and no OPT
    /// record (RFC 6891 §7). Never on a timeout (RFC 8906). Default: on.
    pub edns_fallback: bool,
    /// Random bits for `0x20` (draft-vixie-dnsext-dns0x20): when set, the case of each letter of the question
    /// names follows these bits, and a response must repeat the names in the same case. Default: off.
    pub random_case: Option<[u8; 32]>,
}

impl Default for Options {
    fn default() -> Self {
        Self {
            transport: Transport::Udp,
            tries: NonZeroU8::MIN.saturating_add(2),
            timeout: Duration::from_secs(5),
            edns_fallback: true,
            random_case: None,
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
    /// A query changed by a fallback could not be encoded.
    #[error("cannot encode the query: {0}")]
    Encode(#[from] EncodeError),
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
    edns_dropped: bool,
    bad_cookies: u8,
}

impl Exchange {
    /// Starts an exchange: send [`Exchange::wire`] now. The ID, and the cookie when the query has EDNS, are the
    /// caller's, as are the random bits of [`Options::random_case`].
    ///
    /// # Errors
    ///
    /// [`EncodeError`] when the query cannot be encoded.
    pub fn start(
        query: &Message<'_>,
        server: SocketAddr,
        options: Options,
        now: Instant,
    ) -> Result<Self, EncodeError> {
        let mut query = query.clone().into_owned();
        if let Some(bits) = &options.random_case {
            for question in &mut query.questions {
                question.name = random_case(&question.name, bits);
            }
        }
        let wire = encode(&mut query, options.transport)?;
        Ok(Self {
            server,
            transport: options.transport,
            deadline: now + options.timeout,
            options,
            query,
            wire,
            sent_at: now,
            sends: 1,
            timeouts: 0,
            edns_dropped: false,
            bad_cookies: 0,
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

    /// Takes a message received at `now` over `transport` from `from`.
    ///
    /// A message that is not the response is dropped and the wait goes on (RFC 5452 §9.1): over another transport,
    /// from another address over UDP, unreadable, not a response, or with another ID, opcode or question; with
    /// cookies, one without the client cookie sent or, once the server sent a cookie, without one (RFC 7873 §5.3).
    /// The question may be missing from FORMERR and NOTIMP only.
    #[must_use]
    pub fn receive(
        mut self,
        from: SocketAddr,
        transport: Transport,
        bytes: &[u8],
        now: Instant,
    ) -> Progress {
        if transport != self.transport || (transport == Transport::Udp && from != self.server) {
            return Progress::Wait(self);
        }
        let Ok(decoded) = Message::decode(bytes) else {
            return Progress::Wait(self);
        };
        let response = &decoded.message;
        if !self.answers(response) {
            return Progress::Wait(self);
        }
        let Ok(cookie) = self.cookie_of(response) else {
            return Progress::Wait(self);
        };
        let rcode = response.rcode();
        if response.header.flags.contains(Flags::TC) && self.transport == Transport::Udp {
            return self.send_changed(Transport::Tcp, now);
        }
        if self.options.edns_fallback
            && !self.edns_dropped
            && self.query.edns.is_some()
            && response.edns.is_none()
            && (rcode == Rcode::FORMERR || rcode == Rcode::NOTIMP)
        {
            self.edns_dropped = true;
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
            let transport = if self.bad_cookies == 2 {
                Transport::Tcp
            } else {
                self.transport
            };
            return self.send_changed(transport, now);
        }
        Progress::Done(Ok(Response {
            wire: bytes.to_vec(),
            query: self.wire,
            transport,
            rtt: now.saturating_duration_since(self.sent_at),
            sends: self.sends,
            cookie,
        }))
    }

    /// Notes the time: past the deadline, the query is sent again, or the exchange fails once all tries are spent.
    /// EDNS stays (RFC 8906 §3).
    #[must_use]
    pub fn time_out(mut self, now: Instant) -> Progress {
        if now < self.deadline {
            return Progress::Wait(self);
        }
        self.timeouts += 1;
        if self.timeouts >= self.options.tries.get() {
            return Progress::Done(Err(Failure::TimedOut { sends: self.sends }));
        }
        self.sent(now);
        Progress::Send(self)
    }

    /// Whether `response` answers the query: QR, ID, opcode and questions (RFC 5452 §9.1).
    fn answers(&self, response: &Message<'_>) -> bool {
        let header = response.header;
        if !header.flags.contains(Flags::QR)
            || header.id != self.query.header.id
            || header.opcode != self.query.header.opcode
        {
            return false;
        }
        let rcode = response.rcode();
        if response.questions.is_empty() && (rcode == Rcode::FORMERR || rcode == Rcode::NOTIMP) {
            return true;
        }
        let exact = self.options.random_case.is_some();
        response.questions.len() == self.query.questions.len()
            && response
                .questions
                .iter()
                .zip(&self.query.questions)
                .all(|(got, sent)| same_question(got, sent, exact))
    }

    /// The cookie of `response`, or `Err` when it must be dropped (RFC 7873 §5.3): the first COOKIE option counts.
    fn cookie_of(&self, response: &Message<'_>) -> Result<Option<Cookie>, Forged> {
        let Some(sent) = cookie_in(&self.query) else {
            return Ok(None);
        };
        let first = response
            .edns
            .iter()
            .flat_map(|edns| &edns.options)
            .find(|option| option.code() == OptionCode::COOKIE);
        match first {
            Some(EdnsOption::Cookie(got)) if got.client() == sent.client() => Ok(Some(*got)),
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

    /// Sends the changed query over `transport`.
    fn send_changed(mut self, transport: Transport, now: Instant) -> Progress {
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
        self.deadline = now + self.options.timeout;
    }
}

/// A response to drop for its cookie.
struct Forged;

/// `query` as sent over `transport`: over TCP, EDNS carries an empty edns-tcp-keepalive so the server may tell how
/// long to keep the connection (RFC 7828 §3.2.1); over UDP, it must not.
fn encode(query: &mut Message<'static>, transport: Transport) -> Result<Vec<u8>, EncodeError> {
    let Some(edns) = query.edns.as_mut().filter(|edns| {
        transport == Transport::Tcp
            && !edns
                .options
                .iter()
                .any(|option| matches!(option, EdnsOption::Keepalive(_)))
    }) else {
        return query.to_vec();
    };
    edns.options.push(EdnsOption::Keepalive(None));
    let wire = query.to_vec();
    if let Some(edns) = &mut query.edns {
        edns.options.pop();
    }
    wire
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
