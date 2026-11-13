//! The forward stage: the client's question asked of upstream servers in turn (D41).

use std::fmt;
use std::net::SocketAddr;
use std::num::NonZeroU8;
use std::sync::Arc;
use std::time::Duration;

use dedens_proto::edns::{Edns, EdnsFlags};
use dedens_proto::{Decoded, Flags, Message, Opcode, Question, Rcode};

use crate::reply::Client;
use crate::validate::Validating;

/// Asks upstream servers the client's question, in order, until one answers usably.
#[derive(Debug, Clone)]
pub struct Forward {
    /// Never empty.
    servers: Box<[Server]>,
    timeout: Duration,
    tries: NonZeroU8,
    validation: Option<Validating>,
}

impl Forward {
    /// How long each query to a server waits for its response, by default.
    pub const TIMEOUT: Duration = Duration::from_secs(3);
    /// How many queries a server is sent before the next is asked, by default.
    pub const TRIES: NonZeroU8 = NonZeroU8::new(2).expect("two is not zero");

    /// Forwards to `servers`, tried in order, each [`Forward::TRIES`] times waiting [`Forward::TIMEOUT`]; `None`
    /// without any.
    #[must_use]
    pub fn new(servers: impl IntoIterator<Item = impl Into<Server>>) -> Option<Self> {
        let servers: Box<[Server]> = servers.into_iter().map(Into::into).collect();
        (!servers.is_empty()).then_some(Self {
            servers,
            timeout: Self::TIMEOUT,
            tries: Self::TRIES,
            validation: None,
        })
    }

    /// Waits `timeout` for each response.
    #[must_use]
    pub const fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    /// Sends each server `tries` queries.
    #[must_use]
    pub const fn with_tries(mut self, tries: NonZeroU8) -> Self {
        self.tries = tries;
        self
    }

    /// Validates what the servers answer (D77): AD is set by the verdict alone, a bogus answer is SERVFAIL, and
    /// the validator's questions go to the servers too.
    #[must_use]
    pub fn validating(mut self, validation: Validating) -> Self {
        self.validation = Some(validation);
        self
    }

    /// Whether [`Forward::validating`] was set.
    #[must_use]
    pub const fn validates(&self) -> bool {
        self.validation.is_some()
    }

    /// The [`Validating::tagged`] name of the validation, `None` when the stage does not validate.
    #[must_use]
    pub fn validation_tag(&self) -> Option<&str> {
        self.validation.as_ref().map(Validating::tag)
    }

    /// The validation of the stage, `None` when it does not validate.
    #[must_use]
    pub const fn validation(&self) -> Option<&Validating> {
        self.validation.as_ref()
    }

    /// How long each query waits, and how many each server is sent.
    pub(crate) const fn patience(&self) -> (Duration, NonZeroU8) {
        (self.timeout, self.tries)
    }

    /// The servers, in the order they are asked; the first always exists.
    pub(crate) fn servers(&self) -> &[Server] {
        &self.servers
    }
}

/// An upstream server: its address, and how it is asked (D65).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Server {
    /// Its address.
    pub addr: SocketAddr,
    /// The transport it is asked over.
    pub via: Via,
}

/// The transport an upstream server is asked over (D65).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum Via {
    /// The client's: UDP for a query over UDP, TCP for one over a connection.
    Plain,
    /// TLS (RFC 7858), the server's certificate holding the name, else its address (RFC 8310 §8.1). Shared, so
    /// that an upstream query holds it without a copy.
    Tls(Option<Arc<str>>),
    /// QUIC (RFC 9250), the certificate checked as over TLS.
    Quic(Option<Arc<str>>),
    /// DNS over HTTPS over HTTP/3 (RFC 8484, RFC 9114), the certificate checked as over TLS (D84).
    Https {
        /// The name the certificate must hold, else the address.
        name: Option<Arc<str>>,
        /// The URI template's path, `{?dns}` implied (RFC 8484 §3), starting with `/`.
        path: Arc<str>,
    },
    /// A `DNSCrypt` resolver (draft-denis-dprive-dnscrypt), its provider name and keys those of the stamp, as the
    /// `sdns://` text `dedensd` checked when it read the configuration: this crate has no network code, and the
    /// text is parsed again where the query is sent, as the path of an HTTPS server is (D99).
    Dnscrypt(Arc<str>),
}

impl From<SocketAddr> for Server {
    fn from(addr: SocketAddr) -> Self {
        Self {
            addr,
            via: Via::Plain,
        }
    }
}

/// As written in `dedensd`'s configuration: `IP:PORT`, `tls://IP:PORT#NAME`, `quic://IP:PORT`,
/// `https://IP:PORT/PATH#NAME`, the `sdns://` stamp of a `DNSCrypt` server.
impl fmt::Display for Server {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let (scheme, name, path) = match &self.via {
            Via::Dnscrypt(stamp) => return f.write_str(stamp),
            Via::Plain => ("", None, ""),
            Via::Tls(name) => ("tls://", name.as_deref(), ""),
            Via::Quic(name) => ("quic://", name.as_deref(), ""),
            Via::Https { name, path } => ("https://", name.as_deref(), &**path),
        };
        write!(f, "{scheme}{}{path}", self.addr)?;
        match name {
            Some(name) => write!(f, "#{name}"),
            None => Ok(()),
        }
    }
}

/// The query asked upstream for the client's: its question, RD set (only queries asking for recursion get here,
/// and refreshes), the client's AD and CD bits (RFC 6840 §5.7-5.9), and our EDNS with its DO bit, none of its
/// options. The client subnet stays here (D41), and cookies are between us and upstream (RFC 7873 §5.1).
///
/// Validating (D77), the query is the one of [`probe`]: our own validation needs the signatures, and the client's
/// bits are for the reply.
pub(crate) fn request(
    client: &Client<'_>,
    question: &Question<'_>,
    validating: bool,
) -> Message<'static> {
    if validating {
        return probe(question);
    }
    let mut request = Message::query(0, question.clone().into_owned());
    request.header.flags = client.header.flags & (Flags::AD | Flags::CD) | Flags::RD;
    request.edns = Some(client.our_edns());
    request
}

/// A query of the validator's (D77): RD, DO to get the signatures and CD so that a response failing validation
/// still comes (RFC 6840 §5.9), our EDNS and none of the client's.
pub(crate) fn probe(question: &Question<'_>) -> Message<'static> {
    let mut request = Message::query(0, question.clone().into_owned());
    request.header.flags = Flags::RD | Flags::CD;
    request.edns = Some(Edns {
        flags: EdnsFlags::DO,
        ..Edns::default()
    });
    request
}

/// Whether an upstream response answers `asked`, the question sent, or the next server is asked (D111): not when
/// it is no response to it (QR clear, an opcode other than QUERY, any other question than `asked`, the name in
/// any case, RFC 4343 §4; RFC 5452 §9.1), as a transport drops one, but one of tomorrow may not; nor when it
/// breaks the protocol (D9) or is truncated. Its RCODE must be NOERROR, NXDOMAIN or YXDOMAIN (RFC 6672 §2.2): any
/// other, SERVFAIL, REFUSED, NOTIMP, FORMERR, an update code or an extended one from the server's own OPT record
/// (BADVERS, BADCOOKIE, RFC 6891 §6.1.3), speaks of the server or of our query, not of the client's (RFC 1035
/// §7.3). The ID is the transport's to check: it picks it (D27).
pub(crate) fn usable(response: &Decoded<'_>, asked: &Question<'_>) -> bool {
    let message = &response.message;
    message.header.flags.contains(Flags::QR)
        && message.header.opcode == Opcode::QUERY
        && matches!(message.questions.as_slice(), [got] if got == asked)
        && response.violations.is_empty()
        && !message.header.flags.contains(Flags::TC)
        && matches!(
            message.rcode(),
            Rcode::NOERROR | Rcode::NXDOMAIN | Rcode::YXDOMAIN
        )
}
