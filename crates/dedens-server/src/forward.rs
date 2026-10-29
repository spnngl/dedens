//! The forward stage: the client's question asked of upstream servers in turn (D41).

use std::fmt;
use std::net::SocketAddr;
use std::num::NonZeroU8;
use std::sync::Arc;
use std::time::Duration;

use dedens_proto::{Decoded, Flags, Message, Question, Rcode};

use crate::reply::Client;

/// Asks upstream servers the client's question, in order, until one answers usably.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Forward {
    /// Never empty.
    servers: Box<[Server]>,
    timeout: Duration,
    tries: NonZeroU8,
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
}

impl From<SocketAddr> for Server {
    fn from(addr: SocketAddr) -> Self {
        Self {
            addr,
            via: Via::Plain,
        }
    }
}

/// As written in `dedensd`'s configuration: `IP:PORT`, `tls://IP:PORT#NAME`, `quic://IP:PORT`.
impl fmt::Display for Server {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let (scheme, name) = match &self.via {
            Via::Plain => ("", None),
            Via::Tls(name) => ("tls://", name.as_deref()),
            Via::Quic(name) => ("quic://", name.as_deref()),
        };
        write!(f, "{scheme}{}", self.addr)?;
        match name {
            Some(name) => write!(f, "#{name}"),
            None => Ok(()),
        }
    }
}

/// The query asked upstream for the client's: its question, RD set (only queries asking for recursion get here,
/// and refreshes), the client's AD and CD bits (RFC 6840 §5.7-5.9), and our EDNS with its DO bit, none of its
/// options. The client subnet stays here (D41), and cookies are between us and upstream (RFC 7873 §5.1).
pub(crate) fn request(client: &Client<'_>, question: &Question<'_>) -> Message<'static> {
    let mut request = Message::query(0, question.clone().into_owned());
    request.header.flags = client.header.flags & (Flags::AD | Flags::CD) | Flags::RD;
    request.edns = Some(client.our_edns());
    request
}

/// Whether an upstream response answers the client, or the next server is asked: not when it breaks the protocol
/// (D9), is truncated, or says the server failed, refused, does not implement the query or did not understand it
/// (RFC 1035 §7.3).
pub(crate) fn usable(response: &Decoded<'_>) -> bool {
    let message = &response.message;
    response.violations.is_empty()
        && !message.header.flags.contains(Flags::TC)
        && !matches!(
            message.rcode(),
            Rcode::SERVFAIL | Rcode::REFUSED | Rcode::NOTIMP | Rcode::FORMERR
        )
}
