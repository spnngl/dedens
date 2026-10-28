//! The forward stage: the client's question asked of upstream servers in turn (D41).

use std::net::SocketAddr;

use dedens_proto::{Decoded, Flags, Message, Question, Rcode};

use crate::reply::Client;

/// Asks upstream servers the client's question, in order, until one answers usably.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Forward {
    first: SocketAddr,
    rest: Box<[SocketAddr]>,
}

impl Forward {
    /// Forwards to `servers`, tried in order; `None` without any.
    #[must_use]
    pub fn new(servers: &[SocketAddr]) -> Option<Self> {
        let (&first, rest) = servers.split_first()?;
        Some(Self {
            first,
            rest: rest.into(),
        })
    }

    /// The server asked first.
    pub(crate) const fn first(&self) -> SocketAddr {
        self.first
    }

    /// The servers asked after it, in order.
    pub(crate) fn rest(&self) -> &[SocketAddr] {
        &self.rest
    }
}

/// The query asked upstream for the client's: its question, RD and CD bits, and our EDNS with its DO bit, none
/// of its options. The client subnet stays here (D41), and cookies are between us and upstream (RFC 7873 §5.1).
pub(crate) fn request<'q>(client: &Client<'q>, question: Question<'q>) -> Message<'q> {
    let mut request = Message::query(0, question);
    request.header.flags =
        Flags::from_word(client.header.flags.bits() & (Flags::RD | Flags::CD).bits());
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
