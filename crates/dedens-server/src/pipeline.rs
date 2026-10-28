//! The pipeline: the stages in order (D23), and the replies the core gives before any stage (D41).

use std::net::SocketAddr;

use dedens_proto::{Flags, Header, Message, Opcode, Query, Question, Rcode, RecordType};

use crate::forward::{self, Forward};
use crate::reply::{Client, Transport};

/// A stage of the pipeline (D23).
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum Stage {
    /// Asks upstream servers: the last stage a query reaches.
    Forward(Forward),
}

/// The stages a listener runs on each query, in order (D23); a query no stage answers is refused.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Pipeline {
    stages: Box<[Stage]>,
}

/// What to do next with a query.
#[derive(Debug)]
#[must_use]
pub enum Step<'p, 'q> {
    /// Send `out[..len]` to the client.
    Reply(usize),
    /// Send nothing: the bytes are a response or shorter than a header, or `out` cannot hold the reply.
    Drop,
    /// Send [`Upstream::request`] to [`Upstream::server`], then hand what comes back to [`Upstream::receive`].
    /// Boxed: a reply, the common step, stays small.
    Upstream(Box<Upstream<'p, 'q>>),
}

/// A query waiting for an upstream server's response.
#[derive(Debug)]
pub struct Upstream<'p, 'q> {
    client: Client<'q>,
    request: Message<'q>,
    server: SocketAddr,
    /// The servers to try after this one.
    rest: &'p [SocketAddr],
}

impl Pipeline {
    /// Runs `stages` in order.
    #[must_use]
    pub fn new(stages: Vec<Stage>) -> Self {
        Self {
            stages: stages.into(),
        }
    }

    /// Answers `wire`, a query that came over `transport`, writing any reply into `out`: at least 512 bytes, and
    /// 65535 for a reply over TCP to come whole.
    ///
    /// Before the stages, the core replies itself to what they cannot answer (D41): FORMERR to a query it cannot
    /// read, that breaks a rule (D9) or has no question (RFC 1035 §4.1.1, RFC 9619); NOTIMP to an opcode other
    /// than QUERY; BADVERS to an EDNS version above 0 (RFC 6891 §6.1.3); REFUSED to a zone transfer, which
    /// a forwarder does not do. Responses are dropped, never answered.
    pub fn query<'p, 'q>(
        &'p self,
        wire: &'q [u8],
        transport: Transport,
        out: &mut [u8],
    ) -> Step<'p, 'q> {
        let Ok(query) = Query::read(wire) else {
            return match Header::peek(wire) {
                Some(header) if !header.flags.contains(Flags::QR) => reply(
                    &Client::unread(header, transport),
                    Message::default(),
                    Rcode::FORMERR,
                    out,
                ),
                _ => Step::Drop,
            };
        };
        let header = query.header();
        if header.flags.contains(Flags::QR) {
            return Step::Drop;
        }
        let client = Client::of(&query, transport);
        let rcode = if !query.violations().is_empty() {
            Rcode::FORMERR
        } else if header.opcode != Opcode::QUERY {
            Rcode::NOTIMP
        } else if query.edns().is_some_and(|edns| edns.version > 0) {
            Rcode::BADVERS
        } else {
            match query.question() {
                None => Rcode::FORMERR,
                Some(question) if matches!(question.qtype, RecordType::AXFR | RecordType::IXFR) => {
                    Rcode::REFUSED
                }
                Some(question) => return self.run(client, question.clone(), out),
            }
        };
        reply(&client, Message::default(), rcode, out)
    }

    /// Runs the stages on a query that passed the core's checks.
    fn run<'p, 'q>(
        &'p self,
        client: Client<'q>,
        question: Question<'q>,
        out: &mut [u8],
    ) -> Step<'p, 'q> {
        if let Some(stage) = self.stages.first() {
            match stage {
                Stage::Forward(forward) => {
                    return Step::Upstream(Box::new(Upstream {
                        request: forward::request(&client, question),
                        client,
                        server: forward.first(),
                        rest: forward.rest(),
                    }));
                }
            }
        }
        reply(&client, Message::default(), Rcode::REFUSED, out)
    }
}

impl<'p, 'q> Upstream<'p, 'q> {
    /// The query to send; its ID is the transport's to pick at random (D27).
    #[must_use]
    pub const fn request(&self) -> &Message<'q> {
        &self.request
    }

    /// The server to send it to.
    #[must_use]
    pub const fn server(&self) -> SocketAddr {
        self.server
    }

    /// Takes the server's `response`, matched to the request by the transport (`dedens_net` checks its ID and
    /// question), or `None` when none came. A usable one is the reply, written into `out` as
    /// [`Pipeline::query`] writes; otherwise the next server is asked, and SERVFAIL is the reply after the last
    /// (D41).
    pub fn receive(mut self: Box<Self>, response: Option<&[u8]>, out: &mut [u8]) -> Step<'p, 'q> {
        if let Some(decoded) = response
            .and_then(|wire| Message::decode(wire).ok())
            .filter(forward::usable)
        {
            let rcode = decoded.message.rcode();
            return reply(&self.client, decoded.message, rcode, out);
        }
        match self.rest.split_first() {
            Some((&server, rest)) => {
                self.server = server;
                self.rest = rest;
                Step::Upstream(self)
            }
            None => reply(&self.client, Message::default(), Rcode::SERVFAIL, out),
        }
    }
}

/// The reply to `client`: `message` with `rcode`.
fn reply<'p, 'q, 'a>(
    client: &Client<'a>,
    message: Message<'a>,
    rcode: Rcode,
    out: &mut [u8],
) -> Step<'p, 'q> {
    client
        .reply(message, rcode, out)
        .map_or(Step::Drop, Step::Reply)
}
