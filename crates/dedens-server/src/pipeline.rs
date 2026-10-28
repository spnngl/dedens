//! The pipeline: the stages in order (D23), and the replies the core gives before any stage (D41).

use std::net::SocketAddr;

use dedens_cache::{Cache, Key};
use dedens_proto::{Flags, Header, Message, Opcode, Query, Rcode, RecordType};

use crate::cache::{self, Looked};
use crate::forward::{self, Forward};
use crate::reply::{Client, Transport};

/// A stage of the pipeline (D23).
#[derive(Debug)]
#[non_exhaustive]
pub enum Stage {
    /// Answers from the cache, stores what a later stage asked upstream, and holds failures (D43).
    Cache(Cache),
    /// Asks upstream servers: the last stage a query reaches.
    Forward(Forward),
}

/// The stages a listener runs on each query, in order (D23); a query no stage answers is refused.
#[derive(Debug, Default)]
pub struct Pipeline {
    stages: Box<[Stage]>,
}

/// What to do next with a query.
#[derive(Debug)]
#[must_use]
pub enum Step {
    /// Send `out[..len]` to the client.
    Reply(usize),
    /// Send nothing: the bytes are a response or shorter than a header, or `out` cannot hold the reply.
    Drop,
    /// Send [`Upstream::request`] to [`Upstream::server`], then hand what comes back to [`Pipeline::receive`].
    /// Boxed: a reply, the common step, stays small.
    Upstream(Box<Upstream>),
    /// Send `out[..len]` to the client, then refresh the cache as for [`Step::Upstream`]: it ends without a reply.
    Refresh(usize, Box<Upstream>),
}

/// A query waiting for an upstream server's response; it owns what it needs, so that it outlives the buffers of
/// the query.
#[derive(Debug)]
pub struct Upstream {
    /// The client's query, read again for the reply.
    query: Box<[u8]>,
    transport: Transport,
    request: Message<'static>,
    server: SocketAddr,
    /// The forward stage, its next server, and the cache stage before it.
    forward: usize,
    next: usize,
    cache: Option<usize>,
    /// Only refresh the cache: no reply.
    refresh: bool,
}

impl Pipeline {
    /// Runs `stages` in order.
    #[must_use]
    pub fn new(stages: Vec<Stage>) -> Self {
        Self {
            stages: stages.into(),
        }
    }

    /// Answers `wire`, a query that came over `transport` at `now` (seconds, any monotonic origin), writing any
    /// reply into `out`: at least 512 bytes, and 65535 for a reply over TCP to come whole.
    ///
    /// Before the stages, the core replies itself to what they cannot answer (D41): FORMERR to a query it cannot
    /// read, that breaks a rule (D9) or has no question (RFC 1035 §4.1.1, RFC 9619); NOTIMP to an opcode other
    /// than QUERY; BADVERS to an EDNS version above 0 (RFC 6891 §6.1.3); REFUSED to a zone transfer, which
    /// a forwarder does not do. Responses are dropped, never answered.
    pub fn query(&self, wire: &[u8], transport: Transport, now: u32, out: &mut [u8]) -> Step {
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
                Some(_) => return self.run(wire, &query, &client, now, out),
            }
        };
        reply(&client, Message::default(), rcode, out)
    }

    /// Runs the stages on a query that passed the core's checks.
    fn run(
        &self,
        wire: &[u8],
        query: &Query<'_>,
        client: &Client<'_>,
        now: u32,
        out: &mut [u8],
    ) -> Step {
        let mut cache = None;
        for (index, stage) in self.stages.iter().enumerate() {
            match stage {
                Stage::Cache(stored) => match cache::look(stored, query, client, now, out) {
                    Looked::Reply { len, refresh } => {
                        return match self.upstream(index, wire, query, client, Some(index)) {
                            Some(mut upstream) if refresh => {
                                upstream.refresh = true;
                                Step::Refresh(len, upstream)
                            }
                            _ => Step::Reply(len),
                        };
                    }
                    Looked::Failed => {
                        return reply(client, Message::default(), Rcode::SERVFAIL, out);
                    }
                    Looked::Miss => cache = Some(index),
                },
                Stage::Forward(_) => {
                    return self
                        .upstream(index, wire, query, client, cache)
                        .map_or(Step::Drop, Step::Upstream);
                }
            }
        }
        reply(client, Message::default(), Rcode::REFUSED, out)
    }

    /// The upstream query of the first forward stage from `from` on, storing into the stage `cache`.
    fn upstream(
        &self,
        from: usize,
        wire: &[u8],
        query: &Query<'_>,
        client: &Client<'_>,
        cache: Option<usize>,
    ) -> Option<Box<Upstream>> {
        let (forward, servers) =
            self.stages
                .iter()
                .enumerate()
                .skip(from)
                .find_map(|(index, stage)| match stage {
                    Stage::Forward(forward) => Some((index, forward.servers())),
                    Stage::Cache(_) => None,
                })?;
        Some(Box::new(Upstream {
            query: wire.into(),
            transport: client.transport,
            request: forward::request(client, query.question()?),
            server: *servers.first()?,
            forward,
            next: 1,
            cache,
            refresh: false,
        }))
    }

    /// Takes the server's `response` to `upstream`, received at `now` and matched to the request by the transport
    /// (`dedens_net` checks its ID and question), or `None` when none came. A usable one is stored in the cache
    /// stage before, if any, and is the reply, written into `out` as [`Pipeline::query`] writes; otherwise the
    /// next server is asked. After the last, the failure is held in the cache, and the reply is the expired data it
    /// keeps, or SERVFAIL (D41, D43). Returns [`Step::Reply`], [`Step::Drop`] or [`Step::Upstream`]; a refresh
    /// ends in [`Step::Drop`].
    ///
    /// `upstream` comes from this pipeline.
    pub fn receive(
        &self,
        mut upstream: Box<Upstream>,
        response: Option<&[u8]>,
        now: u32,
        out: &mut [u8],
    ) -> Step {
        // Read once already: this reads it again.
        let Ok(query) = Query::read(&upstream.query) else {
            return Step::Drop;
        };
        let client = Client::of(&query, upstream.transport);
        let cache = upstream
            .cache
            .and_then(|index| match self.stages.get(index) {
                Some(Stage::Cache(cache)) => Some(cache),
                _ => None,
            });
        if let Some(decoded) = response
            .and_then(|wire| Message::decode(wire).ok())
            .filter(forward::usable)
        {
            if let Some(cache) = cache {
                // Some responses are not stored (RFC 2308, D22): the reply goes out all the same.
                let _ = cache.insert(&query, &decoded, now);
            }
            if upstream.refresh {
                return Step::Drop;
            }
            let rcode = decoded.message.rcode();
            return reply(&client, decoded.message, rcode, out);
        }
        let next = match self.stages.get(upstream.forward) {
            Some(Stage::Forward(forward)) => forward.servers().get(upstream.next).copied(),
            _ => None,
        };
        if let Some(server) = next {
            upstream.server = server;
            upstream.next += 1;
            return Step::Upstream(upstream);
        }
        if upstream.refresh {
            return Step::Drop;
        }
        if let Some(cache) = cache
            && let Some(key) = Key::of(&query)
        {
            cache.fail(&key, now);
            if let Looked::Reply { len, .. } = cache::look(cache, &query, &client, now, out) {
                return Step::Reply(len);
            }
        }
        reply(&client, Message::default(), Rcode::SERVFAIL, out)
    }
}

impl Upstream {
    /// The query to send; its ID is the transport's to pick at random (D27).
    #[must_use]
    pub const fn request(&self) -> &Message<'static> {
        &self.request
    }

    /// The server to send it to.
    #[must_use]
    pub const fn server(&self) -> SocketAddr {
        self.server
    }
}

/// The reply to `client`: `message` with `rcode`.
fn reply<'a>(client: &Client<'a>, message: Message<'a>, rcode: Rcode, out: &mut [u8]) -> Step {
    client
        .reply(message, rcode, out)
        .map_or(Step::Drop, Step::Reply)
}
