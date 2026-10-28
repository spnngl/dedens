//! The pipeline: the stages in order (D23), and the replies the core gives before any stage (D41).

use std::cell::Cell;
use std::net::SocketAddr;
use std::num::NonZeroU8;
use std::time::Duration;

use dedens_cache::{Cache, Key, StalePolicy};
use dedens_proto::edns::InfoCode;
use dedens_proto::{Flags, Header, Message, Opcode, Query, Rcode, RecordType, Transport};

use crate::cache::{self, Looked};
use crate::forward::{self, Forward};
use crate::reply::Client;

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

/// What an upstream query is for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Purpose {
    /// The client's reply.
    Reply,
    /// Refreshing a fresh entry before it expires; the client had its reply, and a failure is not held.
    Prefetch,
    /// Refreshing an expired entry that answered the client when its timer ran out (RFC 8767 §5); a failure is
    /// held.
    Stale,
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
    /// The forward stage's timeout and tries.
    patience: (Duration, NonZeroU8),
    /// The client response timer (RFC 8767 §5), while the client waits and the cache stage has one.
    stale_after: Option<Duration>,
    /// A cell: [`Pipeline::stale`] answers while the caller still sends [`Upstream::request`].
    purpose: Cell<Purpose>,
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
                Some(_) => return self.run(&query, &client, now, out),
            }
        };
        reply(&client, Message::default(), rcode, out)
    }

    /// Runs the stages on a query that passed the core's checks. Without RD, only fresh cached data answers: no
    /// stale data (RFC 8767 §5), no upstream query (RFC 1034 §4.3.1), REFUSED with EDE 20 (Not Authoritative,
    /// RFC 8914 §4.21) otherwise.
    fn run(&self, query: &Query<'_>, client: &Client<'_>, now: u32, out: &mut [u8]) -> Step {
        let recursion = client.header.flags.contains(Flags::RD);
        let stale = if recursion {
            StalePolicy::IfFailing
        } else {
            StalePolicy::Never
        };
        let mut cache = None;
        let mut expired = false;
        for (index, stage) in self.stages.iter().enumerate() {
            match stage {
                Stage::Cache(stored) => match cache::look(stored, query, client, now, stale, out) {
                    Looked::Reply { len, refresh } => {
                        if refresh
                            && let Some(upstream) = self.upstream(index, query, client, Some(index))
                        {
                            upstream.purpose.set(Purpose::Prefetch);
                            return Step::Refresh(len, upstream);
                        }
                        return Step::Reply(len);
                    }
                    Looked::Failed if recursion => {
                        return reply(client, Message::default(), Rcode::SERVFAIL, out);
                    }
                    Looked::Failed | Looked::Miss => cache = Some(index),
                    Looked::Expired => (cache, expired) = (Some(index), true),
                },
                Stage::Forward(_) if !recursion => {
                    return client
                        .reply(
                            Message::default(),
                            Rcode::REFUSED,
                            Some(InfoCode::NOT_AUTHORITATIVE),
                            out,
                        )
                        .map_or(Step::Drop, Step::Reply);
                }
                Stage::Forward(_) => {
                    let Some(mut upstream) = self.upstream(index, query, client, cache) else {
                        return Step::Drop;
                    };
                    // The client response timer, only when expired data could answer once it runs out.
                    upstream.stale_after = cache
                        .and_then(|index| self.cache(index))
                        .map(|cache| cache.config().stale_answer_after_ms)
                        .filter(|&ms| expired && ms > 0)
                        .map(|ms| Duration::from_millis(u64::from(ms)));
                    return Step::Upstream(upstream);
                }
            }
        }
        reply(client, Message::default(), Rcode::REFUSED, out)
    }

    /// The upstream query of the first forward stage from `from` on, storing into the stage `cache`.
    fn upstream(
        &self,
        from: usize,
        query: &Query<'_>,
        client: &Client<'_>,
        cache: Option<usize>,
    ) -> Option<Box<Upstream>> {
        let (index, forward) =
            self.stages
                .iter()
                .enumerate()
                .skip(from)
                .find_map(|(index, stage)| match stage {
                    Stage::Forward(forward) => Some((index, forward)),
                    Stage::Cache(_) => None,
                })?;
        Some(Box::new(Upstream {
            query: query.wire().into(),
            transport: client.transport,
            request: forward::request(client, query.question()?),
            server: *forward.servers().first()?,
            forward: index,
            next: 1,
            cache,
            patience: forward.patience(),
            stale_after: None,
            purpose: Cell::new(Purpose::Reply),
        }))
    }

    /// The cache stage at `index`.
    fn cache(&self, index: usize) -> Option<&Cache> {
        match self.stages.get(index) {
            Some(Stage::Cache(cache)) => Some(cache),
            _ => None,
        }
    }

    /// Answers the client of `upstream` with expired data once [`Upstream::stale_after`] ran out, at `now`, while
    /// the upstream query goes on (RFC 8767 §5): the reply is written into `out` as [`Pipeline::query`] writes,
    /// its records' TTL the cache's `stale_answer_ttl`, with EDE 3 (Stale Answer) or 19 (Stale NXDOMAIN Answer)
    /// when the client sent an OPT record. The response to `upstream` then only refreshes the cache, its failure
    /// held: [`Pipeline::receive`] ends in [`Step::Drop`]. `None` when the cache keeps nothing for the query, or the
    /// client was answered already.
    ///
    /// `upstream` comes from this pipeline.
    pub fn stale(&self, upstream: &Upstream, now: u32, out: &mut [u8]) -> Option<usize> {
        if upstream.purpose.get() != Purpose::Reply {
            return None;
        }
        let cache = self.cache(upstream.cache?)?;
        let query = Query::read(&upstream.query).ok()?;
        let client = Client::of(&query, upstream.transport);
        let Looked::Reply { len, .. } =
            cache::look(cache, &query, &client, now, StalePolicy::Always, out)
        else {
            return None;
        };
        upstream.purpose.set(Purpose::Stale);
        Some(len)
    }

    /// Takes the server's `response` to `upstream`, received at `now` and matched to the request by the transport
    /// (`dedens_net` checks its ID and question), or `None` when none came. A usable one is stored in the cache
    /// stage before, if any, and is the reply, written into `out` as [`Pipeline::query`] writes; otherwise the
    /// next server is asked. After the last, the failure is held in the cache, and the reply is the expired data it
    /// keeps, or SERVFAIL (D41, D43). Returns [`Step::Reply`], [`Step::Drop`] or [`Step::Upstream`]; a refresh,
    /// or a query whose client [`Pipeline::stale`] answered, ends in [`Step::Drop`].
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
        let cache = upstream.cache.and_then(|index| self.cache(index));
        let purpose = upstream.purpose.get();
        if let Some(decoded) = response
            .and_then(|wire| Message::decode(wire).ok())
            .filter(forward::usable)
        {
            if let Some(cache) = cache {
                // Some responses are not stored (RFC 2308, D22): the reply goes out all the same.
                let _ = cache.insert(&query, &decoded, now);
            }
            if purpose != Purpose::Reply {
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
        if purpose == Purpose::Prefetch {
            return Step::Drop;
        }
        if let Some(cache) = cache
            && let Some(key) = Key::of(&query)
        {
            cache.fail(&key, now);
            if purpose == Purpose::Reply
                && let Looked::Reply { len, .. } =
                    cache::look(cache, &query, &client, now, StalePolicy::IfFailing, out)
            {
                return Step::Reply(len);
            }
        }
        match purpose {
            Purpose::Reply => reply(&client, Message::default(), Rcode::SERVFAIL, out),
            Purpose::Prefetch | Purpose::Stale => Step::Drop,
        }
    }

    /// Gives `upstream` up after a failure of ours, such as no socket left, not of the server: no other server is
    /// asked, no failure held (RFC 9520 §3.2 is about upstream failures); the reply is SERVFAIL, written into `out`
    /// as [`Pipeline::query`] writes, unless the client was answered already ([`Step::Drop`]).
    ///
    /// `upstream` comes from this pipeline.
    pub fn abandon(&self, upstream: &Upstream, out: &mut [u8]) -> Step {
        if upstream.purpose.get() != Purpose::Reply {
            return Step::Drop;
        }
        let Ok(query) = Query::read(&upstream.query) else {
            return Step::Drop;
        };
        let client = Client::of(&query, upstream.transport);
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

    /// How long to wait for each response, and how many queries to send, before handing `None` to
    /// [`Pipeline::receive`]: the forward stage's.
    #[must_use]
    pub const fn patience(&self) -> (Duration, NonZeroU8) {
        self.patience
    }

    /// How long after the client's query to call [`Pipeline::stale`], resolution going on: the client response
    /// timer of the cache stage before (RFC 8767 §5), `None` without one or when the client has its reply.
    #[must_use]
    pub const fn stale_after(&self) -> Option<Duration> {
        self.stale_after
    }
}

/// The reply to `client`: `message` with `rcode`.
fn reply<'a>(client: &Client<'a>, message: Message<'a>, rcode: Rcode, out: &mut [u8]) -> Step {
    client
        .reply(message, rcode, None, out)
        .map_or(Step::Drop, Step::Reply)
}
