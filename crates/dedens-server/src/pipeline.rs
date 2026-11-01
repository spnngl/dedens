//! The pipeline: the stages in order (D23), and the replies the core gives before any stage (D41).

use std::num::NonZeroU8;
use std::sync::Arc;
use std::time::Duration;

use dedens_cache::{Cache, Checked, Key, StalePolicy};
use dedens_proto::edns::InfoCode;
use dedens_proto::{
    Class, Decoded, Flags, Header, Message, Opcode, Query, Question, Rcode, RecordType, Transport,
    Ttl,
};

use crate::cache::{self, Looked, Read};
use crate::forward::{self, Forward, Server};
use crate::plugin::Plugin;
use crate::reply::Client;
use crate::validate::{Check, Outcome, Progress, present};

/// A stage of the pipeline (D23).
#[derive(Debug)]
#[non_exhaustive]
pub enum Stage {
    /// Answers from the cache, stores what a later stage asked upstream, and holds failures (D43). Shared: a
    /// pipeline built on reload keeps the cache of the one it replaces.
    Cache(Arc<Cache>),
    /// Asks upstream servers: the last stage a query reaches.
    Forward(Forward),
    /// Answers from what it holds, or passes the query on (D54).
    Plugin(Box<dyn Plugin>),
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
    /// The client's query, with a question, read again for the request and the reply.
    query: Box<[u8]>,
    transport: Transport,
    server: Server,
    /// The forward stage, its next server, and the cache stage before it.
    forward: usize,
    next: usize,
    cache: Option<usize>,
    /// The forward stage's timeout and tries.
    patience: (Duration, NonZeroU8),
    /// The client response timer (RFC 8767 §5), while the client waits and the cache stage has one.
    stale_after: Option<Duration>,
    purpose: Purpose,
    /// Whether the response is validated (D77): the forward stage validates, and the client left it to us.
    validate: bool,
    /// The validation under way, while one of its questions is upstream.
    check: Option<Box<Check>>,
}

impl Pipeline {
    /// Runs `stages` in order.
    #[must_use]
    pub fn new(stages: Vec<Stage>) -> Self {
        Self {
            stages: stages.into(),
        }
    }

    /// The stages, in order.
    #[must_use]
    pub fn stages(&self) -> &[Stage] {
        &self.stages
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
                Stage::Cache(stored) => {
                    match cache::look(stored, query, client, now, Read::Lookup(stale), out) {
                        Looked::Reply { len, refresh } => {
                            if refresh
                                && let Ok(mut upstream) =
                                    self.upstream(index, query, client, Some(index))
                            {
                                upstream.purpose = Purpose::Prefetch;
                                return Step::Refresh(len, upstream);
                            }
                            return Step::Reply(len);
                        }
                        Looked::Bogus(code) => return servfail(client, code, out),
                        Looked::Failed if recursion => {
                            return reply(client, Message::default(), Rcode::SERVFAIL, out);
                        }
                        Looked::Failed | Looked::Miss => cache = Some(index),
                        Looked::Expired => (cache, expired) = (Some(index), true),
                    }
                }
                Stage::Plugin(plugin) => {
                    if let Some(answer) = plugin.answer(query) {
                        return client
                            .answer(query.wire(), &answer, out)
                            .map_or(Step::Drop, Step::Reply);
                    }
                }
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
                    let mut upstream = match self.upstream(index, query, client, cache) {
                        Ok(upstream) => upstream,
                        Err(Refused::NoServer) => return Step::Drop,
                        // Not shed in `receive`, nor held: a flood must not fail the names it asks for.
                        Err(Refused::Shed) => return servfail(client, InfoCode::NOT_READY, out),
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

    /// The upstream query of the first forward stage from `from` on, storing into the stage `cache`; none if
    /// the stage has no server, or validates the query and has its allowance spent (D77), before any question
    /// is sent or response decoded.
    fn upstream(
        &self,
        from: usize,
        query: &Query<'_>,
        client: &Client<'_>,
        cache: Option<usize>,
    ) -> Result<Box<Upstream>, Refused> {
        let (index, forward) = self
            .stages
            .iter()
            .enumerate()
            .skip(from)
            .find_map(|(index, stage)| match stage {
                Stage::Forward(forward) => Some((index, forward)),
                Stage::Cache(_) | Stage::Plugin(_) => None,
            })
            .ok_or(Refused::NoServer)?;
        let question = query.question().ok_or(Refused::NoServer)?;
        // CD asks for the data as it is (RFC 4035 §3.2.2), and only class IN has DNSSEC (RFC 4033 §2).
        let validate = forward.validation().is_some()
            && !client.header.flags.contains(Flags::CD)
            && question.qclass == Class::IN;
        if validate
            && forward
                .validation()
                .is_some_and(|validating| !validating.admit())
        {
            return Err(Refused::Shed);
        }
        Ok(Box::new(Upstream {
            query: query.wire().into(),
            transport: client.transport,
            server: forward.servers().first().ok_or(Refused::NoServer)?.clone(),
            forward: index,
            next: 1,
            cache,
            patience: forward.patience(),
            stale_after: None,
            purpose: Purpose::Reply,
            validate,
            check: None,
        }))
    }

    /// The cache stage at `index`.
    fn cache(&self, index: usize) -> Option<&Cache> {
        match self.stages.get(index) {
            Some(Stage::Cache(cache)) => Some(cache),
            Some(Stage::Forward(_) | Stage::Plugin(_)) | None => None,
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
    pub fn stale(&self, upstream: &mut Upstream, now: u32, out: &mut [u8]) -> Option<usize> {
        if upstream.purpose != Purpose::Reply {
            return None;
        }
        let cache = self.cache(upstream.cache?)?;
        let query = Query::read(&upstream.query).ok()?;
        let client = Client::of(&query, upstream.transport);
        let Looked::Reply { len, .. } = cache::look(
            cache,
            &query,
            &client,
            now,
            Read::Lookup(StalePolicy::Always),
            out,
        ) else {
            return None;
        };
        upstream.purpose = Purpose::Stale;
        Some(len)
    }

    /// Takes the server's `response` to `upstream`, received at `now` and matched to the request by the transport
    /// (`dedens_net` checks its ID and question), or `None` when none came. A usable one is stored in the cache
    /// stage before, if any, and is the reply, written into `out` as [`Pipeline::query`] writes; otherwise the
    /// next server is asked. After the last, the failure is held in the cache, and the reply is the expired data it
    /// keeps, or SERVFAIL (D41, D43). Returns [`Step::Reply`], [`Step::Drop`] or [`Step::Upstream`]; a refresh,
    /// or a query whose client [`Pipeline::stale`] answered, ends in [`Step::Drop`].
    ///
    /// A validating forward stage (D77) answers with [`Step::Upstream`] again for each question its validator
    /// asks, DS or DNSKEY, to be sent as any request. The reply comes with the verdict: AD set if secure; SERVFAIL
    /// with an extended error if bogus or without a verdict; the response as it is otherwise.
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
        let purpose = upstream.purpose;
        let forward = match self.stages.get(upstream.forward) {
            Some(Stage::Forward(forward)) => Some(forward),
            _ => None,
        };
        let following = forward.and_then(|forward| forward.servers().get(upstream.next));
        let finish = Finish {
            query: &query,
            client: &client,
            cache,
            purpose,
            now,
        };
        let decoded = response
            .and_then(|wire| Message::decode(wire).ok())
            .filter(forward::usable);
        if let Some(validating) = forward.and_then(Forward::validation) {
            // The next question of the validator's, or its verdict: a response to a question of its own is
            // untrusted input to it, and none is an answer too.
            let check = if let Some(mut check) = upstream.check.take() {
                if decoded.is_none()
                    && let Some(server) = following
                {
                    upstream.server = server.clone();
                    upstream.next += 1;
                    upstream.check = Some(check);
                    return Step::Upstream(upstream);
                }
                check.answer(validating, decoded.as_ref().map(|decoded| &decoded.message));
                Some(check)
            } else if upstream.validate {
                match (decoded, query.question()) {
                    (Some(decoded), Some(question)) => Some(Box::new(Check::new(
                        validating,
                        question,
                        decoded.into_owned(),
                    ))),
                    _ => None,
                }
            } else if let Some(decoded) = decoded {
                // Not validated: the client disabled checking, or the class has no DNSSEC. Never secure, whatever
                // upstream's AD says (RFC 6840 §5.8).
                return finish.deliver(Outcome::Insecure, decoded.into_owned(), None, out);
            } else {
                None
            };
            if let Some(mut check) = check {
                match check.next(validating) {
                    Progress::Ask => {
                        // The next question goes to the server that answered the last: one that failed is not
                        // tried again, so a dead server costs one query's patience, not each question's.
                        validating.metrics().question();
                        upstream.check = Some(check);
                        return Step::Upstream(upstream);
                    }
                    Progress::Done(outcome) => {
                        validating.metrics().outcome(outcome);
                        let cap = check.cap();
                        return finish.deliver(outcome, check.into_answer(), cap, out);
                    }
                }
            }
        } else if let Some(decoded) = decoded {
            // A stored response answers as a hit does, without encoding it again, but not counted a use: a name
            // asked once stays the first evicted (D43). Some are not stored (RFC 2308, D22): the reply goes out all
            // the same.
            let stored = cache.filter(|cache| cache.insert(&query, &decoded, now).is_ok());
            if purpose != Purpose::Reply {
                return Step::Drop;
            }
            if let Some(cache) = stored
                && let Looked::Reply { len, .. } =
                    cache::look(cache, &query, &client, now, Read::Stored, out)
            {
                return Step::Reply(len);
            }
            let rcode = decoded.message.rcode();
            return reply(&client, decoded.message, rcode, out);
        }
        if let Some(server) = following {
            upstream.server = server.clone();
            upstream.next += 1;
            return Step::Upstream(upstream);
        }
        finish.failed(None, out)
    }

    /// Gives `upstream` up after a failure of ours, such as no socket left, not of the server: no other server is
    /// asked, no failure held (RFC 9520 §3.2 is about upstream failures); the reply is SERVFAIL, written into `out`
    /// as [`Pipeline::query`] writes, unless the client was answered already ([`Step::Drop`]).
    ///
    /// `upstream` comes from this pipeline.
    pub fn abandon(&self, upstream: &Upstream, out: &mut [u8]) -> Step {
        if upstream.purpose != Purpose::Reply {
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
    /// The query to send, made for each server: the transport takes it, and picks its ID at random (D27).
    ///
    /// # Panics
    ///
    /// Never: a [`Pipeline`] sends upstream only a query that reads, with a question.
    #[must_use]
    pub fn request(&self) -> Message<'static> {
        let query = Query::read(&self.query).expect("an upstream's query reads");
        let question = query
            .question()
            .expect("an upstream's query has a question");
        match &self.check {
            Some(check) => forward::probe(check.asking()),
            None => forward::request(&Client::of(&query, self.transport), question, self.validate),
        }
    }

    /// The question of the validator that [`Upstream::request`] asks, if it is one: not the client's own. Two
    /// queries asking it of the same server are asking the same thing, whoever they validate for, and the answer
    /// to one serves the other.
    #[must_use]
    pub fn probe(&self) -> Option<&Question<'static>> {
        self.check.as_deref().map(Check::asking)
    }

    /// The server to send it to.
    #[must_use]
    pub const fn server(&self) -> &Server {
        &self.server
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

/// Why no upstream query was made for a client's.
enum Refused {
    /// The forward stage has no server, or the query no question.
    NoServer,
    /// The allowance of the validating forward stage is spent (D77): SERVFAIL "not ready", nothing held.
    Shed,
}

/// What a response is answered with, and where it goes, once known.
struct Finish<'a> {
    query: &'a Query<'a>,
    client: &'a Client<'a>,
    cache: Option<&'a Cache>,
    purpose: Purpose,
    now: u32,
}

impl Finish<'_> {
    /// Ends the query with `outcome` for `decoded`, upstream's answer, its TTLs at most `cap` (D77): stored in the
    /// cache stage with what the verdict made of it, and replied unless the client was answered already.
    fn deliver(
        &self,
        outcome: Outcome,
        mut decoded: Decoded<'static>,
        cap: Option<Ttl>,
        out: &mut [u8],
    ) -> Step {
        let checked = match outcome {
            Outcome::Secure => Checked::Secure,
            Outcome::Insecure => Checked::Insecure,
            Outcome::Bogus(code) => Checked::Bogus(code),
            Outcome::Indeterminate(code) => return self.failed(Some(code), out),
        };
        // A refresh that fails validation leaves the entry it refreshes: bad data kept for 60 s must not replace
        // data that is still good, as Unbound keeps it (RFC 4035 §4.7).
        if self.purpose != Purpose::Reply && matches!(checked, Checked::Bogus(_)) {
            return Step::Drop;
        }
        present(&mut decoded.message, outcome, cap, self.client.dnssec());
        let rcode = decoded.message.rcode();
        let stored = self.cache.filter(|cache| {
            cache
                .insert_checked(self.query, &decoded, self.now, checked)
                .is_ok()
        });
        if self.purpose != Purpose::Reply {
            return Step::Drop;
        }
        if let Checked::Bogus(code) = checked {
            return servfail(self.client, code, out);
        }
        if let Some(cache) = stored
            && let Looked::Reply { len, .. } =
                cache::look(cache, self.query, self.client, self.now, Read::Stored, out)
        {
            return Step::Reply(len);
        }
        reply(self.client, decoded.message, rcode, out)
    }

    /// Ends the query after the last server failed, or without a verdict, `error` then the reason: the failure is
    /// held in the cache (RFC 9520 §3.2), and the reply is the expired data it keeps, or SERVFAIL with `error`.
    fn failed(&self, error: Option<InfoCode>, out: &mut [u8]) -> Step {
        if self.purpose == Purpose::Prefetch {
            return Step::Drop;
        }
        if let Some(cache) = self.cache
            && let Some(key) = Key::of(self.query)
        {
            cache.fail(&key, self.now);
            if self.purpose == Purpose::Reply
                && let Looked::Reply { len, .. } = cache::look(
                    cache,
                    self.query,
                    self.client,
                    self.now,
                    Read::Lookup(StalePolicy::IfFailing),
                    out,
                )
            {
                return Step::Reply(len);
            }
        }
        match self.purpose {
            Purpose::Reply => self
                .client
                .reply(Message::default(), Rcode::SERVFAIL, error, out)
                .map_or(Step::Drop, Step::Reply),
            Purpose::Prefetch | Purpose::Stale => Step::Drop,
        }
    }
}

/// SERVFAIL with the extended error `code` (RFC 8914).
fn servfail(client: &Client<'_>, code: InfoCode, out: &mut [u8]) -> Step {
    client
        .reply(Message::default(), Rcode::SERVFAIL, Some(code), out)
        .map_or(Step::Drop, Step::Reply)
}

/// The reply to `client`: `message` with `rcode`.
fn reply<'a>(client: &Client<'a>, message: Message<'a>, rcode: Rcode, out: &mut [u8]) -> Step {
    client
        .reply(message, rcode, None, out)
        .map_or(Step::Drop, Step::Reply)
}
