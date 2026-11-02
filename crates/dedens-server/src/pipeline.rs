//! The pipeline: the stages in order (D23), and the replies the core gives before any stage (D41).

use std::net::IpAddr;
use std::num::NonZeroU8;
use std::sync::Arc;
use std::time::Duration;

use dedens_cache::{Cache, Checked, Key, StalePolicy};
use dedens_proto::edns::{Cookie, EdnsOption, InfoCode};
use dedens_proto::{
    Class, Decoded, Flags, Header, Message, Opcode, Query, Question, Rcode, RecordType, Transport,
    Ttl,
};

use crate::access::{Access, Denial};
use crate::cache::{self, Looked, Read};
use crate::cookie::{Cookies, Standing};
use crate::forward::{self, Forward, Server};
use crate::plugin::{Answer, Plugin};
use crate::reply::Client;
use crate::rrl::{RateLimit, Verdict};
use crate::validate::{Admitted, Check, Outcome, Progress, Source, present};

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

/// The stages a listener runs on each query, in order (D23); a query no stage answers is refused. Without
/// [`Pipeline::with_access`], every client is answered.
#[derive(Debug, Default)]
pub struct Pipeline {
    stages: Box<[Stage]>,
    access: Option<Access>,
    rate_limit: Option<Arc<RateLimit>>,
    cookies: Option<Cookies>,
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
    /// The cookie of the reply (D113).
    cookie: Option<Cookie>,
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
    /// Whether the response is validated (D77): the forward stage validates, and the client left it to us. The
    /// admission says which share of the allowance the validation is charged to (D117).
    validate: Option<Admitted>,
    /// The validation under way, while one of its questions is upstream.
    check: Option<Box<Check>>,
}

impl Pipeline {
    /// Runs `stages` in order.
    #[must_use]
    pub fn new(stages: Vec<Stage>) -> Self {
        Self {
            stages: stages.into(),
            access: None,
            rate_limit: None,
            cookies: None,
        }
    }

    /// Answers only the clients `access` permits (D91).
    #[must_use]
    pub fn with_access(mut self, access: Access) -> Self {
        self.access = Some(access);
        self
    }

    /// Limits the rate of UDP queries by source network (D113): a source over its rate gets TC=1 or nothing, unless
    /// its query carries a valid Server Cookie ([`Pipeline::with_cookies`]). TCP, TLS, QUIC and HTTPS are not
    /// limited: their clients proved their addresses.
    #[must_use]
    pub fn with_rate_limit(mut self, rate_limit: impl Into<Arc<RateLimit>>) -> Self {
        self.rate_limit = Some(rate_limit.into());
        self
    }

    /// Answers a query that has a Client Cookie with a Server Cookie (RFC 7873 §5.2, RFC 9018), and takes a valid one
    /// as proof of the source address (D113).
    #[must_use]
    pub fn with_cookies(mut self, cookies: Cookies) -> Self {
        self.cookies = Some(cookies);
        self
    }

    /// The cookies made and checked, if any.
    #[must_use]
    pub const fn cookies(&self) -> Option<&Cookies> {
        self.cookies.as_ref()
    }

    /// The rate limit, for a reload to keep it, and its table, when its settings stay.
    #[must_use]
    pub const fn rate_limit(&self) -> Option<&Arc<RateLimit>> {
        self.rate_limit.as_ref()
    }

    /// Whether a query over UDP without TC, `CoAP` or a REFUSED, from `from` at `now` is over its rate and not to be
    /// answered (D113): `DoC` is unprotected CoAP over UDP, an amplifier as DNS over UDP is. Counts the drop.
    #[must_use]
    pub fn limits(&self, from: IpAddr, now: u32) -> bool {
        self.rate_limit
            .as_ref()
            .is_some_and(|limit| limit.check(from, now, false) != Verdict::Pass)
    }

    /// What the access lists do to the client at `from` (D91), `None` when it is answered. Counts nothing: for a
    /// caller that must tell a denied client from a query the pipeline drops, or serve it nothing kept.
    #[must_use]
    pub fn denial(&self, from: IpAddr) -> Option<Denial> {
        self.access
            .as_ref()
            .filter(|access| !access.permits(from))
            .map(Access::denial)
    }

    /// Whether the client at `from` is denied with [`Denial::Drop`] (D91): the caller sends it nothing, and takes
    /// no connection or state for it. Counts the denial. A client denied with [`Denial::Refuse`], or not denied,
    /// is answered by [`Pipeline::query`].
    #[must_use]
    pub fn drops(&self, from: IpAddr) -> bool {
        self.access
            .as_ref()
            .is_some_and(|access| access.denial() == Denial::Drop && access.deny(from))
    }

    /// Whether the client at `from` is denied, with either action (D91). Counts the denial. For a caller that serves
    /// a client something other than a query the pipeline answers, such as a request to forward (D94), and has no
    /// REFUSED message to give.
    #[must_use]
    pub fn denies(&self, from: IpAddr) -> bool {
        self.access.as_ref().is_some_and(|access| access.deny(from))
    }

    /// The stages, in order.
    #[must_use]
    pub fn stages(&self) -> &[Stage] {
        &self.stages
    }

    /// Answers `wire`, a query from the client at `from` that came over `transport` at `now` (seconds, any monotonic
    /// origin), writing any reply into `out`: at least 512 bytes, and 65535 for a reply over TCP to come whole. Over
    /// a proxy, `from` is the proxy's.
    ///
    /// First, a client the access lists deny (D91, RFC 5358 §4) gets what they say, before any stage: nothing for
    /// [`Denial::Drop`], else REFUSED with EDE 18 (Prohibited, RFC 8914 §4.19) built from the query in place, with
    /// no allocation, unless the bytes are a response or shorter than a header. An IPv4-mapped IPv6 address is the
    /// IPv4 one. Over UDP that REFUSED counts against the rate of the source network too, and is dropped past it
    /// ([`Pipeline::with_rate_limit`]).
    ///
    /// Then, with cookies ([`Pipeline::with_cookies`]), a query with a Client Cookie is answered with a fresh Server
    /// Cookie whatever follows (RFC 7873 §5.2, D113), and over UDP a query without a valid Server Cookie counts
    /// against the rate of its source network ([`Pipeline::with_rate_limit`]): over it, a query gets nothing, or
    /// every `slip`th an empty reply with TC=1, or BADCOOKIE with a Server Cookie when it had a Client Cookie.
    ///
    /// Then, before the stages, the core replies itself to what they cannot answer (D41): FORMERR to a query it cannot
    /// read, that breaks a rule (D9) or has no question (RFC 1035 §4.1.1, RFC 9619); NOTIMP to an opcode other
    /// than QUERY; BADVERS to an EDNS version above 0 (RFC 6891 §6.1.3); REFUSED to a zone transfer, which
    /// a forwarder does not do. Responses are dropped, never answered.
    ///
    /// A query for ANY over UDP or CoAP is answered by the forward stage with a truncated, empty response, never
    /// forwarded nor cached; the other transports forward it (RFC 8482 §4.4, D114). A forward stage never passes
    /// upstream's AD on without a verdict of its own (RFC 6840 §5.8, D114).
    pub fn query(
        &self,
        wire: &[u8],
        transport: Transport,
        from: IpAddr,
        now: u32,
        out: &mut [u8],
    ) -> Step {
        if let Some(access) = &self.access
            && access.deny(from)
        {
            return match access.denial() {
                Denial::Drop => Step::Drop,
                // Over UDP a spoofed source is denied too, and its REFUSED is as much an answer to aim at the
                // address as any: the rate limit applies, with no TC (D113).
                Denial::Refuse if transport == Transport::Udp && self.limits(from, now) => {
                    Step::Drop
                }
                Denial::Refuse => prohibit(wire, transport, out),
            };
        }
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
        // The cookie is checked first, which costs a hash only for a Server Cookie, and made last, only for a query
        // that is answered: a flood that is dropped makes none.
        let request = self.request_cookie(&query);
        let standing = self.cookies.as_ref().map_or(Standing::NoCookie, |cookies| {
            cookies.verify(request.as_ref(), from)
        });
        // A source that proved its address with a cookie is not spoofed (RFC 7873 §5.2.5).
        let verdict = match &self.rate_limit {
            Some(limit) if transport == Transport::Udp && standing != Standing::Valid => {
                limit.check(from, now, true)
            }
            _ => Verdict::Pass,
        };
        if verdict == Verdict::Drop {
            return Step::Drop;
        }
        let fresh = self
            .cookies
            .as_ref()
            .zip(request)
            .map(|(cookies, request)| cookies.issue(request.client(), from));
        let client = Client::of(&query, transport).with_cookie(fresh);
        if verdict == Verdict::Slip {
            return slip(&client, out);
        }
        let rcode = if !query.violations().is_empty() {
            Rcode::FORMERR
        } else if header.opcode != Opcode::QUERY {
            Rcode::NOTIMP
        } else if query.edns().is_some_and(|edns| edns.version > 0) {
            Rcode::BADVERS
        } else {
            match query.question() {
                // A query with a cookie and no question asks for one (RFC 7873 §5.4).
                None if client.cookie.is_some() => {
                    if standing == Standing::Invalid {
                        Rcode::BADCOOKIE
                    } else {
                        Rcode::NOERROR
                    }
                }
                None => Rcode::FORMERR,
                Some(question) if matches!(question.qtype, RecordType::AXFR | RecordType::IXFR) => {
                    Rcode::REFUSED
                }
                Some(_) => {
                    // A connection cannot be spoofed, nor a valid Server Cookie (D113).
                    let source = Source {
                        address: from,
                        proven: transport != Transport::Udp || standing == Standing::Valid,
                    };
                    return self.run(&query, &client, source, now, out);
                }
            }
        };
        reply(&client, Message::default(), rcode, out)
    }

    /// The first COOKIE option of `query` (RFC 7873 §5.2), when the pipeline has cookies. A query that breaks a rule
    /// has none: it is answered FORMERR (§5.2.2).
    fn request_cookie(&self, query: &Query<'_>) -> Option<Cookie> {
        if self.cookies.is_none() || !query.violations().is_empty() {
            return None;
        }
        query.edns()?.options().find_map(|option| match option {
            EdnsOption::Cookie(cookie) => Some(cookie),
            _ => None,
        })
    }

    /// Runs the stages on a query that passed the core's checks. Without RD, only fresh cached data answers: no
    /// stale data (RFC 8767 §5), no upstream query (RFC 1034 §4.3.1), REFUSED with EDE 20 (Not Authoritative,
    /// RFC 8914 §4.21) otherwise.
    fn run(
        &self,
        query: &Query<'_>,
        client: &Client<'_>,
        source: Source,
        now: u32,
        out: &mut [u8],
    ) -> Step {
        let recursion = client.header.flags.contains(Flags::RD);
        let stale = if recursion {
            StalePolicy::IfFailing
        } else {
            StalePolicy::Never
        };
        // ANY over UDP and CoAP is truncated by the forward stage, never answered from the cache, which keeps no
        // transport in its keys (RFC 8482 §4.4, D114).
        let truncate = matches!(client.transport, Transport::Udp | Transport::Coap)
            && client
                .question
                .as_ref()
                .is_some_and(|q| q.qtype == RecordType::ANY);
        let mut cache = None;
        let mut expired = false;
        for (index, stage) in self.stages.iter().enumerate() {
            match stage {
                Stage::Cache(_) if truncate => {}
                Stage::Cache(stored) => {
                    match cache::look(stored, query, client, now, Read::Lookup(stale), out) {
                        Looked::Reply { len, refresh } => {
                            if refresh
                                && let Ok(mut upstream) =
                                    self.upstream(index, query, client, (source, now), Some(index))
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
                Stage::Forward(_) if truncate => {
                    return client.truncated(out).map_or(Step::Drop, Step::Reply);
                }
                Stage::Forward(_) => {
                    let mut upstream =
                        match self.upstream(index, query, client, (source, now), cache) {
                            Ok(upstream) => upstream,
                            Err(Refused::NoServer) => return Step::Drop,
                            // Not shed in `receive`, nor held: a flood must not fail the names it asks for.
                            Err(Refused::Shed) => {
                                return servfail(client, InfoCode::NOT_READY, out);
                            }
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
    /// the stage has no server, or validates the query and finds the allowance spent at second `now`, the global
    /// one or the share of the network of `source` (D77, D117), before any question is sent or response decoded.
    fn upstream(
        &self,
        from: usize,
        query: &Query<'_>,
        client: &Client<'_>,
        (source, now): (Source, u32),
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
        let validating = forward
            .validation()
            .filter(|_| !client.header.flags.contains(Flags::CD) && question.qclass == Class::IN);
        let validate = match validating {
            Some(validating) => {
                let exempt = self
                    .rate_limit
                    .as_ref()
                    .is_some_and(|limit| limit.exempts(source.address));
                Some(validating.admit(source, exempt, now).ok_or(Refused::Shed)?)
            }
            None => None,
        };
        Ok(Box::new(Upstream {
            query: query.wire().into(),
            transport: client.transport,
            cookie: client.cookie,
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
        let client = Client::of(&query, upstream.transport).with_cookie(upstream.cookie);
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
    /// (`dedens_net` checks its ID, which only it knows), or `None` when none came. A usable one is stored in the
    /// cache stage before, if any, and is the reply, written into `out` as [`Pipeline::query`] writes; otherwise
    /// the next server is asked, as for none. Not usable is a response that is no response to the question sent
    /// (D111): QR clear, an opcode other than QUERY, or another question, its name compared in any case (RFC 5452
    /// §9.1, RFC 4343 §4); the checks of the transport are not relied on. After the last, the failure is held in the cache, and the reply is the expired data it
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
        let client = Client::of(&query, upstream.transport).with_cookie(upstream.cookie);
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
        // The question this server was sent: the validator's while one is upstream, else the client's. A response
        // to another is as none (D111).
        let asked = upstream
            .check
            .as_deref()
            .map(Check::asking)
            .or_else(|| query.question());
        let decoded = response
            .and_then(|wire| Message::decode(wire).ok())
            .filter(|decoded| asked.is_some_and(|asked| forward::usable(decoded, asked)));
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
            } else if let Some(admitted) = upstream.validate {
                match (decoded, query.question()) {
                    (Some(decoded), Some(question)) => Some(Box::new(Check::new(
                        validating,
                        question,
                        decoded.into_owned(),
                        admitted,
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
                    Progress::Shed => return finish.shed(out),
                }
            }
        } else if let Some(mut decoded) = decoded {
            // No validator: upstream's AD is its word over a channel we cannot vouch for, never ours (RFC 6840
            // §5.8, RFC 4035 §3.2.3, D114). The cache clears it as well, for a response stored as unchecked.
            decoded.message.header.flags = decoded.message.header.flags.without(Flags::AD);
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
        let client = Client::of(&query, upstream.transport).with_cookie(upstream.cookie);
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
            None => forward::request(
                &Client::of(&query, self.transport),
                question,
                self.validate.is_some(),
            ),
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

    /// Ends the query without a verdict because the allowance is in debt (D106): the reply is SERVFAIL "not ready",
    /// as for a query refused at the start, and nothing is held or stored: the response is not at fault.
    fn shed(&self, out: &mut [u8]) -> Step {
        match self.purpose {
            Purpose::Reply => servfail(self.client, InfoCode::NOT_READY, out),
            Purpose::Prefetch | Purpose::Stale => Step::Drop,
        }
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

/// REFUSED with EDE 18 (Prohibited) to the query `wire`, which is no response and holds a header at least. Allocates
/// nothing for a query that reads, the usual one: the question is copied from the wire. A query that does not read,
/// or has no question, gets a reply of the header alone.
fn prohibit(wire: &[u8], transport: Transport, out: &mut [u8]) -> Step {
    let Some(header) = Header::peek(wire).filter(|header| !header.flags.contains(Flags::QR)) else {
        return Step::Drop;
    };
    let query = Query::read(wire);
    let client = match &query {
        Ok(query) => Client::of(query, transport),
        Err(_) => Client::unread(header, transport),
    };
    let refused = Answer {
        rcode: Rcode::REFUSED,
        records: None,
        authoritative: false,
        error: Some(InfoCode::PROHIBITED),
    };
    client
        .answer(wire, &refused, out)
        .or_else(|| {
            client.reply(
                Message::default(),
                Rcode::REFUSED,
                Some(InfoCode::PROHIBITED),
                out,
            )
        })
        .map_or(Step::Drop, Step::Reply)
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

/// The reply to a query over its rate that is not dropped (D113): BADCOOKIE with a Server Cookie when it had a
/// Client Cookie, which a real client takes to retry with it and then no longer limited (RFC 7873 §5.2.3); else
/// an empty reply with TC=1, which sends it to TCP (RFC 1035 §4.2.1).
fn slip(client: &Client<'_>, out: &mut [u8]) -> Step {
    let rcode = if client.cookie.is_some() {
        Rcode::BADCOOKIE
    } else {
        Rcode::NOERROR
    };
    let Some(len) = client.reply(Message::default(), rcode, None, out) else {
        return Step::Drop;
    };
    if client.cookie.is_none()
        && let Some(flags) = out.get_mut(2)
    {
        // The high byte of the flags word: TC is in it.
        *flags |= Flags::TC.bits().to_be_bytes()[0];
    }
    Step::Reply(len)
}
