//! The pipeline: the stages in order (D23), and the replies the core gives before any stage (D41). The reply, once
//! known, is written by `finish`.

mod finish;
mod prewarm;
mod signed;

use std::net::IpAddr;
use std::num::NonZeroU8;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use dedens_cache::{Cache, Checked, StalePolicy};
use dedens_proto::edns::{Cookie, EdnsOption, InfoCode};
use dedens_proto::{
    Class, Decoded, Flags, Header, Message, Opcode, Query, Question, Rcode, RecordType, Transport,
};
use dedens_tsig::{Key, Keyring};

use self::finish::{Finish, Refused, Ttls, prohibit, reply, servfail, slip};
pub use self::prewarm::{Warm, Warmth};
pub use self::signed::VerifiedKey;
use self::signed::{Keys, Signed};
use crate::access::{Access, Denial};
use crate::authoritative::Authoritative;
use crate::budget::Spent;
use crate::cache::{self, Looked, Read};
use crate::cookie::{Cookies, Standing};
use crate::forward::{self, Forward, Server, Via};
use crate::plugin::{Answer, Plugin};
use crate::recurse::{Asker, Asking, Ended, Recurse, Resolving};
use crate::reply::Client;
use crate::rrl::{Admission, RateLimit};
use crate::transfer::Transfer;
use crate::validate::{Check, Clock, Outcome, Payer, Progress, Source, Validating};

/// A stage of the pipeline (D23).
#[derive(Debug)]
#[non_exhaustive]
pub enum Stage {
    /// Answers from the zones it holds, AA set, or passes the query on (D208). Before the first stage of another
    /// kind, it answers every client: the access lists apply to the queries it passes on. Put it first: one
    /// after another stage still answers, but with the access lists not applied to its answers, which is only
    /// right for a zone that is public (D208).
    Authoritative(Authoritative),
    /// Answers from the cache, stores what a later stage asked upstream, and holds failures (D43). Shared: a
    /// pipeline built on reload keeps the cache of the one it replaces.
    Cache(Arc<Cache>),
    /// Asks upstream servers: the last stage a query reaches.
    Forward(Forward),
    /// Answers from what it holds, or passes the query on (D54).
    Plugin(Box<dyn Plugin>),
    /// Resolves from the root down (D195), in place of a forward stage: the last stage a query reaches.
    Recurse(Recurse),
}

/// The stages a listener runs on each query, in order (D23); a query no stage answers is refused. Without
/// [`Pipeline::with_access`], every client is answered.
#[derive(Debug, Default)]
pub struct Pipeline {
    stages: Box<[Stage]>,
    /// How many authoritative stages open the pipeline: they answer every client, and the access lists apply
    /// past them (D208).
    zones: usize,
    /// Whether a forward or recurse stage is there: without one, no reply past the zones has RA (D208).
    recursive: bool,
    access: Option<Access>,
    rate_limit: Option<Arc<RateLimit>>,
    cookies: Option<Cookies>,
    /// The keys signed requests are verified with (D211).
    keys: Option<Keys>,
    /// This pipeline's mark in the cache entries it reviewed (D118): not 0, and not another pipeline's.
    id: u64,
    /// For each stage, whether a plugin before it reviews responses (`Plugin::reviewer`).
    reviews: Box<[bool]>,
    /// The questions kept in the cache without a client (D96).
    warmed: Box<[Warm]>,
}

/// The id of the next pipeline: the marks of cache entries are compared to it, so that a response is reviewed again
/// after a reload (D118). 0 is the mark of an entry nobody reviewed.
static NEXT_ID: AtomicU64 = AtomicU64::new(1);

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
    /// Wait for the validation allowance (D77, D186): hand the query to [`Pipeline::unpark`] at each new second
    /// of the clock until it is admitted, and to [`Pipeline::shed`] once [`Parked::wait`] ran out first. A thread
    /// keeps its parked queries in a [`Parking`](crate::Parking) line.
    Park(Parked),
    /// Step the resolution, sending each query it gives, until it is done, then hand it to
    /// [`Pipeline::resolved`] (D195).
    Resolve(Box<Resolving>),
    /// Send the messages of the zone transfer, each made by [`Transfer::next`] with the pipeline of the time, in
    /// turn as the connection has room for them, then read the next query (D214). Only TCP and TLS make it.
    Transfer(Box<Transfer>),
}

/// A client's query to validate that found the allowance spent (D186): made, holding its share's unit (D117), and
/// not to be sent before [`Pipeline::unpark`] admits it.
#[derive(Debug)]
#[must_use]
pub struct Parked(Box<Upstream>);

impl Parked {
    /// How long a query waits for the allowance without a client response timer: the timer's default (D45), as
    /// RFC 8767 §5 advises it, just under the 2 s after which common stub resolvers ask again.
    pub const WAIT: Duration = Duration::from_millis(1800);

    /// How long after the client's query to give it up: the cache stage's client response timer when expired data
    /// could answer then ([`Upstream::stale_after`]), else [`Parked::WAIT`].
    #[must_use]
    pub fn wait(&self) -> Duration {
        self.0.stale_after.unwrap_or(Self::WAIT)
    }
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
    /// The forward stage's [`Forward::with_random_case`].
    random_case: bool,
    /// The client response timer (RFC 8767 §5), while the client waits and the cache stage has one.
    stale_after: Option<Duration>,
    purpose: Purpose,
    /// Whether the response is validated (D77): the forward stage validates, and the client left it to us. The
    /// payer says which share of the allowance the validation is charged to (D117).
    validate: Option<Payer>,
    /// The validation under way, while one of its questions is upstream.
    check: Option<Box<Check>>,
}

impl Pipeline {
    /// Runs `stages` in order. A plugin's [`Plugin::reviewer`] is asked here and on each response, and must answer
    /// the same for the life of the plugin (D118).
    #[must_use]
    pub fn new(stages: Vec<Stage>) -> Self {
        let mut reviewing = false;
        let reviews = stages
            .iter()
            .map(|stage| {
                let before = reviewing;
                reviewing |= matches!(stage, Stage::Plugin(plugin) if plugin.reviewer().is_some());
                before
            })
            .collect();
        let zones = stages
            .iter()
            .take_while(|stage| matches!(stage, Stage::Authoritative(_)))
            .count();
        let recursive = stages
            .iter()
            .any(|stage| matches!(stage, Stage::Forward(_) | Stage::Recurse(_)));
        Self {
            stages: stages.into(),
            zones,
            recursive,
            access: None,
            rate_limit: None,
            cookies: None,
            keys: None,
            id: NEXT_ID.fetch_add(1, Ordering::Relaxed),
            reviews,
            warmed: Box::default(),
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

    /// Verifies the TSIG of each request with `keys`, its time against `clock` (Unix seconds), and signs the reply
    /// to a signed request (RFC 8945, D211). Without it a TSIG is a record as any other, as a forwarder passes it on
    /// (RFC 8945 §5.5).
    #[must_use]
    pub fn with_keys(mut self, keys: Keyring, clock: Clock) -> Self {
        self.keys = Some(Keys::new(keys, clock));
        self
    }

    /// The keys requests are verified with, if any: read once, before the privileges are dropped, a reload keeps
    /// them (D211).
    #[must_use]
    pub fn keys(&self) -> Option<&Keyring> {
        self.keys.as_ref().map(Keys::keyring)
    }

    /// The key the request `wire` is signed with, verified with the pipeline's keys at its clock's time (RFC 8945
    /// §5.2); `None` for a request that is unsigned or that does not verify, or a pipeline without keys. The one
    /// way to make a [`VerifiedKey`], for the handlers of transfers, notifications and updates (D211).
    #[must_use]
    pub fn verified_key(&self, wire: &[u8]) -> Option<VerifiedKey<'_>> {
        self.keys.as_ref()?.verified_key(wire)
    }

    /// The time to sign a message of a transfer with `key` at, the clock's; `None` once the pipeline's keys have no
    /// key of its name and algorithm (D211, D214).
    pub(crate) fn signing_time(&self, key: &Key) -> Option<u64> {
        self.keys.as_ref()?.signing_time(key)
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
            .is_some_and(|limit| limit.check(from, now, false) != Admission::Pass)
    }

    /// What the access lists do to the client at `from` (D91), `None` when it is answered. Counts nothing: for a
    /// caller that must tell a denied client from a query the pipeline drops, or serve it nothing kept. Always
    /// `None` when an authoritative stage opens the pipeline: the zones answer every client (D208).
    #[must_use]
    pub fn denial(&self, from: IpAddr) -> Option<Denial> {
        self.access
            .as_ref()
            .filter(|access| self.zones == 0 && !access.permits(from))
            .map(Access::denial)
    }

    /// Whether the client at `from` is denied with [`Denial::Drop`] (D91): the caller sends it nothing, and takes
    /// no connection or state for it. Counts the denial. A client denied with [`Denial::Refuse`], or not denied,
    /// is answered by [`Pipeline::query`]. Never when an authoritative stage opens the pipeline: the zones answer
    /// every client, and [`Pipeline::query`] drops the queries they pass on (D208).
    #[must_use]
    pub fn drops(&self, from: IpAddr) -> bool {
        self.access.as_ref().is_some_and(|access| {
            self.zones == 0 && access.denial() == Denial::Drop && access.deny(from)
        })
    }

    /// Whether the client at `from` is denied, with either action (D91). Counts the denial. For a caller that serves
    /// a client something other than a query the pipeline answers, such as a request to forward (D94), and has no
    /// REFUSED message to give. Even when an authoritative stage opens the pipeline: the zones answer queries, not
    /// such requests (D208).
    #[must_use]
    pub fn denies(&self, from: IpAddr) -> bool {
        self.access.as_ref().is_some_and(|access| access.deny(from))
    }

    /// Whether the client at `from` is denied with either action (D91) and its packets are to be left unread, as
    /// a transport that seals its queries does, for want of a REFUSED to seal for it: it costs work to open them
    /// (D99). Counts the denial. Never when an authoritative stage opens the pipeline: the zones answer every
    /// client, and [`Pipeline::query`] denies the queries they pass on (D208).
    #[must_use]
    pub fn silences(&self, from: IpAddr) -> bool {
        self.zones == 0 && self.denies(from)
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
    /// ([`Pipeline::with_rate_limit`]). When authoritative stages open the pipeline, the lists apply past them
    /// instead, to the queries they pass on, with the same replies (D208, BIND's `allow-recursion`).
    ///
    /// Then, with cookies ([`Pipeline::with_cookies`]), a query with a Client Cookie is answered with a fresh Server
    /// Cookie whatever follows (RFC 7873 §5.2, D113), and over UDP a query without a valid Server Cookie counts
    /// against the rate of its source network ([`Pipeline::with_rate_limit`]): over it, a query gets nothing, or
    /// every `slip`th an empty reply with TC=1, or BADCOOKIE with a Server Cookie when it had a Client Cookie.
    ///
    /// Then, with keys ([`Pipeline::with_keys`]), the TSIG of a request is verified whatever its opcode, its
    /// failures answered as RFC 8945 §5.3.2 says, and every reply to a signed request is signed with its key,
    /// room kept for the record over UDP (§5.3). Past the zones a signed request is refused, REFUSED with EDE 20
    /// (Not Authoritative): a later stage's reply comes from upstream (D211).
    ///
    /// Then, before the stages, the core replies itself to what they cannot answer (D41): FORMERR to a query it cannot
    /// read, that breaks a rule (D9) or has no question (RFC 1035 §4.1.1, RFC 9619); NOTIMP to an opcode other
    /// than QUERY; BADVERS to an EDNS version above 0 (RFC 6891 §6.1.3). A zone transfer goes to the authoritative
    /// stage of the zone, as [`Step::Transfer`] when permitted (D214); REFUSED when there are no zones, a forwarder
    /// doing no transfer, NOTAUTH when none is the zone's. Responses are dropped, never answered. A reply
    /// has RA, but when authoritative stages open the pipeline: then only when a forward or recurse stage follows
    /// and the access lists permit the client (D208). A FORMERR to OPT records that break a rule,
    /// several (RFC 6891 §6.1.1), one outside the additional section, not owned by the root or with options
    /// overrunning it (§6.1.2), or with an invalid option, has our OPT record (§6.1.1, §7); one to a query it cannot
    /// read has none: none was read.
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
        if self.zones == 0
            && let Some(access) = &self.access
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
            let Some(header) =
                Header::peek(wire).filter(|header| !header.flags.contains(Flags::QR))
            else {
                return Step::Drop;
            };
            // No cookie can be read: the FORMERR counts against the rate as any reply (D113).
            let client = Client::unread(header, transport).with_recursion(self.recursion(from));
            return match self.admit(transport, from, now, Standing::NoCookie) {
                Admission::Drop => Step::Drop,
                Admission::Slip => slip(&client, out),
                Admission::Pass => reply(&client, Message::default(), Rcode::FORMERR, out),
            };
        };
        let header = query.header();
        if header.flags.contains(Flags::QR) {
            return Step::Drop;
        }
        // The cookie is checked first, which costs a hash only for a Server Cookie, and made last, only for a query
        // that is answered: a flood that is dropped makes none. Both share one reading of the clock.
        let request = self.request_cookie(&query);
        let mut cookies = self.cookies.as_ref().map(Cookies::reading);
        let standing = cookies.as_mut().map_or(Standing::NoCookie, |cookies| {
            cookies.verify(request.as_ref(), from)
        });
        let admission = self.admit(transport, from, now, standing);
        if admission == Admission::Drop {
            return Step::Drop;
        }
        let fresh = cookies
            .as_mut()
            .zip(request)
            .map(|(cookies, request)| cookies.issue(request.client(), from));
        let client = Client::of(&query, transport)
            .with_cookie(fresh)
            .with_recursion(self.recursion(from));
        if admission == Admission::Slip {
            return slip(&client, out);
        }
        let signed = match self
            .keys
            .as_ref()
            .map(|keys| keys.verify((&query, wire), &client, out))
        {
            None | Some(Ok(None)) => None,
            Some(Ok(Some(signed))) => Some(signed),
            Some(Err(step)) => return step,
        };
        let client = client.with_key(signed.as_ref().map(Signed::key));
        match (
            &signed,
            self.check(&query, &client, standing, from, now, out),
        ) {
            (Some(signed), Step::Reply(len)) => signed.seal(&client, len, out),
            (Some(signed), Step::Transfer(transfer)) => {
                Step::Transfer(Box::new(transfer.signed(signed.signer())))
            }
            // Only replies come of a signed request: the stages past the zones are refused it.
            (Some(_), _) => Step::Drop,
            (None, step) => step,
        }
    }

    /// The core's checks of a query that is read, admitted and verified (D41), then the stages ([`Pipeline::run`]).
    fn check(
        &self,
        query: &Query<'_>,
        client: &Client<'_>,
        standing: Standing,
        from: IpAddr,
        now: u32,
        out: &mut [u8],
    ) -> Step {
        let header = query.header();
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
                    return self.transfer(query, client, from, out);
                }
                Some(_) => {
                    // A connection cannot be spoofed, nor a valid Server Cookie; a datagram, UDP or DoC, can (D113).
                    let datagram = matches!(client.transport, Transport::Udp | Transport::Coap);
                    let source = Source {
                        address: from,
                        proven: !datagram || standing == Standing::Valid,
                    };
                    return self.run(query, client, source, now, out);
                }
            }
        };
        reply(client, Message::default(), rcode, out)
    }

    /// The answer to a zone transfer request (D214): the authoritative stage's whose zone has the question's name as
    /// its apex; else NOTAUTH, when there are zones (RFC 5936 §2.2.1, Knot's `axfr.c` and NSD's `query_axfr`),
    /// or REFUSED, a forwarder doing no transfer.
    fn transfer(
        &self,
        query: &Query<'_>,
        client: &Client<'_>,
        from: IpAddr,
        out: &mut [u8],
    ) -> Step {
        let zones = &self.stages[..self.zones];
        let step = zones.iter().find_map(|stage| match stage {
            Stage::Authoritative(zones) => zones.transfer(query, client, from, out),
            _ => None,
        });
        step.unwrap_or_else(|| {
            let rcode = if zones.is_empty() {
                Rcode::REFUSED
            } else {
                Rcode::NOTAUTH
            };
            reply(client, Message::default(), rcode, out)
        })
    }

    /// Whether the client at `from` has recursion available, RA (D208): always, but when authoritative stages
    /// open the pipeline; then when a forward or recurse stage follows them and the access lists permit the
    /// client. Counts nothing.
    fn recursion(&self, from: IpAddr) -> bool {
        self.zones == 0
            || (self.recursive
                && self
                    .access
                    .as_ref()
                    .is_none_or(|access| access.permits(from)))
    }

    /// The reply of the authoritative stages opening the pipeline to `client` at `from` (D208), or, for a query
    /// they pass on, what the access lists do to it, as [`Pipeline::query`] does before the stages otherwise:
    /// `None` when the query goes on. Counts the denial; the query counted against the rate already.
    fn zones(&self, client: &Client<'_>, from: IpAddr, out: &mut [u8]) -> Option<Step> {
        let zones = self
            .stages
            .get(..self.zones)
            .filter(|zones| !zones.is_empty())?;
        let answer = zones.iter().find_map(|stage| match stage {
            Stage::Authoritative(zones) => zones.reply(client, out),
            _ => None,
        });
        if answer.is_some() {
            return answer;
        }
        let access = self.access.as_ref().filter(|access| access.deny(from))?;
        Some(match access.denial() {
            Denial::Drop => Step::Drop,
            Denial::Refuse => client
                .reply(
                    Message::default(),
                    Rcode::REFUSED,
                    Some(InfoCode::PROHIBITED),
                    out,
                )
                .map_or(Step::Drop, Step::Reply),
        })
    }

    /// What the rate limit does to a query from `from` over `transport` at `now`, with cookie `standing` (D113):
    /// only UDP is limited, and a source that proved its address with a valid Server Cookie is not spoofed (RFC 7873
    /// §5.2.5). Counts the query.
    fn admit(&self, transport: Transport, from: IpAddr, now: u32, standing: Standing) -> Admission {
        match &self.rate_limit {
            Some(limit) if transport == Transport::Udp && standing != Standing::Valid => {
                limit.check(from, now, true)
            }
            _ => Admission::Pass,
        }
    }

    /// The first COOKIE option of `query` (RFC 7873 §5.2), when the pipeline has cookies. A malformed one is none, as
    /// the reader keeps it unknown: its FORMERR has no cookie (§5.2.2), where a query breaking another rule has its
    /// own answered (D113).
    fn request_cookie(&self, query: &Query<'_>) -> Option<Cookie> {
        let edns = self.cookies.as_ref().and(query.edns())?;
        edns.options().find_map(|option| match option {
            EdnsOption::Cookie(cookie) => Some(cookie),
            _ => None,
        })
    }

    /// Runs the stages on a query that passed the core's checks. The authoritative stages answer whatever RD says
    /// (D208); past them, without RD, only fresh cached data answers: no stale data (RFC 8767 §5), no upstream
    /// query (RFC 1034 §4.3.1), REFUSED with EDE 20 (Not Authoritative, RFC 8914 §4.21) otherwise. The access
    /// lists apply after the authoritative stages that open the pipeline ([`Pipeline::query`]).
    fn run(
        &self,
        query: &Query<'_>,
        client: &Client<'_>,
        source: Source,
        now: u32,
        out: &mut [u8],
    ) -> Step {
        let zones = self.zones(client, source.address, out);
        if let Some(step) = zones.or_else(|| signed::past_zones(client, out)) {
            return step;
        }
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
        for (index, stage) in self.stages.iter().enumerate().skip(self.zones) {
            match stage {
                // Not one that opens the pipeline (skipped above): its answers skip the access lists ([`Stage`]).
                Stage::Authoritative(zones) => {
                    if let Some(step) = zones.reply(client, out) {
                        return step;
                    }
                }
                Stage::Cache(_) if truncate => {}
                Stage::Cache(_) => {
                    match self.look(index, query, client, now, Read::Lookup(stale), out) {
                        Looked::Reply { len, refresh, .. } => {
                            if refresh {
                                // A refresh does not wait: the client has its reply, and a flood should not
                                // stand in the line of the clients waiting for theirs (D186).
                                match self.upstream(
                                    index,
                                    query,
                                    client,
                                    (source, now),
                                    Some(index),
                                ) {
                                    Ok(mut upstream) => {
                                        upstream.purpose = Purpose::Prefetch;
                                        return Step::Refresh(len, upstream);
                                    }
                                    Err(Refused::Busy(upstream)) => self.give_up(&upstream),
                                    Err(Refused::NoServer | Refused::Shed) => {}
                                }
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
                Stage::Forward(_) | Stage::Recurse(_) if !recursion => {
                    return client
                        .reply(
                            Message::default(),
                            Rcode::REFUSED,
                            Some(InfoCode::NOT_AUTHORITATIVE),
                            out,
                        )
                        .map_or(Step::Drop, Step::Reply);
                }
                Stage::Forward(_) | Stage::Recurse(_) if truncate => {
                    return client.truncated(out).map_or(Step::Drop, Step::Reply);
                }
                Stage::Forward(_) => {
                    let (mut upstream, busy) =
                        match self.upstream(index, query, client, (source, now), cache) {
                            Ok(upstream) => (upstream, false),
                            Err(Refused::NoServer) => return Step::Drop,
                            // Not shed in `receive`, nor held: a flood must not fail the names it asks for.
                            Err(Refused::Shed) => {
                                return servfail(client, InfoCode::NOT_READY, out);
                            }
                            Err(Refused::Busy(upstream)) => (upstream, true),
                        };
                    // The client response timer, only when expired data could answer once it runs out.
                    upstream.stale_after = cache
                        .and_then(|index| self.cache(index))
                        .map(|cache| cache.config().stale_answer_after_ms)
                        .filter(|&ms| expired && ms > 0)
                        .map(|ms| Duration::from_millis(u64::from(ms)));
                    if busy {
                        return Step::Park(self.park(upstream));
                    }
                    return Step::Upstream(upstream);
                }
                Stage::Recurse(resolver) => {
                    return self.recurse((index, resolver), query, client, source, cache, out);
                }
            }
        }
        reply(client, Message::default(), Rcode::REFUSED, out)
    }

    /// The upstream query of the first forward stage from `from` on, storing into the stage `cache`; none if
    /// the stage has no server, or validates the query and finds the share of the network of `source` spent at
    /// second `now` (D117), before any question is sent or response decoded. When it is the allowance that is
    /// spent (D77), the query is made, holding its share's unit, for the caller to park or give up (D186).
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
                Stage::Authoritative(_)
                | Stage::Cache(_)
                | Stage::Plugin(_)
                | Stage::Recurse(_) => None,
            })
            .ok_or(Refused::NoServer)?;
        let question = query.question().ok_or(Refused::NoServer)?;
        // CD asks for the data as it is (RFC 4035 §3.2.2), and only class IN has DNSSEC (RFC 4033 §2).
        let validating = forward
            .validation()
            .filter(|_| !client.header.flags.contains(Flags::CD) && question.qclass == Class::IN);
        let mut busy = false;
        let validate = match validating {
            Some(validating) => {
                let exempt = self
                    .rate_limit
                    .as_ref()
                    .is_some_and(|limit| limit.exempts(source.address));
                let payer = Payer::new(source, exempt);
                match validating.admit(payer, now) {
                    Ok(()) => {}
                    Err(Spent::Network) => return Err(Refused::Shed),
                    Err(Spent::Global) => busy = true,
                }
                Some(payer)
            }
            None => None,
        };
        let upstream = Box::new(Upstream {
            query: query.wire().into(),
            transport: client.transport,
            cookie: client.cookie,
            server: forward.servers().first().ok_or(Refused::NoServer)?.clone(),
            forward: index,
            next: 1,
            cache,
            patience: forward.patience(),
            random_case: forward.random_case(),
            stale_after: None,
            purpose: Purpose::Reply,
            validate,
            check: None,
        });
        if busy {
            return Err(Refused::Busy(upstream));
        }
        Ok(upstream)
    }

    /// The validation of the forward stage of `upstream`, if it validates it.
    fn validating(&self, upstream: &Upstream) -> Option<(&Validating, Payer)> {
        let payer = upstream.validate?;
        match self.stages.get(upstream.forward) {
            Some(Stage::Forward(forward)) => Some((forward.validation()?, payer)),
            _ => None,
        }
    }

    /// Parks `upstream`, which holds its share's unit and not the allowance's (D186).
    fn park(&self, upstream: Box<Upstream>) -> Parked {
        if let Some((validating, _)) = self.validating(&upstream) {
            validating.metrics().parked();
        }
        Parked(upstream)
    }

    /// Gives up `upstream`, which the allowance refused: its share's unit back, counted shed (D77, D186).
    fn give_up(&self, upstream: &Upstream) {
        if let Some((validating, payer)) = self.validating(upstream) {
            validating.give_up(payer);
        }
    }

    /// Asks again, at second `now`, for the unit of the allowance `parked` waits for (D186): the query to send
    /// once it has it, else `parked` back, to ask again at the next second, when the allowance is refilled. Nothing
    /// is counted: a thread asks for the first query of its line only.
    ///
    /// `parked` comes from this pipeline.
    ///
    /// # Errors
    ///
    /// `parked`, while the allowance has no unit.
    pub fn unpark(&self, parked: Parked, now: u32) -> Result<Box<Upstream>, Parked> {
        match self.validating(&parked.0) {
            Some((validating, _)) if !validating.readmit(now) => Err(parked),
            _ => Ok(parked.0),
        }
    }

    /// Gives up `parked` at second `now`, past [`Parked::wait`] or the places of its thread's line (D186): its
    /// share's unit back, counted shed. The reply, written into `out` as [`Pipeline::query`] writes, is the expired
    /// data of the cache stage when its client response timer allows it (D45, RFC 8767 §5), else SERVFAIL with EDE
    /// 14 (Not Ready, RFC 8914 §4.15), as for a query shed at once (D77).
    ///
    /// `parked` comes from this pipeline.
    pub fn shed(&self, parked: Parked, now: u32, out: &mut [u8]) -> Step {
        let Parked(mut upstream) = parked;
        self.give_up(&upstream);
        if upstream.stale_after.is_some()
            && let Some(len) = self.stale(&mut upstream, now, out)
        {
            return Step::Reply(len);
        }
        let Ok(query) = Query::read(&upstream.query) else {
            return Step::Drop;
        };
        let client = Client::of(&query, upstream.transport).with_cookie(upstream.cookie);
        servfail(&client, InfoCode::NOT_READY, out)
    }

    /// Parks `upstream`, admitted, behind the queries of its thread that wait for the allowance (D186), so that
    /// they go first: the allowance's unit is given back. `upstream` back when it is not validated.
    ///
    /// `upstream` is the [`Step::Upstream`] of [`Pipeline::query`] of this pipeline: a client's own question, the
    /// validation not started.
    ///
    /// # Errors
    ///
    /// `upstream`, when it is not validated.
    pub fn defer(&self, upstream: Box<Upstream>) -> Result<Parked, Box<Upstream>> {
        match self.validating(&upstream) {
            Some((validating, _)) => {
                validating.defer();
                validating.metrics().parked();
                Ok(Parked(upstream))
            }
            None => Err(upstream),
        }
    }

    /// The answer to give instead of `response`, the response to `query`, by the first plugin before the stage
    /// `before` that reviews it, and the index of that plugin (D118).
    fn review(
        &self,
        before: usize,
        query: &Query<'_>,
        response: &Message<'_>,
    ) -> Option<(usize, Answer<'_>)> {
        if !*self.reviews.get(before)? {
            return None;
        }
        self.stages
            .iter()
            .enumerate()
            .take(before)
            .find_map(|(at, stage)| match stage {
                Stage::Plugin(plugin) => plugin
                    .reviewer()?
                    .review(query, response)
                    .map(|answer| (at, answer)),
                Stage::Authoritative(_)
                | Stage::Cache(_)
                | Stage::Forward(_)
                | Stage::Recurse(_) => None,
            })
    }

    /// [`cache::look`] at the cache stage `index`, a hit that a plugin before the stage reviews replaced by its
    /// answer (D118): the entry may predate the list, which a reload keeps the cache across (D55). The reply is the
    /// answer then, and no refresh is asked: it would fetch what is blocked.
    ///
    /// An entry is reviewed once by a pipeline: a response that passed is marked with the pipeline's id, in the
    /// cache, and a hit with that mark is served as it is, undecoded. One with another mark (a response stored
    /// before a reload, or one a plugin would have refused) is decoded and reviewed. A truncated reply is not
    /// marked: the records it lost were not reviewed. Between a hit and its marking, a response stored by an
    /// older pipeline with the same mark as the entry seen would take the mark of the new: the older pipeline
    /// stores only until its in-flight queries end.
    fn look(
        &self,
        index: usize,
        query: &Query<'_>,
        client: &Client<'_>,
        now: u32,
        read: Read,
        out: &mut [u8],
    ) -> Looked {
        let Some(cache) = self.cache(index) else {
            return Looked::Miss;
        };
        let looked = cache::look(cache, query, client, now, read, out);
        let Looked::Reply {
            len,
            mark,
            truncated,
            ..
        } = looked
        else {
            return looked;
        };
        if mark == self.id || !self.reviews.get(index).is_some_and(|&reviews| reviews) {
            return looked;
        }
        let Some(decoded) = out.get(..len).and_then(|wire| Message::decode(wire).ok()) else {
            return looked;
        };
        let Some((_, answer)) = self.review(index, query, &decoded.message) else {
            if !truncated {
                let _ = cache.mark(query, mark, self.id);
            }
            return looked;
        };
        match client.answer(query.wire(), &answer, out) {
            Some(len) => Looked::Reply {
                len,
                refresh: false,
                mark: 0,
                truncated: false,
            },
            None => Looked::Miss,
        }
    }

    /// The cache stage at `index`.
    fn cache(&self, index: usize) -> Option<&Cache> {
        match self.stages.get(index) {
            Some(Stage::Cache(cache)) => Some(cache),
            Some(
                Stage::Authoritative(_) | Stage::Forward(_) | Stage::Plugin(_) | Stage::Recurse(_),
            )
            | None => None,
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
        let query = Query::read(&upstream.query).ok()?;
        let client = Client::of(&query, upstream.transport).with_cookie(upstream.cookie);
        let Looked::Reply { len, .. } = self.look(
            upstream.cache?,
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
        let purpose = upstream.purpose;
        let forward = match self.stages.get(upstream.forward) {
            Some(Stage::Forward(forward)) => Some(forward),
            _ => None,
        };
        let following = forward.and_then(|forward| forward.servers().get(upstream.next));
        let finish = Finish {
            pipeline: self,
            query: &query,
            client: &client,
            forward: upstream.forward,
            cache: upstream.cache,
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
            } else if let Some(payer) = upstream.validate {
                match (decoded, query.question()) {
                    // Reviewed before it is validated: a response refused is not worth the questions of the
                    // validation, and is not stored, which only a validated response is here (D118).
                    (Some(decoded), _)
                        if let Some((_, answer)) =
                            self.review(upstream.forward, &query, &decoded.message) =>
                    {
                        return finish.blocked(&answer, out);
                    }
                    (Some(decoded), Some(question)) => Some(Box::new(Check::new(
                        validating,
                        question,
                        decoded.into_owned(),
                        payer,
                    ))),
                    _ => None,
                }
            } else if let Some(decoded) = decoded {
                // Not validated: the client disabled checking, or the class has no DNSSEC. Never secure, whatever
                // upstream's AD says (RFC 6840 §5.8).
                return finish.deliver(
                    Outcome::Insecure,
                    decoded.into_owned(),
                    None,
                    Ttls::Received,
                    out,
                );
            } else {
                None
            };
            if let Some(mut check) = check {
                match check.next(validating, now) {
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
                        return finish.deliver(
                            outcome,
                            check.into_answer(),
                            cap,
                            Ttls::Received,
                            out,
                        );
                    }
                    Progress::Shed => return finish.shed(out),
                }
            }
        } else if let Some(decoded) = decoded {
            return finish.plain(decoded, Ttls::Received, out);
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

    /// The recurse stage `stage` at `index` on a query with RD, not ANY over UDP: the answer of a zone served
    /// locally, AA set (RFC 6303 §3), or the resolution of its question, storing into the cache stage `cache`.
    fn recurse(
        &self,
        (index, stage): (usize, &Recurse),
        query: &Query<'_>,
        client: &Client<'_>,
        source: Source,
        cache: Option<usize>,
        out: &mut [u8],
    ) -> Step {
        let Some(question) = query.question() else {
            return reply(client, Message::default(), Rcode::REFUSED, out);
        };
        if let Some((rcode, message)) = stage.local(question) {
            return client
                .authoritative(message, rcode, out)
                .map_or(Step::Drop, Step::Reply);
        }
        let exempt = self
            .rate_limit
            .as_ref()
            .is_some_and(|limit| limit.exempts(source.address));
        let asking = Asking {
            query: query.wire().into(),
            transport: client.transport,
            cookie: client.cookie,
            stage: index,
            cache,
        };
        // A client that checks for itself gets what was resolved unchecked (RFC 4035 §3.2.2).
        let checking = !client.header.flags.contains(Flags::CD);
        Step::Resolve(stage.resolving_for(
            question.clone().into_owned(),
            asking,
            (source.address, source.proven, exempt),
            checking,
        ))
    }

    /// Writes the reply of `resolving` into `out`, at second `now`, as [`Pipeline::receive`] does a response's:
    /// the answer stored in the cache stage, a failure held there and answered with expired data or SERVFAIL with
    /// its extended error (D191), SERVFAIL with EDE 14 (Not Ready) when the client's network could pay no more
    /// queries (D117), NOTIMP for a type it does not resolve (D195) and REFUSED for a class other than IN. One
    /// that did not end, such as one given up for want of a socket, is answered SERVFAIL, nothing held, as
    /// [`Pipeline::abandon`] answers. A priming ends in [`Step::Drop`].
    ///
    /// `resolving` comes from this pipeline.
    pub fn resolved(&self, resolving: &Resolving, now: u32, out: &mut [u8]) -> Step {
        let Asker::Client(asking) = &resolving.asker else {
            return Step::Drop;
        };
        // Read once already: this reads it again.
        let Ok(query) = Query::read(&asking.query) else {
            return Step::Drop;
        };
        let client = Client::of(&query, asking.transport).with_cookie(asking.cookie);
        let finish = Finish {
            pipeline: self,
            query: &query,
            client: &client,
            forward: asking.stage,
            cache: asking.cache,
            purpose: Purpose::Reply,
            now,
        };
        let Some(ended) = resolving.ended() else {
            return reply(&client, Message::default(), Rcode::SERVFAIL, out);
        };
        match ended {
            // Bogus: SERVFAIL with its code, no stale data in its place, as a forwarded bogus answer (D77); the
            // `RRset` cache holds the verdict for the bogus TTL, so asking again sends nothing.
            Ended::Resolved(dedens_resolver::Resolved::Failed(
                dedens_resolver::Failure::Bogus(code),
            )) => servfail(&client, *code, out),
            Ended::Resolved(dedens_resolver::Resolved::Failed(failure)) => {
                finish.failed(Some(failure.info_code()), out)
            }
            Ended::Resolved(resolved) => {
                let mut decoded = Decoded::default();
                decoded.message = resolved.message(resolving.question(), client.dnssec());
                // The verdicts the `RRset` cache holds: secure when each RRset is, AD set even with CD (RFC 4035
                // §3.2.3, RFC 6840 §5.8); insecure when one is. Data not judged (no validator, a YXDOMAIN) and,
                // with CD, bogus data go as received (RFC 6840 §5.9): a validated bogus answer is a failure.
                let outcome = match resolved.checked() {
                    Checked::Secure => Outcome::Secure,
                    Checked::Insecure => Outcome::Insecure,
                    Checked::Unchecked | Checked::Bogus(_) => {
                        return finish.plain(decoded, Ttls::Bounded, out);
                    }
                };
                finish.deliver(outcome, decoded, None, Ttls::Bounded, out)
            }
            Ended::Shed => finish.shed(out),
            Ended::Unsupported(dedens_resolver::Unsupported::Type(_)) => {
                reply(&client, Message::default(), Rcode::NOTIMP, out)
            }
            Ended::Unsupported(dedens_resolver::Unsupported::Class(_)) => {
                reply(&client, Message::default(), Rcode::REFUSED, out)
            }
        }
    }

    /// The priming of the root's servers by the recurse stage at `now`, on the clock of [`Resolving::step`], if it
    /// is due (RFC 8109 §3.1): its cache holds no fresh root NS `RRset`, and no priming is under way on any thread.
    /// Step it as a client's resolution; its answer goes to the `RRset` cache, and the next resolutions start from
    /// it. Until it does, they start from the hints, the TLDs' for a name under a TLD (D126).
    #[must_use]
    pub fn prime(&self, now: Duration) -> Option<Box<Resolving>> {
        self.stages.iter().find_map(|stage| match stage {
            Stage::Recurse(recurse) => recurse.priming(now),
            Stage::Authoritative(_) | Stage::Cache(_) | Stage::Forward(_) | Stage::Plugin(_) => {
                None
            }
        })
    }

    /// The query of the root's DNSKEY `RRset` by the first recurse stage, for the server itself (RFC 5011 §2.3,
    /// D200): stepped as a client's resolution, its answer, from the stage's `RRset` cache or the root's servers,
    /// is not validated, and [`Pipeline::resolved`] writes no reply for it.
    #[must_use]
    pub fn root_keys(&self) -> Option<Box<Resolving>> {
        self.stages.iter().find_map(|stage| match stage {
            Stage::Recurse(recurse) => Some(recurse.root_keys()),
            Stage::Authoritative(_) | Stage::Cache(_) | Stage::Forward(_) | Stage::Plugin(_) => {
                None
            }
        })
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

    /// Whether [`Upstream::request`] goes with random bits for `0x20` when sent over `transport`, the one the server is
    /// asked over (D184): the forward stage's [`Forward::with_random_case`], for a plain server over UDP, which an
    /// off-path attacker can answer in its place. A connection, TLS, QUIC, HTTPS, Oblivious `DoH` and `DNSCrypt`
    /// stop such an attacker without it.
    #[must_use]
    pub fn random_case(&self, transport: Transport) -> bool {
        self.random_case && self.server.via == Via::Plain && transport == Transport::Udp
    }

    /// How long after the client's query to call [`Pipeline::stale`], resolution going on: the client response
    /// timer of the cache stage before (RFC 8767 §5), `None` without one or when the client has its reply.
    #[must_use]
    pub const fn stale_after(&self) -> Option<Duration> {
        self.stale_after
    }
}
