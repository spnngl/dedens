//! The recurse stage (D195): the pipeline's last stage when the server resolves names itself, from the root down
//! (RFC 1034 §5.3.3), instead of forwarding them. Sans-IO as the rest of the pipeline: [`Resolving`] is a client's
//! question, or the priming of the root's servers (RFC 8109 §3), which the caller steps, sending each query it gives
//! to an authoritative server and handing back the reply, until it is done; [`Pipeline::resolved`] then writes the
//! reply.
//!
//! [`Pipeline::resolved`]: crate::Pipeline::resolved

mod local;

use std::net::IpAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use dedens_cache::Config;
use dedens_proto::edns::Cookie;
use dedens_proto::{
    Class, Flags, Message, Name, Question, Rcode, Record, RecordType, Transport, Ttl,
};
use dedens_resolver::{Caches, Limits, Query, Ranked, Reply, Resolution, Resolved, Unsupported};
use rand_core::CryptoRng;
use thiserror::Error;

use self::local::LocalZones;
use crate::budget::{Budgets, Slot};

/// Resolves the questions that reach it, sharing its caches with every thread: the root's and the TLDs' servers
/// from the hints, the `RRset` and infrastructure caches (D191, D193, D194). The zones served locally are answered
/// without a query (RFC 6303 §3, RFC 8375 §4, RFC 9462 §6.4, RFC 6761 §6.3, §6.4).
#[derive(Debug)]
pub struct Recurse {
    caches: Arc<Caches>,
    limits: Limits,
    local: LocalZones,
    /// What each client network may spend of the queries sent (D117), none for the rate limit's exempt sources.
    share: Option<Arc<Budgets>>,
    /// Whether the root's servers are being primed: one priming at a time, whichever thread starts it.
    priming: Arc<AtomicBool>,
}

/// A zone given to [`Recurse::resolving`] that is not served locally.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
#[error("{0} is not a locally served zone")]
pub struct NotLocal(pub Name<'static>);

impl Recurse {
    /// A stage resolving from `caches`, within the default [`Limits`], serving every zone of D195 locally, with no
    /// share of the queries sent per client network.
    #[must_use]
    pub fn new(caches: Arc<Caches>) -> Self {
        Self {
            caches,
            limits: Limits::default(),
            local: LocalZones::default(),
            share: None,
            priming: Arc::new(AtomicBool::new(false)),
        }
    }

    /// The same stage within `limits`.
    #[must_use]
    pub const fn with_limits(mut self, limits: Limits) -> Self {
        self.limits = limits;
        self
    }

    /// The same stage, each query sent paid by the client's network from `share` (D117): one unit a query, and a
    /// client whose network has none left gets SERVFAIL with EDE 14 (Not Ready).
    #[must_use]
    pub fn with_share(mut self, share: Budgets) -> Self {
        self.share = Some(Arc::new(share));
        self
    }

    /// The same stage resolving `zone`, which it served locally (RFC 6303 §3: each zone may be turned off).
    ///
    /// # Errors
    ///
    /// [`NotLocal`] when `zone` is not served locally.
    pub fn resolving(mut self, zone: &Name<'_>) -> Result<Self, NotLocal> {
        self.local = self
            .local
            .without(zone)
            .ok_or_else(|| NotLocal(zone.clone().into_owned()))?;
        Ok(self)
    }

    /// The caches it resolves from: a stage built on reload with the same settings takes them over.
    #[must_use]
    pub const fn caches(&self) -> &Arc<Caches> {
        &self.caches
    }

    /// The answer of a locally served zone to `question`, if one holds it.
    pub(crate) fn local(&self, question: &Question<'_>) -> Option<(Rcode, Message<'static>)> {
        self.local.answer(question)
    }

    /// The resolution of `question` for a client: `client` at `stage`, storing into the cache stage `cache`, the
    /// queries paid by the network of `from` unless `exempt`.
    pub(crate) fn resolving_for(
        &self,
        question: Question<'static>,
        client: Asking,
        (from, proven, exempt): (IpAddr, bool, bool),
    ) -> Box<Resolving> {
        let payer = self
            .share
            .as_ref()
            .filter(|_| !exempt)
            .map(|share| (Arc::clone(share), Slot::new(from, proven)));
        Box::new(Resolving {
            state: State::Ready,
            question,
            caches: Arc::clone(&self.caches),
            limits: self.limits,
            paid: 0,
            payer,
            asker: Asker::Client(client),
        })
    }

    /// The priming of the root's servers at `now` (RFC 8109 §3.1): when the `RRset` cache holds no fresh root NS
    /// `RRset`, at the start and once it expired, and no priming is under way.
    pub(crate) fn priming(&self, now: Duration) -> Option<Box<Resolving>> {
        let root = Name::root();
        let fresh = self
            .caches
            .rrsets
            .get(&root, RecordType::NS, Class::IN, secs(now))
            .is_some();
        if fresh
            || self
                .priming
                .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
                .is_err()
        {
            return None;
        }
        Some(Box::new(Resolving {
            state: State::Ready,
            question: Question::new(root, RecordType::NS),
            caches: Arc::clone(&self.caches),
            limits: self.limits,
            paid: 0,
            payer: None,
            asker: Asker::Priming(Priming(Arc::clone(&self.priming))),
        }))
    }
}

/// A client's question to resolve, or the priming of the root's servers: step it, send each [`Query`] it gives to
/// its server, hand back the reply, until [`Turn::Done`]; then [`Pipeline::resolved`](crate::Pipeline::resolved)
/// writes the client's reply.
#[derive(Debug)]
pub struct Resolving {
    question: Question<'static>,
    state: State,
    caches: Arc<Caches>,
    limits: Limits,
    /// The queries paid for so far.
    paid: usize,
    payer: Option<(Arc<Budgets>, Slot)>,
    pub(crate) asker: Asker,
}

/// Where a [`Resolving`] is.
#[derive(Debug)]
pub(crate) enum State {
    /// Not stepped yet: the resolution starts at the first step, whose clock is finer than the pipeline's.
    Ready,
    Running(Box<Resolution>),
    Ended(Ended),
}

/// How a [`Resolving`] ended.
#[derive(Debug)]
pub(crate) enum Ended {
    Resolved(Resolved),
    /// The client's network had nothing left to pay a query with (D117).
    Shed,
    /// The question is not resolved (D191).
    Unsupported(Unsupported),
}

/// Who a [`Resolving`] resolves for.
#[derive(Debug)]
pub(crate) enum Asker {
    Client(Asking),
    Priming(#[expect(dead_code, reason = "held until the priming ends, for its drop")] Priming),
}

/// A client's query, as its reply needs it.
#[derive(Debug)]
pub(crate) struct Asking {
    /// The client's query, with a question, read again for the reply.
    pub(crate) query: Box<[u8]>,
    pub(crate) transport: Transport,
    pub(crate) cookie: Option<Cookie>,
    /// The recurse stage.
    pub(crate) stage: usize,
    /// The cache stage before it, if any.
    pub(crate) cache: Option<usize>,
}

/// The priming under way: dropped, it lets the next start.
#[derive(Debug)]
pub(crate) struct Priming(Arc<AtomicBool>);

impl Drop for Priming {
    fn drop(&mut self) {
        self.0.store(false, Ordering::Release);
    }
}

/// What a [`Resolving`] does next.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Turn<'a> {
    /// Send this query, then hand its reply to [`Resolving::receive`]; stepped again before that, it is the same.
    Send(&'a Query),
    /// It is over.
    Done,
}

impl Resolving {
    /// The question resolved.
    #[must_use]
    pub const fn question(&self) -> &Question<'static> {
        &self.question
    }

    /// The caches it resolves into, the stage's.
    #[must_use]
    pub const fn caches(&self) -> &Arc<Caches> {
        &self.caches
    }

    /// Whether it primes the root's servers, for no client.
    #[must_use]
    pub const fn is_priming(&self) -> bool {
        matches!(self.asker, Asker::Priming(_))
    }

    /// What to do at `now`, on the clock of [`Pipeline::query`](crate::Pipeline::query)'s seconds: the query to
    /// send, its server drawn with `rng` (RFC 5452 §4.4), or the end. Each new query is paid for by the client's
    /// network first (D117); it ends there when the network has nothing left.
    pub fn step(&mut self, now: Duration, rng: &mut impl CryptoRng) -> Turn<'_> {
        if let State::Ready = self.state {
            self.state = match Resolution::start(
                self.question.clone(),
                Arc::clone(&self.caches),
                now,
                self.limits,
            ) {
                Ok(resolution) => State::Running(Box::new(resolution)),
                Err(unsupported) => State::Ended(Ended::Unsupported(unsupported)),
            };
        }
        let State::Running(resolution) = &mut self.state else {
            return Turn::Done;
        };
        // Stepping again without a reply gives the same, so the query is taken once paid for.
        let ended = match resolution.step(now, rng) {
            dedens_resolver::Next::Done(resolved) => Some(Ended::Resolved(resolved.clone())),
            dedens_resolver::Next::Send(_) => {
                let sent = resolution.sent();
                let unpaid = sent > self.paid;
                self.paid = sent;
                let shed = unpaid
                    && self
                        .payer
                        .as_ref()
                        .is_some_and(|(share, slot)| !share.admit(*slot, secs(now)));
                shed.then_some(Ended::Shed)
            }
        };
        if let Some(ended) = ended {
            self.state = State::Ended(ended);
            return Turn::Done;
        }
        let State::Running(resolution) = &mut self.state else {
            return Turn::Done;
        };
        match resolution.step(now, rng) {
            dedens_resolver::Next::Send(query) => Turn::Send(query),
            dedens_resolver::Next::Done(_) => Turn::Done,
        }
    }

    /// Hands over the reply to the query [`Resolving::step`] gave, at `now`.
    pub fn receive(&mut self, reply: Reply<'_>, now: Duration) {
        if let State::Running(resolution) = &mut self.state {
            resolution.receive(reply, now);
        }
    }

    /// Hands over the reply to the same query another [`Resolving`] sent while this one waited on it (RFC 5452 §5):
    /// the server was judged by the one that sent it.
    pub fn receive_shared(&mut self, reply: Reply<'_>, now: Duration) {
        if let State::Running(resolution) = &mut self.state {
            resolution.receive_shared(reply, now);
        }
    }

    /// How it ended, and the `RRset` cache's TTL bounds; `None` before it did.
    pub(crate) fn ended(&self) -> Option<(&Ended, &Config)> {
        match &self.state {
            State::Ended(ended) => Some((ended, self.caches.rrsets.config())),
            State::Ready | State::Running(_) => None,
        }
    }
}

/// The response to `question` of `resolved`: its rcode, and its `RRsets` in a message, each with its time left in the cache
/// bounded as `config` bounds it (D124): the resolution gives the TTL it was received with. RRSIGs go only to a
/// client that asked with DO (RFC 4035 §3.2.1).
pub(crate) fn message(
    question: &Question<'static>,
    resolved: &Resolved,
    config: &Config,
    dnssec: bool,
) -> (Rcode, Message<'static>) {
    let records = |section: &mut Vec<Record<'static>>, ranked: &Ranked| {
        let ttl = Ttl::from_wire(config.lifetime(ranked.ttl, ranked.checked).unwrap_or(0));
        let rrset = &ranked.rrset;
        let signatures = if dnssec { rrset.rrsigs() } else { &[] };
        section.extend(rrset.rdatas().iter().chain(signatures).map(|rdata| Record {
            name: rrset.owner().clone(),
            class: rrset.class(),
            ttl,
            rdata: rdata.clone(),
        }));
    };
    // A response to the question, as the cache stage stores one (RFC 1035 §4.1.1).
    let mut message = Message::default();
    message.header.flags = Flags::QR;
    message.questions = vec![question.clone()];
    let (chain, rcode) = match resolved {
        Resolved::Answer { chain, data } => {
            for ranked in chain.iter().chain([data]) {
                records(&mut message.answer, ranked);
            }
            return (Rcode::NOERROR, message);
        }
        Resolved::NoData { chain, soa } => {
            records(&mut message.authority, soa);
            (chain, Rcode::NOERROR)
        }
        Resolved::NxDomain { chain, soa } => {
            records(&mut message.authority, soa);
            (chain, Rcode::NXDOMAIN)
        }
        Resolved::YxDomain { chain } => (chain, Rcode::YXDOMAIN),
        Resolved::Failed(_) => return (Rcode::SERVFAIL, message),
    };
    for ranked in chain {
        records(&mut message.answer, ranked);
    }
    (rcode, message)
}

/// `now` in whole seconds, the clock of the caches and budgets.
fn secs(now: Duration) -> u32 {
    u32::try_from(now.as_secs()).unwrap_or(u32::MAX)
}
