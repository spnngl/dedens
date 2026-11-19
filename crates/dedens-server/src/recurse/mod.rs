//! The recurse stage (D195): the pipeline's last stage when the server resolves names itself, from the root down
//! (RFC 1034 §5.3.3), instead of forwarding them. Sans-IO as the rest of the pipeline: [`Resolving`] is a client's
//! question, or the priming of the root's servers (RFC 8109 §3), which the caller steps, sending each query it gives
//! to an authoritative server and handing back the reply, until it is done; [`Pipeline::resolved`] then writes the
//! reply.
//!
//! A stage [`Recurse::validating`] validates what it resolves for a client without CD (RFC 4035 §5), within the
//! allowance of D77 and the client network's share of it (D117), as a validating forward stage does: the
//! validator's questions are resolved by the same resolution (D197).
//!
//! [`Pipeline::resolved`]: crate::Pipeline::resolved

mod local;

use std::net::IpAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use dedens_proto::edns::{Cookie, InfoCode};
use dedens_proto::{Class, Message, Name, Question, Rcode, RecordType, Transport};
use dedens_resolver::{
    Caches, Failure, Limits, Minimisation, Query, Reply, Resolution, Resolved, Unsupported,
};
use rand_core::CryptoRng;
use thiserror::Error;

use self::local::LocalZones;
use crate::budget::{Budgets, Slot, Spent};
use crate::validate::{Payer, Source, Validating, work};

/// Resolves the questions that reach it, sharing its caches with every thread: the root's and the TLDs' servers
/// from the hints, the `RRset` and infrastructure caches (D191, D193, D194), its questions minimised (D198). The zones served locally are answered
/// without a query (RFC 6303 §3, RFC 8375 §4, RFC 9462 §6.4, RFC 6761 §6.3, §6.4).
#[derive(Debug)]
pub struct Recurse {
    caches: Arc<Caches>,
    limits: Limits,
    minimisation: Minimisation,
    local: LocalZones,
    /// What each client network may spend of the queries sent (D117), none for the rate limit's exempt sources.
    share: Option<Arc<Budgets>>,
    /// Whether the root's servers are being primed: one priming at a time, whichever thread starts it.
    priming: Arc<AtomicBool>,
    /// The validator of what it resolves, if it validates.
    validation: Option<Validating>,
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
            minimisation: Minimisation::default(),
            local: LocalZones::default(),
            share: None,
            priming: Arc::new(AtomicBool::new(false)),
            validation: None,
        }
    }

    /// The same stage, validating with `validation` what it resolves for a client without CD (D197): an answer it
    /// proves authentic has AD, a bogus one is SERVFAIL with its extended error (RFC 4035 §5.5, RFC 8914). Each
    /// client query takes a unit of the allowance and of its network's share (D77, D117) and is charged the
    /// validator's questions and work: one that finds either spent gets SERVFAIL with EDE 14 (Not Ready), not
    /// parked as a forward stage's is (D186), and one past `Allowance::per_query` is indeterminate.
    #[must_use]
    pub fn validating(mut self, validation: Validating) -> Self {
        self.validation = Some(validation);
        self
    }

    /// The validation of [`Recurse::validating`], `None` when the stage does not validate.
    #[must_use]
    pub const fn validation(&self) -> Option<&Validating> {
        self.validation.as_ref()
    }

    /// The [`Validating::tagged`] name of the validation, `None` when the stage does not validate.
    #[must_use]
    pub fn validation_tag(&self) -> Option<&str> {
        self.validation.as_ref().map(Validating::tag)
    }

    /// The same stage within `limits`.
    #[must_use]
    pub const fn with_limits(mut self, limits: Limits) -> Self {
        self.limits = limits;
        self
    }

    /// The same stage minimising the names it asks as `minimisation` says (D198).
    #[must_use]
    pub const fn with_minimisation(mut self, minimisation: Minimisation) -> Self {
        self.minimisation = minimisation;
        self
    }

    /// The same stage, each query sent paid by the client's network from `share` (D117): one unit a query, and a
    /// client whose network has none left gets SERVFAIL with EDE 14 (Not Ready). A stage built on reload with the
    /// same budget takes over the buckets of the one before ([`Recurse::share`]).
    #[must_use]
    pub fn with_share(mut self, share: impl Into<Arc<Budgets>>) -> Self {
        self.share = Some(share.into());
        self
    }

    /// What each client network may spend of the queries sent, if bounded.
    #[must_use]
    pub const fn share(&self) -> Option<&Arc<Budgets>> {
        self.share.as_ref()
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

    /// The zones it serves locally: a cache stage before it holds what the others resolved to, and is flushed on
    /// reload when they change (D195).
    pub fn local_zones(&self) -> impl Iterator<Item = &Name<'static>> {
        self.local.names()
    }

    /// The caches it resolves from: a stage built on reload with the same settings takes them over.
    #[must_use]
    pub const fn caches(&self) -> &Arc<Caches> {
        &self.caches
    }

    /// The bounds of each resolution.
    #[must_use]
    pub const fn limits(&self) -> Limits {
        self.limits
    }

    /// How much of the names it asks it shows each server.
    #[must_use]
    pub const fn minimisation(&self) -> Minimisation {
        self.minimisation
    }

    /// The answer of a locally served zone to `question`, if one holds it.
    pub(crate) fn local(&self, question: &Question<'_>) -> Option<(Rcode, Message<'static>)> {
        self.local.answer(question)
    }

    /// The resolution of `question` for a client: `client` at `stage`, storing into the cache stage `cache`, the
    /// queries paid by the network of `from` unless `exempt`, validated unless the client set CD (`checking`
    /// false).
    pub(crate) fn resolving_for(
        &self,
        question: Question<'static>,
        client: Asking,
        (from, proven, exempt): (IpAddr, bool, bool),
        checking: bool,
    ) -> Box<Resolving> {
        let payer = self
            .share
            .as_ref()
            .filter(|_| !exempt)
            .map(|share| (Arc::clone(share), Slot::new(from, proven)));
        let source = Source {
            address: from,
            proven,
        };
        let validation = self
            .validation
            .as_ref()
            .filter(|_| checking)
            .map(|validating| {
                Box::new(Charging {
                    validating: validating.clone(),
                    payer: Payer::new(source, exempt),
                    charged: 0,
                })
            });
        Box::new(Resolving {
            validation,
            state: State::Ready,
            question,
            caches: Arc::clone(&self.caches),
            limits: self.limits,
            minimisation: self.minimisation,
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
            minimisation: self.minimisation,
            paid: 0,
            payer: None,
            validation: None,
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
    minimisation: Minimisation,
    /// The queries paid for so far.
    paid: usize,
    payer: Option<(Arc<Budgets>, Slot)>,
    /// The validation of the answer, and who pays for it; `None` when not validated.
    validation: Option<Box<Charging>>,
    pub(crate) asker: Asker,
}

/// The allowance a resolution's validation spends (D77, D117).
#[derive(Debug)]
struct Charging {
    validating: Validating,
    payer: Payer,
    /// What the allowance was charged so far, in units.
    charged: u32,
}

impl Charging {
    /// Charges what the validation of `resolution` cost since the last time: its questions and its work. Tells how
    /// it ends when it may ask no more, still validating: past `Allowance::per_query` it is indeterminate, and with
    /// the allowance or the share in debt it is shed, as a forward stage's validation is (D106).
    fn charge(&mut self, resolution: &Resolution, validating: bool) -> Option<Ended> {
        let cost = resolution.validation_cost()?;
        let spent = u32::try_from(cost.questions)
            .unwrap_or(u32::MAX)
            .saturating_add(work(cost));
        let validation = &self.validating;
        validation.charge(self.payer, spent.saturating_sub(self.charged));
        self.charged = spent;
        if !validating {
            None
        } else if spent > validation.allowance().per_query {
            let failure = Failure::Indeterminate(InfoCode::DNSSEC_INDETERMINATE);
            Some(Ended::Resolved(Resolved::Failed(failure)))
        } else {
            validation.shed(self.payer).then_some(Ended::Shed)
        }
    }
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
    /// The client's network had nothing left to pay a query with (D117), or too many resolutions waited on its
    /// query ([`Resolving::shed`]).
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
    /// network first (D117); it ends there when the network has nothing left. A validated one takes a unit of
    /// the validation's allowance first, and is charged its work as it goes (D77).
    pub fn step(&mut self, now: Duration, rng: &mut impl CryptoRng) -> Turn<'_> {
        if let State::Ready = self.state {
            self.state = self.start(now);
        }
        let State::Running(resolution) = &mut self.state else {
            return Turn::Done;
        };
        // Stepping again without a reply gives the same, so the query is taken once paid for.
        let done = match resolution.step(now, rng) {
            dedens_resolver::Next::Done(resolved) => Some(resolved.clone()),
            dedens_resolver::Next::Send(_) => None,
        };
        // A validation that may ask no more ends here, before its query is paid for.
        let over = self
            .validation
            .as_mut()
            .and_then(|charging| charging.charge(resolution, done.is_none()));
        let ended = match done {
            _ if over.is_some() => over,
            Some(resolved) => Some(Ended::Resolved(resolved)),
            None => {
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

    /// The state the first step leaves: the resolution started, validated if it is to be once the allowance
    /// admits it, or ended.
    fn start(&self, now: Duration) -> State {
        if let Some(charging) = &self.validation
            && let Err(spent) = charging.validating.admit(charging.payer, secs(now))
        {
            // The share's unit taken when the allowance refuses goes back: the query is not parked (D186).
            if spent == Spent::Global {
                charging.validating.give_up(charging.payer);
            }
            return State::Ended(Ended::Shed);
        }
        match Resolution::start(
            self.question.clone(),
            Arc::clone(&self.caches),
            now,
            self.limits,
            self.minimisation,
        ) {
            Ok(resolution) => State::Running(Box::new(match &self.validation {
                Some(charging) => {
                    let validating = &charging.validating;
                    resolution.validated(validating.validator().clone(), validating.unix())
                }
                None => resolution,
            })),
            Err(unsupported) => State::Ended(Ended::Unsupported(unsupported)),
        }
    }

    /// Whether its answer was validated: the reply is then the verdict's (D197).
    pub(crate) const fn validated(&self) -> bool {
        self.validation.is_some()
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

    /// Ends it shed, without sending the query [`Resolving::step`] gave: too many resolutions wait on the same one
    /// (D195). The client's network gets back the unit the query took, as nothing was sent, and the client gets
    /// SERVFAIL Not Ready, as one whose network has nothing left (D117).
    pub fn shed(&mut self) {
        if let State::Running(_) = self.state {
            // A query given was paid for, unless the client is exempt.
            if let Some((share, slot)) = &self.payer {
                share.refund(*slot);
            }
            self.state = State::Ended(Ended::Shed);
        }
    }

    /// What it resolved to; `None` before it ended, or when it ended shed or unsupported.
    #[must_use]
    pub const fn resolved(&self) -> Option<&Resolved> {
        match &self.state {
            State::Ended(Ended::Resolved(resolved)) => Some(resolved),
            State::Ended(Ended::Shed | Ended::Unsupported(_))
            | State::Ready
            | State::Running(_) => None,
        }
    }

    /// How it ended; `None` before it did.
    pub(crate) const fn ended(&self) -> Option<&Ended> {
        match &self.state {
            State::Ended(ended) => Some(ended),
            State::Ready | State::Running(_) => None,
        }
    }
}

/// `now` in whole seconds, the clock of the caches and budgets.
fn secs(now: Duration) -> u32 {
    u32::try_from(now.as_secs()).unwrap_or(u32::MAX)
}
