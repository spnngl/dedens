//! A recursive resolution, sans-IO: from the closest delegation known, down the referrals to the answer, one query
//! in flight (RFC 1034 §5.3.3, RFC 1035 §7, D191).
//!
//! The caller drives it: [`Resolution::step`] says what to ask of which server, or that it is done;
//! [`Resolution::receive`] hands it the reply. The transport owns the exchange: the ID, EDNS and DO, `0x20`, TCP
//! after truncation, and matching the response to the query (RFC 5452 §9.1, D190). Every response is read through
//! [`scrub()`](crate::scrub()), whose outcome alone decides what the resolution does next and what the caches learn
//! (D192). Every bound of [`Limits`] ends it with a [`Failure`], so no answer from the Internet keeps it going.

use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, SocketAddr};
use std::slice;
use std::sync::Arc;
use std::time::Duration;

use dedens_cache::Checked;
use dedens_proto::edns::InfoCode;
use dedens_proto::rdata::RData;
use dedens_proto::{Class, MAX_NAME_LEN, Message, Name, Question, Record, RecordType, Ttl};
use dedens_roots::{RootHints, Server, Tlds};
use rand_core::CryptoRng;
use thiserror::Error;
use tracing::debug;

use crate::infra_cache::{self, Choice, InfraCache, Marks};
use crate::metrics::Sent;
use crate::rank::Rank;
use crate::rrset::{self, Rrset};
use crate::rrset_cache::{Ranked, RrsetCache};
use crate::scrub::{Outcome, scrub};

/// What a resolution starts from and adds to: the caches, and the hints for when they know no delegation.
#[derive(Debug)]
pub struct Caches {
    /// What the resolver learned, `RRset` by `RRset` (D193).
    pub rrsets: RrsetCache,
    /// What it knows of the servers (D194).
    pub infra: InfraCache,
    /// The root's servers (RFC 9609 §2).
    pub roots: RootHints,
    /// The servers of the TLDs, to start below the root (D191); `None` starts every resolution the cache cannot
    /// at the root.
    pub tlds: Option<Tlds>,
}

/// The bounds of a resolution: each ends it, or the branch that reached it, so that a zone made to loop or to fan
/// out costs a bounded number of queries (RFC 1035 §7.1, RFC 9520 §3).
///
/// The defaults are the lower of Unbound's and BIND's, unless D191 says otherwise.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Limits {
    /// Queries sent for the client's question, its sub-resolutions included: 32, Unbound's `max-sent-count`
    /// (`util/config_file.c` `config_create`); BIND's `max-recursion-queries` is 50. It caps what one client
    /// question costs, whatever the delegations it meets.
    pub queries: usize,
    /// CNAME hops followed, one per CNAME, from the cache or a response, for the question and its
    /// sub-resolutions: 11, Unbound's `max-query-restarts` (`util/config_file.c`) and BIND's
    /// (`bin/include/defaultconfig.h`).
    pub restarts: usize,
    /// Referrals followed: 30, below Unbound's 130 (`MAX_REFERRAL_COUNT`, `iterator/iterator.h`) and hickory's
    /// 24-deep recursion (`recursion_limit`): the deepest captured resolution follows 4, and the deepest name 127.
    pub referrals: usize,
    /// Sub-resolutions waiting on one another for a server's address: 4, Unbound's `target-fetch-policy`
    /// "3 2 1 0 0" (`iterator/iter_utils.c` `read_fetch_policy`); BIND's `max-recursion-depth` is 7.
    pub depth: usize,
    /// Addresses asked per delegation, and server names kept of a referral: 13, BIND's `max-delegation-servers`
    /// (`bin/include/defaultconfig.h`), the most a referral needs (RFC 1035 §4.2.1's 512 bytes hold 13 root
    /// servers). A delegation that asked as many looks up no more addresses.
    pub servers: usize,
    /// Address lookups per delegation, its servers' A and AAAA each counting: 5, Unbound's `MAX_TARGET_NX`
    /// (`iterator/iterator.h`) against `NXNSAttack` (CVE-2020-12662). Unbound counts the lookups answered NXDOMAIN,
    /// per client question, and allows 16 lookups per delegation (`MAX_DP_TARGET_COUNT`); here a name whose A is
    /// NXDOMAIN has its AAAA skipped (D191).
    pub targets: usize,
    /// Time from start to answer: 4.5 s, a stub's 5 s timer (glibc's `RES_TIMEOUT`) less the time for the
    /// SERVFAIL to reach it before it asks again.
    pub time: Duration,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            queries: 32,
            restarts: 11,
            referrals: 30,
            depth: 4,
            servers: 13,
            targets: 5,
            time: Duration::from_millis(4500),
        }
    }
}

/// How much of the name a resolution shows the servers above it (RFC 9156, D198).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum Minimisation {
    /// The full name to every server.
    Off,
    /// Each zone's servers asked the name one label below the zone, type A (RFC 9156 §2.1, §3), the full name
    /// after a minimised question failed: answered NXDOMAIN, REFUSED, SERVFAIL or not usable, or 3 timeouts in a
    /// row (Unbound's `qname-minimisation-strict: no`).
    #[default]
    Relaxed,
    /// As [`Minimisation::Relaxed`] with no fallback: NXDOMAIN on a minimised name ends the resolution (RFC 8020
    /// §2), other failures have the next server asked the minimised name.
    Strict,
}

/// A bound of [`Limits`] reached.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum Limit {
    /// [`Limits::queries`].
    #[error("queries")]
    Queries,
    /// [`Limits::restarts`].
    #[error("CNAME restarts")]
    Restarts,
    /// [`Limits::referrals`].
    #[error("referrals")]
    Referrals,
    /// [`Limits::depth`].
    #[error("glueless depth")]
    Depth,
    /// [`Limits::servers`].
    #[error("servers per delegation")]
    Servers,
    /// [`Limits::targets`].
    #[error("address lookups per delegation")]
    Targets,
    /// [`Limits::time`].
    #[error("time")]
    Time,
}

/// Why a resolution gives no answer: the client gets SERVFAIL with [`Failure::info_code`] (RFC 8914 §4, D191).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum Failure {
    /// A bound reached, here or in a sub-resolution the answer waited on.
    #[error("{0} limit reached")]
    Limit(Limit),
    /// No server of the delegation asked answered in time.
    #[error("no server answered")]
    Unreachable,
    /// No server answered, and some exchanges failed: the network refused them, or ours did.
    #[error("network error")]
    Network,
    /// Servers responded, none with an answer, a denial or a referral: lame, refusing, failing.
    #[error("no server answered usably")]
    Unusable,
}

impl Failure {
    /// The extended error of the SERVFAIL: No Reachable Authority for a bound or no response, Network Error for
    /// failed exchanges, Other for responses none of which served.
    #[must_use]
    pub const fn info_code(self) -> InfoCode {
        match self {
            Self::Limit(_) | Self::Unreachable => InfoCode::NO_REACHABLE_AUTHORITY,
            Self::Network => InfoCode::NETWORK_ERROR,
            Self::Unusable => InfoCode::OTHER,
        }
    }
}

/// A question a resolution does not take: its type or class is not data (RFC 6895 §3.1, §3.2), or its class is
/// not IN, the only one with a root.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum Unsupported {
    /// ANY, AXFR, OPT and the other QTYPEs and meta types; and RRSIG, no `RRset` of its own but part of the one it
    /// covers (D176), so neither cached nor an answer of [`Resolved`] (D191).
    #[error("type {0} is not resolved")]
    Type(RecordType),
    /// A class other than IN.
    #[error("class {0} is not resolved")]
    Class(Class),
}

/// How a resolution ends. Each `RRset` was cached as it came, at the rank the scrubber gave it (D192), and is given
/// with the TTL to serve it with: its time left when the cache gave it, else the TTL it came with bounded as the
/// cache bounds what it stores (D124). Never bound twice: a floor raising a time left serves expired data.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Resolved {
    /// The data, after the CNAMEs leading to it.
    Answer {
        /// The CNAMEs from the name asked, in order.
        chain: Vec<Ranked>,
        /// The data at the chain's end.
        data: Ranked,
    },
    /// The name, or the chain's end, has no data of the type (RFC 2308 §2.2).
    NoData {
        /// The CNAMEs from the name asked, in order.
        chain: Vec<Ranked>,
        /// The zone's SOA, without which a denial is not taken (RFC 2308 §5).
        soa: Ranked,
    },
    /// The name, or the chain's end, does not exist (RFC 2308 §2.1).
    NxDomain {
        /// The CNAMEs from the name asked, in order.
        chain: Vec<Ranked>,
        /// The zone's SOA.
        soa: Ranked,
    },
    /// A DNAME makes the chain's end longer than 255 bytes (RFC 6672 §2.2).
    YxDomain {
        /// The CNAMEs from the name asked, the DNAME last.
        chain: Vec<Ranked>,
    },
    /// No answer.
    Failed(Failure),
}

/// A query to send: what to ask of which server, as a server of which zone. The transport builds the message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Query {
    /// The question, class IN; the transport varies its case unless [`Marks::no_case`] (D184).
    pub question: Question<'static>,
    /// The server, port 53.
    pub server: SocketAddr,
    /// The zone it is asked as a server of.
    pub zone: Name<'static>,
    /// What the server showed of itself: EDNS, case, TCP (D194).
    pub marks: Marks,
    /// How long the exchange may take before [`Reply::Timeout`]: the server's retransmission timeout, at most the
    /// time the resolution has left.
    pub timeout: Duration,
    /// The time the resolution has left (D191): what a resolution waiting on the same query sent by another may
    /// wait for its reply (D195), the sender's timeout being its server's, not this one's.
    pub left: Duration,
}

/// What the resolution does next.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Next<'a> {
    /// Send this query, then [`Resolution::receive`] its reply; asked again before that, it is the same query.
    Send(&'a Query),
    /// It is over.
    Done(&'a Resolved),
}

/// The reply to the query sent, as the transport ends the exchange.
#[derive(Debug, Clone, Copy)]
pub enum Reply<'a> {
    /// The response matched to the query, and what the transport saw of the server.
    Response {
        /// The response.
        message: &'a Message<'a>,
        /// The server's quirks seen.
        seen: Marks,
        /// The transport's round-trip time, from its last query to this response (D190's `Response::rtt`): not
        /// the time since [`Resolution::step`] gave the query, which counts waits for a socket, the TCP retry
        /// after truncation and the EDNS fallback.
        rtt: Duration,
    },
    /// A response matched to the query that does not decode (RFC 1035 §4.1): the next server is asked and nothing
    /// is remembered of this one, as Unbound's `process_response` ignores a response it cannot parse.
    Undecodable,
    /// No response within [`Query::timeout`]: D190's `ServerError::TimedOut`. A delegation whose servers all time out
    /// fails [`Failure::Unreachable`], EDE 22 (No Reachable Authority).
    Timeout,
    /// The server could not be reached, or would not talk: ICMP unreachable, TCP refused or reset, responses
    /// dropped for their cookie only (D190's `ServerError` but `TimedOut`, which is [`Reply::Timeout`]). It is backed
    /// off as after a timeout, and makes a delegation that fails [`Failure::Network`], EDE 23 (Network Error).
    ServerError,
    /// The exchange failed here, before the server had a say: the server is not blamed (D191).
    LocalError,
}

/// A recursive resolution of one question.
#[derive(Debug)]
pub struct Resolution {
    caches: Arc<Caches>,
    limits: Limits,
    minimisation: Minimisation,
    /// When it started, for [`Limits::time`].
    started: Duration,
    /// When it started, on the caches' clock: the time an NS `RRset` is stored at (D193).
    started_secs: u32,
    sent: usize,
    restarts: usize,
    referrals: usize,
    /// The first per-branch bound reached, reported if the question fails.
    limit: Option<Limit>,
    tasks: Tasks,
    /// The addresses each sub-resolution found, by the question it started with, so that one asked twice is
    /// resolved once.
    found: HashMap<Question<'static>, Vec<IpAddr>>,
    /// The query awaiting its reply, or the outcome; `None` while working out the next query.
    settled: Option<Settled>,
}

/// Where a resolution waits.
#[derive(Debug)]
enum Settled {
    /// For the reply to the query.
    Waiting(Query),
    Done(Resolved),
}

/// The client's question, and the sub-resolutions it waits on, the last one active.
#[derive(Debug)]
struct Tasks {
    client: Task,
    lookups: Vec<Task>,
}

impl Tasks {
    fn active(&mut self) -> &mut Task {
        self.lookups.last_mut().unwrap_or(&mut self.client)
    }

    /// The delegation the active task asks.
    fn asking(&mut self) -> Option<&mut Delegation> {
        match &mut self.active().at {
            At::Asking(delegation) => Some(delegation),
            At::Start => None,
        }
    }

    /// The active sub-resolution, taken off, when `zone` is one its ancestors are stuck on: one waits for it, for
    /// an address of a server of `zone`, so that following `zone` would loop (D191).
    fn looping(&mut self, zone: &Name<'_>) -> Option<Task> {
        let (_, ancestors) = self.lookups.split_last()?;
        let stuck = [&self.client]
            .into_iter()
            .chain(ancestors)
            .any(|task| matches!(&task.at, At::Asking(delegation) if delegation.zone == *zone));
        if stuck { self.lookups.pop() } else { None }
    }
}

/// A question being resolved: the client's, or a server's address.
#[derive(Debug)]
struct Task {
    /// The question it started with.
    question: Question<'static>,
    /// The question asked now: at the end of the CNAMEs followed.
    asked: Question<'static>,
    /// The CNAMEs followed so far.
    chain: Vec<Ranked>,
    at: At,
    minimise: Minimise,
}

impl Task {
    fn new(question: Question<'static>, minimisation: Minimisation) -> Self {
        Self {
            asked: question.clone(),
            question,
            chain: Vec::new(),
            at: At::Start,
            minimise: Minimise::new(minimisation),
        }
    }

    /// Moves the minimised question one step down from the zone it asks, or from the last one asked if below
    /// (RFC 9156 §3 step 3; Unbound's `processQueryTargets`): to the full question once it reaches the name.
    fn descend(&mut self) {
        let At::Asking(delegation) = &self.at else {
            return;
        };
        let Minimise::On {
            question,
            count,
            timeouts,
        } = &mut self.minimise
        else {
            return;
        };
        let zone = delegation.zone.label_count();
        if question.name.label_count() < zone {
            *count = 0;
            question.name = delegation.zone.clone();
        }
        *count += 1;
        *timeouts = 0;
        let full = self.asked.name.label_count();
        let labels = minimised(full, question.name.label_count(), *count);
        if labels >= full {
            self.minimise = Minimise::Off;
        } else {
            question.name = ancestor(&self.asked.name, labels);
        }
    }
}

/// Where a task's minimisation stands (RFC 9156 §3).
#[derive(Debug)]
enum Minimise {
    /// The full question is asked.
    Off,
    /// An ancestor of the name is asked, type A (RFC 9156 §2.1).
    On {
        question: Question<'static>,
        /// Minimised questions asked for the name, toward [`MINIMISE_COUNT`].
        count: usize,
        /// Timeouts in a row on `question`, toward [`MINIMISE_TIMEOUTS`].
        timeouts: usize,
    },
}

impl Minimise {
    /// The state of a new name: the root, below which [`Task::descend`] takes the zone asked.
    fn new(minimisation: Minimisation) -> Self {
        match minimisation {
            Minimisation::Off => Self::Off,
            Minimisation::Relaxed | Minimisation::Strict => Self::On {
                question: Question::new(Name::root(), RecordType::A),
                count: 0,
                timeouts: 0,
            },
        }
    }
}

/// Minimised questions per name, the last one the full name: 10, RFC 9156 §2.3's `MAX_MINIMISE_COUNT` and
/// Unbound's (`iterator/iterator.h`). It bounds what a long name costs: 34 labels of `ip6.arpa` take 10 queries
/// with referrals, not 34.
const MINIMISE_COUNT: usize = 10;
/// The first minimised questions, each one label longer: 4, RFC 9156 §2.3's `MINIMISE_ONE_LAB` and Unbound's.
const ONE_LABEL: usize = 4;
/// Timeouts in a row on one minimised question before [`Minimisation::Relaxed`] asks the full name: 3, Unbound's
/// `MAX_MINIMISE_TIMEOUT_COUNT` (`iterator/iterator.h`).
const MINIMISE_TIMEOUTS: usize = 3;

/// The labels of the `count`th minimised question of a name of `full` labels, after one of `last` labels
/// (RFC 9156 §2.3; Unbound's `processQueryTargets`): one label more for the first [`ONE_LABEL`], then as many as
/// spread the rest of a name of [`MINIMISE_COUNT`] labels or more over the questions left, the full name at the
/// [`MINIMISE_COUNT`]th.
fn minimised(full: usize, last: usize, count: usize) -> usize {
    if count >= MINIMISE_COUNT {
        return full;
    }
    // Unbound counts the root label: its `qchaselabs > MAX_MINIMISE_COUNT` is `full >= MINIMISE_COUNT` here.
    let extra = if full >= MINIMISE_COUNT && count > ONE_LABEL {
        let several = full - ONE_LABEL;
        let questions = MINIMISE_COUNT - ONE_LABEL;
        let extra = several / questions;
        if MINIMISE_COUNT - count >= several % questions {
            extra - 1
        } else {
            extra
        }
    } else {
        0
    };
    (last + 1 + extra).min(full)
}

/// The ancestor of `name` with `labels` labels, `labels` at most its own.
fn ancestor(name: &Name<'_>, labels: usize) -> Name<'static> {
    let mut buf = [0; MAX_NAME_LEN];
    let wire = name.to_wire(&mut buf);
    let mut at = 0;
    for _ in labels..name.label_count() {
        at += 1 + wire.get(at).map_or(0, |&length| usize::from(length));
    }
    (wire.get(at..))
        .and_then(|suffix| Name::from_uncompressed(suffix).ok())
        .map_or_else(Name::root, Name::into_owned)
}

#[derive(Debug)]
enum At {
    /// Looking for an answer or the closest delegation in the cache.
    Start,
    /// Asking the servers of a delegation.
    Asking(Delegation),
}

/// Where a delegation's NS records come from, which says when an NS `RRset` it refers to is stored (D193).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Source {
    /// A referral, or the hints.
    Parent,
    /// The cache.
    Cache,
}

/// What the servers of a delegation did, the most telling kept: the failure if none serves.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum Heard {
    /// Timeouts, if anything.
    Nothing,
    /// Failed exchanges.
    Errors,
    /// Responses.
    Responses,
}

impl Heard {
    const fn failure(self) -> Failure {
        match self {
            Self::Nothing => Failure::Unreachable,
            Self::Errors => Failure::Network,
            Self::Responses => Failure::Unusable,
        }
    }
}

/// A zone's servers, as far as known.
#[derive(Debug)]
struct Delegation {
    zone: Name<'static>,
    source: Source,
    /// The addresses known, asked or not.
    known: HashSet<IpAddr>,
    /// The addresses not asked yet.
    untried: Vec<SocketAddr>,
    /// The addresses whose last query timed out, asked again once nothing new is left to ask (RFC 1035 §7.2, D196).
    timed_out: Vec<SocketAddr>,
    /// The addresses asked.
    asked: usize,
    /// Servers without an address, to look up in random order.
    missing: Vec<Name<'static>>,
    /// The server whose A was looked up last, whose AAAA comes next.
    aaaa: Option<Name<'static>>,
    /// Address lookups started.
    looked_up: usize,
    heard: Heard,
}

impl Delegation {
    fn new(
        zone: Name<'static>,
        source: Source,
        addresses: impl IntoIterator<Item = IpAddr>,
        missing: Vec<Name<'static>>,
    ) -> Self {
        let mut delegation = Self {
            zone,
            source,
            known: HashSet::new(),
            untried: Vec::new(),
            timed_out: Vec::new(),
            asked: 0,
            missing,
            aaaa: None,
            looked_up: 0,
            heard: Heard::Nothing,
        };
        delegation.add(addresses);
        delegation
    }

    /// Adds the addresses not known yet.
    fn add(&mut self, addresses: impl IntoIterator<Item = IpAddr>) {
        for address in addresses {
            if self.known.insert(address) {
                self.untried.push(SocketAddr::new(address, PORT));
            }
        }
    }
}

/// What a delegation does next.
enum Ask {
    Send(Query),
    Lookup(Question<'static>),
    Fail(Failure),
}

impl Resolution {
    /// A resolution of `question` at `now`, a time of any origin that [`Resolution::step`] and
    /// [`Resolution::receive`] keep to, its names and its servers' minimised as `minimisation` says.
    ///
    /// # Errors
    ///
    /// [`Unsupported`] when the question's type or class is not one resolved.
    pub fn start(
        question: Question<'static>,
        caches: Arc<Caches>,
        now: Duration,
        limits: Limits,
        minimisation: Minimisation,
    ) -> Result<Self, Unsupported> {
        if question.qclass != Class::IN {
            return Err(Unsupported::Class(question.qclass));
        }
        if !rrset::data_type(question.qtype) || question.qtype == RecordType::RRSIG {
            return Err(Unsupported::Type(question.qtype));
        }
        Ok(Self {
            caches,
            limits,
            minimisation,
            started: now,
            started_secs: secs(now),
            sent: 0,
            restarts: 0,
            referrals: 0,
            limit: None,
            tasks: Tasks {
                client: Task::new(question, minimisation),
                lookups: Vec::new(),
            },
            found: HashMap::new(),
            settled: None,
        })
    }

    /// Queries sent so far, which the client's budget pays for (D117).
    #[must_use]
    pub const fn sent(&self) -> usize {
        self.sent
    }

    /// What to do at `now`: the query to send, its server drawn with `rng` (RFC 5452 §4.4) as are the server names
    /// looked up, or the outcome.
    pub fn step(&mut self, now: Duration, rng: &mut impl CryptoRng) -> Next<'_> {
        let settled = loop {
            if let Some(settled) = self.settled.take() {
                break settled;
            }
            self.advance(now, rng);
        };
        match self.settled.insert(settled) {
            Settled::Waiting(query) => Next::Send(query),
            Settled::Done(outcome) => Next::Done(outcome),
        }
    }

    /// Hands over the reply to the query [`Resolution::step`] gave, at `now`; ignored when none is awaited.
    pub fn receive(&mut self, reply: Reply<'_>, now: Duration) {
        self.take(reply, now, true);
    }

    /// As [`Resolution::receive`], for the reply to the same query another resolution sent while this one waited on
    /// it (RFC 5452 §5, D195): the server is judged once, by the resolution that sent the query, so the
    /// infrastructure cache is left as that one left it. A timeout counted by each waiter would back the server off
    /// once per waiter.
    pub fn receive_shared(&mut self, reply: Reply<'_>, now: Duration) {
        self.take(reply, now, false);
    }

    /// [`Resolution::receive`], the server judged in the infrastructure cache when `judge`.
    /// The reply to `query` at `now` brought no response to read, as `sent` says: a timeout or a server error backs
    /// the server off, when it is `judge`d; a timeout tells nothing of the delegation's servers. A timeout that comes
    /// when the resolution's time is out was cut short by it, the server's own timeout not waited for: it judges no
    /// server (D195).
    fn unanswered(&mut self, query: &Query, sent: Sent, now: Duration, judge: bool) {
        debug!(server = %query.server, ?sent, "no response");
        if judge {
            crate::metrics::query(sent);
            let judged = match sent {
                Sent::Timeout => !self.remaining(now).is_zero(),
                Sent::ServerError => true,
                _ => false,
            };
            if judged {
                self.caches
                    .infra
                    .timeout(query.server, query.timeout, secs(now));
            }
        }
        match sent {
            Sent::Timeout => {
                if let Some(delegation) = self.tasks.asking() {
                    delegation.timed_out.push(query.server);
                }
            }
            Sent::Undecodable => self.heard(Heard::Responses),
            _ => self.heard(Heard::Errors),
        }
    }

    fn take(&mut self, reply: Reply<'_>, now: Duration, judge: bool) {
        let query = match self.settled.take() {
            Some(Settled::Waiting(query)) => query,
            other => {
                self.settled = other;
                debug!("reply to no query, ignored");
                return;
            }
        };
        let caches = Arc::clone(&self.caches);
        let infra = &caches.infra;
        let now_secs = secs(now);
        let server = query.server;
        let (message, seen, rtt) = match reply {
            Reply::Response { message, seen, rtt } => (message, seen, rtt),
            Reply::Undecodable => return self.unanswered(&query, Sent::Undecodable, now, judge),
            Reply::Timeout => {
                self.timed_out(&query.question);
                return self.unanswered(&query, Sent::Timeout, now, judge);
            }
            Reply::ServerError => return self.unanswered(&query, Sent::ServerError, now, judge),
            Reply::LocalError => return self.unanswered(&query, Sent::LocalError, now, judge),
        };
        self.heard(Heard::Responses);
        let scrubbed = scrub(message, &query.question, &query.zone);
        // Only a response that serves the question credits the server; one that does not, REFUSED and SERVFAIL
        // among them, has the next server asked and leaves this one as it was, as Unbound's `THROWAWAY` (D191).
        match &scrubbed.outcome {
            _ if !judge => {}
            Outcome::Lame => {
                crate::metrics::query(Sent::Lame);
                infra.lame(server, &query.zone, now_secs);
            }
            Outcome::NoSoa(_) | Outcome::Signatures { .. } | Outcome::Unusable(_) => {
                crate::metrics::query(Sent::Unusable);
            }
            _ => {
                crate::metrics::query(Sent::Answer);
                infra.reply(server, rtt, seen, now_secs);
            }
        }
        let referral = matches!(scrubbed.outcome, Outcome::Referral { .. });
        let ranked = self.cache(scrubbed.ranked(), referral, now_secs);
        let sets = |records: &[Record<'_>]| sets(records, &ranked);
        if self.minimised(&query.question) && self.went_on(&scrubbed.outcome, server) {
            return;
        }
        match &scrubbed.outcome {
            Outcome::Answer { chain, records, .. } => {
                if let Some(data) = sets(records).pop()
                    && let Some(chain) = self.hops(sets(chain))
                {
                    self.finish(Resolved::Answer { chain, data });
                }
            }
            Outcome::Cname { chain, target, .. } => {
                self.restart(sets(chain), target.clone().into_owned());
            }
            // The parent's servers asked a DS refer it to the zone below: the child has none to give, and the
            // proof the referral holds is the validator's (recursive step 10).
            Outcome::Referral { child, .. }
                if query.question.qtype == RecordType::DS && *child == query.question.name =>
            {
                debug!(%server, zone = %query.zone, %child, "DS referred to the child, not followed");
            }
            Outcome::Referral {
                child, ns, glue, ..
            } => {
                if let Some(ns) = sets(ns).pop() {
                    self.referral(child.clone().into_owned(), &ns, &sets(glue), now_secs);
                }
            }
            Outcome::NoData { soa, .. } => {
                if let Some(soa) = sets(slice::from_ref(soa)).pop()
                    && let Some(chain) = self.hops(Vec::new())
                {
                    self.finish(Resolved::NoData { chain, soa });
                }
            }
            Outcome::NxDomain { chain, soa, .. } => {
                if let Some(soa) = sets(slice::from_ref(soa)).pop()
                    && let Some(chain) = self.hops(sets(chain))
                {
                    self.finish(Resolved::NxDomain { chain, soa });
                }
            }
            Outcome::YxDomain { chain } => {
                if let Some(chain) = self.hops(sets(chain)) {
                    self.finish(Resolved::YxDomain { chain });
                }
            }
            outcome @ (Outcome::Signatures { .. }
            | Outcome::NoSoa(_)
            | Outcome::Lame
            | Outcome::Unusable(_)) => {
                debug!(%server, zone = %query.zone, ?outcome, "response not used");
            }
        }
    }

    /// The time it has left at `now` ([`Limits::time`]).
    fn remaining(&self, now: Duration) -> Duration {
        (self.limits.time).saturating_sub(now.saturating_sub(self.started))
    }

    /// One move: the active task's start, or its next query or lookup.
    fn advance(&mut self, now: Duration, rng: &mut impl CryptoRng) {
        let remaining = self.remaining(now);
        if remaining.is_zero() {
            return self.end(Limit::Time);
        }
        let now_secs = secs(now);
        let depth = self.tasks.lookups.len();
        let Task {
            asked,
            at,
            minimise,
            ..
        } = self.tasks.active();
        let At::Asking(delegation) = at else {
            return self.begin(now_secs);
        };
        let question = match minimise {
            Minimise::On { question, .. } => question,
            Minimise::Off => asked,
        };
        let ask = ask(
            delegation,
            question,
            &self.caches.infra,
            &self.limits,
            &self.found,
            depth,
            remaining,
            now_secs,
            rng,
        );
        match ask {
            Ask::Send(query) => self.send(query),
            Ask::Lookup(question) => {
                debug!(name = %question.name, rtype = %question.qtype, depth = depth + 1, "address lookup");
                (self.tasks.lookups).push(Task::new(question, self.minimisation));
            }
            Ask::Fail(failure) => {
                if let Failure::Limit(limit) = failure {
                    debug!(%limit, "limit reached");
                    crate::metrics::limit(limit);
                    self.limit.get_or_insert(limit);
                }
                self.finish(Resolved::Failed(failure));
            }
        }
    }

    /// The start of the active task: its answer or CNAME in the cache, else the closest delegation known, above
    /// the name for a DS, which the parent's servers hold (RFC 4035 §3.1.4.1; Unbound's `processInitRequest`).
    fn begin(&mut self, now: u32) {
        let caches = Arc::clone(&self.caches);
        let rrsets = &caches.rrsets;
        let task = self.tasks.active();
        let Question { name, qtype, .. } = &task.asked;
        let qtype = *qtype;
        if let Some(data) = rrsets.get(name, qtype, Class::IN, now).filter(answers) {
            debug!(%name, rtype = %qtype, "answered from the cache");
            let chain = std::mem::take(&mut task.chain);
            return self.finish(Resolved::Answer { chain, data });
        }
        if qtype != RecordType::CNAME
            && let Some(cname) = rrsets
                .get(name, RecordType::CNAME, Class::IN, now)
                .filter(answers)
            && let Some(target) = target(&cname.rrset)
        {
            return self.restart(vec![cname], target);
        }
        let parent = qtype == RecordType::DS;
        let delegation = closest(&caches, name, parent, self.limits.servers, now);
        if let Some(task) = self.tasks.looping(&delegation.zone) {
            return self.abandon(&task);
        }
        let task = self.tasks.active();
        task.at = At::Asking(delegation);
        task.descend();
    }

    /// Whether `question` is the active task's minimised question.
    fn minimised(&mut self, question: &Question<'_>) -> bool {
        matches!(&self.tasks.active().minimise, Minimise::On { question: asked, .. } if asked == question)
    }

    /// Whether `outcome`, from `server` to the minimised question, had the next question chosen (RFC 9156 §3
    /// step 6); else it is read as any other response.
    fn went_on(&mut self, outcome: &Outcome<'_>, server: SocketAddr) -> bool {
        let full = match outcome {
            Outcome::Referral { .. } => return false,
            // The name exists: the next label is asked (RFC 9156 §3 step 6c), of any server.
            Outcome::Answer { .. } | Outcome::Cname { .. } | Outcome::NoData { .. } => false,
            // A CNAME to a name that does not exist: the name asked does (step 6c), and the chain is no answer for
            // the client's name.
            Outcome::NxDomain { chain, .. } if !chain.is_empty() => false,
            // Strict, NXDOMAIN ends the resolution (RFC 8020 §2), any other response has the next server asked the
            // same question.
            _ if self.minimisation == Minimisation::Strict => return false,
            // A server may answer NXDOMAIN for an empty non-terminal, or fail on a name it does not expect: the
            // full name is asked, of any server, as Unbound's relaxed mode does (RFC 9156 §1, §3).
            _ => true,
        };
        self.give_back(server, full);
        true
    }

    /// After a response to the minimised question from `server`: `server` may be asked again, the next question
    /// being another, the full name's when `full`, else the next minimised one. Each zone's servers may then hear
    /// as many questions as [`MINIMISE_COUNT`] allows, each within [`Limits::queries`].
    fn give_back(&mut self, server: SocketAddr, full: bool) {
        let task = self.tasks.active();
        if let At::Asking(delegation) = &mut task.at {
            delegation.untried.push(server);
            delegation.asked = delegation.asked.saturating_sub(1);
        }
        if full {
            debug!(name = %task.asked.name, "minimisation failed, the full name asked");
            task.minimise = Minimise::Off;
        } else {
            task.descend();
        }
    }

    /// Counts a timeout on `question`, the active task's minimised question: [`MINIMISE_TIMEOUTS`] in a row have
    /// [`Minimisation::Relaxed`] ask the full name.
    fn timed_out(&mut self, question: &Question<'static>) {
        let relaxed = self.minimisation == Minimisation::Relaxed;
        let task = self.tasks.active();
        if let Minimise::On {
            question: asked,
            timeouts,
            ..
        } = &mut task.minimise
            && asked == question
            && relaxed
        {
            *timeouts += 1;
            if *timeouts >= MINIMISE_TIMEOUTS {
                debug!(name = %task.asked.name, "minimised questions time out, the full name asked");
                task.minimise = Minimise::Off;
            }
        }
    }

    /// Caches the `RRsets` the scrubber kept, at the rank it gave each (D192), and returns them. The NS records of
    /// a `referral` through a delegation the cache gave are stored as of the resolution's start, so that they cannot
    /// refresh an NS `RRset` that had expired by then (Unbound's `store_rrsets`, D193).
    fn cache(&mut self, ranked: Vec<(Rank, Rrset)>, referral: bool, now: u32) -> Vec<Ranked> {
        let from_cache = self
            .tasks
            .asking()
            .is_some_and(|delegation| delegation.source == Source::Cache);
        let mut kept = Vec::with_capacity(ranked.len());
        for (rank, set) in ranked {
            let at = if referral && from_cache && set.rtype() == RecordType::NS {
                self.started_secs
            } else {
                now
            };
            let rrset = Arc::new(set);
            // The resolution reads what this server said whatever the cache did: an `RRset` too large, or one the
            // cache trusts more and keeps, changes what later questions find, not this response.
            if let Err(error) =
                (self.caches.rrsets).insert(Arc::clone(&rrset), rank, Checked::Unchecked, at)
            {
                debug!(owner = %rrset.owner(), rtype = %rrset.rtype(), %error, "not cached");
            }
            // Bounded as the cache bounds what it stores (D124), as a cache hit's time left is, but from the TTL
            // received: what the cache did with it changes what later questions find, not this response.
            let ttl = (self.caches.rrsets.config())
                .lifetime(rrset.ttl(), Checked::Unchecked)
                .unwrap_or(0);
            kept.push(Ranked {
                ttl: Ttl::from_wire(ttl),
                rrset,
                rank,
                checked: Checked::Unchecked,
            });
        }
        kept
    }

    /// The active task's chain, taken, followed by `chain`, within [`Limits::restarts`]: `None` when the
    /// resolution ends there.
    fn hops(&mut self, mut chain: Vec<Ranked>) -> Option<Vec<Ranked>> {
        self.restarts = self.restarts.saturating_add(chain.len());
        if self.restarts > self.limits.restarts {
            self.end(Limit::Restarts);
            return None;
        }
        let mut held = std::mem::take(&mut self.tasks.active().chain);
        held.append(&mut chain);
        Some(held)
    }

    /// Follows the CNAMEs of `chain` to `target`, within [`Limits::restarts`].
    fn restart(&mut self, chain: Vec<Ranked>, target: Name<'static>) {
        let Some(chain) = self.hops(chain) else {
            return;
        };
        let task = self.tasks.active();
        debug!(from = %task.asked.name, to = %target, "CNAME restart");
        task.chain = chain;
        task.asked.name = target;
        task.at = At::Start;
        task.minimise = Minimise::new(self.minimisation);
    }

    /// Follows a referral to `zone`, within [`Limits::referrals`], to the first [`Limits::servers`] servers of `ns`
    /// at the addresses `glue` gives them, else those cached.
    fn referral(&mut self, zone: Name<'static>, ns: &Ranked, glue: &[Ranked], now: u32) {
        self.referrals = self.referrals.saturating_add(1);
        if self.referrals > self.limits.referrals {
            return self.end(Limit::Referrals);
        }
        if let Some(task) = self.tasks.looping(&zone) {
            return self.abandon(&task);
        }
        debug!(%zone, "referral");
        let mut known = Vec::new();
        let mut missing = Vec::new();
        for name in servers(&ns.rrset, self.limits.servers) {
            let glued = glue.iter().filter(|set| *set.rrset.owner() == name);
            let mut at: Vec<IpAddr> = glued.flat_map(|set| addresses(&set.rrset)).collect();
            if at.is_empty() {
                at = cached_addresses(&self.caches.rrsets, &name, now);
            }
            if at.is_empty() {
                missing.push(name);
            }
            known.extend(at);
        }
        let task = self.tasks.active();
        task.at = At::Asking(Delegation::new(zone, Source::Parent, known, missing));
        task.descend();
    }

    /// Records what the server asked did, for the failure of its delegation.
    fn heard(&mut self, heard: Heard) {
        if let Some(delegation) = self.tasks.asking() {
            delegation.heard = delegation.heard.max(heard);
        }
    }

    /// Ends the whole resolution at a global bound.
    fn end(&mut self, limit: Limit) {
        debug!(%limit, "limit reached, resolution ends");
        crate::metrics::limit(limit);
        self.settled = Some(Settled::Done(Resolved::Failed(Failure::Limit(limit))));
    }

    /// Sends `query`, within [`Limits::queries`].
    fn send(&mut self, query: Query) {
        if self.sent >= self.limits.queries {
            return self.end(Limit::Queries);
        }
        debug!(server = %query.server, zone = %query.zone, name = %query.question.name, rtype = %query.question.qtype, "query");
        self.sent += 1;
        self.settled = Some(Settled::Waiting(query));
    }

    /// Ends `task`, a sub-resolution that loops: neither its A nor its AAAA is looked up again (D191).
    fn abandon(&mut self, task: &Task) {
        debug!(name = %task.question.name, "address lookup loops");
        self.no_address(&task.question.name);
    }

    /// Notes that `name` has no address to look up.
    fn no_address(&mut self, name: &Name<'static>) {
        for rtype in [RecordType::A, RecordType::AAAA] {
            self.found
                .insert(Question::new(name.clone(), rtype), Vec::new());
        }
    }

    /// Ends the active task with `outcome`: the resolution's when it is the client's question, else addresses
    /// for the task waiting on it.
    fn finish(&mut self, outcome: Resolved) {
        let Some(task) = self.tasks.lookups.pop() else {
            let outcome = match (outcome, self.limit) {
                (Resolved::Failed(_), Some(limit)) => Resolved::Failed(Failure::Limit(limit)),
                (outcome, _) => outcome,
            };
            debug!(?outcome, "resolution done");
            self.settled = Some(Settled::Done(outcome));
            return;
        };
        let found: Vec<IpAddr> = match &outcome {
            Resolved::Answer { data, .. } => addresses(&data.rrset).collect(),
            // A name that does not exist has no AAAA either.
            Resolved::NxDomain { .. } => return self.no_address(&task.question.name),
            _ => Vec::new(),
        };
        if let Some(delegation) = self.tasks.asking() {
            delegation.add(found.iter().copied());
        }
        self.found.insert(task.question, found);
    }
}

/// The next query of `delegation`, asking `question`, or its next address lookup, or its failure.
#[expect(
    clippy::too_many_arguments,
    reason = "the resolution's fields beside the delegation borrowed"
)]
fn ask(
    delegation: &mut Delegation,
    question: &Question<'static>,
    infra: &InfraCache,
    limits: &Limits,
    found: &HashMap<Question<'static>, Vec<IpAddr>>,
    depth: usize,
    remaining: Duration,
    now: u32,
    rng: &mut impl CryptoRng,
) -> Ask {
    loop {
        // Past the bound, an address is neither asked nor looked up, which would spend queries on one never asked.
        let left = !delegation.untried.is_empty()
            || !delegation.timed_out.is_empty()
            || delegation.aaaa.is_some()
            || !delegation.missing.is_empty();
        if left && delegation.asked >= limits.servers {
            return Ask::Fail(Failure::Limit(Limit::Servers));
        }
        let zone = &delegation.zone;
        if let Some(choice) = pick(&mut delegation.untried, zone, infra, remaining, now, rng) {
            return send(delegation, question, &choice, remaining);
        }
        // The servers timed out are asked again, each timeout backed off, until the infra cache skips them (D194):
        // a datagram lost costs a try, not the server (RFC 1035 §7.2, Unbound's `outbound-msg-retry`). They come
        // after a name's AAAA, whose A was looked up, and before a name not looked up yet, which costs queries (D196).
        let lookup = if let Some(name) = delegation.aaaa.take() {
            Some(Question::new(name, RecordType::AAAA))
        } else if let Some(choice) =
            pick(&mut delegation.timed_out, zone, infra, remaining, now, rng)
        {
            return send(delegation, question, &choice, remaining);
        } else if delegation.missing.is_empty() {
            None
        } else {
            let at = infra_cache::draw(rng, delegation.missing.len());
            let name = delegation.missing.swap_remove(at);
            delegation.aaaa = Some(name.clone());
            Some(Question::new(name, RecordType::A))
        };
        let mut limit = None;
        if let Some(lookup) = lookup {
            if let Some(addresses) = found.get(&lookup) {
                delegation.add(addresses.iter().copied());
                continue;
            }
            if depth >= limits.depth {
                limit = Some(Limit::Depth);
            } else if delegation.looked_up >= limits.targets {
                limit = Some(Limit::Targets);
            } else {
                delegation.looked_up += 1;
                return Ask::Lookup(lookup);
            }
        }
        // No lookup left within the limits: the servers timed out are all that is left.
        let zone = &delegation.zone;
        if let Some(choice) = pick(&mut delegation.timed_out, zone, infra, remaining, now, rng) {
            return send(delegation, question, &choice, remaining);
        }
        return Ask::Fail(limit.map_or_else(
            || {
                debug!(zone = %delegation.zone, "every server tried");
                delegation.heard.failure()
            },
            Failure::Limit,
        ));
    }
}

/// The server of `servers` to ask, drawn for `zone` (D194), taken out of them.
fn pick(
    servers: &mut Vec<SocketAddr>,
    zone: &Name<'_>,
    infra: &InfraCache,
    remaining: Duration,
    now: u32,
    rng: &mut impl CryptoRng,
) -> Option<Choice> {
    let choice = infra.select(servers, zone, remaining, now, rng)?;
    servers.retain(|&server| server != choice.server);
    Some(choice)
}

/// The query of `delegation` asking `question` of the server `choice` names.
fn send(
    delegation: &mut Delegation,
    question: &Question<'static>,
    choice: &Choice,
    remaining: Duration,
) -> Ask {
    delegation.asked += 1;
    Ask::Send(Query {
        question: question.clone(),
        server: choice.server,
        zone: delegation.zone.clone(),
        marks: choice.marks,
        timeout: choice.timeout,
        left: remaining,
    })
}

/// The port of a name server (RFC 1035 §4.2).
const PORT: u16 = 53;

/// The caches' clock: seconds, saturating.
fn secs(now: Duration) -> u32 {
    u32::try_from(now.as_secs()).unwrap_or(u32::MAX)
}

/// Whether `held` may answer a question (RFC 2181 §5.4.1, D193).
fn answers(held: &Ranked) -> bool {
    held.rank >= Rank::AnswerNonAuthoritative || held.checked == dedens_cache::Checked::Secure
}

/// The addresses of an A or AAAA `RRset`.
fn addresses(set: &Rrset) -> impl Iterator<Item = IpAddr> + '_ {
    set.rdatas().iter().filter_map(|rdata| match rdata.data() {
        RData::A(v4) => Some(IpAddr::V4(v4)),
        RData::Aaaa(v6) => Some(IpAddr::V6(v6)),
        _ => None,
    })
}

/// The first `cap` names of an NS `RRset`.
fn servers(ns: &Rrset, cap: usize) -> impl Iterator<Item = Name<'static>> + '_ {
    ns.rdatas()
        .iter()
        .filter_map(|rdata| match rdata.data() {
            RData::Ns(name) => Some(name.into_owned()),
            _ => None,
        })
        .take(cap)
}

/// The addresses the cache holds for `name`, at any rank: glue serves to reach a server (RFC 2181 §5.4.1).
fn cached_addresses(rrsets: &RrsetCache, name: &Name<'_>, now: u32) -> Vec<IpAddr> {
    [RecordType::A, RecordType::AAAA]
        .into_iter()
        .filter_map(|rtype| rrsets.get(name, rtype, Class::IN, now))
        .flat_map(|held| addresses(&held.rrset).collect::<Vec<_>>())
        .collect()
}

/// The closest delegation above `name` the caches know, strictly above it if `parent` (the root's hints for the root): an NS
/// `RRset` with an address for one of its first `cap` servers, else a TLD's hints, else the root's (RFC 1034 §5.3.3
/// step 2).
fn closest(caches: &Caches, name: &Name<'_>, parent: bool, cap: usize, now: u32) -> Delegation {
    let mut buf = [0; MAX_NAME_LEN];
    let wire = name.to_wire(&mut buf);
    // Each suffix of the name, longest first and the root last, borrowed from its wire form: a label is its
    // length, then its bytes.
    let mut at = match wire.first() {
        Some(&length) if parent => 1 + usize::from(length),
        _ => 0,
    };
    while let Some(&length) = wire.get(at) {
        let suffix = wire.get(at..).map(Name::from_uncompressed);
        at += 1 + usize::from(length);
        let Some(Ok(zone)) = suffix else {
            continue;
        };
        if let Some(ns) = caches.rrsets.get(&zone, RecordType::NS, Class::IN, now) {
            let mut addresses = Vec::new();
            let mut missing = Vec::new();
            for server in servers(&ns.rrset, cap) {
                let known = cached_addresses(&caches.rrsets, &server, now);
                if known.is_empty() {
                    missing.push(server);
                }
                addresses.extend(known);
            }
            if !addresses.is_empty() {
                debug!(%zone, "delegation from the cache");
                return Delegation::new(zone.into_owned(), Source::Cache, addresses, missing);
            }
        }
        if zone.label_count() == 1
            && let Some(tld) = caches.tlds.as_ref().and_then(|tlds| tlds.get(&zone))
        {
            debug!(%zone, "delegation from the TLD hints");
            return hinted(zone.into_owned(), tld.servers());
        }
    }
    debug!("delegation from the root hints");
    hinted(Name::root(), caches.roots.servers())
}

/// The `RRsets` of `records`, as `kept` holds them, grouped by the scrubber with its ranks (D192), in the order their
/// first records come. A record of no `RRset` of `kept` (an RRSIG, held with the `RRset` it covers) adds none.
fn sets(records: &[Record<'_>], kept: &[Ranked]) -> Vec<Ranked> {
    let mut sets: Vec<Ranked> = Vec::new();
    for record in records {
        let of = |held: &&Ranked| {
            *held.rrset.owner() == record.name && held.rrset.rtype() == record.rtype()
        };
        if !sets.iter().any(|set| of(&set))
            && let Some(held) = kept.iter().find(of)
        {
            sets.push(held.clone());
        }
    }
    sets
}

/// The name a CNAME `RRset` of one record leads to.
fn target(cname: &Rrset) -> Option<Name<'static>> {
    match cname.rdatas() {
        [one] => match one.data() {
            RData::Cname(target) => Some(target.into_owned()),
            _ => None,
        },
        _ => None,
    }
}

/// The delegation to `zone` that hints give.
fn hinted(zone: Name<'static>, servers: &[Server]) -> Delegation {
    let addresses = servers.iter().flat_map(Server::addresses);
    Delegation::new(zone, Source::Parent, addresses, Vec::new())
}
