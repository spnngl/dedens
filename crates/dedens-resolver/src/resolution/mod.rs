//! A recursive resolution, sans-IO: from the closest delegation known, down the referrals to the answer, one query
//! in flight (RFC 1034 §5.3.3, RFC 1035 §7, D191).
//!
//! The caller drives it: [`Resolution::step`] says what to ask of which server, or that it is done;
//! [`Resolution::receive`] hands it the reply. The transport owns the exchange: the ID, EDNS and DO, `0x20`, TCP
//! after truncation, and matching the response to the query (RFC 5452 §9.1, D190). Every response is read through
//! [`scrub()`](crate::scrub()), whose outcome alone decides what the resolution does next and what the caches learn
//! (D192). Every bound of [`Limits`] ends it with a [`Failure`], so no answer from the Internet keeps it going.
//!
//! [`Resolution::validated`] has the answer validated (RFC 4035 §5, D197): the validator's questions are resolved
//! the same way, by the same resolution and within its bounds, and its verdict is recorded on the cached `RRsets`.

use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::slice;
use std::sync::Arc;
use std::time::Duration;

use dedens_cache::Checked;
use dedens_dnssec::{Cost, Validation, Validator, Verdict};
use dedens_proto::edns::InfoCode;
use dedens_proto::rdata::RData;
use dedens_proto::{
    Class, Flags, MAX_NAME_LEN, Message, Name, Question, Rcode, Record, RecordType, Ttl,
};
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
/// out costs a bounded number of queries (RFC 1035 §7.1, RFC 9520 §3); and the addresses it may send them to.
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
    /// Queries sent for the validator's questions, beside [`Limits::queries`]: 32, as Unbound gives each of its
    /// validator's fetches a `max-sent-count` of its own within its global quota of 200 (`MAX_GLOBAL_QUOTA`,
    /// `iterator/iterator.h`). A chain of trust costs two queries per zone cut at most, a DS and a DNSKEY, fewer
    /// once the cache holds them (D197).
    pub validation: usize,
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
            validation: 32,
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
    /// [`Limits::validation`].
    #[error("validation queries")]
    Validation,
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
    /// The validator found the answer bogus (RFC 4035 §5.5), with this extended error: its `RRsets` are cached
    /// so, and served to no client but one that sets CD (D197).
    #[error("bogus (extended error {0})")]
    Bogus(InfoCode),
    /// The validator could not judge the answer, with this extended error: one of its questions got no answer,
    /// or a bound of its own stopped it (RFC 4033 §5). Nothing is cached of the verdict.
    #[error("validation indeterminate (extended error {0})")]
    Indeterminate(InfoCode),
}

impl Failure {
    /// The extended error of the SERVFAIL: No Reachable Authority for a bound or no response, Network Error for
    /// failed exchanges, Other for responses none of which served, the validator's for a verdict.
    #[must_use]
    pub const fn info_code(self) -> InfoCode {
        match self {
            Self::Limit(_) | Self::Unreachable => InfoCode::NO_REACHABLE_AUTHORITY,
            Self::Network => InfoCode::NETWORK_ERROR,
            Self::Unusable => InfoCode::OTHER,
            Self::Bogus(code) | Self::Indeterminate(code) => code,
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
        /// The NSEC and NSEC3 `RRsets` proving a wildcard expansion, of the chain or the data (RFC 4035 §5.3.4).
        denials: Vec<Ranked>,
    },
    /// The name, or the chain's end, has no data of the type (RFC 2308 §2.2).
    NoData {
        /// The CNAMEs from the name asked, in order.
        chain: Vec<Ranked>,
        /// The zone's SOA, without which a denial is not taken (RFC 2308 §5).
        soa: Ranked,
        /// The NSEC and NSEC3 `RRsets` proving it (RFC 4035 §3.1.3), and those of a wildcard expansion.
        denials: Vec<Ranked>,
    },
    /// The name, or the chain's end, does not exist (RFC 2308 §2.1).
    NxDomain {
        /// The CNAMEs from the name asked, in order.
        chain: Vec<Ranked>,
        /// The zone's SOA.
        soa: Ranked,
        /// As in [`Resolved::NoData`].
        denials: Vec<Ranked>,
    },
    /// A DNAME makes the chain's end longer than 255 bytes (RFC 6672 §2.2).
    YxDomain {
        /// The CNAMEs from the name asked, the DNAME last.
        chain: Vec<Ranked>,
    },
    /// No answer.
    Failed(Failure),
}

impl Resolved {
    /// The response to `question` this is: its rcode, and its `RRsets` in a message, each with its TTL (bounded by
    /// the cache's lifetime already, D124: bounded again, a time left under the floor would be raised), the CNAMEs
    /// and the data in the answer section, the SOA and the denials in the authority section. RRSIGs and denials go
    /// only when `dnssec`, to a client that set DO (RFC 4035 §3.1.1, §3.1.3) and to the validator; AD is clear.
    #[must_use]
    pub fn message(&self, question: &Question<'static>, dnssec: bool) -> Message<'static> {
        let records = |section: &mut Vec<Record<'static>>, ranked: &Ranked| {
            let rrset = &ranked.rrset;
            let signatures = if dnssec { rrset.rrsigs() } else { &[] };
            section.extend(rrset.rdatas().iter().chain(signatures).map(|rdata| Record {
                name: rrset.owner().clone(),
                class: rrset.class(),
                ttl: ranked.ttl,
                rdata: rdata.clone(),
            }));
        };
        // A response to the question, as the cache stage stores one (RFC 1035 §4.1.1).
        let mut message = Message::default();
        message.header.flags = Flags::QR;
        message.questions = vec![question.clone()];
        message.header.rcode = match self {
            Self::Answer { .. } | Self::NoData { .. } => Rcode::NOERROR,
            Self::NxDomain { .. } => Rcode::NXDOMAIN,
            Self::YxDomain { .. } => Rcode::YXDOMAIN,
            Self::Failed(_) => Rcode::SERVFAIL,
        };
        let (chain, one, denials) = self.parts();
        for ranked in chain {
            records(&mut message.answer, ranked);
        }
        let section = match self {
            Self::Answer { .. } => &mut message.answer,
            _ => &mut message.authority,
        };
        if let Some(ranked) = one {
            records(section, ranked);
        }
        for ranked in denials.iter().filter(|_| dnssec) {
            records(&mut message.authority, ranked);
        }
        message
    }

    /// The validator's verdict on the `RRsets` given, all of them: bogus if one is, secure if all are, insecure
    /// if all are judged, unchecked if one is not or there is none (a failure).
    #[must_use]
    pub fn checked(&self) -> Checked {
        let (chain, one, denials) = self.parts();
        let mut sets = chain.iter().chain(one).chain(denials).peekable();
        if sets.peek().is_none() {
            return Checked::Unchecked;
        }
        sets.fold(Checked::Secure, |verdict, ranked| {
            match (verdict, ranked.checked) {
                (bogus @ Checked::Bogus(_), _) | (_, bogus @ Checked::Bogus(_)) => bogus,
                (Checked::Unchecked, _) | (_, Checked::Unchecked) => Checked::Unchecked,
                (Checked::Insecure, _) | (_, Checked::Insecure) => Checked::Insecure,
                (Checked::Secure, Checked::Secure) => Checked::Secure,
            }
        })
    }

    /// The `RRsets` given: the chain, the data or the SOA, the denials.
    fn parts(&self) -> (&[Ranked], Option<&Ranked>, &[Ranked]) {
        match self {
            Self::Answer {
                chain,
                data: one,
                denials,
            }
            | Self::NoData {
                chain,
                soa: one,
                denials,
            }
            | Self::NxDomain {
                chain,
                soa: one,
                denials,
            } => (chain, Some(one), denials),
            Self::YxDomain { chain } => (chain, None, &[]),
            Self::Failed(_) => (&[], None, &[]),
        }
    }

    /// Every `RRset` given.
    fn rrsets(&self) -> impl Iterator<Item = &Ranked> {
        let (chain, one, denials) = self.parts();
        chain.iter().chain(one).chain(denials)
    }

    /// Every `RRset` given, mutable.
    fn rrsets_mut(&mut self) -> impl Iterator<Item = &mut Ranked> {
        let (chain, rest, denials): (&mut [Ranked], Option<&mut Ranked>, &mut [Ranked]) = match self
        {
            Self::Answer {
                chain,
                data: one,
                denials,
            }
            | Self::NoData {
                chain,
                soa: one,
                denials,
            }
            | Self::NxDomain {
                chain,
                soa: one,
                denials,
            } => (chain, Some(one), denials),
            Self::YxDomain { chain } => (chain, None, &mut []),
            Self::Failed(_) => (&mut [], None, &mut []),
        };
        chain.iter_mut().chain(rest).chain(denials)
    }
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
        /// after truncation and the EDNS fallback. `None` when the query moved from UDP to TCP (D190's
        /// `Response::moved`): that time is the connection's and the response's size, not the server's UDP time
        /// which [`Query::timeout`] estimates, so it credits none (D191).
        rtt: Option<Duration>,
    },
    /// A response matched to the query that does not decode (RFC 1035 §4.1): the next server is asked and nothing
    /// is remembered of this one, as Unbound's `process_response` ignores a response it cannot parse.
    Undecodable,
    /// No response within [`Query::timeout`]: D190's `ServerError::TimedOut`. A delegation whose servers all time out
    /// fails [`Failure::Unreachable`], EDE 22 (No Reachable Authority).
    Timeout,
    /// No response over TCP, the query moved there from UDP (D190's `ServerError::TcpTimedOut`): a
    /// [`Reply::Timeout`] for the delegation, but the server's time over UDP, which [`Query::timeout`] estimates,
    /// is not backed off, as Unbound's `serviced_tcp_callback`.
    TcpTimeout,
    /// No response before the deadline, but an ICMP error seen meanwhile (D190's `ServerError::Unreachable` after
    /// queries sent): a [`Reply::ServerError`] that, like a [`Reply::Timeout`], may have been cut short by the
    /// resolution's end, which judges no server (D195).
    Unreachable,
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
    /// Whether a server at a special-purpose address is asked ([`Resolution::asking_local_addresses`]).
    local: bool,
    minimisation: Minimisation,
    /// When it started, for [`Limits::time`].
    started: Duration,
    /// When it started, on the caches' clock: the time an NS `RRset` is stored at (D193).
    started_secs: u32,
    sent: usize,
    /// Of the queries sent, those for the validator's questions ([`Limits::validation`]).
    proving: usize,
    restarts: usize,
    referrals: usize,
    /// The first per-branch bound reached, reported if the question fails.
    limit: Option<Limit>,
    tasks: Tasks,
    /// The validator, and the time in Unix seconds it judges signatures at; `None` leaves the answer unchecked.
    validator: Option<(Validator, u64)>,
    /// The validation of the answer, once it came: [`Tasks::client`] is then the validator's question.
    checking: Option<Checking>,
    /// The addresses each sub-resolution found, by the question it started with, so that one asked twice is
    /// resolved once.
    found: HashMap<Question<'static>, Vec<IpAddr>>,
    /// What the validation cost, once over.
    spent: Option<Cost>,
    /// The servers whose responses answered the client's question, its CNAMEs included, and the validator's
    /// questions, since it was last asked.
    answered_by: Vec<Answerer>,
    /// The servers that gave a bogus answer, with the zone they gave it as a server of: no question is asked of
    /// them as servers of that zone (D197).
    shunned: Vec<(IpAddr, Name<'static>)>,
    /// The client's question asked again after a bogus verdict, at most [`RETRIES`].
    retries: usize,
    /// The extended error of the first bogus verdict, which stands unless a retry does better.
    bogus: Option<InfoCode>,
    /// The query awaiting its reply, or the outcome; `None` while working out the next query.
    settled: Option<Settled>,
}

/// A server that answered the client's question or one of the validator's, which a bogus verdict may blame.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Answerer {
    server: IpAddr,
    /// The zone it was asked as a server of.
    zone: Name<'static>,
    /// The `RRsets` its response gave.
    gave: Vec<Set>,
    /// Whether it answered a validator's question rather than the client's, its CNAMEs included.
    proving: bool,
}

/// The times the client's question is asked again after a bogus verdict, the servers that answered it shunned:
/// Unbound's `VAL_MAX_RESTART_COUNT` (`validator/validator.h`), whose `val_blacklist` does as much (D197).
const RETRIES: usize = 5;

/// Where a resolution waits.
#[derive(Debug)]
enum Settled {
    /// For the reply to the query.
    Waiting(Query),
    Done(Resolved),
}

/// The answer to the client's question, being validated.
#[derive(Debug)]
struct Checking {
    /// The client's question, asked again if the answer is bogus.
    question: Question<'static>,
    outcome: Resolved,
    validation: Box<Validation>,
    /// The `RRsets` of the answers to the validator's questions: the DS and DNSKEY `RRsets` of the chain and their
    /// denials, whose own verdicts the cache records as it does the answer's (D197).
    fetched: Vec<Ranked>,
}

/// The client's question (or the validator's), and the sub-resolutions it waits on, the last one active.
#[derive(Debug)]
struct Tasks {
    client: Task,
    lookups: Vec<Task>,
}

impl Tasks {
    fn active(&mut self) -> &mut Task {
        self.lookups.last_mut().unwrap_or(&mut self.client)
    }

    fn current(&self) -> &Task {
        self.lookups.last().unwrap_or(&self.client)
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
        let (active, ancestors) = self.lookups.split_last()?;
        if active.purpose != Purpose::Address {
            return None;
        }
        let stuck = [&self.client]
            .into_iter()
            .chain(ancestors)
            .any(|task| matches!(&task.at, At::Asking(delegation) if delegation.zone == *zone));
        if stuck { self.lookups.pop() } else { None }
    }
}

/// A question being resolved: the client's, the validator's, a server's address, or a zone cut.
#[derive(Debug)]
struct Task {
    /// The question it started with.
    question: Question<'static>,
    /// The question asked now: at the end of the CNAMEs followed.
    asked: Question<'static>,
    purpose: Purpose,
    /// The CNAMEs followed so far.
    chain: Vec<Ranked>,
    /// The denials received so far: of a wildcard the chain was expanded from.
    denials: Vec<Ranked>,
    /// The search of a DS question's zone cut, once a DS came from below it.
    cut: Option<Cut>,
    at: At,
    minimise: Minimise,
}

impl Task {
    fn new(question: Question<'static>, purpose: Purpose, minimisation: Minimisation) -> Self {
        Self {
            asked: question.clone(),
            question,
            purpose,
            chain: Vec::new(),
            denials: Vec::new(),
            cut: None,
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

/// What a task's outcome is for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Purpose {
    /// The resolution's: the client's question, or the validator's.
    Answer,
    /// A server's address, for the task below it.
    Address,
    /// The NS `RRset` of a name, for the DS question below it: whether the name is a zone cut, and its servers.
    Cut,
}

/// A DS question answered NODATA from the child's side of its cut, by a server of a zone above the parent that
/// serves the child too: a server of the parent is to be found (RFC 4035 §3.1.4.1), as Unbound's `iter_ds_toolow`
/// and `processDSNSFind` (`iterator/iterator.c`) do. Each name from the DS's parent up is looked up for its NS
/// `RRset`, until one is a zone cut, whose servers are asked the DS, or the zone asked is reached, which the
/// response is taken from (D197).
#[derive(Debug)]
enum Cut {
    /// The NS `RRset` of `point` is looked up.
    Seeking {
        point: Name<'static>,
        /// The zone whose server gave `held`.
        zone: Name<'static>,
        /// The response from below the cut, taken if no cut is found.
        held: Resolved,
    },
    /// The search is over: a later NODATA is the answer.
    Over,
}

#[derive(Debug)]
enum At {
    /// Looking for an answer or the closest delegation in the cache.
    Start,
    /// Asking the servers of a delegation.
    Asking(Box<Delegation>),
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
    /// The addresses known, asked or not, the shunned ones too so that none comes back.
    known: HashSet<IpAddr>,
    /// The addresses known that are shunned (D197): they stay out of the [`MAX_ADDRESSES`].
    shunned: HashSet<IpAddr>,
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
    /// Whether its servers at local addresses are asked ([`Resolution::asking_local_addresses`]).
    local: bool,
}

impl Delegation {
    fn new(
        zone: Name<'static>,
        source: Source,
        addresses: impl IntoIterator<Item = IpAddr>,
        missing: Vec<Name<'static>>,
        local: bool,
    ) -> Self {
        let mut delegation = Self {
            zone,
            source,
            known: HashSet::new(),
            shunned: HashSet::new(),
            untried: Vec::new(),
            timed_out: Vec::new(),
            asked: 0,
            missing,
            aaaa: None,
            looked_up: 0,
            heard: Heard::Nothing,
            local,
        };
        delegation.add(addresses);
        delegation
    }

    /// Adds the addresses not known yet that may be asked ([`askable`]), up to [`MAX_ADDRESSES`] known but the
    /// shunned ones: every address of glue, a lookup, the cache or the hints comes through here.
    fn add(&mut self, addresses: impl IntoIterator<Item = IpAddr>) {
        for address in addresses {
            if self.known.len() - self.shunned.len() >= MAX_ADDRESSES {
                debug!(zone = %self.zone, "delegation at its address bound, the rest not taken");
                break;
            }
            if !askable(address, self.local) {
                debug!(zone = %self.zone, %address, "local address not asked");
            } else if self.known.insert(address) {
                self.untried.push(SocketAddr::new(address, PORT));
            }
        }
    }

    /// Takes the servers `shunned` as servers of this zone out of those to ask, now and once looked up: a server
    /// shunned in a zone still serves the others (D197).
    fn shun(&mut self, shunned: &[(IpAddr, Name<'static>)]) {
        let servers: Vec<IpAddr> = (shunned.iter())
            .filter(|(_, zone)| *zone == self.zone)
            .map(|&(server, _)| server)
            .collect();
        self.known.extend(&servers);
        self.shunned.extend(&servers);
        self.untried
            .retain(|server| !servers.contains(&server.ip()));
        self.timed_out
            .retain(|server| !servers.contains(&server.ip()));
    }
}

/// The most addresses a delegation takes, whatever a lookup's answer or the cache holds, so that drawing among them
/// stays cheap: 100, Unbound's `delegpt_max_addr` (`iter_delegpt.c`), as many as the glue kept from a referral
/// (`scrub::MAX_GLUE`).
const MAX_ADDRESSES: usize = 100;

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
            local: false,
            minimisation,
            started: now,
            started_secs: secs(now),
            sent: 0,
            proving: 0,
            restarts: 0,
            referrals: 0,
            limit: None,
            tasks: Tasks {
                client: Task::new(question, Purpose::Answer, minimisation),
                lookups: Vec::new(),
            },
            validator: None,
            checking: None,
            spent: None,
            answered_by: Vec::new(),
            shunned: Vec::new(),
            retries: 0,
            bogus: None,
            found: HashMap::new(),
            settled: None,
        })
    }

    /// Has it ask servers at special-purpose addresses too, if `ask`: loopback, private, link-local, multicast
    /// and the rest [`askable`] lists. Off by default: a zone would aim the resolver at its own host, its network,
    /// or many hosts at once, as Unbound's `do-not-query-localhost` (on by default) keeps it off loopback and
    /// "this network"; on for authorities on a test's own host or network (D191). It is the resolution's, not
    /// [`Limits`]' or the caches': a count bounds what a client costs, and a reload that changes the switch keeps
    /// the caches.
    #[must_use]
    pub const fn asking_local_addresses(mut self, ask: bool) -> Self {
        self.local = ask;
        self
    }

    /// Has the answer validated by `validator` at `unix`, the time in seconds since the Unix epoch that signatures
    /// are judged at (RFC 4035 §5, D197). Its questions, each DS of the parent's servers (RFC 4035 §3.1.4.1) and
    /// each DNSKEY of the zone's, are resolved as the client's, within [`Limits`], the queries of
    /// [`Limits::validation`]; their responses are what the resolution gives, built by [`Resolved::message`] from
    /// the `RRsets` it trusts, so that nothing a server adds to a response (glue, additional data) reaches it.
    ///
    /// Each `RRset` of the answer is cached with its own verdict (RFC 4035 §4.7): secure ones live no longer than
    /// their signatures; a bogus answer ends the resolution [`Failure::Bogus`]. An answer whose `RRsets` the cache
    /// judged already is not validated again. A YXDOMAIN is validated as an answer: bogus without the DNAME that
    /// makes it (RFC 6672 §2.2).
    #[must_use]
    pub fn validated(mut self, validator: Validator, unix: u64) -> Self {
        self.validator = Some((validator, unix));
        self
    }

    /// Queries sent so far, the validator's included, which the client's budget pays for (D117).
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
                Sent::Timeout | Sent::Unreachable => !self.remaining(now).is_zero(),
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
            Sent::Timeout | Sent::TcpTimeout => {
                if let Some(delegation) = self.tasks.asking() {
                    debug_assert_eq!(
                        query.zone, delegation.zone,
                        "the query is of the zone asked"
                    );
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
            Reply::TcpTimeout => {
                self.timed_out(&query.question);
                return self.unanswered(&query, Sent::TcpTimeout, now, judge);
            }
            Reply::Unreachable => return self.unanswered(&query, Sent::Unreachable, now, judge),
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
                match rtt {
                    Some(rtt) => infra.reply(server, rtt, seen, now_secs),
                    None => infra.answered(server, seen, now_secs),
                }
            }
        }
        let answer = matches!(
            scrubbed.outcome,
            Outcome::Answer { .. }
                | Outcome::Cname { .. }
                | Outcome::NoData { .. }
                | Outcome::NxDomain { .. }
                | Outcome::YxDomain { .. }
        );
        let referral = matches!(scrubbed.outcome, Outcome::Referral { .. });
        let ranked = self.cache(scrubbed.ranked(), referral, now_secs);
        if answer && query.question == self.tasks.client.asked {
            self.answered_by.push(Answerer {
                server: server.ip(),
                zone: query.zone.clone(),
                gave: (ranked.iter())
                    .map(|ranked| (ranked.rrset.owner().clone(), ranked.rrset.rtype()))
                    .collect(),
                proving: self.checking.is_some(),
            });
        }
        if self.minimised(&query.question) && self.went_on(&scrubbed.outcome, server) {
            return;
        }
        self.follow(query, &scrubbed.outcome, &ranked, now_secs);
    }

    /// Moves on from `outcome`, the response to `query` scrubbed, whose `RRsets` `ranked` holds as cached.
    fn follow(&mut self, query: Query, outcome: &Outcome<'_>, ranked: &[Ranked], now_secs: u32) {
        let server = query.server;
        let sets = |records: &[Record<'_>]| sets(records, ranked);
        match outcome {
            Outcome::Answer {
                chain,
                records,
                denials,
                ..
            } => {
                if let Some(data) = sets(records).pop()
                    && let Some(chain) = self.hops(sets(chain))
                {
                    let denials = self.denials(sets(denials));
                    self.finish(
                        Resolved::Answer {
                            chain,
                            data,
                            denials,
                        },
                        now_secs,
                    );
                }
            }
            Outcome::Cname {
                chain,
                target,
                denials,
            } => {
                let denials = self.denials(sets(denials));
                self.tasks.active().denials = denials;
                self.restart(sets(chain), target.clone().into_owned());
            }
            // The parent's servers asked a DS refer it to the zone below: the child has none to give, and the
            // proof the referral holds is the validator's (recursive step 10).
            Outcome::Referral { child, .. }
                if query.question.qtype == RecordType::DS && *child == query.question.name =>
            {
                debug!(%server, zone = %query.zone, %child, "DS referred to the child, not followed");
            }
            // The parent's referral to the name a cut is sought at: the cut, whose servers the glue gives.
            Outcome::Referral { child, ns, .. }
                if self.tasks.current().purpose == Purpose::Cut
                    && *child == query.question.name =>
            {
                if let Some(data) = sets(ns).pop() {
                    let answer = Resolved::Answer {
                        chain: Vec::new(),
                        data,
                        denials: Vec::new(),
                    };
                    self.finish(answer, now_secs);
                }
            }
            Outcome::Referral {
                child, ns, glue, ..
            } => {
                if let Some(ns) = sets(ns).pop() {
                    self.referral(child.clone().into_owned(), &ns, &sets(glue), now_secs);
                }
            }
            Outcome::NoData { soa, denials } => {
                if let Some(soa) = sets(slice::from_ref(soa)).pop() {
                    self.no_data(query, soa, sets(denials), now_secs);
                }
            }
            Outcome::NxDomain {
                chain,
                soa,
                denials,
            } => {
                if let Some(soa) = sets(slice::from_ref(soa)).pop()
                    && let Some(chain) = self.hops(sets(chain))
                {
                    let denials = self.denials(sets(denials));
                    self.finish(
                        Resolved::NxDomain {
                            chain,
                            soa,
                            denials,
                        },
                        now_secs,
                    );
                }
            }
            Outcome::YxDomain { chain } => {
                if let Some(chain) = self.hops(sets(chain)) {
                    self.finish(Resolved::YxDomain { chain }, now_secs);
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
        delegation.shun(&self.shunned);
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
                let task = Task::new(question, Purpose::Address, self.minimisation);
                self.tasks.lookups.push(task);
            }
            Ask::Fail(failure) => {
                if let Failure::Limit(limit) = failure {
                    debug!(%limit, "limit reached");
                    crate::metrics::limit(limit);
                    self.limit.get_or_insert(limit);
                }
                self.finish(Resolved::Failed(failure), now_secs);
            }
        }
    }

    /// The start of the active task: its answer or CNAME in the cache, else the closest delegation known, above
    /// the name for a DS, which the parent's servers hold (RFC 4035 §3.1.4.1; Unbound's `processInitRequest`).
    ///
    /// With a validator, a wildcard expansion not judged insecure or bogus is asked again: the cache holds it
    /// without the proof that no closer name exists (RFC 4035 §5.3.4), which an unchecked one needs to be judged
    /// and a secure one to be served to a client that validates.
    fn begin(&mut self, now: u32) {
        let caches = Arc::clone(&self.caches);
        let rrsets = &caches.rrsets;
        let validating = self.validator.is_some();
        // Asked again after a bogus answer: what was judged bogus, the client's question or the validator's, is
        // asked of the servers left, as Unbound's `val_blacklist` takes the bogus data out of the cache. The checks
        // before wrote the verdict of every set they judged back to the cache, those it held unchecked included,
        // which had no server to shun (D197).
        let retrying = self.retries > 0 && matches!(self.tasks.current().purpose, Purpose::Answer);
        let usable = |held: &Ranked| {
            answers(held)
                && !(validating
                    && matches!(held.checked, Checked::Unchecked | Checked::Secure)
                    && held.rrset.expanded())
                && !(retrying && matches!(held.checked, Checked::Bogus(_)))
        };
        let task = self.tasks.active();
        let Question { name, qtype, .. } = &task.asked;
        let qtype = *qtype;
        if let Some(data) = rrsets
            .get(name, qtype, Class::IN, now)
            .filter(usable)
            .map(unproven)
        {
            debug!(%name, rtype = %qtype, "answered from the cache");
            let chain = std::mem::take(&mut task.chain);
            let denials = std::mem::take(&mut task.denials);
            let answer = Resolved::Answer {
                chain,
                data,
                denials,
            };
            return self.finish(answer, now);
        }
        if qtype != RecordType::CNAME
            && let Some(cname) = rrsets
                .get(name, RecordType::CNAME, Class::IN, now)
                .filter(usable)
                .map(unproven)
            && let Some(target) = target(&cname.rrset)
        {
            return self.restart(vec![cname], target);
        }
        let parent = qtype == RecordType::DS;
        let delegation = closest(&caches, name, parent, (&self.limits, self.local), now);
        if let Some(task) = self.tasks.looping(&delegation.zone) {
            return self.abandon(&task);
        }
        let task = self.tasks.active();
        task.at = At::Asking(Box::new(delegation));
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
        // A server that failed (REFUSED, lame, unusable) is asked the full name after the others: a server that
        // refused a minimised name gets nothing from being asked the next one at once, and Unbound's relaxed mode
        // goes on with its next target too. NXDOMAIN is an answer, an empty non-terminal perhaps, its server kept.
        let failed = full && !matches!(outcome, Outcome::NxDomain { .. });
        self.give_back(server, full, failed);
        true
    }

    /// After a response to the minimised question from `server`: `server` may be asked again, the next question
    /// being another, the full name's when `full`, else the next minimised one. Each zone's servers may then hear
    /// as many questions as [`MINIMISE_COUNT`] allows, each within [`Limits::queries`]. A `failed` server is asked
    /// again after the servers not asked yet, as one that timed out is, not before.
    fn give_back(&mut self, server: SocketAddr, full: bool, failed: bool) {
        let task = self.tasks.active();
        if let At::Asking(delegation) = &mut task.at {
            if failed {
                delegation.timed_out.push(server);
            } else {
                delegation.untried.push(server);
            }
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
    /// refresh an NS `RRset` that had expired by then (Unbound's `store_rrsets`, D193). A CNAME below a DNAME of
    /// the response is not cached: it was synthesized, its TTL as good as 0 (RFC 6672 §3.4), and from the cache it
    /// would answer without the DNAME that makes it, which a validator judges (Unbound's synthesis does as much).
    fn cache(&mut self, ranked: Vec<(Rank, Rrset)>, referral: bool, now: u32) -> Vec<Ranked> {
        let from_cache = self
            .tasks
            .asking()
            .is_some_and(|delegation| delegation.source == Source::Cache);
        let dnames: Vec<Name<'static>> = (ranked.iter())
            .filter(|(_, set)| set.rtype() == RecordType::DNAME)
            .map(|(_, set)| set.owner().clone())
            .collect();
        let mut kept = Vec::with_capacity(ranked.len());
        for (rank, set) in ranked {
            let synthesized = set.rtype() == RecordType::CNAME
                && (dnames.iter())
                    .any(|dname| set.owner() != dname && set.owner().is_within(dname));
            let at = if referral && from_cache && set.rtype() == RecordType::NS {
                self.started_secs
            } else {
                now
            };
            let rrset = Arc::new(set);
            // The resolution reads what this server said whatever the cache did: an `RRset` too large, or one the
            // cache trusts more and keeps, changes what later questions find, not this response.
            if !synthesized
                && let Err(error) =
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

    /// The active task's chain, taken, followed by `chain`, within [`Limits::restarts`], one per CNAME: a DNAME
    /// comes with the CNAME synthesized from it, one hop. `None` when the resolution ends there.
    fn hops(&mut self, mut chain: Vec<Ranked>) -> Option<Vec<Ranked>> {
        let cnames = (chain.iter())
            .filter(|held| held.rrset.rtype() == RecordType::CNAME)
            .count();
        self.restarts = self.restarts.saturating_add(cnames);
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
        let delegation = self.delegation(zone, ns, glue, now);
        let task = self.tasks.active();
        task.at = At::Asking(Box::new(delegation));
        task.descend();
    }

    /// The delegation to `zone` of the first [`Limits::servers`] servers of `ns`, at the addresses `glue` gives
    /// them, else those cached.
    fn delegation(
        &self,
        zone: Name<'static>,
        ns: &Ranked,
        glue: &[Ranked],
        now: u32,
    ) -> Delegation {
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
        Delegation::new(zone, Source::Parent, known, missing, self.local)
    }

    /// Records what the server asked did, for the failure of its delegation.
    fn heard(&mut self, heard: Heard) {
        if let Some(delegation) = self.tasks.asking() {
            delegation.heard = delegation.heard.max(heard);
        }
    }

    /// Ends the whole resolution at a global bound: a validation stopped there is indeterminate, DNSSEC
    /// Indeterminate (RFC 8914 §4.7), nothing of it cached.
    fn end(&mut self, limit: Limit) {
        debug!(%limit, "limit reached, resolution ends");
        crate::metrics::limit(limit);
        let failure = match self.bogus {
            Some(code) => Failure::Bogus(code),
            None if self.checking.is_some() => {
                Failure::Indeterminate(InfoCode::DNSSEC_INDETERMINATE)
            }
            None => Failure::Limit(limit),
        };
        self.settled = Some(Settled::Done(Resolved::Failed(failure)));
    }

    /// Sends `query`, within [`Limits::queries`], or [`Limits::validation`] for the validator's question and the
    /// client's asked again after a bogus answer.
    fn send(&mut self, query: Query) {
        if self.checking.is_some() || self.retries > 0 {
            if self.proving >= self.limits.validation {
                return self.end(Limit::Validation);
            }
            self.proving += 1;
        } else if self.sent >= self.limits.queries {
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

    /// Notes that `name` has no address to look up, but for those a lookup already found: its A found, its AAAA
    /// lookup that loops or is denied leaves it.
    fn no_address(&mut self, name: &Name<'static>) {
        for rtype in [RecordType::A, RecordType::AAAA] {
            self.found
                .entry(Question::new(name.clone(), rtype))
                .or_default();
        }
    }

    /// Moves on from a NODATA of `soa` and `denials` to `query`: the answer, unless a DS question's from below its
    /// cut.
    fn no_data(&mut self, query: Query, soa: Ranked, denials: Vec<Ranked>, now: u32) {
        if self.below_cut(&query, &soa) {
            let held = Resolved::NoData {
                chain: Vec::new(),
                soa,
                denials,
            };
            return self.seek_cut(held, query.zone, now);
        }
        if let Some(chain) = self.hops(Vec::new()) {
            let denials = self.denials(denials);
            self.finish(
                Resolved::NoData {
                    chain,
                    soa,
                    denials,
                },
                now,
            );
        }
    }

    /// The active task's denials, taken, followed by `denials`.
    fn denials(&mut self, mut denials: Vec<Ranked>) -> Vec<Ranked> {
        let mut held = std::mem::take(&mut self.tasks.active().denials);
        held.append(&mut denials);
        held
    }

    /// Whether a NODATA of `soa` to `query` is a DS question's from below its cut: the SOA is of the name asked or
    /// below (Unbound's `iter_ds_toolow`). Once per question. The zone asked may be the name's parent, which
    /// `seek_cut_at` finds at once, taking the NODATA (Unbound's `iter_dp_cangodown`).
    fn below_cut(&self, query: &Query, soa: &Ranked) -> bool {
        let task = self.tasks.current();
        let name = &query.question.name;
        query.question.qtype == RecordType::DS
            && task.purpose == Purpose::Answer
            && task.cut.is_none()
            && task.chain.is_empty()
            && soa.rrset.owner().is_within(name)
    }

    /// Starts the search of the active DS question's cut, from its parent up to `zone`, the zone whose server gave
    /// `held`.
    fn seek_cut(&mut self, held: Resolved, zone: Name<'static>, now: u32) {
        let name = &self.tasks.current().asked.name;
        debug!(%name, %zone, "DS from below its cut");
        match parent(name) {
            Some(point) => self.seek_cut_at(point, zone, held, now),
            None => self.finish(held, now),
        }
    }

    /// Looks up the NS `RRset` of `point` for the active DS question, or takes `held` once `point` is `zone`.
    fn seek_cut_at(&mut self, point: Name<'static>, zone: Name<'static>, held: Resolved, now: u32) {
        if point.label_count() <= zone.label_count() {
            debug!(%zone, "no cut below the zone asked");
            self.tasks.active().cut = Some(Cut::Over);
            return self.finish(held, now);
        }
        if self.tasks.lookups.len() >= self.limits.depth {
            crate::metrics::limit(Limit::Depth);
            self.limit.get_or_insert(Limit::Depth);
            self.tasks.active().cut = Some(Cut::Over);
            return self.finish(Resolved::Failed(Failure::Limit(Limit::Depth)), now);
        }
        debug!(%point, "zone cut lookup");
        let question = Question::new(point.clone(), RecordType::NS);
        self.tasks.active().cut = Some(Cut::Seeking { point, zone, held });
        self.tasks
            .lookups
            .push(Task::new(question, Purpose::Cut, self.minimisation));
    }

    /// Ends the search of a cut with `outcome`, the NS lookup's: its servers asked the DS question if `outcome`
    /// is the NS `RRset` sought, else the name above looked up.
    fn cut(&mut self, outcome: &Resolved, now: u32) {
        let Some(Cut::Seeking { point, zone, held }) = self.tasks.active().cut.take() else {
            return;
        };
        match outcome {
            // A lookup that failed tells nothing of the cut: the DS question fails with it, as Unbound's
            // `processDSNSFind` does, rather than take the name for no cut and judge the child's NODATA.
            Resolved::Failed(failure) => {
                debug!(%point, %failure, "zone cut lookup failed");
                self.tasks.active().cut = Some(Cut::Over);
                self.finish(Resolved::Failed(*failure), now);
            }
            // Through a CNAME the name is an alias, no cut: the name above is looked up.
            Resolved::Answer { chain, data, .. } if chain.is_empty() => {
                debug!(%point, "zone cut found");
                let delegation = self.delegation(point, data, &[], now);
                let task = self.tasks.active();
                task.cut = Some(Cut::Over);
                task.at = At::Asking(Box::new(delegation));
                task.descend();
            }
            _ => match parent(&point) {
                Some(up) => self.seek_cut_at(up, zone, held, now),
                None => self.finish(held, now),
            },
        }
    }

    /// Ends the active task with `outcome`: the client's question, or the validator's, else addresses or a cut
    /// for the task waiting on it.
    fn finish(&mut self, outcome: Resolved, now: u32) {
        let Some(task) = self.tasks.lookups.pop() else {
            return self.answered(outcome, now);
        };
        if task.purpose == Purpose::Cut {
            return self.cut(&outcome, now);
        }
        let found: Vec<IpAddr> = match &outcome {
            Resolved::Answer { data, .. } => addresses(&data.rrset).collect(),
            // A name that does not exist has no AAAA either.
            Resolved::NxDomain { .. } => return self.no_address(&task.question.name),
            // A bound reached says what the lookup's place cost (its depth, its delegation's servers), not that the
            // name has no address: asked again from another place it may resolve.
            Resolved::Failed(Failure::Limit(_)) => return,
            _ => Vec::new(),
        };
        if let Some(delegation) = self.tasks.asking() {
            delegation.add(found.iter().copied());
        }
        self.found.insert(task.question, found);
    }

    /// Ends [`Tasks::client`] with `outcome`: the resolution, or its validation when there is a validator; the
    /// validation goes on when it is the validator's question.
    fn answered(&mut self, outcome: Resolved, now: u32) {
        if let Some(checking) = &mut self.checking {
            let response = (!matches!(outcome, Resolved::Failed(_)))
                .then(|| outcome.message(&self.tasks.client.question, true));
            checking.validation.answer(response.as_ref());
            checking.fetched.extend(outcome.rrsets().cloned());
            return self.check(now);
        }
        let mut outcome = match (outcome, self.bogus, self.limit) {
            (Resolved::Failed(_), Some(code), _) => Resolved::Failed(Failure::Bogus(code)),
            (Resolved::Failed(_), None, Some(limit)) => Resolved::Failed(Failure::Limit(limit)),
            (outcome, _, _) => outcome,
        };
        let judged = matches!(
            outcome,
            Resolved::Answer { .. }
                | Resolved::NoData { .. }
                | Resolved::NxDomain { .. }
                | Resolved::YxDomain { .. }
        );
        if let Some((validator, unix)) = &self.validator
            && judged
        {
            match outcome.checked() {
                Checked::Unchecked => {
                    let question = self.tasks.client.question.clone();
                    let response = outcome.message(&question, true);
                    // Asked again after a bogus verdict, the validation carries on with what the ones before it
                    // left of its budget, as Unbound's `val_restart` keeps its counts (D197).
                    let validation = Box::new(match self.spent {
                        Some(spent) => validator.restart(&question, &response, *unix, spent),
                        None => validator.start(&question, &response, *unix),
                    });
                    self.checking = Some(Checking {
                        question,
                        outcome,
                        validation,
                        fetched: Vec::new(),
                    });
                    return self.check(now);
                }
                Checked::Bogus(code) => outcome = Resolved::Failed(Failure::Bogus(code)),
                Checked::Secure | Checked::Insecure => {}
            }
        }
        debug!(?outcome, "resolution done");
        self.settled = Some(Settled::Done(outcome));
    }

    /// The validation's next move: its question becomes [`Tasks::client`], or its verdict ends the resolution.
    fn check(&mut self, now: u32) {
        let Some(checking) = &mut self.checking else {
            return;
        };
        match checking.validation.step() {
            dedens_dnssec::Next::Ask(question) => {
                debug!(name = %question.name, rtype = %question.qtype, "validator question");
                self.tasks.client = Task::new(question, Purpose::Answer, self.minimisation);
            }
            dedens_dnssec::Next::Done(verdict) => {
                let Some(Checking {
                    question,
                    outcome,
                    validation,
                    fetched,
                }) = self.checking.take()
                else {
                    return;
                };
                // The cost of the validations before it included (`Validator::restart`).
                self.spent = Some(validation.cost());
                let answer = bogus(&validation, outcome.rrsets());
                let proofs = bogus(&validation, fetched.iter());
                self.record(fetched.iter(), &validation, now);
                let outcome = match self.judged(outcome, verdict, &validation, now) {
                    Resolved::Failed(Failure::Bogus(code))
                        if validation.can_restart()
                            && self.retry(question, code, &answer, &proofs) =>
                    {
                        return;
                    }
                    Resolved::Failed(Failure::Bogus(code)) => {
                        Resolved::Failed(Failure::Bogus(*self.bogus.get_or_insert(code)))
                    }
                    Resolved::Failed(_) if let Some(code) = self.bogus => {
                        Resolved::Failed(Failure::Bogus(code))
                    }
                    outcome => outcome,
                };
                debug!(?outcome, "resolution done");
                self.settled = Some(Settled::Done(outcome));
            }
        }
    }

    /// Asks `question` again after a bogus answer, `code`, the servers that answered it shunned, as Unbound's
    /// `val_blacklist`: at most [`RETRIES`] times, the queries within [`Limits::validation`], the validation within
    /// what the ones before it left (`Validator::restart`). A spoofed or garbled response from one server does not
    /// make the answer bogus while another serves it right. The servers shunned, each in the zone it was asked
    /// as a server of, are those whose responses gave an `RRset` the validator's questions fetched and it judged
    /// bogus by itself (`proofs`, Unbound's `chain_blacklist`), what is below a bogus key set being bogus through
    /// it; when there is none, those whose responses gave an `RRset` of the answer judged bogus by itself
    /// (`answer`), or all that answered the client's question when there is none either (a denial missing). A
    /// bogus `RRset` the cache gave unjudged has no server to shun: it is asked again all the same, the cache
    /// passed over (Unbound's `val_blacklist` of an origin it does not know). One the cache held bogus is its
    /// settled verdict until it expires (RFC 4035 §4.7), not asked again, as Unbound's bad key cached leaves no
    /// restart. Without a server to shun nor a set to fetch again, or out of retries, the answer is bogus with the
    /// first code. Whether it is asked again.
    fn retry(
        &mut self,
        question: Question<'static>,
        code: InfoCode,
        answer: &[Bogus],
        proofs: &[Bogus],
    ) -> bool {
        let code = *self.bogus.get_or_insert(code);
        let answered_by = std::mem::take(&mut self.answered_by);
        let bogus = if proofs.is_empty() { answer } else { proofs };
        let gave = |answerer: &&Answerer| match bogus {
            [] => !answerer.proving,
            bogus => bogus.iter().any(|(set, _)| answerer.gave.contains(set)),
        };
        let blamed: Vec<(IpAddr, Name<'static>)> = (answered_by.iter())
            .filter(gave)
            .map(|answerer| (answerer.server, answerer.zone.clone()))
            .collect();
        // A bogus set no server gave came from the cache: fetched unjudged, it is fetched again, the cache passed
        // over; held bogus, it stays so.
        let cached = (bogus.iter()).any(|(set, held)| {
            *held == Checked::Unchecked
                && !(answered_by.iter()).any(|answerer| answerer.gave.contains(set))
        });
        if self.retries >= RETRIES || (blamed.is_empty() && !cached) {
            debug!(%code, ?answer, ?proofs, "bogus, not asked again");
            return false;
        }
        self.retries += 1;
        debug!(
            %code,
            ?answer,
            ?proofs,
            servers = ?blamed,
            cached,
            retry = self.retries,
            "bogus, asked again of other servers"
        );
        // A server answers several questions of a resolution: shunned once.
        for shunned in blamed {
            if !self.shunned.contains(&shunned) {
                self.shunned.push(shunned);
            }
        }
        self.tasks.client = Task::new(question, Purpose::Answer, self.minimisation);
        self.tasks.lookups.clear();
        true
    }

    /// Records in the cache the own verdict of each of `sets` (`Validation::verdict_of`, Unbound's
    /// `rrset_update_sec_status`): a secure one lives no longer than its signatures (RFC 4035 §5.3.3), an insecure
    /// one than D93's cap, a bogus one than `Config::bogus_ttl` (RFC 4035 §4.7); a set with no verdict of its own
    /// stays as it is.
    fn record<'r>(
        &self,
        sets: impl Iterator<Item = &'r Ranked>,
        validation: &Validation,
        now: u32,
    ) {
        let rrsets = &self.caches.rrsets;
        for ranked in sets {
            let Some((checked, cap)) = own(validation, ranked).and_then(recorded) else {
                continue;
            };
            // The time left, not the TTL received: the set may have come from the cache, or stayed in it while the
            // validation ran.
            let mut rrset = Rrset::clone(&ranked.rrset);
            rrset.cap_ttl(cap.map_or(ranked.ttl, |cap| cap.min(ranked.ttl)));
            if let Err(error) = rrsets.insert(Arc::new(rrset), ranked.rank, checked, now) {
                let (owner, rtype) = (ranked.rrset.owner(), ranked.rrset.rtype());
                debug!(%owner, %rtype, %error, "verdict not cached");
            }
        }
    }

    /// `outcome` as `verdict` makes it. The cache records each `RRset`'s own verdict ([`Resolution::record`]), not
    /// the outcome's, whose parts may be of other zones. The outcome served takes the verdict.
    fn judged(
        &self,
        mut outcome: Resolved,
        verdict: Verdict,
        validation: &Validation,
        now: u32,
    ) -> Resolved {
        debug!(?verdict, "validated");
        let rrsets = &self.caches.rrsets;
        self.record(outcome.rrsets(), validation, now);
        let Some((checked, cap)) = recorded(&verdict) else {
            let code = match verdict {
                Verdict::Indeterminate { ede } => ede.code,
                // Neither a referral nor an incomplete chain comes of a response holding the whole chain.
                _ => InfoCode::DNSSEC_INDETERMINATE,
            };
            return Resolved::Failed(Failure::Indeterminate(code));
        };
        for ranked in outcome.rrsets_mut() {
            let mut rrset = Rrset::clone(&ranked.rrset);
            if let Some(cap) = cap {
                rrset.cap_ttl(cap);
            }
            let lifetime = rrsets.config().lifetime(rrset.ttl(), checked).unwrap_or(0);
            ranked.ttl = ranked.ttl.min(Ttl::from_wire(lifetime));
            ranked.checked = checked;
            ranked.rrset = Arc::new(rrset);
        }
        match checked {
            Checked::Bogus(code) => Resolved::Failed(Failure::Bogus(code)),
            _ => outcome,
        }
    }

    /// What the validation cost so far, the validations of every retry summed (`Validator::restart`): `None`
    /// before it started, or when nothing was validated.
    #[must_use]
    pub fn validation_cost(&self) -> Option<Cost> {
        self.checking
            .as_ref()
            .map(|checking| checking.validation.cost())
            .or(self.spent)
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

/// An `RRset` by its owner and type.
type Set = (Name<'static>, RecordType);

/// An `RRset` judged bogus by itself, with the verdict it came with: [`Checked::Unchecked`] when it came unjudged,
/// from a server or the cache, else the cache's.
type Bogus = (Set, Checked);

/// Of `sets`, those `validation` judged bogus by themselves.
fn bogus<'r>(validation: &Validation, sets: impl Iterator<Item = &'r Ranked>) -> Vec<Bogus> {
    sets.filter(|ranked| matches!(own(validation, ranked), Some(Verdict::Bogus { .. })))
        .map(|ranked| {
            let set = (ranked.rrset.owner().clone(), ranked.rrset.rtype());
            (set, ranked.checked)
        })
        .collect()
}

/// The own verdict `validation` gave the `RRset` of `ranked`, if it judged it by itself.
fn own<'v>(validation: &'v Validation, ranked: &Ranked) -> Option<&'v Verdict> {
    let rrset = &ranked.rrset;
    validation.verdict_of(rrset.owner(), rrset.rtype(), rrset.rdatas())
}

/// What the cache records of `verdict`, and the cap on the TTL of a secure `RRset` (RFC 4035 §5.3.3): `None` for
/// a verdict that judges nothing (indeterminate, a referral's, an incomplete chain's).
fn recorded(verdict: &Verdict) -> Option<(Checked, Option<Ttl>)> {
    match verdict {
        Verdict::Secure { ttl } => Some((Checked::Secure, Some(*ttl))),
        Verdict::Insecure { .. } => Some((Checked::Insecure, None)),
        Verdict::Bogus { ede } => Some((Checked::Bogus(ede.code), None)),
        _ => None,
    }
}

/// Whether `held` may answer a question (RFC 2181 §5.4.1, D193): an `RRset` of an answer section, or a DS proved
/// secure, which Unbound's rrset path serves from an authority section too. The authority and additional sections
/// serve the resolution, not the client, whatever their verdict: the parent's NSEC or NSEC3 at a cut, even proved
/// secure, is no answer to `child. NSEC`.
fn answers(held: &Ranked) -> bool {
    matches!(
        held.rank,
        Rank::AnswerNonAuthoritative | Rank::AnswerAuthoritative
    ) || (held.checked == Checked::Secure && held.rrset.rtype() == RecordType::DS)
}

/// `held` as served from the cache without a validator: a secure wildcard expansion goes without the proof that
/// no closer name exists (RFC 4035 §5.3.4), which the cache does not keep, so it is served unchecked, without AD.
fn unproven(mut held: Ranked) -> Ranked {
    if held.checked == Checked::Secure && held.rrset.expanded() {
        held.checked = Checked::Unchecked;
    }
    held
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

/// The closest delegation above `name` the caches know, strictly above it if `parent` (the root's hints for the
/// root): an NS `RRset` with an address that may be asked ([`askable`], `local` for any) for one of its first
/// [`Limits::servers`] servers, else a TLD's hints, else the root's (RFC 1034 §5.3.3 step 2).
fn closest(
    caches: &Caches,
    name: &Name<'_>,
    parent: bool,
    (limits, local): (&Limits, bool),
    now: u32,
) -> Delegation {
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
            for server in servers(&ns.rrset, limits.servers) {
                let known = cached_addresses(&caches.rrsets, &server, now);
                if known.is_empty() {
                    missing.push(server);
                }
                addresses.extend(known);
            }
            if addresses.iter().any(|&address| askable(address, local)) {
                debug!(%zone, "delegation from the cache");
                let zone = zone.into_owned();
                return Delegation::new(zone, Source::Cache, addresses, missing, local);
            }
        }
        if zone.label_count() == 1
            && let Some(tld) = caches.tlds.as_ref().and_then(|tlds| tlds.get(&zone))
        {
            debug!(%zone, "delegation from the TLD hints");
            return hinted(zone.into_owned(), tld.servers(), local);
        }
    }
    debug!("delegation from the root hints");
    hinted(Name::root(), caches.roots.servers(), local)
}

/// Whether a server at `address` may be asked: any if `local` ([`Resolution::asking_local_addresses`]), else one at an
/// address outside the special-purpose ranges a zone could aim the resolver at its own host, its network or many
/// hosts with (D191): `special_v4`, and of IPv6 the unspecified address and loopback, the ranges
/// `fc00::/7`, `fe80::/10`, the deprecated site-local `fec0::/10` and multicast `ff00::/8`, every IPv4-mapped
/// address (`::ffff:0:0/96`, as Unbound's `do-not-query-localhost`) and IPv4-compatible one (`::/96`), the
/// local-use NAT64 prefix (`64:ff9b:1::/48`, RFC 8215), and a NAT64 (`64:ff9b::/96`, RFC 6052) or 6to4
/// (`2002::/16`, RFC 3056) address embedding an IPv4 address that is `special_v4`.
#[must_use]
pub fn askable(address: IpAddr, local: bool) -> bool {
    local
        || !match address {
            IpAddr::V4(v4) => special_v4(v4),
            IpAddr::V6(v6) => special_v6(v6),
        }
}

/// Whether `v4` is in a special-purpose range of RFC 6890 no server is asked at: loopback (127/8), "this network"
/// (0/8), private (10/8, 172.16/12, 192.168/16), shared (100.64/10), link-local (169.254/16), IETF protocol
/// assignments (192.0.0/24), benchmarking (198.18/15), multicast (224/4), reserved (240/4) and broadcast.
fn special_v4(v4: Ipv4Addr) -> bool {
    let [first, second, third, _] = v4.octets();
    v4.is_loopback()
        || first == 0
        || v4.is_private()
        || (first == 100 && second & 0xc0 == 64)
        || v4.is_link_local()
        || (first, second, third) == (192, 0, 0)
        || (first == 198 && second & 0xfe == 18)
        || first >= 224
}

/// Whether `v6` is an address no server is asked at, as [`askable`] lists.
fn special_v6(v6: Ipv6Addr) -> bool {
    let segments = v6.segments();
    // The IPv4 address embedded in the segments `high` and `low`.
    let embedded =
        |high: u16, low: u16| special_v4(Ipv4Addr::from((u32::from(high) << 16) | u32::from(low)));
    v6.is_loopback()
        || v6.is_unspecified()
        || v6.is_unique_local()
        || v6.is_unicast_link_local()
        || segments
            .first()
            .is_some_and(|&first| first & 0xffc0 == 0xfec0)
        || v6.is_multicast()
        || matches!(segments, [0, 0, 0, 0, 0, 0 | 0xffff, ..])
        || matches!(segments, [0x64, 0xff9b, 1, ..])
        || matches!(segments, [0x64, 0xff9b, 0, 0, 0, 0, high, low] if embedded(high, low))
        || matches!(segments, [0x2002, high, low, ..] if embedded(high, low))
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

/// The name without its first label; `None` for the root.
fn parent(name: &Name<'_>) -> Option<Name<'static>> {
    (!name.is_root())
        .then(|| Name::from_labels(name.labels().skip(1)).ok())
        .flatten()
}

/// The delegation to `zone` that hints give.
fn hinted(zone: Name<'static>, servers: &[Server], local: bool) -> Delegation {
    let addresses = servers.iter().flat_map(Server::addresses);
    Delegation::new(zone, Source::Parent, addresses, Vec::new(), local)
}
