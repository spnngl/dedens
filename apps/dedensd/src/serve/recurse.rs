//! A query resolved from the root by the recurse stage (D195): each query of its resolution sent to an
//! authoritative server with the thread's transport (D190), shared with the resolutions of the thread asking the
//! same server the same question at the same time (RFC 5452 §5), and the priming of the root's servers alongside
//! when due (RFC 8109 §3).

use std::cell::{OnceCell, RefCell};
use std::collections::HashMap;
use std::collections::hash_map::Entry;
use std::io;
use std::net::SocketAddr;
use std::rc::Rc;
use std::time::{Duration, Instant};

use dedens_net::authoritative::{
    self, Answer, Authoritative, AuthoritativeError, LocalError, Quirks, ServerError,
};
use dedens_net::entropy::Entropy;
use dedens_net::io::{Io, TimedOut};
use dedens_proto::{Message, Question, Transport};
use dedens_resolver::{Caches, Edns, Marks, Query, Reply, Resolved};
use dedens_server::{Pipeline, Resolving, Step, Turn};
use futures_util::future::join;

use super::Thread;
use super::upstream::copy_out;

const SENT: &str = "dedensd_recurse_errors_total";
const SHED: &str = "dedensd_recurse_shed_total";
const RRSETS: &str = "dedensd_recurse_rrset_cache_entries";
const RRSET_BYTES: &str = "dedensd_recurse_rrset_cache_bytes";
const SERVERS: &str = "dedensd_recurse_infra_cache_entries";
const SERVER_BYTES: &str = "dedensd_recurse_infra_cache_bytes";

/// Describes the metrics of this module.
pub(crate) fn describe() {
    metrics::describe_counter!(
        SENT,
        "Queries to authoritative servers that got no response, by error: no_socket and tcp_busy (the thread's \
         sockets or TCP connections were all taken until the deadline), ports_exhausted, local (another error of \
         ours), forged (responses dropped for their cookie), unreachable (an ICMP error) or tcp (D190)."
    );
    metrics::describe_counter!(
        SHED,
        "Resolutions shed, SERVFAIL Not Ready: they found a query in flight with WAITERS resolutions on it already, \
         and asked no one (D195)."
    );
    metrics::describe_gauge!(RRSETS, "RRsets in the recurse stage's cache (D193).");
    metrics::describe_gauge!(
        RRSET_BYTES,
        "Bytes the RRsets of the recurse stage's cache take (D193)."
    );
    metrics::describe_gauge!(
        SERVERS,
        "Servers in the recurse stage's infrastructure cache (D194)."
    );
    metrics::describe_gauge!(
        SERVER_BYTES,
        "Bytes the entries of the infrastructure cache take (D194)."
    );
}

/// Resolutions of a thread waiting on one query in flight besides the one that sent it: past them, a resolution is
/// shed, as a query past the limits of D117 and D186: it sends nothing, its query is not paid, and its client gets
/// SERVFAIL Not Ready. BIND's `max-clients-per-query` default (`bin/include/defaultconfig.h`):
/// BIND lets 10 clients (`clients-per-query`) wait on one fetch, raised by 5 up to 100 while fetches overflow, and
/// drops the client's query past it (`lib/dns/resolver.c`, `dns_resolver_createfetch`, `fctx_sendevents`); Unbound
/// bounds the queries a thread holds, `num-queries-per-thread`, and not those waiting on one (`services/mesh.c`,
/// `mesh_new_client`).
/// A resolution waits on one query at a time and holds one of the thread's upstream queries (D47): 100 of 1024.
pub(super) const WAITERS: usize = 100;

/// What the recurse stage of a thread holds: its transport, made at its first query, and the queries in flight.
pub(super) struct Recursion<N: Io> {
    transport: OnceCell<Authoritative<N>>,
    flights: Flights,
}

impl<N: Io> Recursion<N> {
    pub(super) fn new() -> Self {
        Self {
            transport: OnceCell::new(),
            flights: Flights::default(),
        }
    }
}

/// Asks the authoritative servers for `resolving`, from `pipeline`, and hands `deliver` the reply, copied out of
/// the thread's buffer; primes the root's servers alongside when due, which the reply does not wait for: until
/// then, the resolution starts from the hints (D191).
pub(super) async fn resolve<N: Io>(
    thread: &Thread<N>,
    pipeline: &Pipeline,
    mut resolving: Box<Resolving>,
    transport: Transport,
    mut deliver: impl AsyncFnMut(Vec<u8>),
) {
    let priming = async {
        if let Some(mut priming) = pipeline.prime(clock(thread)) {
            drive(thread, &mut priming).await;
            match priming.resolved() {
                Some(Resolved::Answer { .. }) => tracing::debug!("root servers primed"),
                resolved => tracing::warn!(?resolved, "root servers not primed"),
            }
        }
    };
    let reply = async {
        drive(thread, &mut resolving).await;
        gauges(resolving.caches());
        let reply = {
            let mut out = thread.scratch.borrow_mut();
            match pipeline.resolved(&resolving, thread.now(), &mut out) {
                Step::Reply(len) => copy_out(&out[..len], transport),
                _ => None,
            }
        };
        if let Some(reply) = reply {
            deliver(reply).await;
        }
    };
    join(priming, reply).await;
}

/// The thread's clock, finer than [`Thread::now`]'s seconds: the resolution times its servers with it.
fn clock<N: Io>(thread: &Thread<N>) -> Duration {
    thread.io.now().saturating_duration_since(thread.started)
}

/// Steps `resolving` to its end, each query sent, shared or shed ([`ask`]); a resolution without randomness to draw
/// its server with stops, unresolved, as does one whose step drew more than [`Entropy`] holds: the query it gave was
/// drawn with zeros, and is withdrawn unsent.
async fn drive<N: Io>(thread: &Thread<N>, resolving: &mut Resolving) {
    loop {
        let mut rng = match Entropy::from_io(&thread.io) {
            Ok(rng) => rng,
            Err(error) => {
                tracing::warn!(%error, "no randomness for a resolution");
                return;
            }
        };
        let query = match resolving.step(clock(thread), &mut rng) {
            Turn::Send(query) => query.clone(),
            Turn::Done => return,
        };
        if let Err(error) = rng.finish() {
            tracing::warn!(%error, "a resolution's step drew past its randomness");
            resolving.withdraw();
            return;
        }
        let asked = ask(thread, &query).await;
        hand(resolving, &query, asked, clock(thread));
    }
}

/// Hands `resolving` what became of the `query` it gave, at `now`: the outcome of one it sent, which judges the
/// server, or of one shared, which does not; one shed ends it.
fn hand(resolving: &mut Resolving, query: &Query, asked: Asked, now: Duration) {
    let (outcome, sent) = match asked {
        Asked::Sent(outcome) => (outcome, true),
        Asked::Shared(outcome) => (outcome, false),
        Asked::Shed => {
            metrics::counter!(SHED).increment(1);
            tracing::debug!(server = %query.server, name = %query.question.name, "too many waiting");
            resolving.shed();
            return;
        }
    };
    let decoded;
    let reply = match &outcome {
        Outcome::Response { wire, seen, rtt } => match Message::decode(wire) {
            Ok(message) => {
                decoded = message;
                Reply::Response {
                    message: &decoded.message,
                    seen: *seen,
                    rtt: *rtt,
                }
            }
            Err(_) => Reply::Undecodable,
        },
        Outcome::Timeout => Reply::Timeout,
        Outcome::TcpTimeout => Reply::TcpTimeout,
        Outcome::ServerError => Reply::ServerError,
        Outcome::LocalError => Reply::LocalError,
    };
    if sent {
        resolving.receive(reply, now);
    } else {
        resolving.receive_shared(reply, now);
    }
}

/// What a query got, as the resolutions waiting on it share it.
#[derive(Clone)]
enum Outcome {
    Response {
        wire: Rc<[u8]>,
        seen: Marks,
        rtt: Duration,
    },
    Timeout,
    TcpTimeout,
    ServerError,
    LocalError,
}

/// What became of a query a resolution asked.
enum Asked {
    /// It sent the query: the server is judged on this outcome.
    Sent(Outcome),
    /// Another resolution of the thread sent the same question to the same server first, and this one took its
    /// outcome, or [`Outcome::Timeout`] when its time ran out first: the server is judged by the one sending.
    Shared(Outcome),
    /// [`WAITERS`] waited on it already: the resolution is shed, nothing sent (D195).
    Shed,
}

/// Asks `query` with the thread's transport, or shares the same one in flight ([`asked`]).
async fn ask<N: Io>(thread: &Thread<N>, query: &Query) -> Asked {
    let ends = thread.io.now() + query.left;
    let flights = &thread.recursion.flights;
    asked(&thread.io, flights, query, ends, async |deadline| {
        send(thread, query, deadline).await
    })
    .await
}

/// What became of `query`, asked on `io` with `send` by the queries in flight `flights`, its resolution ending at
/// `ends` (`query.left`, so `Limits::time` holds whatever the wait): sent until `query.timeout` from now (moved to
/// TCP, the transport's `TCP_TIMEOUT` at least, D196, but not past `ends`), or shared with another resolution that
/// sent it first, its outcome taken until `ends`, a local error included. The one sending waits for its own server's
/// timeout, which may be longer than the waiter's estimate of it: the waiter waits for it rather than send again. One
/// the other gave up on unsent, cancelled, is sent with the time left, as is one whose sender's resolution ended
/// before its server's timeout: that timeout is not the server's, and those waiting may have more time.
async fn asked<N: Io>(
    io: &N,
    flights: &Flights,
    query: &Query,
    ends: Instant,
    send: impl AsyncFnOnce(Instant) -> Outcome,
) -> Asked {
    let key = (query.server, query.question.clone());
    let lead = loop {
        match flights.enter(&key) {
            Entered::Lead(lead) => break lead,
            Entered::Follow(waiting) => match io.timeout_at(ends, waiting.recv_async()).await {
                Ok(Ok(outcome)) => return Asked::Shared(outcome),
                // Gone without an outcome: this one sends it.
                Ok(Err(flume::RecvError::Disconnected)) => {}
                Err(TimedOut) => return Asked::Shared(Outcome::Timeout),
            },
            Entered::Full => return Asked::Shed,
        }
    };
    let deadline = (io.now() + query.timeout).min(ends);
    // A query moved to TCP waits past `deadline` (D196), never past `ends`.
    let outcome = io.timeout_at(ends, send(deadline)).await;
    let cut = deadline == ends || outcome.is_err();
    let outcome = outcome.unwrap_or(Outcome::Timeout);
    // Moved to TCP, its `TCP_TIMEOUT` may fall on `ends`: the transport's timer fires there before `timeout_at`'s.
    if cut && matches!(outcome, Outcome::Timeout | Outcome::TcpTimeout) {
        drop(lead);
    } else {
        lead.finish(&outcome);
    }
    Asked::Sent(outcome)
}

/// Sends `query` with the thread's transport, made at the first, until `deadline`.
async fn send<N: Io>(thread: &Thread<N>, query: &Query, deadline: Instant) -> Outcome {
    let recursion = &thread.recursion;
    let transport = recursion.transport.get_or_init(|| {
        Authoritative::with_io(thread.io.clone(), authoritative::Limits::default())
    });
    let question = query.question.clone();
    let quirks = quirks(query.marks);
    let answered = transport
        .query(question, query.server, quirks, deadline)
        .await;
    outcome(answered, query.server)
}

/// What the transport's `answered` from `server` is to the resolution, each error counted by its kind.
fn outcome(answered: Result<Answer, AuthoritativeError>, server: SocketAddr) -> Outcome {
    match answered {
        Ok(answer) => Outcome::Response {
            seen: marks(answer.quirks),
            rtt: answer.response.rtt,
            wire: answer.response.wire.into(),
        },
        Err(AuthoritativeError::Server(ServerError::TimedOut { .. })) => Outcome::Timeout,
        Err(AuthoritativeError::Server(ServerError::TcpTimedOut { .. })) => Outcome::TcpTimeout,
        Err(AuthoritativeError::Server(error)) => {
            let label = match error {
                ServerError::Forged { .. } => "forged",
                ServerError::Unreachable { .. } => "unreachable",
                _ => "tcp",
            };
            metrics::counter!(SENT, "error" => label).increment(1);
            tracing::debug!(%error, server = %server, "authoritative server");
            Outcome::ServerError
        }
        Err(AuthoritativeError::Local(error)) => {
            let label = match &error {
                LocalError::NoSocket => "no_socket",
                LocalError::TcpBusy => "tcp_busy",
                LocalError::Bind(bind) if bind.kind() == io::ErrorKind::AddrInUse => {
                    "ports_exhausted"
                }
                _ => "local",
            };
            metrics::counter!(SENT, "error" => label).increment(1);
            tracing::warn!(%error, server = %server, "authoritative query not sent");
            Outcome::LocalError
        }
        Err(error) => {
            metrics::counter!(SENT, "error" => "local").increment(1);
            tracing::warn!(%error, server = %server, "authoritative query not sent");
            Outcome::LocalError
        }
    }
}

/// What the transport needs of the marks the infrastructure cache holds: the same, by another name (D194).
fn quirks(marks: Marks) -> Quirks {
    Quirks {
        edns: match marks.edns {
            Edns::Unknown => authoritative::Edns::Unknown,
            Edns::Supported => authoritative::Edns::Supported,
            Edns::Unsupported { rejected, answered } => {
                authoritative::Edns::Unsupported { rejected, answered }
            }
        },
        no_case: marks.no_case,
        tcp: marks.tcp,
    }
}

/// The marks the transport saw of a server, for the infrastructure cache (D194).
fn marks(quirks: Quirks) -> Marks {
    Marks {
        edns: match quirks.edns {
            authoritative::Edns::Unknown => Edns::Unknown,
            authoritative::Edns::Supported => Edns::Supported,
            authoritative::Edns::Unsupported { rejected, answered } => {
                Edns::Unsupported { rejected, answered }
            }
        },
        no_case: quirks.no_case,
        tcp: quirks.tcp,
    }
}

/// Sets the gauges of the sizes of `caches`.
#[expect(
    clippy::cast_precision_loss,
    reason = "a gauge is a float; the sizes are far below 2^52"
)]
fn gauges(caches: &Caches) {
    metrics::gauge!(RRSETS).set(caches.rrsets.len() as f64);
    metrics::gauge!(RRSET_BYTES).set(caches.rrsets.used() as f64);
    metrics::gauge!(SERVERS).set(caches.infra.len() as f64);
    metrics::gauge!(SERVER_BYTES).set(caches.infra.used() as f64);
}

/// A server and the question sent to it.
type Key = (SocketAddr, Question<'static>);

/// The queries of a thread in flight to authoritative servers, each with the resolutions waiting on it.
#[derive(Default)]
struct Flights(RefCell<HashMap<Key, Vec<flume::Sender<Outcome>>>>);

/// What [`Flights::enter`] found.
enum Entered<'a> {
    /// None in flight: send it, then [`Lead::finish`].
    Lead(Lead<'a>),
    /// One in flight: its outcome comes, or the channel closes when the one sending it was cancelled.
    Follow(flume::Receiver<Outcome>),
    /// One in flight with [`WAITERS`] waiting already.
    Full,
}

impl Flights {
    fn enter(&self, key: &Key) -> Entered<'_> {
        match self.0.borrow_mut().entry(key.clone()) {
            Entry::Vacant(vacant) => {
                vacant.insert(Vec::new());
                Entered::Lead(Lead {
                    flights: self,
                    key: key.clone(),
                })
            }
            Entry::Occupied(mut waiting) => {
                let waiting = waiting.get_mut();
                // Those whose deadline came wait no more.
                waiting.retain(|sender| !sender.is_disconnected());
                if waiting.len() >= WAITERS {
                    return Entered::Full;
                }
                let (sender, receiver) = flume::bounded(1);
                waiting.push(sender);
                Entered::Follow(receiver)
            }
        }
    }
}

/// The query in flight sent by one resolution: dropped, it leaves, and those waiting send it again.
struct Lead<'a> {
    flights: &'a Flights,
    key: Key,
}

impl Lead<'_> {
    /// Hands `outcome` to those waiting.
    fn finish(self, outcome: &Outcome) {
        let waiting = self.flights.0.borrow_mut().remove(&self.key);
        for sender in waiting.into_iter().flatten() {
            // Room for one, and gone if the resolution was.
            let _ = sender.try_send(outcome.clone());
        }
    }
}

impl Drop for Lead<'_> {
    fn drop(&mut self) {
        self.flights.0.borrow_mut().remove(&self.key);
    }
}

#[cfg(test)]
mod tests {
    use std::cell::Cell;
    use std::mem::discriminant;
    use std::pin::pin;
    use std::sync::Arc;

    use compio::runtime::Runtime;
    use dedens_net::io::Compio;
    use dedens_proto::{Name, RecordType};
    use dedens_server::{Recurse, Stage};
    use futures_util::FutureExt;

    use super::*;

    const SECOND: Duration = Duration::from_secs(1);

    fn key() -> Key {
        let name: Name<'static> = "example.com.".parse().expect("a name");
        (
            ([192, 0, 2, 1], 53).into(),
            Question::new(name, RecordType::A),
        )
    }

    #[test]
    fn d195_one_query_in_flight_and_waiters_bounded() {
        let flights = Flights::default();
        let Entered::Lead(lead) = flights.enter(&key()) else {
            panic!("the first sends")
        };
        let waiting: Vec<_> = (0..WAITERS)
            .map(|_| match flights.enter(&key()) {
                Entered::Follow(receiver) => receiver,
                _ => panic!("the next wait"),
            })
            .collect();
        assert!(matches!(flights.enter(&key()), Entered::Full));
        lead.finish(&Outcome::Timeout);
        assert!(
            waiting
                .iter()
                .all(|w| matches!(w.try_recv(), Ok(Outcome::Timeout)))
        );
        // Over: the next sends again.
        assert!(matches!(flights.enter(&key()), Entered::Lead(_)));
    }

    /// The query of [`key`], timed out after `timeout`, its resolution with a second left (`asked` is given its end).
    fn query(timeout: Duration) -> Query {
        let (server, question) = key();
        Query {
            question,
            server,
            zone: Name::root(),
            marks: Marks::default(),
            timeout,
            left: SECOND,
        }
    }

    /// A send of a test where only one sends.
    async fn unsent(_: Instant) -> Outcome {
        panic!("sent by another")
    }

    /// The one sending hands the waiters its outcome, a local error too: a query it could not send has the others
    /// wait no more for the same, nor send it each in turn, each its own time out. It sends until its server's
    /// timeout, at most until its resolution ends.
    #[test]
    fn d195_the_one_sending_hands_its_outcome_and_sends_until_its_resolution_ends() {
        Runtime::new().expect("a runtime").block_on(async {
            for outcome in [Outcome::LocalError, Outcome::ServerError] {
                let flights = Flights::default();
                let ends = Compio.now() + Duration::from_millis(100);
                let (sent, waiting) = (Cell::new(None), RefCell::new(None));
                let asked = asked(&Compio, &flights, &query(SECOND), ends, async |until| {
                    sent.set(Some(until));
                    waiting.replace(Some(flights.enter(&key())));
                    outcome.clone()
                })
                .await;
                let Asked::Sent(got) = asked else {
                    panic!("sent")
                };
                assert_eq!(discriminant(&got), discriminant(&outcome));
                assert_eq!(sent.get(), Some(ends));
                let Some(Entered::Follow(waiting)) = waiting.take() else {
                    panic!("a waiter")
                };
                assert_eq!(
                    discriminant(&waiting.try_recv().expect("the outcome")),
                    discriminant(&outcome)
                );
            }
        });
    }

    /// A timeout cut short by the sender's resolution's end is not the server's: those waiting are not handed it,
    /// and one of them sends the query again in its own time. A timeout of the server's is handed. The same over
    /// TCP: a query moved there whose `TCP_TIMEOUT` falls at the resolution's end times out over TCP at that end.
    #[test]
    fn d195_a_timeout_cut_short_by_the_sender_s_end_is_not_shared() {
        Runtime::new().expect("a runtime").block_on(async {
            let cases = [(Duration::from_millis(10), false), (SECOND, true)];
            for ((left, shared), timeout) in cases
                .into_iter()
                .flat_map(|case| [(case, Outcome::Timeout), (case, Outcome::TcpTimeout)])
            {
                let flights = Flights::default();
                let ends = Compio.now() + left;
                let waiting = RefCell::new(None);
                let query = query(Duration::from_millis(100));
                let asked = asked(&Compio, &flights, &query, ends, async |_| {
                    waiting.replace(Some(flights.enter(&key())));
                    timeout.clone()
                })
                .await;
                let Asked::Sent(got) = asked else {
                    panic!("sent")
                };
                assert_eq!(discriminant(&got), discriminant(&timeout));
                let Some(Entered::Follow(waiting)) = waiting.take() else {
                    panic!("a waiter")
                };
                if shared {
                    let handed = waiting.try_recv().expect("the outcome");
                    assert_eq!(discriminant(&handed), discriminant(&timeout));
                } else {
                    assert!(matches!(
                        waiting.try_recv(),
                        Err(flume::TryRecvError::Disconnected)
                    ));
                    assert!(matches!(flights.enter(&key()), Entered::Lead(_)));
                }
            }
        });
    }

    /// A query moved to TCP waits past its deadline (D196) but not past its resolution's end: cut there, its timeout is
    /// not shared.
    #[test]
    fn d196_a_send_past_the_resolution_s_end_is_cut_there_and_not_shared() {
        Runtime::new().expect("a runtime").block_on(async {
            let flights = Flights::default();
            let ends = Compio.now() + Duration::from_millis(50);
            let waiting = RefCell::new(None);
            let query = query(Duration::from_millis(10));
            let asked = asked(&Compio, &flights, &query, ends, async |_| {
                waiting.replace(Some(flights.enter(&key())));
                compio::time::sleep(SECOND).await;
                Outcome::ServerError
            })
            .await;
            assert!(matches!(asked, Asked::Sent(Outcome::Timeout)));
            assert!(Compio.now() < ends + SECOND / 2);
            let Some(Entered::Follow(waiting)) = waiting.take() else {
                panic!("a waiter")
            };
            assert!(matches!(
                waiting.try_recv(),
                Err(flume::TryRecvError::Disconnected)
            ));
        });
    }

    /// A waiter takes the outcome of the one sending, and sends nothing itself.
    #[test]
    fn d195_a_waiter_takes_the_outcome_of_the_one_sending() {
        Runtime::new().expect("a runtime").block_on(async {
            let flights = Flights::default();
            let Entered::Lead(lead) = flights.enter(&key()) else {
                panic!("the first sends")
            };
            let ends = Compio.now() + Duration::from_secs(10);
            let query = query(SECOND);
            let mut waiting = pin!(asked(&Compio, &flights, &query, ends, unsent));
            assert!(waiting.as_mut().now_or_never().is_none());
            lead.finish(&Outcome::LocalError);
            assert!(matches!(waiting.await, Asked::Shared(Outcome::LocalError)));
        });
    }

    /// A waiter waits for the one sending past its own estimate of the server's timeout, which may be shorter than
    /// the sender's: it would send the same query again else.
    #[test]
    fn d195_a_waiter_waits_past_its_own_timeout_for_the_one_sending() {
        Runtime::new().expect("a runtime").block_on(async {
            let flights = Flights::default();
            let Entered::Lead(lead) = flights.enter(&key()) else {
                panic!("the first sends")
            };
            let ends = Compio.now() + Duration::from_secs(10);
            let query = query(Duration::from_millis(1));
            let sending = async {
                compio::time::sleep(Duration::from_millis(50)).await;
                lead.finish(&Outcome::ServerError);
            };
            let (asked, ()) =
                futures_util::future::join(asked(&Compio, &flights, &query, ends, unsent), sending)
                    .await;
            assert!(matches!(asked, Asked::Shared(Outcome::ServerError)));
        });
    }

    /// A waiter whose resolution ends first takes a timeout, which judges no server, and waits no more: one stuck
    /// sending does not hold the others past their time (`Limits::time`).
    #[test]
    fn d195_a_waiter_waits_until_its_resolution_ends() {
        Runtime::new().expect("a runtime").block_on(async {
            let flights = Flights::default();
            let _lead = flights.enter(&key());
            let ends = Compio.now() + Duration::from_millis(10);
            let query = query(SECOND);
            let asked =
                compio::time::timeout(SECOND, asked(&Compio, &flights, &query, ends, unsent))
                    .await
                    .expect("no wait past the resolution's end");
            assert!(matches!(asked, Asked::Shared(Outcome::Timeout)));
            assert!(Compio.now() >= ends);
        });
    }

    /// The one sending cancelled, a waiter sends the query itself, until its server's timeout from then, within
    /// its resolution's end.
    #[test]
    fn d195_a_waiter_sends_in_the_time_left_when_the_one_sending_is_gone() {
        Runtime::new().expect("a runtime").block_on(async {
            let flights = Flights::default();
            let lead = flights.enter(&key());
            let ends = Compio.now() + Duration::from_secs(10);
            let sent = Cell::new(None);
            let query = query(SECOND);
            let mut waiting = pin!(asked(&Compio, &flights, &query, ends, async |until| {
                sent.set(Some(until));
                Outcome::Timeout
            }));
            assert!(waiting.as_mut().now_or_never().is_none());
            let gone = Compio.now();
            drop(lead);
            assert!(matches!(waiting.await, Asked::Sent(Outcome::Timeout)));
            let until = sent.get().expect("sent");
            assert!(until >= gone + SECOND && until < ends, "{until:?}");
        });
    }

    /// Past [`WAITERS`], a resolution is shed: it sends nothing. A waiter gone is not counted.
    #[test]
    fn d195_past_the_waiters_a_resolution_is_shed() {
        Runtime::new().expect("a runtime").block_on(async {
            let flights = Flights::default();
            let _lead = flights.enter(&key());
            let mut waiting: Vec<_> = (0..WAITERS).map(|_| flights.enter(&key())).collect();
            let ends = Compio.now() + SECOND;
            let asked = asked(&Compio, &flights, &query(SECOND), ends, unsent).await;
            assert!(matches!(asked, Asked::Shed));
            waiting.pop();
            assert!(matches!(flights.enter(&key()), Entered::Follow(_)));
        });
    }

    /// A client's resolution of `example.com.` by a recurse stage alone, from the hints, stepped at `now` to its
    /// first query.
    fn resolving(now: Duration) -> (Box<Resolving>, Query) {
        let caches = Arc::new(Caches {
            rrsets: dedens_resolver::RrsetCache::new(1 << 20, dedens_cache::Config::default())
                .expect("a valid size"),
            infra: dedens_resolver::InfraCache::new(1 << 20, 1).expect("a valid size"),
            roots: dedens_roots::RootHints::bundled().clone(),
            tlds: None,
        });
        let pipeline = Pipeline::new(vec![Stage::Recurse(Recurse::new(caches))]);
        let name: Name<'static> = "example.com.".parse().expect("a name");
        let wire = Message::query(1, Question::new(name, RecordType::A))
            .to_vec()
            .expect("a query fits");
        let mut out = vec![0; 65535];
        let client = [192, 0, 2, 9].into();
        let Step::Resolve(mut resolving) =
            pipeline.query(&wire, Transport::Udp, client, 0, &mut out)
        else {
            panic!("a resolution")
        };
        let mut rng = Entropy::from_io(&Compio).expect("randomness");
        let Turn::Send(query) = resolving.step(now, &mut rng) else {
            panic!("a query")
        };
        let query = query.clone();
        (resolving, query)
    }

    /// What one sent got judges its server; what one shared does not, the one sending judged it (RFC 5452 §5).
    #[test]
    fn d195_an_outcome_sent_judges_the_server_one_shared_does_not() {
        let now = Duration::from_secs(1);
        for (asked, judged) in [
            (Asked::Sent(Outcome::Timeout), 1),
            (Asked::Shared(Outcome::Timeout), 0),
            (Asked::Sent(Outcome::ServerError), 1),
            (Asked::Shared(Outcome::ServerError), 0),
        ] {
            let (mut resolving, query) = resolving(now);
            hand(&mut resolving, &query, asked, now);
            assert_eq!(resolving.caches().infra.len(), judged);
            // The next query goes to another server.
            let mut rng = Entropy::from_io(&Compio).expect("randomness");
            let Turn::Send(next) = resolving.step(now, &mut rng) else {
                panic!("a query")
            };
            assert_ne!(next.server, query.server);
        }
    }

    /// One shed ends the resolution, nothing else asked.
    #[test]
    fn d195_a_resolution_shed_ends() {
        let now = Duration::from_secs(1);
        let (mut resolving, query) = resolving(now);
        hand(&mut resolving, &query, Asked::Shed, now);
        let mut rng = Entropy::from_io(&Compio).expect("randomness");
        assert_eq!(resolving.step(now, &mut rng), Turn::Done);
        assert_eq!(resolving.caches().infra.len(), 0);
    }

    #[test]
    fn d195_a_query_not_sent_lets_a_waiter_send_it() {
        let flights = Flights::default();
        let lead = flights.enter(&key());
        let Entered::Follow(waiting) = flights.enter(&key()) else {
            panic!("the next waits")
        };
        drop(lead);
        assert!(waiting.try_recv().is_err());
        assert!(matches!(flights.enter(&key()), Entered::Lead(_)));
    }

    /// The serving tasks describe the metrics, through `serve::describe` that `main` calls.
    #[test]
    fn d195_the_metrics_are_described() {
        let recorder = metrics_util::debugging::DebuggingRecorder::new();
        metrics::with_local_recorder(&recorder, || {
            super::super::describe();
            metrics::counter!(SENT, "error" => "forged").increment(1);
            metrics::counter!(SHED).increment(1);
            gauges(&Caches {
                rrsets: dedens_resolver::RrsetCache::new(1 << 20, dedens_cache::Config::default())
                    .expect("a valid size"),
                infra: dedens_resolver::InfraCache::new(1 << 20, 1).expect("a valid size"),
                roots: dedens_roots::RootHints::bundled().clone(),
                tlds: None,
            });
        });
        let described: Vec<_> = recorder
            .snapshotter()
            .snapshot()
            .into_vec()
            .into_iter()
            .filter(|(_, _, description, _)| description.is_some())
            .map(|(key, ..)| key.key().name().to_owned())
            .collect();
        for name in [SENT, SHED, RRSETS, RRSET_BYTES, SERVERS, SERVER_BYTES] {
            assert!(described.iter().any(|d| d == name), "{name}");
        }
    }

    /// D190's errors: a timeout is the server's silence, the others counted by their kind.
    #[test]
    fn d195_each_error_of_the_transport_is_counted_by_its_kind() {
        // What the resolution takes of `error`, and the label it was counted under, if any.
        let taken = |error| {
            let server: SocketAddr = ([192, 0, 2, 1], 53).into();
            let recorder = metrics_util::debugging::DebuggingRecorder::new();
            let outcome = metrics::with_local_recorder(&recorder, || outcome(Err(error), server));
            let kind = match outcome {
                Outcome::Response { .. } => "response",
                Outcome::Timeout => "timeout",
                Outcome::TcpTimeout => "tcp timeout",
                Outcome::ServerError => "server",
                Outcome::LocalError => "local",
            };
            let labels: Vec<_> = recorder
                .snapshotter()
                .snapshot()
                .into_vec()
                .into_iter()
                .filter(|(key, ..)| key.key().name() == SENT)
                .flat_map(|(key, ..)| {
                    let labels: Vec<_> = key.key().labels().map(|l| l.value().to_owned()).collect();
                    labels
                })
                .collect();
            (kind, labels)
        };
        let local = |error| taken(AuthoritativeError::Local(error));
        let remote = |error| taken(AuthoritativeError::Server(error));
        let unreachable = ServerError::Unreachable {
            sends: 1,
            kind: io::ErrorKind::ConnectionRefused,
        };
        assert_eq!(
            remote(ServerError::TimedOut { sends: 2 }),
            ("timeout", vec![])
        );
        assert_eq!(
            remote(ServerError::TcpTimedOut { sends: 2 }),
            ("tcp timeout", vec![])
        );
        assert_eq!(
            remote(ServerError::Forged { sends: 2 }),
            ("server", vec!["forged".to_owned()])
        );
        assert_eq!(
            remote(unreachable),
            ("server", vec!["unreachable".to_owned()])
        );
        assert_eq!(
            local(LocalError::NoSocket),
            ("local", vec!["no_socket".to_owned()])
        );
        assert_eq!(
            local(LocalError::TcpBusy),
            ("local", vec!["tcp_busy".to_owned()])
        );
        assert_eq!(
            local(LocalError::Bind(io::ErrorKind::AddrInUse.into())),
            ("local", vec!["ports_exhausted".to_owned()])
        );
        assert_eq!(
            local(LocalError::Bind(io::ErrorKind::PermissionDenied.into())),
            ("local", vec!["local".to_owned()])
        );
    }

    #[test]
    fn d194_marks_and_quirks_are_the_same() {
        for edns in [
            Edns::Unknown,
            Edns::Supported,
            Edns::Unsupported {
                rejected: dedens_proto::Rcode::FORMERR,
                answered: dedens_proto::Rcode::NOERROR,
            },
        ] {
            for (no_case, tcp) in [(false, false), (true, false), (false, true)] {
                let held = Marks { edns, no_case, tcp };
                assert_eq!(marks(quirks(held)), held);
            }
        }
    }
}
