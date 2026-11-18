//! DNS over TCP (RFC 7766) and over TLS (RFC 7858): each message behind its two-byte length (RFC 1035 §4.2.2), one
//! connection per server, queries pipelined under IDs unique on the connection and their responses matched by ID
//! in any order (RFC 7766 §6.2.1, RFC 7858 §3.3).
//!
//! A connection is one task, which connects, shakes hands over TLS, then runs two: a writer that writes each queued
//! query whole, so a query that stops waiting never leaves the stream out of step, and closes the connection once
//! no query has been waiting for the idle timeout, or for the server's edns-tcp-keepalive timeout when shorter
//! (RFC 7766 §6.2.3, RFC 7828 §3.2.2, RFC 7858 §3.4); and a reader that reads each message whole, however the
//! stream is cut (RFC 7766 §8), and hands it to the query waiting for its ID. Queries queue before the connection
//! is up, so concurrent queries to a server share one connection.
//!
//! Generic over [`Io`] (D134): time, tasks and sockets come from it; TLS runs over its streams.

#![deny(clippy::disallowed_methods)]

use std::cell::{Cell, OnceCell, RefCell};
use std::collections::{BTreeMap, HashMap};
use std::io;
use std::net::SocketAddr;
use std::num::NonZeroUsize;
use std::ops::Bound;
use std::rc::{Rc, Weak};
use std::time::{Duration, Instant};

use compio::BufResult;
use compio::io::util::Splittable;
use compio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, BufReader};
use compio::rustls::pki_types::ServerName;
use compio::tls::{TlsConnector, TlsStream};
use dedens_proto::Query;
use dedens_proto::edns::EdnsOption;
use futures_util::io::{AsyncReadExt as _, AsyncWriteExt as _, ReadHalf, WriteHalf};

use crate::exchange::after;
use crate::io::{Compio, Io, Stream};
use crate::tls::{self, Trust};

/// The least silence of a connection before a query's timeout closes it, from the send of its oldest query
/// unanswered or the last response read, the later: a shorter one, as of a query with a short deadline left, tells
/// nothing of a server other queries share the connection with. Counted from the oldest query, not from the one
/// timing out, so that queries with short deadlines, each sent after the last timed out, do not keep a dead
/// connection open. Unbound closes the connection on any
/// query's timeout (`outnet_tcptimer`, `services/outside_network.c`); 376 ms is the timeout it gives a server it
/// knows nothing of (`UNKNOWN_SERVER_NICENESS`, `iterator/iterator.c`).
pub const STALLED: Duration = Duration::from_millis(376);

/// Why a TCP or TLS exchange failed.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum TcpError {
    /// The connection could not be opened.
    #[error("cannot connect")]
    Connect(#[source] io::Error),
    /// The TLS handshake failed, the server's certificate not trusted for one (RFC 8310 §6.6).
    #[error("TLS handshake failed")]
    Handshake(#[source] io::Error),
    /// TLS cannot be set up with the trust asked for, such as no certificate authority usable.
    #[error("cannot set up TLS")]
    Trust(#[source] compio::rustls::Error),
    /// The connection closed before the response, twice: on the first connection and on a new one.
    #[error("connection closed before the response")]
    Closed,
    /// The query is shorter than a header or longer than 65535 bytes.
    #[error("a query of {0} bytes cannot be framed")]
    BadLength(usize),
    /// No response before the deadline.
    #[error("no response before the deadline")]
    TimedOut,
    /// No connection to open before the deadline: as many as the pool may hold are open, each with a query
    /// waiting, or as many as it may hold to the server (D190).
    #[error("no connection free before the deadline")]
    Busy,
}

impl TcpError {
    /// The same error for another query: an I/O error keeps its kind and message, not its source.
    fn copy(&self) -> Self {
        let io = |error: &io::Error| io::Error::new(error.kind(), error.to_string());
        match self {
            Self::Connect(error) => Self::Connect(io(error)),
            Self::Handshake(error) => Self::Handshake(io(error)),
            Self::Trust(error) => Self::Trust(error.clone()),
            Self::Closed => Self::Closed,
            Self::BadLength(len) => Self::BadLength(*len),
            Self::TimedOut => Self::TimedOut,
            Self::Busy => Self::Busy,
        }
    }
}

/// The two-byte length then `wire` (RFC 1035 §4.2.2), or `None` when `wire` is longer than 65535 bytes.
#[must_use]
pub fn frame(wire: &[u8]) -> Option<Vec<u8>> {
    let len = u16::try_from(wire.len()).ok()?;
    let mut framed = Vec::with_capacity(wire.len() + 2);
    framed.extend_from_slice(&len.to_be_bytes());
    framed.extend_from_slice(wire);
    Some(framed)
}

/// What a connection goes to: an address over TCP, or over TLS with the name its certificate must hold.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum Link {
    /// TCP to this address.
    Tcp(SocketAddr),
    /// TLS to this address, its certificate verified for this name (RFC 8310 §8.1), an address one when the server
    /// is known by its address only; a DNS name goes as SNI too.
    Tls(SocketAddr, ServerName<'static>),
}

impl Link {
    /// The server's address.
    #[must_use]
    pub const fn addr(&self) -> SocketAddr {
        match self {
            Self::Tcp(addr) | Self::Tls(addr, _) => *addr,
        }
    }
}

impl From<SocketAddr> for Link {
    fn from(addr: SocketAddr) -> Self {
        Self::Tcp(addr)
    }
}

/// TCP and TLS connections, one per server, opened on first use and closed when idle (D27).
#[derive(Debug)]
pub struct TcpPool<N: Io = Compio> {
    io: N,
    idle: Duration,
    trust: Trust,
    /// Built at the first TLS connection.
    tls: OnceCell<TlsConnector>,
    connections: RefCell<HashMap<Link, Connection<N>>>,
    /// The connections out of [`TcpPool::connections`], replaced or closed for room, until they close.
    retired: RefCell<Vec<(Link, Weak<RefCell<State>>)>>,
    /// The connections held at most, see [`TcpPool::at_most`].
    most: NonZeroUsize,
    /// The connections held at most over one link, see [`TcpPool::per_server`].
    per_server: NonZeroUsize,
    /// The time a query waiting for room must have left, see [`TcpPool::leaving`].
    least: Duration,
    /// The queries waiting for room, woken when a query ends or a connection closes.
    waiters: Rc<Waiters>,
}

impl TcpPool {
    /// No connection yet, on compio; each closes after `idle` without a query waiting, and gives up connecting after
    /// `idle`. TLS trusts the system's certificate authorities.
    #[must_use]
    pub fn new(idle: Duration) -> Self {
        Self::with_io(Compio, idle)
    }
}

impl<N: Io> TcpPool<N> {
    /// As [`TcpPool::new`], on `io`.
    #[must_use]
    pub fn with_io(io: N, idle: Duration) -> Self {
        Self {
            io,
            idle,
            trust: Trust::System,
            tls: OnceCell::new(),
            connections: RefCell::default(),
            retired: RefCell::default(),
            most: NonZeroUsize::MAX,
            per_server: NonZeroUsize::MAX,
            least: Duration::ZERO,
            waiters: Rc::default(),
        }
    }

    /// The pool, its TLS connections trusting `trust`.
    #[must_use]
    pub fn trusting(self, trust: Trust) -> Self {
        Self { trust, ..self }
    }

    /// The pool, holding at most `most` connections until they close, those replaced while queries wait on them
    /// included: a new one closes the one idle longest, with no query waiting, or waits for one to be (D190). The
    /// queries waiting for room look for it in the order they came, one at a time, and a query coming meanwhile
    /// waits behind them. No bound by default.
    #[must_use]
    pub fn at_most(self, most: NonZeroUsize) -> Self {
        Self { most, ..self }
    }

    /// The pool, holding at most `most` connections over one link, as [`TcpPool::at_most`] counts them: a server
    /// that asks for no more queries on each connection, by an edns-tcp-keepalive of 0 (RFC 7828 §3.2.2), holds no
    /// more (D190). No bound by default.
    #[must_use]
    pub fn per_server(self, most: NonZeroUsize) -> Self {
        Self {
            per_server: most,
            ..self
        }
    }

    /// The pool, a query that waited for room giving up once less than `least` would be left of it before its
    /// deadline, [`TcpError::Busy`]: the server is not asked on too little time to answer, which its timeout would
    /// then be blamed for (D190). Zero by default.
    #[must_use]
    pub fn leaving(self, least: Duration) -> Self {
        Self { least, ..self }
    }

    /// Sends `wire` over `link` and returns the response, waiting until `deadline`.
    ///
    /// The query goes under an ID no other query on the connection has, its own when free, and the response comes
    /// back with the ID of `wire` (RFC 7766 §6.2.1). The ID of a query that stopped waiting stays taken until its
    /// response comes or the connection closes. Opens a connection when there is none or the last one takes no
    /// more queries, all its IDs taken for one; a connection that closes before the response is replaced once and
    /// the query sent again (D27). A query that times out closes its open connection when it has been silent for
    /// [`STALLED`] at least, from the send of its oldest query unanswered or its last response, the later: the
    /// server stopped answering, or reading. With no
    /// room for a connection, see [`TcpPool::at_most`], the query waits for one until `deadline`, less
    /// [`TcpPool::leaving`].
    ///
    /// # Errors
    ///
    /// [`TcpError`]: no connection or handshake, closed twice, a query that cannot be framed, the deadline, or
    /// [`TcpError::Busy`] when it came with no room for a connection.
    pub async fn exchange(
        &self,
        link: impl Into<Link>,
        wire: &[u8],
        deadline: Instant,
    ) -> Result<Vec<u8>, TcpError> {
        let Some(id) = id_of(wire) else {
            return Err(TcpError::BadLength(wire.len()));
        };
        let link = link.into();
        // However the query ends, its connection may make room: dropped last, once the connection is let go.
        let _ended = Ended(&self.waiters);
        // The connection of the last try.
        let mut last = None;
        let roomless = Cell::new(false);
        let attempt = async {
            // The query's place among those waiting for room, once it waited; and whether it was just woken.
            let mut ticket = None;
            let mut woken = false;
            for _ in 0..2 {
                // Held while the query waits: a connection replaced in the pool lives until its queries are answered.
                let connection = loop {
                    let looked = self.connection(&link, ticket.is_none());
                    if std::mem::take(&mut woken) {
                        // The next in line looks after this one, whether it found room or not.
                        self.waiters.wake_after(ticket);
                    }
                    match looked {
                        Err(TcpError::Busy) => {
                            roomless.set(true);
                            let place = *ticket.get_or_insert_with(|| self.waiters.ticket());
                            let room_by = deadline.checked_sub(self.least).unwrap_or(deadline);
                            if self
                                .io
                                .timeout_at(room_by, self.waiters.wait(place))
                                .await
                                .is_err()
                            {
                                debug!(server = %link.addr(), "no connection free in time to ask");
                                return Err(TcpError::Busy);
                            }
                            woken = true;
                        }
                        got => break got?,
                    }
                };
                roomless.set(false);
                let sent = self.io.now();
                let response = match connection.send(wire, sent) {
                    Ok(response) => response,
                    // It took no more queries: the next is new.
                    Err(TcpError::Closed) => continue,
                    Err(error) => return Err(error),
                };
                let connection = last.insert(connection).clone();
                if let Ok(mut response) = response.recv_async().await {
                    if let Some(head) = response.first_chunk_mut() {
                        *head = id.to_be_bytes();
                    }
                    return Ok(response);
                }
                if let Some(error) = &connection.state.borrow().failure {
                    return Err(error.copy());
                }
            }
            Err(TcpError::Closed)
        };
        let answered = self.io.timeout_at(deadline, attempt).await;
        answered.unwrap_or_else(|_| {
            if roomless.get() {
                debug!(server = %link.addr(), "no connection free before the deadline");
                return Err(TcpError::Busy);
            }
            if let Some(connection) = last {
                connection.state.borrow_mut().stalled(deadline);
            }
            Err(TcpError::TimedOut)
        })
    }

    /// The local address of the connection over `link`, the source of its queries, once it is open; opens one
    /// when there is none taking queries.
    ///
    /// # Errors
    ///
    /// [`TcpError`]: the connection cannot be opened, closed already, or is not open by `deadline`.
    pub async fn local_addr(
        &self,
        link: impl Into<Link>,
        deadline: Instant,
    ) -> Result<SocketAddr, TcpError> {
        let connection = self.connection(&link.into(), true)?;
        // Ends when the connecting does: nothing is ever sent.
        let opened = self
            .io
            .timeout_at(deadline, connection.opening.recv_async())
            .await;
        let state = connection.state.borrow();
        match (state.local, opened) {
            (Some(local), _) => Ok(local),
            (None, Err(_)) => Err(TcpError::TimedOut),
            (None, Ok(_)) => Err(state
                .failure
                .as_ref()
                .map_or(TcpError::Closed, TcpError::copy)),
        }
    }

    /// The connection over `link` taking queries, or a new one; [`TcpError::Busy`] when there is no room for it, or
    /// when the query is `new` and queries woken for room have yet to look.
    fn connection(&self, link: &Link, new: bool) -> Result<Connection<N>, TcpError> {
        let mut connections = self.connections.borrow_mut();
        if let Some(open) = connections.get(link)
            && open.state.borrow().takes_queries()
        {
            return Ok(open.clone());
        }
        if new && self.waiters.passing() {
            return Err(TcpError::Busy);
        }
        let mut retired = self.retired.borrow_mut();
        if let Some(replaced) = connections.remove(link) {
            retired.push((link.clone(), Rc::downgrade(&replaced.state)));
        }
        // A connection counts until it closes; the shutdown of its side may hold its descriptor a moment longer.
        retired.retain(|(_, state)| {
            state
                .upgrade()
                .is_some_and(|state| state.borrow().outgoing.is_some())
        });
        if retired.iter().filter(|(over, _)| over == link).count() >= self.per_server.get() {
            debug!(server = %link.addr(), "no connection: as many as allowed to the server");
            return Err(TcpError::Busy);
        }
        if connections.len() + retired.len() >= self.most.get() {
            // The connection idle longest goes, first those that take no more queries.
            let idle = connections
                .iter()
                .filter(|(_, connection)| !connection.state.borrow().busy())
                .min_by_key(|(_, connection)| {
                    let state = connection.state.borrow();
                    (state.takes_queries(), state.last)
                })
                .map(|(link, _)| link.clone());
            let Some(idle) = idle.and_then(|idle| connections.remove_entry(&idle)) else {
                debug!(server = %link.addr(), "no connection: every one allowed has a query waiting");
                return Err(TcpError::Busy);
            };
            debug!(server = %idle.0.addr(), "closed: idle longest, for a new connection");
            // Not counted: no query waits on it, and it closes as it drops, its task cancelled with its last clone,
            // before the new one connects.
            drop(idle);
        }
        let tls = match link {
            Link::Tcp(_) => None,
            Link::Tls(..) => Some(self.connector()?),
        };
        let fresh = Connection::open(
            &self.io,
            link.clone(),
            tls,
            self.idle,
            Rc::clone(&self.waiters),
        );
        connections.insert(link.clone(), fresh.clone());
        Ok(fresh)
    }

    /// The TLS connector, built the first time.
    fn connector(&self) -> Result<TlsConnector, TcpError> {
        if let Some(connector) = self.tls.get() {
            return Ok(connector.clone());
        }
        let connector = tls::connector(&self.trust).map_err(TcpError::Trust)?;
        Ok(self.tls.get_or_init(|| connector).clone())
    }
}

/// The queries waiting for room in a pool, in the order they came, as Unbound's `tcp_wait_first` list
/// (`services/outside_network.c`). Room may come when a query ends or a connection closes: the first query waiting
/// is woken, looks for room, and wakes the next, and so on down the line, so that each looks before those behind
/// it. A query coming while one woken has yet to look waits behind the line. Room coming meanwhile, which those
/// that looked already missed, wakes the line again from the first once its last has looked.
#[derive(Debug, Default)]
struct Waiters {
    /// By ticket, in the order they came.
    queue: RefCell<BTreeMap<u64, flume::Sender<()>>>,
    /// The ticket of the next query to wait.
    next: Cell<u64>,
    /// The queries woken that have yet to look for room.
    woken: Cell<usize>,
    /// Whether room came while queries woken had yet to look: those that looked before it missed it.
    missed: Cell<bool>,
}

impl Waiters {
    /// A ticket behind every other.
    fn ticket(&self) -> u64 {
        let ticket = self.next.get();
        self.next.set(ticket + 1);
        ticket
    }

    /// Whether a query woken has yet to look for room: one coming now looks after it.
    fn passing(&self) -> bool {
        self.woken.get() > 0
    }

    /// Waits at the place of `ticket` until woken.
    async fn wait(&self, ticket: u64) {
        let (wake, woken) = flume::bounded(1);
        let taken = self.queue.borrow_mut().insert(ticket, wake);
        debug_assert!(taken.is_none(), "one query waits at a place");
        let place = Place {
            waiters: self,
            ticket,
            woken,
        };
        if place.woken.recv_async().await.is_ok() {
            self.woken.set(self.woken.get() - 1);
        }
    }

    /// Room may have come: wakes the first query waiting, unless one woken has yet to look, which wakes the next.
    fn room(&self) {
        if self.passing() {
            self.missed.set(true);
        } else {
            self.wake_after(None);
        }
    }

    /// Wakes the first query waiting behind `ticket`, or the first of all; with none behind and room missed, the
    /// first of all.
    fn wake_after(&self, ticket: Option<u64>) {
        let mut queue = self.queue.borrow_mut();
        let mut behind = ticket.map_or(Bound::Unbounded, Bound::Excluded);
        loop {
            let Some(next) = queue
                .range((behind, Bound::Unbounded))
                .next()
                .map(|(next, _)| *next)
            else {
                if !self.missed.replace(false) {
                    return;
                }
                behind = Bound::Unbounded;
                continue;
            };
            if queue
                .remove(&next)
                .is_some_and(|wake| wake.try_send(()).is_ok())
            {
                self.woken.set(self.woken.get() + 1);
                return;
            }
        }
    }
}

/// A query's place in [`Waiters`] while it waits: given up when it stops waiting, the wake it got passed on.
struct Place<'a> {
    waiters: &'a Waiters,
    ticket: u64,
    woken: flume::Receiver<()>,
}

impl Drop for Place<'_> {
    fn drop(&mut self) {
        let queued = self
            .waiters
            .queue
            .borrow_mut()
            .remove(&self.ticket)
            .is_some();
        if !queued && self.woken.try_recv().is_ok() {
            // Woken, but gone before looking: the next looks in its place.
            self.waiters.woken.set(self.waiters.woken.get() - 1);
            self.waiters.wake_after(Some(self.ticket));
        }
    }
}

/// Wakes the queries waiting for room when dropped, at the end of a query.
struct Ended<'a>(&'a Waiters);

impl Drop for Ended<'_> {
    fn drop(&mut self) {
        self.0.room();
    }
}

/// Closes a connection and wakes the queries waiting for room when dropped, as its task ends or is cancelled.
struct Closing {
    state: Rc<RefCell<State>>,
    waiters: Rc<Waiters>,
}

impl Drop for Closing {
    fn drop(&mut self) {
        self.state.borrow_mut().close();
        self.waiters.room();
    }
}

/// The ID of a message at least a header long.
fn id_of(wire: &[u8]) -> Option<u16> {
    /// The length of a header (RFC 1035 §4.1.1).
    const HEADER_LEN: usize = 12;
    if wire.len() < HEADER_LEN {
        return None;
    }
    wire.first_chunk::<2>().map(|id| u16::from_be_bytes(*id))
}

/// One connection: its task, cancelled when the last clone drops, and what the task shares with the queries.
#[derive(Debug)]
struct Connection<N: Io> {
    state: Rc<RefCell<State>>,
    /// Disconnected once the connection is open or failed to open.
    opening: flume::Receiver<()>,
    _task: Rc<N::Task>,
}

/// By hand: `derive(Clone)` would ask `N::Task` to be `Clone`, and the connection shares its task.
impl<N: Io> Clone for Connection<N> {
    #[expect(
        clippy::used_underscore_binding,
        reason = "the field is named for being held, never read"
    )]
    fn clone(&self) -> Self {
        Self {
            state: Rc::clone(&self.state),
            opening: self.opening.clone(),
            _task: Rc::clone(&self._task),
        }
    }
}

/// Messages a connection queues for its writer: those past them go on another connection. A query is small, so
/// this holds the memory of a server that stopped reading to a few hundred KiB, not the 4 GiB of 65536 queries of
/// 64 KiB (D108).
const QUEUE: usize = 1024;

/// What the tasks and the queries share.
#[derive(Debug)]
struct State {
    /// The queries sent and not answered, by the ID they went with. The sender of a query that stopped waiting is
    /// disconnected, and stays so that its ID is not reused before the response comes (RFC 7766 §6.2.1). Ordered,
    /// so that the queries a close wakes wake in ID order on every run and a seeded simulation replays (D134).
    waiting: BTreeMap<u16, Asked>,
    /// Framed messages for the writer, at most [`QUEUE`], until the connection closes: dropping it ends the writer.
    /// An empty message only wakes the writer to look at a shorter idle timeout.
    outgoing: Option<flume::Sender<Vec<u8>>>,
    /// The local address, once open.
    local: Option<SocketAddr>,
    /// Why the connection could not be opened, for each query on it to see.
    failure: Option<TcpError>,
    /// The last query sent or response received.
    last: Instant,
    /// The last response read, none yet: a frame no query waits for is not one (D108).
    read: Option<Instant>,
    /// The idle timeout; zero once the server asked for no more queries (RFC 7828 §3.2.2).
    idle: Duration,
}

impl State {
    /// Whether a new query may go on the connection.
    fn takes_queries(&self) -> bool {
        self.outgoing.is_some() && !self.idle.is_zero()
    }

    /// Whether a query waits for its response; one that stopped waiting does not count.
    fn busy(&self) -> bool {
        self.waiting
            .values()
            .any(|asked| !asked.response.is_disconnected())
    }

    /// Closes: no new query, the writer ends, and the queries waiting see their channel close.
    fn close(&mut self) {
        self.outgoing = None;
        self.waiting.clear();
    }

    /// Closes the open connection, as a query timed out at `now`, when it has been silent for [`STALLED`] at least:
    /// nothing read since its oldest query unanswered was sent, that of a query that stopped waiting included, or
    /// since the last response read when later.
    fn stalled(&mut self, now: Instant) {
        let Some(oldest) = self.waiting.values().map(|asked| asked.sent).min() else {
            return;
        };
        let silent = self.read.map_or(oldest, |read| read.max(oldest));
        if self.local.is_some() && now.saturating_duration_since(silent) >= STALLED {
            self.close();
        }
    }
}

/// A query sent on a connection and not answered.
#[derive(Debug)]
struct Asked {
    /// Where its response goes; disconnected once it stopped waiting.
    response: flume::Sender<Vec<u8>>,
    /// When it was sent.
    sent: Instant,
}

impl<N: Io> Connection<N> {
    /// Starts connecting over `link`, with TLS by `tls`; queries queue meanwhile. Its end wakes `waiters`.
    fn open(
        io: &N,
        link: Link,
        tls: Option<TlsConnector>,
        idle: Duration,
        waiters: Rc<Waiters>,
    ) -> Self {
        let (opened, opening) = flume::bounded(0);
        let (outgoing, queue) = flume::bounded(QUEUE);
        let now = io.now();
        let state = Rc::new(RefCell::new(State {
            waiting: BTreeMap::new(),
            outgoing: Some(outgoing),
            local: None,
            failure: None,
            last: now,
            read: None,
            idle,
        }));
        let closing = Closing {
            state: Rc::clone(&state),
            waiters,
        };
        let run = run(
            io.clone(),
            link,
            tls,
            Rc::clone(&state),
            queue,
            opened,
            idle,
        );
        let task = io.spawn(async move {
            let _closing = closing;
            run.await;
        });
        Self {
            state,
            opening,
            _task: Rc::new(task),
        }
    }

    /// Queues `wire` at `now` under an ID free on the connection, and returns the wait for its response.
    fn send(&self, wire: &[u8], now: Instant) -> Result<flume::Receiver<Vec<u8>>, TcpError> {
        let mut state = self.state.borrow_mut();
        let state = &mut *state;
        let (Some(mut framed), Some(id)) = (frame(wire), id_of(wire)) else {
            return Err(TcpError::BadLength(wire.len()));
        };
        let Some(outgoing) = state.outgoing.as_ref().filter(|_| !state.idle.is_zero()) else {
            return Err(TcpError::Closed);
        };
        let Some(id) = (0..=u16::MAX)
            .map(|step| id.wrapping_add(step))
            .find(|id| !state.waiting.contains_key(id))
        else {
            // All 65536 IDs wait for a response: as after a zero keepalive, the next query opens a connection.
            state.idle = Duration::ZERO;
            return Err(TcpError::Closed);
        };
        framed[2..4].copy_from_slice(&id.to_be_bytes());
        // The task holds the receiver until the connection closes.
        match outgoing.try_send(framed) {
            Ok(()) => {}
            Err(flume::TrySendError::Full(_)) => {
                // As with every ID taken: the writer drains what is queued, and the next query opens a connection.
                state.idle = Duration::ZERO;
                return Err(TcpError::Closed);
            }
            Err(flume::TrySendError::Disconnected(_)) => return Err(TcpError::Closed),
        }
        let (sender, response) = flume::bounded(1);
        state.waiting.insert(
            id,
            Asked {
                response: sender,
                sent: now,
            },
        );
        state.last = now;
        Ok(response)
    }
}

/// Connects, and shakes hands with `tls` over a TLS link, within the idle timeout; then reads and writes until
/// the connection closes, each write within the idle timeout too. The `idle` timeout is the pool's: the state's is
/// zero already once the queue filled before the connection opened.
async fn run<N: Io>(
    io: N,
    link: Link,
    tls: Option<TlsConnector>,
    state: Rc<RefCell<State>>,
    queue: flume::Receiver<Vec<u8>>,
    opened: flume::Sender<()>,
    idle: Duration,
) {
    let deadline = after(io.now(), idle);
    let connected = async {
        let stream = io
            .tcp_connect(link.addr())
            .await
            .map_err(TcpError::Connect)?;
        // Queries are small and each waits for its answer: send them without delay (RFC 7766 §10).
        stream.set_nodelay(true).map_err(TcpError::Connect)?;
        let local = stream.local_addr().map_err(TcpError::Connect)?;
        let open = match (&link, tls) {
            (Link::Tls(_, name), Some(connector)) => Open::Secured(Box::new(
                connector
                    .connect(&name.to_str(), stream)
                    .await
                    .map_err(TcpError::Handshake)?,
            )),
            _ => Open::Plain(stream),
        };
        Ok((open, local))
    };
    let connected = io
        .timeout_at(deadline, connected)
        .await
        .unwrap_or_else(|_| Err(TcpError::Connect(io::ErrorKind::TimedOut.into())));
    let open = match connected {
        Ok((open, local)) => {
            state.borrow_mut().local = Some(local);
            open
        }
        Err(error) => {
            let mut state = state.borrow_mut();
            state.failure = Some(error);
            state.close();
            return;
        }
    };
    drop(opened);
    match open {
        Open::Plain(stream) => {
            let (reader, writer) = stream.split();
            serve(
                &io,
                BufReader::new(reader),
                Half(writer),
                &state,
                &queue,
                idle,
            )
            .await;
        }
        Open::Secured(stream) => {
            let (reader, writer) = Polled::halves(*stream);
            serve(&io, reader, writer, &state, &queue, idle).await;
        }
    }
}

/// An open connection.
enum Open<S: Stream> {
    /// Over TCP.
    Plain(S),
    /// Over TLS.
    Secured(Box<TlsStream<S>>),
}

/// Runs the reader on a task of its own, and the writer.
async fn serve<N: Io>(
    io: &N,
    reader: impl Inbound,
    writer: impl Outbound,
    state: &Rc<RefCell<State>>,
    queue: &flume::Receiver<Vec<u8>>,
    limit: Duration,
) {
    let _reader = io.spawn(read(io.clone(), reader, Rc::clone(state)));
    write(io, writer, state, queue, limit).await;
}

/// The reading side of a connection, one message at a time.
#[expect(
    async_fn_in_trait,
    reason = "compio tasks stay on their thread: no caller needs the future to be `Send`"
)]
pub trait Inbound: 'static {
    /// The next message (see [`read_message`]).
    async fn message(&mut self) -> io::Result<Vec<u8>>;
}

/// The writing side of a connection.
#[expect(
    async_fn_in_trait,
    reason = "compio tasks stay on their thread: no caller needs the future to be `Send`"
)]
pub trait Outbound {
    /// Writes `batch` whole.
    async fn write_all(&mut self, batch: Vec<u8>) -> BufResult<(), Vec<u8>>;

    /// Closes the writing side; over TLS, after a `close_notify` (RFC 7858 §3.4).
    async fn close(&mut self);
}

impl<R: AsyncRead + 'static> Inbound for BufReader<R> {
    async fn message(&mut self) -> io::Result<Vec<u8>> {
        read_message(self).await
    }
}

impl Outbound for compio::net::TcpStream {
    async fn write_all(&mut self, batch: Vec<u8>) -> BufResult<(), Vec<u8>> {
        AsyncWriteExt::write_all(self, batch).await
    }

    async fn close(&mut self) {
        let _ = self.shutdown().await;
    }
}

/// The write half of a [`Stream`], written to by compio's traits.
struct Half<W>(W);

impl<W: AsyncWrite> Outbound for Half<W> {
    async fn write_all(&mut self, batch: Vec<u8>) -> BufResult<(), Vec<u8>> {
        AsyncWriteExt::write_all(&mut self.0, batch).await
    }

    async fn close(&mut self) {
        let _ = self.0.shutdown().await;
    }
}

/// A half of a TLS stream, polled: each half locks the stream only while polled, so the reader waiting for a
/// message never holds back the writer (D60). [`Polled::halves`] makes both.
#[derive(Debug)]
pub struct Polled<T>(T);

impl<S: futures_util::AsyncRead + futures_util::AsyncWrite> Polled<S> {
    /// The reading and the writing half of `stream`.
    pub fn halves(stream: S) -> (Polled<ReadHalf<S>>, Polled<WriteHalf<S>>) {
        let (reader, writer) = futures_util::io::AsyncReadExt::split(stream);
        (Polled(reader), Polled(writer))
    }
}

impl<R: futures_util::AsyncRead + Unpin + 'static> Inbound for Polled<R> {
    async fn message(&mut self) -> io::Result<Vec<u8>> {
        let mut len = [0; 2];
        self.0.read_exact(&mut len).await?;
        let mut message = vec![0; usize::from(u16::from_be_bytes(len))];
        self.0.read_exact(&mut message).await?;
        Ok(message)
    }
}

impl<W: futures_util::AsyncWrite + Unpin> Outbound for Polled<W> {
    async fn write_all(&mut self, batch: Vec<u8>) -> BufResult<(), Vec<u8>> {
        // rustls holds the records until flushed.
        let written = async {
            self.0.write_all(&batch).await?;
            self.0.flush().await
        };
        BufResult(written.await, batch)
    }

    async fn close(&mut self) {
        let _ = self.0.close().await;
    }
}

/// The bytes past which no more queued message joins a write.
const BATCH_LEN: usize = 65535;

/// Writes each queued message whole, those queued meanwhile with it up to [`BATCH_LEN`] bytes: one write, and one
/// wake-up of the server, for many. Stops when a write fails or takes longer than `limit`, as to a server that no
/// longer reads, or when the connection closes; closes the connection once no query has been waiting for the idle
/// timeout (RFC 7766 §6.2.3), and shuts its side down.
async fn write<N: Io>(
    io: &N,
    mut stream: impl Outbound,
    state: &RefCell<State>,
    queue: &flume::Receiver<Vec<u8>>,
    limit: Duration,
) {
    /// How often to look again while queries wait, so a zero timeout does not spin.
    const RECHECK: Duration = Duration::from_millis(100);
    let mut batch = Vec::new();
    loop {
        let wake = {
            let state = state.borrow();
            let now = io.now();
            let idle_end = after(state.last, state.idle);
            // The queries waiting are looked at once idle only.
            if now < idle_end {
                idle_end
            } else if state.busy() {
                after(now, state.idle.max(RECHECK))
            } else {
                break;
            }
        };
        match io.timeout_at(wake, queue.recv_async()).await {
            // The time to look again.
            Err(_) => {}
            // An empty message, the reader's wake-up call, writes nothing.
            Ok(Ok(framed)) => {
                batch.clear();
                batch.extend_from_slice(&framed);
                while batch.len() < BATCH_LEN
                    && let Ok(framed) = queue.try_recv()
                {
                    batch.extend_from_slice(&framed);
                }
                match io
                    .timeout_at(after(io.now(), limit), stream.write_all(batch))
                    .await
                {
                    Ok(BufResult(Ok(()), written)) => batch = written,
                    Ok(BufResult(Err(_), _)) | Err(_) => break,
                }
            }
            Ok(Err(_)) => break,
        }
    }
    state.borrow_mut().close();
    // The server closes its side in turn.
    let _ = io.timeout_at(after(io.now(), limit), stream.close()).await;
}

/// Reads messages and hands each to the query waiting for its ID. A message no query waits for is dropped, and
/// proves nothing of the server: it neither keeps the connection from idling nor from being found stalled (D108).
/// Closes on end or error.
async fn read<N: Io>(io: N, mut stream: impl Inbound, state: Rc<RefCell<State>>) {
    while let Ok(message) = stream.message().await {
        let mut state = state.borrow_mut();
        let Some(id) = id_of(&message) else { continue };
        let Some(waiting) = state.waiting.remove(&id) else {
            continue;
        };
        state.last = io.now();
        state.read = Some(state.last);
        if let Some(timeout) = keepalive(&message)
            && timeout < state.idle
        {
            state.idle = timeout;
            if let Some(outgoing) = &state.outgoing {
                // Full: the writer wakes for what is queued, and looks again then.
                let _ = outgoing.try_send(Vec::new());
            }
        }
        // The query may have stopped waiting; then the response goes nowhere.
        let _ = waiting.response.try_send(message);
    }
    state.borrow_mut().close();
}

/// The next message: its two-byte length, then as many bytes (RFC 1035 §4.2.2).
///
/// # Errors
///
/// The stream's error, `UnexpectedEof` when it ends first.
pub async fn read_message(stream: &mut impl AsyncRead) -> io::Result<Vec<u8>> {
    let len = usize::from(stream.read_u16().await?);
    // `read_exact` fills the capacity, which `with_capacity` makes exactly `len`.
    let BufResult(read, message) = stream.read_exact(Vec::with_capacity(len)).await;
    read.map(|()| message)
}

/// The edns-tcp-keepalive timeout of a response, if it has one (RFC 7828 §3.2.2): every response on a connection
/// comes through here, so it is read in place, not decoded.
fn keepalive(message: &[u8]) -> Option<Duration> {
    Query::read(message)
        .ok()?
        .edns()?
        .options()
        .find_map(|option| match option {
            EdnsOption::Keepalive(Some(timeout)) => {
                Some(Duration::from_millis(u64::from(timeout) * 100))
            }
            _ => None,
        })
}
