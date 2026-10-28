//! DNS over TCP (RFC 7766): each message behind its two-byte length (RFC 1035 §4.2.2), one connection per server,
//! queries pipelined under IDs unique on the connection and their responses matched by ID in any order (RFC 7766
//! §6.2.1).
//!
//! A connection is one task, which connects then runs three: a writer that writes each queued query whole, so a
//! query that stops waiting never leaves the stream out of step; a reader that splits the stream into messages
//! ([`Frames`]) and hands each to the query waiting for its ID; and an idle timer that closes the connection once
//! no query has been waiting for the idle timeout, or for the server's edns-tcp-keepalive timeout when shorter
//! (RFC 7766 §6.2.3, RFC 7828 §3.2.2). Queries queue before the connection is up, so concurrent queries to a
//! server share one connection.

use std::cell::RefCell;
use std::collections::HashMap;
use std::io;
use std::net::SocketAddr;
use std::rc::Rc;
use std::time::{Duration, Instant};

use compio::BufResult;
use compio::io::{AsyncRead, AsyncWrite, AsyncWriteExt};
use compio::net::TcpStream;
use compio::runtime::JoinHandle;
use dedens_proto::Message;
use dedens_proto::edns::EdnsOption;
use dedens_proto::wire::MAX_MESSAGE_LEN;

use crate::exchange::after;

/// Why a TCP exchange failed.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum TcpError {
    /// The connection could not be opened.
    #[error("cannot connect: {0}")]
    Connect(#[source] io::Error),
    /// The connection closed before the response, twice: on the first connection and on a new one.
    #[error("connection closed before the response")]
    Closed,
    /// The query is shorter than a header or longer than 65535 bytes.
    #[error("a query of {0} bytes cannot be framed")]
    BadLength(usize),
    /// No response before the deadline.
    #[error("no response before the deadline")]
    TimedOut,
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

/// Splits a TCP byte stream into messages, whatever the reads cut it into (RFC 7766 §8).
#[derive(Debug, Default)]
pub struct Frames {
    buf: Vec<u8>,
    /// Where the next frame starts in `buf`.
    start: usize,
}

impl Frames {
    /// No bytes yet.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Adds bytes read from the stream.
    pub fn push(&mut self, bytes: &[u8]) {
        if self.start > 0 {
            self.buf.drain(..self.start);
            self.start = 0;
        }
        self.buf.extend_from_slice(bytes);
    }

    /// The next whole message, if its bytes have all come.
    pub fn next_message(&mut self) -> Option<&[u8]> {
        let rest = self.buf.get(self.start..)?;
        let (len, rest) = rest.split_first_chunk::<2>()?;
        let len = usize::from(u16::from_be_bytes(*len));
        let message = rest.get(..len)?;
        self.start += 2 + len;
        Some(message)
    }

    /// Bytes of an unfinished message.
    #[must_use]
    pub fn pending(&self) -> usize {
        self.buf.len() - self.start
    }
}

/// TCP connections, one per server, opened on first use and closed when idle (D27).
#[derive(Debug)]
pub struct TcpPool {
    idle: Duration,
    connections: RefCell<HashMap<SocketAddr, Connection>>,
}

impl TcpPool {
    /// No connection yet; each closes after `idle` without a query waiting, and gives up connecting after `idle`.
    #[must_use]
    pub fn new(idle: Duration) -> Self {
        Self {
            idle,
            connections: RefCell::default(),
        }
    }

    /// Sends `wire` to `server` and returns the response, waiting until `deadline`.
    ///
    /// The query goes under an ID no other query on the connection has, its own when free, and the response comes
    /// back with the ID of `wire` (RFC 7766 §6.2.1). The ID of a query that stopped waiting stays taken until its
    /// response comes or the connection closes. Opens a connection when there is none or the last one takes no
    /// more queries; a connection that closes before the response is replaced once and the query sent again (D27).
    ///
    /// # Errors
    ///
    /// [`TcpError`]: no connection, closed twice, a query that cannot be framed, or the deadline.
    pub async fn exchange(
        &self,
        server: SocketAddr,
        wire: &[u8],
        deadline: Instant,
    ) -> Result<Vec<u8>, TcpError> {
        let Some(id) = id_of(wire) else {
            return Err(TcpError::BadLength(wire.len()));
        };
        let attempt = async {
            for _ in 0..2 {
                // Held while the query waits: a connection replaced in the pool lives until its queries are answered.
                let connection = self.connection(server);
                let response = connection.send(wire)?;
                if let Ok(mut response) = response.recv_async().await {
                    if let Some(head) = response.first_chunk_mut() {
                        *head = id.to_be_bytes();
                    }
                    return Ok(response);
                }
                if let Some(error) = connection.state.borrow_mut().connect_error.take() {
                    return Err(TcpError::Connect(error));
                }
            }
            Err(TcpError::Closed)
        };
        compio::time::timeout_at(deadline, attempt)
            .await
            .unwrap_or(Err(TcpError::TimedOut))
    }

    /// The connection to `server` taking queries, or a new one.
    fn connection(&self, server: SocketAddr) -> Connection {
        let mut connections = self.connections.borrow_mut();
        if let Some(open) = connections.get(&server)
            && open.state.borrow().takes_queries()
        {
            return open.clone();
        }
        let fresh = Connection::open(server, self.idle);
        connections.insert(server, fresh.clone());
        fresh
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
#[derive(Debug, Clone)]
struct Connection {
    state: Rc<RefCell<State>>,
    _task: Rc<JoinHandle<()>>,
}

/// What the tasks and the queries share.
#[derive(Debug)]
struct State {
    /// The queries sent and not answered, by the ID they went with. The sender of a query that stopped waiting is
    /// disconnected, and stays so that its ID is not reused before the response comes (RFC 7766 §6.2.1).
    waiting: HashMap<u16, flume::Sender<Vec<u8>>>,
    /// Framed messages for the writer, until the connection closes: dropping it ends the writer.
    outgoing: Option<flume::Sender<Vec<u8>>>,
    /// Why the connection could not be opened, for the first query to see it.
    connect_error: Option<io::Error>,
    /// The last query sent or response received.
    last: Instant,
    /// The idle timeout; zero once the server asked for no more queries (RFC 7828 §3.2.2).
    idle: Duration,
    /// Wakes the idle timer when `idle` shrinks.
    nudge: flume::Sender<()>,
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
            .any(|sender| !sender.is_disconnected())
    }

    /// Closes: no new query, the writer ends, and the queries waiting see their channel close.
    fn close(&mut self) {
        self.outgoing = None;
        self.waiting.clear();
    }
}

impl Connection {
    /// Starts connecting to `server`; queries queue meanwhile.
    fn open(server: SocketAddr, idle: Duration) -> Self {
        let (nudge, nudged) = flume::bounded(1);
        let (outgoing, queue) = flume::unbounded();
        let state = Rc::new(RefCell::new(State {
            waiting: HashMap::new(),
            outgoing: Some(outgoing),
            connect_error: None,
            last: Instant::now(),
            idle,
            nudge,
        }));
        let task = compio::runtime::spawn(run(server, Rc::clone(&state), queue, nudged));
        Self {
            state,
            _task: Rc::new(task),
        }
    }

    /// Queues `wire` under an ID free on the connection, and returns the wait for its response.
    fn send(&self, wire: &[u8]) -> Result<flume::Receiver<Vec<u8>>, TcpError> {
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
        outgoing.send(framed).map_err(|_| TcpError::Closed)?;
        let (sender, response) = flume::bounded(1);
        state.waiting.insert(id, sender);
        state.last = Instant::now();
        Ok(response)
    }
}

/// Connects, then writes, reads and watches for idleness until the connection closes.
async fn run(
    server: SocketAddr,
    state: Rc<RefCell<State>>,
    queue: flume::Receiver<Vec<u8>>,
    nudged: flume::Receiver<()>,
) {
    let idle = state.borrow().idle;
    let connected =
        compio::time::timeout_at(after(Instant::now(), idle), TcpStream::connect(server))
            .await
            .unwrap_or_else(|_| Err(io::ErrorKind::TimedOut.into()));
    let stream = match connected {
        Ok(stream) => Rc::new(stream),
        Err(error) => {
            let mut state = state.borrow_mut();
            state.connect_error = Some(error);
            state.close();
            return;
        }
    };
    // Queries are small and each waits for its answer: send them without delay (RFC 7766 §10).
    if stream.set_nodelay(true).is_err() {
        state.borrow_mut().close();
        return;
    }
    let _reader = compio::runtime::spawn(read(Rc::clone(&stream), Rc::clone(&state)));
    let _idle = compio::runtime::spawn(close_when_idle(
        Rc::clone(&stream),
        Rc::clone(&state),
        nudged,
    ));
    write(&stream, &queue).await;
    state.borrow_mut().close();
}

/// Writes each queued message whole, until a write fails or the connection closes.
async fn write(stream: &TcpStream, queue: &flume::Receiver<Vec<u8>>) {
    let mut stream = stream;
    while let Ok(framed) = queue.recv_async().await {
        let BufResult(written, _) = stream.write_all(framed).await;
        if written.is_err() {
            return;
        }
    }
}

/// Reads messages and hands each to the query waiting for its ID; the rest are dropped. Closes on end or error.
async fn read(stream: Rc<TcpStream>, state: Rc<RefCell<State>>) {
    let mut frames = Frames::new();
    let mut buf = Vec::with_capacity(MAX_MESSAGE_LEN + 2);
    let mut stream = &*stream;
    loop {
        // A read fills the buffer from its start: what it does not overwrite is stale.
        buf.clear();
        let BufResult(read, back) = stream.read(buf).await;
        buf = back;
        if !matches!(read, Ok(n) if n > 0) {
            break;
        }
        frames.push(&buf);
        let mut state = state.borrow_mut();
        while let Some(message) = frames.next_message() {
            state.last = Instant::now();
            if let Some(timeout) = keepalive(message)
                && timeout < state.idle
            {
                state.idle = timeout;
                // A nudge already waiting does the same.
                let _ = state.nudge.try_send(());
            }
            if let Some(id) = id_of(message)
                && let Some(waiting) = state.waiting.remove(&id)
            {
                // The query may have stopped waiting; then the response goes nowhere.
                let _ = waiting.try_send(message.to_vec());
            }
        }
    }
    state.borrow_mut().close();
}

/// The edns-tcp-keepalive timeout of a response, if it has one (RFC 7828 §3.2.2).
fn keepalive(message: &[u8]) -> Option<Duration> {
    let decoded = Message::decode(message).ok()?;
    decoded
        .message
        .edns?
        .options
        .iter()
        .find_map(|option| match option {
            EdnsOption::Keepalive(Some(units)) => {
                Some(Duration::from_millis(u64::from(*units) * 100))
            }
            _ => None,
        })
}

/// Closes the connection once it has been idle for its timeout, with no query waiting (RFC 7766 §6.2.3).
async fn close_when_idle(
    stream: Rc<TcpStream>,
    state: Rc<RefCell<State>>,
    nudged: flume::Receiver<()>,
) {
    /// How often to look again while queries wait, so a zero timeout does not spin.
    const RECHECK: Duration = Duration::from_millis(100);
    loop {
        let wake = {
            let mut state = state.borrow_mut();
            if state.outgoing.is_none() {
                return;
            }
            let now = Instant::now();
            let idle_end = after(state.last, state.idle);
            if state.busy() {
                after(now, state.idle.max(RECHECK))
            } else if now >= idle_end {
                state.close();
                break;
            } else {
                idle_end
            }
        };
        // Wakes at the deadline, or sooner when the server shortened the timeout.
        let _ = compio::time::timeout_at(wake, nudged.recv_async()).await;
    }
    // The server closes its side in turn, and the reader sees the end.
    let mut stream = &*stream;
    let _ = stream.shutdown().await;
}
