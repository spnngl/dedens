//! DNS over TCP (RFC 7766): each message behind its two-byte length (RFC 1035 §4.2.2), one connection per server,
//! queries pipelined under IDs unique on the connection and their responses matched by ID in any order (RFC 7766
//! §6.2.1).
//!
//! A connection is one task, which connects then runs two: a writer that writes each queued query whole, so a query
//! that stops waiting never leaves the stream out of step, and closes the connection once no query has been waiting
//! for the idle timeout, or for the server's edns-tcp-keepalive timeout when shorter (RFC 7766 §6.2.3, RFC 7828
//! §3.2.2); and a reader that reads each message whole, however the stream is cut (RFC 7766 §8), and hands it to the
//! query waiting for its ID. Queries queue before the connection is up, so concurrent queries to a server share one
//! connection.

use std::cell::RefCell;
use std::collections::HashMap;
use std::io;
use std::net::SocketAddr;
use std::rc::Rc;
use std::time::{Duration, Instant};

use compio::BufResult;
use compio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, BufReader};
use compio::net::TcpStream;
use compio::runtime::JoinHandle;

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

    /// The local address of the connection to `server`, the source of its queries, once it is open; opens one
    /// when there is none taking queries.
    ///
    /// # Errors
    ///
    /// [`TcpError`]: the connection cannot be opened, closed already, or is not open by `deadline`.
    pub async fn local_addr(
        &self,
        server: SocketAddr,
        deadline: Instant,
    ) -> Result<SocketAddr, TcpError> {
        let connection = self.connection(server);
        // Ends when the connecting does: nothing is ever sent.
        let opened = compio::time::timeout_at(deadline, connection.opening.recv_async()).await;
        let mut state = connection.state.borrow_mut();
        match (state.local, opened) {
            (Some(local), _) => Ok(local),
            (None, Err(_)) => Err(TcpError::TimedOut),
            (None, Ok(_)) => Err(state
                .connect_error
                .take()
                .map_or(TcpError::Closed, TcpError::Connect)),
        }
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
    /// Disconnected once the connection is open or failed to open.
    opening: flume::Receiver<()>,
    _task: Rc<JoinHandle<()>>,
}

/// What the tasks and the queries share.
#[derive(Debug)]
struct State {
    /// The queries sent and not answered, by the ID they went with. The sender of a query that stopped waiting is
    /// disconnected, and stays so that its ID is not reused before the response comes (RFC 7766 §6.2.1).
    waiting: HashMap<u16, flume::Sender<Vec<u8>>>,
    /// Framed messages for the writer, until the connection closes: dropping it ends the writer. An empty message
    /// only wakes the writer to look at a shorter idle timeout.
    outgoing: Option<flume::Sender<Vec<u8>>>,
    /// The local address, once open.
    local: Option<SocketAddr>,
    /// Why the connection could not be opened, for the first query to see it.
    connect_error: Option<io::Error>,
    /// The last query sent or response received.
    last: Instant,
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
        let (opened, opening) = flume::bounded(0);
        let (outgoing, queue) = flume::unbounded();
        let state = Rc::new(RefCell::new(State {
            waiting: HashMap::new(),
            outgoing: Some(outgoing),
            local: None,
            connect_error: None,
            last: Instant::now(),
            idle,
        }));
        let task = compio::runtime::spawn(run(server, Rc::clone(&state), queue, opened));
        Self {
            state,
            opening,
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

/// Connects, within the idle timeout, then reads and writes until the connection closes.
async fn run(
    server: SocketAddr,
    state: Rc<RefCell<State>>,
    queue: flume::Receiver<Vec<u8>>,
    opened: flume::Sender<()>,
) {
    let idle = state.borrow().idle;
    let connected = async {
        let stream =
            compio::time::timeout_at(after(Instant::now(), idle), TcpStream::connect(server))
                .await
                .unwrap_or_else(|_| Err(io::ErrorKind::TimedOut.into()))?;
        // Queries are small and each waits for its answer: send them without delay (RFC 7766 §10).
        stream.set_nodelay(true)?;
        let local = stream.local_addr()?;
        io::Result::Ok((stream, local))
    };
    let stream = match connected.await {
        Ok((stream, local)) => {
            state.borrow_mut().local = Some(local);
            stream
        }
        Err(error) => {
            let mut state = state.borrow_mut();
            state.connect_error = Some(error);
            state.close();
            return;
        }
    };
    drop(opened);
    let (reader, writer) = stream.into_split();
    let _reader = compio::runtime::spawn(read(reader, Rc::clone(&state)));
    write(writer, &state, &queue).await;
}

/// Writes each queued message whole, until a write fails or the connection closes; closes the connection once no
/// query has been waiting for the idle timeout (RFC 7766 §6.2.3), and shuts its side down.
async fn write(mut stream: TcpStream, state: &RefCell<State>, queue: &flume::Receiver<Vec<u8>>) {
    /// How often to look again while queries wait, so a zero timeout does not spin.
    const RECHECK: Duration = Duration::from_millis(100);
    loop {
        let wake = {
            let state = state.borrow();
            let now = Instant::now();
            let idle_end = after(state.last, state.idle);
            if state.busy() {
                after(now, state.idle.max(RECHECK))
            } else if now >= idle_end {
                break;
            } else {
                idle_end
            }
        };
        match compio::time::timeout_at(wake, queue.recv_async()).await {
            // The time to look again.
            Err(_) => {}
            // An empty message, the reader's wake-up call, writes nothing.
            Ok(Ok(framed)) => {
                if stream.write_all(framed).await.0.is_err() {
                    break;
                }
            }
            Ok(Err(_)) => break,
        }
    }
    state.borrow_mut().close();
    // The server closes its side in turn.
    let _ = stream.shutdown().await;
}

/// Reads messages and hands each to the query waiting for its ID; the rest are dropped. Closes on end or error.
async fn read(stream: TcpStream, state: Rc<RefCell<State>>) {
    let mut stream = BufReader::new(stream);
    while let Ok(message) = read_message(&mut stream).await {
        let mut state = state.borrow_mut();
        state.last = Instant::now();
        if let Some(timeout) = keepalive(&message)
            && timeout < state.idle
        {
            state.idle = timeout;
            if let Some(outgoing) = &state.outgoing {
                let _ = outgoing.send(Vec::new());
            }
        }
        if let Some(id) = id_of(&message)
            && let Some(waiting) = state.waiting.remove(&id)
        {
            // The query may have stopped waiting; then the response goes nowhere.
            let _ = waiting.try_send(message);
        }
    }
    state.borrow_mut().close();
}

/// The next message: its two-byte length, then as many bytes (RFC 1035 §4.2.2).
async fn read_message(stream: &mut impl AsyncRead) -> io::Result<Vec<u8>> {
    let len = usize::from(stream.read_u16().await?);
    // `read_exact` fills the capacity, which `with_capacity` makes exactly `len`.
    let BufResult(read, message) = stream.read_exact(Vec::with_capacity(len)).await;
    read.map(|()| message)
}

/// The edns-tcp-keepalive timeout of a response, if it has one (RFC 7828 §3.2.2).
///
/// Every response on a connection comes through here: rather than decode it, this walks to the OPT record of the
/// additional section and reads its options (RFC 6891 §6.1.2). A message too short for what it says has none.
fn keepalive(message: &[u8]) -> Option<Duration> {
    /// The type of the OPT record (RFC 6891 §6.1.1).
    const OPT: u16 = 41;
    /// The code of edns-tcp-keepalive (RFC 7828 §3.1).
    const KEEPALIVE: u16 = 11;
    let u16_at =
        |at: usize| -> Option<u16> { Some(u16::from_be_bytes(*message.get(at..)?.first_chunk()?)) };
    // The four counts follow the ID and the flags (RFC 1035 §4.1.1).
    let mut at = 12;
    for _ in 0..u16_at(4)? {
        // The name, then the type and the class.
        at = skip_name(message, at)? + 4;
    }
    let before = usize::from(u16_at(6)?) + usize::from(u16_at(8)?);
    for record in 0..before + usize::from(u16_at(10)?) {
        // The name, then the type, class, TTL, RDLENGTH and RDATA (RFC 1035 §4.1.3).
        at = skip_name(message, at)?;
        let rdata = at + 10;
        let end = rdata + usize::from(u16_at(at + 8)?);
        if record >= before && u16_at(at)? == OPT {
            // Each option: its code, its length, its value.
            let mut option = rdata;
            while option < end {
                let len = usize::from(u16_at(option + 2)?);
                if u16_at(option)? == KEEPALIVE && len == 2 && option + 6 <= end {
                    return Some(Duration::from_millis(u64::from(u16_at(option + 4)?) * 100));
                }
                option += 4 + len;
            }
            return None;
        }
        at = end;
    }
    None
}

/// Where the name at `at` ends: past its root label or its compression pointer (RFC 1035 §4.1.4).
fn skip_name(message: &[u8], mut at: usize) -> Option<usize> {
    loop {
        match *message.get(at)? {
            0 => return Some(at + 1),
            len @ 1..=63 => at += 1 + usize::from(len),
            0xC0.. => return Some(at + 2),
            _ => return None,
        }
    }
}
