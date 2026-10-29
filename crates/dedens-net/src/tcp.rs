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

use std::cell::{OnceCell, RefCell};
use std::collections::HashMap;
use std::io;
use std::net::SocketAddr;
use std::rc::Rc;
use std::time::{Duration, Instant};

use compio::BufResult;
use compio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, BufReader};
use compio::net::TcpStream;
use compio::runtime::JoinHandle;
use compio::rustls::pki_types::ServerName;
use compio::tls::{TlsConnector, TlsStream};
use dedens_proto::Query;
use dedens_proto::edns::EdnsOption;
use futures_util::io::{AsyncReadExt as _, AsyncWriteExt as _};

use crate::exchange::after;
use crate::tls::{self, Trust};

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
pub struct TcpPool {
    idle: Duration,
    trust: Trust,
    /// Built at the first TLS connection.
    tls: OnceCell<TlsConnector>,
    connections: RefCell<HashMap<Link, Connection>>,
}

impl TcpPool {
    /// No connection yet; each closes after `idle` without a query waiting, and gives up connecting after `idle`.
    /// TLS trusts the system's certificate authorities.
    #[must_use]
    pub fn new(idle: Duration) -> Self {
        Self {
            idle,
            trust: Trust::System,
            tls: OnceCell::new(),
            connections: RefCell::default(),
        }
    }

    /// The pool, its TLS connections trusting `trust`.
    #[must_use]
    pub fn trusting(self, trust: Trust) -> Self {
        Self { trust, ..self }
    }

    /// Sends `wire` over `link` and returns the response, waiting until `deadline`.
    ///
    /// The query goes under an ID no other query on the connection has, its own when free, and the response comes
    /// back with the ID of `wire` (RFC 7766 §6.2.1). The ID of a query that stopped waiting stays taken until its
    /// response comes or the connection closes. Opens a connection when there is none or the last one takes no
    /// more queries, all its IDs taken for one; a connection that closes before the response is replaced once and
    /// the query sent again (D27). A query that times out with nothing read on its open connection since it was
    /// sent closes the connection: the server stopped answering, or reading.
    ///
    /// # Errors
    ///
    /// [`TcpError`]: no connection or handshake, closed twice, a query that cannot be framed, or the deadline.
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
        // The connection of the last try, and when the query went on it.
        let mut last = None;
        let attempt = async {
            for _ in 0..2 {
                // Held while the query waits: a connection replaced in the pool lives until its queries are answered.
                let connection = self.connection(&link)?;
                let sent = Instant::now();
                let response = match connection.send(wire) {
                    Ok(response) => response,
                    // It took no more queries: the next is new.
                    Err(TcpError::Closed) => continue,
                    Err(error) => return Err(error),
                };
                let connection = last.insert((connection, sent)).0.clone();
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
        let answered = compio::time::timeout_at(deadline, attempt).await;
        answered.unwrap_or_else(|_| {
            if let Some((connection, sent)) = last {
                connection.state.borrow_mut().stalled(sent);
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
        let connection = self.connection(&link.into())?;
        // Ends when the connecting does: nothing is ever sent.
        let opened = compio::time::timeout_at(deadline, connection.opening.recv_async()).await;
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

    /// The connection over `link` taking queries, or a new one.
    fn connection(&self, link: &Link) -> Result<Connection, TcpError> {
        let mut connections = self.connections.borrow_mut();
        if let Some(open) = connections.get(link)
            && open.state.borrow().takes_queries()
        {
            return Ok(open.clone());
        }
        let tls = match link {
            Link::Tcp(_) => None,
            Link::Tls(..) => Some(self.connector()?),
        };
        let fresh = Connection::open(link.clone(), tls, self.idle);
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
    /// Why the connection could not be opened, for each query on it to see.
    failure: Option<TcpError>,
    /// The last query sent or response received.
    last: Instant,
    /// The last message read.
    read: Instant,
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

    /// Closes the open connection when nothing was read since `sent`, when a query that went then timed out.
    fn stalled(&mut self, sent: Instant) {
        if self.local.is_some() && self.read < sent {
            self.close();
        }
    }
}

impl Connection {
    /// Starts connecting over `link`, with TLS by `tls`; queries queue meanwhile.
    fn open(link: Link, tls: Option<TlsConnector>, idle: Duration) -> Self {
        let (opened, opening) = flume::bounded(0);
        let (outgoing, queue) = flume::unbounded();
        let now = Instant::now();
        let state = Rc::new(RefCell::new(State {
            waiting: HashMap::new(),
            outgoing: Some(outgoing),
            local: None,
            failure: None,
            last: now,
            read: now,
            idle,
        }));
        let task = compio::runtime::spawn(run(link, tls, Rc::clone(&state), queue, opened));
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

/// Connects, and shakes hands with `tls` over a TLS link, within the idle timeout; then reads and writes until
/// the connection closes, each write within the idle timeout too.
async fn run(
    link: Link,
    tls: Option<TlsConnector>,
    state: Rc<RefCell<State>>,
    queue: flume::Receiver<Vec<u8>>,
    opened: flume::Sender<()>,
) {
    let idle = state.borrow().idle;
    let deadline = after(Instant::now(), idle);
    let connected = async {
        let stream = TcpStream::connect(link.addr())
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
    let connected = compio::time::timeout_at(deadline, connected)
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
            let (reader, writer) = stream.into_split();
            serve(BufReader::new(reader), writer, &state, &queue, idle).await;
        }
        Open::Secured(stream) => {
            let (reader, writer) = futures_util::io::AsyncReadExt::split(*stream);
            serve(Polled(reader), Polled(writer), &state, &queue, idle).await;
        }
    }
}

/// An open connection.
enum Open {
    /// Over TCP.
    Plain(TcpStream),
    /// Over TLS.
    Secured(Box<TlsStream<TcpStream>>),
}

/// Runs the reader on a task of its own, and the writer.
async fn serve(
    reader: impl Inbound,
    writer: impl Outbound,
    state: &Rc<RefCell<State>>,
    queue: &flume::Receiver<Vec<u8>>,
    limit: Duration,
) {
    let _reader = compio::runtime::spawn(read(reader, Rc::clone(state)));
    write(writer, state, queue, limit).await;
}

/// The reading side of a connection, one message at a time.
trait Inbound: 'static {
    /// The next message (see [`read_message`]).
    async fn message(&mut self) -> io::Result<Vec<u8>>;
}

/// The writing side of a connection.
trait Outbound {
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

impl Outbound for TcpStream {
    async fn write_all(&mut self, batch: Vec<u8>) -> BufResult<(), Vec<u8>> {
        AsyncWriteExt::write_all(self, batch).await
    }

    async fn close(&mut self) {
        let _ = self.shutdown().await;
    }
}

/// A half of a TLS stream, polled: each half locks the stream only while polled, so the reader waiting for a
/// response never holds back the writer.
struct Polled<T>(T);

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
async fn write(
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
            let now = Instant::now();
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
        match compio::time::timeout_at(wake, queue.recv_async()).await {
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
                match compio::time::timeout(limit, stream.write_all(batch)).await {
                    Ok(BufResult(Ok(()), written)) => batch = written,
                    Ok(BufResult(Err(_), _)) | Err(_) => break,
                }
            }
            Ok(Err(_)) => break,
        }
    }
    state.borrow_mut().close();
    // The server closes its side in turn.
    let _ = compio::time::timeout(limit, stream.close()).await;
}

/// Reads messages and hands each to the query waiting for its ID; the rest are dropped. Closes on end or error.
async fn read(mut stream: impl Inbound, state: Rc<RefCell<State>>) {
    while let Ok(message) = stream.message().await {
        let mut state = state.borrow_mut();
        state.last = Instant::now();
        state.read = state.last;
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
