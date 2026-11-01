//! The sockets of one thread and the tasks answering on them (D42): a task per UDP socket and per TCP listener,
//! one per TCP connection, and one per query that waits for an upstream server. Replies the pipeline builds at
//! once go out from the socket's own task; the rest are asked upstream with the thread's `dedens_net` client.
//! Each thread bounds its upstream queries and TCP connections, each connection its queries in flight, the bytes
//! of its replies waiting to be written and the time they take to write (D47).

use std::cell::{Cell, RefCell};
use std::io;
use std::net::SocketAddr;
use std::num::NonZero;
use std::pin::pin;
use std::rc::Rc;
use std::sync::{Arc, LazyLock};
use std::time::{Duration, Instant};

use anyhow::Context;
use compio::BufResult;
use compio::buf::{IntoInner, IoBuf};
use compio::driver::ProactorBuilder;
use compio::driver::op::RecvFromMultiResult;
use compio::io::{AsyncWriteExt, BufReader};
use compio::net::{TcpListener, UdpSocket};
use compio::quic::{
    Connection, Endpoint, EndpointConfig, IdleTimeout, SendStream, ServerConfig, TransportConfig,
    VarInt,
};
use compio::runtime::{JoinHandle, Runtime, spawn};
use compio::rustls::pki_types::ServerName;
use compio::tls::TlsAcceptor;
use dedens_net::client::{Client, Server};
use dedens_net::doh::Method;
use dedens_net::exchange::Options;
use dedens_net::https::{Exchange, Pending, Requests};
use dedens_net::quic::{DOQ_PROTOCOL_ERROR, QuicError, read_message as read_stream};
use dedens_net::tcp::{Inbound, Outbound, Polled, frame};
use dedens_net::tls::{self, Presented, Trust};
use dedens_proto::Query;
use dedens_proto::edns::{DEFAULT_UDP_PAYLOAD, OptionCode};
use dedens_proto::wire::MAX_MESSAGE_LEN;
use dedens_server::{Pipeline, Step, Transport, Upstream, Via};
use futures_util::future::{join_all, select_all};
use futures_util::lock::Mutex;
use futures_util::{Stream, StreamExt};
use http::StatusCode;
use socket2::{Domain, Socket, Type};

use crate::config::Listen;
use crate::reload::Current;

/// How long a TCP connection stays open without a query (RFC 7766 §6.2.3).
const TCP_IDLE: Duration = Duration::from_secs(10);

/// Tasks answering on each UDP socket, taking turns at its datagrams: one waits for the next while the others
/// answer or send.
const UDP_RECEIVES: usize = 4;

/// Datagrams a thread holds received and not yet answered, in buffers made once: on Linux, `io_uring` fills them
/// without a receive asked for each datagram, and leaves the rest in the socket while all are taken. A power of
/// two.
const UDP_BUFFERS: NonZero<u16> = NonZero::new(256).expect("256 is not zero");

/// The bytes of each buffer, `io_uring`'s header and the sender's address included: a query longer than about 3.9
/// KiB is cut short, so read as broken.
const UDP_BUFFER_LEN: usize = 4096;

/// Bytes a UDP socket may hold before the OS drops datagrams (`SO_RCVBUF`).
const UDP_RECEIVE_BUFFER: usize = 4 << 20;

/// Connections waiting to be accepted, per TCP listener.
const TCP_BACKLOG: i32 = 1024;

/// How long to wait before accepting again after `accept` failed, for instance out of file descriptors, or
/// receiving again after a UDP receive failed twice in a row: an error that repeats at once would spin.
const ERROR_PAUSE: Duration = Duration::from_millis(100);

/// The sockets of one thread for an address of `listen`, bound but not yet on its runtime.
pub(crate) enum Bound {
    /// A UDP socket and a TCP listener.
    Plain(Socket, Socket),
    /// A TCP listener for TLS.
    Tls(Socket),
    /// A UDP socket for QUIC.
    Quic(Socket),
    /// A UDP socket for HTTP/3, serving `DoH` at the path (D84).
    Https(Socket, Arc<str>),
}

/// The sockets of one thread.
pub(crate) type Sockets = Vec<Bound>;

/// Binds the sockets of each address of `listen`. On Linux they take `SO_REUSEPORT`, so each thread binds its own
/// on the same addresses; the OS sends the datagrams of a QUIC client to one socket while its address and port
/// stay the same.
pub(crate) fn bind(listen: &[Listen]) -> anyhow::Result<Sockets> {
    let udp = |addr| socket(addr, Type::DGRAM).with_context(|| format!("cannot bind UDP {addr}"));
    let tcp = |addr| {
        socket(addr, Type::STREAM)
            .and_then(|tcp| tcp.listen(TCP_BACKLOG).map(|()| tcp))
            .with_context(|| format!("cannot listen on TCP {addr}"))
    };
    listen
        .iter()
        .map(|listen| match listen {
            Listen::Plain(addr) => Ok(Bound::Plain(udp(*addr)?, tcp(*addr)?)),
            Listen::Tls(addr) => tcp(*addr).map(Bound::Tls),
            Listen::Quic(addr) => udp(*addr).map(Bound::Quic),
            Listen::Https(addr, path) => {
                udp(*addr).map(|socket| Bound::Https(socket, Arc::clone(path)))
            }
        })
        .collect()
}

/// A non-blocking socket of type `ty` bound to `addr`; an IPv6 one takes IPv6 alone, so `[::]` and `0.0.0.0` bind
/// side by side.
fn socket(addr: SocketAddr, ty: Type) -> io::Result<Socket> {
    let socket = Socket::new(Domain::for_address(addr), ty, None)?;
    if addr.is_ipv6() {
        socket.set_only_v6(true)?;
    }
    if ty == Type::STREAM {
        socket.set_reuse_address(true)?;
    } else {
        // Room for bursts: the OS default, about 200 KiB on Linux, drops queries under load. The OS may cap it.
        socket.set_recv_buffer_size(UDP_RECEIVE_BUFFER)?;
    }
    #[cfg(target_os = "linux")]
    socket.set_reuse_port(true)?;
    socket.set_nonblocking(true)?;
    socket.bind(&addr.into())?;
    Ok(socket)
}

/// Upstream queries in flight per thread: past them, a UDP query is dropped and a TCP query answered SERVFAIL.
const UPSTREAM_QUERIES: usize = 1024;

/// TCP connections per thread: past them, a new one is closed at once (RFC 7766 §10).
const TCP_CONNECTIONS: usize = 256;

/// Queries in flight per TCP connection, waiting for upstream or for the writer: past them, reading waits.
const TCP_PENDING: usize = 64;

/// Bytes of replies a TCP connection may queue for its writer: past them, reading waits.
const TCP_QUEUED: usize = 128 << 10;

/// How long the replies queued on a TCP connection may take to be written, from when the first is queued until
/// none is left: a client that reads slower than it asks loses its connection (RFC 7766 §10).
const TCP_WRITE: Duration = Duration::from_secs(10);

/// What the tasks of one thread share.
struct Thread {
    current: Arc<Current>,
    /// The pipeline taken from `current`, with its generation; behind an `Rc`, so a query holding it touches no
    /// count shared with other threads.
    #[expect(
        clippy::redundant_allocation,
        reason = "an `Arc` count is shared with every thread, an `Rc` one not"
    )]
    pipeline: RefCell<(u64, Rc<Arc<Pipeline>>)>,
    client: Client,
    upstream: Slots,
    connections: Slots,
    /// The buffer TCP replies and replies after upstream are made in, of a message's largest size (D63): making
    /// one never waits, so one buffer serves every task, borrowed only while a reply is made and copied out.
    scratch: RefCell<Box<[u8]>>,
}

impl Thread {
    /// The state of a thread serving the pipeline of `current`, with room for `upstream_queries`, upstream servers
    /// over TLS and QUIC checked against `trust`.
    fn new(current: Arc<Current>, upstream_queries: usize, trust: Trust) -> Self {
        Self {
            pipeline: RefCell::new((current.generation(), Rc::new(current.get()))),
            current,
            client: Client::new().trusting(trust),
            upstream: Slots::new(upstream_queries),
            connections: Slots::new(TCP_CONNECTIONS),
            scratch: RefCell::new(vec![0; MAX_MESSAGE_LEN].into_boxed_slice()),
        }
    }

    /// The pipeline for a query: the one taken last, unless a reload replaced it since.
    #[expect(
        clippy::redundant_allocation,
        reason = "an `Arc` count is shared with every thread, an `Rc` one not"
    )]
    fn pipeline(&self) -> Rc<Arc<Pipeline>> {
        let mut held = self.pipeline.borrow_mut();
        let generation = self.current.generation();
        if held.0 != generation {
            *held = (generation, Rc::new(self.current.get()));
        }
        Rc::clone(&held.1)
    }
}

/// A count of things in use, up to a limit; a [`Slot`] gives its place back when dropped.
struct Slots {
    used: Rc<Cell<usize>>,
    max: usize,
}

impl Slots {
    fn new(max: usize) -> Self {
        Self {
            used: Rc::default(),
            max,
        }
    }

    /// A slot, `None` when all are taken.
    fn take(&self) -> Option<Slot> {
        let used = self.used.get();
        (used < self.max).then(|| {
            self.used.set(used + 1);
            Slot(Rc::clone(&self.used))
        })
    }
}

/// A place taken in [`Slots`].
struct Slot(Rc<Cell<usize>>);

impl Drop for Slot {
    fn drop(&mut self) {
        self.0.set(self.0.get() - 1);
    }
}

/// The runtime of a serving thread, with [`UDP_BUFFERS`] buffers of [`UDP_BUFFER_LEN`] bytes for UDP queries.
///
/// # Errors
///
/// A runtime the OS refuses.
pub(crate) fn runtime() -> io::Result<Runtime> {
    let mut proactor = ProactorBuilder::new();
    proactor
        .buffer_pool_size(UDP_BUFFERS)
        .buffer_pool_buffer_len(UDP_BUFFER_LEN)
        // Completion work runs when the thread enters the kernel, not as a signal interrupting it (D51).
        .coop_taskrun(true)
        .taskrun_flag(true);
    Runtime::builder().with_proactor(proactor).build()
}

/// Answers on `sockets` with the pipeline of `current`, upstream servers over TLS and QUIC checked against `trust`,
/// presenting `presented` over TLS and QUIC, until the end of the process.
///
/// # Errors
///
/// A socket the runtime cannot take, no certificate for a TLS or QUIC socket, or a task answering on one ended:
/// it panicked.
pub(crate) async fn serve(
    sockets: Sockets,
    current: Arc<Current>,
    trust: Trust,
    presented: Option<Arc<Presented>>,
) -> io::Result<()> {
    let thread = Rc::new(Thread::new(current, UPSTREAM_QUERIES, trust));
    let certificate = || {
        presented
            .clone()
            .ok_or_else(|| io::Error::other("no certificate to present"))
    };
    let mut tasks = Vec::new();
    for bound in sockets {
        let task = match bound {
            Bound::Plain(udp_socket, tcp_listener) => {
                let socket = UdpSocket::from_std(udp_socket.into())?;
                tasks.push(spawn(udp(socket, Rc::clone(&thread))));
                let listener = TcpListener::from_std(tcp_listener.into())?;
                spawn(tcp(listener, None, Rc::clone(&thread)))
            }
            Bound::Tls(tcp_listener) => {
                let acceptor = tls::acceptor(certificate()?).map_err(io::Error::other)?;
                let listener = TcpListener::from_std(tcp_listener.into())?;
                spawn(tcp(listener, Some(acceptor), Rc::clone(&thread)))
            }
            Bound::Quic(udp_socket) => {
                let config = tls::quic_server_config(certificate()?).map_err(io::Error::other)?;
                let endpoint = endpoint(udp_socket, config, 0)?;
                spawn(quic(endpoint, Service::Quic, Rc::clone(&thread)))
            }
            Bound::Https(udp_socket, path) => {
                let config = tls::h3_server_config(certificate()?).map_err(io::Error::other)?;
                let endpoint = endpoint(udp_socket, config, H3_UNI_STREAMS)?;
                spawn(quic(endpoint, Service::Https(path), Rc::clone(&thread)))
            }
        };
        tasks.push(task);
    }
    first_end(tasks).await
}

/// Waits for the first of `tasks` to end, never when there are none. They never end but by a panic, which the
/// runtime catches and would otherwise keep silent: the thread then fails, and the process.
///
/// # Errors
///
/// Always, once a task ended.
async fn first_end(tasks: Vec<JoinHandle<()>>) -> io::Result<()> {
    if tasks.is_empty() {
        return std::future::pending().await;
    }
    match select_all(tasks).await.0 {
        Ok(()) => Err(io::Error::other("a serving task ended")),
        Err(error) => Err(error.into()),
    }
}

/// Answers the queries of one UDP socket with [`UDP_RECEIVES`] tasks, from one stream of datagrams.
async fn udp(socket: UdpSocket, thread: Rc<Thread>) {
    let socket = Rc::new(socket);
    let datagrams = pin!(socket.recv_from_multi());
    let datagrams = Mutex::new(datagrams);
    let tasks = (0..UDP_RECEIVES).map(|_| udp_queries(&socket, &datagrams, &thread));
    join_all(tasks).await;
}

/// Answers queries from `datagrams`, one after the other; the lock passes the stream to the next task once a
/// datagram is taken.
async fn udp_queries(
    socket: &Rc<UdpSocket>,
    datagrams: &Mutex<impl Stream<Item = io::Result<RecvFromMultiResult>> + Unpin>,
    thread: &Rc<Thread>,
) {
    let mut out = vec![0; usize::from(DEFAULT_UDP_PAYLOAD)];
    let mut failing = false;
    loop {
        // An empty datagram ends a stream for a moment: the next poll receives again.
        let datagram = match datagrams.lock().await.next().await {
            Some(Ok(datagram)) => datagram,
            Some(Err(error)) => {
                tracing::debug!(%error, "UDP receive");
                // The lock is held: the socket's other tasks pause too.
                if failing {
                    compio::time::sleep(ERROR_PAUSE).await;
                }
                failing = true;
                continue;
            }
            None => continue,
        };
        failing = false;
        let Some(peer) = datagram.addr().and_then(|addr| addr.as_socket()) else {
            continue;
        };
        let pipeline = thread.pipeline();
        let step = pipeline.query(datagram.data(), Transport::Udp, now(), &mut out);
        // The buffer goes back to the pool before the reply waits to be sent.
        drop(datagram);
        let upstream = match step {
            Step::Reply(len) => {
                out = send(socket, out, len, peer).await;
                continue;
            }
            Step::Drop => continue,
            Step::Upstream(upstream) => upstream,
            Step::Refresh(len, upstream) => {
                out = send(socket, out, len, peer).await;
                upstream
            }
        };
        let Some(slot) = thread.upstream.take() else {
            tracing::debug!(%peer, "too many upstream queries: dropped");
            continue;
        };
        let (socket, thread) = (Rc::clone(socket), Rc::clone(thread));
        spawn(async move {
            let deliver = async |reply: Vec<u8>| {
                let len = reply.len();
                send(&socket, reply, len, peer).await;
            };
            answer(&thread, &pipeline, upstream, Transport::Udp, deliver).await;
            drop(slot);
        })
        .detach();
    }
}

/// Sends the first `len` bytes of `out` to `peer`, and gives `out` back.
async fn send(socket: &UdpSocket, out: Vec<u8>, len: usize, peer: SocketAddr) -> Vec<u8> {
    let BufResult(sent, out) = socket.send_to(out.slice(..len), peer).await;
    if let Err(error) = sent {
        tracing::debug!(%error, %peer, "UDP send");
    }
    out.into_inner()
}

/// Accepts the connections of one TCP listener, up to [`TCP_CONNECTIONS`] at once, over TLS with `acceptor`
/// (RFC 7858): the handshake must end within [`TCP_IDLE`].
async fn tcp(listener: TcpListener, acceptor: Option<TlsAcceptor>, thread: Rc<Thread>) {
    loop {
        match listener.accept().await {
            Ok((stream, peer)) => {
                let Some(slot) = thread.connections.take() else {
                    tracing::debug!(%peer, "too many connections: closed");
                    continue;
                };
                let (acceptor, thread) = (acceptor.clone(), Rc::clone(&thread));
                spawn(async move {
                    // Queries are small and each waits for its answer: send replies without delay (RFC 7766 §10).
                    let _ = stream.set_nodelay(true);
                    let Some(acceptor) = acceptor else {
                        let (reader, writer) = stream.into_split();
                        connection(BufReader::new(reader), writer, Transport::Tcp, &thread).await;
                        drop(slot);
                        return;
                    };
                    match compio::time::timeout(TCP_IDLE, acceptor.accept(stream)).await {
                        Ok(Ok(secured)) => {
                            let (reader, writer) = Polled::halves(secured);
                            connection(reader, writer, Transport::Tls, &thread).await;
                        }
                        Ok(Err(error)) => tracing::debug!(%peer, %error, "TLS handshake failed"),
                        Err(_) => tracing::debug!(%peer, "TLS handshake timed out"),
                    }
                    drop(slot);
                })
                .detach();
            }
            Err(error) => {
                tracing::warn!(%error, "TCP accept");
                compio::time::sleep(ERROR_PAUSE).await;
            }
        }
    }
}

/// Answers the queries of one TCP connection (RFC 7766), its halves `reader` and `writer`, over `transport`, TCP
/// or TLS: read one after the other, each answered as soon as it can be, so replies may come in another order
/// (§6.2.1.1). Reading waits while [`TCP_PENDING`] queries are in flight or more than [`TCP_QUEUED`] bytes of
/// replies wait to be written, and stops after [`TCP_IDLE`] without a query, at the first error, or once the
/// writer gave up; the connection closes once the replies still waiting are written (§6.2.3).
async fn connection(
    mut reader: impl Inbound,
    writer: impl Outbound + 'static,
    transport: Transport,
    thread: &Rc<Thread>,
) {
    let (sender, queue) = flume::unbounded::<Vec<u8>>();
    let replies = Replies {
        sender,
        queued: Rc::default(),
    };
    // The writer tells the reader there is room again; a stale message only makes it check once more.
    let (room, wait_room) = flume::bounded::<()>(1);
    let writing = spawn(write(writer, queue, Rc::clone(&replies.queued), room));
    // A semaphore: a query in flight holds a place in the channel, given back when it is answered.
    let (pending, done) = flume::bounded::<()>(TCP_PENDING);
    'read: loop {
        while replies.queued.get() > TCP_QUEUED {
            if wait_room.recv_async().await.is_err() {
                break 'read;
            }
        }
        let Ok(Ok(query)) = compio::time::timeout(TCP_IDLE, reader.message()).await else {
            break;
        };
        let pipeline = thread.pipeline();
        let (upstream, slot) = match start(thread, &pipeline, &query, transport, |wire| {
            replies.push(wire)
        }) {
            Some(Started::Upstream(upstream, slot)) => (upstream, slot),
            Some(Started::Done) => continue,
            None => break,
        };
        if pending.send_async(()).await.is_err() {
            break;
        }
        let (replies, done, thread) = (replies.clone(), done.clone(), Rc::clone(thread));
        spawn(async move {
            let deliver = async |framed| {
                replies.queue(framed);
            };
            answer(&thread, &pipeline, upstream, transport, deliver).await;
            drop(slot);
            let _ = done.try_recv();
        })
        .detach();
    }
    drop(replies);
    let _ = writing.await;
}

/// Writes the replies of `queue`, counting down the bytes `queued` and telling `room` once they are
/// [`TCP_QUEUED`] or fewer. Ends when every sender is dropped, or a write fails, or the queue is not empty
/// [`TCP_WRITE`] after its first reply. The replies queued meanwhile go out together, up to a message's size: one
/// write for many.
async fn write(
    mut writer: impl Outbound,
    queue: flume::Receiver<Vec<u8>>,
    queued: Rc<Cell<usize>>,
    room: flume::Sender<()>,
) {
    let mut batch = Vec::new();
    while let Ok(first) = queue.recv_async().await {
        // The queue was empty: it must be again in time.
        let deadline = Instant::now() + TCP_WRITE;
        let mut next = Some(first);
        while let Some(framed) = next {
            batch.clear();
            batch.extend_from_slice(&framed);
            while batch.len() < MAX_MESSAGE_LEN
                && let Ok(framed) = queue.try_recv()
            {
                batch.extend_from_slice(&framed);
            }
            match compio::time::timeout_at(deadline, writer.write_all(batch)).await {
                Ok(BufResult(Ok(()), written)) => batch = written,
                _ => return,
            }
            queued.set(queued.get() - batch.len());
            if queued.get() <= TCP_QUEUED {
                let _ = room.try_send(());
            }
            next = queue.try_recv().ok();
        }
    }
    writer.close().await;
}

/// What became of a query after the pipeline's first step.
enum Started {
    /// Answered, or dropped.
    Done,
    /// To ask upstream, in a place of the thread's upstream queries.
    Upstream(Box<Upstream>, Slot),
}

/// Runs `query`, from a client over `transport`, through `pipeline`, handing `push` the reply made in the thread's
/// buffer, if any, before any wait; past the thread's upstream queries, the reply is SERVFAIL. `None` once `push`
/// returned `false`: the client is gone.
fn start(
    thread: &Thread,
    pipeline: &Pipeline,
    query: &[u8],
    transport: Transport,
    mut push: impl FnMut(&[u8]) -> bool,
) -> Option<Started> {
    let mut out = thread.scratch.borrow_mut();
    let upstream = match pipeline.query(query, transport, now(), &mut out) {
        Step::Reply(len) => return push(&out[..len]).then_some(Started::Done),
        Step::Drop => return Some(Started::Done),
        Step::Upstream(upstream) => upstream,
        Step::Refresh(len, upstream) => {
            if !push(&out[..len]) {
                return None;
            }
            upstream
        }
    };
    let Some(slot) = thread.upstream.take() else {
        tracing::debug!("too many upstream queries: SERVFAIL");
        return match pipeline.abandon(&upstream, &mut out) {
            Step::Reply(len) => push(&out[..len]).then_some(Started::Done),
            _ => Some(Started::Done),
        };
    };
    Some(Started::Upstream(upstream, slot))
}

/// The QUIC endpoint on `socket` with `config`: connections closed after [`TCP_IDLE`] without a packet (RFC 9250
/// §5.5.1), with [`TCP_PENDING`] queries in flight at most, and `uni_streams` the client may open: none for DNS over
/// QUIC (§4.2), [`H3_UNI_STREAMS`] for HTTP/3 (RFC 9114 §6.2).
fn endpoint(socket: Socket, mut config: ServerConfig, uni_streams: u32) -> io::Result<Endpoint> {
    let mut transport = TransportConfig::default();
    transport
        .max_idle_timeout(IdleTimeout::try_from(TCP_IDLE).ok())
        .max_concurrent_bidi_streams(
            u32::try_from(TCP_PENDING).map_or(VarInt::MAX, VarInt::from_u32),
        )
        .max_concurrent_uni_streams(VarInt::from_u32(uni_streams));
    config.transport_config(Arc::new(transport));
    let socket = UdpSocket::from_std(socket.into())?;
    Endpoint::new(socket, EndpointConfig::default(), Some(config), None)
}

/// What a QUIC endpoint serves.
enum Service {
    /// DNS over QUIC (RFC 9250).
    Quic,
    /// `DoH` over HTTP/3 at the path (RFC 8484, RFC 9114; D84).
    Https(Arc<str>),
}

/// Uni streams an HTTP/3 client may open: its control stream and QPACK's two (RFC 9114 §6.2), with room for
/// the reserved ones it may add (§6.2.3).
const H3_UNI_STREAMS: u32 = 16;

/// Accepts the connections of one QUIC endpoint, up to [`TCP_CONNECTIONS`] at once with those over TCP, and serves
/// each as `service` says.
async fn quic(endpoint: Endpoint, service: Service, thread: Rc<Thread>) {
    let service = Rc::new(service);
    while let Some(incoming) = endpoint.wait_incoming().await {
        let peer = incoming.remote_address();
        let Some(slot) = thread.connections.take() else {
            tracing::debug!(%peer, "too many connections: refused");
            incoming.refuse();
            continue;
        };
        let connecting = match incoming.accept() {
            Ok(connecting) => connecting,
            Err(error) => {
                tracing::debug!(%peer, %error, "QUIC connection refused");
                continue;
            }
        };
        let (service, thread) = (Rc::clone(&service), Rc::clone(&thread));
        spawn(async move {
            match connecting.await {
                Ok(connection) => match &*service {
                    Service::Quic => streams(&connection, &thread).await,
                    Service::Https(path) => requests(connection, path, peer, &thread).await,
                },
                Err(error) => tracing::debug!(%peer, %error, "QUIC handshake failed"),
            }
            drop(slot);
        })
        .detach();
    }
}

/// Answers the queries of one QUIC connection (RFC 9250 §4.2), each alone on a stream the client opened, as soon
/// as it can be; a stream not one query behind its length within [`TCP_IDLE`] is abandoned, and a query breaking
/// the protocol closes the connection with `DOQ_PROTOCOL_ERROR` (§4.3.3).
async fn streams(connection: &Connection, thread: &Rc<Thread>) {
    while let Ok((send, mut recv)) = connection.accept_bi().await {
        let (connection, thread) = (connection.clone(), Rc::clone(thread));
        spawn(async move {
            let read = compio::time::timeout(TCP_IDLE, read_stream(&mut recv)).await;
            match read {
                Ok(Ok(query)) if !breaks_doq(&query) => stream(&query, send, &thread).await,
                Ok(Ok(_) | Err(QuicError::Framing)) => {
                    connection.close(VarInt::from_u32(DOQ_PROTOCOL_ERROR), b"");
                }
                Ok(Err(_)) | Err(_) => {}
            }
        })
        .detach();
    }
}

/// Whether `query` breaks DNS over QUIC: a Message ID other than 0 (RFC 9250 §4.2.1) or an edns-tcp-keepalive option
/// (§5.5.2). A query that does not read goes on, to be answered FORMERR.
fn breaks_doq(query: &[u8]) -> bool {
    Query::read(query).is_ok_and(|query| {
        query.header().id != 0
            || query.edns().is_some_and(|edns| {
                edns.options()
                    .any(|option| option.code() == OptionCode::KEEPALIVE)
            })
    })
}

/// Answers `query` on its stream `send`, then finishes it: one reply, the first made.
async fn stream(query: &[u8], send: SendStream, thread: &Thread) {
    let pipeline = thread.pipeline();
    let mut first = None;
    let started = start(thread, &pipeline, query, Transport::Quic, |wire| {
        first = frame(wire);
        true
    });
    let mut send = Some(send);
    if let Some(framed) = first {
        respond(&mut send, framed).await;
    }
    if let Some(Started::Upstream(upstream, slot)) = started {
        let deliver = async |framed| respond(&mut send, framed).await;
        answer(thread, &pipeline, upstream, Transport::Quic, deliver).await;
        drop(slot);
    }
}

/// Answers the requests of one HTTP/3 connection (RFC 9114 §4), each alone on a stream the client opened, as
/// soon as it can be: the HTTP/3 setup and each request's reading must end within [`TCP_IDLE`]. Requests go through
/// the pipeline as any query; the client is `peer`.
async fn requests(connection: Connection, path: &Arc<str>, peer: SocketAddr, thread: &Rc<Thread>) {
    let mut requests = match compio::time::timeout(TCP_IDLE, Requests::new(connection)).await {
        Ok(Ok(requests)) => requests,
        Ok(Err(error)) => return tracing::debug!(%peer, %error, "HTTP/3 setup failed"),
        Err(_) => return tracing::debug!(%peer, "HTTP/3 setup timed out"),
    };
    loop {
        match requests.accept().await {
            Ok(Some(pending)) => {
                let (path, thread) = (Arc::clone(path), Rc::clone(thread));
                spawn(async move { request(pending, &path, peer, &thread).await }).detach();
            }
            Ok(None) => return,
            Err(error) => return tracing::debug!(%peer, %error, "HTTP/3 connection ended"),
        }
    }
}

/// Answers one request: what [`Pending::read`] makes of it if it is no query, else the pipeline's reply, or 400 when
/// the pipeline drops it, a query too short to be a DNS message (RFC 8484 §4.2.1).
async fn request(pending: Pending, path: &str, peer: SocketAddr, thread: &Thread) {
    let exchange = match compio::time::timeout(TCP_IDLE, pending.read(path)).await {
        Ok(Ok(exchange)) => exchange,
        Ok(Err(error)) => return tracing::debug!(%peer, %error, "HTTP/3 request failed"),
        Err(_) => return tracing::debug!(%peer, "HTTP/3 request timed out"),
    };
    let pipeline = thread.pipeline();
    let mut first = None;
    let started = match exchange.query() {
        Ok(query) => start(thread, &pipeline, query, Transport::Https, |wire| {
            first = Some(wire.to_vec());
            true
        }),
        Err(status) => return reject(exchange, status, peer).await,
    };
    let mut exchange = Some(exchange);
    if let Some(wire) = first {
        respond_http(&mut exchange, wire, peer).await;
    }
    if let Some(Started::Upstream(upstream, slot)) = started {
        let deliver = async |wire| respond_http(&mut exchange, wire, peer).await;
        answer(thread, &pipeline, upstream, Transport::Https, deliver).await;
        drop(slot);
    }
    if let Some(exchange) = exchange {
        reject(exchange, StatusCode::BAD_REQUEST, peer).await;
    }
}

/// Answers 200 with `wire` on `exchange`, unless it was answered already.
async fn respond_http(exchange: &mut Option<Exchange>, wire: Vec<u8>, peer: SocketAddr) {
    if let Some(exchange) = exchange.take() {
        count_doh(exchange.method(), StatusCode::OK);
        if let Err(error) = exchange.respond(wire).await {
            tracing::debug!(%peer, %error, "HTTP/3 response failed");
        }
    }
}

/// Answers `status` without a message.
async fn reject(exchange: Exchange, status: StatusCode, peer: SocketAddr) {
    count_doh(exchange.method(), status);
    if let Err(error) = exchange.reject(status).await {
        tracing::debug!(%peer, %error, "HTTP/3 response failed");
    }
}

/// Counts a `DoH` request answered with `status` (D84): the statuses [`Pending::read`] and this module answer with
/// and the methods `DoH` uses are labelled, the others "other", so the labels stay few.
fn count_doh(method: Option<Method>, status: StatusCode) {
    let method = match method {
        Some(Method::Get) => "get",
        Some(Method::Post) => "post",
        None => "other",
    };
    let status = match status {
        StatusCode::OK => "200",
        StatusCode::BAD_REQUEST => "400",
        StatusCode::NOT_FOUND => "404",
        StatusCode::METHOD_NOT_ALLOWED => "405",
        StatusCode::PAYLOAD_TOO_LARGE => "413",
        StatusCode::UNSUPPORTED_MEDIA_TYPE => "415",
        _ => "other",
    };
    metrics::counter!(DOH_QUERIES, "method" => method, "status" => status).increment(1);
}

const DOH_QUERIES: &str = "dedensd_doh_queries_total";

/// Writes `framed` on `send` and finishes it, unless it was answered already.
async fn respond(send: &mut Option<SendStream>, framed: Vec<u8>) {
    if let Some(mut stream) = send.take()
        && let BufResult(Ok(()), _) = stream.write_all(framed).await
    {
        let _ = stream.finish();
    }
}

/// The replies of a TCP connection waiting for its writer, and their bytes.
#[derive(Clone)]
struct Replies {
    sender: flume::Sender<Vec<u8>>,
    /// Bytes queued and not yet written, counted down by the writer.
    queued: Rc<Cell<usize>>,
}

impl Replies {
    /// Queues `wire` behind its length for the writer, without waiting: the reader bounds the bytes queued. `false`
    /// once the writer gave up.
    fn push(&self, wire: &[u8]) -> bool {
        // A reply fits 65535 bytes.
        frame(wire).is_none_or(|framed| self.queue(framed))
    }

    /// Queues `framed`, a reply behind its length, as [`Replies::push`] does.
    fn queue(&self, framed: Vec<u8>) -> bool {
        let len = framed.len();
        let sent = self.sender.send(framed).is_ok();
        if sent {
            self.queued.set(self.queued.get() + len);
        }
        sent
    }
}

/// Asks the upstream servers for `upstream`, from `pipeline`, in turn, each over its transport ([`target`]), with
/// the forward stage's timeout and tries (D42), and hands `deliver` the replies to send, made in the thread's buffer and copied out
/// ([`copy_out`]): expired data when the client response timer runs out first, resolution going on to refresh the
/// cache (RFC 8767 §5), then the response's unless that went out; none after a prefetch.
async fn answer(
    thread: &Thread,
    pipeline: &Pipeline,
    mut upstream: Box<Upstream>,
    transport: Transport,
    mut deliver: impl AsyncFnMut(Vec<u8>),
) {
    let mut options = Options::default();
    (options.timeout, options.tries) = upstream.patience();
    // A response without EDNS would be stored for clients asking for DNSSEC records (RFC 3225).
    options.edns_fallback = false;
    let mut stale_at = upstream.stale_after().map(|after| Instant::now() + after);
    loop {
        // A copy: the stale reply below takes `upstream`.
        let server = upstream.server().clone();
        let target;
        (target, options.transport) = self::target(&server, transport);
        let response = 'ask: {
            let mut exchange = pin!(thread.client.exchange(upstream.request(), target, &options));
            if let Some(at) = stale_at {
                // A reborrow: the exchange goes on after the timer.
                if let Ok(response) = compio::time::timeout_at(at, exchange.as_mut()).await {
                    break 'ask response;
                }
                stale_at = None;
                let stale = {
                    let mut out = thread.scratch.borrow_mut();
                    let len = pipeline.stale(&mut upstream, now(), &mut out);
                    len.and_then(|len| copy_out(&out[..len], transport))
                };
                if let Some(reply) = stale {
                    deliver(reply).await;
                }
            }
            exchange.await
        };
        let (reply, next) = {
            let mut out = thread.scratch.borrow_mut();
            let step = match &response {
                Ok(response) => pipeline.receive(upstream, Some(&response.wire), now(), &mut out),
                Err(error) if error.is_local() => {
                    tracing::warn!(%error, %server, "upstream query not sent");
                    pipeline.abandon(&upstream, &mut out)
                }
                Err(error) => {
                    tracing::debug!(%error, %server, "upstream");
                    pipeline.receive(upstream, None, now(), &mut out)
                }
            };
            match step {
                Step::Reply(len) | Step::Refresh(len, _) => {
                    (copy_out(&out[..len], transport), None)
                }
                Step::Drop => (None, None),
                Step::Upstream(next) => (None, Some(next)),
            }
        };
        if let Some(reply) = reply {
            deliver(reply).await;
        }
        let Some(next) = next else {
            return;
        };
        upstream = next;
    }
}

/// The server to ask for `server`, and the transport: its own, else UDP for a client over UDP and TCP for a client
/// over a connection (D65); the URI template of an HTTPS one is at its path (D84). A name and a path were checked when
/// the configuration was read.
fn target(server: &dedens_server::Server, client: Transport) -> (Server, Transport) {
    let (transport, name) = match &server.via {
        Via::Plain if client == Transport::Udp => (Transport::Udp, None),
        Via::Plain => (Transport::Tcp, None),
        Via::Tls(name) => (Transport::Tls, name.as_deref()),
        Via::Quic(name) => (Transport::Quic, name.as_deref()),
        Via::Https { name, .. } => (Transport::Https, name.as_deref()),
    };
    let name = name
        .and_then(|name| ServerName::try_from(name).ok())
        .map(|name| name.to_owned());
    let mut target = Server {
        addr: server.addr,
        name,
        doh: None,
    };
    if let Via::Https { path, .. } = &server.via {
        target.doh = target.template_at(path).ok();
    }
    (target, transport)
}

/// The reply `wire`, made in the thread's buffer, copied out to be sent over `transport`: behind its length but
/// over UDP and HTTPS. Only its bytes leave the buffer, never those of an earlier reply.
fn copy_out(wire: &[u8], transport: Transport) -> Option<Vec<u8>> {
    if matches!(transport, Transport::Udp | Transport::Https) {
        Some(wire.to_vec())
    } else {
        frame(wire)
    }
}

/// Seconds since the first call, the clock of the cache (D43).
fn now() -> u32 {
    static START: LazyLock<Instant> = LazyLock::new(Instant::now);
    u32::try_from(START.elapsed().as_secs()).unwrap_or(u32::MAX)
}

#[cfg(test)]
mod tests {
    use std::cell::RefCell;
    use std::rc::Rc;
    use std::sync::Arc;
    use std::time::Duration;

    use compio::BufResult;
    use compio::io::{AsyncWriteExt, BufReader};
    use compio::net::{TcpListener, TcpStream};
    use compio::runtime::{Runtime, spawn};
    use dedens_net::tcp::{frame, read_message};
    use dedens_net::tls::Trust;
    use dedens_proto::edns::EdnsOption;
    use dedens_proto::{Message, Question, Rcode, RecordType};
    use dedens_server::{Pipeline, Transport};

    use super::{Replies, Slots, TCP_QUEUED, Thread, breaks_doq, connection, first_end, write};
    use crate::reload::Current;

    #[test]
    fn a_serving_task_that_panics_fails_the_thread() {
        let runtime = Runtime::new().expect("a runtime");
        let ended = runtime.block_on(async {
            first_end(vec![
                spawn(std::future::pending()),
                spawn(async { panic!("a bug") }),
            ])
            .await
        });
        assert!(ended.is_err());
    }

    /// A TCP query the thread has no room to ask upstream gets SERVFAIL, on a connection that stays open.
    #[test]
    fn a_tcp_query_without_upstream_room_gets_servfail() {
        let text = "listen: ['127.0.0.1:53']\npipeline: [up]\nstages:\n  up:\n    type: forward\n    servers: ['192.0.2.1']\n";
        let config = crate::config::read(text, |_| None, &Pipeline::default()).expect("read");
        let thread = Rc::new(Thread::new(
            Arc::new(Current::new(config.pipeline)),
            0,
            Trust::default(),
        ));
        let name = "example.com.".parse().expect("a name");
        let query = Message::query(1, Question::new(name, RecordType::A))
            .to_vec()
            .expect("a query fits");
        let framed = frame(&query).expect("framed");
        let runtime = Runtime::new().expect("a runtime");
        runtime.block_on(async {
            let listener = TcpListener::bind("127.0.0.1:0").await.expect("bound");
            let addr = listener.local_addr().expect("its address");
            let serving = spawn(async move {
                let (stream, _) = listener.accept().await.expect("accepted");
                let (reader, writer) = stream.into_split();
                connection(BufReader::new(reader), writer, Transport::Tcp, &thread).await;
            });
            let mut client = TcpStream::connect(addr).await.expect("connected");
            for _ in 0..2 {
                let compio::BufResult(sent, _) = client.write_all(framed.clone()).await;
                sent.expect("sent");
                let reply = read_message(&mut client).await.expect("a reply");
                let reply = Message::decode(&reply).expect("decodes").message;
                assert_eq!(reply.rcode(), Rcode::SERVFAIL);
            }
            drop(client);
            let _ = serving.await;
        });
    }

    /// RFC 9250 \u00a74.3.3: a Message ID other than 0 and an edns-tcp-keepalive option break DNS over QUIC.
    #[test]
    fn doq_queries_have_id_0_and_no_keepalive() {
        let name: dedens_proto::Name<'static> = "example.com.".parse().expect("a name");
        let query = |id, keepalive| {
            let mut query = Message::query(id, Question::new(name.clone(), RecordType::A));
            if keepalive && let Some(edns) = &mut query.edns {
                edns.options.push(EdnsOption::Keepalive(None));
            }
            query.to_vec().expect("a query fits")
        };
        assert!(!breaks_doq(&query(0, false)));
        assert!(breaks_doq(&query(1, false)));
        assert!(breaks_doq(&query(0, true)));
        assert!(!breaks_doq(b"not a query"));
    }

    /// A writer that writes once let through by `gate`, recording each batch's length.
    struct Gated {
        gate: flume::Receiver<()>,
        batches: Rc<RefCell<Vec<usize>>>,
    }

    impl dedens_net::tcp::Outbound for Gated {
        async fn write_all(&mut self, batch: Vec<u8>) -> BufResult<(), Vec<u8>> {
            let _ = self.gate.recv_async().await;
            self.batches.borrow_mut().push(batch.len());
            BufResult(Ok(()), batch)
        }

        async fn close(&mut self) {}
    }

    /// D47: replies queued count in bytes; the reader hears of room once they are 128 KiB or fewer, and replies
    /// queued meanwhile go out together, until a batch reaches a message's size.
    #[test]
    fn queued_replies_are_counted_in_bytes_and_written_together() {
        let runtime = Runtime::new().expect("a runtime");
        runtime.block_on(async {
            let (sender, queue) = flume::unbounded();
            let replies = Replies {
                sender,
                queued: Rc::default(),
            };
            let (room, wait_room) = flume::bounded(1);
            let (open, gate) = flume::unbounded();
            let batches = Rc::default();
            let writer = Gated {
                gate,
                batches: Rc::clone(&batches),
            };
            let writing = spawn(write(writer, queue, Rc::clone(&replies.queued), room));
            let reply = vec![0; 1000];
            for _ in 0..200 {
                assert!(replies.push(&reply));
            }
            let total = 200 * 1002;
            assert_eq!(replies.queued.get(), total);
            // A batch takes replies until it holds 65535 bytes, 66 of them: the first write leaves more than
            // 128 KiB queued, the second not.
            open.send(()).expect("open");
            compio::time::sleep(Duration::from_millis(50)).await;
            assert!(wait_room.is_empty());
            assert_eq!(replies.queued.get(), total - 66 * 1002);
            open.send(()).expect("open");
            wait_room.recv_async().await.expect("room");
            assert!(replies.queued.get() <= TCP_QUEUED);
            for _ in 0..2 {
                open.send(()).expect("open");
            }
            drop(replies);
            writing.await.expect("the writer ends");
            assert_eq!(
                *batches.borrow(),
                [66 * 1002, 66 * 1002, 66 * 1002, 2 * 1002]
            );
        });
    }

    #[test]
    fn slots_are_given_back_when_dropped() {
        let slots = Slots::new(2);
        let (a, b) = (slots.take(), slots.take());
        assert!(a.is_some() && b.is_some());
        assert!(slots.take().is_none());
        drop(a);
        assert!(slots.take().is_some());
    }
}
