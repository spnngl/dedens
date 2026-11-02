//! The sockets of one thread and the tasks answering on them (D42): a task per UDP socket and per TCP listener,
//! one per TCP connection, and one per query that waits for an upstream server. Replies the pipeline builds at
//! once go out from the socket's own task; the rest are asked upstream with the thread's `dedens_net` client.
//! Each thread bounds its upstream queries and TCP connections, each connection its queries in flight, the bytes
//! of its replies waiting to be written and the time they take to write (D47). A task that panics ends alone, and
//! a listener's loop that ends starts again (D121).

use std::cell::{Cell, RefCell};
use std::future::poll_fn;
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::num::NonZero;
use std::pin::pin;
use std::rc::Rc;
use std::sync::{Arc, LazyLock, mpsc};
use std::task::Poll;
use std::time::{Duration, Instant};

use anyhow::Context;
use compio::BufResult;
use compio::buf::{IntoInner, IoBuf};
use compio::driver::op::RecvFromMultiResult;
use compio::driver::{DriverType, ProactorBuilder};
use compio::io::{AsyncWriteExt, BufReader};
use compio::net::{TcpListener, UdpSocket};
use compio::quic::{
    Connection, Endpoint, EndpointConfig, IdleTimeout, SendStream, ServerConfig, TransportConfig,
    VarInt,
};
use compio::runtime::{JoinHandle, Runtime, spawn};
use compio::rustls::pki_types::ServerName;
use compio::tls::TlsAcceptor;
use dedens_net::client::{Client, ClientError, Server};
use dedens_net::doh::Method;
use dedens_net::exchange::{Options, Response};
use dedens_net::https::{Exchange, HttpsError, Pending, Requests};
#[cfg(feature = "odoh")]
use dedens_net::odoh::proxy::{Destination, ProxyError, Route, failure, rejection, route};
#[cfg(feature = "odoh")]
use dedens_net::odoh::{Kind, MAX_BODY};
use dedens_net::quic::{
    DOQ_PROTOCOL_ERROR, QuicError, RECEIVE_WINDOW, STREAM_RECEIVE_WINDOW,
    read_message as read_stream,
};
use dedens_net::tcp::{Inbound, Outbound, Polled, frame};
use dedens_net::tls::{self, Presented, Trust};
#[cfg(feature = "odoh")]
use dedens_odoh::ResponseContext;
use dedens_proto::edns::{DEFAULT_UDP_PAYLOAD, OptionCode};
use dedens_proto::wire::MAX_MESSAGE_LEN;
use dedens_proto::{Message, Query};
use dedens_server::{Pipeline, Step, Transport, Upstream, Via};
use futures_util::future::{join_all, select_all};
use futures_util::lock::Mutex;
use futures_util::{Stream, StreamExt};
use http::StatusCode;
use socket2::{Domain, Socket, Type};

use crate::config::Listen;
use crate::flights::{Flight, Flights, Key, Lead};
use crate::h3_budget::{Budget, Connections};
use crate::isolate::{BACKOFF, Backoff, Listener, Origin, supervise};
#[cfg(feature = "odoh")]
use crate::odoh::proxy::{Forwarder, Proxy};
#[cfg(feature = "odoh")]
use crate::odoh::{self, Target};
use crate::reload::Current;

/// How long a TCP connection stays open without a query (RFC 7766 §6.2.3).
pub(crate) const TCP_IDLE: Duration = Duration::from_secs(10);

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

/// Times a UDP task yields, one after the other, when no buffer is free, before it waits [`BUSY_PAUSE`] between tries.
const BUSY_YIELDS: u8 = 4;

/// How long a UDP task waits between tries once yielding has not freed a buffer: short, as a datagram waits in the
/// socket meanwhile, but long enough that a pool kept empty by another socket costs no busy loop.
const BUSY_PAUSE: Duration = Duration::from_millis(1);

#[cfg(feature = "doc")]
mod coap;

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
    /// A UDP socket for CoAP, serving `DoC` at the path (D81).
    #[cfg(feature = "doc")]
    Coap(Socket, Arc<str>),
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
            #[cfg(feature = "doc")]
            Listen::Coap(addr, path) => {
                udp(*addr).map(|socket| Bound::Coap(socket, Arc::clone(path)))
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
    /// A message each time a reload replaced the pipeline, for [`follow`].
    reloads: flume::Receiver<()>,
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
    /// The HTTP/3 connections whose bytes are counted (D119).
    h3: Rc<Connections>,
    /// The buffer TCP replies and replies after upstream are made in, of a message's largest size (D63): making
    /// one never waits, so one buffer serves every task, borrowed only while a reply is made and copied out.
    scratch: RefCell<Box<[u8]>>,
    /// The Oblivious `DoH` target the HTTP/3 listeners serve, if any (D79).
    #[cfg(feature = "odoh")]
    odoh: Option<Arc<Target>>,
    /// What the Oblivious `DoH` proxy forwards with: connections, checked addresses and a limit of its own (D94).
    #[cfg(feature = "odoh")]
    forwarder: Forwarder,
}

impl Thread {
    /// The state of a thread serving the pipeline of `current`, with room for `upstream_queries`, upstream servers
    /// over TLS and QUIC checked against `trust`.
    fn new(current: Arc<Current>, upstream_queries: usize, trust: Trust) -> Self {
        let (reloads, generation, pipeline) = current.follow();
        Self {
            pipeline: RefCell::new((generation, Rc::new(pipeline))),
            reloads,
            current,
            #[cfg(feature = "odoh")]
            forwarder: Forwarder::new(trust.clone()),
            client: Client::new().trusting(trust),
            upstream: Slots::new(upstream_queries),
            connections: Slots::new(TCP_CONNECTIONS),
            h3: Rc::default(),
            scratch: RefCell::new(vec![0; MAX_MESSAGE_LEN].into_boxed_slice()),
            #[cfg(feature = "odoh")]
            odoh: None,
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

/// Takes each new pipeline as a reload makes it, whether queries come or not: `thread` would hold the old one, with
/// its lists, until its next query, however long that takes (D107). Never ends.
async fn follow(thread: Rc<Thread>) {
    while thread.reloads.recv_async().await.is_ok() {
        drop(thread.pipeline());
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
/// presenting `presented` over TLS and QUIC and serving as the Oblivious `DoH` target (and proxy) `odoh` over
/// HTTP/3, until the end
/// of the process. `listening` gets the runtime's driver once the sockets are taken by the runtime: on macOS a
/// datagram that arrived before carries none of the control data `compio-quic` reads, and it panics (D89), so the
/// process announces itself only then, and with the driver, which falls back from `io_uring` to `poll` silently (D107).
///
/// # Errors
///
/// A socket the runtime cannot take, no certificate for a TLS or QUIC socket, or a task serving one ended: its
/// supervisor panicked (D121).
pub(crate) async fn serve(
    sockets: Sockets,
    current: Arc<Current>,
    trust: Trust,
    presented: Option<Arc<Presented>>,
    #[cfg(feature = "odoh")] odoh: Option<Arc<Target>>,
    listening: mpsc::Sender<DriverType>,
) -> io::Result<()> {
    #[cfg_attr(
        not(feature = "odoh"),
        expect(unused_mut, reason = "only Oblivious DoH sets a field")
    )]
    let mut thread = Thread::new(current, UPSTREAM_QUERIES, trust);
    #[cfg(feature = "odoh")]
    {
        thread.odoh = odoh;
    }
    let thread = Rc::new(thread);
    let certificate = || {
        presented
            .clone()
            .ok_or_else(|| io::Error::other("no certificate to present"))
    };
    let mut tasks = Vec::new();
    for bound in sockets {
        let task = match bound {
            Bound::Plain(udp_socket, tcp_listener) => {
                let name = Listener::new("udp", local(&udp_socket));
                let socket = Rc::new(UdpSocket::from_std(udp_socket.into())?);
                tasks.push(supervised(name, &thread, move |name, thread| {
                    udp(Rc::clone(&socket), name.clone(), Rc::clone(thread))
                }));
                tcp_task(&thread, tcp_listener, "tcp", None)?
            }
            Bound::Tls(tcp_listener) => {
                let acceptor = tls::acceptor(certificate()?).map_err(io::Error::other)?;
                tcp_task(&thread, tcp_listener, "tls", Some(acceptor))?
            }
            Bound::Quic(udp_socket) => {
                let config = tls::quic_server_config(certificate()?).map_err(io::Error::other)?;
                quic_task(&thread, "quic", udp_socket, config, 0, Service::Quic)?
            }
            Bound::Https(udp_socket, path) => {
                let config = tls::h3_server_config(certificate()?).map_err(io::Error::other)?;
                let service = Service::Https(path);
                quic_task(
                    &thread,
                    "https",
                    udp_socket,
                    config,
                    H3_UNI_STREAMS,
                    service,
                )?
            }
            #[cfg(feature = "doc")]
            Bound::Coap(udp_socket, path) => {
                let name = Listener::new("coap", local(&udp_socket));
                let socket = Rc::new(UdpSocket::from_std(udp_socket.into())?);
                let coap = Rc::new(coap::Coap::new(socket, &path));
                supervised(name, &thread, move |name, thread| {
                    coap::serve(Rc::clone(&coap), name.clone(), Rc::clone(thread))
                })
            }
        };
        tasks.push(task);
    }
    tasks.push(spawn(follow(Rc::clone(&thread))));
    // The receiver is gone only if another thread failed first.
    let _ = listening.send(Runtime::with_current(Runtime::driver_type));
    drop(listening);
    first_end(tasks).await
}

/// The address `socket` is bound to, if it says.
fn local(socket: &Socket) -> Option<SocketAddr> {
    socket.local_addr().ok()?.as_socket()
}

/// Spawns [`supervise`] for `listener`, with the loop `serving` makes of the thread each time it starts (D121).
fn supervised<F: Future<Output = ()> + 'static>(
    listener: Listener,
    thread: &Rc<Thread>,
    serving: impl FnMut(&Listener, &Rc<Thread>) -> F + 'static,
) -> JoinHandle<()> {
    supervised_with(BACKOFF, listener, thread, serving)
}

/// As [`supervised`], with the pauses `backoff`.
fn supervised_with<F: Future<Output = ()> + 'static>(
    backoff: Backoff,
    listener: Listener,
    thread: &Rc<Thread>,
    mut serving: impl FnMut(&Listener, &Rc<Thread>) -> F + 'static,
) -> JoinHandle<()> {
    let thread = Rc::clone(thread);
    spawn(async move {
        supervise(&listener, backoff, || serving(&listener, &thread)).await;
    })
}

/// Serves the TCP listener `tcp_listener`, over TLS with `acceptor` if any, as the listener `scheme`. A restarted
/// loop takes the same listener: a panic leaves it open.
fn tcp_task(
    thread: &Rc<Thread>,
    tcp_listener: Socket,
    scheme: &str,
    acceptor: Option<TlsAcceptor>,
) -> io::Result<JoinHandle<()>> {
    let name = Listener::new(scheme, local(&tcp_listener));
    let tcp_listener = Rc::new(TcpListener::from_std(tcp_listener.into())?);
    Ok(supervised(name, thread, move |name, thread| {
        let (tcp_listener, acceptor) = (Rc::clone(&tcp_listener), acceptor.clone());
        tcp(tcp_listener, acceptor, name.clone(), Rc::clone(thread))
    }))
}

/// Serves the QUIC endpoint on `udp_socket` as `service`, as the listener `scheme`. A restarted loop takes the same
/// endpoint: `wait_incoming` ends only once the endpoint is closed, which nothing here does, so the loop does not
/// end by itself, and a panic leaves the endpoint as it was.
fn quic_task(
    thread: &Rc<Thread>,
    scheme: &str,
    udp_socket: Socket,
    config: ServerConfig,
    uni_streams: u32,
    service: Service,
) -> io::Result<JoinHandle<()>> {
    let name = Listener::new(scheme, local(&udp_socket));
    let serving = endpoint(udp_socket, config, uni_streams)?;
    let service = Rc::new(service);
    Ok(supervised(name, thread, move |name, thread| {
        quic(
            serving.clone(),
            Rc::clone(&service),
            name.clone(),
            Rc::clone(thread),
        )
    }))
}

/// Waits for the first of `tasks`, which are not none, to end. They never end but by a panic of their own: the
/// supervisors catch the panics of their listeners, and the tasks of queries and connections end alone (D121). The
/// runtime would otherwise keep it silent: the thread then fails, and the process.
///
/// # Errors
///
/// Always, once a task ended.
async fn first_end(tasks: Vec<JoinHandle<()>>) -> io::Result<()> {
    match select_all(tasks).await.0 {
        Ok(()) => Err(io::Error::other("a serving task ended")),
        Err(error) => Err(error.into()),
    }
}

/// Answers the queries of one UDP socket with [`UDP_RECEIVES`] tasks, from one stream of datagrams.
async fn udp(socket: Rc<UdpSocket>, listener: Listener, thread: Rc<Thread>) {
    let datagrams = pin!(socket.recv_from_multi());
    let datagrams = Mutex::new(datagrams);
    let tasks = (0..UDP_RECEIVES).map(|_| udp_queries(&socket, &datagrams, &listener, &thread));
    join_all(tasks).await;
}

/// Receives that failed in a row on one task of a UDP socket, which decide how long it waits before the next (D107).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Receiving {
    /// The last one gave a datagram, or none has failed yet.
    Fine,
    /// The last one failed, of an error other than `Busy`.
    Failed,
    /// The last ones found no free buffer in the pool (`ENOBUFS`, `ResourceBusy`): this many.
    Busy(u8),
}

/// How long a task waits before receiving again.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Pause {
    None,
    /// Until the thread's other tasks and the driver have had a turn.
    Yield,
    Sleep(Duration),
}

impl Receiving {
    /// The pause after a receive that failed, `busy` if for a lack of free buffers. A first error of another kind
    /// is retried at once; a second in a row, as an error that repeats would spin, after [`ERROR_PAUSE`]. The
    /// pool's buffers (D49) are held by datagrams the kernel filled and the thread's streams have not yet been read,
    /// which the tasks free as they read them: a few yields let them, then [`BUSY_PAUSE`], since each retry on
    /// `io_uring` costs a submission the kernel refuses at once while the pool is empty.
    fn failed(&mut self, busy: bool) -> Pause {
        let (next, pause) = match (*self, busy) {
            (Self::Failed, false) => (Self::Failed, Pause::Sleep(ERROR_PAUSE)),
            (_, false) => (Self::Failed, Pause::None),
            (Self::Busy(tried), true) if tried >= BUSY_YIELDS => {
                (Self::Busy(tried), Pause::Sleep(BUSY_PAUSE))
            }
            (Self::Busy(tried), true) => (Self::Busy(tried + 1), Pause::Yield),
            (_, true) => (Self::Busy(1), Pause::Yield),
        };
        *self = next;
        pause
    }
}

/// Lets the thread's other tasks run, and the driver complete what it holds, before this one goes on: compio has no
/// such yield.
async fn yield_now() {
    let mut yielded = false;
    poll_fn(|cx| {
        if yielded {
            return Poll::Ready(());
        }
        yielded = true;
        cx.waker().wake_by_ref();
        Poll::Pending
    })
    .await;
}

/// Answers queries from `datagrams`, one after the other; the lock passes the stream to the next task once a
/// datagram is taken.
async fn udp_queries(
    socket: &Rc<UdpSocket>,
    datagrams: &Mutex<impl Stream<Item = io::Result<RecvFromMultiResult>> + Unpin>,
    listener: &Listener,
    thread: &Rc<Thread>,
) {
    let mut out = vec![0; usize::from(DEFAULT_UDP_PAYLOAD)];
    let mut receiving = Receiving::Fine;
    loop {
        // The lock is given back at the end of this statement, before any pause (D107).
        let next = datagrams.lock().await.next().await;
        // An empty datagram ends a stream for a moment: the next poll receives again.
        let datagram = match next {
            Some(Ok(datagram)) => datagram,
            Some(Err(error)) => {
                tracing::debug!(%error, "UDP receive");
                // Only this task pauses: the socket's other tasks go on receiving (D107).
                match receiving.failed(error.kind() == io::ErrorKind::ResourceBusy) {
                    Pause::None => {}
                    Pause::Yield => yield_now().await,
                    Pause::Sleep(pause) => compio::time::sleep(pause).await,
                }
                continue;
            }
            None => continue,
        };
        receiving = Receiving::Fine;
        let Some(peer) = datagram.addr().and_then(|addr| addr.as_socket()) else {
            continue;
        };
        let pipeline = thread.pipeline();
        // A panic anywhere in the datagram's turn costs this query, not the socket (D121).
        let stepped = listener
            .guard_async(peer, udp_step(socket, &pipeline, datagram, peer, &mut out))
            .await;
        if out.len() < usize::from(DEFAULT_UDP_PAYLOAD) {
            // The buffer was out for a send that panicked.
            out = vec![0; usize::from(DEFAULT_UDP_PAYLOAD)];
        }
        let Some(Some(upstream)) = stepped else {
            continue;
        };
        let Some(slot) = thread.upstream.take() else {
            tracing::debug!(%peer, "too many upstream queries: dropped");
            continue;
        };
        let (socket, thread) = (Rc::clone(socket), Rc::clone(thread));
        Origin::new(listener, peer).spawn(async move {
            let deliver = async |reply: Vec<u8>| {
                let len = reply.len();
                send(&socket, reply, len, peer).await;
            };
            answer(&thread, &pipeline, upstream, Transport::Udp, deliver).await;
            drop(slot);
        });
    }
}

/// The turn of one datagram: the pipeline's first step, the reply it makes sent, and the upstream query it leaves, if any.
/// The datagram's buffer goes back to the pool before the reply waits to be sent.
async fn udp_step(
    socket: &UdpSocket,
    pipeline: &Pipeline,
    datagram: RecvFromMultiResult,
    peer: SocketAddr,
    out: &mut Vec<u8>,
) -> Option<Box<Upstream>> {
    let step = pipeline.query(datagram.data(), Transport::Udp, peer.ip(), now(), out);
    drop(datagram);
    let (len, upstream) = match step {
        Step::Reply(len) => (Some(len), None),
        Step::Drop => (None, None),
        Step::Upstream(upstream) => (None, Some(upstream)),
        Step::Refresh(len, upstream) => (Some(len), Some(upstream)),
    };
    if let Some(len) = len {
        *out = send(socket, std::mem::take(out), len, peer).await;
    }
    upstream
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
async fn tcp(
    tcp_listener: Rc<TcpListener>,
    acceptor: Option<TlsAcceptor>,
    listener: Listener,
    thread: Rc<Thread>,
) {
    loop {
        match tcp_listener.accept().await {
            Ok((stream, peer)) => {
                // `action: drop` (D91): no slot, no handshake, no reply; `refuse` answers each query.
                if thread.pipeline().drops(peer.ip()) {
                    drop(stream);
                    continue;
                }
                let Some(slot) = thread.connections.take() else {
                    tracing::debug!(%peer, "too many connections: closed");
                    continue;
                };
                let (acceptor, thread) = (acceptor.clone(), Rc::clone(&thread));
                let origin = Origin::new(&listener, peer);
                origin.clone().spawn(async move {
                    // Queries are small and each waits for its answer: send replies without delay (RFC 7766 §10).
                    let _ = stream.set_nodelay(true);
                    let Some(acceptor) = acceptor else {
                        let (reader, writer) = stream.into_split();
                        connection(
                            BufReader::new(reader),
                            writer,
                            Transport::Tcp,
                            &origin,
                            &thread,
                        )
                        .await;
                        drop(slot);
                        return;
                    };
                    match compio::time::timeout(TCP_IDLE, acceptor.accept(stream)).await {
                        Ok(Ok(secured)) => {
                            let (reader, writer) = Polled::halves(secured);
                            connection(reader, writer, Transport::Tls, &origin, &thread).await;
                        }
                        Ok(Err(error)) => tracing::debug!(%peer, %error, "TLS handshake failed"),
                        Err(_) => tracing::debug!(%peer, "TLS handshake timed out"),
                    }
                    drop(slot);
                });
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
    origin: &Origin,
    thread: &Rc<Thread>,
) {
    let (sender, queue) = flume::unbounded::<Vec<u8>>();
    let replies = Replies {
        sender,
        queued: Rc::default(),
    };
    // The writer tells the reader there is room again; a stale message only makes it check once more.
    let (room, wait_room) = flume::bounded::<()>(1);
    let writing = origin.spawn_joinable(write(writer, queue, Rc::clone(&replies.queued), room));
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
        let from = origin.peer.ip();
        let (upstream, slot) = match start(thread, &pipeline, &query, transport, from, |wire| {
            replies.push(wire)
        }) {
            Some(Started::Upstream(upstream, slot)) => (upstream, slot),
            Some(Started::Done) => continue,
            None => break,
        };
        if pending.send_async(()).await.is_err() {
            break;
        }
        let (replies, place, thread) = (replies.clone(), Place(done.clone()), Rc::clone(thread));
        origin.clone().spawn(async move {
            let deliver = async |framed| {
                replies.queue(framed);
            };
            answer(&thread, &pipeline, upstream, transport, deliver).await;
            drop(slot);
            drop(place);
        });
    }
    drop(replies);
    let _ = writing.await;
}

/// A place of a connection's in-flight queries, given back when dropped: a query that panics gives it back too, else
/// 64 panics (D121) would leave the connection reading no more.
struct Place(flume::Receiver<()>);

impl Drop for Place {
    fn drop(&mut self) {
        let _ = self.0.try_recv();
    }
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

/// Runs `query`, from the client at `from` over `transport`, through `pipeline`, handing `push` the reply made in the thread's
/// buffer, if any, before any wait; past the thread's upstream queries, the reply is SERVFAIL. `None` once `push`
/// returned `false`: the client is gone.
fn start(
    thread: &Thread,
    pipeline: &Pipeline,
    query: &[u8],
    transport: Transport,
    from: IpAddr,
    mut push: impl FnMut(&[u8]) -> bool,
) -> Option<Started> {
    let mut out = thread.scratch.borrow_mut();
    let upstream = match pipeline.query(query, transport, from, now(), &mut out) {
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
/// QUIC (§4.2), [`H3_UNI_STREAMS`] for HTTP/3 (RFC 9114 §6.2). No DATAGRAM frame is read (D107): the receive buffer
/// is off, so quinn advertises no `max_datagram_frame_size` (RFC 9221 §3) and closes the connection on a DATAGRAM
/// frame from the peer. A peer may send [`RECEIVE_WINDOW`] bytes on the connection and [`STREAM_RECEIVE_WINDOW`] on a
/// stream before the reader returns credit (D119).
fn endpoint(socket: Socket, mut config: ServerConfig, uni_streams: u32) -> io::Result<Endpoint> {
    let mut transport = TransportConfig::default();
    transport
        .max_idle_timeout(IdleTimeout::try_from(TCP_IDLE).ok())
        .max_concurrent_bidi_streams(
            u32::try_from(TCP_PENDING).map_or(VarInt::MAX, VarInt::from_u32),
        )
        .max_concurrent_uni_streams(VarInt::from_u32(uni_streams))
        .receive_window(VarInt::from_u32(RECEIVE_WINDOW))
        .stream_receive_window(VarInt::from_u32(STREAM_RECEIVE_WINDOW))
        .datagram_receive_buffer_size(None);
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

/// `DOQ_EXCESSIVE_LOAD`: a stream given up because its client does not read the reply (RFC 9250 §4.3.2).
const DOQ_EXCESSIVE_LOAD: u32 = 0x4;

/// Uni streams an HTTP/3 client may open: its control stream and QPACK's two (RFC 9114 §6.2), with room for
/// the reserved ones it may add (§6.2.3).
const H3_UNI_STREAMS: u32 = 16;

/// Accepts the connections of one QUIC endpoint, up to [`TCP_CONNECTIONS`] at once with those over TCP, and serves
/// each as `service` says. A client whose address is not validated gets a Retry (RFC 9000 §8.1.2) and no state or
/// slot: a spoofed source never sees it, so forged Initials cannot fill the slots.
async fn quic(endpoint: Endpoint, service: Rc<Service>, listener: Listener, thread: Rc<Thread>) {
    while let Some(incoming) = endpoint.wait_incoming().await {
        let peer = incoming.remote_address();
        // `action: drop` (D91): not even a Retry, no slot, no handshake; `refuse` answers each query.
        if thread.pipeline().drops(peer.ip()) {
            incoming.ignore();
            continue;
        }
        if !incoming.remote_address_validated() {
            if let Err(error) = incoming.retry() {
                tracing::debug!(%peer, %error, "QUIC retry failed");
            }
            continue;
        }
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
        let origin = Origin::new(&listener, peer);
        origin.clone().spawn(async move {
            match connecting.await {
                Ok(connection) => match &*service {
                    Service::Quic => streams(&connection, &origin, &thread).await,
                    Service::Https(path) => {
                        let budget = thread.h3.register(connection.clone(), &origin);
                        requests(connection, path, &origin, &thread, &budget).await;
                    }
                },
                Err(error) => tracing::debug!(%peer, %error, "QUIC handshake failed"),
            }
            drop(slot);
        });
    }
}

/// Answers the queries of one QUIC connection (RFC 9250 §4.2), each alone on a stream the client opened, as soon
/// as it can be; a stream not one query behind its length within [`TCP_IDLE`] is abandoned, and a query breaking
/// the protocol closes the connection with `DOQ_PROTOCOL_ERROR` (§4.3.3).
async fn streams(connection: &Connection, origin: &Origin, thread: &Rc<Thread>) {
    while let Ok(Ok((send, mut recv))) =
        compio::time::timeout(TCP_IDLE, connection.accept_bi()).await
    {
        let (connection, thread) = (connection.clone(), Rc::clone(thread));
        let from = origin.peer.ip();
        origin.clone().spawn(async move {
            let read = compio::time::timeout(TCP_IDLE, read_stream(&mut recv)).await;
            match read {
                Ok(Ok(query)) if !breaks_doq(&query) => stream(&query, send, from, &thread).await,
                Ok(Ok(_) | Err(QuicError::Framing)) => {
                    connection.close(VarInt::from_u32(DOQ_PROTOCOL_ERROR), b"");
                }
                Ok(Err(_)) | Err(_) => {}
            }
        });
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
async fn stream(query: &[u8], send: SendStream, from: IpAddr, thread: &Thread) {
    let pipeline = thread.pipeline();
    let mut first = None;
    let started = start(thread, &pipeline, query, Transport::Quic, from, |wire| {
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
/// soon as it can be: the HTTP/3 setup and each request's reading must end within [`TCP_IDLE`], and a new request
/// must come within it too, as [`streams`] says. Requests go through the pipeline as any query; the client is `peer`.
/// Once the connection passed its byte budget (D119) it is sent `GOAWAY` at the next request, and ends when it is
/// quiet: nothing in flight, and no request taken for [`DRAIN_QUIET`].
async fn requests(
    connection: Connection,
    path: &Arc<str>,
    origin: &Origin,
    thread: &Rc<Thread>,
    budget: &Rc<Budget>,
) {
    let peer = origin.peer;
    let mut requests = match compio::time::timeout(TCP_IDLE, Requests::new(connection)).await {
        Ok(Ok(requests)) => requests,
        Ok(Err(error)) => return tracing::debug!(%peer, %error, "HTTP/3 setup failed"),
        Err(_) => return tracing::debug!(%peer, "HTTP/3 setup timed out"),
    };
    // Set at `GOAWAY`: the last time a request was taken, then.
    let mut going_away = None::<Instant>;
    loop {
        if budget.passed() && going_away.is_none() {
            if let Err(error) = requests.shutdown().await {
                return tracing::debug!(%peer, %error, "HTTP/3 GOAWAY failed");
            }
            going_away = Some(Instant::now());
        }
        let wait = if going_away.is_some() {
            DRAIN_TICK
        } else {
            TCP_IDLE
        };
        match compio::time::timeout(wait, requests.accept()).await {
            Ok(Ok(Some(pending))) => {
                let (path, thread, flight) = (Arc::clone(path), Rc::clone(thread), budget.fly());
                origin.clone().spawn(async move {
                    request(pending, &path, peer, &thread).await;
                    drop(flight);
                });
                if let Some(last) = &mut going_away {
                    *last = Instant::now();
                }
            }
            Ok(Err(error)) => return tracing::debug!(%peer, %error, "HTTP/3 connection ended"),
            Ok(Ok(None)) if going_away.is_none() => return,
            Err(_) if going_away.is_none() => {
                return tracing::debug!(%peer, "HTTP/3 connection idle");
            }
            // After `GOAWAY`, h3 ends `accept` once the client did too: a request it sent before it heard of
            // `GOAWAY` may still come, to be refused, and dropping `requests` closes the connection.
            Ok(Ok(None)) | Err(_) => {
                if budget.quiet() && going_away.is_some_and(|last| last.elapsed() >= DRAIN_QUIET) {
                    return tracing::debug!(%peer, "HTTP/3 connection drained");
                }
                compio::time::sleep(DRAIN_TICK).await;
            }
        }
    }
}

/// How long a connection sent `GOAWAY` waits for a request that was in flight, once its own are answered.
const DRAIN_QUIET: Duration = Duration::from_millis(100);

/// How often a connection sent `GOAWAY` looks for a request still to come, and for the end of its own.
const DRAIN_TICK: Duration = Duration::from_millis(10);

/// Answers one request: what [`Pending::read`] makes of it if it is no query, else the pipeline's reply, or 400 when
/// the pipeline drops it, a query too short to be a DNS message (RFC 8484 §4.2.1).
async fn request(pending: Pending, path: &str, peer: SocketAddr, thread: &Thread) {
    #[cfg(feature = "odoh")]
    if let Some(target) = &thread.odoh {
        return oblivious(pending, path, peer, thread, target).await;
    }
    let exchange = match compio::time::timeout(TCP_IDLE, pending.read(path)).await {
        Ok(Ok(exchange)) => exchange,
        Ok(Err(error)) => return tracing::debug!(%peer, %error, "HTTP/3 request failed"),
        Err(_) => return tracing::debug!(%peer, "HTTP/3 request timed out"),
    };
    let pipeline = thread.pipeline();
    let mut first = None;
    let started = match exchange.query() {
        Ok(query) => start(
            thread,
            &pipeline,
            query,
            Transport::Https,
            peer.ip(),
            |wire| {
                first = Some(wire.to_vec());
                true
            },
        ),
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

/// Answers one request at a listener that is an Oblivious `DoH` target too (D79): a POST of an encrypted query is
/// opened, asked of the pipeline as a query over [`Transport::Odoh`] and answered sealed; a GET of the configurations
/// is answered with them; any other request is `DoH`'s, as [`request`] answers it. When the target is a proxy too, a
/// request that names a target of its own is forwarded there (D94).
#[cfg(feature = "odoh")]
async fn oblivious(
    pending: Pending,
    path: &str,
    peer: SocketAddr,
    thread: &Thread,
    target: &Target,
) {
    let read = pending.read_with(MAX_BODY, |request, body| {
        route(request, body, path, target.proxy.as_ref())
    });
    let exchange = match compio::time::timeout(TCP_IDLE, read).await {
        Ok(Ok(exchange)) => exchange,
        Ok(Err(error)) => return tracing::debug!(%peer, %error, "HTTP/3 request failed"),
        Err(_) => return tracing::debug!(%peer, "HTTP/3 request timed out"),
    };
    let (transport, mut context, query) = match (exchange.kind(), exchange.query()) {
        // Not `DoH` requests: not counted (D84).
        (Route::Target(Kind::Configs), Err(status)) => {
            sent(exchange.reject(status), peer).await;
            return;
        }
        (Route::Malformed(status), _) => {
            let response = rejection(*status);
            return proxied(exchange, response, peer).await;
        }
        (_, Err(status)) => return reject(exchange, status, peer).await,
        (Route::Target(Kind::Configs), Ok(_)) => {
            sent(exchange.respond_with(target.configs()), peer).await;
            return;
        }
        (Route::Proxy(proxy, destination), Ok(body)) => {
            // A client the access lists deny is served no forward, whatever the action (D91, D94).
            let response = if thread.pipeline().denies(peer.ip()) {
                failure(StatusCode::FORBIDDEN, ProxyError::ClientDenied)
            } else {
                forward(proxy, destination, body, thread).await
            };
            return proxied(exchange, response, peer).await;
        }
        (Route::Target(Kind::Oblivious), Ok(body)) => {
            // The target opens it only for a client with budget left, the opening being work an unauthenticated
            // client makes it do; a source on the rate limit's exempt list pays no network unit (D117, D113).
            let exempt = thread
                .pipeline()
                .rate_limit()
                .is_some_and(|limit| limit.exempts(peer.ip()));
            match target.open(peer.ip(), now(), exempt, body) {
                Ok((query, context)) => (Transport::Odoh, Some(context), query),
                Err(status) => return reject(exchange, status, peer).await,
            }
        }
        (Route::Target(Kind::Dns), Ok(query)) => (Transport::Https, None, query.to_vec()),
    };
    let pipeline = thread.pipeline();
    let mut first = None;
    let started = start(thread, &pipeline, &query, transport, peer.ip(), |wire| {
        first = Some(wire.to_vec());
        true
    });
    let mut exchange = Some(exchange);
    if let Some(wire) = first {
        respond_sealed(&mut exchange, &mut context, wire, peer).await;
    }
    if let Some(Started::Upstream(upstream, slot)) = started {
        let deliver = async |wire| respond_sealed(&mut exchange, &mut context, wire, peer).await;
        answer(thread, &pipeline, upstream, transport, deliver).await;
        drop(slot);
    }
    if let Some(exchange) = exchange {
        reject(exchange, StatusCode::BAD_REQUEST, peer).await;
    }
}

/// The response to the request to forward the encrypted query `body` to `destination` (D94): the target's, or the
/// proxy's error. Boxed: the futures of the HTTP/3 request tasks are large already.
#[cfg(feature = "odoh")]
async fn forward(
    proxy: &Proxy,
    destination: &Destination,
    body: &[u8],
    thread: &Thread,
) -> http::Response<Vec<u8>> {
    Box::pin(proxy.forward(&thread.forwarder, destination, body)).await
}

/// The label `status` of the proxied count (D94): a status the proxy answers with, else "other".
#[cfg(feature = "odoh")]
const fn proxied_status(status: StatusCode) -> &'static str {
    match status {
        StatusCode::OK => "200",
        StatusCode::BAD_REQUEST => "400",
        StatusCode::UNAUTHORIZED => "401",
        StatusCode::FORBIDDEN => "403",
        StatusCode::METHOD_NOT_ALLOWED => "405",
        StatusCode::PAYLOAD_TOO_LARGE => "413",
        StatusCode::UNSUPPORTED_MEDIA_TYPE => "415",
        StatusCode::INTERNAL_SERVER_ERROR => "500",
        StatusCode::BAD_GATEWAY => "502",
        StatusCode::SERVICE_UNAVAILABLE => "503",
        StatusCode::GATEWAY_TIMEOUT => "504",
        _ => "other",
    }
}

/// Answers `exchange` with `response` of the proxy role, and counts it (D94).
#[cfg(feature = "odoh")]
async fn proxied(
    exchange: Exchange<Route<&Proxy>>,
    response: http::Response<Vec<u8>>,
    peer: SocketAddr,
) {
    let status = proxied_status(response.status());
    metrics::counter!(ODOH_PROXIED, "status" => status).increment(1);
    sent(exchange.respond_with(response), peer).await;
}

#[cfg(feature = "odoh")]
const ODOH_PROXIED: &str = "dedensd_odoh_proxied_total";

/// Answers 200 with `wire` on `exchange`, sealed for the client when `context` holds what that takes, unless it was
/// answered already.
#[cfg(feature = "odoh")]
async fn respond_sealed(
    exchange: &mut Option<Exchange<Route<&Proxy>>>,
    context: &mut Option<ResponseContext>,
    wire: Vec<u8>,
    peer: SocketAddr,
) {
    let Some(context) = context.take() else {
        return respond_http(exchange, wire, peer).await;
    };
    let Some(exchange) = exchange.take() else {
        return;
    };
    match odoh::seal(context, &wire) {
        Ok(response) => {
            count_doh(exchange.method(), StatusCode::OK);
            sent(exchange.respond_with(response), peer).await;
        }
        Err(status) => reject(exchange, status, peer).await,
    }
}

/// Answers 200 with `wire` on `exchange`, unless it was answered already.
async fn respond_http<K>(exchange: &mut Option<Exchange<K>>, wire: Vec<u8>, peer: SocketAddr) {
    if let Some(exchange) = exchange.take() {
        count_doh(exchange.method(), StatusCode::OK);
        sent(exchange.respond(wire), peer).await;
    }
}

/// Answers `status` without a message.
async fn reject<K>(exchange: Exchange<K>, status: StatusCode, peer: SocketAddr) {
    count_doh(exchange.method(), status);
    sent(exchange.reject(status), peer).await;
}

/// Waits for the response `write` to `peer` to go out, at most [`TCP_WRITE`]: a client that grants no credit to
/// receive it loses the request, as a TCP one reading too slowly loses its connection (D47). The write is boxed: the
/// futures of the HTTP/3 request tasks are large already.
async fn sent(write: impl Future<Output = Result<(), HttpsError>>, peer: SocketAddr) {
    match compio::time::timeout(TCP_WRITE, Box::pin(write)).await {
        Ok(Ok(())) => {}
        Ok(Err(error)) => tracing::debug!(%peer, %error, "HTTP/3 response failed"),
        Err(_) => tracing::debug!(%peer, "HTTP/3 response timed out"),
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
        StatusCode::UNAUTHORIZED => "401",
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

/// Writes `framed` on `send` and finishes it, unless it was answered already; a write lasting [`TCP_WRITE`] is given
/// up and the stream reset with `DOQ_EXCESSIVE_LOAD` (RFC 9250 §4.3.2), as a TCP client reading too slowly loses
/// its connection (D47).
async fn respond(send: &mut Option<SendStream>, framed: Vec<u8>) {
    let Some(mut stream) = send.take() else {
        return;
    };
    match compio::time::timeout(TCP_WRITE, stream.write_all(framed)).await {
        Ok(BufResult(Ok(()), _)) => {
            let _ = stream.finish();
        }
        Ok(_) => {}
        Err(_) => {
            let _ = stream.reset(VarInt::from_u32(DOQ_EXCESSIVE_LOAD));
        }
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
        // The validator's questions are shared with the queries asking them at the same time (D86).
        let key = upstream.probe().map(|question| Key {
            server: server.clone(),
            udp: transport == Transport::Udp,
            question: question.clone(),
        });
        let fetched = 'ask: {
            let mut exchange = pin!(fetch(thread, key, upstream.request(), target, &options));
            if let Some(at) = stale_at {
                // A reborrow: the exchange goes on after the timer.
                if let Ok(fetched) = compio::time::timeout_at(at, exchange.as_mut()).await {
                    break 'ask fetched;
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
            let step = match &fetched {
                Fetched::Own(Ok(response), _) => {
                    pipeline.receive(upstream, Some(&response.wire), now(), &mut out)
                }
                Fetched::Own(Err(error), _) if error.is_local() => {
                    tracing::warn!(%error, %server, "upstream query not sent");
                    pipeline.abandon(&upstream, &mut out)
                }
                Fetched::Own(Err(error), _) => {
                    tracing::debug!(%error, %server, "upstream");
                    pipeline.receive(upstream, None, now(), &mut out)
                }
                Fetched::Shared(wire) => {
                    pipeline.receive(upstream, wire.as_deref(), now(), &mut out)
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
        // After `receive`, which put what the response proved in the key cache, and before the client is
        // written to, which may wait.
        if let Fetched::Own(result, Some(lead)) = fetched {
            match result {
                Ok(response) => lead.finish(Some(&response.wire)),
                Err(error) if !error.is_local() => lead.finish(None),
                // Not sent: the followers ask for themselves.
                Err(_) => drop(lead),
            }
        }
        if let Some(reply) = reply {
            deliver(reply).await;
        }
        let Some(next) = next else {
            return;
        };
        upstream = next;
    }
}

/// What an upstream question got.
#[expect(
    clippy::large_enum_variant,
    reason = "made once per upstream query and used at once: a box would be an allocation on the forwarding path"
)]
enum Fetched<'a> {
    /// The response, or why there was none, to a query sent by this one; `Some` when others wait for it.
    Own(Result<Response, ClientError>, Option<Lead<'a>>),
    /// The response, bytes only, of the query another sent, or none if that one failed on the server's side.
    Shared(Option<Arc<[u8]>>),
}

/// Sends `request` to `target`, unless a query of the same `key` is in flight: then waits for its response.
async fn fetch<'a>(
    thread: &'a Thread,
    key: Option<Key>,
    request: Message<'static>,
    target: Server,
    options: &Options,
) -> Fetched<'a> {
    let flights: &Flights = thread.current.flights();
    let mut lead = None;
    if let Some(key) = key {
        loop {
            match flights.join(key.clone()) {
                Flight::Lead(flight) => {
                    lead = Some(flight);
                    break;
                }
                Flight::Follow(response) => {
                    if let Ok(shared) = response.recv_async().await {
                        return Fetched::Shared(shared);
                    }
                    // Its query ended without a response: ask again, as the first of those left.
                }
            }
        }
    }
    Fetched::Own(thread.client.exchange(request, target, options).await, lead)
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
        docpath: Vec::new(),
    };
    if let Via::Https { path, .. } = &server.via {
        target.doh = target.template_at(path).ok();
    }
    (target, transport)
}

/// The reply `wire`, made in the thread's buffer, copied out to be sent over `transport`: behind its length but
/// over UDP, HTTPS and CoAP. Only its bytes leave the buffer, never those of an earlier reply.
fn copy_out(wire: &[u8], transport: Transport) -> Option<Vec<u8>> {
    if matches!(
        transport,
        Transport::Udp | Transport::Https | Transport::Odoh | Transport::Coap
    ) {
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
    use std::cell::{Cell, RefCell};
    use std::io;
    use std::net::SocketAddr;
    use std::pin::pin;
    use std::rc::Rc;
    use std::sync::Arc;
    use std::time::{Duration, Instant};

    use compio::BufResult;
    use compio::driver::op::RecvFromMultiResult;
    use compio::io::{AsyncWriteExt, BufReader};
    use compio::net::{TcpListener, TcpStream, UdpSocket};
    use compio::runtime::{Runtime, spawn};
    use dedens_net::tcp::{frame, read_message};
    use dedens_net::tls::Trust;
    use dedens_proto::edns::EdnsOption;
    use dedens_proto::{Message, Question, Rcode, RecordType};
    use dedens_server::{Answer, Forward, Pipeline, Plugin, Reviewer, Stage, Transport};
    use futures_util::Stream;
    use futures_util::future::{Either, select};
    use futures_util::lock::Mutex;
    use futures_util::stream::repeat_with;
    use metrics_util::debugging::DebuggingRecorder;

    use super::{
        BUSY_PAUSE, BUSY_YIELDS, Backoff, ERROR_PAUSE, Pause, Receiving, Replies, Slots,
        TCP_PENDING, TCP_QUEUED, Thread, UPSTREAM_QUERIES, breaks_doq, connection, first_end,
        follow, runtime, supervised_with, tcp, udp, udp_queries, write,
    };
    use crate::isolate::tests::counted;
    use crate::isolate::{Listener, Origin};
    use crate::lists::Store;
    use crate::reload::Current;

    fn udp_listener() -> Listener {
        Listener::new("udp", Some(SocketAddr::from(([127, 0, 0, 1], 53))))
    }

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
        let config =
            crate::config::read(text, |_| None, &Pipeline::default(), &mut Store::default())
                .expect("read");
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
                let origin = Origin::new(&udp_listener(), SocketAddr::from(([127, 0, 0, 1], 1)));
                connection(
                    BufReader::new(reader),
                    writer,
                    Transport::Tcp,
                    &origin,
                    &thread,
                )
                .await;
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

    /// RFC 9250 §4.3.3: a Message ID other than 0 and an edns-tcp-keepalive option break DNS over QUIC.
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

    /// D94: each status the proxy answers with has its label in the count, and another is "other".
    #[cfg(feature = "odoh")]
    #[test]
    fn the_proxied_count_is_labelled_by_status() {
        use http::StatusCode;

        use super::proxied_status;

        for code in [200, 400, 401, 403, 405, 413, 415, 500, 502, 503, 504] {
            let status = StatusCode::from_u16(code).expect("a status");
            assert_eq!(proxied_status(status), code.to_string());
        }
        for code in [204, 404, 429, 501] {
            let status = StatusCode::from_u16(code).expect("a status");
            assert_eq!(proxied_status(status), "other");
        }
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

    /// A stream failing on every poll with `kind`, counting its polls in `polls`.
    fn failing(
        kind: io::ErrorKind,
        polls: &Cell<u32>,
    ) -> Mutex<impl Stream<Item = io::Result<RecvFromMultiResult>> + Unpin + '_> {
        Mutex::new(repeat_with(move || {
            polls.set(polls.get() + 1);
            Err(io::Error::new(kind, "a failure"))
        }))
    }

    /// A thread over a pipeline that answers nothing.
    fn idle() -> Rc<Thread> {
        let current = Arc::new(Current::new(Pipeline::default()));
        Rc::new(Thread::new(current, 0, Trust::default()))
    }

    /// D107: a task pausing after two failed receives in a row leaves the stream free, so the socket's other tasks
    /// keep receiving: its lock is not held while the task sleeps.
    #[test]
    fn a_udp_receive_failing_twice_pauses_only_its_task() {
        let runtime = Runtime::new().expect("a runtime");
        runtime.block_on(async {
            let socket = Rc::new(UdpSocket::bind("127.0.0.1:0").await.expect("bound"));
            let polls = Cell::new(0);
            let datagrams = failing(io::ErrorKind::Other, &polls);
            let thread = idle();
            let probe = async {
                // The task is asleep by then.
                compio::time::sleep(ERROR_PAUSE / 5).await;
                compio::time::timeout(ERROR_PAUSE / 3, datagrams.lock())
                    .await
                    .is_ok()
            };
            let name = udp_listener();
            let receiving = pin!(udp_queries(&socket, &datagrams, &name, &thread));
            let Either::Right((free, _)) = select(receiving, pin!(probe)).await else {
                panic!("the receiving task never ends");
            };
            assert!(free, "the stream stayed locked while its task slept");
            assert_eq!(polls.get(), 2);
        });
    }

    /// D107: no free buffer in the pool (`ENOBUFS`, `ResourceBusy`) is a wait for the tasks to read what the kernel
    /// filled: the task tries again after a few yields, then every [`BUSY_PAUSE`], without the pause of a failed
    /// socket, and without spinning either.
    #[test]
    fn a_udp_receive_without_a_free_buffer_is_tried_again_without_spinning() {
        let runtime = Runtime::new().expect("a runtime");
        runtime.block_on(async {
            let socket = Rc::new(UdpSocket::bind("127.0.0.1:0").await.expect("bound"));
            let polls = Cell::new(0);
            let datagrams = failing(io::ErrorKind::ResourceBusy, &polls);
            let thread = idle();
            let name = udp_listener();
            let receiving = udp_queries(&socket, &datagrams, &name, &thread);
            let ended = compio::time::timeout(ERROR_PAUSE / 2, receiving).await;
            assert!(ended.is_err(), "the receiving task never ends");
            // The yields, then one try a millisecond (a timer may be late, never early); without a pause it is
            // thousands.
            let polls = polls.get();
            assert!((10..100).contains(&polls), "{polls} polls");
        });
    }

    /// D107: the pause after failed receives by kind: a first error is retried at once, a second in a row after
    /// [`ERROR_PAUSE`]; a lack of buffers yields [`BUSY_YIELDS`] times, then sleeps [`BUSY_PAUSE`], and counts
    /// neither as a failure nor towards one.
    #[test]
    fn receives_that_failed_are_paused_by_kind() {
        let mut receiving = Receiving::Fine;
        assert_eq!(receiving.failed(false), Pause::None);
        assert_eq!(receiving.failed(false), Pause::Sleep(ERROR_PAUSE));
        assert_eq!(receiving.failed(false), Pause::Sleep(ERROR_PAUSE));
        // A lack of buffers between two other errors breaks the run.
        assert_eq!(receiving.failed(true), Pause::Yield);
        assert_eq!(receiving.failed(false), Pause::None);
        let mut receiving = Receiving::Fine;
        for _ in 0..BUSY_YIELDS {
            assert_eq!(receiving.failed(true), Pause::Yield);
        }
        for _ in 0..3 {
            assert_eq!(receiving.failed(true), Pause::Sleep(BUSY_PAUSE));
        }
    }

    /// D107: a thread no query reaches takes the pipeline a reload made, and so lets go of the old one (and its
    /// lists), as its runtime wakes to the reload from another thread.
    #[test]
    fn an_idle_thread_gives_up_the_old_pipeline_after_a_reload() {
        let current = Arc::new(Current::new(Pipeline::default()));
        let old = Arc::downgrade(&current.get());
        let thread = Rc::new(Thread::new(Arc::clone(&current), 0, Trust::default()));
        assert_eq!(old.strong_count(), 2, "`current` and the thread hold it");
        let (released, wait) = flume::bounded(1);
        let reloading = std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(50));
            current.replace(Pipeline::default());
            let start = Instant::now();
            while old.strong_count() > 0 && start.elapsed() < Duration::from_secs(5) {
                std::thread::sleep(Duration::from_millis(5));
            }
            released.send(old.strong_count()).expect("the test waits");
        });
        let runtime = Runtime::new().expect("a runtime");
        let left = runtime.block_on(async {
            spawn(follow(thread)).detach();
            compio::time::timeout(Duration::from_secs(10), wait.recv_async())
                .await
                .expect("an end within 10 s")
                .expect("a count")
        });
        reloading.join().expect("the reload ran");
        assert_eq!(left, 0, "the old pipeline is still held");
    }

    /// A thread whose pipeline answers `www.example` A at once, with no upstream.
    fn answering() -> Rc<Thread> {
        let text = "listen: ['127.0.0.1:53']\npipeline: [hosts]\nstages:\n  hosts:\n    type: hosts\n    entries: ['192.0.2.1 www.example']\n";
        let config =
            crate::config::read(text, |_| None, &Pipeline::default(), &mut Store::default())
                .expect("read");
        let current = Arc::new(Current::new(config.pipeline));
        Rc::new(Thread::new(current, 0, Trust::default()))
    }

    /// The number of answers `server` gives to `www.example` A over UDP, within five seconds.
    async fn answers(server: SocketAddr) -> usize {
        let name = "www.example.".parse().expect("a name");
        let query = Message::query(1, Question::new(name, RecordType::A))
            .to_vec()
            .expect("a query fits");
        let client = UdpSocket::bind("127.0.0.1:0").await.expect("bound");
        client.send_to(query, server).await.0.expect("sent");
        let BufResult(received, reply) = compio::time::timeout(
            Duration::from_secs(5),
            client.recv_from(Vec::with_capacity(512)),
        )
        .await
        .expect("a reply within 5 s");
        let len = received.expect("received").0;
        let reply = Message::decode(&reply[..len]).expect("decodes").message;
        assert_eq!(reply.rcode(), Rcode::NOERROR);
        reply.answer.len()
    }

    /// A plugin that answers `www.example` and reviews every response from upstream with a panic, as a bug in a
    /// plugin or in the pipeline would: a query for another name panics once its response is in.
    #[derive(Debug)]
    struct Reviewing;

    impl Plugin for Reviewing {
        fn answer(&self, query: &dedens_proto::Query<'_>) -> Option<Answer<'_>> {
            let question = query.question()?;
            (question.name.to_string() == "www.example.").then_some(Answer {
                rcode: Rcode::NOERROR,
                records: None,
                authoritative: true,
                error: None,
            })
        }

        fn reviewer(&self) -> Option<&dyn Reviewer> {
            Some(self)
        }
    }

    impl Reviewer for Reviewing {
        fn review(
            &self,
            _query: &dedens_proto::Query<'_>,
            _response: &Message<'_>,
        ) -> Option<Answer<'_>> {
            panic!("a bug")
        }
    }

    /// An upstream server on loopback, over TCP, as a query over TCP is asked there: it answers every query with
    /// itself, marked as a response.
    async fn echoing() -> SocketAddr {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bound");
        let addr = listener.local_addr().expect("its address");
        spawn(async move {
            while let Ok((mut stream, _)) = listener.accept().await {
                spawn(async move {
                    while let Ok(mut query) = read_message(&mut stream).await {
                        query[2] |= 0x80;
                        let BufResult(sent, _) =
                            stream.write_all(frame(&query).expect("framed")).await;
                        if sent.is_err() {
                            return;
                        }
                    }
                })
                .detach();
            }
        })
        .detach();
        addr
    }

    /// The panics counted so far, adding what `recorder` took before.
    fn panics_counted(recorder: &DebuggingRecorder, total: &Cell<u64>) -> u64 {
        let new: u64 = counted(recorder)
            .iter()
            .filter(|(metric, ..)| metric == "dedensd_task_panics_total")
            .map(|(.., count)| count)
            .sum();
        total.set(total.get() + new);
        total.get()
    }

    /// D121: queries that panic inside `connection()` end alone: each gives its place back, so the 66th query of a
    /// connection that had 65 panic is read and answered, and the thread goes on serving UDP.
    #[test]
    fn queries_that_panic_leave_their_connection_and_the_thread_serving() {
        let _ = tracing_subscriber::fmt()
            .with_max_level(tracing::Level::TRACE)
            .try_init();
        let recorder = DebuggingRecorder::new();
        let total = Cell::new(0);
        metrics::with_local_recorder(&recorder, || {
            runtime().expect("a runtime").block_on(async {
                let upstream = echoing().await;
                let pipeline = Pipeline::new(vec![
                    Stage::Plugin(Box::new(Reviewing)),
                    Stage::Forward(Forward::new([upstream]).expect("a server")),
                ]);
                let current = Arc::new(Current::new(pipeline));
                let thread = Rc::new(Thread::new(current, UPSTREAM_QUERIES, Trust::default()));
                let udp_socket = Rc::new(UdpSocket::bind("127.0.0.1:0").await.expect("bound"));
                let udp_addr = udp_socket.local_addr().expect("its address");
                spawn(udp(udp_socket, udp_listener(), Rc::clone(&thread))).detach();
                let tcp_listener = TcpListener::bind("127.0.0.1:0").await.expect("bound");
                let tcp_addr = tcp_listener.local_addr().expect("its address");
                let tcp_task = tcp(Rc::new(tcp_listener), None, udp_listener(), thread);
                spawn(tcp_task).detach();

                let mut client = TcpStream::connect(tcp_addr).await.expect("connected");
                let asking = |name: &str, id| {
                    let question = Question::new(name.parse().expect("a name"), RecordType::A);
                    frame(&Message::query(id, question).to_vec().expect("a query fits"))
                        .expect("framed")
                };
                for id in 0..=TCP_PENDING {
                    let id = u16::try_from(id).expect("a small number");
                    let BufResult(sent, _) = client.write_all(asking("other.example.", id)).await;
                    sent.expect("sent");
                }
                let BufResult(sent, _) = client.write_all(asking("www.example.", 1000)).await;
                sent.expect("sent");
                let reply =
                    compio::time::timeout(Duration::from_secs(5), read_message(&mut client))
                        .await
                        .expect("a reply within 5 s")
                        .expect("a reply");
                let reply = Message::decode(&reply).expect("decodes").message;
                assert_eq!((reply.header.id, reply.rcode()), (1000, Rcode::NOERROR));
                // The panics are those of the 65 queries, counted as the tasks end.
                let wanted = TCP_PENDING as u64 + 1;
                let waiting = async {
                    while panics_counted(&recorder, &total) < wanted {
                        compio::time::sleep(Duration::from_millis(5)).await;
                    }
                };
                compio::time::timeout(Duration::from_secs(5), waiting)
                    .await
                    .expect("65 panics counted within 5 s");
                assert_eq!(answers(udp_addr).await, 0);
            });
        });
        assert_eq!(total.get(), TCP_PENDING as u64 + 1);
    }

    /// Pauses of 1 ms, as a test cannot wait for 10 ms doubling.
    const QUICK: Backoff = Backoff {
        first: Duration::from_millis(1),
        max: Duration::from_millis(1),
        healthy: Duration::from_secs(60),
    };

    /// D121: a listener loop that panics while it serves starts again on the same socket, which answers again.
    #[test]
    fn a_udp_listener_that_panics_is_restarted_on_its_socket() {
        let recorder = DebuggingRecorder::new();
        metrics::with_local_recorder(&recorder, || {
            runtime().expect("a runtime").block_on(async {
                let thread = answering();
                let socket = Rc::new(UdpSocket::bind("127.0.0.1:0").await.expect("bound"));
                let server = socket.local_addr().expect("its address");
                let (poke, poked) = flume::bounded::<()>(1);
                let mut turns = 0;
                let supervisor =
                    supervised_with(QUICK, udp_listener(), &thread, move |name, thread| {
                        turns += 1;
                        let first = turns == 1;
                        let (socket, name, thread) =
                            (Rc::clone(&socket), name.clone(), Rc::clone(thread));
                        let poked = poked.clone();
                        async move {
                            if first {
                                let serving = pin!(udp(socket, name, thread));
                                select(serving, pin!(poked.recv_async())).await;
                                panic!("a bug");
                            }
                            udp(socket, name, thread).await;
                        }
                    });
                assert_eq!(answers(server).await, 1);
                poke.send(()).expect("the listener waits");
                assert_eq!(answers(server).await, 1);
                drop(supervisor);
            });
        });
        let name = "udp://127.0.0.1:53".to_owned();
        assert_eq!(
            counted(&recorder),
            [
                (
                    "dedensd_listener_restarts_total".to_owned(),
                    name.clone(),
                    1
                ),
                ("dedensd_task_panics_total".to_owned(), name, 1),
            ]
        );
    }

    /// D107, D121: on `io_uring`, a loop that ends with its multishot receive in flight, a hundred times over while
    /// datagrams arrive, still leaves a socket that answers: the kernel's receives, and the buffers they hold, go
    /// back to the pool as the stream is dropped. Linux only: the other drivers have no such ring.
    #[cfg(target_os = "linux")]
    #[test]
    fn a_udp_listener_restarted_a_hundred_times_under_load_still_answers() {
        runtime().expect("a runtime").block_on(async {
            let thread = answering();
            let socket = Rc::new(UdpSocket::bind("127.0.0.1:0").await.expect("bound"));
            let server = socket.local_addr().expect("its address");
            let mut turns = 0;
            let supervisor =
                supervised_with(QUICK, udp_listener(), &thread, move |name, thread| {
                    turns += 1;
                    let last = turns > 100;
                    let (socket, name, thread) =
                        (Rc::clone(&socket), name.clone(), Rc::clone(thread));
                    async move {
                        if last {
                            udp(socket, name, thread).await;
                        } else {
                            let serving = pin!(udp(socket, name, thread));
                            select(serving, pin!(compio::time::sleep(Duration::from_millis(1))))
                                .await;
                            panic!("a bug");
                        }
                    }
                });
            let flooding = spawn(async move {
                let client = UdpSocket::bind("127.0.0.1:0").await.expect("bound");
                for _ in 0..500 {
                    let name = "www.example.".parse().expect("a name");
                    let query = Message::query(1, Question::new(name, RecordType::A));
                    client
                        .send_to(query.to_vec().expect("a query fits"), server)
                        .await
                        .0
                        .expect("sent");
                    compio::time::sleep(Duration::from_micros(500)).await;
                }
            });
            let _ = flooding.await;
            assert_eq!(answers(server).await, 1);
            drop(supervisor);
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
