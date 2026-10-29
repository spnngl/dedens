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
use compio::io::{AsyncWrite, AsyncWriteExt, BufReader};
use compio::net::{TcpListener, TcpStream, UdpSocket};
use compio::runtime::{JoinHandle, Runtime, spawn};
use compio::rustls::pki_types::ServerName;
use dedens_net::client::{Client, Server};
use dedens_net::exchange::Options;
use dedens_net::tcp::{frame, read_message};
use dedens_net::tls::Trust;
use dedens_proto::edns::DEFAULT_UDP_PAYLOAD;
use dedens_proto::wire::MAX_MESSAGE_LEN;
use dedens_server::{Pipeline, Step, Transport, Upstream, Via};
use futures_util::future::{join_all, select_all};
use futures_util::lock::Mutex;
use futures_util::{Stream, StreamExt};
use socket2::{Domain, Socket, Type};

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

/// The sockets of one thread, bound but not yet on its runtime: a UDP socket and a TCP listener per address.
pub(crate) type Sockets = Vec<(Socket, Socket)>;

/// Binds a UDP socket and a TCP listener on each of `addrs`. On Linux they take `SO_REUSEPORT`, so each thread
/// binds its own on the same addresses.
pub(crate) fn bind(addrs: &[SocketAddr]) -> anyhow::Result<Sockets> {
    addrs
        .iter()
        .map(|&addr| {
            let udp =
                socket(addr, Type::DGRAM).with_context(|| format!("cannot bind UDP {addr}"))?;
            let tcp = socket(addr, Type::STREAM)
                .and_then(|tcp| tcp.listen(TCP_BACKLOG).map(|()| tcp))
                .with_context(|| format!("cannot listen on TCP {addr}"))?;
            Ok((udp, tcp))
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
/// until the end of the process.
///
/// # Errors
///
/// A socket the runtime cannot take, or a task answering on one ended: it panicked.
pub(crate) async fn serve(sockets: Sockets, current: Arc<Current>, trust: Trust) -> io::Result<()> {
    let thread = Rc::new(Thread::new(current, UPSTREAM_QUERIES, trust));
    let mut tasks = Vec::new();
    for (udp_socket, tcp_listener) in sockets {
        let socket = UdpSocket::from_std(udp_socket.into())?;
        tasks.push(spawn(udp(socket, Rc::clone(&thread))));
        let listener = TcpListener::from_std(tcp_listener.into())?;
        tasks.push(spawn(tcp(listener, Rc::clone(&thread))));
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

/// Accepts the connections of one TCP listener, up to [`TCP_CONNECTIONS`] at once.
async fn tcp(listener: TcpListener, thread: Rc<Thread>) {
    loop {
        match listener.accept().await {
            Ok((stream, peer)) => {
                let Some(slot) = thread.connections.take() else {
                    tracing::debug!(%peer, "too many TCP connections: closed");
                    continue;
                };
                let thread = Rc::clone(&thread);
                spawn(async move {
                    connection(stream, &thread).await;
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

/// Answers the queries of one TCP connection (RFC 7766): read one after the other, each answered as soon as it can
/// be, so replies may come in another order (§6.2.1.1). Reading waits while [`TCP_PENDING`] queries are in flight
/// or more than [`TCP_QUEUED`] bytes of replies wait to be written, and stops after [`TCP_IDLE`] without a query,
/// at the first error, or once the writer gave up; the connection closes once the replies still waiting are
/// written (§6.2.3). A query the thread has no room to ask upstream is answered SERVFAIL.
async fn connection(stream: TcpStream, thread: &Rc<Thread>) {
    // Queries are small and each waits for its answer: send replies without delay (RFC 7766 §10).
    let _ = stream.set_nodelay(true);
    let (reader, writer) = stream.into_split();
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
    let mut reader = BufReader::new(reader);
    'read: loop {
        while replies.queued.get() > TCP_QUEUED {
            if wait_room.recv_async().await.is_err() {
                break 'read;
            }
        }
        let Ok(Ok(query)) = compio::time::timeout(TCP_IDLE, read_message(&mut reader)).await else {
            break;
        };
        let pipeline = thread.pipeline();
        // The thread's buffer is borrowed until the replies made are queued, before any wait.
        let (upstream, slot) = {
            let mut out = thread.scratch.borrow_mut();
            let upstream = match pipeline.query(&query, Transport::Tcp, now(), &mut out) {
                Step::Reply(len) => {
                    if replies.push(&out[..len]) {
                        continue;
                    }
                    break;
                }
                Step::Drop => continue,
                Step::Upstream(upstream) => upstream,
                Step::Refresh(len, upstream) => {
                    if !replies.push(&out[..len]) {
                        break;
                    }
                    upstream
                }
            };
            let Some(slot) = thread.upstream.take() else {
                tracing::debug!("too many upstream queries: SERVFAIL");
                if let Step::Reply(len) = pipeline.abandon(&upstream, &mut out)
                    && !replies.push(&out[..len])
                {
                    break;
                }
                continue;
            };
            (upstream, slot)
        };
        if pending.send_async(()).await.is_err() {
            break;
        }
        let (replies, done, thread) = (replies.clone(), done.clone(), Rc::clone(thread));
        spawn(async move {
            let deliver = async |framed| {
                replies.queue(framed);
            };
            answer(&thread, &pipeline, upstream, Transport::Tcp, deliver).await;
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
    mut writer: impl AsyncWrite,
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
    let _ = writer.shutdown().await;
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
/// over a connection (D65). A name was checked when the configuration was read.
fn target(server: &dedens_server::Server, client: Transport) -> (Server, Transport) {
    let (transport, name) = match &server.via {
        Via::Plain if client == Transport::Udp => (Transport::Udp, None),
        Via::Plain => (Transport::Tcp, None),
        Via::Tls(name) => (Transport::Tls, name.as_deref()),
        Via::Quic(name) => (Transport::Quic, name.as_deref()),
    };
    let name = name
        .and_then(|name| ServerName::try_from(name).ok())
        .map(|name| name.to_owned());
    (
        Server {
            addr: server.addr,
            name,
        },
        transport,
    )
}

/// The reply `wire`, made in the thread's buffer, copied out to be sent over `transport`: behind its length for TCP.
/// Only its bytes leave the buffer, never those of an earlier reply.
fn copy_out(wire: &[u8], transport: Transport) -> Option<Vec<u8>> {
    if transport == Transport::Tcp {
        frame(wire)
    } else {
        Some(wire.to_vec())
    }
}

/// Seconds since the first call, the clock of the cache (D43).
fn now() -> u32 {
    static START: LazyLock<Instant> = LazyLock::new(Instant::now);
    u32::try_from(START.elapsed().as_secs()).unwrap_or(u32::MAX)
}

#[cfg(test)]
mod tests {
    use std::rc::Rc;
    use std::sync::Arc;

    use compio::io::AsyncWriteExt;
    use compio::net::{TcpListener, TcpStream};
    use compio::runtime::{Runtime, spawn};
    use dedens_net::tcp::{frame, read_message};
    use dedens_net::tls::Trust;
    use dedens_proto::{Message, Question, Rcode, RecordType};
    use dedens_server::Pipeline;

    use super::{Slots, Thread, connection, first_end};
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
                connection(stream, &thread).await;
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
