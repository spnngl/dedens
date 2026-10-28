//! The sockets of one thread and the tasks answering on them (D42): a task per UDP socket and per TCP listener,
//! one per TCP connection, and one per query that waits for an upstream server. Replies the pipeline builds at
//! once go out from the socket's own task; the rest are asked upstream with the thread's `dedens_net` client.
//! Each thread bounds its upstream queries and TCP connections, each connection its queries in flight and the time
//! a reply takes to write (D47).

use std::cell::Cell;
use std::io;
use std::net::SocketAddr;
use std::pin::pin;
use std::rc::Rc;
use std::sync::{Arc, LazyLock};
use std::time::{Duration, Instant};

use anyhow::Context;
use compio::BufResult;
use compio::buf::{IntoInner, IoBuf};
use compio::io::{AsyncWrite, AsyncWriteExt, BufReader};
use compio::net::{TcpListener, TcpStream, UdpSocket};
use compio::runtime::spawn;
use dedens_net::client::Client;
use dedens_net::exchange::{self, Options};
use dedens_net::tcp::{frame, read_message};
use dedens_proto::edns::DEFAULT_UDP_PAYLOAD;
use dedens_proto::wire::MAX_MESSAGE_LEN;
use dedens_server::{Pipeline, Step, Transport, Upstream};
use socket2::{Domain, Socket, Type};

/// How long a TCP connection stays open without a query (RFC 7766 §6.2.3).
const TCP_IDLE: Duration = Duration::from_secs(10);

/// Tasks answering on each UDP socket: one receives while another answers or sends, so the socket always has a
/// receive posted.
const UDP_RECEIVES: usize = 4;

/// Bytes a UDP socket may hold before the OS drops datagrams (`SO_RCVBUF`).
const UDP_RECEIVE_BUFFER: usize = 4 << 20;

/// Connections waiting to be accepted, per TCP listener.
const TCP_BACKLOG: i32 = 1024;

/// How long to wait before accepting again after `accept` failed, for instance out of file descriptors.
const ACCEPT_PAUSE: Duration = Duration::from_millis(100);

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

/// Upstream queries in flight per thread: past them, a UDP query is dropped and a TCP connection closed.
const UPSTREAM_QUERIES: usize = 1024;

/// TCP connections per thread: past them, a new one is closed at once (RFC 7766 §10).
const TCP_CONNECTIONS: usize = 256;

/// Queries in flight per TCP connection, waiting for upstream or for the writer: past them, reading waits.
const TCP_PENDING: usize = 64;

/// How long a reply may take to write: a client that stops reading loses its connection (RFC 7766 §10).
const TCP_WRITE: Duration = Duration::from_secs(10);

/// What the tasks of one thread share.
struct Thread {
    pipeline: Arc<Pipeline>,
    client: Client,
    upstream: Slots,
    connections: Slots,
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

/// Answers on `sockets` with `pipeline`, until the end of the process.
///
/// # Errors
///
/// A socket the runtime cannot take.
pub(crate) async fn serve(sockets: Sockets, pipeline: Arc<Pipeline>) -> io::Result<()> {
    let thread = Rc::new(Thread {
        pipeline,
        client: Client::new(),
        upstream: Slots::new(UPSTREAM_QUERIES),
        connections: Slots::new(TCP_CONNECTIONS),
    });
    for (udp_socket, tcp_listener) in sockets {
        let socket = Rc::new(UdpSocket::from_std(udp_socket.into())?);
        for _ in 0..UDP_RECEIVES {
            spawn(udp(Rc::clone(&socket), Rc::clone(&thread))).detach();
        }
        let listener = TcpListener::from_std(tcp_listener.into())?;
        spawn(tcp(listener, Rc::clone(&thread))).detach();
    }
    // The tasks never end.
    std::future::pending().await
}

/// Answers queries of one UDP socket, one after the other; [`UDP_RECEIVES`] of them share a socket.
async fn udp(socket: Rc<UdpSocket>, thread: Rc<Thread>) {
    let mut query = Vec::with_capacity(MAX_MESSAGE_LEN);
    let mut out = vec![0; usize::from(DEFAULT_UDP_PAYLOAD)];
    loop {
        query.clear();
        let BufResult(received, buffer) = socket.recv_from(query).await;
        query = buffer;
        let peer = match received {
            Ok((_, peer)) => peer,
            Err(error) => {
                tracing::debug!(%error, "UDP receive");
                continue;
            }
        };
        let upstream = match thread
            .pipeline
            .query(&query, Transport::Udp, now(), &mut out)
        {
            Step::Reply(len) => {
                out = send(&socket, out, len, peer).await;
                continue;
            }
            Step::Drop => continue,
            Step::Upstream(upstream) => upstream,
            Step::Refresh(len, upstream) => {
                out = send(&socket, out, len, peer).await;
                upstream
            }
        };
        let Some(slot) = thread.upstream.take() else {
            tracing::debug!(%peer, "too many upstream queries: dropped");
            continue;
        };
        let (socket, thread) = (Rc::clone(&socket), Rc::clone(&thread));
        spawn(async move {
            let deliver = async |out, len| send(&socket, out, len, peer).await;
            let size = usize::from(DEFAULT_UDP_PAYLOAD);
            answer(&thread, upstream, Transport::Udp, size, deliver).await;
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
                compio::time::sleep(ACCEPT_PAUSE).await;
            }
        }
    }
}

/// Answers the queries of one TCP connection (RFC 7766): read one after the other, each answered as soon as it can
/// be, so replies may come in another order (§6.2.1.1). Reading waits while [`TCP_PENDING`] queries are in flight,
/// and stops after [`TCP_IDLE`] without a query, at the first error, once the writer gave up, or when the thread
/// has no room for another upstream query; the connection closes once the replies still waiting are written
/// (§6.2.3).
async fn connection(stream: TcpStream, thread: &Rc<Thread>) {
    // Queries are small and each waits for its answer: send replies without delay (RFC 7766 §10).
    let _ = stream.set_nodelay(true);
    let (reader, mut writer) = stream.into_split();
    let (replies, queue) = flume::bounded::<Vec<u8>>(TCP_PENDING);
    // Ends when the reader and every pending query have dropped their senders, or a write fails or times out. The
    // replies queued meanwhile go out together, up to a message's size: one write for many.
    let writing = spawn(async move {
        let mut batch = Vec::new();
        while let Ok(framed) = queue.recv_async().await {
            batch.clear();
            batch.extend_from_slice(&framed);
            while batch.len() < MAX_MESSAGE_LEN
                && let Ok(framed) = queue.try_recv()
            {
                batch.extend_from_slice(&framed);
            }
            match compio::time::timeout(TCP_WRITE, writer.write_all(batch)).await {
                Ok(BufResult(Ok(()), written)) => batch = written,
                _ => return,
            }
        }
        let _ = writer.shutdown().await;
    });
    // A semaphore: a query in flight holds a place in the channel, given back when it is answered.
    let (pending, done) = flume::bounded::<()>(TCP_PENDING);
    let mut reader = BufReader::new(reader);
    let mut out = vec![0; MAX_MESSAGE_LEN];
    while let Ok(Ok(query)) = compio::time::timeout(TCP_IDLE, read_message(&mut reader)).await {
        let upstream = match thread
            .pipeline
            .query(&query, Transport::Tcp, now(), &mut out)
        {
            Step::Reply(len) => {
                if reply(&replies, &out[..len]).await {
                    continue;
                }
                break;
            }
            Step::Drop => continue,
            Step::Upstream(upstream) => upstream,
            Step::Refresh(len, upstream) => {
                if !reply(&replies, &out[..len]).await {
                    break;
                }
                upstream
            }
        };
        if pending.send_async(()).await.is_err() {
            break;
        }
        let Some(slot) = thread.upstream.take() else {
            tracing::debug!("too many upstream queries: TCP connection closed");
            break;
        };
        let (replies, done, thread) = (replies.clone(), done.clone(), Rc::clone(thread));
        spawn(async move {
            let deliver = async |out: Vec<u8>, len| {
                reply(&replies, &out[..len]).await;
                out
            };
            answer(&thread, upstream, Transport::Tcp, MAX_MESSAGE_LEN, deliver).await;
            drop(slot);
            let _ = done.try_recv();
        })
        .detach();
    }
    drop(replies);
    let _ = writing.await;
}

/// Queues `wire` behind its length for the connection's writer, waiting for room; `false` once the writer gave up.
async fn reply(replies: &flume::Sender<Vec<u8>>, wire: &[u8]) -> bool {
    // A reply fits 65535 bytes.
    match frame(wire) {
        Some(framed) => replies.send_async(framed).await.is_ok(),
        None => true,
    }
}

/// Asks the upstream servers for `upstream` in turn, over `transport`, the client's, each with the forward stage's
/// timeout and tries (D42), and hands `deliver` the replies to send, in a buffer of `size` bytes made only then:
/// expired data when the client response timer runs out first, resolution going on to refresh the cache (RFC 8767
/// §5), then the response's unless that went out; none after a prefetch. `deliver` gives the buffer back.
async fn answer(
    thread: &Thread,
    mut upstream: Box<Upstream>,
    transport: Transport,
    size: usize,
    mut deliver: impl AsyncFnMut(Vec<u8>, usize) -> Vec<u8>,
) {
    let pipeline = &thread.pipeline;
    let mut options = Options::default();
    options.transport = match transport {
        Transport::Udp => exchange::Transport::Udp,
        Transport::Tcp => exchange::Transport::Tcp,
    };
    (options.timeout, options.tries) = upstream.patience();
    // A response without EDNS would be stored for clients asking for DNSSEC records (RFC 3225).
    options.edns_fallback = false;
    let mut stale_at = upstream.stale_after().map(|after| Instant::now() + after);
    // Pending queries wait seconds: the buffer is made when a reply is.
    let mut out = Vec::new();
    loop {
        let server = upstream.server();
        let response = 'ask: {
            let mut exchange = pin!(thread.client.exchange(upstream.request(), server, &options));
            if let Some(at) = stale_at {
                // A reborrow: the exchange goes on after the timer.
                if let Ok(response) = compio::time::timeout_at(at, exchange.as_mut()).await {
                    break 'ask response;
                }
                stale_at = None;
                out.resize(size, 0);
                if let Some(len) = pipeline.stale(&upstream, now(), &mut out) {
                    out = deliver(out, len).await;
                }
            }
            exchange.await
        };
        out.resize(size, 0);
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
                deliver(out, len).await;
                return;
            }
            Step::Drop => return,
            Step::Upstream(next) => upstream = next,
        }
    }
}

/// Seconds since the first call, the clock of the cache (D43).
fn now() -> u32 {
    static START: LazyLock<Instant> = LazyLock::new(Instant::now);
    u32::try_from(START.elapsed().as_secs()).unwrap_or(u32::MAX)
}

#[cfg(test)]
mod tests {
    use super::Slots;

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
