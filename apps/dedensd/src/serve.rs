//! The sockets of one thread and the tasks answering on them (D42): a task per UDP socket and per TCP listener,
//! one per TCP connection, and one per query that waits for an upstream server. Replies the pipeline builds at
//! once go out from the socket's own task; the rest are asked upstream with the thread's `dedens_net` client.

use std::io;
use std::net::SocketAddr;
use std::num::NonZeroU8;
use std::rc::Rc;
use std::sync::Arc;
use std::time::Duration;

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
use dedens_server::{Pipeline, Step, Transport};
use socket2::{Domain, Socket, Type};

/// How long a TCP connection stays open without a query (RFC 7766 §6.2.3).
const TCP_IDLE: Duration = Duration::from_secs(10);

/// Connections waiting to be accepted, per TCP listener.
const TCP_BACKLOG: i32 = 1024;

/// How long to wait for each upstream query, and how many to send, before asking the next server (D42).
const UPSTREAM_TIMEOUT: Duration = Duration::from_secs(1);
const UPSTREAM_TRIES: NonZeroU8 = NonZeroU8::new(2).expect("two is not zero");

/// How long to wait before accepting again after `accept` failed, for instance out of file descriptors.
const ACCEPT_PAUSE: Duration = Duration::from_millis(100);

/// The sockets of one thread, bound but not yet on its runtime.
#[derive(Debug)]
pub(crate) struct Sockets {
    udp: Vec<Socket>,
    tcp: Vec<Socket>,
}

/// Binds a UDP socket and a TCP listener on each of `addrs`. On Linux they take `SO_REUSEPORT`, so each thread
/// binds its own on the same addresses.
pub(crate) fn bind(addrs: &[SocketAddr]) -> anyhow::Result<Sockets> {
    let mut sockets = Sockets {
        udp: Vec::new(),
        tcp: Vec::new(),
    };
    for &addr in addrs {
        let udp = socket(addr, Type::DGRAM).with_context(|| format!("cannot bind UDP {addr}"))?;
        sockets.udp.push(udp);
        let tcp = socket(addr, Type::STREAM)
            .and_then(|tcp| tcp.listen(TCP_BACKLOG).map(|()| tcp))
            .with_context(|| format!("cannot listen on TCP {addr}"))?;
        sockets.tcp.push(tcp);
    }
    Ok(sockets)
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
    }
    #[cfg(target_os = "linux")]
    socket.set_reuse_port(true)?;
    socket.set_nonblocking(true)?;
    socket.bind(&addr.into())?;
    Ok(socket)
}

/// Answers on `sockets` with `pipeline`, until the end of the process.
///
/// # Errors
///
/// A socket the runtime cannot take.
pub(crate) async fn serve(sockets: Sockets, pipeline: Arc<Pipeline>) -> io::Result<()> {
    let client = Rc::new(Client::new());
    let mut tasks = Vec::new();
    for socket in sockets.udp {
        let socket = UdpSocket::from_std(socket.into())?;
        tasks.push(spawn(udp(
            socket,
            Arc::clone(&pipeline),
            Rc::clone(&client),
        )));
    }
    for socket in sockets.tcp {
        let listener = TcpListener::from_std(socket.into())?;
        tasks.push(spawn(tcp(
            listener,
            Arc::clone(&pipeline),
            Rc::clone(&client),
        )));
    }
    // None of them ends.
    for task in tasks {
        let _ = task.await;
    }
    Ok(())
}

/// Answers the queries of one UDP socket.
async fn udp(socket: UdpSocket, pipeline: Arc<Pipeline>, client: Rc<Client>) {
    let socket = Rc::new(socket);
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
        match pipeline.query(&query, Transport::Udp, &mut out) {
            Step::Reply(len) => out = send(&socket, out, len, peer).await,
            Step::Drop => {}
            // Owned for the task to outlive this buffer; the pipeline reads it again, a fraction of the wait.
            Step::Upstream(_) => {
                let (query, socket, pipeline, client) = (
                    query.clone(),
                    Rc::clone(&socket),
                    Arc::clone(&pipeline),
                    Rc::clone(&client),
                );
                spawn(async move {
                    let out = vec![0; usize::from(DEFAULT_UDP_PAYLOAD)];
                    if let Some((out, len)) =
                        answer(&pipeline, &client, &query, Transport::Udp, out).await
                    {
                        send(&socket, out, len, peer).await;
                    }
                })
                .detach();
            }
        }
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

/// Accepts the connections of one TCP listener.
async fn tcp(listener: TcpListener, pipeline: Arc<Pipeline>, client: Rc<Client>) {
    loop {
        match listener.accept().await {
            Ok((stream, _)) => {
                spawn(connection(
                    stream,
                    Arc::clone(&pipeline),
                    Rc::clone(&client),
                ))
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
/// be, so replies may come in another order (§6.2.1.1). Reading stops after [`TCP_IDLE`] without a query or at the
/// first error; the connection closes once the replies still waiting are written (§6.2.3).
async fn connection(stream: TcpStream, pipeline: Arc<Pipeline>, client: Rc<Client>) {
    // Queries are small and each waits for its answer: send replies without delay (RFC 7766 §10).
    let _ = stream.set_nodelay(true);
    let (reader, mut writer) = stream.into_split();
    let (replies, queue) = flume::unbounded::<Vec<u8>>();
    // Ends when the reader and every pending query have dropped their senders.
    let writing = spawn(async move {
        while let Ok(framed) = queue.recv_async().await {
            if writer.write_all(framed).await.0.is_err() {
                break;
            }
        }
        let _ = writer.shutdown().await;
    });
    let mut reader = BufReader::new(reader);
    let mut out = vec![0; MAX_MESSAGE_LEN];
    while let Ok(Ok(query)) = compio::time::timeout(TCP_IDLE, read_message(&mut reader)).await {
        match pipeline.query(&query, Transport::Tcp, &mut out) {
            Step::Reply(len) => reply(&replies, &out[..len]),
            Step::Drop => {}
            Step::Upstream(_) => {
                let (replies, pipeline, client) =
                    (replies.clone(), Arc::clone(&pipeline), Rc::clone(&client));
                spawn(async move {
                    let out = vec![0; MAX_MESSAGE_LEN];
                    if let Some((out, len)) =
                        answer(&pipeline, &client, &query, Transport::Tcp, out).await
                    {
                        reply(&replies, &out[..len]);
                    }
                })
                .detach();
            }
        }
    }
    drop(replies);
    let _ = writing.await;
}

/// Queues `wire` behind its length for the connection's writer.
fn reply(replies: &flume::Sender<Vec<u8>>, wire: &[u8]) {
    // A reply fits 65535 bytes, and the writer only stops after the last sender.
    if let Some(framed) = frame(wire) {
        let _ = replies.send(framed);
    }
}

/// Answers `query` through the pipeline, asking the upstream servers it names in turn; returns `out` and the
/// length of the reply in it, or `None` when the query gets none.
async fn answer(
    pipeline: &Pipeline,
    client: &Client,
    query: &[u8],
    transport: Transport,
    mut out: Vec<u8>,
) -> Option<(Vec<u8>, usize)> {
    // The upstream transport is the client's (D42).
    let mut options = Options::default();
    options.transport = match transport {
        Transport::Udp => exchange::Transport::Udp,
        Transport::Tcp => exchange::Transport::Tcp,
    };
    options.tries = UPSTREAM_TRIES;
    options.timeout = UPSTREAM_TIMEOUT;
    let mut step = pipeline.query(query, transport, &mut out);
    loop {
        match step {
            Step::Reply(len) => return Some((out, len)),
            Step::Drop => return None,
            Step::Upstream(upstream) => {
                let server = upstream.server();
                let response = client.exchange(upstream.request(), server, &options).await;
                if let Err(error) = &response {
                    tracing::debug!(%error, %server, "upstream");
                }
                let wire = response
                    .as_ref()
                    .ok()
                    .map(|response| response.wire.as_slice());
                step = upstream.receive(wire, &mut out);
            }
        }
    }
}
