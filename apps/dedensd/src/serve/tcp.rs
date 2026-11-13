//! TCP and TLS: the accept loop, a task per connection reading its pipelined queries (RFC 7766 §6.2.1), and the
//! writer of their replies, bounded in connections, queries in flight, bytes queued and time to write (RFC 7766 §10,
//! D47). The listener, its connections and the clock are the thread's [`Io`]'s (D182).

#![deny(clippy::disallowed_methods)]

use std::cell::Cell;
use std::io;
use std::net::IpAddr;
use std::rc::Rc;
use std::time::Duration;

use compio::BufResult;
use compio::io::BufReader;
use compio::io::util::Splittable as _;
use compio::net::TcpListener;
use compio::runtime::JoinHandle;
use compio::tls::TlsAcceptor;
use dedens_net::io::{Io, Listener as _, Stream as _};
use dedens_net::tcp::{Inbound, Outbound, Polled, frame};
use dedens_proto::{MAX_MESSAGE_LEN, Transport};
use dedens_server::Pipeline;
use socket2::Socket;

use super::isolate::{Listener, Origin};
use super::upstream::answer;
use super::{ERROR_PAUSE, Started, TCP_IDLE, Thread, local, pause, start, supervised};

/// Connections waiting to be accepted, per TCP listener.
pub(super) const TCP_BACKLOG: i32 = 1024;

/// TCP connections per thread: past them, a new one is closed at once (RFC 7766 §10).
pub(super) const TCP_CONNECTIONS: usize = 256;

/// Queries in flight per TCP connection, waiting for upstream or for the writer: past them, reading waits.
pub(super) const TCP_PENDING: usize = 64;

/// Bytes of replies a TCP connection may queue for its writer: past them, reading waits.
const TCP_QUEUED: usize = 128 << 10;

/// How long one write of the replies queued on a TCP connection may take: a client that stops reading loses its
/// connection (RFC 7766 §10). Per write, not until the queue empties: a client that keeps asking keeps the queue from
/// emptying while it reads all it is sent, and one that reads slower than it asks is held back by [`TCP_QUEUED`].
pub(super) const TCP_WRITE: Duration = Duration::from_secs(10);

/// What a connection makes of each message it reads and of each reply: DNS as it is, or sealed `DNSCrypt` packets
/// (D99). One value serves all the connections of a listener on a thread.
pub(super) trait Codec: 'static {
    /// What a query leaves for its reply: the keys it was opened under.
    type Context: 'static;

    /// Whether the client at `ip` is to get nothing, a connection included, before any work is done for it (D91).
    fn silenced(&self, pipeline: &Pipeline, ip: IpAddr) -> bool;

    /// What `message`, read off a connection from the client at `from`, is.
    fn open<N: Io>(
        &self,
        thread: &Thread<N>,
        from: IpAddr,
        message: Vec<u8>,
    ) -> Opened<Self::Context>;

    /// The reply to a query opened under `context`, `wire`, behind its length; `None` if it has none to send.
    fn seal<N: Io>(
        &self,
        thread: &Thread<N>,
        context: &Self::Context,
        wire: &[u8],
    ) -> Option<Vec<u8>>;

    /// As [`Codec::seal`], for a reply [`answer`] made, `framed` behind its length already.
    fn reseal<N: Io>(
        &self,
        thread: &Thread<N>,
        context: &Self::Context,
        framed: Vec<u8>,
    ) -> Option<Vec<u8>>;
}

/// What [`Codec::open`] made of a message.
#[cfg_attr(
    not(feature = "dnscrypt"),
    expect(dead_code, reason = "only `DNSCrypt` has replies of its own and drops")
)]
pub(super) enum Opened<C> {
    /// A query for the pipeline, and what its reply is sealed with.
    Query(Vec<u8>, C),
    /// A reply to send as it is, behind its length: the message was for the server itself.
    Reply(Vec<u8>),
    /// Nothing to answer.
    Drop,
}

/// DNS over TCP or TLS as RFC 7766 has it: messages are queries, replies go out as made.
struct Plain;

impl Codec for Plain {
    type Context = ();

    fn silenced(&self, pipeline: &Pipeline, ip: IpAddr) -> bool {
        pipeline.drops(ip)
    }

    fn open<N: Io>(&self, _: &Thread<N>, _: IpAddr, message: Vec<u8>) -> Opened<()> {
        Opened::Query(message, ())
    }

    fn seal<N: Io>(&self, _: &Thread<N>, (): &(), wire: &[u8]) -> Option<Vec<u8>> {
        // A reply fits 65535 bytes.
        frame(wire)
    }

    fn reseal<N: Io>(&self, _: &Thread<N>, (): &(), framed: Vec<u8>) -> Option<Vec<u8>> {
        Some(framed)
    }
}

/// Serves the TCP listener `tcp_listener`, over TLS with `acceptor` if any, as the listener `scheme`. A restarted
/// loop takes the same listener: a panic leaves it open.
pub(super) fn tcp_task(
    thread: &Rc<Thread>,
    tcp_listener: Socket,
    scheme: &str,
    acceptor: Option<TlsAcceptor>,
) -> io::Result<JoinHandle<()>> {
    tcp_task_with(thread, tcp_listener, scheme, acceptor, Rc::new(Plain))
}

/// [`tcp_task`] for messages `codec` reads and seals.
pub(super) fn tcp_task_with<C: Codec>(
    thread: &Rc<Thread>,
    tcp_listener: Socket,
    scheme: &str,
    acceptor: Option<TlsAcceptor>,
    codec: Rc<C>,
) -> io::Result<JoinHandle<()>> {
    let name = Listener::new(scheme, local(&tcp_listener));
    #[expect(
        clippy::disallowed_methods,
        reason = "compio takes the listener bound before (D42, D182)"
    )]
    let tcp_listener = Rc::new(TcpListener::from_std(tcp_listener.into())?);
    Ok(supervised(name, thread, move |name, thread| {
        let (tcp_listener, acceptor) = (Rc::clone(&tcp_listener), acceptor.clone());
        let codec = Rc::clone(&codec);
        accept(
            tcp_listener,
            acceptor,
            name.clone(),
            Rc::clone(thread),
            codec,
        )
    }))
}

/// Accepts the connections of one TCP listener, up to [`TCP_CONNECTIONS`] at once, over TLS with `acceptor`
/// (RFC 7858): the handshake must end within [`TCP_IDLE`].
pub(super) async fn tcp<N: Io>(
    tcp_listener: Rc<N::Listener>,
    acceptor: Option<TlsAcceptor>,
    listener: Listener,
    thread: Rc<Thread<N>>,
) {
    accept(tcp_listener, acceptor, listener, thread, Rc::new(Plain)).await;
}

/// [`tcp`] for messages `codec` reads and seals.
pub(super) async fn accept<N: Io, C: Codec>(
    tcp_listener: Rc<N::Listener>,
    acceptor: Option<TlsAcceptor>,
    listener: Listener,
    thread: Rc<Thread<N>>,
    codec: Rc<C>,
) {
    loop {
        match tcp_listener.accept().await {
            Ok((stream, peer)) => {
                // `action: drop` (D91): no slot, no handshake, no reply; `refuse` answers each query.
                if codec.silenced(&thread.pipeline(), peer.ip()) {
                    drop(stream);
                    continue;
                }
                let Some(slot) = thread.connections.take() else {
                    tracing::debug!(%peer, "too many connections: closed");
                    continue;
                };
                let (acceptor, thread, codec) =
                    (acceptor.clone(), Rc::clone(&thread), Rc::clone(&codec));
                let origin = Origin::new(&listener, peer);
                origin.clone().spawn(&thread.io.clone(), async move {
                    // Queries are small and each waits for its answer: send replies without delay (RFC 7766 §10).
                    let _ = stream.set_nodelay(true);
                    let Some(acceptor) = acceptor else {
                        let (reader, writer) = stream.split();
                        connection(
                            BufReader::new(reader),
                            writer,
                            Transport::Tcp,
                            &origin,
                            &thread,
                            &codec,
                        )
                        .await;
                        drop(slot);
                        return;
                    };
                    let deadline = thread.io.now() + TCP_IDLE;
                    match thread
                        .io
                        .timeout_at(deadline, acceptor.accept(stream))
                        .await
                    {
                        Ok(Ok(secured)) => {
                            let (reader, writer) = Polled::halves(secured);
                            connection(reader, writer, Transport::Tls, &origin, &thread, &codec)
                                .await;
                        }
                        Ok(Err(error)) => tracing::debug!(%peer, %error, "TLS handshake failed"),
                        Err(_) => tracing::debug!(%peer, "TLS handshake timed out"),
                    }
                    drop(slot);
                });
            }
            Err(error) => {
                tracing::warn!(%error, "TCP accept");
                pause(&thread.io, ERROR_PAUSE).await;
            }
        }
    }
}

/// Answers the queries of one TCP connection (RFC 7766), its halves `reader` and `writer`, over `transport`, TCP
/// or TLS: read one after the other, each answered as soon as it can be, so replies may come in another order
/// (§6.2.1.1). Reading waits while [`TCP_PENDING`] queries are in flight or more than [`TCP_QUEUED`] bytes of
/// replies wait to be written, and stops after [`TCP_IDLE`] without a query, at the first error, or once the
/// writer gave up; the connection closes once the replies still waiting are written (§6.2.3).
async fn connection<N: Io, C: Codec>(
    mut reader: impl Inbound,
    writer: impl Outbound + 'static,
    transport: Transport,
    origin: &Origin,
    thread: &Rc<Thread<N>>,
    codec: &Rc<C>,
) {
    let (sender, queue) = flume::unbounded::<Vec<u8>>();
    let replies = Replies {
        sender,
        queued: Rc::default(),
    };
    // The writer tells the reader there is room again; a stale message only makes it check once more.
    let (room, wait_room) = flume::bounded::<()>(1);
    let writing = origin.spawn_joinable(
        &thread.io,
        write(
            thread.io.clone(),
            writer,
            queue,
            Rc::clone(&replies.queued),
            room,
        ),
    );
    // A semaphore: a query in flight holds a place in the channel, given back when it is answered.
    let (pending, done) = flume::bounded::<()>(TCP_PENDING);
    'read: loop {
        while replies.full() {
            if wait_room.recv_async().await.is_err() {
                break 'read;
            }
        }
        let deadline = thread.io.now() + TCP_IDLE;
        let Ok(Ok(message)) = thread.io.timeout_at(deadline, reader.message()).await else {
            break;
        };
        let pipeline = thread.pipeline();
        let from = origin.peer.ip();
        let (query, context) = match codec.open(thread, from, message) {
            Opened::Query(query, context) => (query, context),
            Opened::Reply(framed) => {
                if replies.queue(framed) {
                    continue;
                }
                break;
            }
            Opened::Drop => continue,
        };
        let (upstream, slot) = match start(thread, &pipeline, &query, transport, from, |wire| {
            codec
                .seal(thread, &context, wire)
                .is_none_or(|framed| replies.queue(framed))
        }) {
            Some(Started::Upstream(upstream, slot)) => (upstream, slot),
            Some(Started::Done) => continue,
            None => break,
        };
        if pending.send_async(()).await.is_err() {
            break;
        }
        let (replies, place, thread) = (replies.clone(), Place(done.clone()), Rc::clone(thread));
        let codec = Rc::clone(codec);
        origin.clone().spawn(&thread.io.clone(), async move {
            let deliver = async |framed| {
                if let Some(framed) = codec.reseal(&thread, &context, framed) {
                    replies.queue(framed);
                }
            };
            answer(&thread, &pipeline, upstream, transport, deliver).await;
            drop(slot);
            drop(place);
        });
    }
    drop(replies);
    // The writer ends once every reply is written, and drops `room` as it ends, panicking or not. `room` is never
    // cloned, its one sender is the writer's: the channel closing is the writer's end, which `Io` tasks offer no
    // other way to wait for. A clone kept elsewhere would hang here, the connection open.
    while wait_room.recv_async().await.is_ok() {}
    drop(writing);
}

/// A place of a connection's in-flight queries, given back when dropped: a query that panics gives it back too, else
/// 64 panics (D121) would leave the connection reading no more.
struct Place(flume::Receiver<()>);

impl Drop for Place {
    fn drop(&mut self) {
        let _ = self.0.try_recv();
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
    /// Whether more than [`TCP_QUEUED`] bytes wait for the writer: reading waits (RFC 7766 §10).
    fn full(&self) -> bool {
        self.queued.get() > TCP_QUEUED
    }

    /// Queues `framed`, a reply behind its length, for the writer, without waiting: the reader bounds the bytes
    /// queued. `false` once the writer gave up.
    fn queue(&self, framed: Vec<u8>) -> bool {
        let len = framed.len();
        let sent = self.sender.send(framed).is_ok();
        if sent {
            self.queued.set(self.queued.get() + len);
        }
        sent
    }
}

/// Writes the replies of `queue`, counting down the bytes `queued` and telling `room` once they are
/// [`TCP_QUEUED`] or fewer. Ends when every sender is dropped, or a write fails or lasts [`TCP_WRITE`]. The replies
/// queued meanwhile go out together, up to a message's size: one write for many.
async fn write(
    io: impl Io,
    mut writer: impl Outbound,
    queue: flume::Receiver<Vec<u8>>,
    queued: Rc<Cell<usize>>,
    room: flume::Sender<()>,
) {
    let mut batch = Vec::new();
    while let Ok(first) = queue.recv_async().await {
        let mut next = Some(first);
        while let Some(framed) = next {
            batch.clear();
            batch.extend_from_slice(&framed);
            while batch.len() < MAX_MESSAGE_LEN
                && let Ok(framed) = queue.try_recv()
            {
                batch.extend_from_slice(&framed);
            }
            match io
                .timeout_at(io.now() + TCP_WRITE, writer.write_all(batch))
                .await
            {
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

// The tests run sockets and a runtime, which loom's threads and locks cannot drive (D135).
#[cfg(test)]
#[cfg(not(dedens_loom))]
#[expect(
    clippy::disallowed_methods,
    reason = "the tests run on compio's runtime, clock and sockets"
)]
mod tests {
    use std::cell::RefCell;
    use std::net::SocketAddr;
    use std::rc::Rc;
    use std::sync::Arc;
    use std::time::Duration;

    use compio::BufResult;
    use compio::io::{AsyncWriteExt, BufReader};
    use compio::net::{TcpListener, TcpStream};
    use compio::runtime::{Runtime, spawn};
    use dedens_net::io::Compio;
    use dedens_net::tcp::{frame, read_message};
    use dedens_net::tls::Trust;
    use dedens_proto::{Message, Question, Rcode, RecordType, Transport};
    use dedens_server::Pipeline;

    use super::{Plain, Replies, TCP_QUEUED, TCP_WRITE, connection, tcp, write};
    use crate::lists::Store;
    use crate::reload::Current;
    use crate::serve::isolate::{Listener, Origin};
    use crate::serve::tests::{answering, udp_listener};
    use crate::serve::{Slots, Thread};

    /// A query for `www.example` A, framed for TCP.
    fn www_example() -> Vec<u8> {
        let name = "www.example.".parse().expect("a name");
        let query = Message::query(1, Question::new(name, RecordType::A))
            .to_vec()
            .expect("a query fits");
        frame(&query).expect("framed")
    }

    /// Whether `client` gets a reply to `www.example` A within five seconds; `false` when the server closed it.
    async fn answered(client: &mut TcpStream) -> bool {
        let BufResult(sent, _) = client.write_all(www_example()).await;
        let reply = compio::time::timeout(Duration::from_secs(5), read_message(client))
            .await
            .expect("a reply or a close within 5 s");
        sent.is_ok() && reply.is_ok()
    }

    /// D47: past the thread's connection limit, the accept loop closes a new connection at once, and the ones it
    /// holds are served still; a slot given back takes a new one.
    #[test]
    fn a_connection_past_the_limit_is_closed_at_once() {
        let mut thread = answering();
        Rc::get_mut(&mut thread).expect("alone").connections = Slots::new(1);
        Runtime::new().expect("a runtime").block_on(async {
            let tcp_listener = TcpListener::bind("127.0.0.1:0").await.expect("bound");
            let addr = tcp_listener.local_addr().expect("its address");
            let listener = Listener::new("tcp", Some(addr));
            let accepting = spawn(tcp(Rc::new(tcp_listener), None, listener, thread));
            let mut first = TcpStream::connect(addr).await.expect("connected");
            assert!(answered(&mut first).await, "the first connection is served");
            let mut second = TcpStream::connect(addr).await.expect("connected");
            assert!(
                !answered(&mut second).await,
                "the second connection is served"
            );
            assert!(answered(&mut first).await, "the first connection is closed");
            drop(first);
            let start = std::time::Instant::now();
            let mut third = false;
            while !third && start.elapsed() < Duration::from_secs(5) {
                let mut next = TcpStream::connect(addr).await.expect("connected");
                third = answered(&mut next).await;
            }
            assert!(third, "the first connection's slot is not given back");
            drop(accepting);
        });
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
                    &Rc::new(Plain),
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
            let writing = spawn(write(
                Compio,
                writer,
                queue,
                Rc::clone(&replies.queued),
                room,
            ));
            let reply = vec![0; 1000];
            for _ in 0..200 {
                assert!(replies.queue(frame(&reply).expect("framed")));
            }
            let total = 200 * 1002;
            assert_eq!(replies.queued.get(), total);
            assert!(replies.full());
            // A batch takes replies until it holds 65535 bytes, 66 of them: the first write leaves more than
            // 128 KiB queued, the second not.
            open.send(()).expect("open");
            compio::time::sleep(Duration::from_millis(50)).await;
            assert!(wait_room.is_empty());
            assert_eq!(replies.queued.get(), total - 66 * 1002);
            assert!(replies.full());
            open.send(()).expect("open");
            wait_room.recv_async().await.expect("room");
            assert!(replies.queued.get() <= TCP_QUEUED);
            assert!(!replies.full());
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

    /// A batch takes no reply more once it holds a message's size: five replies of 65535 bytes in all, behind their
    /// lengths, go out together, the sixth after.
    #[test]
    fn a_batch_of_a_message_size_takes_no_more() {
        let runtime = Runtime::new().expect("a runtime");
        runtime.block_on(async {
            let (sender, queue) = flume::unbounded();
            let replies = Replies {
                sender,
                queued: Rc::default(),
            };
            let (room, _wait_room) = flume::bounded(1);
            let (open, gate) = flume::unbounded();
            let batches = Rc::default();
            let writer = Gated {
                gate,
                batches: Rc::clone(&batches),
            };
            let writing = spawn(write(
                Compio,
                writer,
                queue,
                Rc::clone(&replies.queued),
                room,
            ));
            let reply = vec![0; 13105];
            for _ in 0..6 {
                assert!(replies.queue(frame(&reply).expect("framed")));
            }
            for _ in 0..2 {
                open.send(()).expect("open");
            }
            drop(replies);
            writing.await.expect("the writer ends");
            assert_eq!(*batches.borrow(), [5 * 13107, 13107]);
        });
    }

    /// A writer whose every write takes `pause`, recording each batch's length.
    struct Slow {
        pause: Duration,
        batches: Rc<RefCell<Vec<usize>>>,
    }

    impl dedens_net::tcp::Outbound for Slow {
        async fn write_all(&mut self, batch: Vec<u8>) -> BufResult<(), Vec<u8>> {
            compio::time::sleep(self.pause).await;
            self.batches.borrow_mut().push(batch.len());
            BufResult(Ok(()), batch)
        }

        async fn close(&mut self) {}
    }

    /// D47: a client that asks without a pause, and reads all it is sent, keeps the queue from emptying past
    /// `TCP_WRITE`; its connection stays, each write being on time.
    #[test]
    fn a_queue_that_never_empties_is_written_while_each_write_is_on_time() {
        let runtime = Runtime::new().expect("a runtime");
        runtime.block_on(async {
            let (sender, queue) = flume::unbounded();
            let replies = Replies {
                sender,
                queued: Rc::default(),
            };
            let (room, _wait_room) = flume::bounded(1);
            let batches = Rc::default();
            let writer = Slow {
                pause: Duration::from_millis(300),
                batches: Rc::clone(&batches),
            };
            let writing = spawn(write(
                Compio,
                writer,
                queue,
                Rc::clone(&replies.queued),
                room,
            ));
            let start = std::time::Instant::now();
            let mut pushed = 0;
            while start.elapsed() < TCP_WRITE + Duration::from_secs(1) {
                assert!(
                    replies.queue(frame(&[0; 100]).expect("framed")),
                    "the writer gave up"
                );
                pushed += 102;
                compio::time::sleep(Duration::from_millis(100)).await;
            }
            drop(replies);
            writing.await.expect("the writer ends");
            assert_eq!(batches.borrow().iter().sum::<usize>(), pushed);
        });
    }

    /// D47: reading waits once more than 128 KiB of replies are queued, not at 128 KiB.
    #[test]
    fn reading_waits_past_128_kib_queued() {
        let (sender, _queue) = flume::unbounded();
        let replies = Replies {
            sender,
            queued: Rc::default(),
        };
        assert!(replies.queue(vec![0; TCP_QUEUED]));
        assert!(!replies.full());
        assert!(replies.queue(vec![0]));
        assert!(replies.full());
    }
}
