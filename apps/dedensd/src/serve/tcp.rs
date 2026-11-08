//! TCP and TLS: the accept loop, a task per connection reading its pipelined queries (RFC 7766 §6.2.1), and the
//! writer of their replies, bounded in connections, queries in flight, bytes queued and time to write (RFC 7766 §10,
//! D47).

use std::cell::Cell;
use std::io;
use std::rc::Rc;
use std::time::{Duration, Instant};

use compio::BufResult;
use compio::io::BufReader;
use compio::net::TcpListener;
use compio::runtime::JoinHandle;
use compio::tls::TlsAcceptor;
use dedens_net::tcp::{Inbound, Outbound, Polled, frame};
use dedens_proto::{MAX_MESSAGE_LEN, Transport};
use socket2::Socket;

use super::isolate::{Listener, Origin};
use super::upstream::answer;
use super::{ERROR_PAUSE, Started, TCP_IDLE, Thread, local, start, supervised};

/// Connections waiting to be accepted, per TCP listener.
pub(super) const TCP_BACKLOG: i32 = 1024;

/// TCP connections per thread: past them, a new one is closed at once (RFC 7766 §10).
pub(super) const TCP_CONNECTIONS: usize = 256;

/// Queries in flight per TCP connection, waiting for upstream or for the writer: past them, reading waits.
pub(super) const TCP_PENDING: usize = 64;

/// Bytes of replies a TCP connection may queue for its writer: past them, reading waits.
const TCP_QUEUED: usize = 128 << 10;

/// How long the replies queued on a TCP connection may take to be written, from when the first is queued until
/// none is left: a client that reads slower than it asks loses its connection (RFC 7766 §10).
pub(super) const TCP_WRITE: Duration = Duration::from_secs(10);

/// Serves the TCP listener `tcp_listener`, over TLS with `acceptor` if any, as the listener `scheme`. A restarted
/// loop takes the same listener: a panic leaves it open.
pub(super) fn tcp_task(
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

/// Accepts the connections of one TCP listener, up to [`TCP_CONNECTIONS`] at once, over TLS with `acceptor`
/// (RFC 7858): the handshake must end within [`TCP_IDLE`].
pub(super) async fn tcp(
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

// The tests run sockets and a runtime, which loom's threads and locks cannot drive (D135).
#[cfg(test)]
#[cfg(not(dedens_loom))]
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
    use dedens_net::tcp::{frame, read_message};
    use dedens_net::tls::Trust;
    use dedens_proto::{Message, Question, Rcode, RecordType, Transport};
    use dedens_server::Pipeline;

    use super::{Replies, TCP_QUEUED, connection, write};
    use crate::lists::Store;
    use crate::reload::Current;
    use crate::serve::Thread;
    use crate::serve::isolate::Origin;
    use crate::serve::tests::udp_listener;

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
}
