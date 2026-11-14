//! UDP: the tasks taking turns at a socket's datagrams (D48, D107), and its `Outbox`, whose one sender sends the
//! replies they queue (D123). The socket and the clock are the thread's [`Io`]'s (D182).

#![deny(clippy::disallowed_methods)]

use std::cell::RefCell;
use std::future::poll_fn;
use std::io;
use std::net::SocketAddr;
use std::num::NonZero;
use std::pin::pin;
use std::rc::Rc;
use std::task::Poll;
use std::time::{Duration, Instant};

use compio::BufResult;
use compio::buf::{IntoInner, IoBuf, Slice};
use dedens_net::io::{Datagram, Io, Udp};
use dedens_proto::Transport;
use dedens_proto::edns::DEFAULT_UDP_PAYLOAD;
use dedens_server::{Pipeline, Step, Upstream};
use futures_util::future::{join, join_all};
use futures_util::lock::Mutex;
use futures_util::stream::FuturesUnordered;
use futures_util::{Stream, StreamExt};

use super::isolate::{Listener, Origin};
use super::upstream::answer;
use super::{ERROR_PAUSE, Thread, pause};

/// Tasks answering on each UDP socket, taking turns at its datagrams: with the replies queued, 1, 2 and 4 serve
/// alike within noise, and two keep one free to take a datagram while the other answers (D48, D123).
pub(super) const UDP_RECEIVES: usize = 2;

/// Replies a UDP socket holds queued for its sender, as many in flight at most, and as many spare buffers kept: a
/// task with a reply waits for room in the queue (D123).
const UDP_SENDS: usize = 64;

/// Datagrams a thread holds received and not yet answered, in buffers made once: on Linux, `io_uring` fills them
/// without a receive asked for each datagram, and leaves the rest in the socket while all are taken. A power of
/// two.
pub(super) const UDP_BUFFERS: NonZero<u16> = NonZero::new(256).expect("256 is not zero");

/// The longest UDP query read whole: 4096 bytes, as a `DNSCrypt` packet may be (D49).
const UDP_QUERY_LEN: usize = 4096;

/// The header `io_uring` writes in front of a datagram it receives into a pool buffer (`io_uring_recvmsg_out`).
const URING_HEADER_LEN: usize = 16;

/// The room compio asks for the sender's address in the buffer: a `sockaddr_storage`, whatever the family.
const URING_ADDRESS_LEN: usize = 128;

/// The bytes of each buffer: a query of [`UDP_QUERY_LEN`] bytes, with what `io_uring` puts before it. A buffer holds
/// the datagram as it is, whatever its length, so it takes no page or alignment (D49). A longer query is cut short, so
/// read as broken.
pub(super) const UDP_BUFFER_LEN: usize = URING_HEADER_LEN + URING_ADDRESS_LEN + UDP_QUERY_LEN;

/// Bytes a UDP socket may hold before the OS drops datagrams (`SO_RCVBUF`).
pub(super) const UDP_RECEIVE_BUFFER: usize = 4 << 20;

/// Times a UDP task yields, one after the other, when no buffer is free, before it waits [`BUSY_PAUSE`] between tries.
const BUSY_YIELDS: u8 = 4;

/// How long a UDP task waits between tries once yielding has not freed a buffer: short, as a datagram waits in the
/// socket meanwhile, but long enough that a pool kept empty by another socket costs no busy loop.
const BUSY_PAUSE: Duration = Duration::from_millis(1);

/// Answers the queries of one UDP socket with [`UDP_RECEIVES`] tasks, from one stream of datagrams, and sends the
/// replies from one more future of its task (D123). `outbox` is the socket's, made with it: it outlives this loop,
/// so after a restart (D121) the replies of queries still waiting for upstream go out as before.
pub(super) async fn udp<N: Io>(
    socket: Rc<N::Udp>,
    outbox: Rc<Outbox>,
    listener: Listener,
    thread: Rc<Thread<N>>,
) {
    let datagrams = pin!(socket.recv_multi());
    let datagrams = Mutex::new(datagrams);
    let tasks = (0..UDP_RECEIVES).map(|_| udp_queries(&datagrams, &outbox, &listener, &thread));
    join(join_all(tasks), send_replies(&*socket, &outbox)).await;
}

/// A reply on its way out of a UDP socket: a slice of a buffer, so its length never passes the buffer's, and the
/// peer it is for.
struct Outgoing {
    reply: Slice<Vec<u8>>,
    peer: SocketAddr,
}

/// The replies the tasks of one UDP socket hand to its sender, and the buffers it gives back to make the next in.
/// It holds both ends of the queue, so queueing never fails, and the sender can start again on it.
pub(super) struct Outbox {
    queue: flume::Sender<Outgoing>,
    outgoing: flume::Receiver<Outgoing>,
    spare: RefCell<Vec<Vec<u8>>>,
}

impl Outbox {
    /// An empty outbox: [`UDP_SENDS`] replies wait in its queue.
    pub(super) fn new() -> Self {
        let (queue, outgoing) = flume::bounded(UDP_SENDS);
        let spare = RefCell::new(Vec::new());
        Self {
            queue,
            outgoing,
            spare,
        }
    }

    /// A buffer of [`DEFAULT_UDP_PAYLOAD`] bytes: a spare one if there is, else a new one.
    pub(super) fn buffer(&self) -> Vec<u8> {
        let spare = self.spare.borrow_mut().pop();
        spare.unwrap_or_else(|| vec![0; usize::from(DEFAULT_UDP_PAYLOAD)])
    }

    /// Queues the first `len` bytes of `buffer` for `peer`, once there is room.
    pub(super) async fn push(&self, buffer: Vec<u8>, len: usize, peer: SocketAddr) {
        let reply = buffer.slice(..len);
        // The outbox holds the receiver too: sending cannot fail.
        let _ = self.queue.send_async(Outgoing { reply, peer }).await;
    }

    /// Keeps a buffer a reply was sent from, if it is one of [`Outbox::buffer`]'s.
    fn give_back(&self, buffer: Vec<u8>) {
        let mut spare = self.spare.borrow_mut();
        if buffer.len() == usize::from(DEFAULT_UDP_PAYLOAD) && spare.len() < UDP_SENDS {
            spare.push(buffer);
        }
    }
}

/// Sends what `outbox` queues, [`UDP_SENDS`] at once at most, never ends. The tasks answering queue replies without
/// waiting for them to go out, so one turn of the runtime sends all they made in one submission, not one for each
/// task (`io_uring_enter` 0.255 → 0.005 a query, D123).
pub(super) async fn send_replies(socket: &impl Udp, outbox: &Outbox) {
    let mut incoming = outbox.outgoing.clone().into_stream();
    let mut sending = FuturesUnordered::new();
    poll_fn(|cx| {
        loop {
            while sending.len() < UDP_SENDS
                && let Poll::Ready(Some(Outgoing { reply, peer })) = incoming.poll_next_unpin(cx)
            {
                sending.push(send(socket, reply, peer));
            }
            // A send that ended makes room for a reply the queue already holds, which wakes no one.
            let mut ended = false;
            while let Poll::Ready(Some(buffer)) = sending.poll_next_unpin(cx) {
                outbox.give_back(buffer);
                ended = true;
            }
            if !ended {
                break Poll::<()>::Pending;
            }
        }
    })
    .await;
}

/// Receives that failed in a row on one task of a UDP socket, which decide how long it waits before the next (D107).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Receiving {
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

/// How often a task of a UDP socket warns at most of a receive error that repeats (D174).
const WARN_EVERY: Duration = Duration::from_secs(60);

/// When a task of a UDP socket last warned of a receive error that repeats. A lone error is logged at debug, as
/// before; one that repeats leaves the socket deaf, as compio's refused receive before Linux 6.0 did (D174), so it is
/// warned of, once a [`WARN_EVERY`] at most. Only a failed receive asks: a datagram costs nothing.
#[derive(Default)]
pub(super) struct Warned(Option<Instant>);

impl Warned {
    /// Whether a receive that failed at `now`, `busy` if for a lack of free buffers, after its task was `before`, is
    /// to be warned of: an error other than `Busy` following another, with no warning in the last [`WARN_EVERY`].
    fn due(&mut self, before: Receiving, busy: bool, now: Instant) -> bool {
        let repeats = !busy && before == Receiving::Failed;
        let quiet = self
            .0
            .is_none_or(|last| now.saturating_duration_since(last) >= WARN_EVERY);
        if repeats && quiet {
            self.0 = Some(now);
        }
        repeats && quiet
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

/// What a task of a UDP socket does after a receive failed with `error`: logs it, and waits as `receiving` says.
pub(super) async fn receive_failed<N: Io>(
    error: &io::Error,
    receiving: &mut Receiving,
    warned: &mut Warned,
    listener: &Listener,
    thread: &Thread<N>,
) {
    let busy = error.kind() == io::ErrorKind::ResourceBusy;
    if warned.due(*receiving, busy, thread.io.now()) {
        tracing::warn!(%error, %listener, "UDP receive fails again, retried every {ERROR_PAUSE:?}");
    } else {
        tracing::debug!(%error, "UDP receive");
    }
    // Only this task pauses: the socket's other tasks go on receiving (D107).
    match receiving.failed(busy) {
        Pause::None => {}
        Pause::Yield => yield_now().await,
        Pause::Sleep(time) => pause(&thread.io, time).await,
    }
}

/// Answers queries from `datagrams`, one after the other; the lock passes the stream to the next task once a
/// datagram is taken. Replies are queued in `outbox` (D123).
async fn udp_queries<N: Io, D: Datagram>(
    datagrams: &Mutex<impl Stream<Item = io::Result<D>> + Unpin>,
    outbox: &Rc<Outbox>,
    listener: &Listener,
    thread: &Rc<Thread<N>>,
) {
    let mut out = outbox.buffer();
    let mut receiving = Receiving::Fine;
    let mut warned = Warned::default();
    loop {
        // The lock is given back at the end of this statement, before any pause (D107).
        let next = datagrams.lock().await.next().await;
        // An empty datagram ends a stream for a moment: the next poll receives again.
        let datagram = match next {
            Some(Ok(datagram)) => datagram,
            Some(Err(error)) => {
                receive_failed(&error, &mut receiving, &mut warned, listener, thread).await;
                continue;
            }
            None => continue,
        };
        receiving = Receiving::Fine;
        let Some(peer) = datagram.peer() else {
            continue;
        };
        let pipeline = thread.pipeline();
        // A panic anywhere in the datagram's turn costs this query, not the socket (D121).
        let stepped = listener
            .guard_async(
                peer,
                udp_step(outbox, &pipeline, datagram, peer, thread.now(), &mut out),
            )
            .await;
        let Some(Some(upstream)) = stepped else {
            continue;
        };
        let Some(slot) = thread.upstream.take() else {
            tracing::debug!(%peer, "too many upstream queries: dropped");
            continue;
        };
        let (outbox, thread) = (Rc::clone(outbox), Rc::clone(thread));
        Origin::new(listener, peer).spawn(&thread.io.clone(), async move {
            let deliver = async |reply: Vec<u8>| {
                let len = reply.len();
                outbox.push(reply, len, peer).await;
            };
            answer(&thread, &pipeline, upstream, Transport::Udp, deliver).await;
            drop(slot);
        });
    }
}

/// The turn of one datagram at `now`, the cache's clock: the pipeline's first step, the reply it makes sent, and the
/// upstream query it leaves, if any. The datagram's buffer goes back to the pool before the reply waits to be sent.
async fn udp_step(
    outbox: &Outbox,
    pipeline: &Pipeline,
    datagram: impl Datagram,
    peer: SocketAddr,
    now: u32,
    out: &mut Vec<u8>,
) -> Option<Box<Upstream>> {
    let step = pipeline.query(datagram.data(), Transport::Udp, peer.ip(), now, out);
    drop(datagram);
    let (len, upstream) = match step {
        Step::Reply(len) => (Some(len), None),
        Step::Drop => (None, None),
        Step::Upstream(upstream) => (None, Some(upstream)),
        Step::Refresh(len, upstream) => (Some(len), Some(upstream)),
    };
    if let Some(len) = len {
        outbox
            .push(std::mem::replace(out, outbox.buffer()), len, peer)
            .await;
    }
    upstream
}

/// Sends `reply` to `peer`, and gives its buffer back, to [`send_replies`].
async fn send(socket: &impl Udp, reply: Slice<Vec<u8>>, peer: SocketAddr) -> Vec<u8> {
    let BufResult(sent, out) = socket.send_to(reply, peer).await;
    if let Err(error) = sent {
        tracing::debug!(%error, %peer, "UDP send");
    }
    out.into_inner()
}

// The tests run sockets and a runtime, which loom's threads and locks cannot drive (D135).
#[cfg(test)]
#[cfg(not(dedens_loom))]
#[expect(
    clippy::disallowed_methods,
    reason = "the tests run on compio's runtime, clock and sockets"
)]
mod tests {
    use std::cell::Cell;
    use std::io;
    use std::net::SocketAddr;
    use std::pin::pin;
    use std::rc::Rc;
    use std::sync::Arc;
    use std::time::{Duration, Instant};

    use compio::BufResult;
    use compio::driver::op::RecvFromMultiResult;
    use compio::net::UdpSocket;
    use compio::runtime::{Runtime, spawn};
    use dedens_net::tls::Trust;
    use dedens_server::Pipeline;
    use futures_util::Stream;
    use futures_util::future::{Either, join, select};
    use futures_util::lock::Mutex;
    use futures_util::stream::repeat_with;
    use socket2::{Domain, Socket, Type};

    use super::{
        BUSY_PAUSE, BUSY_YIELDS, Outbox, Pause, Receiving, UDP_BUFFER_LEN, UDP_BUFFERS, UDP_SENDS,
        WARN_EVERY, Warned, send_replies, udp_queries,
    };
    use crate::reload::Current;
    use crate::serve::tests::udp_listener;
    use crate::serve::{ERROR_PAUSE, Thread};

    /// D49 states the pool's memory: 256 buffers of 4240 bytes (16 of `io_uring`'s header, 128 of the address, 4096 of
    /// query), 1,085,440 bytes a thread. A change of either number is a change of that decision.
    #[test]
    fn the_pool_holds_what_d49_says() {
        assert_eq!(UDP_BUFFER_LEN, 4240);
        assert_eq!(usize::from(UDP_BUFFERS.get()) * UDP_BUFFER_LEN, 1_085_440);
    }

    #[test]
    fn a_yield_lets_the_other_tasks_run() {
        let ran = Rc::new(Cell::new(false));
        Runtime::new().expect("a runtime").block_on(async {
            let flag = Rc::clone(&ran);
            spawn(async move { flag.set(true) }).detach();
            super::yield_now().await;
            assert!(ran.get());
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
            let outbox = Rc::new(Outbox::new());
            let receiving = pin!(udp_queries(&datagrams, &outbox, &name, &thread));
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
            let polls = Cell::new(0);
            let datagrams = failing(io::ErrorKind::ResourceBusy, &polls);
            let thread = idle();
            let name = udp_listener();
            let outbox = Rc::new(Outbox::new());
            let receiving = udp_queries(&datagrams, &outbox, &name, &thread);
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

    /// D174: a receive error that repeats is warned of, once a [`WARN_EVERY`] at most; a lone error, or a lack of
    /// free buffers, is not.
    #[test]
    fn a_receive_error_that_repeats_is_warned_about() {
        let start = Instant::now();
        let mut warned = Warned::default();
        assert!(!warned.due(Receiving::Fine, false, start), "a lone error");
        assert!(
            !warned.due(Receiving::Busy(2), true, start),
            "no free buffer"
        );
        assert!(
            !warned.due(Receiving::Busy(2), false, start),
            "after no free buffer"
        );
        assert!(warned.due(Receiving::Failed, false, start));
        let soon = start + ERROR_PAUSE;
        assert!(
            !warned.due(Receiving::Failed, false, soon),
            "warned already"
        );
        assert!(!warned.due(
            Receiving::Failed,
            false,
            start + WARN_EVERY.saturating_sub(ERROR_PAUSE)
        ));
        assert!(warned.due(Receiving::Failed, false, start + WARN_EVERY));
    }

    /// D123: a socket holds [`UDP_SENDS`] replies for its sender, and the task queueing one more waits for room.
    #[test]
    fn a_full_outbox_makes_the_next_reply_wait() {
        let runtime = Runtime::new().expect("a runtime");
        runtime.block_on(async {
            let outbox = Outbox::new();
            let peer = SocketAddr::from(([127, 0, 0, 1], 9));
            for _ in 0..UDP_SENDS {
                outbox.push(outbox.buffer(), 1, peer).await;
            }
            let waits = compio::time::timeout(
                Duration::from_millis(50),
                outbox.push(outbox.buffer(), 1, peer),
            )
            .await;
            assert!(waits.is_err(), "a reply went past the queue's bound");
        });
    }

    /// A socket bound on loopback, whose datagram queue holds several thousand small ones.
    fn client() -> UdpSocket {
        let socket = Socket::new(Domain::IPV4, Type::DGRAM, None).expect("a socket");
        socket.set_recv_buffer_size(4 << 20).expect("a buffer size");
        socket
            .bind(&SocketAddr::from(([127, 0, 0, 1], 0)).into())
            .expect("bound");
        UdpSocket::from_std(socket.into()).expect("a socket for the runtime")
    }

    /// Receives `count` replies of two bytes, a number each, and says which numbers came.
    async fn numbers(client: &UdpSocket, count: usize) -> Vec<bool> {
        let mut seen = vec![false; count];
        for _ in 0..count {
            let BufResult(received, buffer) = client.recv_from(vec![0; 512]).await;
            assert_eq!(received.expect("received").0, 2);
            seen[usize::from(u16::from_be_bytes([buffer[0], buffer[1]]))] = true;
        }
        seen
    }

    /// Queues the reply `number` for `peer`.
    async fn queue_number(outbox: &Outbox, number: usize, peer: SocketAddr) {
        let mut buffer = outbox.buffer();
        buffer[..2].copy_from_slice(&u16::try_from(number).expect("fits").to_be_bytes());
        outbox.push(buffer, 2, peer).await;
    }

    /// D123: every reply queued reaches its peer, more than the sender holds in flight, and the buffers it sent come
    /// back to make the next replies in.
    #[test]
    fn queued_replies_are_all_sent_and_their_buffers_reused() {
        const REPLIES: usize = 3 * UDP_SENDS;
        let runtime = Runtime::new().expect("a runtime");
        runtime.block_on(async {
            let server = UdpSocket::bind("127.0.0.1:0").await.expect("bound");
            let client = client();
            let peer = client.local_addr().expect("its address");
            let outbox = Outbox::new();
            let queueing = async {
                for number in 0..REPLIES {
                    queue_number(&outbox, number, peer).await;
                }
            };
            let both = pin!(join(queueing, numbers(&client, REPLIES)));
            let sending = pin!(send_replies(&server, &outbox));
            let within = compio::time::timeout(Duration::from_secs(5), select(both, sending));
            let Either::Left((((), seen), _)) = within.await.expect("every reply within 5 s")
            else {
                panic!("the sender never ends");
            };
            assert!(seen.iter().all(|seen| *seen), "a reply never came");
            assert!(!outbox.spare.borrow().is_empty(), "no buffer came back");
            assert!(outbox.spare.borrow().len() <= UDP_SENDS);
        });
    }

    /// D123: a send that fails costs its reply, not the sender nor the replies behind it.
    #[test]
    fn a_failed_send_costs_only_its_reply() {
        const REPLIES: usize = 10;
        let runtime = Runtime::new().expect("a runtime");
        runtime.block_on(async {
            let server = UdpSocket::bind("127.0.0.1:0").await.expect("bound");
            let client = client();
            let peer = client.local_addr().expect("its address");
            let outbox = Outbox::new();
            // An IPv6 peer, from an IPv4 socket: the kernel refuses it.
            let refused = SocketAddr::from((std::net::Ipv6Addr::LOCALHOST, 9));
            outbox.push(outbox.buffer(), 2, refused).await;
            for number in 0..REPLIES {
                queue_number(&outbox, number, peer).await;
            }
            let sending = send_replies(&server, &outbox);
            let receiving =
                compio::time::timeout(Duration::from_secs(5), numbers(&client, REPLIES));
            let Either::Left((seen, _)) = select(pin!(receiving), pin!(sending)).await else {
                panic!("the sender never ends");
            };
            let seen = seen.expect("every reply within 5 s");
            assert!(seen.iter().all(|seen| *seen), "a reply never came");
        });
    }

    /// D121, D123: the outbox outlives the sender, so replies queued while no sender runs, as between a listener
    /// loop's end and its restart, go out when the next one starts.
    #[test]
    fn a_new_sender_sends_what_the_last_one_left_queued() {
        const REPLIES: usize = 10;
        let runtime = Runtime::new().expect("a runtime");
        runtime.block_on(async {
            let server = UdpSocket::bind("127.0.0.1:0").await.expect("bound");
            let client = client();
            let peer = client.local_addr().expect("its address");
            let outbox = Outbox::new();
            // A sender that ends: dropped by a restart.
            let first =
                compio::time::timeout(Duration::from_millis(20), send_replies(&server, &outbox));
            assert!(first.await.is_err(), "the sender never ends");
            // Queueing waits for no sender, whatever the sender's end.
            let queued = compio::time::timeout(Duration::from_millis(50), async {
                for number in 0..REPLIES {
                    queue_number(&outbox, number, peer).await;
                }
            });
            queued.await.expect("queued at once");
            let sending = send_replies(&server, &outbox);
            let receiving =
                compio::time::timeout(Duration::from_secs(5), numbers(&client, REPLIES));
            let Either::Left((seen, _)) = select(pin!(receiving), pin!(sending)).await else {
                panic!("the sender never ends");
            };
            assert!(
                seen.expect("every reply within 5 s")
                    .iter()
                    .all(|seen| *seen)
            );
        });
    }
}
