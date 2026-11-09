//! The sockets of one thread and the tasks answering on them (D42): a task per UDP socket and per TCP listener,
//! one per TCP connection, and one per query that waits for an upstream server. Replies the pipeline builds at
//! once are queued for the socket's sender, one more future of its task (D123); the rest are asked upstream with
//! the thread's `dedens_net` client.
//! Each thread bounds its upstream queries and TCP connections, each connection its queries in flight, the bytes
//! of its replies waiting to be written and the time they take to write (D47). A task that panics ends alone, and
//! a listener's loop that ends starts again (D121).
//!
//! One file a transport: `udp.rs`, `tcp.rs` (and TLS), `quic.rs` (`DoQ`), `http3.rs` (`DoH` and `ODoH`), `coap.rs` (`DoC`);
//! `upstream.rs` asks upstream, `isolate.rs` contains panics, `h3_budget.rs` rotates HTTP/3 connections.

#[cfg(feature = "doc")]
mod coap;
mod h3_budget;
mod http3;
pub(crate) mod isolate;
mod quic;
mod tcp;
mod udp;
mod upstream;

use std::cell::{Cell, RefCell};
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::rc::Rc;
use std::sync::{Arc, LazyLock, mpsc};
use std::time::{Duration, Instant};

use anyhow::Context;
use compio::driver::{DriverType, ProactorBuilder};
use compio::net::UdpSocket;
use compio::runtime::{JoinHandle, Runtime, spawn};
use dedens_net::client::Client;
use dedens_net::tls::{self, Presented, Trust};
use dedens_proto::{MAX_MESSAGE_LEN, Transport};
use dedens_server::{Pipeline, Step, Upstream};
use futures_util::future::select_all;
use socket2::{Domain, Socket, Type};

use self::h3_budget::Connections;
use self::http3::H3_UNI_STREAMS;
use self::isolate::{BACKOFF, Backoff, Listener, supervise};
use self::quic::{Service, quic_task};
use self::tcp::{TCP_BACKLOG, TCP_CONNECTIONS, tcp_task};
use self::udp::{Outbox, UDP_BUFFER_LEN, UDP_BUFFERS, UDP_RECEIVE_BUFFER, udp};
use crate::config::Listen;
#[cfg(feature = "odoh")]
use crate::odoh;
#[cfg(feature = "odoh")]
use crate::odoh::proxy::Forwarder;
use crate::reload::Current;
use crate::sync;

/// How long a TCP connection stays open without a query (RFC 7766 §6.2.3).
const TCP_IDLE: Duration = Duration::from_secs(10);

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

/// What the tasks of one thread share.
struct Thread {
    current: Arc<Current>,
    /// A message each time a reload replaced the pipeline, for [`follow`].
    reloads: sync::Receiver<()>,
    /// The pipeline taken from `current`, with its generation; behind an `Rc`, so a query holding it touches no
    /// count shared with other threads.
    // Loom's `Arc` is not clippy's.
    #[cfg_attr(
        not(dedens_loom),
        expect(
            clippy::redundant_allocation,
            reason = "an `Arc` count is shared with every thread, an `Rc` one not"
        )
    )]
    pipeline: RefCell<(u64, Rc<sync::Arc<Pipeline>>)>,
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
    odoh: Option<Arc<odoh::Service>>,
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
    // Loom's `Arc` is not clippy's.
    #[cfg_attr(
        not(dedens_loom),
        expect(
            clippy::redundant_allocation,
            reason = "an `Arc` count is shared with every thread, an `Rc` one not"
        )
    )]
    fn pipeline(&self) -> Rc<sync::Arc<Pipeline>> {
        let mut held = self.pipeline.borrow_mut();
        if let Some((generation, pipeline)) = self.current.newer(held.0) {
            *held = (generation, Rc::new(pipeline));
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

/// The runtime of a serving thread, with [`UDP_BUFFERS`] buffers of [`UDP_BUFFER_LEN`] bytes for UDP queries, on
/// `poll` on Linux before 6.0 (D174).
///
/// # Errors
///
/// A runtime the OS refuses.
pub(crate) fn runtime() -> io::Result<Runtime> {
    #[cfg(target_os = "linux")]
    let driver = (!io_uring_serves(kernel_release())).then_some(DriverType::Poll);
    #[cfg(not(target_os = "linux"))]
    let driver = None;
    runtime_on(driver)
}

/// The first Linux release `dedensd` serves on `io_uring` from (D174): compio receives UDP datagrams by multishot
/// `recvmsg` from 6.0 only, and before it pops buffers from the ring by hand, which its `io_uring` pool refuses, so
/// a UDP socket would receive nothing.
#[cfg(any(target_os = "linux", test))]
const IO_URING_FLOOR: (u32, u32) = (6, 0);

/// Whether a Linux kernel of `release`, its major and minor numbers, serves on `io_uring`: from
/// [`IO_URING_FLOOR`], and not when its release could not be read.
#[cfg(any(target_os = "linux", test))]
fn io_uring_serves(release: Option<(u32, u32)>) -> bool {
    release.is_some_and(|release| release >= IO_URING_FLOOR)
}

/// The major and minor numbers of the running kernel, `None` when unread.
#[cfg(target_os = "linux")]
fn kernel_release() -> Option<(u32, u32)> {
    let uname = nix::sys::utsname::uname().ok()?;
    parse_release(uname.release().to_str()?)
}

/// The major and minor numbers of a kernel release such as `6.8.0-45-generic` or `6.1-rc3`.
#[cfg(any(target_os = "linux", test))]
fn parse_release(release: &str) -> Option<(u32, u32)> {
    // The digits a part starts with: `0-rc1` is 0.
    let mut numbers = release.split('.').map(|part| {
        let digits = part.split(|c: char| !c.is_ascii_digit()).next()?;
        digits.parse::<u32>().ok()
    });
    Some((numbers.next()??, numbers.next()??))
}

/// [`runtime`] on `driver`, or on the one compio picks when `None`.
fn runtime_on(driver: Option<DriverType>) -> io::Result<Runtime> {
    let mut proactor = ProactorBuilder::new();
    if let Some(driver) = driver {
        proactor.driver_type(driver);
    }
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
    #[cfg(feature = "odoh")] odoh: Option<Arc<odoh::Service>>,
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
                // Made here, not in `udp`, so a restart of the loop keeps it (D123).
                let outbox = Rc::new(Outbox::new());
                tasks.push(supervised(name, &thread, move |name, thread| {
                    udp(
                        Rc::clone(&socket),
                        Rc::clone(&outbox),
                        name.clone(),
                        Rc::clone(thread),
                    )
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

/// Seconds since the first call, the clock of the cache (D43).
fn now() -> u32 {
    static START: LazyLock<Instant> = LazyLock::new(Instant::now);
    u32::try_from(START.elapsed().as_secs()).unwrap_or(u32::MAX)
}

// The tests run sockets and a runtime, which loom's threads and locks cannot drive (D135).
#[cfg(test)]
#[cfg(not(dedens_loom))]
mod tests {
    use std::cell::Cell;
    use std::net::{IpAddr, SocketAddr};
    use std::pin::pin;
    use std::rc::Rc;
    use std::sync::Arc;
    use std::time::{Duration, Instant};

    use compio::BufResult;
    use compio::driver::DriverType;
    use compio::io::AsyncWriteExt;
    use compio::net::{TcpListener, TcpStream, UdpSocket};
    use compio::runtime::{Runtime, spawn};
    use dedens_net::tcp::{frame, read_message};
    use dedens_net::tls::Trust;
    use dedens_proto::{Message, Question, Rcode, RecordType, Transport};
    use dedens_server::{Answer, Forward, Pipeline, Plugin, Reviewer, Stage, Step};
    use futures_util::future::select;
    use metrics_util::debugging::DebuggingRecorder;
    use socket2::{Domain, Socket, Type};

    use super::isolate::tests::counted;
    use super::isolate::{Backoff, Listener};
    use super::tcp::{TCP_PENDING, tcp};
    use super::udp::{Outbox, udp};
    use super::{
        Slots, Started, Thread, UPSTREAM_QUERIES, first_end, follow, io_uring_serves, now,
        parse_release, runtime, runtime_on, socket, start, supervised_with,
    };
    use crate::lists::Store;
    use crate::reload::Current;

    pub(super) fn udp_listener() -> Listener {
        Listener::new("udp", Some(SocketAddr::from(([127, 0, 0, 1], 53))))
    }

    /// A query for `example.com` A, ID 7, and the response captured from 1.1.1.1 (`dedens-proto`'s `a.bin`).
    pub(super) fn example_com_a() -> (Vec<u8>, Vec<u8>) {
        let query = dedens_testkit::query("a", 7)
            .to_vec()
            .expect("a query fits");
        (query, dedens_testkit::captured("a"))
    }

    #[test]
    fn a_socket_names_its_listener_by_its_address() {
        let socket = Socket::new(Domain::IPV4, Type::DGRAM, None).expect("a socket");
        let asked = SocketAddr::from(([127, 0, 0, 1], 0));
        socket.bind(&asked.into()).expect("bound");
        let bound = super::local(&socket).expect("its address");
        assert_eq!(bound.ip(), asked.ip());
        assert_ne!(bound.port(), 0);
    }

    /// A TCP listener reuses its address, so that a restarted server binds while the last one's connections wait
    /// out `TIME_WAIT`; a UDP socket has nothing to wait out.
    #[test]
    fn a_tcp_socket_reuses_its_address() {
        let addr = SocketAddr::from(([127, 0, 0, 1], 0));
        let tcp = socket(addr, Type::STREAM).expect("a TCP socket");
        assert!(tcp.reuse_address().expect("read"));
        let udp = socket(addr, Type::DGRAM).expect("a UDP socket");
        assert!(!udp.reuse_address().expect("read"));
    }

    /// A cache hit that asks for a prefetch is sent to the client, then asked upstream in a place of the thread's
    /// upstream queries: the captured response of `example.com` A, cached a second ago, is past
    /// `prefetch_percent: 100`.
    #[test]
    fn a_hit_to_prefetch_is_sent_then_asked_upstream() {
        let text = "listen: ['127.0.0.1:53']\npipeline: [cache, up]\nstages:\n  cache:\n    type: cache\n    prefetch_percent: 100\n  up:\n    type: forward\n    servers: ['192.0.2.1']\n";
        let config =
            crate::config::read(text, |_| None, &Pipeline::default(), &mut Store::default())
                .expect("read");
        let thread = Thread::new(Arc::new(Current::new(config.pipeline)), 1, Trust::default());
        let pipeline = thread.pipeline();
        let (query, response) = example_com_a();
        let from = IpAddr::from([127, 0, 0, 1]);
        let mut out = vec![0; 65535];
        let cached_at = now();
        let Step::Upstream(upstream) =
            pipeline.query(&query, Transport::Tcp, from, cached_at, &mut out)
        else {
            panic!("a miss")
        };
        let step = pipeline.receive(upstream, Some(&response), cached_at, &mut out);
        assert!(matches!(step, Step::Reply(_)), "{step:?}");
        let deadline = Instant::now() + Duration::from_secs(3);
        while now() == cached_at && Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(20));
        }
        let mut sent = 0;
        let started = start(&thread, &pipeline, &query, Transport::Tcp, from, |_| {
            sent += 1;
            true
        });
        assert_eq!(sent, 1, "the cached reply");
        assert!(matches!(started, Some(Started::Upstream(..))));
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
                let outbox = Rc::new(Outbox::new());
                spawn(udp(udp_socket, outbox, udp_listener(), Rc::clone(&thread))).detach();
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
                let wanted = u64::try_from(TCP_PENDING + 1).expect("65 fits");
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
        assert_eq!(
            total.get(),
            u64::try_from(TCP_PENDING + 1).expect("65 fits")
        );
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
                let outbox = Rc::new(Outbox::new());
                let (poke, poked) = flume::bounded::<()>(1);
                let mut turns = 0;
                let supervisor =
                    supervised_with(QUICK, udp_listener(), &thread, move |name, thread| {
                        turns += 1;
                        let first = turns == 1;
                        let (socket, outbox) = (Rc::clone(&socket), Rc::clone(&outbox));
                        let (name, thread) = (name.clone(), Rc::clone(thread));
                        let poked = poked.clone();
                        async move {
                            if first {
                                let serving = pin!(udp(socket, outbox, name, thread));
                                select(serving, pin!(poked.recv_async())).await;
                                panic!("a bug");
                            }
                            udp(socket, outbox, name, thread).await;
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

    /// D107, D147: on the `poll` driver, which compio falls back to where the ring cannot be made (a container's
    /// default seccomp profile), a UDP query is answered: its datagram keeps its length.
    #[test]
    fn a_udp_socket_answers_on_the_poll_driver() {
        runtime_on(Some(DriverType::Poll))
            .expect("a runtime")
            .block_on(async {
                assert_eq!(
                    Runtime::with_current(Runtime::driver_type),
                    DriverType::Poll
                );
                let thread = answering();
                let socket = Rc::new(UdpSocket::bind("127.0.0.1:0").await.expect("bound"));
                let server = socket.local_addr().expect("its address");
                let serving = spawn(udp(socket, Rc::new(Outbox::new()), udp_listener(), thread));
                assert_eq!(answers(server).await, 1);
                drop(serving);
            });
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
            let outbox = Rc::new(Outbox::new());
            let mut turns = 0;
            let supervisor =
                supervised_with(QUICK, udp_listener(), &thread, move |name, thread| {
                    turns += 1;
                    let last = turns > 100;
                    let (socket, outbox) = (Rc::clone(&socket), Rc::clone(&outbox));
                    let (name, thread) = (name.clone(), Rc::clone(thread));
                    async move {
                        if last {
                            udp(socket, outbox, name, thread).await;
                        } else {
                            let serving = pin!(udp(socket, outbox, name, thread));
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

    /// D174: before Linux 6.0 compio receives UDP by popping buffers its `io_uring` pool refuses, so the threads
    /// serve on `poll` there, as on a kernel whose release does not read.
    #[test]
    fn a_kernel_before_6_0_serves_on_poll() {
        assert!(!io_uring_serves(Some((5, 19))));
        assert!(io_uring_serves(Some((6, 0))));
        assert!(io_uring_serves(Some((10, 1))));
        assert!(!io_uring_serves(None));
        assert_eq!(parse_release("5.19.17"), Some((5, 19)));
        assert_eq!(parse_release("6.8.0-45-generic"), Some((6, 8)));
        assert_eq!(parse_release("6.1-rc3"), Some((6, 1)));
        assert_eq!(
            parse_release("5.15.153.1-microsoft-standard-WSL2"),
            Some((5, 15))
        );
        assert_eq!(parse_release("6"), None);
        assert_eq!(parse_release(""), None);
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
