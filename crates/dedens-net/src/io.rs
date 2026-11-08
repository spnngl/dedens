//! The seam between the pools and the runtime (D134): the clock, tasks, timers, randomness and sockets the UDP and
//! TCP pools use, behind one trait.
//!
//! [`Compio`] is production: each method forwards to compio, and the pools, generic over [`Io`], compile to the
//! calls they made before. A test supplies another [`Io`], such as `dedens-sim`'s on a simulated network, and runs
//! the same pools on it. Buffers are owned and come back with the result, as compio's do (D4).
//!
//! The pools read no clock, spawn no task and open no socket but through their `Io`: `udp`, `tcp` and `client` deny
//! `clippy::disallowed_methods`, whose list in the crate's `clippy.toml` fails their build when one does. The other
//! modules on compio call it directly (D134): `quic`, `dial`, `http3` and `odoh::client` run on compio's QUIC,
//! which has its own endpoint and clock, and no simulation runs `doc` yet. The lint is allowed elsewhere, as clippy
//! takes its list per crate, not per module.

use std::fmt::Debug;
use std::future::Future;
use std::io;
use std::net::SocketAddr;
use std::time::Instant;

use compio::BufResult;
use compio::buf::{IoBuf, IoBufMut};
use compio::io::util::Splittable;
use compio::io::{AsyncRead, AsyncWrite};
use compio::net::{TcpStream, UdpSocket};
use compio::runtime::JoinHandle;

use crate::exchange::Exchange;

/// A [`Io::timeout_at`] whose deadline passed before its future finished.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TimedOut;

/// What the pools ask of the runtime. One value per thread of one runtime, cloned into the tasks it spawns.
#[expect(
    async_fn_in_trait,
    reason = "tasks stay on their thread, as compio's do: no caller needs the futures to be `Send`"
)]
pub trait Io: Clone + Debug + 'static {
    /// A UDP socket.
    type Udp: Udp;
    /// A TCP connection.
    type Stream: Stream;
    /// A spawned task: dropping it cancels the task.
    type Task: Debug + 'static;

    /// The time now, from the clock all of this `Io`'s timers run on.
    fn now(&self) -> Instant;

    /// Runs `task` on this thread's runtime until it ends or the returned handle drops.
    fn spawn(&self, task: impl Future<Output = ()> + 'static) -> Self::Task;

    /// The output of `future`, or [`TimedOut`] once `deadline` passes first. The one timer: a pause is a timeout
    /// on a future that never ends.
    async fn timeout_at<F: Future>(
        &self,
        deadline: Instant,
        future: F,
    ) -> Result<F::Output, TimedOut>;

    /// Called by `Client` each time it is about to send `exchange`'s query, a try of the exchange: a trace's hook,
    /// nothing in production. The TCP pool's own resend of a query whose connection closed (D27) is not a try and
    /// does not call it.
    #[inline]
    fn sending(&self, exchange: &Exchange) {
        let _ = exchange;
    }

    /// Fills `bytes` with random bytes.
    ///
    /// # Errors
    ///
    /// The system has no randomness to give.
    fn random(&self, bytes: &mut [u8]) -> io::Result<()>;

    /// A UDP socket bound to `addr`.
    ///
    /// # Errors
    ///
    /// The socket cannot be opened or bound.
    async fn udp_bind(&self, addr: SocketAddr) -> io::Result<Self::Udp>;

    /// A TCP connection to `addr`.
    ///
    /// # Errors
    ///
    /// The connection is refused, reset, unreachable, or fails otherwise.
    async fn tcp_connect(&self, addr: SocketAddr) -> io::Result<Self::Stream>;
}

/// A UDP socket.
#[expect(
    async_fn_in_trait,
    reason = "tasks stay on their thread, as compio's do: no caller needs the futures to be `Send`"
)]
pub trait Udp: Debug + 'static {
    /// Its local address.
    ///
    /// # Errors
    ///
    /// The socket is closed.
    fn local_addr(&self) -> io::Result<SocketAddr>;

    /// Connects it to `addr`: from then on it sends there, and receives only from there.
    ///
    /// # Errors
    ///
    /// No route to `addr`.
    async fn connect(&self, addr: SocketAddr) -> io::Result<()>;

    /// Receives one datagram of the connected peer into `buffer`, which keeps what a longer one would not fit.
    async fn recv<B: IoBufMut>(&self, buffer: B) -> BufResult<usize, B>;

    /// Sends `buffer` as one datagram to the connected peer.
    async fn send<B: IoBuf>(&self, buffer: B) -> BufResult<usize, B>;
}

/// A TCP connection: split into a reading and a writing half, as compio's is.
pub trait Stream:
    Splittable<ReadHalf: AsyncRead + Unpin + 'static, WriteHalf: AsyncWrite + Unpin + 'static> + 'static
{
    /// Its local address.
    ///
    /// # Errors
    ///
    /// The connection is closed.
    fn local_addr(&self) -> io::Result<SocketAddr>;

    /// Sends small writes without delay (`TCP_NODELAY`) or not.
    ///
    /// # Errors
    ///
    /// The connection is closed.
    fn set_nodelay(&self, nodelay: bool) -> io::Result<()>;
}

/// The production [`Io`]: compio's runtime, timers and sockets, the system's clock and randomness.
#[derive(Debug, Clone, Copy, Default)]
pub struct Compio;

impl Io for Compio {
    type Udp = UdpSocket;
    type Stream = TcpStream;
    type Task = JoinHandle<()>;

    #[inline]
    fn now(&self) -> Instant {
        Instant::now()
    }

    #[inline]
    fn spawn(&self, task: impl Future<Output = ()> + 'static) -> Self::Task {
        compio::runtime::spawn(task)
    }

    #[inline]
    async fn timeout_at<F: Future>(
        &self,
        deadline: Instant,
        future: F,
    ) -> Result<F::Output, TimedOut> {
        compio::time::timeout_at(deadline, future)
            .await
            .map_err(|_| TimedOut)
    }

    #[inline]
    fn random(&self, bytes: &mut [u8]) -> io::Result<()> {
        getrandom::fill(bytes).map_err(io::Error::other)
    }

    #[inline]
    async fn udp_bind(&self, addr: SocketAddr) -> io::Result<Self::Udp> {
        UdpSocket::bind(addr).await
    }

    #[inline]
    async fn tcp_connect(&self, addr: SocketAddr) -> io::Result<Self::Stream> {
        TcpStream::connect(addr).await
    }
}

impl Udp for UdpSocket {
    #[inline]
    fn local_addr(&self) -> io::Result<SocketAddr> {
        Self::local_addr(self)
    }

    #[inline]
    async fn connect(&self, addr: SocketAddr) -> io::Result<()> {
        Self::connect(self, addr).await
    }

    #[inline]
    async fn recv<B: IoBufMut>(&self, buffer: B) -> BufResult<usize, B> {
        Self::recv(self, buffer).await
    }

    #[inline]
    async fn send<B: IoBuf>(&self, buffer: B) -> BufResult<usize, B> {
        Self::send(self, buffer).await
    }
}

impl Stream for TcpStream {
    #[inline]
    fn local_addr(&self) -> io::Result<SocketAddr> {
        Self::local_addr(self)
    }

    #[inline]
    fn set_nodelay(&self, nodelay: bool) -> io::Result<()> {
        Self::set_nodelay(self, nodelay)
    }
}
