//! The simulated side of the seam (D134): [`Sim`] is `dedens_net::io::Io` on turmoil's sockets and tokio's clock, so
//! the real `UdpPool`, `TcpPool` and `Client` run on the simulated network of a host, and `dedensd`'s serving loop of
//! UDP and TCP on [`SimUdp`] and [`SimListener`] (D182).
//!
//! Time is tokio's, which turmoil pauses and advances, and the randomness is the host's seeded stream: a run
//! replays. turmoil's sockets speak tokio's traits and borrowed buffers; the adapters here speak compio's owned
//! ones, copying through a scratch buffer, which a test can afford.

use std::any::Any;
use std::cell::{Cell, RefCell};
use std::future::Future;
use std::net::{IpAddr, SocketAddr};
use std::panic::resume_unwind;
use std::rc::Rc;
use std::time::Instant;
use std::{fmt, io};

use compio::BufResult;
use compio::buf::{IoBuf, IoBufMut};
use compio::io::util::Splittable;
use compio::io::{AsyncRead, AsyncWrite};
use dedens_net::exchange::Exchange;
use dedens_net::io::{Datagram, Io, Listener, Stream, TimedOut, Udp};
use dedens_net::tcp::Outbound;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::task::AbortHandle;
use turmoil::net::tcp::{OwnedReadHalf, OwnedWriteHalf};
use turmoil::net::{TcpListener, TcpStream, UdpSocket};

use crate::seed::Rng;
use crate::trace::{Trace, What};

/// The longest datagram `dedensd`'s loop reads whole on `io_uring`: a buffer of its pool, 4096 bytes, less the
/// kernel's 16-byte header and the 128 bytes compio keeps for the sender's address (D49). A longer one is cut, as
/// there.
const DATAGRAM_LEN: usize = 4096 - 16 - 128;

/// Errors to inject into the connected UDP sockets of one [`Sim`], a client's: the next `n` sends, or the next `n`
/// arrivals.
#[derive(Debug, Default)]
pub struct Glitches {
    sends: Cell<u32>,
    receives: Cell<u32>,
}

impl Glitches {
    /// Fails the next `n` sends before anything leaves the socket.
    pub fn fail_sends(&self, n: u32) {
        self.sends.set(n);
    }

    /// Fails the next `n` receives, each in place of a datagram that arrives and is lost: an ICMP error comes with
    /// no data.
    pub fn fail_receives(&self, n: u32) {
        self.receives.set(n);
    }

    /// Whether this one fails, and counts it.
    fn take(counter: &Cell<u32>) -> bool {
        let left = counter.get();
        counter.set(left.saturating_sub(1));
        left > 0
    }
}

/// A host's runtime, as [`Io`]: its seeded randomness, its trace, the errors a test injects, and the first panic of
/// a task it spawned.
#[derive(Debug, Clone)]
pub struct Sim {
    rng: Rc<RefCell<Rng>>,
    host: IpAddr,
    trace: Trace,
    glitches: Rc<Glitches>,
    panic: Rc<RefCell<Option<Box<dyn Any + Send>>>>,
}

impl Sim {
    /// The runtime of `host`, drawing from `rng` and recording each query sent in `trace`.
    #[must_use]
    pub fn new(rng: Rc<RefCell<Rng>>, host: IpAddr, trace: Trace) -> Self {
        Self {
            rng,
            host,
            trace,
            glitches: Rc::default(),
            panic: Rc::default(),
        }
    }

    /// The errors to inject into its UDP sockets.
    #[must_use]
    pub fn glitches(&self) -> &Glitches {
        &self.glitches
    }

    /// Resumes the first panic of a task it spawned, if one panicked: its tasks run detached, as the pools spawn
    /// them, so the host that uses it looks here (D133).
    ///
    /// # Panics
    ///
    /// With the payload of that task's panic.
    pub fn resume_panic(&self) {
        if let Some(payload) = self.panic.take() {
            resume_unwind(payload);
        }
    }

    /// Keeps the payload of `task`'s panic, which tokio would drop; an aborted task leaves nothing.
    fn watch(&self, task: tokio::task::JoinHandle<()>) {
        let panic = Rc::clone(&self.panic);
        drop(tokio::task::spawn_local(async move {
            if let Err(error) = task.await
                && error.is_panic()
            {
                panic.borrow_mut().get_or_insert(error.into_panic());
            }
        }));
    }
}

impl Io for Sim {
    type Udp = SimUdp;
    type Stream = SimStream;
    type Listener = SimListener;
    type Task = SimTask;

    fn now(&self) -> Instant {
        tokio::time::Instant::now().into_std()
    }

    fn spawn(&self, task: impl Future<Output = ()> + 'static) -> SimTask {
        let task = tokio::task::spawn_local(task);
        let abort = task.abort_handle();
        self.watch(task);
        SimTask(abort)
    }

    /// Unwatched: only `dedensd`'s `Origin` detaches, which catches and counts its tasks' panics (D121), and
    /// `World::run` reads the counts.
    fn detach(&self, task: impl Future<Output = ()> + 'static) {
        drop(tokio::task::spawn_local(task));
    }

    async fn timeout_at<F: Future>(
        &self,
        deadline: Instant,
        future: F,
    ) -> Result<F::Output, TimedOut> {
        tokio::time::timeout_at(deadline.into(), future)
            .await
            .map_err(|_| TimedOut)
    }

    fn sending(&self, exchange: &Exchange) {
        let id = exchange
            .wire()
            .first_chunk()
            .map_or(0, |id| u16::from_be_bytes(*id));
        self.trace.record(
            self.host,
            What::Sent {
                server: exchange.server(),
                id,
                sends: exchange.sends(),
                transport: exchange.transport(),
            },
        );
    }

    fn random(&self, bytes: &mut [u8]) -> io::Result<()> {
        let mut rng = self.rng.borrow_mut();
        for chunk in bytes.chunks_mut(8) {
            let word = rng.next_u64().to_be_bytes();
            chunk.copy_from_slice(word.get(..chunk.len()).unwrap_or_default());
        }
        Ok(())
    }

    async fn udp_bind(&self, addr: SocketAddr) -> io::Result<SimUdp> {
        Ok(SimUdp {
            socket: UdpSocket::bind(addr).await?,
            peer: Cell::new(None),
            glitches: Rc::clone(&self.glitches),
        })
    }

    async fn tcp_connect(&self, addr: SocketAddr) -> io::Result<SimStream> {
        SimStream::new(TcpStream::connect(addr).await?)
    }
}

/// A spawned task, aborted when dropped, as compio's handles cancel.
#[derive(Debug)]
pub struct SimTask(AbortHandle);

impl Drop for SimTask {
    fn drop(&mut self) {
        self.0.abort();
    }
}

/// A turmoil UDP socket as the seam's: turmoil's has no `send` and `recv` for a connected socket, so the peer is
/// kept here, and its own `connect` drops what comes from elsewhere.
#[derive(Debug)]
pub struct SimUdp {
    socket: UdpSocket,
    peer: Cell<Option<SocketAddr>>,
    glitches: Rc<Glitches>,
}

impl Udp for SimUdp {
    fn local_addr(&self) -> io::Result<SocketAddr> {
        self.socket.local_addr()
    }

    async fn connect(&self, addr: SocketAddr) -> io::Result<()> {
        self.socket.connect(addr).await?;
        self.peer.set(Some(addr));
        Ok(())
    }

    async fn recv<B: IoBufMut>(&self, mut buffer: B) -> BufResult<usize, B> {
        let mut scratch = vec![0; spare(&mut buffer)];
        let received = self.socket.recv_from(&mut scratch).await;
        if Glitches::take(&self.glitches.receives) {
            return BufResult(Err(io::ErrorKind::ConnectionRefused.into()), buffer);
        }
        match received {
            Ok((len, _)) => fill(buffer, scratch.get(..len).unwrap_or_default()),
            Err(error) => BufResult(Err(error), buffer),
        }
    }

    async fn send<B: IoBuf>(&self, buffer: B) -> BufResult<usize, B> {
        if Glitches::take(&self.glitches.sends) {
            return BufResult(Err(io::ErrorKind::NetworkUnreachable.into()), buffer);
        }
        let Some(peer) = self.peer.get() else {
            return BufResult(Err(io::ErrorKind::NotConnected.into()), buffer);
        };
        let sent = self.socket.send_to(buffer.as_init(), peer).await;
        BufResult(sent, buffer)
    }

    type Datagram = SimDatagram;

    /// Datagrams from any peer, each received into one scratch buffer of 3952 bytes (D49) and copied out.
    fn recv_multi(&self) -> impl futures_util::Stream<Item = io::Result<SimDatagram>> {
        let scratch = vec![0; DATAGRAM_LEN];
        futures_util::stream::unfold((self, scratch), |(socket, mut scratch)| async move {
            let received = socket.socket.recv_from(&mut scratch).await;
            let datagram = received.map(|(len, peer)| SimDatagram {
                data: scratch.get(..len).unwrap_or_default().to_vec(),
                peer,
            });
            Some((datagram, (socket, scratch)))
        })
    }

    async fn send_to<B: IoBuf>(&self, buffer: B, peer: SocketAddr) -> BufResult<usize, B> {
        let sent = self.socket.send_to(buffer.as_init(), peer).await;
        BufResult(sent, buffer)
    }
}

/// A datagram [`SimUdp`] received, copied out of turmoil's.
#[derive(Debug)]
pub struct SimDatagram {
    data: Vec<u8>,
    peer: SocketAddr,
}

impl Datagram for SimDatagram {
    fn data(&self) -> &[u8] {
        &self.data
    }

    fn peer(&self) -> Option<SocketAddr> {
        Some(self.peer)
    }
}

/// A turmoil TCP listener as the seam's.
pub struct SimListener(TcpListener);

impl fmt::Debug for SimListener {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("SimListener").finish_non_exhaustive()
    }
}

impl SimListener {
    /// A listener bound to `addr`, as `dedensd` binds before its threads start.
    ///
    /// # Errors
    ///
    /// The address is taken.
    pub async fn bind(addr: SocketAddr) -> io::Result<Self> {
        Ok(Self(TcpListener::bind(addr).await?))
    }
}

impl Listener for SimListener {
    type Stream = SimStream;

    async fn accept(&self) -> io::Result<(SimStream, SocketAddr)> {
        let (stream, peer) = self.0.accept().await?;
        Ok((SimStream::new(stream)?, peer))
    }
}

/// The room left in `buffer`.
fn spare<B: IoBufMut>(buffer: &mut B) -> usize {
    let len = IoBuf::buf_len(&*buffer);
    buffer.buf_capacity().saturating_sub(len)
}

/// `buffer` with `bytes` appended, and their number.
fn fill<B: IoBufMut>(mut buffer: B, bytes: &[u8]) -> BufResult<usize, B> {
    match buffer.extend_from_slice(bytes) {
        Ok(()) => BufResult(Ok(bytes.len()), buffer),
        Err(error) => BufResult(Err(io::Error::other(error)), buffer),
    }
}

/// A turmoil TCP connection as the seam's: compio's traits over the halves of tokio's.
#[derive(Debug)]
pub struct SimStream {
    read: SimRead,
    write: SimWrite,
    local: SocketAddr,
}

impl SimStream {
    /// `stream`, split at once as the seam's streams are.
    ///
    /// # Errors
    ///
    /// The stream is closed.
    pub fn new(stream: TcpStream) -> io::Result<Self> {
        let local = stream.local_addr()?;
        let (read, write) = stream.into_split();
        Ok(Self {
            read: SimRead(read),
            write: SimWrite(write),
            local,
        })
    }
}

impl Splittable for SimStream {
    type ReadHalf = SimRead;
    type WriteHalf = SimWrite;

    fn split(self) -> (SimRead, SimWrite) {
        (self.read, self.write)
    }
}

impl Stream for SimStream {
    fn local_addr(&self) -> io::Result<SocketAddr> {
        Ok(self.local)
    }

    fn set_nodelay(&self, _: bool) -> io::Result<()> {
        Ok(())
    }
}

/// The reading half of a [`SimStream`].
#[derive(Debug)]
pub struct SimRead(OwnedReadHalf);

impl AsyncRead for SimRead {
    async fn read<B: IoBufMut>(&mut self, mut buf: B) -> BufResult<usize, B> {
        let mut scratch = vec![0; spare(&mut buf)];
        match self.0.read(&mut scratch).await {
            Ok(len) => fill(buf, scratch.get(..len).unwrap_or_default()),
            Err(error) => BufResult(Err(error), buf),
        }
    }
}

/// The writing half of a [`SimStream`].
#[derive(Debug)]
pub struct SimWrite(OwnedWriteHalf);

impl AsyncWrite for SimWrite {
    async fn write<B: IoBuf>(&mut self, buf: B) -> BufResult<usize, B> {
        let written = self.0.write(buf.as_init()).await;
        BufResult(written, buf)
    }

    async fn flush(&mut self) -> io::Result<()> {
        self.0.flush().await
    }

    async fn shutdown(&mut self) -> io::Result<()> {
        self.0.shutdown().await
    }
}

/// The writing side of a simulated server's TCP connection (`upstream::queries`).
impl Outbound for SimWrite {
    async fn write_all(&mut self, batch: Vec<u8>) -> BufResult<(), Vec<u8>> {
        compio::io::AsyncWriteExt::write_all(self, batch).await
    }

    async fn close(&mut self) {
        let _ = AsyncWrite::shutdown(self).await;
    }
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;
    use std::time::Duration;

    use super::*;
    use crate::seed::Seed;

    #[test]
    fn a_panic_in_a_spawned_task_fails_the_run() {
        let mut sim = turmoil::Builder::new().build();
        sim.client("client", async {
            let rng = Rc::new(RefCell::new(Rng::new(Seed(1), 1)));
            let io = Sim::new(rng, IpAddr::V4(Ipv4Addr::LOCALHOST), Trace::new());
            let _task = io.spawn(async { panic!("a pool's task") });
            tokio::time::sleep(Duration::from_millis(1)).await;
            io.resume_panic();
            Ok(())
        });
        let failure = sim.run().expect_err("the task's panic fails the run");
        assert!(failure.to_string().contains("panic"), "{failure}");
    }
}
