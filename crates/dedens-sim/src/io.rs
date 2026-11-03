//! The simulated side of the seam (D134): [`Sim`] is `dedens_net::io::Io` on turmoil's sockets and tokio's clock, so
//! the real `UdpPool`, `TcpPool` and `Client` run on the simulated network of a host.
//!
//! Time is tokio's, which turmoil pauses and advances, and the randomness is the host's seeded stream: a run
//! replays. turmoil's sockets speak tokio's traits and borrowed buffers; the adapters here speak compio's owned
//! ones, copying through a scratch buffer, which a test can afford.

use std::cell::{Cell, RefCell};
use std::future::Future;
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::rc::Rc;
use std::time::Instant;

use compio::BufResult;
use compio::buf::{IoBuf, IoBufMut};
use compio::io::util::Splittable;
use compio::io::{AsyncRead, AsyncWrite};
use dedens_net::exchange::Exchange;
use dedens_net::io::{Io, Stream, TimedOut, Udp};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::task::JoinHandle;
use turmoil::net::tcp::{OwnedReadHalf, OwnedWriteHalf};
use turmoil::net::{TcpStream, UdpSocket};

use crate::seed::Rng;
use crate::trace::{Trace, What};

/// Errors to inject into the UDP sockets of one [`Sim`]: the next `n` sends, or the next `n` arrivals.
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

/// A host's runtime, as [`Io`]: its seeded randomness, its trace, and the errors a test injects.
#[derive(Debug, Clone)]
pub struct Sim {
    rng: Rc<RefCell<Rng>>,
    host: IpAddr,
    trace: Trace,
    glitches: Rc<Glitches>,
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
        }
    }

    /// The errors to inject into its UDP sockets.
    #[must_use]
    pub fn glitches(&self) -> &Glitches {
        &self.glitches
    }
}

impl Io for Sim {
    type Udp = SimUdp;
    type Stream = SimStream;
    type Task = SimTask;

    fn now(&self) -> Instant {
        tokio::time::Instant::now().into_std()
    }

    fn spawn(&self, task: impl Future<Output = ()> + 'static) -> SimTask {
        SimTask(tokio::task::spawn_local(task))
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
pub struct SimTask(JoinHandle<()>);

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
