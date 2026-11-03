//! DNS over UDP (RFC 1035 §4.2.1): queries muxed on a fixed pool of connected sockets per server (D27, D50).
//!
//! A server gets up to the pool's size of sockets, each opened on first use on port 0, the OS picking a random
//! source port, and connected to the server: it only receives from it, and an ICMP port unreachable comes back as
//! an error. A query takes a socket the caller picks at random and waits for the datagrams carrying its ID; the
//! socket's task receives for every query on it. The ID and the socket are what an off-path attacker must guess:
//! 16 bits and the log2 of the pool size (RFC 5452 §9.2). Retries go over the same socket, so a late response to
//! an earlier try still counts.
//!
//! Generic over [`Io`] (D134): time, tasks and sockets come from it.

#![deny(clippy::disallowed_methods)]

use std::cell::RefCell;
use std::collections::{HashMap, VecDeque};
use std::future::poll_fn;
use std::io;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
use std::rc::Rc;
use std::task::{Poll, Waker};
use std::time::{Duration, Instant};

use compio::BufResult;

use crate::io::{Compio, Io, Udp};

/// Datagrams kept for a query before it reads them; past them, the next for it are dropped. Per query, so one
/// flooded or slow does not take the room of the others on its socket (D108).
const INBOX: usize = 4;

/// Sockets per server, opened on first use and kept for the life of the pool.
#[derive(Debug)]
pub struct UdpPool<N: Io = Compio> {
    io: N,
    size: usize,
    servers: RefCell<HashMap<SocketAddr, Sockets<N>>>,
}

/// The sockets of one server, by index; `None` until first used.
type Sockets<N> = Box<[Option<Rc<Mux<N>>>]>;

impl UdpPool {
    /// A pool of `size` sockets per server on compio, none open yet.
    #[must_use]
    pub fn new(size: usize) -> Self {
        Self::with_io(Compio, size)
    }
}

impl<N: Io> UdpPool<N> {
    /// A pool of `size` sockets per server on `io`, none open yet.
    #[must_use]
    pub fn with_io(io: N, size: usize) -> Self {
        Self {
            io,
            size: size.max(1),
            servers: RefCell::default(),
        }
    }

    /// Waits on socket `pick` modulo the pool's size for `server`, opening it first if need be, for datagrams with
    /// ID `id`.
    ///
    /// # Errors
    ///
    /// The socket cannot be opened or connected.
    pub async fn query(&self, server: SocketAddr, pick: usize, id: u16) -> io::Result<UdpQuery<N>> {
        let index = pick % self.size;
        let open = self
            .servers
            .borrow()
            .get(&server)
            .and_then(|sockets| sockets[index].clone());
        let mux = if let Some(mux) = open {
            mux
        } else {
            let mux = Rc::new(Mux::connect(self.io.clone(), server).await?);
            // Another query may have opened it meanwhile: the first stays.
            let mut servers = self.servers.borrow_mut();
            let sockets = servers
                .entry(server)
                .or_insert_with(|| vec![None; self.size].into_boxed_slice());
            Rc::clone(sockets[index].get_or_insert(mux))
        };
        let token = mux.waiting.borrow_mut().add(id);
        Ok(UdpQuery { mux, token })
    }
}

/// A socket connected to one server, and the task receiving for its queries.
#[derive(Debug)]
struct Mux<N: Io> {
    io: N,
    socket: Rc<N::Udp>,
    /// Its local address, asked once: a system call.
    local: SocketAddr,
    waiting: Rc<RefCell<Waiting>>,
    /// Cancelled with the socket.
    _receiving: N::Task,
}

impl<N: Io> Mux<N> {
    /// Opens a socket on port 0 of the unspecified address of `server`'s family, connected to `server`, and starts
    /// its task.
    async fn connect(io: N, server: SocketAddr) -> io::Result<Self> {
        let socket = io.udp_bind(unspecified(server)).await?;
        socket.connect(server).await?;
        let local = socket.local_addr()?;
        let (socket, waiting) = (Rc::new(socket), Rc::<RefCell<Waiting>>::default());
        let receiving = io.spawn(receive(io.clone(), Rc::clone(&socket), Rc::clone(&waiting)));
        Ok(Self {
            io,
            socket,
            local,
            waiting,
            _receiving: receiving,
        })
    }
}

/// Port 0 of the unspecified address of `addr`'s family, to bind a socket that reaches `addr`.
pub(crate) fn unspecified(addr: SocketAddr) -> SocketAddr {
    match addr {
        SocketAddr::V4(_) => SocketAddr::from((Ipv4Addr::UNSPECIFIED, 0)),
        SocketAddr::V6(_) => SocketAddr::from((Ipv6Addr::UNSPECIFIED, 0)),
    }
}

/// Receives the datagrams of `socket` for the queries `waiting`, each whole: a query may advertise any UDP payload
/// size (RFC 6891 §6.2.3), and one buffer of the largest serves them all.
async fn receive<N: Io>(io: N, socket: Rc<N::Udp>, waiting: Rc<RefCell<Waiting>>) {
    /// The largest UDP payload.
    const MAX_DATAGRAM: usize = 65535;
    /// The pause after an error that follows an error, so one that keeps coming does not spin.
    const PAUSE: Duration = Duration::from_millis(10);
    let mut buf = Vec::with_capacity(MAX_DATAGRAM);
    let mut failed = false;
    loop {
        // A receive fills the buffer from its start: what it does not overwrite is stale.
        buf.clear();
        let BufResult(received, back) = socket.recv(buf).await;
        buf = back;
        match received {
            Ok(len) => {
                failed = false;
                waiting.borrow_mut().deliver(&buf[..len]);
            }
            Err(error) => {
                waiting.borrow_mut().fail(error.kind());
                if failed {
                    let _ = io
                        .timeout_at(io.now() + PAUSE, std::future::pending::<()>())
                        .await;
                }
                failed = true;
            }
        }
    }
}

/// The queries waiting on a socket and the datagrams for them.
#[derive(Debug, Default)]
struct Waiting {
    queries: Vec<Waiter>,
    next: u64,
}

/// A query waiting for datagrams with its ID.
#[derive(Debug)]
struct Waiter {
    token: u64,
    id: u16,
    /// Datagrams with its ID not read yet, at most [`INBOX`].
    inbox: VecDeque<Vec<u8>>,
    /// Whether it sent a datagram: only then may an error be its.
    sent: bool,
    error: Option<io::ErrorKind>,
    waker: Option<Waker>,
}

impl Waiting {
    /// Adds a query waiting for ID `id`, and returns its token.
    fn add(&mut self, id: u16) -> u64 {
        let token = self.next;
        self.next += 1;
        self.queries.push(Waiter {
            token,
            id,
            inbox: VecDeque::new(),
            sent: false,
            error: None,
            waker: None,
        });
        token
    }

    fn waiter(&mut self, token: u64) -> Option<&mut Waiter> {
        self.queries.iter_mut().find(|waiter| waiter.token == token)
    }

    /// Hands `datagram` to each query waiting for its ID; a datagram nobody waits for is dropped.
    fn deliver(&mut self, datagram: &[u8]) {
        let Some(&[high, low]) = datagram.get(..2) else {
            return;
        };
        let id = u16::from_be_bytes([high, low]);
        for waiter in self.queries.iter_mut().filter(|waiter| waiter.id == id) {
            if waiter.inbox.len() < INBOX {
                waiter.inbox.push_back(datagram.to_vec());
            }
            if let Some(waker) = waiter.waker.take() {
                waker.wake();
            }
        }
    }

    /// Hands `error` to every query that sent a datagram: all went to the same server, and which one the error
    /// answers is unknown. Each counts it as a try lost.
    fn fail(&mut self, error: io::ErrorKind) {
        for waiter in self.queries.iter_mut().filter(|waiter| waiter.sent) {
            waiter.error = Some(error);
            if let Some(waker) = waiter.waker.take() {
                waker.wake();
            }
        }
    }
}

/// A query waiting on a socket of a [`UdpPool`]; dropping it stops the wait.
#[derive(Debug)]
pub struct UdpQuery<N: Io = Compio> {
    mux: Rc<Mux<N>>,
    token: u64,
}

impl<N: Io> UdpQuery<N> {
    /// The local address: the source address the OS picked to reach the server, and the port.
    #[must_use]
    pub fn local_addr(&self) -> SocketAddr {
        self.mux.local
    }

    /// Waits for datagrams with ID `id` from now on, as the query goes with a new one.
    pub fn expect(&self, id: u16) {
        if let Some(waiter) = self.mux.waiting.borrow_mut().waiter(self.token) {
            waiter.id = id;
        }
    }

    /// Sends `wire` as one datagram; from then on, an error of the socket is the query's too.
    ///
    /// # Errors
    ///
    /// The send fails, or sends only part of the message.
    pub async fn send(&self, wire: &[u8]) -> io::Result<()> {
        if let Some(waiter) = self.mux.waiting.borrow_mut().waiter(self.token) {
            waiter.sent = true;
            // An error before this try was the last one's.
            waiter.error = None;
        }
        let BufResult(sent, _) = self.mux.socket.send(wire.to_vec()).await;
        if sent? == wire.len() {
            Ok(())
        } else {
            Err(io::Error::new(
                io::ErrorKind::WriteZero,
                "datagram sent in part",
            ))
        }
    }

    /// Receives the next datagram with the query's ID, or `None` once `deadline` passes.
    ///
    /// # Errors
    ///
    /// The socket failed after the query sent, for instance with [`io::ErrorKind::ConnectionRefused`] after an ICMP
    /// port unreachable: maybe for another query on the socket.
    pub async fn recv(&mut self, deadline: Instant) -> io::Result<Option<Vec<u8>>> {
        let next = poll_fn(|cx| {
            let mut waiting = self.mux.waiting.borrow_mut();
            // The query waits until dropped.
            if let Some(waiter) = waiting.waiter(self.token) {
                if let Some(datagram) = waiter.inbox.pop_front() {
                    return Poll::Ready(Ok(datagram));
                }
                if let Some(error) = waiter.error.take() {
                    return Poll::Ready(Err(io::Error::from(error)));
                }
                waiter.waker = Some(cx.waker().clone());
            }
            Poll::Pending
        });
        self.mux
            .io
            .timeout_at(deadline, next)
            .await
            .map_or(Ok(None), |received| received.map(Some))
    }
}

impl<N: Io> Drop for UdpQuery<N> {
    fn drop(&mut self) {
        let token = self.token;
        self.mux
            .waiting
            .borrow_mut()
            .queries
            .retain(|waiter| waiter.token != token);
    }
}

#[cfg(test)]
mod tests {
    use std::net::{Ipv4Addr, SocketAddr};
    use std::rc::Rc;

    use super::{INBOX, UdpPool, Waiting};

    /// A query dropped stops waiting: the socket keeps no waiter of it, which would hold its datagrams forever.
    #[compio::test]
    async fn a_dropped_query_leaves_no_waiter() {
        let pool = UdpPool::new(1);
        let server = SocketAddr::from((Ipv4Addr::LOCALHOST, 53));
        let (query, other) = (
            pool.query(server, 0, 7).await.expect("a socket"),
            pool.query(server, 0, 8).await.expect("a socket"),
        );
        let mux = Rc::clone(&query.mux);
        drop(query);
        let ids: Vec<u16> = mux
            .waiting
            .borrow()
            .queries
            .iter()
            .map(|waiter| waiter.id)
            .collect();
        assert_eq!(ids, [8]);
        drop(other);
        assert!(mux.waiting.borrow().queries.is_empty());
    }

    /// A query keeps [`INBOX`] datagrams, no more, and what is sent to one takes no room from another.
    #[test]
    fn a_query_keeps_at_most_its_inbox() {
        let mut waiting = Waiting::default();
        let (flooded, other) = (waiting.add(1), waiting.add(2));
        for _ in 0..=INBOX {
            waiting.deliver(&[0, 1]);
        }
        waiting.deliver(&[0, 2]);
        let mut kept = |token| waiting.waiter(token).map(|waiter| waiter.inbox.len());
        assert_eq!(kept(flooded), Some(INBOX));
        assert_eq!(kept(other), Some(1));
    }
}
