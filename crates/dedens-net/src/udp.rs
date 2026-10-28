//! DNS over UDP (RFC 1035 §4.2.1): queries muxed on a fixed pool of connected sockets per server (D27, D50).
//!
//! A server gets up to the pool's size of sockets, each opened on first use on port 0, the OS picking a random
//! source port, and connected to the server: it only receives from it, and an ICMP port unreachable comes back as
//! an error. A query takes a socket the caller picks at random and waits for the datagrams carrying its ID; the
//! socket's task receives for every query on it. The ID and the socket are what an off-path attacker must guess:
//! 16 bits and the log2 of the pool size (RFC 5452 §9.2). Retries go over the same socket, so a late response to
//! an earlier try still counts.

use std::cell::RefCell;
use std::collections::HashMap;
use std::future::poll_fn;
use std::io;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
use std::rc::Rc;
use std::task::{Poll, Waker};
use std::time::Instant;

use compio::BufResult;
use compio::net::UdpSocket;
use compio::runtime::{JoinHandle, spawn};

/// Datagrams a socket keeps for its queries before they read them; past them, the next are dropped.
const INBOX: usize = 64;

/// Sockets per server, opened on first use and kept for the life of the pool.
#[derive(Debug)]
pub struct UdpPool {
    size: usize,
    servers: RefCell<HashMap<SocketAddr, Sockets>>,
}

/// The sockets of one server, by index; `None` until first used.
type Sockets = Box<[Option<Rc<Mux>>]>;

impl UdpPool {
    /// A pool of `size` sockets per server, none open yet.
    #[must_use]
    pub fn new(size: usize) -> Self {
        Self {
            size: size.max(1),
            servers: RefCell::default(),
        }
    }

    /// Waits on socket `pick` modulo the pool's size for `server`, opening it first if need be, for datagrams with
    /// ID `id` of up to `size` bytes: the UDP payload size the query advertises (RFC 6891 §6.2.3).
    ///
    /// # Errors
    ///
    /// The socket cannot be opened or connected.
    pub async fn query(
        &self,
        server: SocketAddr,
        pick: usize,
        id: u16,
        size: usize,
    ) -> io::Result<UdpQuery> {
        let index = pick % self.size;
        let open = self
            .servers
            .borrow()
            .get(&server)
            .and_then(|sockets| sockets[index].clone());
        let mux = if let Some(mux) = open {
            mux
        } else {
            let mux = Rc::new(Mux::connect(server).await?);
            // Another query may have opened it meanwhile: the first stays.
            let mut servers = self.servers.borrow_mut();
            let sockets = servers
                .entry(server)
                .or_insert_with(|| vec![None; self.size].into_boxed_slice());
            Rc::clone(sockets[index].get_or_insert(mux))
        };
        let token = mux.waiting.borrow_mut().add(id, size);
        Ok(UdpQuery { mux, token })
    }
}

/// A socket connected to one server, and the task receiving for its queries.
#[derive(Debug)]
struct Mux {
    socket: Rc<UdpSocket>,
    waiting: Rc<RefCell<Waiting>>,
    /// Cancelled with the socket.
    _receiving: JoinHandle<()>,
}

impl Mux {
    /// Opens a socket on port 0 of the unspecified address of `server`'s family, connected to `server`, and starts
    /// its task.
    async fn connect(server: SocketAddr) -> io::Result<Self> {
        let local = match server {
            SocketAddr::V4(_) => SocketAddr::from((Ipv4Addr::UNSPECIFIED, 0)),
            SocketAddr::V6(_) => SocketAddr::from((Ipv6Addr::UNSPECIFIED, 0)),
        };
        let socket = UdpSocket::bind(local).await?;
        socket.connect(server).await?;
        let (socket, waiting) = (Rc::new(socket), Rc::<RefCell<Waiting>>::default());
        let receiving = spawn(receive(Rc::clone(&socket), Rc::clone(&waiting)));
        Ok(Self {
            socket,
            waiting,
            _receiving: receiving,
        })
    }
}

/// Receives the datagrams of `socket` for the queries `waiting`.
async fn receive(socket: Rc<UdpSocket>, waiting: Rc<RefCell<Waiting>>) {
    let mut buf = Vec::new();
    loop {
        let size = waiting.borrow().size;
        // A receive fills the buffer from its start: what it does not overwrite is stale.
        buf.clear();
        buf.reserve_exact(size);
        let BufResult(received, back) = socket.recv(buf).await;
        buf = back;
        match received {
            Ok(len) => waiting.borrow_mut().deliver(&buf[..len.min(size)]),
            Err(error) => waiting.borrow_mut().fail(error.kind()),
        }
    }
}

/// The queries waiting on a socket and the datagrams for them.
#[derive(Debug, Default)]
struct Waiting {
    queries: Vec<Waiter>,
    /// Datagrams not read yet, by the token of their query.
    inbox: Vec<(u64, Vec<u8>)>,
    next: u64,
    /// The largest size a query advertised.
    size: usize,
}

/// A query waiting for datagrams with its ID.
#[derive(Debug)]
struct Waiter {
    token: u64,
    id: u16,
    error: Option<io::ErrorKind>,
    waker: Option<Waker>,
}

impl Waiting {
    /// Adds a query waiting for ID `id` and datagrams of up to `size` bytes, and returns its token.
    fn add(&mut self, id: u16, size: usize) -> u64 {
        let token = self.next;
        self.next += 1;
        self.size = self.size.max(size);
        self.queries.push(Waiter {
            token,
            id,
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
            if self.inbox.len() < INBOX {
                self.inbox.push((waiter.token, datagram.to_vec()));
            }
            if let Some(waker) = waiter.waker.take() {
                waker.wake();
            }
        }
    }

    /// Hands `error` to every query: all wait on the same server.
    fn fail(&mut self, error: io::ErrorKind) {
        for waiter in &mut self.queries {
            waiter.error = Some(error);
            if let Some(waker) = waiter.waker.take() {
                waker.wake();
            }
        }
    }
}

/// A query waiting on a socket of a [`UdpPool`]; dropping it stops the wait.
#[derive(Debug)]
pub struct UdpQuery {
    mux: Rc<Mux>,
    token: u64,
}

impl UdpQuery {
    /// The local address: the source address the OS picked to reach the server, and the port.
    ///
    /// # Errors
    ///
    /// The OS cannot tell.
    pub fn local_addr(&self) -> io::Result<SocketAddr> {
        self.mux.socket.local_addr()
    }

    /// Waits for datagrams with ID `id` from now on, as the query goes with a new one.
    pub fn expect(&self, id: u16) {
        if let Some(waiter) = self.mux.waiting.borrow_mut().waiter(self.token) {
            waiter.id = id;
        }
    }

    /// Sends `wire` as one datagram.
    ///
    /// # Errors
    ///
    /// The send fails, or sends only part of the message.
    pub async fn send(&self, wire: &[u8]) -> io::Result<()> {
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
    /// A datagram larger than the largest size given to [`UdpPool::query`] for the socket comes cut to that size: a
    /// server that honours the advertised size never sends one, and the exchange drops it as unreadable.
    ///
    /// # Errors
    ///
    /// The socket failed, for instance with [`io::ErrorKind::ConnectionRefused`] after an ICMP port unreachable.
    pub async fn recv(&mut self, deadline: Instant) -> io::Result<Option<Vec<u8>>> {
        let next = poll_fn(|cx| {
            let mut waiting = self.mux.waiting.borrow_mut();
            if let Some(at) = waiting
                .inbox
                .iter()
                .position(|(token, _)| *token == self.token)
            {
                return Poll::Ready(Ok(waiting.inbox.remove(at).1));
            }
            // The query waits until dropped.
            if let Some(waiter) = waiting.waiter(self.token) {
                if let Some(error) = waiter.error.take() {
                    return Poll::Ready(Err(io::Error::from(error)));
                }
                waiter.waker = Some(cx.waker().clone());
            }
            Poll::Pending
        });
        compio::time::timeout_at(deadline, next)
            .await
            .map_or(Ok(None), |received| received.map(Some))
    }
}

impl Drop for UdpQuery {
    fn drop(&mut self) {
        let mut waiting = self.mux.waiting.borrow_mut();
        let token = self.token;
        waiting.queries.retain(|waiter| waiter.token != token);
        waiting.inbox.retain(|(of, _)| *of != token);
    }
}
