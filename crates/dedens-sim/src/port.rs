//! What a server host shares: port 53 over UDP and TCP, and the tasks it spawns for what arrives.

use std::future::Future;
use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::rc::Rc;

use tokio::task::JoinSet;
use turmoil::net::{TcpListener, TcpStream, UdpSocket};

/// The DNS port.
pub(crate) const PORT: u16 = 53;

/// The unspecified address of `host`'s family: turmoil binds a socket in the family of its host alone, so an
/// authoritative server at an IPv6 address of a capture (D189) binds `::`.
pub(crate) const fn unspecified(host: IpAddr) -> IpAddr {
    match host {
        IpAddr::V4(_) => IpAddr::V4(Ipv4Addr::UNSPECIFIED),
        IpAddr::V6(_) => IpAddr::V6(Ipv6Addr::UNSPECIFIED),
    }
}

/// What arrived on the port.
#[derive(Debug)]
pub(crate) enum Arrival {
    /// A datagram.
    Datagram { wire: Vec<u8>, from: SocketAddr },
    /// A connection, accepted.
    Connection { stream: TcpStream, peer: SocketAddr },
}

/// A host's port 53 over UDP and TCP, and its tasks. A task that panics ends the host with an error, which fails
/// the run: no panic goes unseen in a spawned task.
pub(crate) struct Port {
    udp: Rc<UdpSocket>,
    tcp: TcpListener,
    tasks: JoinSet<()>,
    buffer: Vec<u8>,
}

impl Port {
    /// Binds the port on every address of `host`, an IPv4 or an IPv6 one.
    pub(crate) async fn bind(host: IpAddr) -> io::Result<Self> {
        let any = unspecified(host);
        Ok(Self {
            udp: Rc::new(UdpSocket::bind((any, PORT)).await?),
            tcp: TcpListener::bind((any, PORT)).await?,
            tasks: JoinSet::new(),
            buffer: vec![0; usize::from(u16::MAX)],
        })
    }

    /// The UDP socket, to send replies with.
    pub(crate) fn udp(&self) -> Rc<UdpSocket> {
        Rc::clone(&self.udp)
    }

    /// Runs `task` beside the port.
    pub(crate) fn spawn(&mut self, task: impl Future<Output = ()> + 'static) {
        self.tasks.spawn_local(task);
    }

    /// Waits for the next datagram or connection.
    ///
    /// # Errors
    ///
    /// The socket's, or a task's panic.
    pub(crate) async fn next(&mut self) -> turmoil::Result<Arrival> {
        let Self {
            udp,
            tcp,
            tasks,
            buffer,
        } = self;
        loop {
            // Biased: the random order of the branches is not drawn from the seed, and a run must replay.
            tokio::select! {
                biased;
                received = udp.recv_from(buffer) => {
                    let (len, from) = received?;
                    let wire = buffer.get(..len).unwrap_or_default().to_vec();
                    return Ok(Arrival::Datagram { wire, from });
                }
                accepted = tcp.accept() => {
                    let (stream, peer) = accepted?;
                    return Ok(Arrival::Connection { stream, peer });
                }
                Some(ended) = tasks.join_next() => ended?,
            }
        }
    }
}
