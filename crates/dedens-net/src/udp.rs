//! DNS over UDP (RFC 1035 §4.2.1): one connected socket per exchange (D27).
//!
//! The socket binds port 0 so the OS picks a random source port: with the random ID, about 32 bits an off-path
//! attacker must guess (RFC 5452 §9.2). Connected, it only receives from the server, and an ICMP port unreachable
//! comes back as an error. Retries go over the same socket, so a late response to an earlier try still counts.

use std::io;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
use std::time::Instant;

use compio::BufResult;
use compio::net::UdpSocket;

/// A UDP socket connected to one server.
#[derive(Debug)]
pub struct UdpChannel {
    socket: UdpSocket,
    /// The last datagram received; its allocation is reused.
    buf: Vec<u8>,
    /// The largest datagram received whole.
    size: usize,
}

impl UdpChannel {
    /// Opens a socket on port 0 of the unspecified address of `server`'s family, connected to `server`, that
    /// receives datagrams of up to `size` bytes: the UDP payload size the queries advertise (RFC 6891 §6.2.3).
    ///
    /// # Errors
    ///
    /// The socket cannot be opened or connected.
    pub async fn connect(server: SocketAddr, size: usize) -> io::Result<Self> {
        let local = match server {
            SocketAddr::V4(_) => SocketAddr::from((Ipv4Addr::UNSPECIFIED, 0)),
            SocketAddr::V6(_) => SocketAddr::from((Ipv6Addr::UNSPECIFIED, 0)),
        };
        let socket = UdpSocket::bind(local).await?;
        socket.connect(server).await?;
        Ok(Self {
            socket,
            buf: Vec::with_capacity(size),
            size,
        })
    }

    /// The local address: the source address the OS picked to reach the server, and the port.
    ///
    /// # Errors
    ///
    /// The OS cannot tell.
    pub fn local_addr(&self) -> io::Result<SocketAddr> {
        self.socket.local_addr()
    }

    /// Sends `wire` as one datagram.
    ///
    /// # Errors
    ///
    /// The send fails, or sends only part of the message.
    pub async fn send(&self, wire: &[u8]) -> io::Result<()> {
        let BufResult(sent, _) = self.socket.send(wire.to_vec()).await;
        if sent? == wire.len() {
            Ok(())
        } else {
            Err(io::Error::new(
                io::ErrorKind::WriteZero,
                "datagram sent in part",
            ))
        }
    }

    /// Receives the next datagram from the server, or `None` once `deadline` passes.
    ///
    /// A datagram larger than the size given to [`UdpChannel::connect`] comes cut to that size: a server that
    /// honours the advertised size never sends one, and the exchange drops it as unreadable.
    ///
    /// # Errors
    ///
    /// The receive fails, for instance with [`io::ErrorKind::ConnectionRefused`] after an ICMP port unreachable.
    pub async fn recv(&mut self, deadline: Instant) -> io::Result<Option<&[u8]>> {
        let mut buf = std::mem::take(&mut self.buf);
        // A receive fills the buffer from its start: what it does not overwrite is stale.
        buf.clear();
        let Ok(BufResult(received, buf)) =
            compio::time::timeout_at(deadline, self.socket.recv(buf)).await
        else {
            // The buffer went with the cancelled receive. Getting it back would take a cancel token per receive,
            // more than this allocation after each timeout.
            self.buf = Vec::with_capacity(self.size);
            return Ok(None);
        };
        self.buf = buf;
        received?;
        Ok(Some(&self.buf))
    }
}
