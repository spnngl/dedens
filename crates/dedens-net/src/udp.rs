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
use dedens_proto::wire::MAX_MESSAGE_LEN;

/// A UDP socket connected to one server.
#[derive(Debug)]
pub struct UdpChannel {
    socket: UdpSocket,
    server: SocketAddr,
    /// The last datagram received; its allocation is reused.
    buf: Vec<u8>,
}

impl UdpChannel {
    /// Opens a socket on port 0 of the unspecified address of `server`'s family, connected to `server`.
    ///
    /// # Errors
    ///
    /// The socket cannot be opened or connected.
    pub async fn connect(server: SocketAddr) -> io::Result<Self> {
        let local = match server {
            SocketAddr::V4(_) => SocketAddr::from((Ipv4Addr::UNSPECIFIED, 0)),
            SocketAddr::V6(_) => SocketAddr::from((Ipv6Addr::UNSPECIFIED, 0)),
        };
        let socket = UdpSocket::bind(local).await?;
        socket.connect(server).await?;
        Ok(Self {
            socket,
            server,
            buf: Vec::with_capacity(MAX_MESSAGE_LEN),
        })
    }

    /// The server.
    #[must_use]
    pub const fn server(&self) -> SocketAddr {
        self.server
    }

    /// The local address, with the port the OS picked.
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
    /// # Errors
    ///
    /// The receive fails, for instance with [`io::ErrorKind::ConnectionRefused`] after an ICMP port unreachable.
    pub async fn recv(&mut self, deadline: Instant) -> io::Result<Option<&[u8]>> {
        let buf = std::mem::take(&mut self.buf);
        let Ok(BufResult(received, buf)) =
            compio::time::timeout_at(deadline, self.socket.recv(buf)).await
        else {
            // The buffer went with the cancelled receive.
            self.buf = Vec::with_capacity(MAX_MESSAGE_LEN);
            return Ok(None);
        };
        self.buf = buf;
        received?;
        Ok(Some(&self.buf))
    }
}
