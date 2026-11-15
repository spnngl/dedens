//! A UDP relay on the loopback address in front of a QUIC server: [`Relay::restart`] sends what comes next to another
//! server, as a server restarted at the same address would get it, and drops what the first one still sends, as from
//! one that crashed: the client keeps its connection to an address that no longer knows it.

use std::cell::Cell;
use std::net::SocketAddr;
use std::rc::Rc;

use compio::BufResult;
use compio::net::UdpSocket;

/// The relay, passing datagrams until the runtime ends.
pub(crate) struct Relay {
    addr: SocketAddr,
    server: Rc<Cell<SocketAddr>>,
}

impl Relay {
    /// A relay to `server`: what a client sends goes to it, and what it sends back goes to the last client heard.
    pub(crate) async fn start(server: SocketAddr) -> Self {
        let front = Rc::new(UdpSocket::bind("127.0.0.1:0").await.expect("a UDP port"));
        let back = Rc::new(UdpSocket::bind("127.0.0.1:0").await.expect("a UDP port"));
        let addr = front.local_addr().expect("its address");
        let server = Rc::new(Cell::new(server));
        let client = Rc::new(Cell::new(None));
        let (to, heard, out) = (Rc::clone(&server), Rc::clone(&client), Rc::clone(&back));
        let inbound = Rc::clone(&front);
        compio::runtime::spawn(async move {
            let mut buf = Vec::with_capacity(65_535);
            loop {
                let BufResult(received, datagram) = inbound.recv_from(buf).await;
                let (_, from) = received.expect("a datagram");
                heard.set(Some(from));
                let BufResult(_, datagram) = out.send_to(datagram, to.get()).await;
                buf = datagram;
                buf.clear();
            }
        })
        .detach();
        let from_server = Rc::clone(&server);
        compio::runtime::spawn(async move {
            let mut buf = Vec::with_capacity(65_535);
            loop {
                let BufResult(received, datagram) = back.recv_from(buf).await;
                let (_, from) = received.expect("a datagram");
                buf = match client.get() {
                    // Only the current server is heard: the one before is gone.
                    Some(client) if from == from_server.get() => {
                        front.send_to(datagram, client).await.1
                    }
                    _ => datagram,
                };
                buf.clear();
            }
        })
        .detach();
        Self { addr, server }
    }

    /// The address the client asks: the server's, as far as it knows.
    pub(crate) const fn addr(&self) -> SocketAddr {
        self.addr
    }

    /// From now on the relay passes to and from `server` only: the server at its address was restarted.
    pub(crate) fn restart(&self, server: SocketAddr) {
        self.server.set(server);
    }
}
