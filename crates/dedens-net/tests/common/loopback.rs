//! A scripted server on the loopback address: each test drives its side by hand.

use std::net::{IpAddr, Ipv4Addr, SocketAddr};

use compio::BufResult;
use compio::io::{AsyncReadExt, AsyncWrite, AsyncWriteExt};
use compio::net::{TcpListener, TcpStream, UdpSocket};
use dedens_net::tcp::frame;
use dedens_proto::edns::EdnsOption;
use dedens_proto::{Flags, Message, Rcode};

/// A port nothing listens on, over UDP or TCP, and nothing can take: below the ports the system hands out. One that
/// was open a moment ago is any test's to take, and its server would answer.
pub(crate) const CLOSED: SocketAddr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 1);

/// The response to `query`, with these EDNS options when it has EDNS.
pub(crate) fn answer(query: &[u8], options: Vec<EdnsOption<'static>>) -> Vec<u8> {
    let query = Message::decode(query).expect("a query").message;
    let mut response = super::response(&query, Rcode::NOERROR);
    if let Some(edns) = &mut response.edns {
        edns.options = options;
    }
    super::wire(&response)
}

/// A query for `example.com. A` with `id`.
pub(crate) fn query_with_id(id: u16) -> Vec<u8> {
    let mut query = super::query();
    query.header.id = id;
    super::wire(&query)
}

/// The ID of a message.
pub(crate) fn id(message: &[u8]) -> u16 {
    Message::decode(message)
        .expect("a message")
        .message
        .header
        .id
}

/// A TCP listener on the loopback address.
pub(crate) async fn listen() -> (TcpListener, SocketAddr) {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("a TCP listener");
    let addr = listener.local_addr().expect("an address");
    (listener, addr)
}

/// The server's side of a TCP connection.
pub(crate) struct Peer {
    stream: TcpStream,
}

impl Peer {
    pub(crate) async fn accept(listener: &TcpListener) -> Self {
        let (stream, _) = listener.accept().await.expect("a connection");
        Self { stream }
    }

    /// The next query, or `None` once the client closed its side.
    pub(crate) async fn read(&mut self) -> Option<Vec<u8>> {
        let len = self.stream.read_u16().await.ok()?;
        let BufResult(read, query) = self.stream.read_exact(Vec::with_capacity(len.into())).await;
        read.ok().map(|()| query)
    }

    /// Writes `messages`, each framed, in one write.
    pub(crate) async fn write(&mut self, messages: &[Vec<u8>]) {
        let bytes: Vec<u8> = messages
            .iter()
            .flat_map(|m| frame(m).expect("a message under 64 KiB"))
            .collect();
        self.write_bytes(bytes).await;
    }

    /// Writes `bytes` as they are.
    pub(crate) async fn write_bytes(&mut self, bytes: Vec<u8>) {
        let BufResult(written, _) = self.stream.write_all(bytes).await;
        written.expect("the client reads");
    }

    /// Closes the server's side: the client reads the end.
    pub(crate) async fn shutdown(&mut self) {
        self.stream.shutdown().await.expect("a shutdown");
    }
}

/// A UDP server answering each query with `respond`, or not at all when it gives `None`.
pub(crate) async fn udp_responder(
    respond: impl Fn(&[u8]) -> Option<Vec<u8>> + 'static,
) -> SocketAddr {
    let socket = UdpSocket::bind("127.0.0.1:0").await.expect("a UDP socket");
    serve_udp(socket, respond)
}

/// UDP and TCP servers on one port: `udp` answers as for [`udp_responder`], `tcp` each query of each connection.
pub(crate) async fn responders(
    udp: impl Fn(&[u8]) -> Option<Vec<u8>> + 'static,
    tcp: fn(&[u8]) -> Vec<u8>,
) -> SocketAddr {
    // The port free for UDP may be taken for TCP: then try another.
    let (socket, listener) = loop {
        let socket = UdpSocket::bind("127.0.0.1:0").await.expect("a UDP socket");
        let addr = socket.local_addr().expect("an address");
        if let Ok(listener) = TcpListener::bind(addr).await {
            break (socket, listener);
        }
    };
    compio::runtime::spawn(async move {
        loop {
            let mut peer = Peer::accept(&listener).await;
            compio::runtime::spawn(async move {
                while let Some(query) = peer.read().await {
                    peer.write(&[tcp(&query)]).await;
                }
            })
            .detach();
        }
    })
    .detach();
    serve_udp(socket, udp)
}

/// Answers each query `socket` receives with `respond`, or not at all when it gives `None`; returns its address.
fn serve_udp(
    socket: UdpSocket,
    respond: impl Fn(&[u8]) -> Option<Vec<u8>> + 'static,
) -> SocketAddr {
    let addr = socket.local_addr().expect("an address");
    compio::runtime::spawn(async move {
        let mut buf = Vec::with_capacity(65535);
        loop {
            // A receive fills the buffer from its start: what it does not overwrite is stale.
            buf.clear();
            let BufResult(received, back) = socket.recv_from(buf).await;
            buf = back;
            let Ok((len, from)) = received else { return };
            // A port is reused as soon as it closes: what comes may be meant for the socket before, such as the
            // packets a QUIC server of another test keeps sending to the port of a client that is gone.
            let is_query = Message::decode(&buf[..len])
                .is_ok_and(|decoded| !decoded.message.header.flags.contains(Flags::QR));
            if !is_query {
                continue;
            }
            if let Some(response) = respond(&buf) {
                let _ = socket.send_to(response, from).await;
            }
        }
    })
    .detach();
    addr
}
