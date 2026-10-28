//! A scripted server on the loopback address: each test drives its side by hand.

use std::net::SocketAddr;
use std::time::Duration;

use compio::BufResult;
use compio::io::{AsyncRead, AsyncWriteExt};
use compio::net::{TcpListener, TcpStream, UdpSocket};
use dedens_net::tcp::{Frames, frame};
use dedens_proto::edns::EdnsOption;
use dedens_proto::{Message, Rcode};

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

/// A UDP server that answers each query, after `delay`.
pub(crate) async fn udp_server(delay: Duration) -> SocketAddr {
    let socket = UdpSocket::bind("127.0.0.1:0").await.expect("a UDP socket");
    let addr = socket.local_addr().expect("an address");
    compio::runtime::spawn(async move {
        let mut buf = Vec::with_capacity(65535);
        loop {
            let BufResult(received, back) = socket.recv_from(buf).await;
            buf = back;
            let Ok((_, from)) = received else { return };
            compio::time::sleep(delay).await;
            let _ = socket.send_to(answer(&buf, Vec::new()), from).await;
        }
    })
    .detach();
    addr
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
    frames: Frames,
}

impl Peer {
    pub(crate) async fn accept(listener: &TcpListener) -> Self {
        let (stream, _) = listener.accept().await.expect("a connection");
        Self {
            stream,
            frames: Frames::new(),
        }
    }

    /// The next query, or `None` once the client closed its side.
    pub(crate) async fn read(&mut self) -> Option<Vec<u8>> {
        loop {
            if let Some(message) = self.frames.next_message() {
                return Some(message.to_vec());
            }
            let BufResult(read, buf) = self.stream.read(Vec::with_capacity(4096)).await;
            if !matches!(read, Ok(n) if n > 0) {
                return None;
            }
            self.frames.push(&buf);
        }
    }

    /// Writes `messages`, each framed, in one write.
    pub(crate) async fn write(&mut self, messages: &[Vec<u8>]) {
        let bytes: Vec<u8> = messages
            .iter()
            .flat_map(|m| frame(m).expect("a message under 64 KiB"))
            .collect();
        let BufResult(written, _) = self.stream.write_all(bytes).await;
        written.expect("the client reads");
    }
}

/// A UDP server answering each query with `respond`, or not at all when it gives `None`.
pub(crate) async fn udp_responder(
    respond: impl Fn(&[u8]) -> Option<Vec<u8>> + 'static,
) -> SocketAddr {
    let socket = UdpSocket::bind("127.0.0.1:0").await.expect("a UDP socket");
    let addr = socket.local_addr().expect("an address");
    compio::runtime::spawn(async move {
        let mut buf = Vec::with_capacity(65535);
        loop {
            let BufResult(received, back) = socket.recv_from(buf).await;
            buf = back;
            let Ok((_, from)) = received else { return };
            if let Some(response) = respond(&buf) {
                let _ = socket.send_to(response, from).await;
            }
        }
    })
    .detach();
    addr
}

/// A TCP server on `addr` answering each query of each connection with `respond`.
pub(crate) async fn tcp_responder(addr: SocketAddr, respond: fn(&[u8]) -> Vec<u8>) {
    let listener = TcpListener::bind(addr).await.expect("a TCP listener");
    compio::runtime::spawn(async move {
        loop {
            let mut peer = Peer::accept(&listener).await;
            compio::runtime::spawn(async move {
                while let Some(query) = peer.read().await {
                    peer.write(&[respond(&query)]).await;
                }
            })
            .detach();
        }
    })
    .detach();
}
