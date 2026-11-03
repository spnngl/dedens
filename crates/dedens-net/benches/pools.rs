//! Queries a second over the UDP and TCP pools (D27, D50), against loopback servers echoing each query as a response,
//! client and servers on one thread: what `UdpPool`, `TcpPool` and `Client` cost, not the network. Run with
//! `cargo bench -p dedens-net --bench pools`; numbers go to `docs/benchmarks.md`.

use std::net::SocketAddr;
use std::time::{Duration, Instant};

use compio::BufResult;
use compio::io::{AsyncReadExt, AsyncWriteExt};
use compio::net::{TcpListener, TcpStream, UdpSocket};
use dedens_net::client::Client;
use dedens_net::exchange::{Options, Transport};
use dedens_net::tcp::frame;
use dedens_proto::{Message, Question, RecordType};
use futures_util::future::join_all;

/// How long each measure runs.
const RUN: Duration = Duration::from_secs(3);

/// Queries in flight at once: one, then many sharing a socket pool or a connection.
const IN_FLIGHT: [usize; 2] = [1, 32];

/// The query every exchange asks.
fn query() -> Message<'static> {
    let name = "example.com.".parse().expect("a name");
    Message::query(0, Question::new(name, RecordType::A))
}

/// `query` as a response: the same bytes with QR and RA set, so its ID and question match.
fn respond(query: &mut [u8]) {
    query[2] |= 0x80;
    query[3] |= 0x80;
}

/// A UDP server answering each datagram with its response.
async fn udp_server() -> SocketAddr {
    let socket = UdpSocket::bind("127.0.0.1:0").await.expect("a UDP socket");
    let addr = socket.local_addr().expect("its address");
    compio::runtime::spawn(async move {
        let mut buffer = vec![0; 512];
        loop {
            let BufResult(received, back) = socket.recv_from(buffer).await;
            buffer = back;
            let Ok((len, peer)) = received else {
                continue;
            };
            respond(&mut buffer[..len]);
            let BufResult(_, back) = socket.send_to(buffer[..len].to_vec(), peer).await;
            drop(back);
        }
    })
    .detach();
    addr
}

/// A TCP server answering the queries of each connection one after the other.
async fn tcp_server() -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("a TCP listener");
    let addr = listener.local_addr().expect("its address");
    compio::runtime::spawn(async move {
        while let Ok((stream, _)) = listener.accept().await {
            compio::runtime::spawn(serve(stream)).detach();
        }
    })
    .detach();
    addr
}

/// One connection: reads a framed query, writes its framed response, until the client closes.
async fn serve(mut stream: TcpStream) {
    while let Ok(len) = stream.read_u16().await {
        let BufResult(read, mut query) = stream.read_exact(Vec::with_capacity(len.into())).await;
        if read.is_err() {
            return;
        }
        respond(&mut query);
        let BufResult(written, _) = stream.write_all(frame(&query).expect("framed")).await;
        if written.is_err() {
            return;
        }
    }
}

/// Queries a second with `in_flight` loops asking until [`RUN`] is over.
async fn rate(client: &Client, addr: SocketAddr, options: &Options, in_flight: usize) -> f64 {
    let end = Instant::now() + RUN;
    let asked = || async {
        let mut done = 0_u64;
        while Instant::now() < end {
            client
                .exchange(query(), addr, options)
                .await
                .expect("a response");
            done += 1;
        }
        done
    };
    let done: u64 = join_all((0..in_flight).map(|_| asked()))
        .await
        .into_iter()
        .sum();
    #[expect(clippy::cast_precision_loss, reason = "a count of queries in seconds")]
    let done = done as f64;
    done / RUN.as_secs_f64()
}

fn main() {
    let runtime = compio::runtime::Runtime::new().expect("a runtime");
    runtime.block_on(async {
        let udp = udp_server().await;
        let tcp = tcp_server().await;
        let client = Client::new();
        println!("| Transport | in flight | queries/s |\n|---|---|---|");
        for (label, addr, transport) in [("UDP", udp, Transport::Udp), ("TCP", tcp, Transport::Tcp)]
        {
            let mut options = Options::default();
            options.transport = transport;
            // The sockets or the connection opened and warm.
            client
                .exchange(query(), addr, &options)
                .await
                .expect("a response");
            for in_flight in IN_FLIGHT {
                let rate = rate(&client, addr, &options, in_flight).await;
                println!("| {label} | {in_flight} | {rate:.0} |");
            }
        }
    });
}
