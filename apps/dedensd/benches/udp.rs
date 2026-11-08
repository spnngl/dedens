//! Queries a second over UDP through a `dedensd` answering from its cache, over loopback, one socket per query in
//! flight, all on one thread. Run with `cargo bench -p dedensd --bench udp`; numbers go to `docs/benchmarks.md`.
//! The server runs one thread (a one-core budget as in `just bench-dnsperf`), so what the run measures is the cost of
//! the path of a datagram in `dedensd`, panic isolation included (D121).

#[path = "../tests/common/mod.rs"]
mod common;

use std::net::SocketAddr;
use std::time::{Duration, Instant};

use common::{Server, query_for};
use compio::BufResult;
use compio::net::UdpSocket;
use dedens_testkit::captured;
use dedens_testkit::responder::Responder;
use futures_util::future::join_all;

/// How long each measure runs.
const RUN: Duration = Duration::from_secs(3);

/// Queries in flight at once: one, then many.
const IN_FLIGHT: [usize; 2] = [1, 32];

/// Queries a second with `in_flight` sockets asking until [`RUN`] is over.
async fn rate(addr: SocketAddr, query: &[u8], in_flight: usize) -> f64 {
    let end = Instant::now() + RUN;
    let asked = || async {
        let socket = UdpSocket::bind("127.0.0.1:0").await.expect("bound");
        socket.connect(addr).await.expect("connected");
        let mut done = 0_u64;
        let mut reply = Vec::with_capacity(1232);
        while Instant::now() < end {
            socket.send(query.to_vec()).await.0.expect("sent");
            let BufResult(received, back) = socket.recv(reply).await;
            received.expect("a response");
            reply = back;
            reply.clear();
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
    let upstream = Responder::start(&["a"]);
    let server = Server::configured(|listen| {
        format!(
            "listen: ['{listen}']\nthreads: 1\npipeline: [cache, up]\nstages:\n  cache:\n    type: cache\n  up:\n    type: forward\n    servers: ['{}']\n    timeout_ms: 2000\n    tries: 1\n",
            upstream.addr
        )
    });
    let query = query_for(&captured("a"), 0);
    let runtime = compio::runtime::Runtime::new().expect("a runtime");
    println!("| in flight | queries/s |\n|---|---|");
    runtime.block_on(async {
        // The cache warm.
        let socket = UdpSocket::bind("127.0.0.1:0").await.expect("bound");
        socket
            .send_to(query.clone(), server.addr)
            .await
            .0
            .expect("sent");
        let BufResult(received, _) = socket.recv_from(Vec::with_capacity(1232)).await;
        received.expect("a response");
        for in_flight in IN_FLIGHT {
            let rate = rate(server.addr, &query, in_flight).await;
            println!("| {in_flight} | {rate:.0} |");
        }
    });
}
