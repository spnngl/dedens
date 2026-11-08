//! Queries a second over DNS over HTTPS on HTTP/3 (D84) through a `dedensd` answering from its cache, over loopback,
//! the client a `dedens-net` `Client` on one thread. Run with `cargo bench -p dedensd --bench doh3`; numbers go to
//! `docs/benchmarks.md`.

#[path = "../tests/common/mod.rs"]
mod common;

use std::net::SocketAddr;
use std::time::{Duration, Instant};

use common::{Responder, Server, decode, query_for};
use dedens_net::client::Client;
use dedens_net::doh::Method;
use dedens_net::exchange::Options;
use dedens_net::tls::Trust;
use dedens_proto::Transport;
use dedens_testkit::captured;
use dedens_testkit::certificates::{NAME, certificates, named};
use futures_util::future::join_all;

/// How long each measure runs.
const RUN: Duration = Duration::from_secs(3);

/// Queries in flight at once: one, then many sharing a connection.
const IN_FLIGHT: [usize; 2] = [1, 32];

/// Queries a second with `in_flight` loops asking until [`RUN`] is over.
async fn rate(client: &Client, addr: SocketAddr, options: &Options, in_flight: usize) -> f64 {
    let end = Instant::now() + RUN;
    let query = decode(&query_for(&captured("a"), 0));
    let asked = || async {
        let mut done = 0_u64;
        while Instant::now() < end {
            client
                .exchange(query.clone(), named(addr, NAME), options)
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
    let certificates = certificates();
    let upstream = Responder::start(&["a"]);
    let config = common::write_config("");
    let (certificate, key) = (
        config.with_extension("crt.pem"),
        config.with_extension("key.pem"),
    );
    std::fs::write(&certificate, &certificates.server_pem).expect("the certificate written");
    common::write_key(&key, &certificates.key_pem);
    let server = Server::configured(|listen| {
        format!(
            "listen: ['https://{listen}']\ntls:\n  certificate: '{}'\n  key: '{}'\npipeline: [cache, up]\nstages:\n  cache:\n    type: cache\n  up:\n    type: forward\n    servers: ['{}']\n    timeout_ms: 2000\n    tries: 1\n",
            certificate.display(),
            key.display(),
            upstream.addr
        )
    });
    let client = Client::new().trusting(Trust::Roots(vec![certificates.ca]));
    let runtime = compio::runtime::Runtime::new().expect("a runtime");
    println!("| Method | in flight | queries/s |\n|---|---|---|");
    runtime.block_on(async {
        for (label, method) in [("GET", Method::Get), ("POST", Method::Post)] {
            let mut options = Options::default();
            options.transport = Transport::Https;
            options.method = method;
            // The connection opened and the cache warm.
            let query = decode(&query_for(&captured("a"), 0));
            client
                .exchange(query, named(server.addr, NAME), &options)
                .await
                .expect("a response");
            for in_flight in IN_FLIGHT {
                let rate = rate(&client, server.addr, &options, in_flight).await;
                println!("| DoH3 {label} | {in_flight} | {rate:.0} |");
            }
        }
    });
}
