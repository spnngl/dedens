//! Queries a second over DNS over HTTPS on HTTP/3 (D83) and DNS over QUIC (D61), against loopback servers answering
//! one response at once, client and servers on one thread: what the protocols cost, not the network. Run with
//! `cargo bench -p dedens-net --bench transports`; numbers go to `docs/benchmarks.md`.

use std::net::SocketAddr;
use std::rc::Rc;
use std::time::{Duration, Instant};

use certificates::{Certificates, NAME, certificates, named};
use compio::BufResult;
use compio::bytes::Bytes;
use compio::io::AsyncWriteExt;
use compio::quic::{ServerBuilder, h3};
use compio::rustls::version::TLS13;
use dedens_net::client::Client;
use dedens_net::doh::{Method, server_response};
use dedens_net::exchange::Options;
use dedens_net::tcp::frame;
use dedens_net::tls::Trust;
use dedens_proto::{Flags, Message, Question, RecordType, Transport};
use futures_util::future::join_all;

#[path = "../tests/common/certificates.rs"]
#[allow(dead_code, reason = "shared with the tests, which use all of it")]
mod certificates;

/// How long each measure runs.
const RUN: Duration = Duration::from_secs(3);

/// Queries in flight at once: one, then many sharing a connection.
const IN_FLIGHT: [usize; 2] = [1, 32];

/// The query every exchange asks: ID 0, as both transports send it.
fn query() -> Message<'static> {
    let name = "example.com.".parse().expect("a name");
    Message::query(0, Question::new(name, RecordType::A))
}

/// The one response every query gets: the query with QR and RA set.
fn response() -> Vec<u8> {
    let mut response = query();
    response.header.flags = response.header.flags.with(Flags::QR).with(Flags::RA);
    response.to_vec().expect("a response")
}

/// A `DoQ` server (RFC 9250): each stream's query answered, framed.
async fn quic_server(certificates: &Certificates, wire: Rc<Vec<u8>>) -> SocketAddr {
    let config = certificates.config(&[&TLS13], b"doq");
    let endpoint = ServerBuilder::new_with_rustls_server_config(config)
        .bind("127.0.0.1:0")
        .await
        .expect("a QUIC endpoint");
    let addr = endpoint.local_addr().expect("its address");
    compio::runtime::spawn(async move {
        while let Some(incoming) = endpoint.wait_incoming().await {
            let wire = Rc::clone(&wire);
            compio::runtime::spawn(async move {
                let Ok(connecting) = incoming.accept() else {
                    return;
                };
                let Ok(connection) = connecting.await else {
                    return;
                };
                while let Ok((mut send, mut recv)) = connection.accept_bi().await {
                    let wire = Rc::clone(&wire);
                    compio::runtime::spawn(async move {
                        let BufResult(read, _) = recv.read_to_end(Vec::new()).await;
                        if read.is_err() {
                            return;
                        }
                        let framed = frame(&wire).expect("framed");
                        let _ = send.write_all(framed).await;
                        let _ = send.finish();
                    })
                    .detach();
                }
            })
            .detach();
        }
    })
    .detach();
    addr
}

/// A `DoH` server (RFC 8484) on HTTP/3: each request answered.
async fn https_server(certificates: &Certificates, wire: Rc<Vec<u8>>) -> SocketAddr {
    let config = certificates.config(&[&TLS13], b"h3");
    let endpoint = ServerBuilder::new_with_rustls_server_config(config)
        .bind("127.0.0.1:0")
        .await
        .expect("a QUIC endpoint");
    let addr = endpoint.local_addr().expect("its address");
    compio::runtime::spawn(async move {
        while let Some(incoming) = endpoint.wait_incoming().await {
            let wire = Rc::clone(&wire);
            compio::runtime::spawn(async move {
                let Ok(connecting) = incoming.accept() else {
                    return;
                };
                let Ok(connection) = connecting.await else {
                    return;
                };
                let Ok(mut server) = h3::server::builder().build::<_, Bytes>(connection).await
                else {
                    return;
                };
                while let Ok(Some(resolver)) = server.accept().await {
                    let wire = Rc::clone(&wire);
                    compio::runtime::spawn(async move {
                        let Ok((request, mut stream)) = resolver.resolve_request().await else {
                            return;
                        };
                        let reply =
                            server_response(wire.to_vec(), request.method()).expect("a response");
                        let (head, body) = reply.into_parts();
                        let _ = stream
                            .send_response(http::Response::from_parts(head, ()))
                            .await;
                        let _ = stream.send_data(Bytes::from(body)).await;
                        let _ = stream.finish().await;
                    })
                    .detach();
                }
            })
            .detach();
        }
    })
    .detach();
    addr
}

/// Queries a second with `in_flight` loops asking until [`RUN`] is over.
async fn rate(client: &Client, addr: SocketAddr, options: &Options, in_flight: usize) -> f64 {
    let end = Instant::now() + RUN;
    let asked = || async {
        let mut done = 0_u64;
        while Instant::now() < end {
            client
                .exchange(query(), named(addr, NAME), options)
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
        let certificates = certificates();
        let wire = Rc::new(response());
        let quic = quic_server(&certificates, Rc::clone(&wire)).await;
        let https = https_server(&certificates, wire).await;
        let client = Client::new().trusting(Trust::Roots(vec![certificates.ca]));
        println!("| Transport | in flight | queries/s |\n|---|---|---|");
        for (label, addr, transport) in [
            ("DoQ", quic, Transport::Quic),
            ("DoH3 GET", https, Transport::Https),
            ("DoH3 POST", https, Transport::Https),
        ] {
            let mut options = Options::default();
            options.transport = transport;
            options.method = if label.ends_with("POST") {
                Method::Post
            } else {
                Method::Get
            };
            // The connection opened and warm.
            client
                .exchange(query(), named(addr, NAME), &options)
                .await
                .expect("a response");
            for in_flight in IN_FLIGHT {
                let rate = rate(&client, addr, &options, in_flight).await;
                println!("| {label} | {in_flight} | {rate:.0} |");
            }
        }
    });
}
