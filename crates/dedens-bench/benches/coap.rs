//! CoAP for DNS over CoAP (D80): a `DoC` request and response read and written, on the datagrams of
//! `crates/dedens-net/tests/testdata/coap/fetch_doc.txt` (aiocoap's FETCH for `gmail.com MX` and the real response),
//! and a whole exchange of them, through `Exchange`.

use std::hint::black_box;
use std::net::SocketAddr;
use std::time::Instant;

use dedens_net::coap::Message;
use dedens_net::coap::exchange::{Exchange, Next, Params, Request};
use divan::Bencher;

#[global_allocator]
static ALLOC: dedens_bench::alloc::Profiled = dedens_bench::alloc::profiled();

fn main() {
    divan::main();
}

/// The captured datagrams: the request, then the response.
fn captured() -> [Vec<u8>; 2] {
    let path = format!(
        "{}/../dedens-net/tests/testdata/coap/fetch_doc.txt",
        env!("CARGO_MANIFEST_DIR")
    );
    let text = std::fs::read_to_string(&path).expect("the capture is there");
    let mut datagrams = text
        .lines()
        .filter(|line| !line.starts_with('#'))
        .filter_map(|line| line.split(' ').nth(2))
        .map(|hex| {
            (0..hex.len())
                .step_by(2)
                .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).expect("hex"))
                .collect::<Vec<u8>>()
        });
    [
        datagrams.next().expect("a request"),
        datagrams.next().expect("a response"),
    ]
}

#[divan::bench(args = ["request", "response"])]
fn parse(bencher: Bencher<'_, '_>, which: &str) {
    let [request, response] = captured();
    let wire = if which == "request" {
        request
    } else {
        response
    };
    bencher.bench_local(|| Message::parse(black_box(&wire)).expect("a message"));
}

#[divan::bench(args = ["request", "response"])]
fn write(bencher: Bencher<'_, '_>, which: &str) {
    let [request, response] = captured();
    let wire = if which == "request" {
        request
    } else {
        response
    };
    let message = Message::parse(&wire).expect("a message");
    bencher.bench_local(|| black_box(&message).to_vec().expect("a message writes"));
}

/// One query: the exchange starts with the request, the response comes, the exchange ends.
#[divan::bench]
fn exchange(bencher: Bencher<'_, '_>) {
    let [request, response] = captured();
    let request = Message::parse(&request).expect("a request");
    let server: SocketAddr = "127.0.0.1:5683".parse().expect("an address");
    let now = Instant::now();
    bencher.bench_local(|| {
        let request = Request {
            code: request.code,
            options: request.options.clone(),
            payload: request.payload.clone(),
            token: request.token,
        };
        let step = Exchange::start(request, server, Params::default(), 1, 1, now);
        let Next::Wait(exchange) = step.next else {
            unreachable!("a request waits")
        };
        exchange.receive(server, black_box(&response), now)
    });
}
