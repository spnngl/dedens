//! DNS over HTTPS (D82): the request a query makes, the DNS response an HTTP response holds, and the same for a
//! server, on the captured responses `a`, `mx` and `txt_large`. HTTP/2 and HTTP/3 are not measured: they are
//! the `h2` and `h3` crates'.

use std::hint::black_box;
use std::time::{Duration, UNIX_EPOCH};

use dedens_bench::{CASES, wire};
use dedens_net::doh::{
    MEDIA_TYPE, Method, Template, request, response, server_request, server_response,
};
use dedens_proto::{Edns, Message};
use divan::Bencher;
use http::header::{AGE, CONTENT_TYPE};

#[global_allocator]
static ALLOC: dedens_bench::alloc::Profiled = dedens_bench::alloc::profiled();

fn main() {
    divan::main();
}

fn template() -> Template {
    Template::parse("https://dnsserver.example.net/dns-query{?dns}").expect("a template")
}

/// A query for the captured response `case`, ID 0 with EDNS, as a `DoH` client sends it.
fn query_for(case: &str) -> Vec<u8> {
    let response = wire(case);
    let message = Message::decode(&response).expect("decodes").message;
    let mut query = Message::query(0, message.questions[0].clone().into_owned());
    query.edns = Some(Edns::default());
    query.to_vec().expect("a query fits")
}

#[divan::bench(args = CASES)]
fn request_get(bencher: Bencher<'_, '_>, case: &str) {
    let (template, query) = (template(), query_for(case));
    bencher.bench_local(|| request(&template, black_box(&query), Method::Get).expect("a request"));
}

#[divan::bench(args = CASES)]
fn request_post(bencher: Bencher<'_, '_>, case: &str) {
    let (template, query) = (template(), query_for(case));
    bencher.bench_local(|| request(&template, black_box(&query), Method::Post).expect("a request"));
}

/// A 200 response of the DNS media type, aged by `age` seconds when it is not 0.
fn http_response(age: u32) -> http::Response<()> {
    let mut builder = http::Response::builder()
        .status(200)
        .header(CONTENT_TYPE, MEDIA_TYPE);
    if age > 0 {
        builder = builder.header(AGE, age);
    }
    builder.body(()).expect("a response")
}

/// The response as received: parsed, the TTLs untouched.
#[divan::bench(args = CASES)]
fn response_fresh(bencher: Bencher<'_, '_>, case: &str) {
    let (headers, body) = (http_response(0), wire(case));
    let now = UNIX_EPOCH + Duration::from_secs(1_793_522_455);
    bencher
        .bench_local(|| response(black_box(&headers), black_box(&body), now).expect("a response"));
}

/// The response a cache kept for 10 seconds: every TTL lowered.
#[divan::bench(args = CASES)]
fn response_aged(bencher: Bencher<'_, '_>, case: &str) {
    let (headers, body) = (http_response(10), wire(case));
    let now = UNIX_EPOCH + Duration::from_secs(1_793_522_455);
    bencher
        .bench_local(|| response(black_box(&headers), black_box(&body), now).expect("a response"));
}

#[divan::bench(args = CASES)]
fn server_request_get(bencher: Bencher<'_, '_>, case: &str) {
    let get = request(&template(), &query_for(case), Method::Get)
        .expect("a request")
        .map(|_| ());
    bencher.bench_local(|| server_request(black_box(&get), &[]).expect("a query"));
}

#[divan::bench(args = CASES)]
fn server_response_get(bencher: Bencher<'_, '_>, case: &str) {
    let body = wire(case);
    bencher.bench_local(|| {
        server_response(black_box(body.clone()), &http::Method::GET).expect("a response")
    });
}
