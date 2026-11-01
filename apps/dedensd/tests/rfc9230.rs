//! Serving Oblivious `DoH` (RFC 9230 §8) as a target on the HTTP/3 listener (D79): the configurations at their
//! well-known path, queries opened and answered through the pipeline, the statuses of §4.3, a key from a file.
#![cfg(feature = "odoh")]

#[path = "../../../crates/dedens-net/tests/common/certificates.rs"]
#[allow(
    dead_code,
    reason = "shared with the tests of dedens-net, which use all of it"
)]
mod certificates;
mod common;

use std::net::SocketAddr;
use std::num::NonZero;

use certificates::{Certificates, NAME, certificates, named};
use common::{Responder, Server, captured, decode, query_for, write_config};
use compio::bytes::{Buf, Bytes};
use compio::quic::{ClientBuilder, h3};
use compio::runtime::{Runtime, spawn};
use compio::rustls::RootCertStore;
use dedens_net::client::Client;
use dedens_net::exchange::{Options, Transport};
use dedens_net::odoh::{CONFIGS_PATH, Entropy};
use dedens_net::tls::Trust;
use dedens_odoh::{MEDIA_TYPE, ObliviousDoHConfigs, encrypt_query};
use dedens_proto::Rcode;
use http::header::{CACHE_CONTROL, CONTENT_TYPE};
use http::{HeaderMap, StatusCode};

/// `dedensd` answering over HTTP/3 with the certificate of `certificates`, forwarding to `upstream`; `odoh` is the
/// lines of its `odoh` section, none for a server that is no target.
fn serving(certificates: &Certificates, odoh: &str, upstream: SocketAddr) -> Server {
    let config = write_config("");
    let (certificate, key) = (
        config.with_extension("crt.pem"),
        config.with_extension("key.pem"),
    );
    std::fs::write(&certificate, &certificates.server_pem).expect("the certificate written");
    std::fs::write(&key, &certificates.key_pem).expect("the key written");
    Server::configured(|listen| {
        format!(
            "listen: ['https://{listen}']\ntls:\n  certificate: '{}'\n  key: '{}'\n{odoh}pipeline: [up]\nstages:\n  up:\n    type: forward\n    servers: ['{upstream}']\n    timeout_ms: 2000\n    tries: 1\n",
            certificate.display(),
            key.display()
        )
    })
}

/// The answer of an HTTP/3 server to a request.
struct Got {
    status: StatusCode,
    headers: HeaderMap,
    body: Vec<u8>,
}

/// Sends `request` with `body` to the HTTP/3 server at `addr`, trusting `certificates`, and reads the response.
fn send(
    addr: SocketAddr,
    certificates: &Certificates,
    request: http::Request<()>,
    body: &[u8],
) -> Got {
    let mut roots = RootCertStore::empty();
    roots.add(certificates.ca.clone()).expect("a root");
    Runtime::new().expect("a runtime").block_on(async {
        let endpoint = ClientBuilder::new_with_root_certificates(roots)
            .with_alpn_protocols(&["h3"])
            .bind("127.0.0.1:0")
            .await
            .expect("a QUIC endpoint");
        let connection = endpoint
            .connect(addr, NAME, None)
            .expect("connecting")
            .await
            .expect("connected");
        let (mut driver, mut requests) = h3::client::new(connection).await.expect("HTTP/3");
        spawn(async move { driver.wait_idle().await }).detach();
        let mut stream = requests.send_request(request).await.expect("a stream");
        if !body.is_empty() {
            stream
                .send_data(Bytes::copy_from_slice(body))
                .await
                .expect("the body sent");
        }
        stream.finish().await.expect("the request finished");
        let head = stream.recv_response().await.expect("a response");
        let mut body = Vec::new();
        while let Some(mut chunk) = stream.recv_data().await.expect("the body") {
            body.extend_from_slice(&chunk.copy_to_bytes(chunk.remaining()));
        }
        Got {
            status: head.status(),
            headers: head.headers().clone(),
            body,
        }
    })
}

/// A request of `method` at `path` of the server at `addr`, of content type `content_type` if given.
fn request(
    addr: SocketAddr,
    method: http::Method,
    path: &str,
    content_type: Option<&str>,
) -> http::Request<()> {
    let mut builder = http::Request::builder()
        .method(method)
        .uri(format!("https://{NAME}:{}{path}", addr.port()));
    if let Some(value) = content_type {
        builder = builder.header(CONTENT_TYPE, value);
    }
    builder.body(()).expect("a request")
}

/// The configurations the server at `addr` serves.
fn configs(addr: SocketAddr, certificates: &Certificates) -> Vec<u8> {
    let got = send(
        addr,
        certificates,
        request(addr, http::Method::GET, CONFIGS_PATH, None),
        &[],
    );
    assert_eq!(got.status, StatusCode::OK);
    got.body
}

/// RFC 9230 §4.2, §8: a client fetches the target's configurations, encrypts its query to them, and gets the answer
/// of the pipeline, sealed, from the loopback target.
#[test]
fn s8_a_client_is_answered_through_the_pipeline() {
    let response = captured("a");
    let upstream = Responder::start(&["a"]);
    let ca = certificates();
    let server = serving(&ca, "odoh: {}\n", upstream.addr);
    let client = Client::new().trusting(Trust::Roots(vec![ca.ca.clone()]));
    let mut options = Options::default();
    options.tries = NonZero::<u8>::MIN;
    let query = decode(&query_for(&response, 0));
    let reply = Runtime::new().expect("a runtime").block_on(async {
        let response = client
            .exchange_oblivious(query, named(server.addr, NAME), None, &options)
            .await
            .expect("an answer");
        assert_eq!(response.transport, Transport::Odoh);
        decode(&response.wire)
    });
    assert_eq!(
        (reply.rcode(), &reply.answer),
        (Rcode::NOERROR, &decode(&response).answer)
    );
    assert_eq!(upstream.queries(), 1);
}

/// RFC 9230 §5, D79: the configurations are served at the well-known path and may be kept an hour; only a GET
/// reads them.
#[test]
fn s5_the_configurations_are_served() {
    let upstream = Responder::start(&["a"]);
    let ca = certificates();
    let server = serving(&ca, "odoh: {}\n", upstream.addr);
    let get = request(server.addr, http::Method::GET, CONFIGS_PATH, None);
    let got = send(server.addr, &ca, get, &[]);
    assert_eq!(got.status, StatusCode::OK);
    assert_eq!(got.headers[CACHE_CONTROL], "max-age=3600");
    assert_eq!(
        ObliviousDoHConfigs::parse(&got.body)
            .expect("configurations")
            .configs()
            .len(),
        1
    );
    let post = request(server.addr, http::Method::POST, CONFIGS_PATH, None);
    let got = send(server.addr, &ca, post, &[]);
    assert_eq!(got.status, StatusCode::METHOD_NOT_ALLOWED);
}

/// RFC 9230 §4.3: a query to another key is 401, so the client fetches the configurations again; one that does not
/// decrypt is 400.
#[test]
fn s4_3_a_wrong_key_is_401_and_garbage_400() {
    let upstream = Responder::start(&["a"]);
    let ca = certificates();
    let (one, other) = (
        serving(&ca, "odoh: {}\n", upstream.addr),
        serving(&ca, "odoh: {}\n", upstream.addr),
    );
    let parsed = ObliviousDoHConfigs::parse(&configs(other.addr, &ca)).expect("configurations");
    let mut entropy = Entropy::new().expect("randomness");
    let (message, _) = encrypt_query(
        &parsed.configs()[0],
        &query_for(&captured("a"), 0),
        0,
        &mut entropy,
    )
    .expect("a query");
    let post = || request(one.addr, http::Method::POST, "/dns-query", Some(MEDIA_TYPE));
    let got = send(one.addr, &ca, post(), &message.encode());
    assert_eq!(got.status, StatusCode::UNAUTHORIZED);
    assert_eq!(got.body, Vec::<u8>::new());
    let got = send(one.addr, &ca, post(), b"not a message");
    assert_eq!(got.status, StatusCode::BAD_REQUEST);
    assert_eq!(upstream.queries(), 0);
}

/// D79: a key file fixes the key across restarts; without one each start makes its own.
#[test]
fn a_key_file_fixes_the_configurations() {
    let upstream = Responder::start(&["a"]);
    let ca = certificates();
    let key = write_config(&format!("{}\n", "5a".repeat(32)));
    let section = format!("odoh:\n  key: '{}'\n", key.display());
    let (one, two) = (
        serving(&ca, &section, upstream.addr),
        serving(&ca, &section, upstream.addr),
    );
    assert_eq!(configs(one.addr, &ca), configs(two.addr, &ca));
    let (one, two) = (
        serving(&ca, "odoh: {}\n", upstream.addr),
        serving(&ca, "odoh: {}\n", upstream.addr),
    );
    assert_ne!(configs(one.addr, &ca), configs(two.addr, &ca));
}

/// D79: a server without `odoh` is no target: no configurations, and an oblivious message is a media type `DoH`
/// does not take. Plain `DoH` is answered with or without.
#[test]
fn a_server_without_odoh_is_no_target() {
    let upstream = Responder::start(&["a"]);
    let ca = certificates();
    let server = serving(&ca, "", upstream.addr);
    let get = request(server.addr, http::Method::GET, CONFIGS_PATH, None);
    assert_eq!(
        send(server.addr, &ca, get, &[]).status,
        StatusCode::NOT_FOUND
    );
    let post = request(
        server.addr,
        http::Method::POST,
        "/dns-query",
        Some(MEDIA_TYPE),
    );
    let got = send(server.addr, &ca, post, b"message");
    assert_eq!(got.status, StatusCode::UNSUPPORTED_MEDIA_TYPE);
}

/// D79: a target still answers plain `DoH` at the same path.
#[test]
fn a_target_answers_plain_doh_too() {
    let response = captured("a");
    let upstream = Responder::start(&["a"]);
    let ca = certificates();
    let server = serving(&ca, "odoh: {}\n", upstream.addr);
    let client = Client::new().trusting(Trust::Roots(vec![ca.ca.clone()]));
    let mut options = Options::default();
    options.transport = Transport::Https;
    options.tries = NonZero::<u8>::MIN;
    let query = decode(&query_for(&response, 0));
    let reply = Runtime::new().expect("a runtime").block_on(async {
        let response = client
            .exchange(query, named(server.addr, NAME), &options)
            .await
            .expect("an answer");
        decode(&response.wire)
    });
    assert_eq!(reply.rcode(), Rcode::NOERROR);
}
