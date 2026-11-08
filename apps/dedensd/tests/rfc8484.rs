//! Serving DNS over HTTPS (RFC 8484) over HTTP/3 (RFC 9114), on addresses behind `https://` with the certificate of
//! `tls` (D84): the answers, their `cache-control`, the statuses of requests that are no query, the path.

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
use common::{Responder, Server, decode, query_for, write_config};
use compio::bytes::{Buf, Bytes};
use compio::quic::{ClientBuilder, h3};
use compio::runtime::{Runtime, spawn};
use compio::rustls::RootCertStore;
use dedens_net::client::Client;
use dedens_net::doh::{MEDIA_TYPE, Method, Template, request};
use dedens_net::exchange::Options;
use dedens_net::tls::Trust;
use dedens_proto::{Message, Rcode, Transport};
use dedens_testkit::captured;
use http::header::{CACHE_CONTROL, CONTENT_TYPE};
use http::{HeaderMap, StatusCode};

/// `dedensd` answering `DoH` over HTTP/3 on `listen` (`ADDR`, then the path) with the certificate of `certificates`,
/// forwarding to `upstream`.
fn serving(certificates: &Certificates, listen_path: &str, upstream: SocketAddr) -> Server {
    let config = write_config("");
    let (certificate, key) = (
        config.with_extension("crt.pem"),
        config.with_extension("key.pem"),
    );
    std::fs::write(&certificate, &certificates.server_pem).expect("the certificate written");
    common::write_key(&key, &certificates.key_pem);
    Server::configured(|listen| {
        format!(
            "listen: ['https://{listen}{listen_path}']\ntls:\n  certificate: '{}'\n  key: '{}'\npipeline: [up]\nstages:\n  up:\n    type: forward\n    servers: ['{upstream}']\n    timeout_ms: 2000\n    tries: 1\n",
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

/// The request of `method` for the query `wire` at `path` of the server at `addr`, as the client makes it.
fn query_request(addr: SocketAddr, path: &str, method: Method) -> http::Request<Vec<u8>> {
    let template =
        Template::parse(&format!("https://{NAME}:{}{path}", addr.port())).expect("a template");
    request(&template, &query_for(&captured("a"), 0), method).expect("a request")
}

/// A request that is no query: `method` at `path` with an optional content type.
fn other(
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

/// The least TTL of the answer in the DNS message `wire`.
fn least_ttl(wire: &[u8]) -> u32 {
    decode(wire)
        .answer
        .iter()
        .map(|record| record.ttl.get())
        .min()
        .expect("an answer")
}

/// §4.1: both methods are answered, through the pipeline as any query; the replies are padded, as the clients' queries
/// are (RFC 8467).
#[test]
fn s4_1_clients_get_and_post_answers() {
    let response = captured("a");
    let upstream = Responder::start(&["a"]);
    let ca = certificates();
    let server = serving(&ca, "", upstream.addr);
    for method in [Method::Get, Method::Post] {
        // A client of its own: its connection lives on the runtime that opened it.
        let client = Client::new().trusting(Trust::Roots(vec![ca.ca.clone()]));
        let mut options = Options::default();
        options.transport = Transport::Https;
        options.method = method;
        options.tries = NonZero::<u8>::MIN;
        let query = decode(&query_for(&response, 0));
        let reply = Runtime::new().expect("a runtime").block_on(async {
            let response = client
                .exchange(query, named(server.addr, NAME), &options)
                .await
                .expect("an answer");
            assert_eq!(response.transport, Transport::Https);
            decode(&response.wire)
        });
        assert_eq!(
            (reply.rcode(), &reply.answer),
            (Rcode::NOERROR, &decode(&response).answer),
            "{method:?}"
        );
        assert_eq!(
            reply.to_vec().expect("encodes").len() % 468,
            0,
            "{method:?}"
        );
    }
    assert_eq!(upstream.queries(), 2);
}

/// §5.1: a GET's `cache-control` has the least TTL of the answer; a POST's has none.
#[test]
fn s5_1_cache_control_is_the_least_ttl() {
    let upstream = Responder::start(&["a"]);
    let ca = certificates();
    let server = serving(&ca, "", upstream.addr);
    let get = query_request(server.addr, "/dns-query", Method::Get);
    let got = send(server.addr, &ca, get.map(|_| ()), &[]);
    assert_eq!(got.status, StatusCode::OK);
    assert_eq!(got.headers[CONTENT_TYPE], MEDIA_TYPE);
    assert_eq!(
        got.headers[CACHE_CONTROL],
        format!("max-age={}", least_ttl(&got.body))
    );
    let post = query_request(server.addr, "/dns-query", Method::Post);
    let (head, body) = post.into_parts();
    let got = send(server.addr, &ca, http::Request::from_parts(head, ()), &body);
    assert_eq!(got.status, StatusCode::OK);
    assert_eq!(got.headers[CONTENT_TYPE], MEDIA_TYPE);
    assert!(!got.headers.contains_key(CACHE_CONTROL));
    assert_eq!(
        Message::decode(&got.body)
            .expect("a message")
            .message
            .rcode(),
        Rcode::NOERROR
    );
}

/// §4.1, §6: what is no query gets a status and no message: 415 for a POST of another media type, 405 for another
/// method, 400 for a GET without a query or a query that is no message, 413 for a body past a message's size.
#[test]
fn s4_2_1_requests_that_are_no_query_get_statuses() {
    let upstream = Responder::start(&["a"]);
    let ca = certificates();
    let server = serving(&ca, "", upstream.addr);
    let addr = server.addr;
    let post = |content_type| other(addr, http::Method::POST, "/dns-query", content_type);
    for (request, body, status) in [
        (
            post(Some("text/plain")),
            vec![0; 12],
            StatusCode::UNSUPPORTED_MEDIA_TYPE,
        ),
        (post(None), vec![0; 12], StatusCode::UNSUPPORTED_MEDIA_TYPE),
        (
            other(addr, http::Method::PUT, "/dns-query", Some(MEDIA_TYPE)),
            vec![0; 12],
            StatusCode::METHOD_NOT_ALLOWED,
        ),
        (
            other(addr, http::Method::DELETE, "/dns-query", None),
            vec![],
            StatusCode::METHOD_NOT_ALLOWED,
        ),
        (
            other(addr, http::Method::GET, "/dns-query", None),
            vec![],
            StatusCode::BAD_REQUEST,
        ),
        (
            other(addr, http::Method::GET, "/dns-query?dns=AA", None),
            vec![],
            // Too short to be a DNS message: the pipeline drops it.
            StatusCode::BAD_REQUEST,
        ),
        (
            post(Some(MEDIA_TYPE)),
            vec![0; 65536],
            StatusCode::PAYLOAD_TOO_LARGE,
        ),
    ] {
        let uri = request.uri().to_string();
        let got = send(addr, &ca, request, &body);
        assert_eq!(got.status, status, "{uri}");
        assert!(got.body.is_empty(), "{uri}");
    }
    assert_eq!(upstream.queries(), 0);
}

/// §3: the service is at the path of the listener, `/dns-query` unless set; another path is 404.
#[test]
fn s3_the_path_is_the_listeners() {
    let upstream = Responder::start(&["a"]);
    let ca = certificates();
    for (listen_path, served, not_served) in
        [("", "/dns-query", "/doh"), ("/doh", "/doh", "/dns-query")]
    {
        let server = serving(&ca, listen_path, upstream.addr);
        let get = |path| query_request(server.addr, path, Method::Get).map(|_| ());
        let got = send(server.addr, &ca, get(served), &[]);
        assert_eq!(got.status, StatusCode::OK, "{served}");
        let got = send(server.addr, &ca, get(not_served), &[]);
        assert_eq!(got.status, StatusCode::NOT_FOUND, "{not_served}");
        assert!(got.body.is_empty(), "{not_served}");
    }
}

/// §4.2.1: an upstream failure is still an answer with status 200, a DNS error.
#[test]
fn s4_2_1_an_upstream_failure_is_a_dns_error() {
    let (silent, upstream) = common::silent();
    let ca = certificates();
    let server = serving(&ca, "", upstream);
    let get = query_request(server.addr, "/dns-query", Method::Get);
    let got = send(server.addr, &ca, get.map(|_| ()), &[]);
    assert_eq!(got.status, StatusCode::OK);
    assert_eq!(decode(&got.body).rcode(), Rcode::SERVFAIL);
    assert_eq!(got.headers[CACHE_CONTROL], "max-age=0");
    drop(silent);
}
