//! Serving Oblivious `DoH` (RFC 9230 §8) as a target on the HTTP/3 listener (D79): the configurations at their
//! well-known path, queries opened and answered through the pipeline, the statuses of §4.3, a key from a file; and as
//! a proxy (§4, D94): queries forwarded to the targets listed, the `Proxy-Status` of each failure (RFC 9209).
#![cfg(feature = "odoh")]

#[path = "../../../crates/dedens-net/tests/common/certificates.rs"]
#[allow(
    dead_code,
    reason = "shared with the tests of dedens-net, which use all of it"
)]
mod certificates;
mod common;

use std::net::{SocketAddr, UdpSocket};
use std::num::NonZero;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, mpsc};
use std::thread;
use std::time::{Duration, Instant};

use certificates::{Certificates, NAME, certificates, named};
use common::{Responder, Server, captured, decode, query_for, write_config};
use compio::bytes::{Buf, Bytes};
use compio::quic::{ClientBuilder, ServerBuilder, h3};
use compio::runtime::{Runtime, spawn};
use compio::rustls::RootCertStore;
use compio::rustls::version::TLS13;
use dedens_net::client::{Client, Server as Peer};
use dedens_net::exchange::Options;
use dedens_net::odoh::{CONFIGS_PATH, Entropy};
use dedens_net::tls::Trust;
use dedens_odoh::{Configs, MEDIA_TYPE, encrypt_query};
use dedens_proto::{Rcode, Transport};
use http::header::{ALLOW, CACHE_CONTROL, CONTENT_TYPE, FORWARDED, LOCATION, VIA};
use http::{HeaderMap, StatusCode};

/// `dedensd` answering over HTTP/3 with the certificate of `certificates`, forwarding to `upstream`; `odoh` is the
/// lines of its `odoh` section, none for a server that is no target.
fn serving(certificates: &Certificates, odoh: &str, upstream: SocketAddr) -> Server {
    serving_trusting(certificates, certificates, odoh, upstream)
}

/// As [`serving`], the servers it forwards to over HTTP/3 (a proxy's targets) checked against the authority of
/// `trusted`.
fn serving_trusting(
    certificates: &Certificates,
    trusted: &Certificates,
    odoh: &str,
    upstream: SocketAddr,
) -> Server {
    let config = write_config("");
    let (certificate, key, authority) = (
        config.with_extension("crt.pem"),
        config.with_extension("key.pem"),
        config.with_extension("ca.pem"),
    );
    std::fs::write(&certificate, &certificates.server_pem).expect("the certificate written");
    common::write_key(&key, &certificates.key_pem);
    std::fs::write(&authority, &trusted.ca_pem).expect("the authority written");
    Server::configured(|listen| {
        format!(
            "listen: ['https://{listen}']\ntls:\n  certificate: '{}'\n  key: '{}'\nupstream_ca: '{}'\n{odoh}pipeline: [up]\nstages:\n  up:\n    type: forward\n    servers: ['{upstream}']\n    timeout_ms: 2000\n    tries: 1\n",
            certificate.display(),
            key.display(),
            authority.display()
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
        Configs::parse(&got.body)
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
    let parsed = Configs::parse(&configs(other.addr, &ca)).expect("configurations");
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

/// A valid sealed query of the target at `addr`, as a client sends it.
fn valid_query(addr: SocketAddr, ca: &Certificates) -> Vec<u8> {
    let parsed = Configs::parse(&configs(addr, ca)).expect("configurations");
    let mut entropy = Entropy::new().expect("randomness");
    let (message, _) = encrypt_query(
        &parsed.configs()[0],
        &query_for(&captured("a"), 0),
        0,
        &mut entropy,
    )
    .expect("a query");
    message.encode()
}

/// D117, audit S14: posts past a budget are 503 before their body is opened, so the upstream is asked for what was
/// opened and no more. All clients here are the loopback's, which `rrl.exempt` leaves out of the network budget by
/// default: the global one bounds them, and the network one once nothing is exempt. (That another network is still
/// opened is the unit test of `odoh::Service::open`.)
#[test]
fn d117_a_flood_of_posts_past_a_budget_is_503_before_it_is_opened() {
    for config in [
        "odoh:\n  budget: {rate: 1, burst: 2}\n",
        "rrl:\n  exempt: []\nodoh:\n  client_budget: {rate: 1, burst: 2}\n",
    ] {
        a_flood_is_refused_past_two_posts(config);
    }
}

fn a_flood_is_refused_past_two_posts(config: &str) {
    let upstream = Responder::start(&["a"]);
    let ca = certificates();
    let server = serving(&ca, config, upstream.addr);
    let message = valid_query(server.addr, &ca);
    let post = |body: &[u8]| {
        let post = request(
            server.addr,
            http::Method::POST,
            "/dns-query",
            Some(MEDIA_TYPE),
        );
        send(server.addr, &ca, post, body).status
    };
    let start = Instant::now();
    let statuses: Vec<_> = (0..20).map(|_| post(&message)).collect();
    // The bucket holds 2 and refills one a second, so no more than 2 plus the seconds the posts took, and one
    // for the second that began before them, are opened, however fast the posts are.
    let bound = 3 + usize::try_from(start.elapsed().as_secs()).expect("seconds");
    let opened = statuses
        .iter()
        .filter(|&&status| status == StatusCode::OK)
        .count();
    assert!(
        (2..=bound).contains(&opened),
        "{opened} opened of {statuses:?}"
    );
    assert!(
        statuses.contains(&StatusCode::SERVICE_UNAVAILABLE),
        "a post is refused: {statuses:?}"
    );
    assert_eq!(upstream.queries(), opened);
}

/// D79: a key file fixes the key across restarts; without one each start makes its own.
#[test]
fn a_key_file_fixes_the_configurations() {
    let upstream = Responder::start(&["a"]);
    let ca = certificates();
    let key = write_config("");
    common::write_key(&key, format!("{}\n", "5a".repeat(32)));
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

/// The proxy section listing `targets`, with a timeout short enough for a test of one that never answers.
fn proxy_section(targets: &[String]) -> String {
    let targets = targets
        .iter()
        .map(|target| format!("'{target}'"))
        .collect::<Vec<_>>()
        .join(", ");
    format!("odoh:\n  proxy:\n    targets: [{targets}]\n    timeout_ms: 1000\n")
}

/// The target at `addr`, named by its address.
fn at(addr: SocketAddr) -> Peer {
    Peer {
        addr,
        name: None,
        doh: None,
        docpath: Vec::new(),
    }
}

/// The path at a proxy that asks it for `path` at the target `host` (RFC 9230 §4.2).
fn forwarding(host: &str, path: &str) -> String {
    let escaped = |text: &str| text.replace(':', "%3A").replace('/', "%2F");
    format!(
        "/dns-query?targethost={}&targetpath={}",
        escaped(host),
        escaped(path)
    )
}

/// POSTs `body` at `path` of the proxy, an oblivious message.
fn through(proxy: &Server, ca: &Certificates, path: &str, body: &[u8]) -> Got {
    let post = request(proxy.addr, http::Method::POST, path, Some(MEDIA_TYPE));
    send(proxy.addr, ca, post, body)
}

/// The `Proxy-Status` of a response.
fn proxy_status(got: &Got) -> &str {
    got.headers
        .get("proxy-status")
        .and_then(|value| value.to_str().ok())
        .unwrap_or_default()
}

/// A query for the target at `addr`, encrypted to its configurations.
fn sealed_query(addr: SocketAddr, ca: &Certificates) -> Vec<u8> {
    let parsed = Configs::parse(&configs(addr, ca)).expect("configurations");
    let mut entropy = Entropy::new().expect("randomness");
    let (message, _) = encrypt_query(
        &parsed.configs()[0],
        &query_for(&captured("a"), 0),
        0,
        &mut entropy,
    )
    .expect("a query");
    message.encode()
}

/// An HTTP/3 server on the loopback that refuses every connection (RFC 9000 §5.2.2), until the process ends.
fn refusing(certificates: &Certificates) -> SocketAddr {
    let config = certificates.config(&[&TLS13], b"h3");
    let (send, receive) = mpsc::channel();
    thread::spawn(move || {
        Runtime::new().expect("a runtime").block_on(async move {
            let endpoint = ServerBuilder::new_with_rustls_server_config(config)
                .bind("127.0.0.1:0")
                .await
                .expect("a QUIC endpoint");
            send.send(endpoint.local_addr().expect("its address"))
                .expect("sent");
            while let Some(incoming) = endpoint.wait_incoming().await {
                incoming.refuse();
            }
        });
    });
    receive.recv().expect("its address")
}

/// How a [`Recording`] target answers.
#[derive(Clone, Copy)]
enum Answers {
    /// 200 with the oblivious media type and a body.
    Message,
    /// 200 with another content type.
    Text,
    /// Nothing, once the request is read.
    Silence,
}

/// What a [`recording`] target saw.
struct Recording {
    addr: SocketAddr,
    /// The connections it accepted.
    connections: Arc<AtomicUsize>,
    /// The head fields of each request it read, with its method and path.
    requests: Arc<Mutex<Vec<(String, HeaderMap)>>>,
}

/// An HTTP/3 server on the loopback, answering as `answers` says and keeping what it sees, until the process ends.
fn recording(certificates: &Certificates, answers: Answers) -> Recording {
    let config = certificates.config(&[&TLS13], b"h3");
    let seen = Recording {
        addr: SocketAddr::from(([127, 0, 0, 1], 0)),
        connections: Arc::default(),
        requests: Arc::default(),
    };
    let (connections, requests) = (Arc::clone(&seen.connections), Arc::clone(&seen.requests));
    let (send, receive) = mpsc::channel();
    thread::spawn(move || {
        Runtime::new().expect("a runtime").block_on(async move {
            let endpoint = ServerBuilder::new_with_rustls_server_config(config)
                .bind("127.0.0.1:0")
                .await
                .expect("a QUIC endpoint");
            send.send(endpoint.local_addr().expect("its address"))
                .expect("sent");
            while let Some(incoming) = endpoint.wait_incoming().await {
                let (connections, requests) = (Arc::clone(&connections), Arc::clone(&requests));
                spawn(async move {
                    let Ok(connecting) = incoming.accept() else {
                        return;
                    };
                    let Ok(connection) = connecting.await else {
                        return;
                    };
                    connections.fetch_add(1, Ordering::SeqCst);
                    let Ok(mut server) = h3::server::builder().build::<_, Bytes>(connection).await
                    else {
                        return;
                    };
                    while let Ok(Some(resolver)) = server.accept().await {
                        let requests = Arc::clone(&requests);
                        spawn(async move {
                            let Ok((request, mut stream)) = resolver.resolve_request().await else {
                                return;
                            };
                            while let Ok(Some(_)) = stream.recv_data().await {}
                            let line = format!("{} {}", request.method(), request.uri());
                            requests
                                .lock()
                                .expect("a lock")
                                .push((line, request.headers().clone()));
                            let content_type = match answers {
                                Answers::Message => MEDIA_TYPE,
                                Answers::Text => "text/plain",
                                Answers::Silence => {
                                    compio::time::sleep(Duration::from_secs(30)).await;
                                    return;
                                }
                            };
                            let head = http::Response::builder()
                                .status(StatusCode::OK)
                                .header(CONTENT_TYPE, content_type)
                                .body(())
                                .expect("a response");
                            stream.send_response(head).await.expect("the client reads");
                            stream
                                .send_data(Bytes::from_static(b"an answer"))
                                .await
                                .expect("the client reads");
                            stream.finish().await.expect("an open stream");
                        })
                        .detach();
                    }
                })
                .detach();
            }
        });
    });
    Recording {
        addr: receive.recv().expect("its address"),
        ..seen
    }
}

/// A client sends its query through a proxy to a loopback target and is answered as it is straight from the target;
/// a proxy is a target too: a request that names none is answered as such (RFC 9230 §4, D94).
#[test]
fn s4_a_client_is_answered_through_a_proxy() {
    let response = captured("a");
    let upstream = Responder::start(&["a"]);
    let ca = certificates();
    let target = serving(&ca, "odoh: {}\n", upstream.addr);
    let listed = format!("127.0.0.1:{}", target.addr.port());
    let proxy = serving(&ca, &proxy_section(&[listed]), upstream.addr);
    let client = Client::new().trusting(Trust::Roots(vec![ca.ca.clone()]));
    let mut options = Options::default();
    options.tries = NonZero::<u8>::MIN;
    let ask = async |target: Peer, via: Option<Peer>| {
        let query = decode(&query_for(&response, 0));
        let response = client
            .exchange_oblivious(query, target, via, &options)
            .await
            .expect("an answer");
        assert_eq!(response.transport, Transport::Odoh);
        decode(&response.wire)
    };
    let runtime = Runtime::new().expect("a runtime");
    let through = runtime.block_on(ask(at(target.addr), Some(named(proxy.addr, NAME))));
    assert_eq!(
        (through.rcode(), &through.answer),
        (Rcode::NOERROR, &decode(&response).answer)
    );
    assert_eq!(upstream.queries(), 1);
    let itself = runtime.block_on(ask(named(proxy.addr, NAME), None));
    assert_eq!(itself.rcode(), Rcode::NOERROR);
    assert_eq!(upstream.queries(), 2);
}

/// RFC 9230 §4.3, D94: the target's response goes back with its status and body, never cacheable, marked
/// with its `received-status`; nothing of the target's but the content type comes back; each request is forwarded,
/// none answered from memory.
#[test]
fn s4_3_the_targets_response_is_returned_and_never_cached() {
    let upstream = Responder::start(&["a"]);
    let ca = certificates();
    let (target, other) = (
        serving(&ca, "odoh: {}\n", upstream.addr),
        serving(&ca, "odoh: {}\n", upstream.addr),
    );
    let host = format!("127.0.0.1:{}", target.addr.port());
    let proxy = serving(
        &ca,
        &proxy_section(std::slice::from_ref(&host)),
        upstream.addr,
    );
    let path = forwarding(&host, "/dns-query");
    let query = sealed_query(target.addr, &ca);
    for _ in 0..2 {
        let got = through(&proxy, &ca, &path, &query);
        assert_eq!(got.status, StatusCode::OK);
        assert_eq!(got.headers[CONTENT_TYPE], MEDIA_TYPE);
        assert_eq!(got.headers[CACHE_CONTROL], "no-cache, no-store");
        assert!(proxy_status(&got).contains("received-status=200"));
        for header in [VIA, FORWARDED, LOCATION] {
            assert!(!got.headers.contains_key(&header), "{header}");
        }
        assert_ne!(got.body.len(), 0);
    }
    assert_eq!(upstream.queries(), 2);
    // The target's 401, for a query to another key, as it is.
    let foreign = sealed_query(other.addr, &ca);
    let got = through(&proxy, &ca, &path, &foreign);
    assert_eq!(got.status, StatusCode::UNAUTHORIZED);
    assert_eq!(got.body.len(), 0);
    assert!(proxy_status(&got).contains("received-status=401"));
}

/// RFC 9230 §4.1, RFC 9209 §2.3, D94: a request that is no request for the proxy is 400, a target or port not
/// listed 403, one that cannot be reached 502, one that does not answer in time 504, each with its `Proxy-Status`
/// `error`.
#[test]
fn s4_1_a_proxy_that_cannot_forward_says_why() {
    let upstream = Responder::start(&["a"]);
    let ca = certificates();
    let target = serving(&ca, "odoh: {}\n", upstream.addr);
    let port = target.addr.port();
    let host = format!("127.0.0.1:{port}");
    let refused = refusing(&ca);
    // Bound and never read from: a connection to it waits for an answer.
    let silent = UdpSocket::bind("127.0.0.1:0").expect("a UDP port");
    let silent_addr = silent.local_addr().expect("its address");
    let proxy = serving(
        &ca,
        &proxy_section(&[
            host.clone(),
            "nonexistent.invalid".to_owned(),
            format!("localhost:{port}"),
            refused.to_string(),
            silent_addr.to_string(),
        ]),
        upstream.addr,
    );
    let host_only = format!("/dns-query?targethost=127.0.0.1%3A{port}");
    let twice = forwarding(&host, "/dns-query") + &format!("&targethost=127.0.0.1%3A{port}");
    let cases = [
        (
            "/dns-query?targetpath=%2Fdns-query".to_owned(),
            400,
            "http_request_error",
        ),
        (host_only, 400, "http_request_error"),
        (twice, 400, "http_request_error"),
        (forwarding(&host, "dns-query"), 400, "http_request_error"),
        (
            forwarding(&format!("127.0.0.2:{port}"), "/dns-query"),
            403,
            "http_request_denied",
        ),
        (
            forwarding("127.0.0.1", "/dns-query"),
            403,
            "http_request_denied",
        ),
        (
            forwarding("127.0.0.1:1", "/dns-query"),
            403,
            "http_request_denied",
        ),
        (
            forwarding("nonexistent.invalid", "/dns-query"),
            502,
            "dns_error",
        ),
        (
            forwarding(&format!("localhost:{port}"), "/dns-query"),
            502,
            "destination_ip_prohibited",
        ),
        (
            forwarding(&refused.to_string(), "/dns-query"),
            502,
            "connection_refused",
        ),
        (
            forwarding(&silent_addr.to_string(), "/dns-query"),
            504,
            "connection_timeout",
        ),
    ];
    for (path, status, error) in cases {
        let got = through(&proxy, &ca, &path, b"an encrypted query");
        assert_eq!(got.status.as_u16(), status, "{path}");
        let expected = format!("dedensd; error={error}");
        let status = proxy_status(&got);
        assert!(status.starts_with(&expected), "{path}: {status}");
        // A refusal to forward says what it refused (RFC 9230 §4.1), the other errors need no more.
        assert_eq!(
            status.contains("details="),
            StatusCode::FORBIDDEN == got.status,
            "{path}: {status}"
        );
        assert!(got.body.is_empty(), "{path}");
        assert_eq!(got.headers[CACHE_CONTROL], "no-cache, no-store", "{path}");
    }
    // Nothing reached the target: it was never asked.
    assert_eq!(upstream.queries(), 0);
    // A request for the proxy is a POST of the media type, as a target's is.
    let path = forwarding(&host, "/dns-query");
    let get = request(proxy.addr, http::Method::GET, &path, None);
    let got = send(proxy.addr, &ca, get, &[]);
    assert_eq!(got.status, StatusCode::METHOD_NOT_ALLOWED);
    assert_eq!(got.headers[ALLOW], "POST");
    assert_eq!(proxy_status(&got), "dedensd; error=http_request_error");
    let plain = request(proxy.addr, http::Method::POST, &path, Some("text/plain"));
    assert_eq!(
        send(proxy.addr, &ca, plain, b"a").status,
        StatusCode::UNSUPPORTED_MEDIA_TYPE
    );
}

/// RFC 9230 §11.2, §4.5, D94: requests share the connection to a target, and the target sees nothing of the
/// client: no `Via`, `Forwarded`, `X-Forwarded-For` or cookie, and the request is the one the proxy builds.
#[test]
fn s11_2_forwards_share_a_connection_and_carry_nothing_of_the_client() {
    let upstream = Responder::start(&["a"]);
    let ca = certificates();
    let target = recording(&ca, Answers::Message);
    let host = format!("127.0.0.1:{}", target.addr.port());
    // One serving thread: each thread keeps its own pool of connections to the targets, so the connection is shared
    // per serving thread, and on Linux, where a thread serves per core, two clients may be served by two threads.
    let proxy = serving(
        &ca,
        &format!("threads: 1\n{}", proxy_section(std::slice::from_ref(&host))),
        upstream.addr,
    );
    let path = forwarding(&host, "/dns-query");
    let mut post = request(proxy.addr, http::Method::POST, &path, Some(MEDIA_TYPE));
    for (name, value) in [
        ("cookie", "session=1"),
        ("forwarded", "for=192.0.2.1"),
        ("x-forwarded-for", "192.0.2.1"),
        ("via", "1.1 client"),
        ("user-agent", "a client"),
    ] {
        post.headers_mut()
            .insert(name, http::HeaderValue::from_static(value));
    }
    let first = send(proxy.addr, &ca, post, b"an encrypted query");
    assert_eq!(first.status, StatusCode::OK);
    assert_eq!(first.body, b"an answer");
    // Another client of the proxy, on a connection of its own.
    let second = through(&proxy, &ca, &path, b"an encrypted query");
    assert_eq!(second.status, StatusCode::OK);
    assert_eq!(target.connections.load(Ordering::SeqCst), 1);
    let requests = target.requests.lock().expect("a lock");
    assert_eq!(requests.len(), 2);
    let line = format!("POST https://{host}/dns-query");
    for (seen, headers) in requests.iter() {
        assert_eq!(*seen, line);
        assert_eq!(headers[CONTENT_TYPE], MEDIA_TYPE);
        let names = headers
            .keys()
            .map(http::HeaderName::as_str)
            .collect::<Vec<_>>();
        for client in [
            "cookie",
            "forwarded",
            "x-forwarded-for",
            "via",
            "user-agent",
        ] {
            assert!(!names.contains(&client), "{client} in {names:?}");
        }
    }
}

/// RFC 9209 §2.3.26, §2.3.2, RFC 9230 §4.3, D94: a target that connects and does not answer is a timeout of the
/// response, not of the connection; one that answers with another content type is an HTTP protocol error.
#[test]
fn s4_3_a_target_that_does_not_answer_or_answers_wrongly() {
    let upstream = Responder::start(&["a"]);
    let ca = certificates();
    let (silent, text) = (
        recording(&ca, Answers::Silence),
        recording(&ca, Answers::Text),
    );
    let hosts = [silent.addr, text.addr].map(|addr| addr.to_string());
    let proxy = serving(&ca, &proxy_section(&hosts), upstream.addr);
    let got = through(
        &proxy,
        &ca,
        &forwarding(&hosts[0], "/dns-query"),
        b"a query",
    );
    assert_eq!(got.status, StatusCode::GATEWAY_TIMEOUT);
    assert_eq!(proxy_status(&got), "dedensd; error=http_response_timeout");
    let got = through(
        &proxy,
        &ca,
        &forwarding(&hosts[1], "/dns-query"),
        b"a query",
    );
    assert_eq!(got.status, StatusCode::BAD_GATEWAY);
    assert_eq!(proxy_status(&got), "dedensd; error=http_protocol_error");
}

/// RFC 9209 §2.3.17, D91, D94: a client the access lists refuse is served no forward: 403 `http_request_denied`,
/// and the target is never contacted. One the lists allow is forwarded for. (A client they drop gets no connection.)
#[test]
fn d91_a_denied_client_is_forwarded_for_nobody() {
    let upstream = Responder::start(&["a"]);
    let ca = certificates();
    let target = recording(&ca, Answers::Message);
    let host = target.addr.to_string();
    let path = forwarding(&host, "/dns-query");
    for (access, status) in [
        ("access:\n  allow: ['10.0.0.0/8']\n", StatusCode::FORBIDDEN),
        ("access:\n  allow: ['127.0.0.0/8']\n", StatusCode::OK),
    ] {
        let section = proxy_section(std::slice::from_ref(&host)) + access;
        let proxy = serving(&ca, &section, upstream.addr);
        let got = through(&proxy, &ca, &path, b"an encrypted query");
        assert_eq!(got.status, status, "{access}");
        if status == StatusCode::FORBIDDEN {
            assert_eq!(
                proxy_status(&got),
                "dedensd; error=http_request_denied; details=\"client not allowed\"",
                "{access}"
            );
            assert_eq!(target.requests.lock().expect("a lock").len(), 0, "{access}");
            assert_eq!(target.connections.load(Ordering::SeqCst), 0, "{access}");
        }
    }
    assert_eq!(target.requests.lock().expect("a lock").len(), 1);
}

/// RFC 9209 §2.3.13, D94: a target whose certificate the proxy does not trust is a TLS failure, 502.
#[test]
fn s4_1_a_target_that_is_not_trusted_is_a_tls_error() {
    let upstream = Responder::start(&["a"]);
    let (ca, other) = (certificates(), certificates());
    let target = serving(&ca, "odoh: {}\n", upstream.addr);
    let host = format!("127.0.0.1:{}", target.addr.port());
    let proxy = serving_trusting(
        &ca,
        &other,
        &proxy_section(std::slice::from_ref(&host)),
        upstream.addr,
    );
    let got = through(&proxy, &ca, &forwarding(&host, "/dns-query"), b"a query");
    assert_eq!(got.status, StatusCode::BAD_GATEWAY);
    assert_eq!(proxy_status(&got), "dedensd; error=tls_protocol_error");
}
