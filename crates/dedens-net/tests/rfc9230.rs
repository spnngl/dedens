//! Oblivious `DoH` (RFC 9230) over HTTP/3: the request of §4.2 byte for byte, the responses and statuses of §4.3, the
//! configurations of a target (§5; their discovery is no RFC's), and exchanges with a loopback target, direct and
//! through a loopback proxy (D79).
#![cfg(feature = "odoh")]

mod common;

use std::cell::{Cell, RefCell};
use std::net::{SocketAddr, ToSocketAddrs};
use std::path::PathBuf;
use std::process::Command;
use std::rc::Rc;
use std::time::{Duration, Instant, SystemTime};
use std::{fs, io};

use common::certificates::{Certificates, NAME, certificates, named};
use common::loopback::answer;
use common::query;
use compio::bytes::{Buf, Bytes};
use compio::quic::{ServerBuilder, h3};
use compio::rustls::pki_types::ServerName;
use compio::rustls::version::TLS13;
use dedens_net::client::{Client, ClientError, Server};
use dedens_net::doh::Template;
use dedens_net::exchange::{Http, Options};
use dedens_net::http3::{Http3Error, Http3Pool};
use dedens_net::odoh::{
    CONFIGS_PATH, Entropy, Kind, Lifetime, MAX_BODY, Notice, OdohError, classify, configs_lifetime,
    configs_request, configs_response, names_target, proxy_error, request, response,
    target_response,
};
use dedens_net::quic::QuicError;
use dedens_net::tls::Trust;
use dedens_odoh::rand_core::TryRng;
use dedens_odoh::{
    ConfigContents, Configs, MEDIA_TYPE, MessageType, TargetKey, decrypt_query, encrypt_query,
    encrypt_response, query_padding, response_padding,
};
use dedens_proto::{Message, Rcode, Transport};
use http::header::{ACCEPT, AGE, CACHE_CONTROL, CONTENT_TYPE, HeaderName};
use http::uri::Authority;
use http::{HeaderMap, HeaderValue, Request, Response, StatusCode, Version};

/// The proxy of RFC 9230 §4.2, without the variables the client adds (D79)
const PROXY: &str = "https://dnsproxy.example/dns-query";

/// The target of RFC 9230 §4.2.
const TARGET: &str = "https://dnstarget.example/dns-query";

/// What the target of the tests serves its configurations for, in seconds.
const MAX_AGE: u32 = 7200;

/// The header of a proxy's errors.
const PROXY_STATUS: HeaderName = HeaderName::from_static("proxy-status");

fn message() -> dedens_odoh::Message {
    let key = TargetKey::derive(&[1; 32]);
    let mut entropy = Entropy::new().expect("randomness");
    encrypt_query(key.config(), b"query", 0, &mut entropy)
        .expect("a query")
        .0
}

fn headers(fields: &[(http::header::HeaderName, &str)]) -> HeaderMap {
    let mut headers = HeaderMap::new();
    for (name, value) in fields {
        headers.append(
            name.clone(),
            HeaderValue::from_str(value).expect("a header value"),
        );
    }
    headers
}

/// RFC 9230 §4.2: a client asking `dnsproxy.example` to forward to `dnstarget.example`: a POST with the media type
/// as content type and accept, `targethost` and `targetpath` in the path.
#[test]
fn s4_2_the_request_through_a_proxy() {
    let proxy = Template::parse(PROXY).expect("a template");
    let target = Template::parse(TARGET).expect("a template");
    let message = message();
    let request = request(Some(&proxy), &target, &message).expect("a request");
    assert_eq!(request.method(), http::Method::POST);
    assert_eq!(request.uri().scheme_str(), Some("https"));
    assert_eq!(
        request.uri().authority().map(http::uri::Authority::as_str),
        Some("dnsproxy.example")
    );
    assert_eq!(
        request
            .uri()
            .path_and_query()
            .map(http::uri::PathAndQuery::as_str),
        Some("/dns-query?targethost=dnstarget.example&targetpath=/dns-query")
    );
    assert_eq!(request.headers()[ACCEPT], MEDIA_TYPE);
    assert_eq!(request.headers()[CONTENT_TYPE], MEDIA_TYPE);
    // Cloudflare's target answers 400 over HTTP/3 to a POST without it.
    assert_eq!(
        request.headers()[http::header::CONTENT_LENGTH],
        message.encode().len().to_string().as_str()
    );
    assert_eq!(request.body(), &message.encode());
}

/// RFC 9230 §4.1: the characters of the target that are the proxy's separators are percent-encoded, and a proxy
/// template with a query of its own takes the variables after it.
#[test]
fn s4_1_the_target_is_encoded() {
    let proxy = Template::parse("https://proxy.example/relay?key=1").expect("a template");
    let target =
        Template::parse("https://dnstarget.example:8443/a&b=c/dns-query").expect("a template");
    let request = request(Some(&proxy), &target, &message()).expect("a request");
    assert_eq!(
        request
            .uri()
            .path_and_query()
            .map(http::uri::PathAndQuery::as_str),
        Some("/relay?key=1&targethost=dnstarget.example%3A8443&targetpath=/a%26b%3Dc/dns-query")
    );
}

/// RFC 9230 §4.2: without a proxy, the request is the one the proxy forwards: the target's URI.
#[test]
fn s4_2_the_request_to_the_target() {
    let target = Template::parse(TARGET).expect("a template");
    let request = request(None, &target, &message()).expect("a request");
    assert_eq!(request.method(), http::Method::POST);
    assert_eq!(request.uri().to_string(), TARGET);
    assert_eq!(request.headers()[CONTENT_TYPE], MEDIA_TYPE);
}

/// D79: the configurations come from the well-known URI of the target.
#[test]
fn s5_the_configurations_request() {
    let target = Template::parse(TARGET).expect("a template");
    let request = configs_request(&target).expect("a request");
    assert_eq!(request.method(), http::Method::GET);
    assert_eq!(
        request.uri().to_string(),
        "https://dnstarget.example/.well-known/odohconfigs"
    );
}

/// RFC 9230 §4.3: only a 2xx response of the media type with a message in it holds a response.
#[test]
fn s4_3_responses() {
    let encoded = message().encode();
    let ok = |media: Option<&str>, status: u16| {
        let mut builder = Response::builder().status(status);
        if let Some(media) = media {
            builder = builder.header(CONTENT_TYPE, media);
        }
        builder.body(()).expect("a response")
    };
    assert_eq!(
        response(&ok(Some(MEDIA_TYPE), 200), &encoded)
            .expect("a message")
            .encode(),
        encoded
    );
    assert!(matches!(
        response(&ok(Some(MEDIA_TYPE), 401), &encoded),
        Err(OdohError::Status(StatusCode::UNAUTHORIZED))
    ));
    assert!(matches!(
        response(&ok(Some("application/dns-message"), 200), &encoded),
        Err(OdohError::ContentType(Some(_)))
    ));
    assert!(matches!(
        response(&ok(None, 200), &encoded),
        Err(OdohError::ContentType(None))
    ));
    assert!(matches!(
        response(&ok(Some(MEDIA_TYPE), 200), &encoded[..5]),
        Err(OdohError::Wire(_))
    ));
}

/// What `curl -i https://odoh.cloudflare-dns.com/.well-known/odohconfigs` answered: `cache-control: no-cache,
/// no-store`. The client asks it to be told, and keeps the configurations an hour all the same (D79).
#[test]
fn the_captured_cloudflare_headers_forbid_keeping_the_configurations() {
    let now = SystemTime::UNIX_EPOCH + Duration::from_secs(1_700_000_000);
    let cloudflare = headers(&[(CACHE_CONTROL, "no-cache, no-store")]);
    assert_eq!(
        configs_lifetime(&cloudflare, now),
        Lifetime {
            keep: HOUR,
            forbidden: true
        }
    );
}

const HOUR: Duration = Duration::from_secs(3600);

/// RFC 9111 §4.2.1, §5.2.2 with D79: `max-age` less the age, between an hour and a day; a response that says not to
/// keep it is flagged; `no-cache` with field names is no `no-cache` of the whole response.
#[test]
fn the_lifetime_of_configurations() {
    let now = SystemTime::UNIX_EPOCH + Duration::from_secs(1_700_000_000);
    let lifetime =
        |fields: &[(http::header::HeaderName, &str)]| configs_lifetime(&headers(fields), now);
    let kept = |keep: Duration| Lifetime {
        keep,
        forbidden: false,
    };
    assert_eq!(
        lifetime(&[(CACHE_CONTROL, "max-age=7200")]),
        kept(Duration::from_secs(7200))
    );
    assert_eq!(
        lifetime(&[(CACHE_CONTROL, "public, Max-Age=\"7200\""), (AGE, "100")]),
        kept(Duration::from_secs(7100))
    );
    assert_eq!(
        lifetime(&[(CACHE_CONTROL, "max-age=60"), (AGE, "100")]),
        kept(HOUR),
        "an hour at least"
    );
    assert_eq!(
        lifetime(&[(CACHE_CONTROL, "max-age=31536000")]),
        kept(Duration::from_hours(24)),
        "a day at most"
    );
    assert_eq!(
        lifetime(&[(CACHE_CONTROL, "max-age=7200, no-store")]),
        Lifetime {
            keep: HOUR,
            forbidden: true
        }
    );
    assert!(lifetime(&[(CACHE_CONTROL, "max-age=7200, No-Cache")]).forbidden);
    assert_eq!(
        lifetime(&[(CACHE_CONTROL, "max-age=7200, no-cache=\"set-cookie\"")]),
        kept(Duration::from_secs(7200)),
        "a no-cache for a field leaves the response cacheable"
    );
    assert_eq!(
        lifetime(&[(CACHE_CONTROL, "x-no-store=1, max-age=7200")]),
        kept(Duration::from_secs(7200))
    );
    assert_eq!(lifetime(&[(CACHE_CONTROL, "max-age=soon")]), kept(HOUR));
    assert_eq!(lifetime(&[(CACHE_CONTROL, "public")]), kept(HOUR));
    assert_eq!(lifetime(&[]), kept(HOUR));
}

/// RFC 9111 §5.2: a `no-store` beside a quoted argument holding obs-text is still read; the `read_odoh_http` fuzz
/// target found the whole field skipped as not UTF-8.
#[test]
fn obs_text_in_cache_control_hides_no_directive() {
    let mut headers = HeaderMap::new();
    let control = HeaderValue::from_bytes(b"private=\"\x82\", no-store, max-age=7200")
        .expect("obs-text is allowed");
    headers.insert(CACHE_CONTROL, control);
    let now = SystemTime::UNIX_EPOCH + Duration::from_secs(1_700_000_000);
    assert_eq!(
        configs_lifetime(&headers, now),
        Lifetime {
            keep: HOUR,
            forbidden: true
        }
    );
}

/// RFC 9111 §4.2.3: a `Date` far before the client's clock, or after it, is no reason to keep the configurations
/// less than an hour, nor more than a day.
#[test]
fn a_skewed_date_leaves_the_bounds() {
    let now = SystemTime::UNIX_EPOCH + Duration::from_secs(1_700_000_000);
    let behind = headers(&[
        (CACHE_CONTROL, "max-age=7200"),
        (http::header::DATE, "Sun, 13 Sep 2020 12:26:40 GMT"),
    ]);
    assert_eq!(configs_lifetime(&behind, now).keep, HOUR);
    let ahead = headers(&[
        (CACHE_CONTROL, "max-age=7200"),
        (http::header::DATE, "Fri, 15 Jan 2027 08:00:00 GMT"),
    ]);
    assert_eq!(
        configs_lifetime(&ahead, now).keep,
        Duration::from_secs(7200)
    );
}

/// D79: a proxy's URI is plain: one that sets `targethost` or `targetpath` is a URI template.
#[test]
fn proxy_uris_with_the_variables_are_found() {
    let named = |uri: &str| names_target(&Template::parse(uri).expect("a template"));
    assert!(!named(PROXY));
    assert!(!named("https://proxy.example/relay?key=1"));
    assert!(named("https://proxy.example/relay?targethost=a"));
    assert!(named("https://proxy.example/relay?key=1&targetpath"));
    assert!(!named("https://proxy.example/relay?mytargethost=a"));
}

/// RFC 9209 §2: a `Proxy-Status` that names an error says the proxy made the response.
#[test]
fn proxy_errors_are_found() {
    let status = |value: &str| proxy_error(&headers(&[(PROXY_STATUS, value)]));
    assert!(status("proxy.example; error=http_request_error"));
    assert!(status(
        "other; received-status=200, proxy.example; Error=connection_timeout"
    ));
    assert!(!status("proxy.example; received-status=401"));
    assert!(!status("proxy.example"));
    assert!(!proxy_error(&HeaderMap::new()));
}

/// RFC 9230 §6.1, §6.2: the draws of an encryption stay within the entropy, and one past it is an error, not a
/// panic (D79).
#[test]
fn entropy_past_its_bytes_is_an_error() {
    let mut entropy = Entropy::new().expect("randomness");
    let mut bytes = [1; 40];
    entropy.try_fill_bytes(&mut bytes).expect("infallible");
    assert!(entropy.finish().is_ok());
    let mut entropy = Entropy::new().expect("randomness");
    entropy.try_fill_bytes(&mut bytes).expect("infallible");
    entropy.try_fill_bytes(&mut bytes).expect("infallible");
    assert_eq!(bytes, [0; 40]);
    assert!(entropy.finish().is_err());
}

/// RFC 9230 §4.1, §4.3 with RFC 8484 §4.1: what a target takes at its path, and what it answers.
#[test]
fn s4_1_a_target_classifies_requests() {
    let post = |path: &str, media: &str| {
        Request::builder()
            .method(http::Method::POST)
            .uri(format!("https://dnstarget.example{path}"))
            .header(CONTENT_TYPE, media)
            .body(())
            .expect("a request")
    };
    let (kind, query) = classify(&post("/dns-query", MEDIA_TYPE), b"abc", "/dns-query");
    assert_eq!((kind, query), (Kind::Oblivious, Ok(b"abc".to_vec())));
    let (kind, query) = classify(&post("/dns-query", MEDIA_TYPE), b"", "/dns-query");
    assert_eq!(
        (kind, query),
        (Kind::Oblivious, Err(StatusCode::BAD_REQUEST))
    );
    let (kind, query) = classify(
        &post("/dns-query", MEDIA_TYPE),
        &vec![0; MAX_BODY],
        "/dns-query",
    );
    assert_eq!(
        (kind, query.map(|body| body.len())),
        (Kind::Oblivious, Ok(MAX_BODY))
    );
    let (kind, query) = classify(
        &post("/dns-query", MEDIA_TYPE),
        &vec![0; MAX_BODY + 1],
        "/dns-query",
    );
    assert_eq!(
        (kind, query),
        (Kind::Oblivious, Err(StatusCode::PAYLOAD_TOO_LARGE))
    );
    // The listener's path wins over the well-known one.
    let (kind, query) = classify(&post(CONFIGS_PATH, MEDIA_TYPE), b"abc", CONFIGS_PATH);
    assert_eq!((kind, query), (Kind::Oblivious, Ok(b"abc".to_vec())));
    let (kind, query) = classify(&post("/elsewhere", MEDIA_TYPE), b"abc", "/dns-query");
    assert_eq!((kind, query), (Kind::Dns, Err(StatusCode::NOT_FOUND)));
    let (kind, query) = classify(&post("/dns-query", "text/plain"), b"abc", "/dns-query");
    assert_eq!(
        (kind, query),
        (Kind::Dns, Err(StatusCode::UNSUPPORTED_MEDIA_TYPE))
    );
    let get = |path: &str, method: http::Method| {
        Request::builder()
            .method(method)
            .uri(format!("https://dnstarget.example{path}"))
            .body(())
            .expect("a request")
    };
    let (kind, query) = classify(&get(CONFIGS_PATH, http::Method::GET), b"", "/dns-query");
    assert_eq!((kind, query), (Kind::Configs, Ok(Vec::new())));
    let (kind, query) = classify(&get(CONFIGS_PATH, http::Method::POST), b"", "/dns-query");
    assert_eq!(
        (kind, query),
        (Kind::Configs, Err(StatusCode::METHOD_NOT_ALLOWED))
    );
}

/// RFC 9230 §4.1, §4.3: a target's responses are of the media type and not to be cached.
#[test]
fn s4_3_a_target_answers_without_caching() {
    let reply = target_response(&message());
    assert_eq!(reply.status(), StatusCode::OK);
    assert_eq!(reply.headers()[CONTENT_TYPE], MEDIA_TYPE);
    assert_eq!(reply.headers()[CACHE_CONTROL], "no-cache, no-store");
    let configs = configs_response(vec![1, 2], 60);
    assert_eq!(configs.headers()[CACHE_CONTROL], "max-age=60");
}

/// The loopback servers' handler: a request's head and body in, a response out.
type Handler = Rc<dyn Fn(&Request<()>, &[u8]) -> Response<Vec<u8>>>;

/// The bytes of `buf`.
fn bytes_of(mut buf: impl Buf) -> Vec<u8> {
    let mut bytes = Vec::new();
    while buf.has_remaining() {
        let part = buf.chunk();
        bytes.extend_from_slice(part);
        let taken = part.len();
        buf.advance(taken);
    }
    bytes
}

/// An HTTP/3 server on the loopback address answering with `handler`.
async fn h3_server(certificates: &Certificates, handler: Handler) -> SocketAddr {
    let config = certificates.config(&[&TLS13], b"h3");
    let endpoint = ServerBuilder::new_with_rustls_server_config(config)
        .bind("127.0.0.1:0")
        .await
        .expect("a QUIC endpoint");
    let addr = endpoint.local_addr().expect("its address");
    compio::runtime::spawn(async move {
        while let Some(incoming) = endpoint.wait_incoming().await {
            let handler = Rc::clone(&handler);
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
                    let handler = Rc::clone(&handler);
                    compio::runtime::spawn(async move {
                        let Ok((request, mut stream)) = resolver.resolve_request().await else {
                            return;
                        };
                        let mut body = Vec::new();
                        while let Ok(Some(chunk)) = stream.recv_data().await {
                            body.extend(bytes_of(chunk));
                        }
                        let (head, body) = handler(&request, &body).into_parts();
                        stream
                            .send_response(Response::from_parts(head, ()))
                            .await
                            .expect("the client reads");
                        stream
                            .send_data(Bytes::from(body))
                            .await
                            .expect("the client reads");
                        stream.finish().await.expect("an open stream");
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

/// A target: a key, and what it was asked.
struct Target {
    key: RefCell<TargetKey>,
    /// The configurations it serves, if not its key's.
    configs: RefCell<Option<Vec<u8>>>,
    /// The `cache-control` of its configurations.
    cache_control: &'static str,
    configs_asked: Cell<u32>,
    /// The queries it decrypted.
    queries: RefCell<Vec<Vec<u8>>>,
}

impl Target {
    fn new(seed: u8) -> Rc<Self> {
        Rc::new(Self {
            key: RefCell::new(TargetKey::derive(&[seed; 32])),
            configs: RefCell::new(None),
            cache_control: "max-age=3600",
            configs_asked: Cell::new(0),
            queries: RefCell::default(),
        })
    }

    /// RFC 9230 §4.1, §4.3, §8: the target's answers.
    fn handle(&self, request: &Request<()>, body: &[u8]) -> Response<Vec<u8>> {
        let status = |status: StatusCode| {
            Response::builder()
                .status(status)
                .body(Vec::new())
                .expect("a response")
        };
        match classify(request, body, "/dns-query") {
            (Kind::Configs, Ok(_)) => {
                self.configs_asked.set(self.configs_asked.get() + 1);
                let encoded = self.configs.borrow().clone().unwrap_or_else(|| {
                    Configs::new(vec![self.key.borrow().config().clone()])
                        .encode()
                        .expect("configurations encode")
                });
                let mut reply = configs_response(encoded, MAX_AGE);
                reply
                    .headers_mut()
                    .insert(CACHE_CONTROL, HeaderValue::from_static(self.cache_control));
                reply
            }
            (Kind::Oblivious, Ok(body)) => {
                let Ok(message) = dedens_odoh::Message::parse(&body) else {
                    return status(StatusCode::BAD_REQUEST);
                };
                match decrypt_query(&self.key.borrow(), &message) {
                    Err(dedens_odoh::ExchangeError::UnknownKey) => status(StatusCode::UNAUTHORIZED),
                    Err(_) => status(StatusCode::BAD_REQUEST),
                    Ok((plaintext, context)) => {
                        let wire = plaintext.into_dns_message();
                        self.queries.borrow_mut().push(wire.clone());
                        let reply = answer(&wire, Vec::new());
                        let mut entropy = Entropy::new().expect("randomness");
                        let message = encrypt_response(
                            context,
                            &reply,
                            response_padding(reply.len()),
                            &mut entropy,
                        )
                        .expect("a response");
                        target_response(&message)
                    }
                }
            }
            (_, Err(code)) => status(code),
            (_, Ok(_)) => status(StatusCode::UNSUPPORTED_MEDIA_TYPE),
        }
    }
}

fn trusting(certificates: Certificates) -> Client {
    Client::new().trusting(Trust::Roots(vec![certificates.ca]))
}

/// RFC 9230 §3, §4.1, §7: straight to the target, the client fetches the configurations once, they are kept for
/// their `max-age`, and each query is a POST of an encrypted message with ID 0, padded inside the encryption.
#[compio::test]
async fn s4_a_query_to_the_target() {
    let certificates = certificates();
    let target = Target::new(1);
    let handler = Rc::clone(&target);
    let addr = h3_server(
        &certificates,
        Rc::new(move |request, body| handler.handle(request, body)),
    )
    .await;
    let client = trusting(certificates);
    for _ in 0..2 {
        let response = client
            .exchange_oblivious(query(), named(addr, NAME), None, &Options::default())
            .await
            .expect("a response");
        assert_eq!(response.transport, Transport::Odoh);
        assert_eq!(
            response.http,
            Some(Http {
                version: Version::HTTP_3,
                status: StatusCode::OK
            })
        );
        let answered = Message::decode(&response.wire).expect("a response").message;
        assert_eq!(answered.questions, query().questions);
    }
    assert_eq!(target.configs_asked.get(), 1, "the configurations are kept");
    let queries = target.queries.borrow();
    assert_eq!(queries.len(), 2);
    let asked = Message::decode(&queries[0]).expect("a query").message;
    assert_eq!(asked.header.id, 0);
    assert_eq!(asked.questions, query().questions);
    assert_eq!(queries[0].len(), queries[1].len());
}

/// RFC 9230 §4.1, §4.2: through a proxy, the encrypted query goes to the proxy with the target in `targethost` and
/// `targetpath`; the configurations are fetched from the target and never from the proxy (D79).
#[compio::test]
async fn s4_1_a_query_through_a_proxy() {
    let certificates = certificates();
    let target = Target::new(2);
    let at_target = Rc::clone(&target);
    let target_addr = h3_server(
        &certificates,
        Rc::new(move |request, body| at_target.handle(request, body)),
    )
    .await;
    let proxied = Rc::new(RefCell::new(Vec::<(http::Method, String)>::new()));
    let log = Rc::clone(&proxied);
    let forward = Rc::clone(&target);
    let proxy_addr = h3_server(
        &certificates,
        Rc::new(move |request, body| {
            log.borrow_mut().push((
                request.method().clone(),
                request
                    .uri()
                    .path_and_query()
                    .map(ToString::to_string)
                    .unwrap_or_default(),
            ));
            // What a proxy does: forward the POST to the target it is told.
            let forwarded = Request::builder()
                .method(request.method())
                .uri("https://dns.example/dns-query")
                .header(CONTENT_TYPE, request.headers()[CONTENT_TYPE].clone())
                .body(())
                .expect("a request");
            forward.handle(&forwarded, body)
        }),
    )
    .await;
    let client = trusting(certificates);
    let response = client
        .exchange_oblivious(
            query(),
            named(target_addr, NAME),
            Some(named(proxy_addr, NAME)),
            &Options::default(),
        )
        .await
        .expect("a response");
    assert_eq!(response.transport, Transport::Odoh);
    assert_eq!(target.configs_asked.get(), 1);
    assert_eq!(
        proxied.borrow().as_slice(),
        [(
            http::Method::POST,
            format!(
                "/dns-query?targethost={NAME}%3A{}&targetpath=/dns-query",
                target_addr.port()
            )
        )],
        "only the encrypted query goes through the proxy"
    );
    assert_eq!(target.queries.borrow().len(), 1);
}

/// RFC 9230 §4.3: a 401 under configurations kept from before means the target changed its key: the client fetches
/// them again, once, and asks again.
#[compio::test]
async fn s4_3_a_401_fetches_the_configurations_again() {
    let certificates = certificates();
    let target = Target::new(3);
    let handler = Rc::clone(&target);
    let addr = h3_server(
        &certificates,
        Rc::new(move |request, body| handler.handle(request, body)),
    )
    .await;
    let client = trusting(certificates);
    let options = Options::default();
    client
        .exchange_oblivious(query(), named(addr, NAME), None, &options)
        .await
        .expect("a response");
    *target.key.borrow_mut() = TargetKey::derive(&[4; 32]);
    let response = client
        .exchange_oblivious(query(), named(addr, NAME), None, &options)
        .await
        .expect("a response with the new key");
    assert_eq!(response.http.map(|http| http.status), Some(StatusCode::OK));
    assert_eq!(target.configs_asked.get(), 2);
    assert_eq!(target.queries.borrow().len(), 2);
}

/// RFC 9230 §4.3: configurations the caller gave to keep, under a key the target no longer holds, are fetched again
/// after the 401, once, as fetched ones are: `keep_odoh_configs`, which the live check of that refetch relies on.
#[compio::test]
async fn s4_3_kept_configurations_given_are_fetched_again_after_a_401() {
    let certificates = certificates();
    let target = Target::new(15);
    let handler = Rc::clone(&target);
    let addr = h3_server(
        &certificates,
        Rc::new(move |request, body| handler.handle(request, body)),
    )
    .await;
    let client = trusting(certificates);
    let stale = Configs::new(vec![TargetKey::derive(&[16; 32]).config().clone()])
        .encode()
        .expect("configurations encode");
    assert!(matches!(
        client.keep_odoh_configs(named(addr, NAME), b"nonsense"),
        Err(OdohError::Wire(_))
    ));
    client
        .keep_odoh_configs(named(addr, NAME), &stale)
        .expect("configurations");
    let response = client
        .exchange_oblivious(query(), named(addr, NAME), None, &Options::default())
        .await
        .expect("a response under the configurations fetched after the 401");
    assert_eq!(response.http.map(|http| http.status), Some(StatusCode::OK));
    assert_eq!(target.configs_asked.get(), 1);
    assert_eq!(target.queries.borrow().len(), 1);
}

/// RFC 9230 §4.3: configurations that are fresh from the target and still get a 401 end the exchange: no second
/// fetch, and the status is the error.
#[compio::test]
async fn s4_3_a_401_under_fresh_configurations_fails() {
    let certificates = certificates();
    let target = Target::new(5);
    let other = TargetKey::derive(&[6; 32]);
    *target.configs.borrow_mut() = Some(
        Configs::new(vec![other.config().clone()])
            .encode()
            .expect("configurations encode"),
    );
    let handler = Rc::clone(&target);
    let addr = h3_server(
        &certificates,
        Rc::new(move |request, body| handler.handle(request, body)),
    )
    .await;
    let client = trusting(certificates);
    let error = client
        .exchange_oblivious(query(), named(addr, NAME), None, &Options::default())
        .await
        .expect_err("a 401");
    assert!(
        matches!(
            error,
            ClientError::Odoh(OdohError::Status(StatusCode::UNAUTHORIZED))
        ),
        "{error:?}"
    );
    assert_eq!(target.configs_asked.get(), 1);
}

/// What `curl https://odoh.cloudflare-dns.com/.well-known/odohconfigs` returned, with its `cache-control: no-cache,
/// no-store`: the client parses it, encrypts to it, and keeps it all the same (D79). This target does not hold
/// Cloudflare's key, so it answers 401.
#[compio::test]
async fn s5_the_captured_configurations_are_kept_though_forbidden() {
    let captured = fs::read(
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../dedens-odoh/tests/testdata/odohconfigs-cloudflare.bin"),
    )
    .expect("the captured configurations");
    let certificates = certificates();
    let mut target = Target::new(7);
    Rc::get_mut(&mut target).expect("one owner").cache_control = "no-cache, no-store";
    *target.configs.borrow_mut() = Some(captured);
    let handler = Rc::clone(&target);
    let addr = h3_server(
        &certificates,
        Rc::new(move |request, body| handler.handle(request, body)),
    )
    .await;
    let client = trusting(certificates);
    let error = client
        .exchange_oblivious(query(), named(addr, NAME), None, &Options::default())
        .await
        .expect_err("a 401: the key is not this target's");
    assert!(
        matches!(
            error,
            ClientError::Odoh(OdohError::Status(StatusCode::UNAUTHORIZED))
        ),
        "{error:?}"
    );
    assert_eq!(target.configs_asked.get(), 1);
    assert!(
        client.take_odoh_notices().is_empty(),
        "no proxy to hide the address from"
    );
}

/// RFC 9230 §4.3: a response without the media type is an error, whatever its status.
#[compio::test]
async fn s4_3_a_wrong_content_type_fails() {
    let certificates = certificates();
    let target = Target::new(8);
    let handler = Rc::clone(&target);
    let addr = h3_server(
        &certificates,
        Rc::new(move |request, body| {
            let mut reply = handler.handle(request, body);
            if reply
                .headers()
                .get(CONTENT_TYPE)
                .is_some_and(|value| value == MEDIA_TYPE)
            {
                reply.headers_mut().insert(
                    CONTENT_TYPE,
                    HeaderValue::from_static("application/dns-message"),
                );
            }
            reply
        }),
    )
    .await;
    let client = trusting(certificates);
    let error = client
        .exchange_oblivious(query(), named(addr, NAME), None, &Options::default())
        .await
        .expect_err("no response");
    assert!(
        matches!(error, ClientError::Odoh(OdohError::ContentType(Some(_)))),
        "{error:?}"
    );
}

/// RFC 9230 §6.2: the query is padded to a multiple of the block inside the encryption, by the client.
#[test]
fn s6_2_the_client_pads_inside_the_encryption() {
    let key = TargetKey::derive(&[9; 32]);
    let mut entropy = Entropy::new().expect("randomness");
    let wire = b"0123456789";
    let (message, _) = encrypt_query(key.config(), wire, query_padding(wire.len()), &mut entropy)
        .expect("a query");
    assert_eq!(message.message_type(), MessageType::Query);
    let (plaintext, _) = decrypt_query(&key, &message).expect("the query");
    assert_eq!(plaintext.dns_message(), wire);
    assert_eq!((wire.len() + plaintext.padding()) % 128, 0);
}

/// A proxy forwarding to `target` what it is sent, or, while `failing`, answering 401 with a `Proxy-Status` naming
/// an error.
async fn proxy_to(
    certificates: &Certificates,
    target: &Rc<Target>,
    failing: &Rc<Cell<bool>>,
) -> SocketAddr {
    let target = Rc::clone(target);
    let failing = Rc::clone(failing);
    h3_server(
        certificates,
        Rc::new(move |request, body| {
            if failing.get() {
                return Response::builder()
                    .status(StatusCode::UNAUTHORIZED)
                    .header(PROXY_STATUS, "proxy.example; error=http_request_denied")
                    .body(Vec::new())
                    .expect("a response");
            }
            let forwarded = Request::builder()
                .method(request.method())
                .uri("https://dns.example/dns-query")
                .header(CONTENT_TYPE, request.headers()[CONTENT_TYPE].clone())
                .body(())
                .expect("a request");
            target.handle(&forwarded, body)
        }),
    )
    .await
}

/// D79: a target that asks for its configurations not to be kept gets them kept an hour all the same, and a client
/// that sends its queries through a proxy tells its user, once, that the target saw its address.
#[compio::test]
async fn s5_forbidden_configurations_are_kept_and_noticed() {
    let certificates = certificates();
    let mut target = Target::new(10);
    Rc::get_mut(&mut target).expect("one owner").cache_control = "no-cache, no-store";
    let handler = Rc::clone(&target);
    let target_addr = h3_server(
        &certificates,
        Rc::new(move |request, body| handler.handle(request, body)),
    )
    .await;
    let proxy_addr = proxy_to(&certificates, &target, &Rc::new(Cell::new(false))).await;
    let client = trusting(certificates);
    for _ in 0..2 {
        client
            .exchange_oblivious(
                query(),
                named(target_addr, NAME),
                Some(named(proxy_addr, NAME)),
                &Options::default(),
            )
            .await
            .expect("a response");
    }
    assert_eq!(target.configs_asked.get(), 1);
    let authority = Authority::try_from(format!("{NAME}:{}", target_addr.port())).expect("one");
    assert_eq!(
        client.take_odoh_notices(),
        [Notice::ConfigsNotToBeKept(authority)]
    );
    assert_eq!(client.take_odoh_notices(), []);
}

/// RFC 9230 §4.3, §11.3 with RFC 9209: a 401 the proxy made, as its `Proxy-Status` says, tells nothing of the
/// target's key: the configurations are not fetched again, which would also give the target the client's address.
#[compio::test]
async fn s4_3_a_401_of_the_proxy_does_not_fetch_the_configurations_again() {
    let certificates = certificates();
    let target = Target::new(11);
    let handler = Rc::clone(&target);
    let target_addr = h3_server(
        &certificates,
        Rc::new(move |request, body| handler.handle(request, body)),
    )
    .await;
    let failing = Rc::new(Cell::new(false));
    let proxy_addr = proxy_to(&certificates, &target, &failing).await;
    let client = trusting(certificates);
    let options = Options::default();
    let ask = || {
        client.exchange_oblivious(
            query(),
            named(target_addr, NAME),
            Some(named(proxy_addr, NAME)),
            &options,
        )
    };
    ask().await.expect("a response");
    failing.set(true);
    let error = ask().await.expect_err("the proxy refuses");
    assert!(
        matches!(
            error,
            ClientError::Odoh(OdohError::Proxy(StatusCode::UNAUTHORIZED))
        ),
        "{error:?}"
    );
    assert_eq!(target.configs_asked.get(), 1);
}

/// D79: a proxy URI that sets `targethost` is a URI template, which is not supported: refused before any request.
#[compio::test]
async fn s4_1_a_proxy_uri_with_the_variables_is_refused() {
    let certificates = certificates();
    let target = Target::new(12);
    let handler = Rc::clone(&target);
    let target_addr = h3_server(
        &certificates,
        Rc::new(move |request, body| handler.handle(request, body)),
    )
    .await;
    let proxy_addr = proxy_to(&certificates, &target, &Rc::new(Cell::new(false))).await;
    let proxy = Server {
        doh: Some(Template::parse("https://proxy.example/relay?targethost=x").expect("one")),
        ..named(proxy_addr, NAME)
    };
    let client = trusting(certificates);
    let error = client
        .exchange_oblivious(
            query(),
            named(target_addr, NAME),
            Some(proxy),
            &Options::default(),
        )
        .await
        .expect_err("a template");
    assert!(
        matches!(error, ClientError::Odoh(OdohError::ProxyVariables)),
        "{error:?}"
    );
    assert!(error.is_local());
    assert_eq!(target.configs_asked.get(), 0);
}

/// D79: `Client::exchange` has no proxy to give, so no Oblivious `DoH`.
#[compio::test]
async fn exchange_refuses_oblivious_without_a_proxy() {
    let mut options = Options::default();
    options.transport = Transport::Odoh;
    let addr: SocketAddr = "127.0.0.1:9".parse().expect("an address");
    let error = Client::new()
        .exchange(query(), named(addr, NAME), &options)
        .await
        .expect_err("no proxy");
    assert!(matches!(error, ClientError::OdohWithoutProxy), "{error:?}");
    assert!(error.is_local());
}

/// D46: an Oblivious `DoH` socket that cannot be bound for want of resources is our failure; one the network
/// refuses, or a status, is not.
#[test]
fn odoh_failures_of_ours_are_local() {
    let bind = |kind| {
        ClientError::Odoh(OdohError::Https(Http3Error::Quic(QuicError::Bind(
            io::Error::from(kind),
        ))))
    };
    assert!(bind(io::ErrorKind::OutOfMemory).is_local());
    assert!(!bind(io::ErrorKind::ConnectionRefused).is_local());
    assert!(!ClientError::Odoh(OdohError::Status(StatusCode::BAD_REQUEST)).is_local());
}

/// D79: configurations the caller gives are not fetched, and a 401 under them is the error: they are not fetched
/// again either.
#[compio::test]
async fn s5_pinned_configurations_are_not_fetched() {
    let certificates = certificates();
    let target = Target::new(13);
    let handler = Rc::clone(&target);
    let addr = h3_server(
        &certificates,
        Rc::new(move |request, body| handler.handle(request, body)),
    )
    .await;
    let client = trusting(certificates);
    let encode = |key: &TargetKey| {
        Configs::new(vec![key.config().clone()])
            .encode()
            .expect("configurations encode")
    };
    assert!(matches!(
        client.pin_odoh_configs(named(addr, NAME), b"nonsense"),
        Err(OdohError::Wire(_))
    ));
    client
        .pin_odoh_configs(named(addr, NAME), &encode(&TargetKey::derive(&[13; 32])))
        .expect("configurations");
    client
        .exchange_oblivious(query(), named(addr, NAME), None, &Options::default())
        .await
        .expect("a response");
    assert_eq!(target.configs_asked.get(), 0);
    client
        .pin_odoh_configs(named(addr, NAME), &encode(&TargetKey::derive(&[14; 32])))
        .expect("configurations");
    let error = client
        .exchange_oblivious(query(), named(addr, NAME), None, &Options::default())
        .await
        .expect_err("a 401");
    assert!(
        matches!(
            error,
            ClientError::Odoh(OdohError::Status(StatusCode::UNAUTHORIZED))
        ),
        "{error:?}"
    );
    assert_eq!(target.configs_asked.get(), 0);
}

// Live targets: public Oblivious DoH targets of D79's list, asked over the network by `just odoh-live`.

/// The targets: host and the path of the POST.
const LIVE_TARGETS: [(&str, &str); 2] = [
    ("odoh.cloudflare-dns.com", "/dns-query"),
    ("doh.tiar.app", "/odoh"),
];

/// The configurations `host` serves, fetched by curl: the client has no way to hand them out.
fn live_configs(host: &str) -> Configs {
    let output = Command::new("curl")
        .args([
            "--silent",
            "--show-error",
            "--fail",
            "--max-time",
            "20",
            "--http2",
        ])
        .arg(format!("https://{host}{CONFIGS_PATH}"))
        .output()
        .expect("curl runs");
    assert!(output.status.success(), "{host}: {output:?}");
    Configs::parse(&output.stdout).expect("the configurations of the target")
}

/// `configs` with the first key changed by one bit: a key the target does not hold, as one it rotated away.
fn stale(configs: &Configs) -> Vec<u8> {
    let mut key = *configs.configs()[0].public_key();
    key[0] ^= 1;
    Configs::new(vec![ConfigContents::new(key)])
        .encode()
        .expect("configurations encode")
}

/// `host`, its address from the system's resolver, and the template of its POSTs at `path`.
fn live_server(host: &str, path: &str) -> Server {
    let addr = (host, 443)
        .to_socket_addrs()
        .expect("the host resolves")
        .next()
        .expect("an address");
    Server {
        addr,
        name: Some(ServerName::try_from(host.to_owned()).expect("a server name")),
        doh: Some(Template::parse(&format!("https://{host}{path}")).expect("a template")),
        docpath: Vec::new(),
    }
}

/// RFC 9230 §4.3 against each live target: configurations under a key it does not hold, kept as an earlier fetch
/// (`keep_odoh_configs`), get its 401, then one fetch of the real ones, and an answer, which no stale key could
/// yield; pinned, the same configurations end in the 401 with no fetch. Run by `just odoh-live`.
#[compio::test]
#[ignore = "asks public servers over the network: `just odoh-live`"]
async fn s4_3_live_a_stale_key_is_refetched_after_the_401() {
    for (host, path) in LIVE_TARGETS {
        let stale = stale(&live_configs(host));

        let pinned = Client::new();
        pinned
            .pin_odoh_configs(live_server(host, path), &stale)
            .expect("configurations");
        let error = pinned
            .exchange_oblivious(query(), live_server(host, path), None, &Options::default())
            .await
            .expect_err("a 401");
        assert!(
            matches!(
                error,
                ClientError::Odoh(OdohError::Status(StatusCode::UNAUTHORIZED))
            ),
            "{host}: {error:?}"
        );

        let client = Client::new();
        client
            .keep_odoh_configs(live_server(host, path), &stale)
            .expect("configurations");
        let response = client
            .exchange_oblivious(query(), live_server(host, path), None, &Options::default())
            .await
            .unwrap_or_else(|error| panic!("{host}: {error:?}"));
        assert_eq!(
            response.http.map(|http| http.status),
            Some(StatusCode::OK),
            "{host}"
        );
        let answered = Message::decode(&response.wire).expect("a response").message;
        assert_eq!(answered.rcode(), Rcode::NOERROR, "{host}");
        assert!(!answered.answer.is_empty(), "{host}: no answer");
        println!(
            "{host}: 401 under a stale key, refetched, {} answers",
            answered.answer.len()
        );
    }
}

/// RFC 9114 §3.3: connecting opens the connection, which fails for a certificate that does not hold the name (RFC
/// 8310 §6.6) and for a server that does not answer in time (D94): before any request goes out.
#[compio::test]
async fn s3_3_a_connection_is_made_before_any_request() {
    let certificates = certificates();
    let addr = h3_server(&certificates, Rc::new(|_, _| Response::new(Vec::new()))).await;
    let pool =
        Http3Pool::new(Duration::from_secs(10)).trusting(Trust::Roots(vec![certificates.ca]));
    let later = || Instant::now() + Duration::from_secs(5);
    let name = |name| ServerName::try_from(name).expect("a name");
    pool.connect(addr, name(NAME), later())
        .await
        .expect("a connection");
    let refused = pool.connect(addr, name("other.example"), later()).await;
    assert!(matches!(refused, Err(Http3Error::Quic(_))), "{refused:?}");
    // A socket nobody reads from: the deadline ends the wait.
    let silent = std::net::UdpSocket::bind("127.0.0.1:0").expect("a socket");
    let silent_addr = silent.local_addr().expect("its address");
    let late = Instant::now() + Duration::from_millis(200);
    let timed_out = pool.connect(silent_addr, name(NAME), late).await;
    assert!(
        matches!(timed_out, Err(Http3Error::TimedOut)),
        "{timed_out:?}"
    );
}
