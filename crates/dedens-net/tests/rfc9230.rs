//! Oblivious `DoH` (RFC 9230) over HTTP/3: the request of §4.2 byte for byte, the responses and statuses of §4.3, the
//! configurations of a target (§5; their discovery is no RFC's), and exchanges with a loopback target, direct and
//! through a loopback proxy (D79).
#![cfg(feature = "odoh")]

mod common;

use std::cell::{Cell, RefCell};
use std::fs;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::rc::Rc;
use std::time::{Duration, SystemTime};

use common::certificates::{Certificates, NAME, certificates, named};
use common::loopback::answer;
use common::query;
use compio::bytes::{Buf, Bytes};
use compio::quic::{ServerBuilder, h3};
use compio::rustls::version::TLS13;
use dedens_net::client::{Client, ClientError};
use dedens_net::doh::Template;
use dedens_net::exchange::{Http, Options, Transport};
use dedens_net::odoh::{
    CONFIGS_PATH, Entropy, Kind, OdohError, classify, configs_lifetime, configs_request,
    configs_response, request, response, target_response,
};
use dedens_net::tls::Trust;
use dedens_odoh::{
    MEDIA_TYPE, MessageType, ObliviousDoHConfigs, ObliviousDoHMessage, TargetKey, decrypt_query,
    encrypt_query, encrypt_response, query_padding, response_padding,
};
use dedens_proto::Message;
use http::header::{ACCEPT, AGE, CACHE_CONTROL, CONTENT_TYPE};
use http::{HeaderMap, HeaderValue, Request, Response, StatusCode, Version};

/// The proxy of RFC 9230 §4.2, without the variables the client adds (D79)
const PROXY: &str = "https://dnsproxy.example/dns-query";

/// The target of RFC 9230 §4.2.
const TARGET: &str = "https://dnstarget.example/dns-query";

/// What the target of the tests serves its configurations for, in seconds.
const MAX_AGE: u32 = 3600;

fn message() -> ObliviousDoHMessage {
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
/// no-store`. Cloudflare's configurations are fetched again for every exchange.
#[test]
fn the_captured_cloudflare_headers_forbid_keeping_the_configurations() {
    let now = SystemTime::UNIX_EPOCH + Duration::from_secs(1_700_000_000);
    let cloudflare = headers(&[(CACHE_CONTROL, "no-cache, no-store")]);
    assert_eq!(configs_lifetime(&cloudflare, now), Duration::ZERO);
}

/// RFC 9111 §4.2.1, §5.2.2: `max-age` less the age, and none where the response says not to keep it or says nothing.
#[test]
fn the_lifetime_of_configurations() {
    let now = SystemTime::UNIX_EPOCH + Duration::from_secs(1_700_000_000);
    let lifetime =
        |fields: &[(http::header::HeaderName, &str)]| configs_lifetime(&headers(fields), now);
    assert_eq!(
        lifetime(&[(CACHE_CONTROL, "max-age=3600")]),
        Duration::from_secs(3600)
    );
    assert_eq!(
        lifetime(&[(CACHE_CONTROL, "public, Max-Age=\"3600\""), (AGE, "100")]),
        Duration::from_secs(3500)
    );
    assert_eq!(
        lifetime(&[(CACHE_CONTROL, "max-age=60"), (AGE, "100")]),
        Duration::ZERO
    );
    assert_eq!(
        lifetime(&[(CACHE_CONTROL, "max-age=3600, no-store")]),
        Duration::ZERO
    );
    assert_eq!(
        lifetime(&[(CACHE_CONTROL, "max-age=3600, no-cache")]),
        Duration::ZERO
    );
    assert_eq!(lifetime(&[(CACHE_CONTROL, "max-age=soon")]), Duration::ZERO);
    assert_eq!(lifetime(&[(CACHE_CONTROL, "public")]), Duration::ZERO);
    assert_eq!(lifetime(&[]), Duration::ZERO);
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
        &vec![0; 65536],
        "/dns-query",
    );
    assert_eq!(
        (kind, query),
        (Kind::Oblivious, Err(StatusCode::PAYLOAD_TOO_LARGE))
    );
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
                    ObliviousDoHConfigs::new(vec![self.key.borrow().config().clone()])
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
                let Ok(message) = ObliviousDoHMessage::parse(&body) else {
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

/// RFC 9230 §4.3: configurations that are fresh from the target and still get a 401 end the exchange: no second
/// fetch, and the status is the error.
#[compio::test]
async fn s4_3_a_401_under_fresh_configurations_fails() {
    let certificates = certificates();
    let target = Target::new(5);
    let other = TargetKey::derive(&[6; 32]);
    *target.configs.borrow_mut() = Some(
        ObliviousDoHConfigs::new(vec![other.config().clone()])
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
/// no-store`: the client parses it, encrypts to it, and fetches it again for each exchange. This target does not
/// hold Cloudflare's key, so it answers 401.
#[compio::test]
async fn s5_the_captured_configurations_are_fetched_for_each_exchange() {
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
    for _ in 0..2 {
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
    }
    assert_eq!(target.configs_asked.get(), 2);
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
