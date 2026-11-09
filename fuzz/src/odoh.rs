//! Targets of Oblivious `DoH` (RFC 9230): dedens-odoh's structures and encryption, and the HTTP side of
//! dedens-net's `odoh` (D79), proxy included (D94).

use std::sync::LazyLock;

use dedens_net::doh::Template;
use dedens_odoh::{
    Configs, MessagePlaintext, MessageType, QueryContext, TargetKey, decrypt_query,
    decrypt_response, encrypt_query,
};
use rand_core::{TryCryptoRng, TryRng};

/// `ObliviousDoHConfigs` read from arbitrary bytes (RFC 9230 §5): the configs written back read as the same
/// configs, and every key ID is the length RFC 9230 §6.1 gives.
///
/// # Panics
///
/// When a list does not read back as itself.
pub fn parse_odoh_configs(data: &[u8]) {
    let Ok(configs) = Configs::parse(data) else {
        return;
    };
    assert!(
        configs
            .configs()
            .iter()
            .all(|config| config.key_id().len() == dedens_odoh::KEY_ID_LEN)
    );
    // A list of configs this crate cannot use has nothing to write (D78).
    if let Ok(written) = configs.encode() {
        assert_eq!(Configs::parse(&written), Ok(configs));
    }
}

/// `ObliviousDoHMessage` and `ObliviousDoHMessagePlaintext` read from arbitrary bytes (RFC 9230 §6.1): what
/// reads writes back to the same bytes.
///
/// # Panics
///
/// When a structure does not write back to the bytes it was read from.
pub fn parse_odoh_message(data: &[u8]) {
    if let Ok(message) = dedens_odoh::Message::parse(data) {
        assert_eq!(message.encode(), data);
    }
    if let Ok(plaintext) = MessagePlaintext::parse(data) {
        assert_eq!(plaintext.encode(), data);
    }
}

/// Arbitrary bytes as the HTTP side of Oblivious `DoH` (RFC 9230 §4, D79): `meta`, `cache-control`, `age`, `date`
/// and the body, apart by NUL bytes. The first byte of `meta` picks the shape of the request (method, path,
/// `Content-Type`), the second that of the response, the rest the clock.
///
/// A target's configurations are kept at least an hour, at most a day and no longer than `max-age` says, `no-store`
/// and `no-cache` without field names meaning the hour and a warning, whatever `Age` and `Date` say; a request is
/// classified with a status or a body within the cap, by its `Content-Type` and path; a response is read as a message
/// or an error; and the proxy request for a target holds the target's authority and path as `targethost` and
/// `targetpath`, percent-encoded, which decode to them; and a request naming a target and a path is routed to the proxy
/// (D94): the destination is what was named, and what is forwarded carries nothing of the client.
///
/// # Panics
///
/// On a bug in one of the readers.
pub fn read_odoh_http(data: &[u8]) {
    use dedens_net::odoh;
    let mut parts = data.splitn(5, |&byte| byte == 0);
    let (Some(meta), Some(control), Some(held), Some(stamp), Some(body)) = (
        parts.next(),
        parts.next(),
        parts.next(),
        parts.next(),
        parts.next(),
    ) else {
        return;
    };
    let shape = meta.first().copied().unwrap_or(0);
    let response_shape = meta.get(1).copied().unwrap_or(0);
    let clock = meta
        .iter()
        .skip(2)
        .fold(0_u32, |clock, &byte| clock.rotate_left(8) ^ u32::from(byte));
    odoh_lifetime(control, held, stamp, clock);
    odoh_classify(shape, body);
    let mut builder =
        http::Response::builder().status(if response_shape & 1 == 0 { 200 } else { 401 });
    if response_shape & 2 != 0 {
        builder = builder.header(http::header::CONTENT_TYPE, dedens_odoh::MEDIA_TYPE);
    }
    if let Ok(response) = builder.body(())
        && let Ok(message) = odoh::response(&response, body)
    {
        assert_eq!(message.encode(), body);
    }
    odoh_proxy_request(held, body);
    odoh_route(control, held, body);
}

/// A request to a proxy for the target `host` and the path `path` (both arbitrary bytes, percent-encoded into its
/// query), routed: a request to forward names the target and the path it was given, its forwarded request goes to
/// that authority and path and carries nothing of the client, and every error of the proxy makes a response that says
/// its `error`; the query as it came is routed too, and a request not for the target is a 4xx.
fn odoh_route(host: &[u8], path: &[u8], body: &[u8]) {
    use std::fmt::Write as _;

    use dedens_net::odoh::proxy::{Route, Target, forward_request, rejection, route};
    use http::header::{COOKIE, FORWARDED, VIA};
    let encode = |bytes: &[u8]| {
        bytes.iter().fold(String::new(), |mut text, byte| {
            let _ = write!(text, "%{byte:02X}");
            text
        })
    };
    let request = |query: &str| {
        http::Request::builder()
            .method(http::Method::POST)
            .uri(format!("https://proxy.example/dns-query?{query}"))
            .header(http::header::CONTENT_TYPE, dedens_odoh::MEDIA_TYPE)
            .body(())
    };
    let encoded = format!("targethost={}&targetpath={}", encode(host), encode(path));
    for query in [encoded, String::from_utf8_lossy(path).into_owned()] {
        let Ok(request) = request(&query) else {
            continue;
        };
        let (routed, accepted) = route(&request, body, "/dns-query", Some(&()));
        match (&routed, &accepted) {
            (Route::Proxy((), destination), Ok(accepted)) => {
                assert!(!accepted.is_empty() && accepted.len() <= dedens_net::odoh::MAX_BODY);
                let listed = std::str::from_utf8(host)
                    .ok()
                    .and_then(|host| host.parse::<Target>().ok());
                if query.starts_with("targethost=%") {
                    assert_eq!(listed.as_ref(), Some(&destination.target));
                    assert_eq!(destination.path.as_str().as_bytes(), path);
                }
                assert!(destination.path.as_str().starts_with('/'), "{query}");
                // The proxy's own request is one `http` takes: the 500 it answers otherwise is not reached.
                let forward =
                    forward_request(destination, accepted).expect("a request for a routed target");
                assert_eq!(
                    forward.uri().authority().map(http::uri::Authority::as_str),
                    Some(destination.target.to_string().as_str())
                );
                assert_eq!(forward.uri().path_and_query(), Some(&destination.path));
                assert_eq!(forward.body(), accepted);
                for header in [VIA, FORWARDED, COOKIE] {
                    assert!(!forward.headers().contains_key(&header), "{header}");
                }
                // Read back as written: what is listed is what is forwarded to.
                assert_eq!(
                    destination.target.to_string().parse::<Target>().as_ref(),
                    Ok(&destination.target)
                );
            }
            (Route::Proxy(..), Err(status)) => panic!("forwarding with status {status}"),
            (Route::Malformed(status), _) => {
                assert!(status.is_client_error(), "status {status}");
                assert_eq!(rejection(*status).status(), *status);
            }
            (Route::Target(_), Err(status)) => {
                assert!(status.is_client_error(), "status {status}");
            }
            (Route::Target(_), Ok(_)) => {}
        }
    }
    odoh_proxy_responses(host, body);
}

/// What the proxy answers: every error with its status, saying what it is, and the target's response, which goes on
/// whatever its status unless it is none of an encrypted message.
fn odoh_proxy_responses(content_type: &[u8], body: &[u8]) {
    use dedens_net::odoh::proxy::{ProxyError, failure, forwarded};
    for error in [
        ProxyError::HttpRequestError,
        ProxyError::HttpRequestDenied,
        ProxyError::ClientDenied,
        ProxyError::DnsError,
        ProxyError::DnsTimeout,
        ProxyError::DestinationIpProhibited,
        ProxyError::ConnectionRefused,
        ProxyError::ConnectionTimeout,
        ProxyError::ConnectionTerminated,
        ProxyError::ConnectionLimitReached,
        ProxyError::TlsProtocolError,
        ProxyError::HttpProtocolError,
        ProxyError::HttpResponseBodySize,
        ProxyError::HttpResponseTimeout,
        ProxyError::ProxyInternalError,
    ] {
        let response = failure(error.status(), error);
        assert_eq!(response.status(), error.status());
        assert!(dedens_net::odoh::proxy_error(response.headers()));
    }
    let status = body
        .first()
        .copied()
        .map_or(200, |byte| 200 + u16::from(byte));
    if let Ok(head) = http::Response::builder()
        .status(status)
        .header(http::header::CONTENT_TYPE, content_type)
        .body(())
    {
        let response = forwarded(&head, body.to_vec());
        assert!(
            response.status() == head.status()
                || response.status() == ProxyError::HttpProtocolError.status()
        );
        assert_eq!(
            response.headers().get(http::header::CACHE_CONTROL),
            Some(&http::HeaderValue::from_static("no-cache, no-store"))
        );
    }
}

/// How long the configurations of a response with the given `Cache-Control`, `Age` and `Date` are kept at `clock`
/// seconds after the epoch: the directives as the RFC reads them, apart from the code under test, say how long.
fn odoh_lifetime(control: &[u8], age: &[u8], date: &[u8], clock: u32) {
    const HOUR: u64 = 3600;
    const DAY: u64 = 24 * HOUR;
    let (Ok(control), Ok(age), Ok(date)) = (
        http::HeaderValue::from_bytes(control),
        http::HeaderValue::from_bytes(age),
        http::HeaderValue::from_bytes(date),
    ) else {
        return;
    };
    let text = String::from_utf8_lossy(control.as_bytes()).into_owned();
    let mut forbidden = false;
    let mut max_age = None;
    for directive in text.split(',') {
        let directive = directive.trim();
        let (name, value) = directive
            .split_once('=')
            .map_or((directive, None), |(name, value)| (name, Some(value)));
        let name = name.trim().to_ascii_lowercase();
        forbidden |= name == "no-store" || (name == "no-cache" && value.is_none());
        if name == "max-age" && max_age.is_none() {
            max_age = value.map(|value| value.trim().trim_matches('"').parse::<u64>().unwrap_or(0));
        }
    }
    let mut headers = http::HeaderMap::new();
    headers.insert(http::header::CACHE_CONTROL, control);
    headers.insert(http::header::AGE, age);
    headers.insert(http::header::DATE, date);
    let now = std::time::UNIX_EPOCH + std::time::Duration::from_secs(u64::from(clock));
    let lifetime = dedens_net::odoh::configs_lifetime(&headers, now);
    let kept = lifetime.keep.as_secs();
    assert_eq!(lifetime.forbidden, forbidden, "{text}");
    assert!((HOUR..=DAY).contains(&kept), "{text}: kept {kept} s");
    assert!(
        kept <= max_age.unwrap_or(0).max(HOUR),
        "{text}: kept {kept} s over max-age {max_age:?}"
    );
    if forbidden {
        assert_eq!(kept, HOUR, "{text}: forbidden, yet kept {kept} s");
    }
}

/// A request of the shape `shape` (method, path, `Content-Type`) with `body`, classified.
fn odoh_classify(shape: u8, body: &[u8]) {
    use dedens_net::odoh::{self, Kind};
    let method = match shape & 3 {
        0 => http::Method::GET,
        1 => http::Method::POST,
        2 => http::Method::PUT,
        _ => http::Method::HEAD,
    };
    let at_listener = shape & 4 == 0;
    let path = if at_listener {
        "/dns-query"
    } else {
        odoh::CONFIGS_PATH
    };
    let content_types: &[&str] = match (shape >> 3) & 7 {
        0 => &[dedens_odoh::MEDIA_TYPE],
        1 => &["Application/Oblivious-DNS-Message"],
        2 => &["application/oblivious-dns-message; charset=utf-8"],
        3 => &["application/oblivious-dns-message-x"],
        4 => &["application/dns-message"],
        5 => &[],
        _ => &["application/dns-message", dedens_odoh::MEDIA_TYPE],
    };
    let mut builder = http::Request::builder()
        .method(method.clone())
        .uri(format!("https://odoh.example{path}"));
    for content_type in content_types {
        builder = builder.header(http::header::CONTENT_TYPE, *content_type);
    }
    if let Ok(request) = builder.body(()) {
        let (kind, query) = odoh::classify(&request, body, "/dns-query");
        match &query {
            Ok(accepted) => assert!(accepted.len() <= odoh::MAX_BODY),
            Err(status) => assert!(
                [400, 404, 405, 413, 415].contains(&status.as_u16()),
                "status {status}"
            ),
        }
        // The listener's path is its own, the well-known one is configurations'.
        let oblivious = method == http::Method::POST && matches!((shape >> 3) & 7, 0..=2);
        let expected = match (at_listener, oblivious) {
            (true, true) => Kind::Oblivious,
            (true, false) => Kind::Dns,
            (false, _) => Kind::Configs,
        };
        assert_eq!(kind, expected, "{method} {path} {content_types:?}");
    }
}

/// The request through a proxy to a target whose path is `path`, as far as it is one, with `body`, as far as it is a
/// message: the target's authority and path are its `targethost` and `targetpath`, percent-encoded.
fn odoh_proxy_request(path: &[u8], body: &[u8]) {
    use dedens_net::odoh;
    if let Ok(message) = dedens_odoh::Message::parse(body)
        && let target_path = format!("/{}", String::from_utf8_lossy(path))
        && let Ok(authority) = "target.example:8443".parse()
        && let Ok(target) = Template::relative(authority, &target_path)
        && let Ok(proxy) = Template::parse("https://proxy.example/proxy")
        && let Ok(request) = odoh::request(Some(&proxy), &target, &message)
    {
        let uri = request.uri();
        assert_eq!(
            uri.authority().map(http::uri::Authority::as_str),
            Some("proxy.example")
        );
        assert_eq!(uri.path(), "/proxy");
        let query = uri.query().unwrap_or_default();
        let mut pairs = query
            .split('&')
            .map(|pair| pair.split_once('=').unwrap_or((pair, "")));
        let (host, path) = (pairs.next(), pairs.next());
        assert_eq!(pairs.next(), None, "{query}");
        assert_eq!(
            host.map(|(name, value)| (name, percent_decoded(value))),
            Some(("targethost", "target.example:8443".to_owned())),
            "{query}"
        );
        assert_eq!(
            path.map(|(name, value)| (name, percent_decoded(value))),
            Some(("targetpath", target.path().to_owned())),
            "{query}"
        );
        assert_eq!(request.body(), &message.encode());
    }
}

/// `value` with its `%XX` escapes decoded, as a proxy reads a query value (RFC 3986 §2.1); a `%` without two digits
/// stays.
fn percent_decoded(value: &str) -> String {
    let bytes = value.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut at = 0;
    while let Some(&byte) = bytes.get(at) {
        let digits = bytes
            .get(at + 1..at + 3)
            .and_then(|pair| std::str::from_utf8(pair).ok())
            .and_then(|pair| u8::from_str_radix(pair, 16).ok());
        if let (b'%', Some(decoded)) = (byte, digits) {
            out.push(decoded);
            at += 3;
        } else {
            out.push(byte);
            at += 1;
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// Bytes the "randomness" of a fuzz run repeats: the exchange stays deterministic.
struct Fixed(u8);

impl TryRng for Fixed {
    type Error = core::convert::Infallible;

    fn try_next_u32(&mut self) -> Result<u32, Self::Error> {
        Ok(u32::from_ne_bytes([self.0; 4]))
    }

    fn try_next_u64(&mut self) -> Result<u64, Self::Error> {
        Ok(u64::from_ne_bytes([self.0; 8]))
    }

    fn try_fill_bytes(&mut self, dst: &mut [u8]) -> Result<(), Self::Error> {
        dst.fill(self.0);
        Ok(())
    }
}

impl TryCryptoRng for Fixed {}

/// The target of the `odoh-go` vector (`testdata/odoh/README.md`): its `public_key_seed`, so
/// that the captured query below decrypts.
static ODOH_KEY: LazyLock<TargetKey> = LazyLock::new(|| {
    TargetKey::derive(&[
        0xc9, 0xd8, 0x4d, 0x04, 0xe6, 0x36, 0x9f, 0xcc, 0xb8, 0xa4, 0xd5, 0xa2, 0x64, 0x00, 0x14,
        0x91, 0x22, 0x1f, 0x1b, 0x97, 0xd9, 0xb8, 0x0d, 0xd3, 0x2c, 0x35, 0x83, 0x4b, 0xb4, 0x46,
        0x23, 0x83,
    ])
});

/// A query `odoh-go` encrypted for [`ODOH_KEY`].
const ODOH_QUERY: &[u8] = include_bytes!("../../testdata/odoh/odoh-go-query.bin");

/// The context of a query of our own: no response of the fuzzer can authenticate under it. Made once, since
/// the key exchange is slow unoptimized.
static ODOH_CLIENT: LazyLock<QueryContext> = LazyLock::new(|| {
    encrypt_query(ODOH_KEY.config(), b"q", 0, &mut Fixed(1))
        .expect("the key of a target is a good public key")
        .1
});

/// Arbitrary bytes as an `ODoH` query and as a response (RFC 9230 §7, §8): a forged message is refused, never a
/// panic. A parsed query is also given the target key ID, so that it reaches the key exchange; only the
/// ciphertext of `odoh-go` may authenticate. The exchange of well-formed messages is tested in
/// `crates/dedens-odoh/tests/odoh.rs`.
///
/// # Panics
///
/// When a forged message is accepted.
pub fn odoh_decrypt(data: &[u8]) {
    let Ok(message) = dedens_odoh::Message::parse(data) else {
        return;
    };
    let key = &*ODOH_KEY;
    let _ = decrypt_query(key, &message);
    if message.message_type() == MessageType::Query
        && let Ok(grafted) = dedens_odoh::Message::new(
            MessageType::Query,
            key.config().key_id().to_vec(),
            message.encrypted_message().to_vec(),
        )
        && decrypt_query(key, &grafted).is_ok()
    {
        let known = dedens_odoh::Message::parse(ODOH_QUERY).expect("the captured query parses");
        assert_eq!(message.encrypted_message(), known.encrypted_message());
    }
    assert!(decrypt_response(&ODOH_CLIENT, &message).is_err());
}
