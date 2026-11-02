//! The proxy role of Oblivious `DoH` (RFC 9230 §4, D94): reading a request to forward, making the request to the
//! target, and the responses a proxy makes. What a proxy may forward to, and the I/O, are the caller's.
//!
//! A request is for the proxy when its query holds `targethost` or `targetpath` (§4.1's `{?targethost,targetpath}`
//! form, §4.2); the path form `/{targethost}/{targetpath}` is not supported, as the client's is not (D79, D94).

use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::num::NonZeroU16;
use std::str::FromStr;

use compio::quic::{ConnectionError, TransportErrorCode};
use compio::rustls::pki_types::{DnsName, ServerName};
use dedens_odoh::MEDIA_TYPE;
use http::header::{ACCEPT, ALLOW, CACHE_CONTROL, CONTENT_LENGTH, CONTENT_TYPE};
use http::uri::PathAndQuery;
use http::{HeaderValue, Request, Response, StatusCode};

use super::{Kind, PROXY_STATUS, check_message, classify};
use crate::doh;
use crate::https::HttpsError;
use crate::quic::QuicError;

/// The port of a target that gives none: HTTPS's (RFC 9230 §4.1 expects the standard port).
pub const DEFAULT_PORT: NonZeroU16 = NonZeroU16::MIN.saturating_add(442);

/// How the proxy names itself in `Proxy-Status` (RFC 9209 §2): the service, not a host name.
const PROXY_NAME: &str = "dedensd";

/// Why a target does not read.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum TargetError {
    /// No host.
    #[error("no host")]
    Empty,
    /// Neither an IP address nor a host name (letters, digits and hyphens in labels of 1 to 63 bytes, 253 in all,
    /// in A-labels or U-labels): IPv6 addresses go in brackets.
    #[error("not a host name or an IP address")]
    Host,
    /// A port that is not 1 to 65535 in digits.
    #[error("not a port")]
    Port,
}

/// A host name, in lower case and A-labels (RFC 5891 §4) so that two spellings of one name are equal, with no
/// trailing dot, and valid as the name of a certificate: UTS 46's STD3 rules, labels of 1 to 63 bytes, 253 in all.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Name(DnsName<'static>);

impl Name {
    /// The name as a certificate's, for TLS.
    #[must_use]
    pub fn server_name(&self) -> ServerName<'static> {
        ServerName::DnsName(self.0.clone())
    }

    /// The name, in A-labels and lower case.
    #[must_use]
    pub fn as_str(&self) -> &str {
        self.0.as_ref()
    }
}

impl FromStr for Name {
    type Err = TargetError;

    /// One trailing dot, which makes the name absolute, is dropped.
    fn from_str(text: &str) -> Result<Self, TargetError> {
        let text = text.strip_suffix('.').unwrap_or(text);
        if text.is_empty() {
            return Err(TargetError::Empty);
        }
        let ascii = idna::domain_to_ascii_strict(text).map_err(|_| TargetError::Host)?;
        // `idna` is lenient about the hyphen and underscore edges that certificates' names are not.
        if !ascii
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.'))
        {
            return Err(TargetError::Host);
        }
        DnsName::try_from(ascii)
            .map(Self)
            .map_err(|_| TargetError::Host)
    }
}

impl fmt::Display for Name {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// The host of a target: an address, or a name.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum Host {
    /// A name, to be resolved.
    Name(Name),
    /// An address, used as it is.
    Address(IpAddr),
}

impl fmt::Display for Host {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Name(name) => name.fmt(f),
            Self::Address(IpAddr::V4(address)) => address.fmt(f),
            Self::Address(IpAddr::V6(address)) => write!(f, "[{address}]"),
        }
    }
}

/// A host and a port: `HOST[:PORT]`, as `targethost` (RFC 9230 §4.1) and the proxy's configuration write it, IPv6
/// addresses in brackets.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Target {
    host: Host,
    port: NonZeroU16,
}

impl Target {
    /// The host.
    #[must_use]
    pub const fn host(&self) -> &Host {
        &self.host
    }

    /// The port: [`DEFAULT_PORT`] when none is written.
    #[must_use]
    pub const fn port(&self) -> NonZeroU16 {
        self.port
    }

    /// The name the target's certificate must hold: the host's, or the address.
    #[must_use]
    pub fn server_name(&self) -> ServerName<'static> {
        match &self.host {
            Host::Name(name) => name.server_name(),
            Host::Address(address) => ServerName::IpAddress((*address).into()),
        }
    }
}

impl FromStr for Target {
    type Err = TargetError;

    fn from_str(text: &str) -> Result<Self, TargetError> {
        let (host, port) = if let Some(rest) = text.strip_prefix('[') {
            let (address, rest) = rest.split_once(']').ok_or(TargetError::Host)?;
            let address = address.parse::<Ipv6Addr>().map_err(|_| TargetError::Host)?;
            let port = match rest {
                "" => None,
                _ => Some(rest.strip_prefix(':').ok_or(TargetError::Host)?),
            };
            (Host::Address(IpAddr::V6(address)), port)
        } else {
            let (host, port) = match text.split_once(':') {
                Some((host, port)) => (host, Some(port)),
                None => (text, None),
            };
            (name_or_address(host)?, port)
        };
        let port = port.map_or(Ok(DEFAULT_PORT), |port| {
            if port.bytes().all(|byte| byte.is_ascii_digit()) {
                port.parse::<NonZeroU16>().map_err(|_| TargetError::Port)
            } else {
                Err(TargetError::Port)
            }
        })?;
        Ok(Self { host, port })
    }
}

/// The host in `text`: a dotted-quad IPv4 address, else a name.
fn name_or_address(text: &str) -> Result<Host, TargetError> {
    if let Ok(address) = text.parse::<Ipv4Addr>() {
        return Ok(Host::Address(IpAddr::V4(address)));
    }
    text.parse().map(Host::Name)
}

impl fmt::Display for Target {
    /// As the authority of a URI: the port is left out when it is the default.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.host.fmt(f)?;
        if self.port != DEFAULT_PORT {
            write!(f, ":{}", self.port)?;
        }
        Ok(())
    }
}

/// Where a request is to be forwarded: `https://` and the target, and the path (RFC 9230 §4.1).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Destination {
    /// The target's host and port.
    pub target: Target,
    /// The target's path, with the query it may hold: made of the characters RFC 3986 §3.3 and §3.4 allow.
    pub path: PathAndQuery,
}

/// What a request to a proxy and target is for (D94), `P` being the proxy a request for it holds.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Route<P> {
    /// Not for the proxy: the target's, as [`classify`] says.
    Target(Kind),
    /// To be forwarded by the proxy, the query its body.
    Proxy(P, Destination),
    /// For the proxy, and not as RFC 9230 §4.1 has it: [`rejection`] with the status.
    Malformed(StatusCode),
}

/// The route and the query, the body of a request to a listener at `path` that is the proxy `proxy` too, if any, for
/// [`Pending::read_with`](crate::https::Pending::read_with) (RFC 9230 §4.1).
///
/// At `path`, a request whose query has `targethost` or `targetpath` is for the proxy, and any other is
/// [`classify`]'s. The proxy's must be a POST of the oblivious media type with a body (405, 415, 400, 413 as
/// [`classify`] answers for a target), and name each variable once: `targethost` as [`Target`] reads it, and
/// `targetpath` an absolute path made of the characters of a URI's path and query; the status is 400 for any other.
/// The values are percent-decoded.
pub fn route<'p, T, P>(
    request: &Request<T>,
    body: &[u8],
    path: &str,
    proxy: Option<&'p P>,
) -> (Route<&'p P>, Result<Vec<u8>, StatusCode>) {
    let named = proxy
        .filter(|_| request.uri().path() == path)
        .and_then(|proxy| Some((proxy, variables(request.uri().query().unwrap_or_default())?)));
    let Some((proxy, (hosts, paths))) = named else {
        let (kind, query) = classify(request, body, path);
        return (Route::Target(kind), query);
    };
    let refused = |status| (Route::Malformed(status), Err(status));
    if request.method() != http::Method::POST {
        return refused(StatusCode::METHOD_NOT_ALLOWED);
    }
    if !doh::is_media_type(request.headers(), MEDIA_TYPE) {
        return refused(StatusCode::UNSUPPORTED_MEDIA_TYPE);
    }
    if let Err(status) = check_message(body) {
        return refused(status);
    }
    let ([host], [target_path]) = (hosts.as_slice(), paths.as_slice()) else {
        return refused(StatusCode::BAD_REQUEST);
    };
    match destination(host, target_path) {
        Some(destination) => (Route::Proxy(proxy, destination), Ok(body.to_vec())),
        None => refused(StatusCode::BAD_REQUEST),
    }
}

/// The values of `targethost` and of `targetpath` in `query`, as written; `None` when it has neither.
fn variables(query: &str) -> Option<(Vec<&str>, Vec<&str>)> {
    let (mut hosts, mut paths) = (Vec::new(), Vec::new());
    let mut named = false;
    for pair in query.split('&') {
        let (name, value) = pair.split_once('=').unwrap_or((pair, ""));
        match name {
            "targethost" => hosts.push(value),
            "targetpath" => paths.push(value),
            _ => continue,
        }
        named = true;
    }
    named.then_some((hosts, paths))
}

/// The destination of the percent-encoded `host` and `path` values: a target, and an absolute path with no fragment.
fn destination(host: &str, path: &str) -> Option<Destination> {
    let target = decode(host)?.parse().ok()?;
    let path = decode(path).filter(|path| path.starts_with('/') && is_path_and_query(path))?;
    Some(Destination {
        target,
        path: path.parse().ok()?,
    })
}

/// Whether `text` is made of the characters of a URI's path and query: unreserved, sub-delimiters, `:`, `@`, `/`
/// and `?`, and `%` before two hexadecimal digits (RFC 3986 §2, §3.3, §3.4). The decoded value of `targetpath` is
/// the path as it goes to the target, not encoded again, so a byte outside them is refused.
fn is_path_and_query(text: &str) -> bool {
    let mut bytes = text.bytes();
    while let Some(byte) = bytes.next() {
        let allowed = match byte {
            b'%' => bytes.next().and_then(hex).is_some() && bytes.next().and_then(hex).is_some(),
            _ => byte.is_ascii_alphanumeric() || b"-._~!$&'()*+,;=:@/?".contains(&byte),
        };
        if !allowed {
            return false;
        }
    }
    true
}

/// `value` with each `%XX` replaced by its byte, as UTF-8; `None` for an escape that is cut short or not
/// hexadecimal, or bytes that are no text (RFC 3986 §2.1). A `+` stays one: this is a URI's query, not a form's.
fn decode(value: &str) -> Option<String> {
    let mut bytes = Vec::with_capacity(value.len());
    let mut rest = value.bytes();
    while let Some(byte) = rest.next() {
        if byte == b'%' {
            let high = rest.next().and_then(hex)?;
            let low = rest.next().and_then(hex)?;
            bytes.push(high * 16 + low);
        } else {
            bytes.push(byte);
        }
    }
    String::from_utf8(bytes).ok()
}

/// The value of the hexadecimal digit `byte`.
fn hex(byte: u8) -> Option<u8> {
    char::from(byte)
        .to_digit(16)
        .and_then(|digit| u8::try_from(digit).ok())
}

/// The request to the target of `destination` carrying the encrypted query `body` (RFC 9230 §4.2): a POST of the
/// oblivious media type, with nothing of the client's: no `Forwarded`, `Via`, cookie or address (§4.5).
///
/// # Errors
///
/// [`http::Error`] for a URI `http` refuses: none a [`Destination`] from [`route`] makes.
pub fn forward_request(
    destination: &Destination,
    body: &[u8],
) -> Result<Request<Vec<u8>>, http::Error> {
    Request::builder()
        .method(http::Method::POST)
        .uri(format!(
            "https://{}{}",
            destination.target, destination.path
        ))
        .header(ACCEPT, MEDIA_TYPE)
        .header(CONTENT_TYPE, MEDIA_TYPE)
        .header(CONTENT_LENGTH, body.len())
        .body(body.to_vec())
}

/// Why a proxy answers with an error: the `error` of its `Proxy-Status` (RFC 9209 §2.1.1, §2.3).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum ProxyError {
    /// The request is not what RFC 9230 §4.1 describes.
    HttpRequestError,
    /// The target or its port is not one the proxy forwards to (§4.1, §11.2).
    HttpRequestDenied,
    /// The client is one the access lists deny (D91): the same error, for another reason, in `details`.
    ClientDenied,
    /// The target's name does not resolve.
    DnsError,
    /// The target's name did not resolve in time.
    DnsTimeout,
    /// The target's name resolves to an address the proxy does not connect to: one that is not global.
    DestinationIpProhibited,
    /// The target refused the connection.
    ConnectionRefused,
    /// The connection to the target was not up in time.
    ConnectionTimeout,
    /// The target closed the connection or reset the request.
    ConnectionTerminated,
    /// The proxy has all the forwards it makes at once.
    ConnectionLimitReached,
    /// The TLS handshake with the target failed: no certificate the proxy trusts for the name, or an alert.
    TlsProtocolError,
    /// The target broke HTTP/3, or answered with something else than an encrypted message.
    HttpProtocolError,
    /// The target's response is longer than an encrypted DNS message.
    HttpResponseBodySize,
    /// The request went out and the target did not answer in time.
    HttpResponseTimeout,
    /// The proxy cannot make the request.
    ProxyInternalError,
}

impl ProxyError {
    /// The `error` parameter's token.
    #[must_use]
    pub const fn token(self) -> &'static str {
        match self {
            Self::HttpRequestError => "http_request_error",
            Self::HttpRequestDenied | Self::ClientDenied => "http_request_denied",
            Self::DnsError => "dns_error",
            Self::DnsTimeout => "dns_timeout",
            Self::DestinationIpProhibited => "destination_ip_prohibited",
            Self::ConnectionRefused => "connection_refused",
            Self::ConnectionTimeout => "connection_timeout",
            Self::ConnectionTerminated => "connection_terminated",
            Self::ConnectionLimitReached => "connection_limit_reached",
            Self::TlsProtocolError => "tls_protocol_error",
            Self::HttpProtocolError => "http_protocol_error",
            Self::HttpResponseBodySize => "http_response_body_size",
            Self::HttpResponseTimeout => "http_response_timeout",
            Self::ProxyInternalError => "proxy_internal_error",
        }
    }

    /// The status of the response: RFC 9209 §2.3's, but 502 for a name that did not resolve in time, as RFC 9230
    /// §4.1 says; 400 for a request that is none, the status of the actual fault aside (D94).
    #[must_use]
    pub const fn status(self) -> StatusCode {
        match self {
            Self::HttpRequestError => StatusCode::BAD_REQUEST,
            Self::HttpRequestDenied | Self::ClientDenied => StatusCode::FORBIDDEN,
            Self::ConnectionTimeout | Self::HttpResponseTimeout => StatusCode::GATEWAY_TIMEOUT,
            Self::ConnectionLimitReached => StatusCode::SERVICE_UNAVAILABLE,
            Self::ProxyInternalError => StatusCode::INTERNAL_SERVER_ERROR,
            Self::DnsError
            | Self::DnsTimeout
            | Self::DestinationIpProhibited
            | Self::ConnectionRefused
            | Self::ConnectionTerminated
            | Self::TlsProtocolError
            | Self::HttpProtocolError
            | Self::HttpResponseBodySize => StatusCode::BAD_GATEWAY,
        }
    }

    /// The `details` parameter (RFC 9209 §2.1.5), for the errors that say more than their token: a target refused is
    /// not told apart from a port refused, as RFC 9230 §4.1 words it.
    #[must_use]
    pub const fn details(self) -> Option<&'static str> {
        match self {
            Self::HttpRequestDenied => Some("target host or port not listed"),
            Self::ClientDenied => Some("client not allowed"),
            _ => None,
        }
    }

    /// What `error` says about the exchange with the target, `connected` once the connection to it was up: a timeout
    /// is the connection's before, the response's after.
    #[must_use]
    pub fn of(error: &HttpsError, connected: bool) -> Self {
        match error {
            HttpsError::TimedOut if connected => Self::HttpResponseTimeout,
            HttpsError::TimedOut | HttpsError::Quic(QuicError::TimedOut) => Self::ConnectionTimeout,
            HttpsError::Quic(QuicError::Connection(error)) => connection(error),
            HttpsError::Quic(QuicError::Stream(_)) | HttpsError::Stream(_) => {
                Self::ConnectionTerminated
            }
            HttpsError::Connection(_) | HttpsError::Response(_) => Self::HttpProtocolError,
            HttpsError::TooLong => Self::HttpResponseBodySize,
            HttpsError::Quic(_) | HttpsError::Request(_) => Self::ProxyInternalError,
        }
    }
}

/// What a failed QUIC connection says: the handshake's refusal or alert (RFC 9001 §4.8), or the server's
/// `CONNECTION_REFUSED` (RFC 9000 §20.1), else a connection that ended.
fn connection(error: &ConnectionError) -> ProxyError {
    let crypto = |code: TransportErrorCode| (0x100..0x200).contains(&u64::from(code));
    match error {
        ConnectionError::TimedOut => ProxyError::ConnectionTimeout,
        ConnectionError::TransportError(error) if crypto(error.code) => {
            ProxyError::TlsProtocolError
        }
        ConnectionError::ConnectionClosed(close) if crypto(close.error_code) => {
            ProxyError::TlsProtocolError
        }
        ConnectionError::ConnectionClosed(close)
            if close.error_code == TransportErrorCode::CONNECTION_REFUSED =>
        {
            ProxyError::ConnectionRefused
        }
        _ => ProxyError::ConnectionTerminated,
    }
}

/// A response of the proxy's: never to be cached, by the client or anyone (RFC 9230 §4.1), with the `Proxy-Status`
/// member `proxy_status` says.
fn reply(status: StatusCode, body: Vec<u8>, proxy_status: &str) -> Response<Vec<u8>> {
    let mut response = Response::new(body);
    *response.status_mut() = status;
    let headers = response.headers_mut();
    headers.insert(
        CACHE_CONTROL,
        HeaderValue::from_static("no-cache, no-store"),
    );
    // Tokens, digits and a quoted string of ours make a valid value.
    headers.insert(
        PROXY_STATUS,
        HeaderValue::try_from(format!("{PROXY_NAME}; {proxy_status}"))
            .unwrap_or_else(|_| HeaderValue::from_static(PROXY_NAME)),
    );
    response
}

/// The response of the proxy to a request it does not forward or cannot: `status` and no body, `Proxy-Status`
/// naming `error` and its `details` (RFC 9209 §2, RFC 9230 §4.1).
#[must_use]
pub fn failure(status: StatusCode, error: ProxyError) -> Response<Vec<u8>> {
    let member = match error.details() {
        Some(details) => format!("error={}; details=\"{details}\"", error.token()),
        None => format!("error={}", error.token()),
    };
    reply(status, Vec::new(), &member)
}

/// The response to a request for the proxy that is not one RFC 9230 §4.1 describes, `status` being 400, 405, 413 or
/// 415 as [`route`] says: a 405 says what is allowed (RFC 9110 §15.5.6).
#[must_use]
pub fn rejection(status: StatusCode) -> Response<Vec<u8>> {
    let mut response = failure(status, ProxyError::HttpRequestError);
    if status == StatusCode::METHOD_NOT_ALLOWED {
        response
            .headers_mut()
            .insert(ALLOW, HeaderValue::from_static("POST"));
    }
    response
}

/// The response of the proxy carrying the target's: its status, its body unchanged and its content type, and
/// `Proxy-Status` with the `received-status` (RFC 9230 §4.3, RFC 9209 §2.1.4). No other header of the target's goes
/// on: a `Location` would send the client to the target directly. A success that is not of the oblivious media type
/// is no answer to the query (§4.3): the target broke the protocol, `http_protocol_error`.
#[must_use]
pub fn forwarded(head: &Response<()>, body: Vec<u8>) -> Response<Vec<u8>> {
    let status = head.status();
    if status.is_success() && !doh::is_media_type(head.headers(), MEDIA_TYPE) {
        let error = ProxyError::HttpProtocolError;
        return failure(error.status(), error);
    }
    let mut response = reply(
        status,
        body,
        &format!("received-status={}", status.as_u16()),
    );
    if let Some(content_type) = head.headers().get(CONTENT_TYPE) {
        response
            .headers_mut()
            .insert(CONTENT_TYPE, content_type.clone());
    }
    response
}

#[cfg(test)]
mod tests {
    use std::io;

    use compio::quic::ConnectionClose;

    use super::*;
    use crate::odoh::{MAX_BODY, proxy_error};

    /// A request of the oblivious media type, POST unless `method` says otherwise.
    fn post(uri: &str, method: http::Method, content_type: &str) -> Request<()> {
        Request::builder()
            .method(method)
            .uri(uri)
            .header(CONTENT_TYPE, content_type)
            .body(())
            .expect("a request")
    }

    /// The proxy of these tests: nothing but the mark that the listener is one.
    const PROXY: &() = &();

    fn routed(uri: &str) -> (Route<&'static ()>, Result<Vec<u8>, StatusCode>) {
        route(
            &post(uri, http::Method::POST, MEDIA_TYPE),
            b"message",
            "/dns-query",
            Some(PROXY),
        )
    }

    /// RFC 9230 §4.2's request: `targethost` and `targetpath` in the query, the path percent-encoded or not.
    #[test]
    fn s4_2_a_request_names_its_destination() {
        for uri in [
            "https://p.example/dns-query?targethost=odoh.example&targetpath=/dns-query",
            "https://p.example/dns-query?targetpath=%2Fdns-query&targethost=odoh.example",
            "https://p.example/dns-query?x=1&targethost=ODOH.example:443&targetpath=%2fdns-query",
        ] {
            let (route, body) = routed(uri);
            let Route::Proxy(&(), destination) = route else {
                panic!("{uri}: {route:?}");
            };
            assert_eq!(destination.target.to_string(), "odoh.example", "{uri}");
            assert_eq!(destination.path, "/dns-query", "{uri}");
            assert_eq!(body, Ok(b"message".to_vec()), "{uri}");
        }
    }

    /// A variable missing or given twice, a path that is not absolute or has a fragment, an escape cut short,
    /// userinfo and a bad port are all 400, `Malformed` for the proxy.
    #[test]
    fn s4_1_a_malformed_request_is_400() {
        for query in [
            "targethost=odoh.example",
            "targetpath=/dns-query",
            "targethost=a.example&targethost=b.example&targetpath=/q",
            "targethost=a.example&targetpath=/q&targetpath=/r",
            "targethost=a.example&targetpath=dns-query",
            "targethost=a.example&targetpath=/q%23x",
            "targethost=a.example&targetpath=/%C3%A9",
            "targethost=a.example&targetpath=/q%7F",
            "targethost=a.example&targetpath=/q%20x",
            "targethost=a.example&targetpath=/q%5B",
            "targethost=-a.example&targetpath=/q",
            "targethost=a_b.example&targetpath=/q",
            "targethost=a..example&targetpath=/q",
            "targethost=a.example&targetpath=/q%2",
            "targethost=a.example&targetpath=/q%zz",
            "targethost=u%40a.example&targetpath=/q",
            "targethost=a.example%2Fb&targetpath=/q",
            "targethost=a.example:0&targetpath=/q",
            "targethost=a.example:80x&targetpath=/q",
            "targethost=&targetpath=/q",
            "targethost&targetpath",
        ] {
            let (route, body) = routed(&format!("https://p.example/dns-query?{query}"));
            assert_eq!(
                (route, body),
                (
                    Route::Malformed(StatusCode::BAD_REQUEST),
                    Err(StatusCode::BAD_REQUEST)
                ),
                "{query}"
            );
        }
    }

    /// A request for the proxy that is no POST of the oblivious media type, or has no body or too long a one.
    #[test]
    fn s4_1_a_request_that_is_no_oblivious_post_is_refused() {
        let uri = "https://p.example/dns-query?targethost=a.example&targetpath=/q";
        let refused = |request, body: &[u8], status| {
            assert_eq!(
                route(&request, body, "/dns-query", Some(PROXY)),
                (Route::Malformed(status), Err(status))
            );
        };
        refused(
            post(uri, http::Method::GET, MEDIA_TYPE),
            b"m",
            StatusCode::METHOD_NOT_ALLOWED,
        );
        refused(
            post(uri, http::Method::POST, "application/dns-message"),
            b"m",
            StatusCode::UNSUPPORTED_MEDIA_TYPE,
        );
        refused(
            post(uri, http::Method::POST, MEDIA_TYPE),
            b"",
            StatusCode::BAD_REQUEST,
        );
        refused(
            post(uri, http::Method::POST, MEDIA_TYPE),
            &vec![0; MAX_BODY + 1],
            StatusCode::PAYLOAD_TOO_LARGE,
        );
    }

    /// A request without either variable stays a target's, and so does any when the listener is no proxy.
    #[test]
    fn a_request_without_variables_is_the_targets() {
        let request = post(
            "https://p.example/dns-query",
            http::Method::POST,
            MEDIA_TYPE,
        );
        assert_eq!(
            route(&request, b"m", "/dns-query", Some(PROXY)),
            (Route::Target(Kind::Oblivious), Ok(b"m".to_vec()))
        );
        let request = post(
            "https://p.example/dns-query?targethost=a.example&targetpath=/q",
            http::Method::POST,
            MEDIA_TYPE,
        );
        assert_eq!(
            route::<_, ()>(&request, b"m", "/dns-query", None),
            (Route::Target(Kind::Oblivious), Ok(b"m".to_vec()))
        );
        let (route, query) = route(&request, b"m", "/other", Some(PROXY));
        assert_eq!(
            (route, query),
            (Route::Target(Kind::Dns), Err(StatusCode::NOT_FOUND))
        );
    }

    /// `HOST[:PORT]`: names in lower case and A-labels, the default port, addresses, and what is refused.
    #[test]
    fn targets_read_as_written() {
        let read = |text: &str| text.parse::<Target>().map(|target| target.to_string());
        assert_eq!(read("Odoh.Example"), Ok("odoh.example".to_owned()));
        assert_eq!(
            read("odoh.example:8443"),
            Ok("odoh.example:8443".to_owned())
        );
        assert_eq!(read("odoh.example:443"), Ok("odoh.example".to_owned()));
        assert_eq!(
            read("bücher.example"),
            Ok("xn--bcher-kva.example".to_owned())
        );
        assert_eq!(read("127.0.0.1:4443"), Ok("127.0.0.1:4443".to_owned()));
        assert_eq!(read("[2001:db8::1]"), Ok("[2001:db8::1]".to_owned()));
        assert_eq!(
            read("[2001:DB8:0::1]:853"),
            Ok("[2001:db8::1]:853".to_owned())
        );
        assert_eq!(read("odoh.example."), Ok("odoh.example".to_owned()));
        assert_eq!(read(""), Err(TargetError::Empty));
        assert_eq!(read(":443"), Err(TargetError::Empty));
        assert_eq!(read("."), Err(TargetError::Empty));
        let label = "a".repeat(63);
        assert!(read(&format!("{label}.example")).is_ok());
        assert!(read(&format!("{label}a.example")).is_err());
        let names = |last: usize| [63, 63, 63, last].map(|len| "a".repeat(len)).join(".");
        assert!(read(&names(61)).is_ok(), "253 bytes");
        assert!(read(&names(62)).is_err(), "254 bytes");
        for text in [
            "a_b.example",
            "-a.example",
            "a-.example",
            "a..example",
            "a.example..",
            "a b",
            "a/b",
            "a@b",
            "2001:db8::1",
            "[::1",
            "[::1]x",
            "a.example:",
        ] {
            assert!(read(text).is_err(), "{text}");
        }
        assert_eq!(read("a.example:+1"), Err(TargetError::Port));
        assert_eq!(read("a.example:65536"), Err(TargetError::Port));
    }

    /// The request to the target is a POST of the oblivious media type and carries nothing else of the client's.
    #[test]
    fn s4_2_the_forwarded_request_is_the_posts_alone() {
        let (route, _) =
            routed("https://p.example/dns-query?targethost=a.example:8443&targetpath=%2Fq%3Fx%3D1");
        let Route::Proxy(&(), destination) = route else {
            panic!("{route:?}");
        };
        let request = forward_request(&destination, b"message").expect("a request");
        assert_eq!(request.method(), http::Method::POST);
        assert_eq!(request.uri(), "https://a.example:8443/q?x=1");
        let mut names = request
            .headers()
            .keys()
            .map(http::HeaderName::as_str)
            .collect::<Vec<_>>();
        names.sort_unstable();
        assert_eq!(names, ["accept", "content-length", "content-type"]);
        assert_eq!(request.headers()[CONTENT_TYPE], MEDIA_TYPE);
        assert_eq!(request.headers()[CONTENT_LENGTH], "7");
    }

    /// RFC 9209 §2.1.1: a proxy's error names itself and the error, and the client reads it as the proxy's.
    #[test]
    fn s2_the_errors_of_the_proxy_name_themselves() {
        let response = failure(StatusCode::FORBIDDEN, ProxyError::HttpRequestDenied);
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
        assert_eq!(
            response.headers()[PROXY_STATUS],
            "dedensd; error=http_request_denied; details=\"target host or port not listed\""
        );
        assert_eq!(response.headers()[CACHE_CONTROL], "no-cache, no-store");
        assert!(proxy_error(response.headers()));
        let response = failure(StatusCode::BAD_GATEWAY, ProxyError::DnsError);
        assert_eq!(response.headers()[PROXY_STATUS], "dedensd; error=dns_error");
    }

    /// RFC 9110 §15.5.6: a 405 says which method is allowed.
    #[test]
    fn s15_5_6_a_refused_method_names_the_allowed_one() {
        let response = rejection(StatusCode::METHOD_NOT_ALLOWED);
        assert_eq!(response.headers()[ALLOW], "POST");
        assert!(
            !rejection(StatusCode::BAD_REQUEST)
                .headers()
                .contains_key(ALLOW)
        );
    }

    /// RFC 9230 §4.3: a success that is not an encrypted message is the target breaking the protocol.
    #[test]
    fn s4_3_a_success_that_is_no_message_is_a_protocol_error() {
        let mut head = Response::new(());
        head.headers_mut()
            .insert(CONTENT_TYPE, HeaderValue::from_static("text/html"));
        let response = forwarded(&head, b"<html>".to_vec());
        assert_eq!(response.status(), StatusCode::BAD_GATEWAY);
        assert_eq!(
            response.headers()[PROXY_STATUS],
            "dedensd; error=http_protocol_error"
        );
        assert_eq!(response.body().len(), 0);
        // Another status keeps its own, whatever its content type.
        *head.status_mut() = StatusCode::NOT_FOUND;
        assert_eq!(forwarded(&head, Vec::new()).status(), StatusCode::NOT_FOUND);
    }

    /// RFC 9230 §4.3: the target's status, body and content type go on, and the proxy says it was the target's.
    #[test]
    fn s4_3_the_targets_response_goes_on() {
        let mut head = Response::new(());
        *head.status_mut() = StatusCode::UNAUTHORIZED;
        head.headers_mut()
            .insert(CONTENT_TYPE, HeaderValue::from_static(MEDIA_TYPE));
        head.headers_mut().insert(
            http::header::LOCATION,
            HeaderValue::from_static("https://elsewhere.example/"),
        );
        let response = forwarded(&head, b"body".to_vec());
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        assert_eq!(response.body(), b"body");
        assert_eq!(response.headers()[CONTENT_TYPE], MEDIA_TYPE);
        assert_eq!(
            response.headers()[PROXY_STATUS],
            "dedensd; received-status=401"
        );
        assert!(!response.headers().contains_key(http::header::LOCATION));
        assert!(!proxy_error(response.headers()));
    }

    /// The failures of the exchange with the target, as RFC 9209 §2.3 names them.
    #[test]
    fn failures_have_their_errors() {
        use ProxyError::{
            ConnectionTerminated, ConnectionTimeout, HttpResponseBodySize, HttpResponseTimeout,
            ProxyInternalError,
        };
        let of = |error| ProxyError::of(&error, false);
        assert_eq!(of(HttpsError::TimedOut), ConnectionTimeout);
        assert_eq!(
            ProxyError::of(&HttpsError::TimedOut, true),
            HttpResponseTimeout
        );
        assert_eq!(HttpResponseTimeout.status(), StatusCode::GATEWAY_TIMEOUT);
        assert_eq!(of(HttpsError::TooLong), HttpResponseBodySize);
        assert_eq!(
            of(HttpsError::Quic(QuicError::Connection(
                ConnectionError::TimedOut
            ))),
            ConnectionTimeout
        );
        assert_eq!(
            of(HttpsError::Quic(QuicError::Connection(
                ConnectionError::Reset
            ))),
            ConnectionTerminated
        );
        assert_eq!(
            of(HttpsError::Quic(QuicError::Bind(io::Error::other(
                "no socket"
            )))),
            ProxyInternalError
        );
        assert_eq!(ConnectionTimeout.status(), StatusCode::GATEWAY_TIMEOUT);
        assert_eq!(ProxyError::DnsTimeout.status(), StatusCode::BAD_GATEWAY);
    }

    /// RFC 9001 §4.8: a handshake that fails, by the alert or by the close that carries it, is a TLS error; RFC 9000
    /// §20.1: `CONNECTION_REFUSED` is a refusal; any other end is a connection that ended.
    #[test]
    fn s20_1_a_failed_connection_is_told_by_its_error_code() {
        use ProxyError::{ConnectionRefused, ConnectionTerminated, TlsProtocolError};
        let close = |error_code| {
            ConnectionError::ConnectionClosed(ConnectionClose {
                error_code,
                frame_type: None,
                reason: <_>::default(),
            })
        };
        // The alert 40, handshake_failure, and the ends of the crypto range.
        for alert in [0, 40, 255] {
            let code = TransportErrorCode::crypto(alert);
            assert_eq!(
                connection(&ConnectionError::TransportError(code.into())),
                TlsProtocolError
            );
            assert_eq!(connection(&close(code)), TlsProtocolError);
        }
        let other = TransportErrorCode::PROTOCOL_VIOLATION;
        assert_eq!(
            connection(&ConnectionError::TransportError(other.into())),
            ConnectionTerminated
        );
        assert_eq!(connection(&close(other)), ConnectionTerminated);
        assert_eq!(
            connection(&close(TransportErrorCode::CONNECTION_REFUSED)),
            ConnectionRefused
        );
        assert_eq!(
            connection(&ConnectionError::TimedOut),
            ProxyError::ConnectionTimeout
        );
        assert_eq!(connection(&ConnectionError::Reset), ConnectionTerminated);
    }

    /// RFC 3986 §3.3, §3.4: a path and query is made of its characters and of `%` before two hexadecimal digits.
    #[test]
    fn s3_3_a_path_is_made_of_the_characters_of_a_path() {
        for text in [
            "/",
            "/q?x=1&y=a:b@c",
            "/%41",
            "/a%2Fb",
            "/%7e%7E",
            "/-._~!$&'()*+,;=",
        ] {
            assert!(is_path_and_query(text), "{text}");
        }
        for text in [
            "/%", "/%4", "/%4z", "/%z4", "/%zz", "/a b", "/a#b", "/\"", "/é", "/[]",
        ] {
            assert!(!is_path_and_query(text), "{text}");
        }
    }

    /// RFC 9209 §2.1.5: the details tell what is denied: the target, or the client.
    #[test]
    fn s2_1_5_a_denial_says_what_is_denied() {
        assert_eq!(
            ProxyError::HttpRequestDenied.details(),
            Some("target host or port not listed")
        );
        assert_eq!(
            ProxyError::ClientDenied.details(),
            Some("client not allowed")
        );
        assert_eq!(ProxyError::DnsError.details(), None);
        let response = failure(StatusCode::FORBIDDEN, ProxyError::ClientDenied);
        assert_eq!(
            response.headers()[PROXY_STATUS],
            "dedensd; error=http_request_denied; details=\"client not allowed\""
        );
    }
}
