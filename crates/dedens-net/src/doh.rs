//! DNS over HTTPS (RFC 8484), without a connection: the HTTP request a query makes, the DNS response an HTTP
//! response holds, and the same for a server (D82).
//!
//! `http` types go in and out; HTTP/2 and HTTP/3 carry them. The caller sets the query's ID to 0 (RFC 8484 §4.1),
//! which [`crate::exchange::Exchange`] does over [`Transport::Https`](dedens_proto::Transport::Https), and pads it.

use core::fmt;
use std::time::{SystemTime, UNIX_EPOCH};

use dedens_proto::rdata::RData;
use dedens_proto::{
    DecodeError, Decoded, EncodeError, MAX_MESSAGE_LEN, Message, RecordType, Ttl, decode_base64url,
    encode_base64url,
};
use http::header::{ACCEPT, AGE, CACHE_CONTROL, CONTENT_LENGTH, CONTENT_TYPE};
use http::uri::{Authority, InvalidUri, PathAndQuery};
use http::{HeaderMap, HeaderValue, Request, Response, StatusCode};

/// The media type of a DNS message in an HTTP body (RFC 8484 §6): the message of RFC 1035 §4.2.1, without a length.
pub const MEDIA_TYPE: &str = "application/dns-message";

/// The path of a `DoH` server that gives none: `/dns-query`, as RFC 8484 §3 writes its examples and servers use it.
pub const DEFAULT_PATH: &str = "/dns-query";

/// How a query goes in the HTTP request (RFC 8484 §4.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Method {
    /// GET: the query as the `dns` parameter, which HTTP caches can keep.
    Get,
    /// POST: the query as the body, smaller than its GET.
    Post,
}

/// A template that is not a `DoH` one.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum TemplateError {
    /// The scheme is not `https` (RFC 8484 §5).
    #[error("not an https URL")]
    NotHttps,
    /// The host and port are not an authority.
    #[error("invalid authority")]
    Authority(#[source] InvalidUri),
    /// The authority has a user name or password, which `https` deprecates (RFC 9110 §4.2.4).
    #[error("authority with user information")]
    UserInfo,
    /// A relative template not starting with `/` (RFC 9461 §5, RFC 9113 §8.3.1).
    #[error("the path does not start with /")]
    NotAbsolute,
    /// An expression other than the one `dns` variable, or one not at the end: `{?dns}`, or `{&dns}` after a query
    /// (RFC 6570 §3.2.8, RFC 8484 §4.1).
    #[error("only {{?dns}}, or {{&dns}} after a query, may end the template")]
    Expression,
    /// The template has no `dns` variable, which a `dohpath` must have (RFC 9461 §5).
    #[error("no dns variable")]
    MissingVariable,
    /// The literal part is not a path with a query, has a fragment, or a `dns` parameter of its own, which the
    /// variable would repeat.
    #[error("invalid path")]
    Path(#[source] Option<InvalidUri>),
}

/// The address of a `DoH` server: the authority and the path of its URI Template (RFC 8484 §3), the one form `DoH`
/// uses being the form-style query expansion of its `dns` variable (RFC 6570 §3.2.8): `https://host/path{?dns}`.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Template {
    authority: Authority,
    /// The path and query before the `dns` variable, starting with `/`.
    path: String,
}

impl Template {
    /// Reads `https://host[:port]/path{?dns}`. A template without expression, as `https://host/dns-query`, has
    /// `{?dns}` implied, as dig and kdig take theirs.
    ///
    /// # Errors
    ///
    /// [`TemplateError`] for another scheme, an authority that is not one, user information, or a template
    /// [`Template::relative`] refuses.
    pub fn parse(text: &str) -> Result<Self, TemplateError> {
        let scheme = text.get(..8).ok_or(TemplateError::NotHttps)?;
        if !scheme.eq_ignore_ascii_case("https://") {
            return Err(TemplateError::NotHttps);
        }
        let rest = text.get(8..).ok_or(TemplateError::NotHttps)?;
        let (authority, path) = rest.split_at(rest.find('/').unwrap_or(rest.len()));
        Self::relative(authority.parse().map_err(TemplateError::Authority)?, path)
    }

    /// The template `path` of the server `authority`: a path starting with `/`, empty for `/`, with a `{?dns}`
    /// ending it, or, once it holds a query, `{&dns}`; implied when it has no expression, as in [`Template::parse`].
    ///
    /// # Errors
    ///
    /// [`TemplateError`] when `authority` has user information, `path` is not absolute, has another expression
    /// or a fragment, or is not a path.
    pub fn relative(authority: Authority, path: &str) -> Result<Self, TemplateError> {
        Self::build(authority, path, false)
    }

    /// The template of an SVCB `dohpath` value (RFC 9461 §5) for the server `authority`: as [`Template::relative`],
    /// but with the `dns` variable written out, which a `dohpath` must have.
    ///
    /// # Errors
    ///
    /// [`TemplateError::MissingVariable`] without the variable, else as [`Template::relative`].
    pub fn from_dohpath(authority: Authority, dohpath: &str) -> Result<Self, TemplateError> {
        Self::build(authority, dohpath, true)
    }

    fn build(
        authority: Authority,
        template: &str,
        variable_required: bool,
    ) -> Result<Self, TemplateError> {
        if authority.as_str().contains('@') {
            return Err(TemplateError::UserInfo);
        }
        let template = if template.is_empty() { "/" } else { template };
        if !template.starts_with('/') {
            return Err(TemplateError::NotAbsolute);
        }
        let (literal, expression) = template.split_at(template.find('{').unwrap_or(template.len()));
        let joiner = if literal.contains('?') { "&" } else { "?" };
        match expression {
            "" if variable_required => return Err(TemplateError::MissingVariable),
            "" => {}
            _ if expression
                .strip_prefix('{')
                .and_then(|e| e.strip_suffix("dns}"))
                == Some(joiner) => {}
            _ => return Err(TemplateError::Expression),
        }
        let own_dns = literal.split_once('?').is_some_and(|(_, query)| {
            query
                .split('&')
                .any(|pair| pair == "dns" || pair.starts_with("dns="))
        });
        if literal.contains(['#', '}']) || own_dns {
            return Err(TemplateError::Path(None));
        }
        PathAndQuery::try_from(literal).map_err(|e| TemplateError::Path(Some(e)))?;
        Ok(Self {
            authority,
            path: literal.to_owned(),
        })
    }

    /// The server's host and port: the TLS name and the `:authority` of its requests.
    #[must_use]
    pub const fn authority(&self) -> &Authority {
        &self.authority
    }

    /// The path and query before the `dns` variable, starting with `/`.
    #[must_use]
    pub fn path(&self) -> &str {
        &self.path
    }

    /// What follows `dns=` joins: `&` once the path holds a query, else `?`.
    fn joiner(&self) -> char {
        if self.path.contains('?') { '&' } else { '?' }
    }
}

impl fmt::Display for Template {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "https://{}{}{{{}dns}}",
            self.authority,
            self.path,
            self.joiner()
        )
    }
}

/// The HTTP request asking `server` for the answer to `query`, a DNS message with ID 0 (RFC 8484 §4.1): a GET with
/// the query as `dns`, base64url without padding, or a POST with it as the body. It accepts, and for a POST sends,
/// [`MEDIA_TYPE`] and its length (Cloudflare's HTTP/3 answers 405 to a POST without one).
///
/// # Errors
///
/// [`http::Error`] when the URI is too long for `http`: a query of more than about 49 000 bytes by GET.
pub fn request(
    server: &Template,
    query: &[u8],
    method: Method,
) -> Result<Request<Vec<u8>>, http::Error> {
    let builder = Request::builder().header(ACCEPT, MEDIA_TYPE);
    match method {
        Method::Get => builder
            .uri(format!(
                "https://{}{}{}dns={}",
                server.authority,
                server.path,
                server.joiner(),
                encode_base64url(query),
            ))
            .body(Vec::new()),
        Method::Post => builder
            .method(http::Method::POST)
            .uri(format!("https://{}{}", server.authority, server.path))
            .header(CONTENT_TYPE, MEDIA_TYPE)
            .header(CONTENT_LENGTH, query.len())
            .body(query.to_vec()),
    }
}

/// Why an HTTP response holds no DNS response.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum DohError {
    /// A status other than 2xx: no DNS response in it, whatever its body (RFC 8484 §4.2.1).
    #[error("HTTP status {0}")]
    Status(StatusCode),
    /// A content type other than [`MEDIA_TYPE`], or none (RFC 8484 §4.2).
    #[error("content type {0:?}, not {MEDIA_TYPE}")]
    ContentType(Option<HeaderValue>),
    /// The body is not a DNS message.
    #[error("not a DNS message")]
    Decode(#[from] DecodeError),
    /// The message, its TTLs reduced, cannot be written again.
    #[error("cannot write the message again")]
    Encode(#[from] EncodeError),
}

/// The DNS response in an HTTP `response` with body `body`, as received at `now`.
///
/// Any 2xx status is a DNS response whatever its rcode (RFC 8484 §4.2.1); anything else is an error naming the
/// status. TTLs are reduced by the age of the response, so that a copy a cache kept is not read as fresh: the
/// larger of its `Age` header and the time since its `Date` (RFC 8484 §5.1, RFC 9111 §4.2.3), not below 0. An
/// `Age` that is not a number is ignored (RFC 9111 §5.1). The message is as [`Message::decode`] reads it.
///
/// # Errors
///
/// [`DohError`] for a status that is not 2xx, a content type that is not [`MEDIA_TYPE`], and a body that is not a
/// DNS message.
pub fn response<'b, T>(
    response: &Response<T>,
    body: &'b [u8],
    now: SystemTime,
) -> Result<Decoded<'b>, DohError> {
    let status = response.status();
    if !status.is_success() {
        return Err(DohError::Status(status));
    }
    let headers = response.headers();
    if !is_dns_message(headers) {
        return Err(DohError::ContentType(headers.get(CONTENT_TYPE).cloned()));
    }
    let mut decoded = Message::decode(body)?;
    let age = age(headers, now);
    if age > 0 {
        let message = &mut decoded.message;
        for record in message
            .answer
            .iter_mut()
            .chain(&mut message.authority)
            .chain(&mut message.additional)
            // A stray OPT record keeps EDNS bits where its TTL is.
            .filter(|record| record.rtype() != RecordType::OPT)
        {
            record.ttl = Ttl::from_wire(record.ttl.get().saturating_sub(age));
        }
    }
    Ok(decoded)
}

/// The DNS message in an HTTP `response` with body `body`, as [`response`] reads it, as wire: `body` itself, or,
/// when its TTLs are reduced by the response's age, the message written again.
///
/// # Errors
///
/// As [`response`], and [`DohError::Encode`] for a message that grew past 65535 bytes.
pub fn wire<T>(http: &Response<T>, body: &[u8], now: SystemTime) -> Result<Vec<u8>, DohError> {
    let decoded = response(http, body, now)?;
    if age(http.headers(), now) == 0 {
        return Ok(body.to_vec());
    }
    let mut wire = vec![0; MAX_MESSAGE_LEN];
    let len = decoded.message.encode(&mut wire)?;
    wire.truncate(len);
    Ok(wire)
}

/// Whether `headers` say the body is [`MEDIA_TYPE`], whatever the case and the parameters.
fn is_dns_message(headers: &HeaderMap) -> bool {
    is_media_type(headers, MEDIA_TYPE)
}

/// Whether `headers` say the body is of `media`, whatever the case and the parameters.
pub(crate) fn is_media_type(headers: &HeaderMap, media: &str) -> bool {
    headers
        .get(CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.split(';').next())
        .is_some_and(|found| found.trim().eq_ignore_ascii_case(media))
}

/// The seconds a response was already old when it came: the larger of its `Age` and `now` less its `Date`
/// (RFC 9111 §4.2.3, without the response delay).
pub(crate) fn age(headers: &HeaderMap, now: SystemTime) -> u32 {
    // The first member of a list, and an invalid one ignored (RFC 9111 §5.1); a number beyond 2^31 is that.
    let age = headers
        .get(AGE)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.split(',').next())
        .and_then(digits)
        .unwrap_or(0);
    let apparent = headers
        .get(http::header::DATE)
        .and_then(|value| value.to_str().ok())
        .and_then(http_date)
        .map_or(0, |date| {
            now.duration_since(UNIX_EPOCH)
                .map_or(0, |now| now.as_secs().saturating_sub(date))
        });
    u32::try_from(age.max(apparent)).unwrap_or(u32::MAX)
}

/// A decimal number of ASCII digits and nothing else; saturating.
fn digits(text: &str) -> Option<u64> {
    let text = text.trim();
    (!text.is_empty() && text.bytes().all(|b| b.is_ascii_digit())).then(|| {
        text.bytes().fold(0_u64, |n, b| {
            n.saturating_mul(10).saturating_add(u64::from(b - b'0'))
        })
    })
}

/// Seconds since the Unix epoch of an IMF-fixdate such as `Sun, 06 Nov 1994 08:49:37 GMT` (RFC 9110 §5.6.7); `None`
/// for the obsolete forms, which a recipient need not read, and for what is not a date.
fn http_date(text: &str) -> Option<u64> {
    const MONTHS: [&str; 12] = [
        "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
    ];
    if text.len() != 29
        || text.get(3..5)? != ", "
        || text.get(7..8)? != " "
        || text.get(11..12)? != " "
        || text.get(16..17)? != " "
        || text.get(19..20)? != ":"
        || text.get(22..23)? != ":"
        || text.get(25..)? != " GMT"
    {
        return None;
    }
    let day = digits(text.get(5..7)?)?;
    let month = MONTHS
        .iter()
        .position(|&m| m == text.get(8..11).unwrap_or(""))?;
    let year = digits(text.get(12..16)?)?;
    let (hour, minute, second) = (
        digits(text.get(17..19)?)?,
        digits(text.get(20..22)?)?,
        digits(text.get(23..25)?)?,
    );
    if !(1..=31).contains(&day) || hour > 23 || minute > 59 || second > 60 {
        return None;
    }
    // Days from the civil date, with the year starting in March so that the leap day ends it.
    let month = u64::try_from(month).ok()? + 1;
    let (year, shifted) = if month <= 2 {
        (year.checked_sub(1)?, month + 9)
    } else {
        (year, month - 3)
    };
    let era_day =
        year % 400 * 365 + year % 400 / 4 - year % 400 / 100 + (153 * shifted + 2) / 5 + day - 1;
    let days = (year / 400 * 146_097 + era_day).checked_sub(719_468)?;
    Some(days * 86_400 + hour * 3600 + minute * 60 + second)
}

/// The DNS query in an HTTP `request` with body `body`, for a `DoH` server (RFC 8484 §4.1).
///
/// A GET carries it as the `dns` parameter of the URI, a POST as the body, which must be [`MEDIA_TYPE`]. Whether the
/// query is a DNS message is the caller's to find, and to answer FORMERR (RFC 8484 §4.2.1).
///
/// # Errors
///
/// The status to answer with, no DNS response: 405 for a method other than GET and POST, 415 for a POST of another
/// content type, 400 for a GET without a valid `dns` parameter or a request with an empty query, 413 for a POST of
/// more than 65535 bytes. A GET is never above it: `http` keeps a URI under 65535 bytes, 49150 of a query.
pub fn server_request<T>(request: &Request<T>, body: &[u8]) -> Result<Vec<u8>, StatusCode> {
    let query = match *request.method() {
        http::Method::GET => {
            let text = request
                .uri()
                .query()
                .and_then(|query| query.split('&').find_map(|pair| pair.strip_prefix("dns=")))
                .ok_or(StatusCode::BAD_REQUEST)?;
            decode_base64url(text.as_bytes()).ok_or(StatusCode::BAD_REQUEST)?
        }
        http::Method::POST => {
            if !is_dns_message(request.headers()) {
                return Err(StatusCode::UNSUPPORTED_MEDIA_TYPE);
            }
            if body.len() > MAX_MESSAGE_LEN {
                return Err(StatusCode::PAYLOAD_TOO_LARGE);
            }
            body.to_vec()
        }
        _ => return Err(StatusCode::METHOD_NOT_ALLOWED),
    };
    if query.is_empty() {
        return Err(StatusCode::BAD_REQUEST);
    }
    Ok(query)
}

/// The HTTP response of a server to a `method` request, carrying `dns_response`, a DNS message in wire format.
///
/// The status is 200 whatever the rcode (RFC 8484 §4.2.1). The answer to a GET may be cached: `cache-control:
/// max-age` is the least TTL of the answer and of the SOA of the authority section, least of its TTL and its
/// MINIMUM (RFC 8484 §5.1, RFC 2308 §5); 0 for a message with neither, such as an error.
/// That of a POST has no `cache-control`: caches do not keep it (RFC 8484 §5.1).
///
/// # Errors
///
/// [`DecodeError`] when `dns_response` is not a DNS message.
pub fn server_response(
    dns_response: Vec<u8>,
    method: &http::Method,
) -> Result<Response<Vec<u8>>, DecodeError> {
    let max_age = (method == http::Method::GET)
        .then(|| Message::decode(&dns_response).map(|decoded| lifetime(&decoded.message)))
        .transpose()?;
    let mut response = Response::new(dns_response);
    let headers = response.headers_mut();
    headers.insert(CONTENT_TYPE, HeaderValue::from_static(MEDIA_TYPE));
    if let Some(max_age) = max_age {
        headers.insert(
            CACHE_CONTROL,
            // Digits make a valid value; a cache that cannot read it keeps nothing.
            HeaderValue::try_from(format!("max-age={max_age}"))
                .unwrap_or_else(|_| HeaderValue::from_static("max-age=0")),
        );
    }
    Ok(response)
}

/// How long `message` may be cached by HTTP caches, in seconds: see [`server_response`].
fn lifetime(message: &Message<'_>) -> u32 {
    let soa = message
        .authority
        .iter()
        .filter_map(|record| match record.data() {
            RData::Soa(soa) => Some(record.ttl.get().min(soa.minimum)),
            _ => None,
        });
    message
        .answer
        .iter()
        .map(|record| record.ttl.get())
        .chain(soa)
        .min()
        .unwrap_or(0)
}
