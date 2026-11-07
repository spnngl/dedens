//! Oblivious DNS over HTTPS (RFC 9230) over HTTP/3, experimental (D79): the HTTP of a client and of a target, and the
//! client's exchange. The encryption is [`dedens_odoh`]'s (D78).
//!
//! A client sends the encrypted query by POST to a proxy, which forwards it to the target named in the URI's
//! `targethost` and `targetpath` variables (§4.1); without a proxy, to the target itself, which tests and
//! trusting setups use. Both answer 200 with an encrypted response, or a status: 401 for a key the target does not
//! hold (§4.3).
//!
//! The target's key configurations come from `/.well-known/odohconfigs` (§5 leaves discovery out of scope; the path
//! is the convention public targets follow), or from the caller ([`Client::pin_odoh_configs`]). The client asks the
//! target for them directly, never through the proxy: a proxy forwards the POSTs of §4.1 and nothing else. The
//! target sees the client's address then, and no query; to keep that address from being linked to the query that
//! follows, the configurations are kept for an hour at least, whatever the target says: they are public (D79).
//!
//! A proxy's URI is a plain URI: the RFC 9230 §4.1 URI templates (`{?targethost,targetpath}`) are not supported.
//! The proxy role, the other side of that URI, is [`proxy`] (D94).

pub mod proxy;

use core::convert::Infallible;
use std::cell::RefCell;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::time::{Duration, Instant, SystemTime};

use dedens_odoh::rand_core::{TryCryptoRng, TryRng};
use dedens_odoh::{
    ExchangeError, MEDIA_TYPE, MessageType, ObliviousDoHConfigs, ObliviousDoHMessage, WireError,
    decrypt_response, encrypt_query, query_padding,
};
use dedens_proto::MAX_MESSAGE_LEN;
use http::header::{ACCEPT, CACHE_CONTROL, CONTENT_LENGTH, CONTENT_TYPE, HeaderName};
use http::uri::Authority;
use http::{HeaderMap, HeaderValue, Request, Response, StatusCode, Version};
use zeroize::Zeroizing;

#[cfg(doc)]
use crate::client::Client;
use crate::client::{Server, local_io};
use crate::doh::{self, Template, TemplateError};
use crate::exchange::Http;
use crate::https::{HttpsError, HttpsPool, Reply};
use crate::quic::QuicError;

/// Where a target serves its key configurations: the well-known URI of public targets, which no RFC defines.
pub const CONFIGS_PATH: &str = "/.well-known/odohconfigs";

/// The longest HTTP body of a query or response: a DNS message, and what the encryption adds to it: the message
/// header, the key identifier, the encapsulated key or nonce, the tag and the padding, well under 1024 bytes (RFC
/// 9230 §6.1, §6.2, RFC 9180 §4).
pub const MAX_BODY: usize = MAX_MESSAGE_LEN + 1024;

/// The least time configurations are kept, whatever their `Cache-Control` says (D79).
const MIN_KEPT: Duration = Duration::from_hours(1);

/// The most time configurations are kept: a key a target changes without a 401 for the old one is not used longer.
const MAX_KEPT: Duration = Duration::from_hours(24);

/// The targets whose configurations are kept at most.
const MAX_TARGETS: usize = 64;

/// The header a proxy adds to the errors it makes (RFC 9209 §2).
const PROXY_STATUS: HeaderName = HeaderName::from_static("proxy-status");

/// Why an Oblivious `DoH` exchange got no DNS response.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum OdohError {
    /// The HTTP/3 connection or request failed.
    #[error("HTTPS")]
    Https(#[from] HttpsError),
    /// The proxy's or the target's name and port make no template.
    #[error("no template for the server")]
    Template(#[from] TemplateError),
    /// The request cannot be made: a URI `http` refuses.
    #[error("cannot make the request")]
    Request(#[source] http::Error),
    /// No randomness for the ephemeral key.
    #[error("no randomness: {0}")]
    Random(getrandom::Error),
    /// The proxy's URI sets `targethost` or `targetpath` itself: a URI template, which is not supported.
    #[error("the proxy's URI holds targethost or targetpath: URI templates are not supported")]
    ProxyVariables,
    /// The target does not give its configurations: its status.
    #[error("configurations: HTTP status {0}")]
    Configs(StatusCode),
    /// An error status the proxy made, as its `Proxy-Status` says: not the target's (RFC 9230 §4.3, §11.3).
    #[error("the proxy answered HTTP status {0}")]
    Proxy(StatusCode),
    /// The configurations or the message are not what RFC 9230 §5 and §6.1 encode.
    #[error("malformed message or configuration")]
    Wire(#[from] WireError),
    /// The query cannot be encrypted or the response decrypted.
    #[error("encryption")]
    Exchange(#[from] ExchangeError),
    /// A status other than 2xx: no response in it, whatever its body (RFC 9230 §4.3).
    #[error("HTTP status {0}")]
    Status(StatusCode),
    /// A content type other than [`MEDIA_TYPE`], or none (RFC 9230 §4.3).
    #[error("content type {0:?}, not {MEDIA_TYPE}")]
    ContentType(Option<HeaderValue>),
}

impl OdohError {
    /// Whether the failure is ours, not the server's or the network's, as [`crate::client::ClientError::is_local`] says.
    pub(crate) fn is_local(&self) -> bool {
        match self {
            Self::Random(_)
            | Self::Template(_)
            | Self::ProxyVariables
            | Self::Request(_)
            | Self::Https(
                HttpsError::Quic(QuicError::Trust(_) | QuicError::Connect(_))
                | HttpsError::Request(_),
            ) => true,
            Self::Https(HttpsError::Quic(QuicError::Bind(error))) => local_io(error),
            _ => false,
        }
    }

    /// Whether the configurations the query was encrypted under may be out of date: the target's 401 for a key it
    /// does not hold (RFC 9230 §4.3). A 401 the proxy made is [`OdohError::Proxy`], and a response that does not
    /// decrypt says nothing of the key: a proxy can send any.
    fn stale_configs(&self) -> bool {
        matches!(self, Self::Status(StatusCode::UNAUTHORIZED))
    }
}

/// The bytes the ephemeral key of a query and the nonce of a response draw: 32 and 16 (RFC 9180 §7.1.3, RFC 9230
/// §6.2), with room to spare.
const ENTROPY: usize = 64;

/// Random bytes for [`dedens_odoh::encrypt_query`] and [`dedens_odoh::encrypt_response`], drawn from the system when
/// made, so that a failing generator is an error where the exchange starts and not a panic where the encryption
/// draws. One per encryption: a second would reuse the bytes.
///
/// A draw past the bytes, which no encryption makes, gets zeros and is no panic: [`Entropy::finish`] says so, and
/// what was encrypted is then dropped.
pub struct Entropy {
    bytes: Zeroizing<[u8; ENTROPY]>,
    used: usize,
    /// A draw found too few bytes left.
    exhausted: bool,
}

impl Entropy {
    /// Draws the bytes.
    ///
    /// # Errors
    ///
    /// [`getrandom::Error`] when the system has none.
    pub fn new() -> Result<Self, getrandom::Error> {
        let mut bytes = Zeroizing::new([0; ENTROPY]);
        getrandom::fill(bytes.as_mut_slice())?;
        Ok(Self {
            bytes,
            used: 0,
            exhausted: false,
        })
    }

    /// Whether every draw got random bytes: to be asked once the encryption is done, before its output is used.
    ///
    /// # Errors
    ///
    /// [`getrandom::Error::UNEXPECTED`] when a draw found too few bytes left.
    pub fn finish(self) -> Result<(), getrandom::Error> {
        if self.exhausted {
            Err(getrandom::Error::UNEXPECTED)
        } else {
            Ok(())
        }
    }

    /// Fills `dst` with the next bytes, or with zeros when there are too few.
    fn fill(&mut self, dst: &mut [u8]) {
        let taken = self
            .used
            .checked_add(dst.len())
            .and_then(|end| Some((self.bytes.get(self.used..end)?, end)));
        if let Some((bytes, end)) = taken {
            dst.copy_from_slice(bytes);
            self.used = end;
        } else {
            dst.fill(0);
            self.exhausted = true;
        }
    }
}

impl TryRng for Entropy {
    type Error = Infallible;

    fn try_next_u32(&mut self) -> Result<u32, Infallible> {
        let mut bytes = [0; 4];
        self.fill(&mut bytes);
        Ok(u32::from_le_bytes(bytes))
    }

    fn try_next_u64(&mut self) -> Result<u64, Infallible> {
        let mut bytes = [0; 8];
        self.fill(&mut bytes);
        Ok(u64::from_le_bytes(bytes))
    }

    fn try_fill_bytes(&mut self, dst: &mut [u8]) -> Result<(), Infallible> {
        self.fill(dst);
        Ok(())
    }
}

impl TryCryptoRng for Entropy {}

/// The characters of a query value left as they are: the unreserved ones (RFC 3986 §2.3) and `/`, which the query
/// component allows (RFC 3986 §3.4) and the RFC's example leaves in `targetpath` (RFC 9230 §4.2).
const fn is_literal(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~' | b'/')
}

/// `text` as a query value: all but the characters of [`is_literal`] percent-encoded, so that `&`, `=`, `#`, `+` and
/// `%` in it keep their meaning to the proxy, which decodes it (RFC 9230 §4.1).
fn encode_component(text: &str) -> String {
    const HEX: &[u8; 16] = b"0123456789ABCDEF";
    let mut encoded = String::with_capacity(text.len());
    for byte in text.bytes() {
        if is_literal(byte) {
            encoded.push(char::from(byte));
        } else {
            encoded.push('%');
            encoded.push(char::from(HEX[usize::from(byte >> 4)]));
            encoded.push(char::from(HEX[usize::from(byte & 0xf)]));
        }
    }
    encoded
}

/// The HTTP request carrying the encrypted query `message` to `target` (RFC 9230 §4.1): a POST of the oblivious
/// media type, with no cookie or other state of the client's (§4.5).
///
/// Through a `proxy`, to its template expanded with the target's `targethost` (its authority) and `targetpath`
/// (its path), encoded as above; without one, to the target's template.
///
/// # Errors
///
/// [`http::Error`] for a URI `http` refuses.
pub fn request(
    proxy: Option<&Template>,
    target: &Template,
    message: &ObliviousDoHMessage,
) -> Result<Request<Vec<u8>>, http::Error> {
    let uri = match proxy {
        Some(proxy) => format!(
            "https://{}{}{}targethost={}&targetpath={}",
            proxy.authority(),
            proxy.path(),
            if proxy.path().contains('?') { '&' } else { '?' },
            encode_component(target.authority().as_str()),
            encode_component(target.path()),
        ),
        None => format!("https://{}{}", target.authority(), target.path()),
    };
    let body = message.encode();
    // Cloudflare's target answers 400 to a POST over HTTP/3 without the length of its body (November 2026).
    Request::builder()
        .method(http::Method::POST)
        .uri(uri)
        .header(ACCEPT, MEDIA_TYPE)
        .header(CONTENT_TYPE, MEDIA_TYPE)
        .header(CONTENT_LENGTH, body.len())
        .body(body)
}

/// The HTTP request for the key configurations of `target`: a GET of [`CONFIGS_PATH`] on its authority.
///
/// # Errors
///
/// [`http::Error`] for a URI `http` refuses.
pub fn configs_request(target: &Template) -> Result<Request<Vec<u8>>, http::Error> {
    Request::builder()
        .uri(format!("https://{}{CONFIGS_PATH}", target.authority()))
        .body(Vec::new())
}

/// The encrypted response in an HTTP `response` with body `body` (RFC 9230 §4.3).
///
/// # Errors
///
/// [`OdohError::Status`] for a status that is not 2xx, [`OdohError::ContentType`] for a type other than
/// [`MEDIA_TYPE`], [`OdohError::Wire`] for a body that is no message.
pub fn response<T>(response: &Response<T>, body: &[u8]) -> Result<ObliviousDoHMessage, OdohError> {
    if !response.status().is_success() {
        return Err(OdohError::Status(response.status()));
    }
    let headers = response.headers();
    if !doh::is_media_type(headers, MEDIA_TYPE) {
        return Err(OdohError::ContentType(headers.get(CONTENT_TYPE).cloned()));
    }
    Ok(ObliviousDoHMessage::parse(body)?)
}

/// How long a client keeps the configurations of a response (D79).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Lifetime {
    /// The time to keep them: the `max-age` of the response's `Cache-Control` less its age, or none when it has
    /// none, but at least an hour and at most a day. The configurations are public, and a fetch the target can link
    /// to the query that follows is rare this way.
    pub keep: Duration,
    /// The response says not to keep them: `no-store`, or `no-cache` with no field name (RFC 9111 §5.2.2).
    pub forbidden: bool,
}

/// How long the configurations in a response with `headers` are kept, as of `now` (RFC 9111 §4.2.1, §5.2.2).
/// `Cache-Control` is read as bytes: a quoted argument may hold obs-text (§5.2), which hides no other directive.
///
/// The age is the larger of `Age` and `now` less `Date`, so a clock behind the target's makes it large and the
/// lifetime short: the hour [`Lifetime::keep`] never goes under.
#[must_use]
pub fn configs_lifetime(headers: &HeaderMap, now: SystemTime) -> Lifetime {
    let mut max_age = None;
    let mut forbidden = false;
    for directive in headers
        .get_all(CACHE_CONTROL)
        .iter()
        .flat_map(|value| value.as_bytes().split(|&byte| byte == b','))
    {
        let mut parts = directive.splitn(2, |&byte| byte == b'=');
        let name = parts
            .next()
            .unwrap_or_default()
            .trim_ascii()
            .to_ascii_lowercase();
        match (name.as_slice(), parts.next()) {
            (b"no-store", _) | (b"no-cache", None) => forbidden = true,
            (b"max-age", Some(argument)) if max_age.is_none() => {
                max_age = Some(
                    str::from_utf8(argument.trim_ascii())
                        .ok()
                        .and_then(|argument| argument.trim_matches('"').parse::<u64>().ok())
                        .unwrap_or(0),
                );
            }
            _ => {}
        }
    }
    let fresh = if forbidden {
        0
    } else {
        let age = u64::from(doh::age(headers, now));
        max_age.unwrap_or(0).saturating_sub(age)
    };
    Lifetime {
        keep: Duration::from_secs(fresh).clamp(MIN_KEPT, MAX_KEPT),
        forbidden,
    }
}

/// What a target is asked for (D79).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    /// A `DoH` query, or a request that is none: [`Exchange::query`](crate::https::Exchange::query) says which.
    Dns,
    /// A POST of an encrypted query, its body the message.
    Oblivious,
    /// A GET of the configurations, its query empty.
    Configs,
}

/// The kind and the query of a request to a target serving `DoH` and Oblivious `DoH` at `path`, for
/// [`Pending::read_with`](crate::https::Pending::read_with) (RFC 9230 §4.1, RFC 8484 §4.1).
///
/// A POST of the oblivious media type at `path` is [`Kind::Oblivious`], its body the query; any other request at
/// `path` is `DoH`'s, as [`doh::server_request`] reads it. A GET of [`CONFIGS_PATH`], unless that is `path`, is
/// [`Kind::Configs`]. The status is 404 for another path, 405 for a configs request that is no GET, 400 for an empty
/// message and 413 for one longer than [`MAX_BODY`].
pub fn classify<T>(
    request: &Request<T>,
    body: &[u8],
    path: &str,
) -> (Kind, Result<Vec<u8>, StatusCode>) {
    let at = request.uri().path();
    if at != path && at == CONFIGS_PATH {
        let query = if request.method() == http::Method::GET {
            Ok(Vec::new())
        } else {
            Err(StatusCode::METHOD_NOT_ALLOWED)
        };
        return (Kind::Configs, query);
    }
    if at != path {
        return (Kind::Dns, Err(StatusCode::NOT_FOUND));
    }
    if request.method() == http::Method::POST && doh::is_media_type(request.headers(), MEDIA_TYPE) {
        return (Kind::Oblivious, check_message(body).map(|()| body.to_vec()));
    }
    (Kind::Dns, doh::server_request(request, body))
}

/// Whether `body` can be an encrypted message to open or forward: 400 when empty, 413 when longer than [`MAX_BODY`].
fn check_message(body: &[u8]) -> Result<(), StatusCode> {
    if body.is_empty() {
        Err(StatusCode::BAD_REQUEST)
    } else if body.len() > MAX_BODY {
        Err(StatusCode::PAYLOAD_TOO_LARGE)
    } else {
        Ok(())
    }
}

/// The 200 response carrying the encrypted `message`: of the oblivious media type, and not to be cached, by the proxy
/// or anyone (RFC 9230 §4.1, §4.3).
#[must_use]
pub fn target_response(message: &ObliviousDoHMessage) -> Response<Vec<u8>> {
    let mut response = Response::new(message.encode());
    let headers = response.headers_mut();
    headers.insert(CONTENT_TYPE, HeaderValue::from_static(MEDIA_TYPE));
    headers.insert(
        CACHE_CONTROL,
        HeaderValue::from_static("no-cache, no-store"),
    );
    response
}

/// The 200 response carrying the encoded configurations `configs`, which clients may keep `max_age` seconds.
#[must_use]
pub fn configs_response(configs: Vec<u8>, max_age: u32) -> Response<Vec<u8>> {
    let mut response = Response::new(configs);
    let headers = response.headers_mut();
    headers.insert(
        CONTENT_TYPE,
        HeaderValue::from_static("application/octet-stream"),
    );
    headers.insert(
        CACHE_CONTROL,
        // Digits make a valid value.
        HeaderValue::try_from(format!("max-age={max_age}"))
            .unwrap_or_else(|_| HeaderValue::from_static("no-store")),
    );
    response
}

/// Whether the URI template of `proxy` sets `targethost` or `targetpath` itself in its query: RFC 9230 §4.1 URI
/// templates, which are not supported, as the module says.
#[must_use]
pub fn names_target(proxy: &Template) -> bool {
    proxy.path().split_once('?').is_some_and(|(_, query)| {
        query.split('&').any(|pair| {
            let name = pair.split_once('=').map_or(pair, |(name, _)| name);
            matches!(name, "targethost" | "targetpath")
        })
    })
}

/// Whether `headers` hold a `Proxy-Status` that names an error: the proxy made the response, the target did not
/// (RFC 9209 §2, §2.1.1, RFC 9230 §4.3).
#[must_use]
pub fn proxy_error(headers: &HeaderMap) -> bool {
    headers
        .get_all(PROXY_STATUS)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .flat_map(|value| value.split(','))
        .flat_map(|member| member.split(';').skip(1))
        .any(|parameter| {
            let name = parameter
                .split_once('=')
                .map_or(parameter, |(name, _)| name);
            name.trim().eq_ignore_ascii_case("error")
        })
}

/// What a client tells its user about the configurations of a target (D79).
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum Notice {
    /// The target asked for its configurations not to be kept, and the client asked for them from its own address
    /// while it sends its queries through a proxy: the target can link that address to a query that follows. They
    /// are kept anyway, for an hour at least; [`Client::pin_odoh_configs`] keeps the address out of it.
    ConfigsNotToBeKept(Authority),
}

/// A target's configurations and when they stop being fresh.
#[derive(Debug)]
struct Known {
    configs: ObliviousDoHConfigs,
    until: Instant,
}

/// The identity of a target: its address and authority.
type Key = (SocketAddr, Authority);

/// The configurations of the targets a client asked, kept as [`Lifetime::keep`] says, and those it was given.
#[derive(Debug, Default)]
pub(crate) struct Configs {
    /// Fetched, at most [`MAX_TARGETS`].
    known: RefCell<HashMap<Key, Known>>,
    /// Given by the caller, never fetched again nor dropped: a 401 for them is an error.
    pinned: RefCell<HashMap<Key, ObliviousDoHConfigs>>,
    /// Not yet taken by [`Configs::take_notices`].
    notices: RefCell<Vec<Notice>>,
}

impl Configs {
    /// Asks `target`, through `proxy` when there is one, for the answer to `wire`, a DNS query with ID 0 and no
    /// padding of its own (D79).
    ///
    /// The configurations are the pinned ones, the kept ones, else fetched from the target. A 401 the target made
    /// under kept ones may mean it changed its key: they are fetched again, once (RFC 9230 §4.3). A response that
    /// does not decrypt, or an error of the proxy's, is no reason to.
    ///
    /// # Errors
    ///
    /// [`OdohError`]: no template, a proxy URI that sets the target, no randomness, a failed request,
    /// configurations that are none, a response that is not one, or no response before `deadline`.
    pub(crate) async fn exchange(
        &self,
        https: &HttpsPool,
        target: &Server,
        proxy: Option<&Server>,
        wire: &[u8],
        deadline: Instant,
    ) -> Result<Reply, OdohError> {
        let target_template = target.template()?;
        let proxy_template = proxy.map(Server::template).transpose()?;
        if proxy_template.as_ref().is_some_and(names_target) {
            return Err(OdohError::ProxyVariables);
        }
        let key = (target.addr, target_template.authority().clone());
        let pinned = self.pinned.borrow().get(&key).cloned();
        let mut cached = pinned.clone().or_else(|| self.fresh(&key));
        loop {
            let from_cache = cached.is_some() && pinned.is_none();
            let configs = match cached.take() {
                Some(configs) => configs,
                None => {
                    self.fetch(
                        https,
                        (target, &target_template),
                        proxy.is_some(),
                        &key,
                        deadline,
                    )
                    .await?
                }
            };
            let asked = ask(
                https,
                (target, &target_template),
                (proxy, proxy_template.as_ref()),
                &configs,
                wire,
                deadline,
            )
            .await;
            match asked {
                Err(error) if from_cache && error.stale_configs() => {
                    debug!(error = %error, "configurations out of date: fetching them again");
                    self.known.borrow_mut().remove(&key);
                }
                asked => return asked,
            }
        }
    }

    /// Keeps `bytes`, encoded configurations, for `target` for good: they are not fetched, nor dropped.
    ///
    /// # Errors
    ///
    /// [`OdohError::Template`] for a target with no template, [`OdohError::Wire`] for bytes that are no
    /// configurations.
    pub(crate) fn pin(&self, target: &Server, bytes: &[u8]) -> Result<(), OdohError> {
        let key = (target.addr, target.template()?.authority().clone());
        let configs = ObliviousDoHConfigs::parse(bytes)?;
        self.pinned.borrow_mut().insert(key, configs);
        Ok(())
    }

    /// Keeps `bytes`, encoded configurations, for `target` as if it had served them: for [`MIN_KEPT`], and fetched
    /// again after a 401 or when they expire, which pinned ones never are.
    ///
    /// # Errors
    ///
    /// [`OdohError::Template`] for a target with no template, [`OdohError::Wire`] for bytes that are no
    /// configurations.
    pub(crate) fn keep_given(&self, target: &Server, bytes: &[u8]) -> Result<(), OdohError> {
        let key = (target.addr, target.template()?.authority().clone());
        self.keep(&key, &ObliviousDoHConfigs::parse(bytes)?, MIN_KEPT);
        Ok(())
    }

    /// The notices since the last call.
    pub(crate) fn take_notices(&self) -> Vec<Notice> {
        std::mem::take(&mut *self.notices.borrow_mut())
    }

    /// The configurations of `key` while they are fresh.
    fn fresh(&self, key: &Key) -> Option<ObliviousDoHConfigs> {
        self.known
            .borrow()
            .get(key)
            .filter(|known| known.until > Instant::now())
            .map(|known| known.configs.clone())
    }

    /// Fetches the configurations from `target` directly, and keeps them as [`Lifetime::keep`] says. `proxied` tells
    /// that the queries go through a proxy: the fetch gives the target the address of the client, and a target that
    /// asks for no keeping then makes a [`Notice`].
    async fn fetch(
        &self,
        https: &HttpsPool,
        (target, template): (&Server, &Template),
        proxied: bool,
        key: &Key,
        deadline: Instant,
    ) -> Result<ObliviousDoHConfigs, OdohError> {
        let request = configs_request(template).map_err(OdohError::Request)?;
        let (head, body) = https
            .send(
                target.addr,
                target.certified(),
                &request,
                MAX_BODY,
                deadline,
            )
            .await?;
        if !head.status().is_success() {
            return Err(OdohError::Configs(head.status()));
        }
        let configs = ObliviousDoHConfigs::parse(&body)?;
        let lifetime = configs_lifetime(head.headers(), SystemTime::now());
        if proxied && lifetime.forbidden {
            let notice = Notice::ConfigsNotToBeKept(key.1.clone());
            let mut notices = self.notices.borrow_mut();
            if !notices.contains(&notice) {
                notices.push(notice);
            }
        }
        self.keep(key, &configs, lifetime.keep);
        Ok(configs)
    }

    /// Keeps `configs` for `key` for `keep`, dropping what is stale, and the soonest to be stale when there are
    /// [`MAX_TARGETS`].
    fn keep(&self, key: &Key, configs: &ObliviousDoHConfigs, keep: Duration) {
        let now = Instant::now();
        let mut known = self.known.borrow_mut();
        known.retain(|_, known| known.until > now);
        if known.len() >= MAX_TARGETS
            && !known.contains_key(key)
            && let Some(soonest) = known
                .iter()
                .min_by_key(|(_, known)| known.until)
                .map(|(key, _)| key.clone())
        {
            known.remove(&soonest);
        }
        known.insert(
            key.clone(),
            Known {
                configs: configs.clone(),
                until: crate::exchange::after(now, keep),
            },
        );
    }
}

/// Encrypts `wire` under the most preferred of `configs`, sends it to `proxy` or, without one, to `target`, and
/// decrypts the response.
async fn ask(
    https: &HttpsPool,
    (target, target_template): (&Server, &Template),
    (proxy, proxy_template): (Option<&Server>, Option<&Template>),
    configs: &ObliviousDoHConfigs,
    wire: &[u8],
    deadline: Instant,
) -> Result<Reply, OdohError> {
    let config = configs.configs().first().ok_or(WireError::NoUsableConfig)?;
    let mut entropy = Entropy::new().map_err(OdohError::Random)?;
    let (message, context) = encrypt_query(config, wire, query_padding(wire.len()), &mut entropy)?;
    entropy.finish().map_err(OdohError::Random)?;
    let request = request(proxy_template, target_template, &message).map_err(OdohError::Request)?;
    let server = proxy.unwrap_or(target);
    let (head, body) = https
        .send(
            server.addr,
            server.certified(),
            &request,
            MAX_BODY,
            deadline,
        )
        .await?;
    if proxy.is_some() && !head.status().is_success() && proxy_error(head.headers()) {
        return Err(OdohError::Proxy(head.status()));
    }
    let message = response(&head, &body)?;
    debug_assert_eq!(message.message_type(), MessageType::Response);
    let plaintext = decrypt_response(&context, &message)?;
    Ok(Reply {
        wire: plaintext.into_dns_message(),
        http: Http {
            version: Version::HTTP_3,
            status: head.status(),
        },
    })
}

#[cfg(test)]
mod tests {
    use dedens_odoh::{TargetKey, decrypt_query, encrypt_response, response_padding};

    use super::*;

    /// The kept configurations are at most [`MAX_TARGETS`], however many targets are asked.
    #[test]
    fn the_kept_configurations_are_bounded() {
        let configs = Configs::default();
        let parsed = ObliviousDoHConfigs::new(vec![TargetKey::derive(&[7; 32]).config().clone()]);
        for port in 0..u16::try_from(MAX_TARGETS * 2).expect("a small number") {
            let key = (
                SocketAddr::from(([127, 0, 0, 1], 1000 + port)),
                Authority::from_static("a.example"),
            );
            configs.keep(&key, &parsed, MIN_KEPT);
        }
        assert_eq!(configs.known.borrow().len(), MAX_TARGETS);
    }

    /// Both encryptions stay within the bytes drawn: the bound `Entropy::fill` relies on.
    #[test]
    fn encryptions_draw_within_the_entropy() {
        let key = TargetKey::derive(&[7; 32]);
        let mut entropy = Entropy::new().expect("randomness");
        let (query, _) = encrypt_query(key.config(), b"query", 0, &mut entropy).expect("a query");
        assert!(entropy.used <= ENTROPY);
        let (_, context) = decrypt_query(&key, &query).expect("the query");
        let mut entropy = Entropy::new().expect("randomness");
        encrypt_response(context, b"response", response_padding(8), &mut entropy)
            .expect("a response");
        assert!(entropy.used <= ENTROPY);
    }
}
