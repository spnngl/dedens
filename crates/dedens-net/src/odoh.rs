//! Oblivious DNS over HTTPS (RFC 9230) over HTTP/3, experimental (D79): the HTTP of a client and of a target, and the
//! client's exchange. The encryption is [`dedens_odoh`]'s (D78).
//!
//! A client sends the encrypted query by POST to a proxy, which forwards it to the target named in the URI's
//! `targethost` and `targetpath` variables (§4.1); without a proxy, to the target itself, which tests and
//! trusting setups use. Both answer 200 with an encrypted response, or a status: 401 for a key the target does not
//! hold (§4.3).
//!
//! The target's key configurations come from `/.well-known/odohconfigs` (§5 leaves discovery out of scope; the path
//! is the convention public targets follow). The client asks the target for them directly, never through the proxy:
//! a proxy forwards the POSTs of §4.1 and nothing else. The target sees the client's address then, once per
//! lifetime of the configurations, but no query (D79).

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
use dedens_proto::wire::MAX_MESSAGE_LEN;
use http::header::{ACCEPT, CACHE_CONTROL, CONTENT_LENGTH, CONTENT_TYPE};
use http::uri::Authority;
use http::{HeaderMap, HeaderValue, Request, Response, StatusCode, Version};
use zeroize::Zeroizing;

use crate::client::{Server, local_io};
use crate::doh::{self, Template, TemplateError};
use crate::exchange::Http;
use crate::https::{HttpsError, HttpsPool, Reply};
use crate::quic::QuicError;

/// Where a target serves its key configurations: the well-known URI of public targets, which no RFC defines.
pub const CONFIGS_PATH: &str = "/.well-known/odohconfigs";

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
    /// The target does not give its configurations: its status.
    #[error("configurations: HTTP status {0}")]
    Configs(StatusCode),
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
    /// does not hold, or a response that does not decrypt (RFC 9230 §4.3).
    fn stale_configs(&self) -> bool {
        matches!(
            self,
            Self::Status(StatusCode::UNAUTHORIZED) | Self::Exchange(_)
        )
    }
}

/// The bytes the ephemeral key of a query and the nonce of a response draw: 32 and 16 (RFC 9180 §7.1.3, RFC 9230
/// §6.2), with room to spare.
const ENTROPY: usize = 64;

/// Random bytes for [`dedens_odoh::encrypt_query`] and [`dedens_odoh::encrypt_response`], drawn from the system when
/// made, so that a failing generator is an error where the exchange starts and not a panic where the encryption
/// draws. One per encryption: a second would reuse the bytes, and a third find none.
pub struct Entropy {
    bytes: Zeroizing<[u8; ENTROPY]>,
    used: usize,
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
        Ok(Self { bytes, used: 0 })
    }

    /// The next `len` bytes.
    fn take(&mut self, len: usize) -> &[u8] {
        let end = self.used + len;
        // Both encryptions draw less than `ENTROPY` bytes; a test holds them to it.
        let taken = self
            .bytes
            .get(self.used..end)
            .expect("an encryption draws less than ENTROPY bytes");
        self.used = end;
        taken
    }
}

impl TryRng for Entropy {
    type Error = Infallible;

    fn try_next_u32(&mut self) -> Result<u32, Infallible> {
        let mut bytes = [0; 4];
        bytes.copy_from_slice(self.take(4));
        Ok(u32::from_le_bytes(bytes))
    }

    fn try_next_u64(&mut self) -> Result<u64, Infallible> {
        let mut bytes = [0; 8];
        bytes.copy_from_slice(self.take(8));
        Ok(u64::from_le_bytes(bytes))
    }

    fn try_fill_bytes(&mut self, dst: &mut [u8]) -> Result<(), Infallible> {
        dst.copy_from_slice(self.take(dst.len()));
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

/// How long the configurations in a response with `headers` may be kept, as of `now`: the `max-age` of its
/// `Cache-Control` less the response's age, none for `no-store`, `no-cache`, no `max-age` or one that is not a
/// number (RFC 9111 §4.2.1, §5.2.2).
#[must_use]
pub fn configs_lifetime(headers: &HeaderMap, now: SystemTime) -> Duration {
    let mut max_age = None;
    for directive in headers
        .get_all(CACHE_CONTROL)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .flat_map(|value| value.split(','))
    {
        let (name, argument) = directive.split_once('=').unwrap_or((directive, ""));
        match name.trim().to_ascii_lowercase().as_str() {
            "no-store" | "no-cache" => return Duration::ZERO,
            "max-age" if max_age.is_none() => {
                let Ok(seconds) = argument.trim().trim_matches('"').parse::<u64>() else {
                    return Duration::ZERO;
                };
                max_age = Some(seconds);
            }
            _ => {}
        }
    }
    let age = u64::from(doh::age(headers, now));
    Duration::from_secs(max_age.unwrap_or(0).saturating_sub(age))
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
/// A POST of the oblivious media type at `path` is [`Kind::Oblivious`], its body the query; a GET of
/// [`CONFIGS_PATH`] is [`Kind::Configs`]. Any other request at `path` is `DoH`'s, as
/// [`doh::server_request`] reads it; the status is 404 for another path, 405 for a configs request that is no GET,
/// 400 for an empty message and 413 for one longer than a DNS message.
pub fn classify<T>(
    request: &Request<T>,
    body: &[u8],
    path: &str,
) -> (Kind, Result<Vec<u8>, StatusCode>) {
    let at = request.uri().path();
    if at == CONFIGS_PATH {
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
        let query = if body.is_empty() {
            Err(StatusCode::BAD_REQUEST)
        } else if body.len() > MAX_MESSAGE_LEN {
            Err(StatusCode::PAYLOAD_TOO_LARGE)
        } else {
            Ok(body.to_vec())
        };
        return (Kind::Oblivious, query);
    }
    (Kind::Dns, doh::server_request(request, body))
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

/// A target's configurations and when they stop being fresh.
#[derive(Debug)]
struct Known {
    configs: ObliviousDoHConfigs,
    until: Instant,
}

/// The configurations of the targets a client asked, kept for their HTTP lifetime.
#[derive(Debug, Default)]
pub(crate) struct Configs {
    /// By the target's address and authority.
    known: RefCell<HashMap<(SocketAddr, Authority), Known>>,
}

impl Configs {
    /// Asks `target`, through `proxy` when there is one, for the answer to `wire`, a DNS query with ID 0 and no
    /// padding of its own (D79).
    ///
    /// The configurations are the cached ones, else fetched from the target. A 401, or a response that does not
    /// decrypt, under cached ones may mean the target changed its key: they are fetched again, once (RFC 9230 §4.3).
    ///
    /// # Errors
    ///
    /// [`OdohError`]: no template, no randomness, a failed request, configurations that are none, a response that
    /// is not one, or no response before `deadline`.
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
        let key = (target.addr, target_template.authority().clone());
        let mut cached = self.fresh(&key);
        loop {
            let from_cache = cached.is_some();
            let configs = match cached.take() {
                Some(configs) => configs,
                None => {
                    self.fetch(https, target, &target_template, &key, deadline)
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

    /// The configurations of `key` while they are fresh.
    fn fresh(&self, key: &(SocketAddr, Authority)) -> Option<ObliviousDoHConfigs> {
        self.known
            .borrow()
            .get(key)
            .filter(|known| known.until > Instant::now())
            .map(|known| known.configs.clone())
    }

    /// Fetches the configurations from `target` directly, and keeps them as long as the response says.
    async fn fetch(
        &self,
        https: &HttpsPool,
        target: &Server,
        template: &Template,
        key: &(SocketAddr, Authority),
        deadline: Instant,
    ) -> Result<ObliviousDoHConfigs, OdohError> {
        let request = configs_request(template).map_err(OdohError::Request)?;
        let (head, body) = https
            .send(target.addr, target.certified(), &request, deadline)
            .await?;
        if !head.status().is_success() {
            return Err(OdohError::Configs(head.status()));
        }
        let configs = ObliviousDoHConfigs::parse(&body)?;
        let lifetime = configs_lifetime(head.headers(), SystemTime::now());
        if !lifetime.is_zero() {
            let until = crate::exchange::after(Instant::now(), lifetime);
            self.known.borrow_mut().insert(
                key.clone(),
                Known {
                    configs: configs.clone(),
                    until,
                },
            );
        }
        Ok(configs)
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
    let request = request(proxy_template, target_template, &message).map_err(OdohError::Request)?;
    let server = proxy.unwrap_or(target);
    let (head, body) = https
        .send(server.addr, server.certified(), &request, deadline)
        .await?;
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

    /// Both encryptions stay within the bytes drawn: the bound `Entropy::take` relies on.
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
