//! DNS over HTTPS (RFC 8484) over HTTP/3 (RFC 9114): one HTTP/3 connection per server and certificate name, opened
//! on first use and shared by the queries meanwhile, each query on a request stream of its own (D83). The request
//! and the response are [`crate::doh`]'s; the QUIC connection is the dialer's, as DNS over QUIC's. The server's
//! side of a connection, [`Requests`], serves the same (D84).

use std::cell::Cell;
use std::net::SocketAddr;
use std::rc::Rc;
use std::time::{Duration, Instant, SystemTime};

use compio::bytes::{Buf, Bytes};
use compio::quic::Connection;
use compio::quic::h3::client::{self, RequestStream, SendRequest};
use compio::quic::h3::error::{Code, ConnectionError, StreamError};
use compio::quic::h3::{self, BidiStream, OpenStreams};
use compio::rustls::pki_types::ServerName;
use dedens_proto::wire::MAX_MESSAGE_LEN;
use http::{Request, Response, StatusCode, Version};

use crate::dial::{Dialer, Peer, Slots};
use crate::doh::{self, DohError, Method, Template};
use crate::exchange::Http;
use crate::quic::QuicError;
use crate::tls::{self, Trust};

/// The unidirectional streams the server opens: its control stream and its two QPACK streams (RFC 9114 §6.2.1,
/// RFC 9204 §4.2), with room for the reserved types a peer may open (RFC 9114 §6.2.3).
const SERVER_STREAMS: u32 = 16;

/// The header section of a request a server reads, at most: a GET's URI of up to 65535 bytes and room for its other
/// fields (RFC 9114 §4.2.2, §7.2.4.1).
const MAX_FIELD_SECTION: u64 = 80 << 10;

/// Why an HTTPS exchange failed.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum HttpsError {
    /// The QUIC connection cannot be opened or failed: no TLS or socket, a refused certificate, the idle timeout.
    #[error("QUIC")]
    Quic(#[from] QuicError),
    /// The HTTP/3 connection cannot start or closed: a protocol error of the server's (RFC 9114 §8).
    #[error("HTTP/3 connection")]
    Connection(#[source] ConnectionError),
    /// The request cannot be made, such as a query too long for a GET's URI.
    #[error("cannot make the request")]
    Request(#[source] http::Error),
    /// The request stream failed: reset by the server, or cut by a connection that is closing.
    #[error("HTTP/3 request")]
    Stream(#[source] StreamError),
    /// The body is longer than a DNS message (RFC 8484 §6).
    #[error("the body is longer than a DNS message")]
    TooLong,
    /// The HTTP response holds no DNS response.
    #[error("HTTP response")]
    Response(#[from] DohError),
    /// No response before the deadline.
    #[error("no response before the deadline")]
    TimedOut,
}

/// The DNS response and the HTTP response it came in.
#[derive(Debug)]
pub struct Reply {
    /// The DNS message, with its TTLs reduced by the response's age (D82).
    pub wire: Vec<u8>,
    /// The HTTP response's version and status.
    pub http: Http,
}

/// HTTP/3 connections, one per server and name, closed by the QUIC idle timeout.
#[derive(Debug)]
pub struct HttpsPool {
    dialer: Dialer,
    connections: Slots<Open>,
}

/// An open HTTP/3 connection.
#[derive(Clone)]
struct Open {
    /// Sends the requests: cloned for each, the last one dropped closing the connection (RFC 9114 §5.2).
    requests: SendRequest<OpenStreams, Bytes>,
    connection: Connection,
    /// The server sent `GOAWAY`: no new request goes on this connection (RFC 9114 §5.2).
    going_away: Rc<Cell<bool>>,
}

impl HttpsPool {
    /// No connection yet; those opened close after `idle` without a packet, unless the server asks for less.
    #[must_use]
    pub fn new(idle: Duration) -> Self {
        Self {
            dialer: Dialer::new(tls::ALPN_H3, SERVER_STREAMS, idle),
            connections: Slots::default(),
        }
    }

    /// The pool, its connections trusting `trust`.
    #[must_use]
    pub fn trusting(self, trust: Trust) -> Self {
        Self {
            dialer: self.dialer.trusting(trust),
            ..self
        }
    }

    /// Asks the server at `addr`, whose certificate must hold `name`, for the answer to `wire` (a DNS message with
    /// ID 0), at `template` by `method`.
    ///
    /// A request that did not go through because the server is closing the connection (`GOAWAY`, a rejected
    /// request, RFC 9114 §4.1.1, §5.2), or because it closed while idle, is sent again once on a new connection
    /// (D27).
    ///
    /// # Errors
    ///
    /// [`HttpsError`]: no connection, a failed request, an HTTP response that holds no DNS response, or none before
    /// `deadline`.
    pub async fn exchange(
        &self,
        addr: SocketAddr,
        name: ServerName<'static>,
        template: &Template,
        method: Method,
        wire: &[u8],
        deadline: Instant,
    ) -> Result<Reply, HttpsError> {
        let request = doh::request(template, wire, method).map_err(HttpsError::Request)?;
        let (head, body) = self
            .send(addr, name, &request, MAX_MESSAGE_LEN, deadline)
            .await?;
        let wire = doh::wire(&head, &body, SystemTime::now())?;
        Ok(Reply {
            wire,
            http: Http {
                version: Version::HTTP_3,
                status: head.status(),
            },
        })
    }

    /// Sends `request` to the server at `addr`, whose certificate must hold `name`, and returns the response's head
    /// and body, of whatever status and type: what `DoH` makes of it is [`HttpsPool::exchange`]'s, and what
    /// Oblivious `DoH` makes is the caller's (D79).
    ///
    /// A request is sent again once on a new connection as [`HttpsPool::exchange`] says. A body longer than `limit`
    /// bytes is an error: a DNS message at most, or what Oblivious `DoH` adds to one (D79).
    ///
    /// # Errors
    ///
    /// [`HttpsError`]: no connection, a failed request, a body longer than `limit`, or no response before
    /// `deadline`.
    pub async fn send(
        &self,
        addr: SocketAddr,
        name: ServerName<'static>,
        request: &Request<Vec<u8>>,
        limit: usize,
        deadline: Instant,
    ) -> Result<(Response<()>, Vec<u8>), HttpsError> {
        let server = (addr, name);
        let asked = async {
            let (open, reused) = self.connection(&server).await?;
            match ask(&open, request, limit).await {
                Err(error) if reused && open.dropped(&error) => {
                    let (fresh, _) = self.connection(&server).await?;
                    ask(&fresh, request, limit).await
                }
                asked => asked,
            }
        };
        compio::time::timeout_at(deadline, asked)
            .await
            .unwrap_or(Err(HttpsError::TimedOut))
    }

    /// The open connection to `server`, reused, or a new one.
    async fn connection(&self, server: &Peer) -> Result<(Open, bool), HttpsError> {
        let slot = self.connections.slot(server);
        let mut slot = slot.lock().await;
        if let Some(open) = slot.as_ref()
            && open.connection.close_reason().is_none()
            && !open.going_away.get()
        {
            return Ok((open.clone(), true));
        }
        let connection = self.dialer.connect(server.0, &server.1).await?;
        let (mut driver, requests) = client::new(connection.clone())
            .await
            .map_err(HttpsError::Connection)?;
        // The connection's control stream is read, and `GOAWAY` heeded, while this task runs: until the
        // connection closes.
        compio::runtime::spawn(async move { driver.wait_idle().await }).detach();
        let open = Open {
            requests,
            connection,
            going_away: Rc::default(),
        };
        Ok((slot.insert(open).clone(), false))
    }
}

impl Open {
    /// Whether `error` came from a connection the server was done with: a request the server did not process, a
    /// `GOAWAY`, or a connection closed meanwhile.
    fn dropped(&self, error: &HttpsError) -> bool {
        match error {
            HttpsError::Stream(StreamError::RemoteClosing) => true,
            HttpsError::Stream(StreamError::RemoteTerminate { code }) => {
                *code == Code::H3_REQUEST_REJECTED
            }
            _ => self.connection.close_reason().is_some(),
        }
    }
}

/// Sends `request` alone on a new stream of `open` and reads the response to the end of the stream, which may not be
/// longer than `limit`.
async fn ask(
    open: &Open,
    request: &Request<Vec<u8>>,
    limit: usize,
) -> Result<(Response<()>, Vec<u8>), HttpsError> {
    let (parts, body) = request.clone().into_parts();
    let sent = open
        .requests
        .clone()
        .send_request(Request::from_parts(parts, ()))
        .await;
    let inner = sent.map_err(|error| {
        if matches!(error, StreamError::RemoteClosing) {
            open.going_away.set(true);
        }
        HttpsError::Stream(error)
    })?;
    let mut stream = Stream { inner, read: false };
    if !body.is_empty() {
        let body = Bytes::from(body);
        stream
            .inner
            .send_data(body)
            .await
            .map_err(HttpsError::Stream)?;
    }
    stream.inner.finish().await.map_err(HttpsError::Stream)?;
    let head = stream
        .inner
        .recv_response()
        .await
        .map_err(HttpsError::Stream)?;
    let mut body = Vec::new();
    while let Some(chunk) = stream.inner.recv_data().await.map_err(HttpsError::Stream)? {
        append(&mut body, chunk);
        if body.len() > limit {
            return Err(HttpsError::TooLong);
        }
    }
    stream.read = true;
    Ok((head, body))
}

/// The request stream, cancelled when dropped before its response is read whole: `RESET_STREAM` and
/// `STOP_SENDING` with `H3_REQUEST_CANCELLED` (RFC 9114 §4.1.1), so that a query cut by a timeout does not go out
/// finished.
struct Stream {
    inner: RequestStream<BidiStream<Bytes>, Bytes>,
    /// The response was read to the end of the stream: nothing to cancel.
    read: bool,
}

impl Drop for Stream {
    fn drop(&mut self) {
        if !self.read {
            self.inner.stop_stream(Code::H3_REQUEST_CANCELLED);
            self.inner.stop_sending(Code::H3_REQUEST_CANCELLED);
        }
    }
}

/// Appends the bytes of `chunk` to `body`.
fn append(body: &mut Vec<u8>, mut chunk: impl Buf) {
    while chunk.has_remaining() {
        let part = chunk.chunk();
        body.extend_from_slice(part);
        let taken = part.len();
        chunk.advance(taken);
    }
}

/// The server side of an HTTP/3 connection a client opened: the `DoH` requests on it (RFC 8484 §4, RFC 9114 §4).
pub struct Requests {
    inner: h3::server::Connection<Connection, Bytes>,
}

impl Requests {
    /// Starts HTTP/3 on the accepted QUIC `connection`: the control stream and the settings go out (RFC 9114 §3.3,
    /// §6.2.1, §7.2.4).
    ///
    /// # Errors
    ///
    /// [`HttpsError::Connection`] when the client breaks the protocol or the connection closes.
    pub async fn new(connection: Connection) -> Result<Self, HttpsError> {
        let mut builder = h3::server::builder();
        builder.max_field_section_size(MAX_FIELD_SECTION);
        let inner = builder
            .build(connection)
            .await
            .map_err(HttpsError::Connection)?;
        Ok(Self { inner })
    }

    /// The next request stream the client opened; `None` once the client is done with the connection (RFC 9114
    /// §5.2). Called again as soon as a request is taken, so that the connection's control stream is read while the
    /// requests are answered.
    ///
    /// # Errors
    ///
    /// [`HttpsError::Connection`] when the client breaks the protocol or the connection closes.
    pub async fn accept(&mut self) -> Result<Option<Pending>, HttpsError> {
        let resolver = self.inner.accept().await.map_err(HttpsError::Connection)?;
        Ok(resolver.map(Pending))
    }
}

/// A request stream the client opened, its request not read yet.
pub struct Pending(h3::server::RequestResolver<Connection, Bytes>);

impl Pending {
    /// Reads the request head and, to the end or past a DNS message's size, its body, for the service at `path`:
    /// the query it holds, or the status to answer with ([`Exchange::query`]).
    ///
    /// The status is 404 for another path (RFC 9110 §15.5.5), else [`doh::server_request`]'s. The authority and the
    /// scheme are not checked: the server answers for the names its certificate holds.
    ///
    /// # Errors
    ///
    /// [`HttpsError::Stream`] for a request the client broke (RFC 9114 §4.1.2: the stream is reset) or cut.
    pub async fn read(self, path: &str) -> Result<Exchange, HttpsError> {
        self.read_with(MAX_MESSAGE_LEN, |request, body| {
            let query = if request.uri().path() == path {
                doh::server_request(request, body)
            } else {
                Err(StatusCode::NOT_FOUND)
            };
            ((), query)
        })
        .await
    }

    /// As [`Pending::read`], for a service that is not `DoH` alone: `classify` makes of the request head and body
    /// what the service takes of them, the kind of request and what [`Exchange::query`] gives (Oblivious `DoH`, D79).
    /// The body is read to the end or past `limit` bytes: a DNS message's size, or what Oblivious `DoH` adds to it.
    ///
    /// # Errors
    ///
    /// As [`Pending::read`].
    pub async fn read_with<K>(
        self,
        limit: usize,
        classify: impl FnOnce(&Request<()>, &[u8]) -> (K, Result<Vec<u8>, StatusCode>),
    ) -> Result<Exchange<K>, HttpsError> {
        let (request, mut stream) = self.0.resolve_request().await.map_err(HttpsError::Stream)?;
        let mut body = Vec::new();
        while body.len() <= limit
            && let Some(chunk) = stream.recv_data().await.map_err(HttpsError::Stream)?
        {
            append(&mut body, chunk);
        }
        let (kind, query) = classify(&request, &body);
        Ok(Exchange {
            stream,
            method: request.method().clone(),
            query,
            kind,
        })
    }
}

/// A request read, to answer on its stream; `K` is the kind [`Pending::read_with`]'s classifier gave it.
pub struct Exchange<K = ()> {
    stream: h3::server::RequestStream<BidiStream<Bytes>, Bytes>,
    method: http::Method,
    query: Result<Vec<u8>, StatusCode>,
    kind: K,
}

impl<K> Exchange<K> {
    /// The kind of request its classifier gave it.
    #[must_use]
    pub const fn kind(&self) -> &K {
        &self.kind
    }

    /// The request's method: `None` for one `DoH` does not use (RFC 8484 §4.1).
    #[must_use]
    pub fn method(&self) -> Option<Method> {
        match self.method {
            http::Method::GET => Some(Method::Get),
            http::Method::POST => Some(Method::Post),
            _ => None,
        }
    }

    /// The DNS query, or the status to [`reject`](Exchange::reject) the request with.
    ///
    /// # Errors
    ///
    /// [`Pending::read`]'s status.
    pub fn query(&self) -> Result<&[u8], StatusCode> {
        self.query.as_deref().map_err(|status| *status)
    }

    /// Answers 200 with the DNS message `dns_response`, as [`doh::server_response`] makes it for the request's method,
    /// and finishes the stream.
    ///
    /// # Errors
    ///
    /// [`HttpsError::Response`] for a message that is not a DNS one, [`HttpsError::Stream`] for a stream the client
    /// reset or a connection that closed.
    pub async fn respond(self, dns_response: Vec<u8>) -> Result<(), HttpsError> {
        let response = doh::server_response(dns_response, &self.method)
            .map_err(|error| HttpsError::Response(error.into()))?;
        self.respond_with(response).await
    }

    /// Answers with `response` as it is, and finishes the stream: the response of a service that is not `DoH`
    /// (Oblivious `DoH`, D79).
    ///
    /// # Errors
    ///
    /// [`HttpsError::Stream`] for a stream the client reset or a connection that closed.
    pub async fn respond_with(self, response: Response<Vec<u8>>) -> Result<(), HttpsError> {
        let (head, body) = response.into_parts();
        self.send(Response::from_parts(head, ()), body).await
    }

    /// Answers `status`, with no body, and finishes the stream.
    ///
    /// # Errors
    ///
    /// [`HttpsError::Stream`] for a stream the client reset or a connection that closed.
    pub async fn reject(self, status: StatusCode) -> Result<(), HttpsError> {
        let mut response = Response::new(());
        *response.status_mut() = status;
        self.send(response, Vec::new()).await
    }

    async fn send(mut self, head: Response<()>, body: Vec<u8>) -> Result<(), HttpsError> {
        let stream = &mut self.stream;
        stream
            .send_response(head)
            .await
            .map_err(HttpsError::Stream)?;
        if !body.is_empty() {
            stream
                .send_data(Bytes::from(body))
                .await
                .map_err(HttpsError::Stream)?;
        }
        stream.finish().await.map_err(HttpsError::Stream)
    }
}
