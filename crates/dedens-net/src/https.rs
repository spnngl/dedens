//! DNS over HTTPS (RFC 8484) over HTTP/3 (RFC 9114): one HTTP/3 connection per server and certificate name, opened
//! on first use and shared by the queries meanwhile, each query on a request stream of its own (D83). The request
//! and the response are [`crate::doh`]'s; the QUIC connection is the dialer's, as DNS over QUIC's.

use std::cell::Cell;
use std::net::SocketAddr;
use std::rc::Rc;
use std::time::{Duration, Instant, SystemTime};

use compio::bytes::{Buf, Bytes};
use compio::quic::Connection;
use compio::quic::h3::client::{self, RequestStream, SendRequest};
use compio::quic::h3::error::{Code, ConnectionError, StreamError};
use compio::quic::h3::{BidiStream, OpenStreams};
use compio::rustls::pki_types::ServerName;
use dedens_proto::wire::MAX_MESSAGE_LEN;
use http::{Request, Version};

use crate::dial::{Dialer, Peer, Slots};
use crate::doh::{self, DohError, Method, Template};
use crate::exchange::Http;
use crate::quic::QuicError;
use crate::tls::{self, Trust};

/// The unidirectional streams the server opens: its control stream and its two QPACK streams (RFC 9114 §6.2.1,
/// RFC 9204 §4.2), with room for the reserved types a peer may open (RFC 9114 §6.2.3).
const SERVER_STREAMS: u32 = 16;

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
        let server = (addr, name);
        let asked = async {
            let (open, reused) = self.connection(&server).await?;
            match ask(&open, &request).await {
                Err(error) if reused && open.dropped(&error) => {
                    let (fresh, _) = self.connection(&server).await?;
                    ask(&fresh, &request).await
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

/// Sends `request` alone on a new stream of `open` and reads the response to the end of the stream.
async fn ask(open: &Open, request: &Request<Vec<u8>>) -> Result<Reply, HttpsError> {
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
    while let Some(mut chunk) = stream.inner.recv_data().await.map_err(HttpsError::Stream)? {
        while chunk.has_remaining() {
            let part = chunk.chunk();
            body.extend_from_slice(part);
            let taken = part.len();
            chunk.advance(taken);
        }
        if body.len() > MAX_MESSAGE_LEN {
            return Err(HttpsError::TooLong);
        }
    }
    stream.read = true;
    let wire = doh::wire(&head, &body, SystemTime::now())?;
    Ok(Reply {
        wire,
        http: Http {
            version: Version::HTTP_3,
            status: head.status(),
        },
    })
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
