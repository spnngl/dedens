//! DNS over QUIC (RFC 9250): one QUIC connection per server and certificate name, opened on first use and reused
//! while open; each query alone on a bidirectional stream, behind its two-byte length, the stream finished after it
//! (RFC 9250 §4.2). No 0-RTT: queries wait for the handshake (RFC 9250 §4.5). The server may open no stream
//! (RFC 9250 §4.3.3).

use std::cell::{OnceCell, RefCell};
use std::collections::HashMap;
use std::io;
use std::net::SocketAddr;
use std::rc::Rc;
use std::sync::Arc;
use std::time::{Duration, Instant};

use compio::BufResult;
use compio::io::AsyncWriteExt as _;
use compio::quic::crypto::rustls::QuicClientConfig;
use compio::quic::{
    ClientConfig, ConnectError, Connection, ConnectionError, Endpoint, IdleTimeout, RecvStream,
    SendStream, TransportConfig, VarInt,
};
use compio::rustls::pki_types::ServerName;
use futures_util::lock::Mutex;

use crate::tcp::frame;
use crate::tls::{self, Trust};
use crate::udp::unspecified;

/// `DOQ_REQUEST_CANCELLED`: the client gave up waiting for a response (RFC 9250 §4.3, §4.3.1).
const DOQ_REQUEST_CANCELLED: u32 = 0x3;

/// The most a response stream holds: the two-byte length, then the message (RFC 9250 §4.2).
const MAX_STREAM: usize = 2 + 65535;

/// Why a QUIC exchange failed.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum QuicError {
    /// TLS cannot be set up with the trust asked for, such as no certificate authority usable.
    #[error("cannot set up TLS")]
    Trust(#[source] compio::rustls::Error),
    /// No UDP socket to send from.
    #[error("cannot open a UDP socket")]
    Bind(#[source] io::Error),
    /// The connection cannot start, for instance with a name rustls refuses.
    #[error("cannot connect")]
    Connect(#[source] ConnectError),
    /// The connection failed or closed: a refused certificate (RFC 8310 §6.6), the server's closing or no packet
    /// for the idle timeout.
    #[error("connection")]
    Connection(#[source] ConnectionError),
    /// The stream of the query failed, reset or stopped by the server.
    #[error("stream")]
    Stream(#[source] io::Error),
    /// The query is longer than 65535 bytes.
    #[error("a query of {0} bytes cannot be framed")]
    BadLength(usize),
    /// What came back is not one message behind its length (RFC 9250 §4.3.3).
    #[error("the response is not one message behind its length")]
    Framing,
    /// No response before the deadline.
    #[error("no response before the deadline")]
    TimedOut,
}

/// QUIC connections, one per server and name, closed by the QUIC idle timeout (RFC 9250 §4.4).
#[derive(Debug)]
pub struct QuicPool {
    idle: Duration,
    trust: Trust,
    config: OnceCell<ClientConfig>,
    /// The endpoints of IPv4 and IPv6 servers, each on its own UDP socket.
    endpoints: RefCell<[Option<Endpoint>; 2]>,
    /// Each server's connection, locked while it opens so that queries meanwhile wait for it, not open another.
    connections: RefCell<HashMap<(SocketAddr, ServerName<'static>), Slot>>,
}

/// The connection to a server, none before the first or after a failed one.
type Slot = Rc<Mutex<Option<Connection>>>;

impl QuicPool {
    /// No connection yet; those opened close after `idle` without a packet, unless the server asks for less.
    #[must_use]
    pub fn new(idle: Duration) -> Self {
        Self {
            idle,
            trust: Trust::default(),
            config: OnceCell::new(),
            endpoints: RefCell::default(),
            connections: RefCell::default(),
        }
    }

    /// The pool, its connections trusting `trust`.
    #[must_use]
    pub fn trusting(self, trust: Trust) -> Self {
        Self { trust, ..self }
    }

    /// Sends `wire` to `addr`, whose certificate must hold `name`, and returns the response.
    ///
    /// A reused connection found closed once the query fails, as one the server dropped while idle (RFC 9250
    /// §4.4), is replaced once and the query sent again (D27).
    ///
    /// # Errors
    ///
    /// [`QuicError`]: no TLS, socket or connection, a failed stream, a response not framed, or none before
    /// `deadline`.
    pub async fn exchange(
        &self,
        addr: SocketAddr,
        name: ServerName<'static>,
        wire: &[u8],
        deadline: Instant,
    ) -> Result<Vec<u8>, QuicError> {
        let framed = frame(wire).ok_or(QuicError::BadLength(wire.len()))?;
        let server = (addr, name);
        let asked = async {
            let (connection, reused) = self.connection(&server).await?;
            match ask(&connection, &framed).await {
                Err(_) if reused && connection.close_reason().is_some() => {
                    let (fresh, _) = self.connection(&server).await?;
                    ask(&fresh, &framed).await
                }
                asked => asked,
            }
        };
        compio::time::timeout_at(deadline, asked)
            .await
            .unwrap_or(Err(QuicError::TimedOut))
    }

    /// The open connection to the server at `addr` for `name`, reused, or a new one.
    async fn connection(
        &self,
        server: &(SocketAddr, ServerName<'static>),
    ) -> Result<(Connection, bool), QuicError> {
        let (addr, name) = (server.0, &server.1);
        let known = self.connections.borrow().get(server).cloned();
        // The key is copied for a new server only.
        let slot = known.unwrap_or_else(|| {
            Rc::clone(
                self.connections
                    .borrow_mut()
                    .entry(server.clone())
                    .or_default(),
            )
        });
        let mut slot = slot.lock().await;
        if let Some(open) = slot.as_ref()
            && open.close_reason().is_none()
        {
            return Ok((open.clone(), true));
        }
        let endpoint = self.endpoint(addr).await?;
        let connection = endpoint
            .connect(addr, &name.to_str(), Some(self.config()?))
            .map_err(QuicError::Connect)?
            .await
            .map_err(QuicError::Connection)?;
        Ok((slot.insert(connection).clone(), false))
    }

    /// The endpoint of `addr`'s address family, bound to any address on first use.
    async fn endpoint(&self, addr: SocketAddr) -> Result<Endpoint, QuicError> {
        let family = usize::from(addr.is_ipv6());
        if let Some(endpoint) = &self.endpoints.borrow()[family] {
            return Ok(endpoint.clone());
        }
        let endpoint = Endpoint::client(unspecified(addr))
            .await
            .map_err(QuicError::Bind)?;
        // Another query may have bound one meanwhile: the first stays.
        Ok(self.endpoints.borrow_mut()[family]
            .get_or_insert(endpoint)
            .clone())
    }

    /// The configuration of new connections, built on first use.
    fn config(&self) -> Result<ClientConfig, QuicError> {
        if let Some(config) = self.config.get() {
            return Ok(config.clone());
        }
        // rustls leaves early data off: no 0-RTT (D61).
        let tls = tls::quic_config(&self.trust).map_err(QuicError::Trust)?;
        let tls = QuicClientConfig::try_from(tls)
            .expect("TLS 1.3 with ring's cipher suites has QUIC's initial suite");
        let mut config = ClientConfig::new(Arc::new(tls));
        let mut transport = TransportConfig::default();
        transport
            .max_idle_timeout(IdleTimeout::try_from(self.idle).ok())
            .max_concurrent_bidi_streams(VarInt::from_u32(0))
            .max_concurrent_uni_streams(VarInt::from_u32(0));
        config.transport_config(Arc::new(transport));
        Ok(self.config.get_or_init(|| config).clone())
    }
}

/// Sends `framed` alone on a new stream of `connection` and reads the response to the end of the stream.
async fn ask(connection: &Connection, framed: &[u8]) -> Result<Vec<u8>, QuicError> {
    let (send, recv) = connection
        .open_bi_wait()
        .await
        .map_err(QuicError::Connection)?;
    let mut stream = Stream {
        send,
        recv,
        read: false,
    };
    let BufResult(written, _) = stream.send.write_all(framed.to_vec()).await;
    written.map_err(QuicError::Stream)?;
    stream
        .send
        .finish()
        .map_err(|closed| QuicError::Stream(io::Error::other(closed)))?;
    let mut bytes = Vec::new();
    // One byte past the most a response holds is enough to refuse it.
    while let Some(chunk) = stream
        .recv
        .read_chunk(MAX_STREAM + 1 - bytes.len(), true)
        .await
        .map_err(|error| QuicError::Stream(error.into()))?
    {
        bytes.extend_from_slice(&chunk.bytes);
        if bytes.len() > MAX_STREAM {
            return Err(QuicError::Framing);
        }
    }
    stream.read = true;
    match bytes.get(..2) {
        Some(&[high, low]) if usize::from(u16::from_be_bytes([high, low])) == bytes.len() - 2 => {
            bytes.drain(..2);
            Ok(bytes)
        }
        _ => Err(QuicError::Framing),
    }
}

/// The stream of a query, cancelled when dropped before its response is read whole: `RESET_STREAM` and
/// `STOP_SENDING` with `DOQ_REQUEST_CANCELLED` (RFC 9250 §4.3.1), so that a query cut by a timeout does not go out
/// finished.
struct Stream {
    send: SendStream,
    recv: RecvStream,
    /// The response was read to the end of the stream: nothing to cancel.
    read: bool,
}

impl Drop for Stream {
    fn drop(&mut self) {
        if !self.read {
            let code = VarInt::from_u32(DOQ_REQUEST_CANCELLED);
            // Each fails once its side is closed: nothing left to cancel there.
            let _ = self.send.reset(code);
            let _ = self.recv.stop(code);
        }
    }
}
