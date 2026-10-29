//! DNS over QUIC (RFC 9250): one QUIC connection per server and certificate name, opened on first use and reused
//! while open; each query alone on a bidirectional stream, behind its two-byte length, the stream finished after it
//! (RFC 9250 §4.2). No 0-RTT: queries wait for the handshake (RFC 9250 §4.5).

use std::cell::{OnceCell, RefCell};
use std::collections::HashMap;
use std::io;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
use std::ops::{Deref, DerefMut};
use std::rc::Rc;
use std::sync::Arc;
use std::time::{Duration, Instant};

use compio::BufResult;
use compio::io::AsyncWriteExt as _;
use compio::quic::{
    ClientBuilder, ClientConfig, ConnectError, Connection, ConnectionError, Endpoint, IdleTimeout,
    RecvStream, TransportConfig, VarInt,
};
use compio::rustls::pki_types::ServerName;
use futures_util::lock::Mutex;

use crate::tcp::frame;
use crate::tls::{self, Trust};

/// `DOQ_REQUEST_CANCELLED`: the client gave up waiting for a response (RFC 9250 §4.3, §4.3.1).
const DOQ_REQUEST_CANCELLED: u32 = 0x3;

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
    /// # Errors
    ///
    /// [`QuicError`]: no TLS, socket or connection, a failed stream, a response not framed, or none before
    /// `deadline`.
    pub async fn exchange(
        &self,
        addr: SocketAddr,
        name: &ServerName<'static>,
        wire: &[u8],
        deadline: Instant,
    ) -> Result<Vec<u8>, QuicError> {
        let framed = frame(wire).ok_or(QuicError::BadLength(wire.len()))?;
        let asked = async {
            let connection = self.connection(addr, name).await?;
            let (mut send, recv) = connection
                .open_bi_wait()
                .await
                .map_err(QuicError::Connection)?;
            let mut recv = Cancelled(recv);
            let BufResult(written, _) = send.write_all(framed).await;
            written.map_err(QuicError::Stream)?;
            send.finish()
                .map_err(|closed| QuicError::Stream(io::Error::other(closed)))?;
            let BufResult(read, mut bytes) = recv.read_to_end(Vec::new()).await;
            read.map_err(QuicError::Stream)?;
            match bytes.get(..2) {
                Some(&[high, low])
                    if usize::from(u16::from_be_bytes([high, low])) == bytes.len() - 2 =>
                {
                    bytes.drain(..2);
                    Ok(bytes)
                }
                _ => Err(QuicError::Framing),
            }
        };
        compio::time::timeout_at(deadline, asked)
            .await
            .unwrap_or(Err(QuicError::TimedOut))
    }

    /// The open connection to `addr` for `name`, or a new one.
    async fn connection(
        &self,
        addr: SocketAddr,
        name: &ServerName<'static>,
    ) -> Result<Connection, QuicError> {
        let slot = Rc::clone(
            self.connections
                .borrow_mut()
                .entry((addr, name.clone()))
                .or_default(),
        );
        let mut slot = slot.lock().await;
        if let Some(open) = slot.as_ref()
            && open.close_reason().is_none()
        {
            return Ok(open.clone());
        }
        let endpoint = self.endpoint(addr).await?;
        let connection = endpoint
            .connect(addr, &name.to_str(), Some(self.config()?))
            .map_err(QuicError::Connect)?
            .await
            .map_err(QuicError::Connection)?;
        Ok(slot.insert(connection).clone())
    }

    /// The endpoint of `addr`'s address family, bound to any address on first use.
    async fn endpoint(&self, addr: SocketAddr) -> Result<Endpoint, QuicError> {
        let family = usize::from(addr.is_ipv6());
        if let Some(endpoint) = &self.endpoints.borrow()[family] {
            return Ok(endpoint.clone());
        }
        let any = if addr.is_ipv6() {
            SocketAddr::from((Ipv6Addr::UNSPECIFIED, 0))
        } else {
            SocketAddr::from((Ipv4Addr::UNSPECIFIED, 0))
        };
        let endpoint = Endpoint::client(any).await.map_err(QuicError::Bind)?;
        self.endpoints.borrow_mut()[family] = Some(endpoint.clone());
        Ok(endpoint)
    }

    /// The configuration of new connections, built on first use.
    fn config(&self) -> Result<ClientConfig, QuicError> {
        if let Some(config) = self.config.get() {
            return Ok(config.clone());
        }
        let tls = tls::quic_config(&self.trust).map_err(QuicError::Trust)?;
        let mut config = ClientBuilder::new_with_rustls_client_config(tls).build();
        let mut transport = TransportConfig::default();
        transport.max_idle_timeout(IdleTimeout::try_from(self.idle).ok());
        config.transport_config(Arc::new(transport));
        Ok(self.config.get_or_init(|| config).clone())
    }
}

/// A stream whose response is no longer waited for when dropped: `STOP_SENDING` with `DOQ_REQUEST_CANCELLED` (RFC 9250
/// §4.3.1); nothing once the response is read whole.
struct Cancelled(RecvStream);

impl Drop for Cancelled {
    fn drop(&mut self) {
        // Fails once the stream is read to its end: nothing to cancel.
        let _ = self.0.stop(VarInt::from_u32(DOQ_REQUEST_CANCELLED));
    }
}

impl Deref for Cancelled {
    type Target = RecvStream;

    fn deref(&self) -> &RecvStream {
        &self.0
    }
}

impl DerefMut for Cancelled {
    fn deref_mut(&mut self) -> &mut RecvStream {
        &mut self.0
    }
}
