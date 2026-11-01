//! What the QUIC transports share: the endpoints a client sends from, the connections it opens for one ALPN
//! protocol, and the slot each server's connection sits in (D61, D83).

use std::cell::{OnceCell, RefCell};
use std::collections::HashMap;
use std::fmt;
use std::net::SocketAddr;
use std::rc::Rc;
use std::sync::Arc;
use std::time::Duration;

use compio::quic::crypto::rustls::QuicClientConfig;
use compio::quic::{ClientConfig, Connection, Endpoint, IdleTimeout, TransportConfig, VarInt};
use compio::rustls::pki_types::ServerName;
use futures_util::lock::Mutex;

use crate::quic::QuicError;
use crate::tls::{self, Trust};
use crate::udp::unspecified;

/// Opens QUIC connections speaking `alpn`, each on the endpoint of its server's address family.
#[derive(Debug)]
pub(crate) struct Dialer {
    alpn: &'static [u8],
    /// The unidirectional streams the server may open: none for DNS over QUIC (RFC 9250 §4.3.3), the control and QPACK
    /// streams at least for HTTP/3 (RFC 9114 §6.2).
    server_streams: u32,
    idle: Duration,
    trust: Trust,
    config: OnceCell<ClientConfig>,
    /// The endpoints of IPv4 and IPv6 servers, each on its own UDP socket.
    endpoints: RefCell<[Option<Endpoint>; 2]>,
}

impl Dialer {
    /// A dialer of connections that close after `idle` without a packet, unless the server asks for less. The
    /// server opens no bidirectional stream, and `server_streams` unidirectional ones.
    pub(crate) fn new(alpn: &'static [u8], server_streams: u32, idle: Duration) -> Self {
        Self {
            alpn,
            server_streams,
            idle,
            trust: Trust::default(),
            config: OnceCell::new(),
            endpoints: RefCell::default(),
        }
    }

    /// The dialer, its connections trusting `trust`.
    pub(crate) fn trusting(self, trust: Trust) -> Self {
        Self { trust, ..self }
    }

    /// A new connection to `addr`, whose certificate must hold `name`.
    ///
    /// # Errors
    ///
    /// [`QuicError`]: no TLS, socket or connection.
    pub(crate) async fn connect(
        &self,
        addr: SocketAddr,
        name: &ServerName<'static>,
    ) -> Result<Connection, QuicError> {
        let endpoint = self.endpoint(addr).await?;
        endpoint
            .connect(addr, &name.to_str(), Some(self.config()?))
            .map_err(QuicError::Connect)?
            .await
            .map_err(QuicError::Connection)
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
        let tls = tls::quic_config(&self.trust, self.alpn).map_err(QuicError::Trust)?;
        let tls = QuicClientConfig::try_from(tls)
            .expect("TLS 1.3 with ring's cipher suites has QUIC's initial suite");
        let mut config = ClientConfig::new(Arc::new(tls));
        let mut transport = TransportConfig::default();
        transport
            .max_idle_timeout(IdleTimeout::try_from(self.idle).ok())
            .max_concurrent_bidi_streams(VarInt::from_u32(0))
            .max_concurrent_uni_streams(VarInt::from_u32(self.server_streams));
        config.transport_config(Arc::new(transport));
        Ok(self.config.get_or_init(|| config).clone())
    }
}

/// A server's address and the name its certificate must hold.
pub(crate) type Peer = (SocketAddr, ServerName<'static>);

/// The connection to a server, none before the first or after a failed one.
pub(crate) type Slot<T> = Rc<Mutex<Option<T>>>;

/// One slot per server, locked while its connection opens so that queries meanwhile wait for it, not open another.
pub(crate) struct Slots<T>(RefCell<HashMap<Peer, Slot<T>>>);

impl<T> fmt::Debug for Slots<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Slots").finish_non_exhaustive()
    }
}

impl<T> Default for Slots<T> {
    fn default() -> Self {
        Self(RefCell::default())
    }
}

impl<T> Slots<T> {
    /// The slot of `peer`, a new one for a server not seen yet.
    pub(crate) fn slot(&self, peer: &Peer) -> Slot<T> {
        let known = self.0.borrow().get(peer).cloned();
        // The key is copied for a new server only.
        known.unwrap_or_else(|| Rc::clone(self.0.borrow_mut().entry(peer.clone()).or_default()))
    }
}
