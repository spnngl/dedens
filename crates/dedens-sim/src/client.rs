//! The client: the real `dedens_net::client::Client`, run on a host's simulated network through [`Sim`] (D26, D27,
//! D134).
//!
//! Its UDP socket pool, TCP and TLS connection per server, inboxes, retries and cookies are the production ones;
//! only the clock, the randomness and the sockets are the simulation's. Each query it sends goes in the trace as
//! [`What::Sent`]. QUIC, HTTPS and CoAP stay out: they stay on compio (D133).
//!
//! [`What::Sent`]: crate::trace::What::Sent

use std::cell::RefCell;
use std::net::IpAddr;
use std::rc::Rc;

use dedens_net::client::{Client as Real, ClientError, Server};
use dedens_net::exchange::{Options, Response};
use dedens_net::tls::Trust;
use dedens_proto::{Message, Transport};

use crate::io::{Glitches, Sim};
use crate::seed::Rng;
use crate::trace::Trace;

/// The transports the simulation speaks.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Carrier {
    /// UDP, falling back to TCP on a truncated response.
    Udp,
    /// TCP.
    Tcp,
    /// TLS over TCP (DNS over TLS, RFC 7858).
    Tls,
}

impl From<Carrier> for Transport {
    fn from(carrier: Carrier) -> Self {
        match carrier {
            Carrier::Udp => Self::Udp,
            Carrier::Tcp => Self::Tcp,
            Carrier::Tls => Self::Tls,
        }
    }
}

/// A host's client: its IDs, those of the queries a fallback changes and its client cookies come from the host's
/// `rng` (RFC 5452 §9.2, RFC 7873 §4.1, D114). The pools and cookies belong to the host: a client of a host that
/// restarted starts with none.
#[derive(Debug, Clone)]
pub struct Client {
    inner: Rc<Real<Sim>>,
    io: Sim,
}

impl Client {
    /// The client of `host`, drawing from `rng`.
    #[must_use]
    pub fn new(rng: Rc<RefCell<Rng>>, host: IpAddr, trace: Trace) -> Self {
        let io = Sim::new(rng, host, trace);
        Self {
            inner: Rc::new(Real::with_io(io.clone())),
            io,
        }
    }

    /// The client, its TLS connections trusting `trust`; its pools start empty.
    #[must_use]
    pub fn trusting(self, trust: Trust) -> Self {
        Self {
            inner: Rc::new(Real::with_io(self.io.clone()).trusting(trust)),
            io: self.io,
        }
    }

    /// The errors to inject into the client's UDP sockets.
    #[must_use]
    pub fn glitches(&self) -> &Glitches {
        self.io.glitches()
    }

    /// Sends `query` to `server` over `carrier`, with the timeout, tries and fallbacks of `options`, and returns
    /// the response or why there is none. The ID of `query` is replaced by a random one.
    ///
    /// # Errors
    ///
    /// [`ClientError`] as the real client ends: [`Failure`] when no try is answered or the query cannot be
    /// encoded, and the I/O error of the socket or the connection otherwise.
    ///
    /// [`Failure`]: dedens_net::exchange::Failure
    ///
    /// # Panics
    ///
    /// When a task of its pools panicked before the exchange ended: the pools run them detached, so the panic
    /// fails the host here (D133).
    pub async fn exchange(
        &self,
        query: Message<'static>,
        server: impl Into<Server>,
        carrier: Carrier,
        options: &Options,
    ) -> Result<Response, ClientError> {
        let mut options = *options;
        options.transport = carrier.into();
        let response = self.inner.exchange(query, server, &options).await;
        self.io.resume_panic();
        response
    }
}
