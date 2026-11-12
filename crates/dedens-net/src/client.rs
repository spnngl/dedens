//! The client: the sans-IO [`Exchange`] run over the UDP, TCP, TLS, QUIC, HTTPS and CoAP transports (D26, D27, D81,
//! D83).
//!
//! [`Client::exchange`] gives each query a random ID and, when it has EDNS and no cookie of the caller's, a cookie
//! (RFC 7873 §4.1, §5.1): the client cookie is drawn at random for each pair of source and server addresses, so it
//! changes with either, and the server cookie is the last one that server sent, kept for the life of the client.
//! The source address is that of the socket the query goes out of, open before the query is encoded.
//! A client lives on one thread, as compio tasks do.
//!
//! Generic over [`Io`] (D134) for the UDP and TCP transports and the clock and randomness: compio's by default, a
//! simulation's under test. QUIC, HTTPS and CoAP stay on compio.

#![deny(clippy::disallowed_methods)]

use std::cell::RefCell;
use std::collections::HashMap;
use std::collections::hash_map::Entry;
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::num::NonZeroU8;
use std::time::{Duration, Instant};

use compio::rustls::pki_types::ServerName;
use dedens_proto::edns::{Cookie, EdnsOption};
use dedens_proto::{EncodeError, Message, Transport};

#[cfg(feature = "doc")]
use crate::doc::{DocError, coap, discover};
use crate::doh::{DEFAULT_PATH, Template, TemplateError};
use crate::exchange::{Exchange, Failure, Http, Options, Progress, Response, after};
use crate::http3::{Http3Error, Http3Pool};
use crate::io::{Compio, Io};
#[cfg(feature = "odoh")]
use crate::odoh::{self, OdohError};
use crate::quic::{QuicError, QuicPool};
use crate::tcp::{Link, TcpError, TcpPool};
use crate::tls::Trust;
use crate::udp::{UdpPool, UdpQuery};

/// How long a TCP connection stays open without a query waiting, unless the server asks for less (RFC 7766
/// §6.2.3, RFC 7828 §3.2.2).
const TCP_IDLE: Duration = Duration::from_secs(10);

/// The port of HTTPS, which a template leaves out (RFC 9110 §4.2.2).
const HTTPS_PORT: u16 = 443;

/// UDP sockets per server, each muxing queries by ID (D50).
const UDP_SOCKETS: usize = 256;

/// Why [`Client::exchange`] got no response.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum ClientError {
    /// No randomness for the ID or the client cookie.
    #[error("no randomness: {0}")]
    Random(io::Error),
    /// The query cannot be encoded.
    #[error("cannot encode the query")]
    Encode(#[from] EncodeError),
    /// The UDP socket failed, for instance on an ICMP port unreachable.
    #[error("UDP")]
    Udp(#[source] io::Error),
    /// The TCP or TLS connection failed.
    #[error("connection")]
    Tcp(#[from] TcpError),
    /// The QUIC connection or stream failed.
    #[error("QUIC")]
    Quic(#[from] QuicError),
    /// The HTTPS connection or request failed, or its response holds no DNS response.
    #[error("HTTPS")]
    Https(#[from] Http3Error),
    /// The server's name and port make no `DoH` template.
    #[error("no DoH template for the server")]
    Template(#[from] TemplateError),
    /// The Oblivious `DoH` exchange failed (D79).
    #[cfg(feature = "odoh")]
    #[error("Oblivious DoH")]
    Odoh(#[from] OdohError),
    /// Oblivious `DoH` was asked for and the crate built without its `odoh` feature (D69).
    #[cfg(not(feature = "odoh"))]
    #[error("built without the odoh feature")]
    OdohNotBuilt,
    /// The CoAP exchange failed, or its response holds no DNS response (D81).
    #[cfg(feature = "doc")]
    #[error("CoAP")]
    Doc(#[from] DocError),
    /// The transport is not built in: its Cargo feature is off (D69).
    #[error("the {0} transport is not built in")]
    NotBuilt(&'static str),
    /// [`Client::exchange`] was asked for [`Transport::Odoh`], which is oblivious through a proxy only: it is
    /// `Client::exchange_oblivious`'s (feature `odoh`, D79): no link, the method is not built without it.
    #[error("Oblivious DoH goes through Client::exchange_oblivious")]
    OdohWithoutProxy,
    /// The exchange ended without a response.
    #[error(transparent)]
    Exchange(#[from] Failure),
}

impl ClientError {
    /// Whether the failure is ours, not the server's or the network's: no randomness, a query that cannot be
    /// encoded, or a socket error other than the server or network refusing, resetting or unreachable, such as no
    /// file descriptor left.
    #[must_use]
    pub fn is_local(&self) -> bool {
        let io = match self {
            Self::Random(_)
            | Self::Encode(_)
            | Self::Template(_)
            | Self::NotBuilt(_)
            | Self::OdohWithoutProxy
            | Self::Tcp(TcpError::Trust(_))
            | Self::Quic(QuicError::Trust(_) | QuicError::Connect(_))
            | Self::Https(
                Http3Error::Quic(QuicError::Trust(_) | QuicError::Connect(_))
                | Http3Error::Request(_),
            )
            | Self::Exchange(Failure::Encode(_)) => return true,
            #[cfg(feature = "odoh")]
            Self::Odoh(error) => return error.is_local(),
            #[cfg(not(feature = "odoh"))]
            Self::OdohNotBuilt => return true,
            Self::Udp(error)
            | Self::Tcp(TcpError::Connect(error))
            | Self::Quic(QuicError::Bind(error))
            | Self::Https(Http3Error::Quic(QuicError::Bind(error))) => error,
            #[cfg(feature = "doc")]
            Self::Doc(DocError::Udp(error)) => error,
            #[cfg(feature = "doc")]
            Self::Doc(_) => return false,
            Self::Tcp(_)
            | Self::Quic(_)
            | Self::Https(_)
            | Self::Exchange(Failure::TimedOut { .. } | Failure::Forged { .. }) => {
                return false;
            }
        };
        local_io(io)
    }
}

/// Whether a socket error is ours: not the server or network refusing, resetting or being unreachable.
pub(crate) fn local_io(error: &io::Error) -> bool {
    !matches!(
        error.kind(),
        io::ErrorKind::ConnectionRefused
            | io::ErrorKind::ConnectionReset
            | io::ErrorKind::ConnectionAborted
            | io::ErrorKind::HostUnreachable
            | io::ErrorKind::NetworkUnreachable
            | io::ErrorKind::NetworkDown
            | io::ErrorKind::TimedOut
    )
}

/// A server to ask.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Server {
    /// Its address.
    pub addr: SocketAddr,
    /// Over TLS, the name its certificate must hold, sent as SNI; without one, the certificate must hold its address
    /// (RFC 8310 §8.1).
    pub name: Option<ServerName<'static>>,
    /// Over HTTPS, its URI template: the host and port of the `:authority` of the requests, and the path. Without
    /// one, `https://NAME/dns-query`, or its address for NAME, the port left out for 443 (D83).
    pub doh: Option<Template>,
    /// Over CoAP, the segments of the path of its URI, none for the root path (D81).
    pub docpath: Vec<Box<[u8]>>,
}

impl From<SocketAddr> for Server {
    fn from(addr: SocketAddr) -> Self {
        Self {
            addr,
            name: None,
            doh: None,
            docpath: Vec::new(),
        }
    }
}

impl Server {
    /// The TCP or TLS connection to it over `transport`, none over UDP, QUIC, HTTPS and CoAP.
    fn link(&self, transport: Transport) -> Option<Link> {
        match transport {
            Transport::Udp
            | Transport::Quic
            | Transport::Https
            | Transport::Odoh
            | Transport::Coap => None,
            Transport::Tcp => Some(Link::Tcp(self.addr)),
            Transport::Tls => Some(Link::Tls(self.addr, self.certified())),
        }
    }

    /// The URI template of its `DoH` service: the one given, else the default one.
    pub(crate) fn template(&self) -> Result<Template, TemplateError> {
        match &self.doh {
            Some(template) => Ok(template.clone()),
            None => self.template_at(DEFAULT_PATH),
        }
    }

    /// The URI template of its `DoH` service at `path`: its authority is the certificate name, else the address,
    /// with the port unless it is 443 (RFC 9110 §4.2.2).
    ///
    /// # Errors
    ///
    /// [`TemplateError`] when `path` is not an absolute path without another expression or a fragment.
    pub fn template_at(&self, path: &str) -> Result<Template, TemplateError> {
        if !path.starts_with('/') {
            return Err(TemplateError::NotAbsolute);
        }
        let host = match (&self.name, self.addr.ip()) {
            (Some(ServerName::DnsName(name)), _) => name.as_ref().to_owned(),
            (_, IpAddr::V4(ip)) => ip.to_string(),
            (_, IpAddr::V6(ip)) => format!("[{ip}]"),
        };
        let port = match self.addr.port() {
            HTTPS_PORT => String::new(),
            port => format!(":{port}"),
        };
        Template::parse(&format!("https://{host}{port}{path}"))
    }

    /// The name its certificate must hold: the one given, else its address.
    pub(crate) fn certified(&self) -> ServerName<'static> {
        self.name
            .clone()
            .unwrap_or_else(|| ServerName::IpAddress(self.addr.ip().into()))
    }
}

/// Sends queries and returns their responses, keeping TCP, TLS, QUIC and HTTP/3 connections and cookies per server.
#[derive(Debug)]
pub struct Client<N: Io = Compio> {
    io: N,
    udp: UdpPool<N>,
    tcp: TcpPool<N>,
    quic: QuicPool,
    https: Http3Pool,
    /// The key configurations of the Oblivious `DoH` targets asked (D79).
    #[cfg(feature = "odoh")]
    odoh: odoh::client::Configs,
    /// By source and server address: the client cookie and the last cookie the server sent.
    cookies: RefCell<HashMap<(IpAddr, SocketAddr), Cookies>>,
    random: RefCell<Random>,
}

/// Random bytes from [`Io::random`], drawn [`RANDOM_BATCH`] at a time and each used once: one system call per
/// [`RANDOM_BATCH`] bytes taken instead of one per draw.
#[derive(Debug)]
struct Random {
    bytes: [u8; RANDOM_BATCH],
    used: usize,
}

/// Random bytes drawn at once.
const RANDOM_BATCH: usize = 256;

impl Random {
    /// The next `LEN` bytes.
    fn take<const LEN: usize>(&mut self, io: &impl Io) -> Result<[u8; LEN], ClientError> {
        if self.used + LEN > RANDOM_BATCH {
            io.random(&mut self.bytes).map_err(ClientError::Random)?;
            self.used = 0;
        }
        let mut taken = [0; LEN];
        taken.copy_from_slice(&self.bytes[self.used..self.used + LEN]);
        self.used += LEN;
        Ok(taken)
    }
}

/// The cookies of one source and server pair.
#[derive(Debug)]
struct Cookies {
    client: [u8; 8],
    /// The last cookie returned, its client cookie checked by the exchange.
    returned: Option<Cookie>,
}

impl Default for Client {
    fn default() -> Self {
        Self::new()
    }
}

impl Client {
    /// No connection and no cookie yet, on compio.
    #[must_use]
    pub fn new() -> Self {
        Self::with_io(Compio)
    }
}

impl<N: Io> Client<N> {
    /// As [`Client::new`], on `io`.
    #[must_use]
    pub fn with_io(io: N) -> Self {
        Self {
            udp: UdpPool::with_io(io.clone(), UDP_SOCKETS),
            tcp: TcpPool::with_io(io.clone(), TCP_IDLE),
            io,
            quic: QuicPool::new(TCP_IDLE),
            https: Http3Pool::new(TCP_IDLE),
            #[cfg(feature = "odoh")]
            odoh: odoh::client::Configs::default(),
            cookies: RefCell::default(),
            random: RefCell::new(Random {
                bytes: [0; RANDOM_BATCH],
                used: RANDOM_BATCH,
            }),
        }
    }

    /// The client, its TLS, QUIC and HTTPS connections trusting `trust`.
    #[must_use]
    pub fn trusting(self, trust: Trust) -> Self {
        Self {
            tcp: self.tcp.trusting(trust.clone()),
            quic: self.quic.trusting(trust.clone()),
            https: self.https.trusting(trust),
            ..self
        }
    }

    /// Sends `query` to `server` and returns the response, with the retries and fallbacks of `options` (D27).
    ///
    /// The query goes with a random ID, and a cookie when it has EDNS and none of its own, unless
    /// [`Options::cookies`] is off. Over QUIC, with ID 0 and no cookie: QUIC checks the client's address itself
    /// (RFC 9000 §8), and over HTTPS, where the response's HTTP version and status come in [`Response::http`].
    ///
    /// # Errors
    ///
    /// [`ClientError`]: no randomness, a query that cannot be encoded, a socket or connection failure, or no
    /// response after all the tries; [`ClientError::OdohWithoutProxy`] for [`Transport::Odoh`].
    pub async fn exchange(
        &self,
        query: Message<'_>,
        server: impl Into<Server>,
        options: &Options,
    ) -> Result<Response, ClientError> {
        if options.transport == Transport::Odoh {
            return Err(ClientError::OdohWithoutProxy);
        }
        self.run(query, &server.into(), None, options).await
    }

    /// Sends `query` to the Oblivious `DoH` `target` through `proxy`, or straight to it without one, and returns the
    /// response, over [`Transport::Odoh`] whatever [`Options::transport`] says (RFC 9230 §4, D79).
    ///
    /// The query goes with ID 0 and no cookie, as over HTTPS; the encryption pads it (D78). Both servers are
    /// reached over HTTP/3, and the target's key configurations are fetched from it directly, kept as long as it
    /// allows ([`crate::odoh`]).
    ///
    /// # Errors
    ///
    /// As [`Client::exchange`], and for the target's configurations or the encryption.
    #[cfg(feature = "odoh")]
    pub async fn exchange_oblivious(
        &self,
        query: Message<'_>,
        target: impl Into<Server>,
        proxy: Option<Server>,
        options: &Options,
    ) -> Result<Response, ClientError> {
        let options = Options {
            transport: Transport::Odoh,
            ..*options
        };
        self.run(query, &target.into(), proxy.as_ref(), &options)
            .await
    }

    /// Keeps `configs`, the encoded key configurations of the Oblivious `DoH` `target`, for good: they are not
    /// fetched from it, which would give it the client's address (D79).
    ///
    /// # Errors
    ///
    /// [`OdohError`] for a target with no template, or bytes that are no configurations.
    #[cfg(feature = "odoh")]
    pub fn pin_odoh_configs(
        &self,
        target: impl Into<Server>,
        configs: &[u8],
    ) -> Result<(), OdohError> {
        self.odoh.pin(&target.into(), configs)
    }

    /// Keeps `configs`, the encoded key configurations of the Oblivious `DoH` `target`, as if it had served them: for
    /// an hour, after which, or after a 401, they are fetched from it (RFC 9230 §4.3), as
    /// [`Client::pin_odoh_configs`]' never are. For a caller that saved what a past run fetched, and for tests of
    /// that refetch.
    ///
    /// # Errors
    ///
    /// [`OdohError`] for a target with no template, or bytes that are no configurations.
    #[cfg(feature = "odoh")]
    pub fn keep_odoh_configs(
        &self,
        target: impl Into<Server>,
        configs: &[u8],
    ) -> Result<(), OdohError> {
        self.odoh.keep_given(&target.into(), configs)
    }

    /// What the Oblivious `DoH` exchanges since the last call have to tell the user (D79).
    #[cfg(feature = "odoh")]
    #[must_use]
    pub fn take_odoh_notices(&self) -> Vec<odoh::Notice> {
        self.odoh.take_notices()
    }

    /// The paths of the `DoC` resources of the CoAP server at `server`, asked of `/.well-known/core` by their
    /// resource type, `core.dns`: each a list of path segments, none for the root path, in the order the server lists
    /// them; none when it lists no such resource (RFC 9953 §3.1, RFC 6690, D95).
    ///
    /// The server is not authenticated: what it lists is no more trusted than it is (RFC 9953 §3), so the caller
    /// asks only where the user said to. The discovery ends `timeout` after it starts, as an exchange does (D109):
    /// the CoAP retransmissions alone would wait 93 s.
    ///
    /// # Errors
    ///
    /// [`ClientError`]: no randomness, a socket failure, no response before `timeout` (`DocError::TimedOut`), a CoAP
    /// error code or a response that is not in the link format, or links all of which name resources outside the
    /// server; [`ClientError::NotBuilt`] without the `doc` feature.
    pub async fn discover_doc(
        &self,
        server: SocketAddr,
        timeout: Duration,
    ) -> Result<Vec<Vec<Box<[u8]>>>, ClientError> {
        let random = self.draw::<14>()?;
        discover(server, random, after(self.io.now(), timeout)).await
    }

    /// [`Client::exchange`] with the proxy of an Oblivious `DoH` exchange, if any.
    async fn run(
        &self,
        mut query: Message<'_>,
        target: &Server,
        proxy: Option<&Server>,
        options: &Options,
    ) -> Result<Response, ClientError> {
        let server = target.addr;
        // The ID, then the UDP socket of the pool.
        let random = self.draw::<4>()?;
        query.header.id = u16::from_be_bytes([random[0], random[1]]);
        let pick = usize::from(u16::from_be_bytes([random[2], random[3]]));
        // The socket first: its address is the source the cookie goes with. One UDP socket for the whole exchange,
        // so a late response to an earlier try still counts (D27).
        let mut udp = None;
        // A connection slower than the try's timeout costs that try (D27).
        let mut slow = false;
        let source = match target.link(options.transport) {
            None if matches!(
                options.transport,
                Transport::Quic | Transport::Https | Transport::Odoh | Transport::Coap
            ) =>
            {
                None
            }
            None => {
                let waiting = self
                    .udp
                    .query(server, pick, query.header.id)
                    .await
                    .map_err(ClientError::Udp)?;
                Some(udp.insert(waiting).local_addr())
            }
            // The connection's address, for the cookie only.
            Some(link) if options.cookies => {
                let deadline = after(self.io.now(), options.timeout);
                match self.tcp.local_addr(link, deadline).await {
                    Ok(local) => Some(local),
                    Err(TcpError::TimedOut) => {
                        slow = true;
                        None
                    }
                    Err(error) => return Err(error.into()),
                }
            }
            Some(_) => None,
        };
        let pair = match source {
            Some(source) if options.cookies => {
                self.add_cookie(&mut query, (source.ip(), server))?
            }
            _ => None,
        };
        // CoAP retransmits by itself, so DNS does not (D81).
        let mut asked = *options;
        if asked.transport == Transport::Coap {
            asked.tries = NonZeroU8::MIN;
        }
        // The IDs of the queries a fallback changes (RFC 5452 §9.2, D114).
        let spare = self.draw::<8>()?;
        let spare_ids = [0, 2, 4, 6].map(|at| u16::from_be_bytes([spare[at], spare[at + 1]]));
        let exchange = Exchange::start(query, server, asked, spare_ids, self.io.now())?;
        let mut progress = if slow {
            exchange.lose(self.io.now())
        } else {
            Progress::Send(exchange)
        };
        // The HTTP response of the last query, over HTTPS.
        let mut http = None;
        let mut response = loop {
            progress = match progress {
                Progress::Send(next) => {
                    self.io.sending(&next);
                    self.keep_cookie(pair, next.cookie());
                    self.step(next, (target, proxy), udp.as_mut(), options, &mut http)
                        .await?
                }
                Progress::Wait(next) => {
                    self.step(next, (target, proxy), udp.as_mut(), options, &mut http)
                        .await?
                }
                Progress::Done(done) => break done?,
            };
        };
        response.http = http;
        self.keep_cookie(pair, response.cookie);
        Ok(response)
    }

    /// The next `LEN` random bytes.
    fn draw<const LEN: usize>(&self) -> Result<[u8; LEN], ClientError> {
        self.random.borrow_mut().take(&self.io)
    }

    /// The progress of `exchange` once `bytes` came back on its own connection or stream: nothing else comes with
    /// its ID, so a response that does not match ends the wait at `deadline`.
    fn answered(
        &self,
        exchange: Exchange,
        transport: Transport,
        bytes: Vec<u8>,
        deadline: Instant,
    ) -> Progress {
        let server = exchange.server();
        match exchange.receive(server, transport, bytes, self.io.now()) {
            Progress::Wait(next) => next.time_out(deadline.max(self.io.now())),
            progress => progress,
        }
    }

    /// Keeps the server cookie of `cookie`, if it has one, for the next query of `pair` (RFC 7873 §5.3): a cookie
    /// with the client cookie alone leaves the known one.
    fn keep_cookie(&self, pair: Option<(IpAddr, SocketAddr)>, cookie: Option<Cookie>) {
        if let (Some(pair), Some(cookie)) = (pair, cookie)
            && cookie.server().is_some()
            && let Some(cookies) = self.cookies.borrow_mut().get_mut(&pair)
        {
            cookies.returned = Some(cookie);
        }
    }

    /// Sends the query of `exchange` and waits for what comes back: a message, or the deadline.
    async fn step(
        &self,
        exchange: Exchange,
        (target, proxy): (&Server, Option<&Server>),
        udp: Option<&mut UdpQuery<N>>,
        options: &Options,
        http: &mut Option<Http>,
    ) -> Result<Progress, ClientError> {
        let server = exchange.server();
        let transport = exchange.transport();
        trace!(%server, transport = ?exchange.transport(), len = exchange.wire().len(), "sending");
        let deadline = exchange.deadline();
        if transport == Transport::Https {
            let template = target.template()?;
            // Boxed: the HTTP/3 exchange's future is large, and it would grow every caller's.
            let asked = Box::pin(self.https.exchange(
                server,
                target.certified(),
                &template,
                options.method,
                exchange.wire(),
                deadline,
            ));
            return match asked.await {
                Ok(reply) => {
                    debug!(%server, version = ?reply.http.version, status = %reply.http.status, "HTTP response");
                    *http = Some(reply.http);
                    Ok(self.answered(exchange, transport, reply.wire, deadline))
                }
                Err(Http3Error::TimedOut) => Ok(exchange.time_out(self.io.now().max(deadline))),
                Err(error) => Err(error.into()),
            };
        }
        if transport == Transport::Odoh {
            return self.oblivious(exchange, target, proxy, http).await;
        }
        if transport == Transport::Coap {
            let random = self.draw::<14>()?;
            // Boxed, as HTTPS is: with its deadline the CoAP exchange's future grows every caller's past 16 KiB.
            let asked = Box::pin(coap(
                exchange.wire(),
                server,
                &target.docpath,
                random,
                deadline,
            ));
            return match asked.await {
                Ok(bytes) => Ok(self.answered(exchange, transport, bytes, deadline)),
                #[cfg(feature = "doc")]
                Err(ClientError::Doc(DocError::TimedOut)) => {
                    Ok(exchange.time_out(self.io.now().max(deadline)))
                }
                Err(error) => Err(error),
            };
        }
        if transport == Transport::Quic {
            return match self
                .quic
                .exchange(server, target.certified(), exchange.wire(), deadline)
                .await
            {
                Ok(bytes) => Ok(self.answered(exchange, transport, bytes, deadline)),
                Err(QuicError::TimedOut) => Ok(exchange.time_out(self.io.now().max(deadline))),
                Err(error) => Err(error.into()),
            };
        }
        let Some(link) = target.link(transport) else {
            let channel = udp.expect("an exchange over UDP started over UDP, which took a socket");
            // A fallback sends the query with another ID (D114).
            if let Some(&[high, low]) = exchange.wire().get(..2) {
                channel.expect(u16::from_be_bytes([high, low]));
            }
            // An error of the shared socket, maybe another query's: the try is lost, not the exchange, unless it was
            // the last (D31).
            let lose = |exchange: Exchange, error: io::Error| match exchange.lose(self.io.now()) {
                Progress::Done(Err(Failure::TimedOut { .. })) => Err(ClientError::Udp(error)),
                progress => Ok(progress),
            };
            match channel.send(exchange.wire()).await {
                Ok(()) => {}
                // Never this datagram's: the ICMP port unreachable an earlier one got, maybe another query's (D50).
                Err(error) if error.kind() == io::ErrorKind::ConnectionRefused => {
                    return lose(exchange, error);
                }
                // The route or the socket refuses this datagram itself: sending again does no better.
                Err(error) => return Err(ClientError::Udp(error)),
            }
            let mut exchange = exchange;
            loop {
                let deadline = exchange.deadline();
                let bytes = match channel.recv(deadline).await {
                    Ok(Some(bytes)) => bytes,
                    Ok(None) => return Ok(exchange.time_out(self.io.now().max(deadline))),
                    Err(error) => return lose(exchange, error),
                };
                match exchange.receive(server, Transport::Udp, bytes, self.io.now()) {
                    Progress::Wait(next) => exchange = next,
                    progress => return Ok(progress),
                }
            }
        };
        match self.tcp.exchange(link, exchange.wire(), deadline).await {
            Ok(bytes) => Ok(self.answered(exchange, transport, bytes, deadline)),
            Err(TcpError::TimedOut) => Ok(exchange.time_out(self.io.now().max(deadline))),
            Err(error) => Err(error.into()),
        }
    }

    /// Sends the query of `exchange` encrypted to the Oblivious `DoH` `target`, through `proxy` if there is one (D79).
    #[cfg(feature = "odoh")]
    async fn oblivious(
        &self,
        exchange: Exchange,
        target: &Server,
        proxy: Option<&Server>,
        http: &mut Option<Http>,
    ) -> Result<Progress, ClientError> {
        let deadline = exchange.deadline();
        // Boxed, as the HTTPS exchange is: two HTTP/3 exchanges and the encryption make a large future.
        let asked =
            Box::pin(
                self.odoh
                    .exchange(&self.https, target, proxy, exchange.wire(), deadline),
            );
        match asked.await {
            Ok(reply) => {
                debug!(server = %exchange.server(), status = %reply.http.status, "Oblivious DoH response");
                *http = Some(reply.http);
                Ok(self.answered(exchange, Transport::Odoh, reply.wire, deadline))
            }
            Err(OdohError::Https(Http3Error::TimedOut)) => {
                Ok(exchange.time_out(self.io.now().max(deadline)))
            }
            Err(error) => Err(error.into()),
        }
    }

    /// Without the `odoh` feature there is no Oblivious `DoH` to send.
    #[cfg(not(feature = "odoh"))]
    #[expect(
        clippy::unused_async,
        clippy::unused_async_trait_impl,
        reason = "the same call as with the feature"
    )]
    async fn oblivious(
        &self,
        _exchange: Exchange,
        _target: &Server,
        _proxy: Option<&Server>,
        _http: &mut Option<Http>,
    ) -> Result<Progress, ClientError> {
        Err(ClientError::OdohNotBuilt)
    }

    /// Adds a cookie to a query with EDNS and none of its own, and returns the pair of addresses it belongs to.
    fn add_cookie(
        &self,
        query: &mut Message<'_>,
        pair: (IpAddr, SocketAddr),
    ) -> Result<Option<(IpAddr, SocketAddr)>, ClientError> {
        let Some(edns) = &mut query.edns else {
            return Ok(None);
        };
        if edns
            .options
            .iter()
            .any(|option| matches!(option, EdnsOption::Cookie(_)))
        {
            return Ok(None);
        }
        let mut all = self.cookies.borrow_mut();
        let cookies = match all.entry(pair) {
            Entry::Occupied(known) => known.into_mut(),
            Entry::Vacant(slot) => slot.insert(Cookies {
                client: self.draw()?,
                returned: None,
            }),
        };
        let cookie = cookies.returned.unwrap_or_else(|| {
            Cookie::new(cookies.client, None).expect("a client cookie alone is valid")
        });
        edns.options.push(EdnsOption::Cookie(cookie));
        Ok(Some(pair))
    }
}

/// Asks over CoAP without the `doc` feature: not built in (D69).
#[cfg(not(feature = "doc"))]
#[expect(clippy::unused_async, reason = "the signature of the `doc` one")]
async fn coap(
    _query: &[u8],
    _server: SocketAddr,
    _docpath: &[Box<[u8]>],
    _random: [u8; 14],
    _deadline: Instant,
) -> Result<Vec<u8>, ClientError> {
    Err(ClientError::NotBuilt("CoAP"))
}

/// Discovers over CoAP without the `doc` feature: not built in (D69).
#[cfg(not(feature = "doc"))]
#[expect(clippy::unused_async, reason = "the signature of the `doc` one")]
async fn discover(
    _server: SocketAddr,
    _random: [u8; 14],
    _deadline: Instant,
) -> Result<Vec<Vec<Box<[u8]>>>, ClientError> {
    Err(ClientError::NotBuilt("CoAP"))
}

#[cfg(test)]
mod tests {
    use super::{Compio, RANDOM_BATCH, Random};

    /// Takes across a refill come whole, and fresh bytes are not the zeros the batch starts with.
    #[test]
    fn takes_refill_the_batch_when_short() {
        let mut random = Random {
            bytes: [0; RANDOM_BATCH],
            used: RANDOM_BATCH - 4,
        };
        assert_eq!(random.take::<4>(&Compio).ok(), Some([0; 4]));
        let fresh: Vec<_> = (0..4)
            .map(|_| random.take::<8>(&Compio).expect("randomness"))
            .collect();
        assert_eq!(random.used, 32);
        assert!(fresh.iter().any(|bytes| *bytes != [0; 8]));
    }
}
