//! The client: the sans-IO [`Exchange`] run over the UDP, TCP, TLS, QUIC, HTTPS and CoAP transports (D26, D27, D81,
//! D83).
//!
//! [`Client::exchange`] gives each query a random ID and, when it has EDNS and no cookie of the caller's, a cookie
//! (RFC 7873 §4.1, §5.1): the client cookie is drawn at random for each pair of source and server addresses, so it
//! changes with either, and the server cookie is the last one that server sent, kept for the life of the client.
//! The source address is that of the socket the query goes out of, open before the query is encoded.
//! A client lives on one thread, as compio tasks do.

use std::cell::RefCell;
use std::collections::HashMap;
use std::collections::hash_map::Entry;
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::num::NonZeroU8;
use std::time::{Duration, Instant};

use compio::rustls::pki_types::ServerName;
use dedens_proto::edns::{Cookie, EdnsOption};
use dedens_proto::{EncodeError, Message};

#[cfg(feature = "doc")]
use crate::doc::{DocError, coap};
use crate::doh::{DEFAULT_PATH, Template, TemplateError};
use crate::exchange::{Exchange, Failure, Http, Options, Progress, Response, Transport, after};
use crate::https::{HttpsError, HttpsPool};
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
    Random(getrandom::Error),
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
    Https(#[from] HttpsError),
    /// The server's name and port make no `DoH` template.
    #[error("no DoH template for the server")]
    Template(#[from] TemplateError),
    /// The CoAP exchange failed, or its response holds no DNS response (D81).
    #[cfg(feature = "doc")]
    #[error("CoAP")]
    Doc(#[from] DocError),
    /// The transport is not built in: its Cargo feature is off (D69).
    #[error("the {0} transport is not built in")]
    NotBuilt(&'static str),
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
            | Self::Tcp(TcpError::Trust(_))
            | Self::Quic(QuicError::Trust(_) | QuicError::Connect(_))
            | Self::Https(
                HttpsError::Quic(QuicError::Trust(_) | QuicError::Connect(_))
                | HttpsError::Request(_),
            )
            | Self::Exchange(Failure::Encode(_)) => return true,
            Self::Udp(error)
            | Self::Tcp(TcpError::Connect(error))
            | Self::Quic(QuicError::Bind(error))
            | Self::Https(HttpsError::Quic(QuicError::Bind(error))) => error,
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
        !matches!(
            io.kind(),
            io::ErrorKind::ConnectionRefused
                | io::ErrorKind::ConnectionReset
                | io::ErrorKind::ConnectionAborted
                | io::ErrorKind::HostUnreachable
                | io::ErrorKind::NetworkUnreachable
                | io::ErrorKind::NetworkDown
                | io::ErrorKind::TimedOut
        )
    }
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
            Transport::Udp | Transport::Quic | Transport::Https | Transport::Coap => None,
            Transport::Tcp => Some(Link::Tcp(self.addr)),
            Transport::Tls => Some(Link::Tls(self.addr, self.certified())),
        }
    }

    /// The URI template of its `DoH` service: the one given, else the default one.
    fn template(&self) -> Result<Template, TemplateError> {
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
    fn certified(&self) -> ServerName<'static> {
        self.name
            .clone()
            .unwrap_or_else(|| ServerName::IpAddress(self.addr.ip().into()))
    }
}

/// Sends queries and returns their responses, keeping TCP, TLS, QUIC and HTTP/3 connections and cookies per server.
#[derive(Debug)]
pub struct Client {
    udp: UdpPool,
    tcp: TcpPool,
    quic: QuicPool,
    https: HttpsPool,
    /// By source and server address: the client cookie and the last cookie the server sent.
    cookies: RefCell<HashMap<(IpAddr, SocketAddr), Cookies>>,
    random: RefCell<Random>,
}

/// Random bytes from `getrandom`, drawn [`RANDOM_BATCH`] at a time and each used once: one system call per 64
/// exchanges instead of one each.
#[derive(Debug)]
struct Random {
    bytes: [u8; RANDOM_BATCH],
    used: usize,
}

/// Random bytes drawn at once.
const RANDOM_BATCH: usize = 256;

impl Random {
    /// The next `N` bytes.
    fn take<const N: usize>(&mut self) -> Result<[u8; N], ClientError> {
        if self.used + N > RANDOM_BATCH {
            getrandom::fill(&mut self.bytes).map_err(ClientError::Random)?;
            self.used = 0;
        }
        let mut taken = [0; N];
        taken.copy_from_slice(&self.bytes[self.used..self.used + N]);
        self.used += N;
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
    /// No connection and no cookie yet.
    #[must_use]
    pub fn new() -> Self {
        Self {
            udp: UdpPool::new(UDP_SOCKETS),
            tcp: TcpPool::new(TCP_IDLE),
            quic: QuicPool::new(TCP_IDLE),
            https: HttpsPool::new(TCP_IDLE),
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
    /// response after all the tries.
    pub async fn exchange(
        &self,
        mut query: Message<'_>,
        server: impl Into<Server>,
        options: &Options,
    ) -> Result<Response, ClientError> {
        let target = server.into();
        let server = target.addr;
        // The ID, then the UDP socket of the pool.
        let random = self.random.borrow_mut().take::<4>()?;
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
                Transport::Quic | Transport::Https | Transport::Coap
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
                let deadline = after(Instant::now(), options.timeout);
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
        let exchange = Exchange::start(query, server, asked, Instant::now())?;
        let mut progress = if slow {
            exchange.lose(Instant::now())
        } else {
            Progress::Send(exchange)
        };
        // The HTTP response of the last query, over HTTPS.
        let mut http = None;
        let mut response = loop {
            progress = match progress {
                Progress::Send(next) => {
                    self.keep_cookie(pair, next.cookie());
                    self.step(next, &target, udp.as_mut(), options, &mut http)
                        .await?
                }
                Progress::Wait(next) => {
                    self.step(next, &target, udp.as_mut(), options, &mut http)
                        .await?
                }
                Progress::Done(done) => break done?,
            };
        };
        response.http = http;
        self.keep_cookie(pair, response.cookie);
        Ok(response)
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
        target: &Server,
        udp: Option<&mut UdpQuery>,
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
                    Ok(answered(exchange, transport, reply.wire, deadline))
                }
                Err(HttpsError::TimedOut) => Ok(exchange.time_out(Instant::now().max(deadline))),
                Err(error) => Err(error.into()),
            };
        }
        if transport == Transport::Coap {
            let random = self.random.borrow_mut().take::<14>()?;
            let bytes = coap(exchange.wire(), server, &target.docpath, random).await?;
            return Ok(answered(exchange, transport, bytes, deadline));
        }
        if transport == Transport::Quic {
            return match self
                .quic
                .exchange(server, target.certified(), exchange.wire(), deadline)
                .await
            {
                Ok(bytes) => Ok(answered(exchange, transport, bytes, deadline)),
                Err(QuicError::TimedOut) => Ok(exchange.time_out(Instant::now().max(deadline))),
                Err(error) => Err(error.into()),
            };
        }
        let Some(link) = target.link(transport) else {
            let channel = udp.expect("an exchange over UDP started over UDP, which took a socket");
            // A fallback sends the query with the next ID (D27).
            if let Some(&[high, low]) = exchange.wire().get(..2) {
                channel.expect(u16::from_be_bytes([high, low]));
            }
            channel
                .send(exchange.wire())
                .await
                .map_err(ClientError::Udp)?;
            let mut exchange = exchange;
            loop {
                let deadline = exchange.deadline();
                let bytes = match channel.recv(deadline).await {
                    Ok(Some(bytes)) => bytes,
                    Ok(None) => return Ok(exchange.time_out(Instant::now().max(deadline))),
                    // Maybe another query's: the try is lost, not the exchange, unless it was the last.
                    Err(error) => {
                        return match exchange.lose(Instant::now()) {
                            Progress::Done(Err(Failure::TimedOut { .. })) => {
                                Err(ClientError::Udp(error))
                            }
                            progress => Ok(progress),
                        };
                    }
                };
                match exchange.receive(server, Transport::Udp, bytes, Instant::now()) {
                    Progress::Wait(next) => exchange = next,
                    progress => return Ok(progress),
                }
            }
        };
        match self.tcp.exchange(link, exchange.wire(), deadline).await {
            Ok(bytes) => Ok(answered(exchange, transport, bytes, deadline)),
            Err(TcpError::TimedOut) => Ok(exchange.time_out(Instant::now().max(deadline))),
            Err(error) => Err(error.into()),
        }
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
                client: self.random.borrow_mut().take()?,
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
) -> Result<Vec<u8>, ClientError> {
    Err(ClientError::NotBuilt("CoAP"))
}

/// The progress of `exchange` once `bytes` came back on its own connection or stream: nothing else comes with its
/// ID, so a response that does not match ends the wait at `deadline`.
fn answered(
    exchange: Exchange,
    transport: Transport,
    bytes: Vec<u8>,
    deadline: Instant,
) -> Progress {
    let server = exchange.server();
    match exchange.receive(server, transport, bytes, Instant::now()) {
        Progress::Wait(next) => next.time_out(deadline.max(Instant::now())),
        progress => progress,
    }
}

#[cfg(test)]
mod tests {
    use super::{RANDOM_BATCH, Random};

    /// Takes across a refill come whole, and fresh bytes are not the zeros the batch starts with.
    #[test]
    fn takes_refill_the_batch_when_short() {
        let mut random = Random {
            bytes: [0; RANDOM_BATCH],
            used: RANDOM_BATCH - 4,
        };
        assert_eq!(random.take::<4>().ok(), Some([0; 4]));
        let fresh: Vec<_> = (0..4)
            .map(|_| random.take::<8>().expect("randomness"))
            .collect();
        assert_eq!(random.used, 32);
        assert!(fresh.iter().any(|bytes| *bytes != [0; 8]));
    }
}
