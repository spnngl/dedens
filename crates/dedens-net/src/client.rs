//! The client: the sans-IO [`Exchange`] run over the UDP and TCP transports (D26, D27).
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
use std::time::{Duration, Instant};

use dedens_proto::edns::{Cookie, EdnsOption};
use dedens_proto::{EncodeError, Message};

use crate::exchange::{Exchange, Failure, Options, Progress, Response, Transport, after};
use crate::tcp::{TcpError, TcpPool};
use crate::udp::UdpChannel;

/// How long a TCP connection stays open without a query waiting, unless the server asks for less (RFC 7766
/// §6.2.3, RFC 7828 §3.2.2).
const TCP_IDLE: Duration = Duration::from_secs(10);

/// The UDP payload size of a query without EDNS, and the least one with it means (RFC 6891 §6.2.3).
const MIN_UDP_PAYLOAD: u16 = 512;

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
    /// The TCP connection failed.
    #[error("TCP")]
    Tcp(#[from] TcpError),
    /// The exchange ended without a response.
    #[error(transparent)]
    Exchange(#[from] Failure),
}

/// Sends queries and returns their responses, keeping TCP connections and cookies per server.
#[derive(Debug)]
pub struct Client {
    tcp: TcpPool,
    /// By source and server address: the client cookie and the last cookie the server sent.
    cookies: RefCell<HashMap<(IpAddr, SocketAddr), Cookies>>,
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
            tcp: TcpPool::new(TCP_IDLE),
            cookies: RefCell::default(),
        }
    }

    /// Sends `query` to `server` and returns the response, with the retries and fallbacks of `options` (D27).
    ///
    /// The query goes with a random ID, and a cookie when it has EDNS and none of its own, unless
    /// [`Options::cookies`] is off.
    ///
    /// # Errors
    ///
    /// [`ClientError`]: no randomness, a query that cannot be encoded, a socket or connection failure, or no
    /// response after all the tries.
    pub async fn exchange(
        &self,
        query: &Message<'_>,
        server: SocketAddr,
        options: &Options,
    ) -> Result<Response, ClientError> {
        let mut query = query.clone();
        let mut id = [0; 2];
        getrandom::fill(&mut id).map_err(ClientError::Random)?;
        query.header.id = u16::from_be_bytes(id);
        // The socket first: its address is the source the cookie goes with. One UDP socket for the whole exchange,
        // so a late response to an earlier try still counts (D27).
        let mut udp = None;
        let source = match options.transport {
            Transport::Udp => {
                // Room for the largest response the query asks for (RFC 6891 §6.2.3); TCP takes any larger.
                let size = query.edns.as_ref().map_or(MIN_UDP_PAYLOAD, |edns| {
                    edns.udp_payload.max(MIN_UDP_PAYLOAD)
                });
                let channel = UdpChannel::connect(server, usize::from(size))
                    .await
                    .map_err(ClientError::Udp)?;
                udp.insert(channel).local_addr().map_err(ClientError::Udp)?
            }
            Transport::Tcp => {
                let deadline = after(Instant::now(), options.timeout);
                self.tcp.local_addr(server, deadline).await?
            }
        };
        let pair = if options.cookies {
            self.add_cookie(&mut query, (source.ip(), server))?
        } else {
            None
        };
        let mut exchange = Exchange::start(query, server, *options, Instant::now())?;
        let response = loop {
            match self.step(exchange, udp.as_mut()).await? {
                Progress::Send(next) => {
                    self.keep_cookie(pair, next.cookie());
                    exchange = next;
                }
                Progress::Wait(next) => exchange = next,
                Progress::Done(done) => break done?,
            }
        };
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
        udp: Option<&mut UdpChannel>,
    ) -> Result<Progress, ClientError> {
        let server = exchange.server();
        trace!(%server, transport = ?exchange.transport(), len = exchange.wire().len(), "sending");
        match exchange.transport() {
            Transport::Udp => {
                let channel =
                    udp.expect("an exchange over UDP started over UDP, which opened the socket");
                channel
                    .send(exchange.wire())
                    .await
                    .map_err(ClientError::Udp)?;
                let mut exchange = exchange;
                loop {
                    let deadline = exchange.deadline();
                    let Some(bytes) = channel.recv(deadline).await.map_err(ClientError::Udp)?
                    else {
                        return Ok(exchange.time_out(Instant::now().max(deadline)));
                    };
                    match exchange.receive(server, Transport::Udp, bytes, Instant::now()) {
                        Progress::Wait(next) => exchange = next,
                        progress => return Ok(progress),
                    }
                }
            }
            Transport::Tcp => {
                let deadline = exchange.deadline();
                match self.tcp.exchange(server, exchange.wire(), deadline).await {
                    Ok(bytes) => Ok(
                        match exchange.receive(server, Transport::Tcp, &bytes, Instant::now()) {
                            // Nothing else comes with that ID: the wait is over.
                            Progress::Wait(next) => next.time_out(deadline.max(Instant::now())),
                            progress => progress,
                        },
                    ),
                    Err(TcpError::TimedOut) => Ok(exchange.time_out(Instant::now().max(deadline))),
                    Err(error) => Err(error.into()),
                }
            }
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
            Entry::Vacant(slot) => {
                let mut client = [0; 8];
                getrandom::fill(&mut client).map_err(ClientError::Random)?;
                slot.insert(Cookies {
                    client,
                    returned: None,
                })
            }
        };
        let cookie = cookies.returned.unwrap_or_else(|| {
            Cookie::new(cookies.client, None).expect("a client cookie alone is valid")
        });
        edns.options.push(EdnsOption::Cookie(cookie));
        Ok(Some(pair))
    }
}
