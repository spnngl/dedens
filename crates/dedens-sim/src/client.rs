//! The client: one [`Exchange`] over turmoil's UDP and TCP, as `dedens_net::client::Client::exchange` drives it
//! over compio's (D26, D27).
//!
//! Mirrored: one UDP socket for all the tries of an exchange, so a late response to an earlier try still counts;
//! a send or receive error that ends the last try is an error, not a timeout; a TCP query that finds its connection
//! closed goes again on a new one, once, and a connection that cannot be opened ends the exchange (D27); a
//! response that does not match ends the wait at the deadline; the cookies of RFC 7873 §5.3.
//!
//! Left out: connection reuse and the TCP pool, and the transports other than UDP and TCP (D133).

use std::cell::RefCell;
use std::collections::BTreeMap;
use std::net::{IpAddr, SocketAddr};
use std::rc::Rc;
use std::time::Instant;

use dedens_net::client::ClientError;
use dedens_net::exchange::{Exchange, Failure, Options, Progress, Response, SPARE_IDS};
use dedens_net::tcp::TcpError;
use dedens_proto::edns::{Cookie, EdnsOption};
use dedens_proto::{Message, Transport};
use tokio::time::timeout_at;
use turmoil::net::{TcpStream, UdpSocket};

use crate::framing;
use crate::seed::Rng;
use crate::trace::{Trace, What};

/// The transports the simulation speaks.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Carrier {
    /// UDP, falling back to TCP on a truncated response.
    Udp,
    /// TCP.
    Tcp,
}

impl From<Carrier> for Transport {
    fn from(carrier: Carrier) -> Self {
        match carrier {
            Carrier::Udp => Self::Udp,
            Carrier::Tcp => Self::Tcp,
        }
    }
}

/// The clock of the exchanges: tokio's, which turmoil advances.
pub(crate) fn now() -> Instant {
    tokio::time::Instant::now().into_std()
}

/// The cookies of one server, as the real client keeps them (RFC 7873 §5.3).
#[derive(Debug)]
struct Cookies {
    client: [u8; 8],
    /// The last cookie returned, its client cookie checked by the exchange.
    returned: Option<Cookie>,
}

/// A host's client: its IDs, those of the queries a fallback changes and its client cookies come from `rng`
/// (RFC 5452 §9.2, RFC 7873 §4.1, D114). A cookie belongs to the host and the server it is for, and a client of a
/// host that restarted starts with none. Each query it sends goes in the trace as [`What::Sent`].
#[derive(Debug, Clone)]
pub struct Client {
    rng: Rc<RefCell<Rng>>,
    cookies: Rc<RefCell<BTreeMap<SocketAddr, Cookies>>>,
    host: IpAddr,
    trace: Trace,
}

impl Client {
    /// The client of `host`, drawing from `rng`.
    #[must_use]
    pub fn new(rng: Rc<RefCell<Rng>>, host: IpAddr, trace: Trace) -> Self {
        Self {
            rng,
            cookies: Rc::default(),
            host,
            trace,
        }
    }

    /// Adds the cookie for `server` to a query with EDNS and none of its own; says whether it did.
    fn add_cookie(&self, query: &mut Message<'static>, server: SocketAddr) -> bool {
        let Some(edns) = &mut query.edns else {
            return false;
        };
        if edns
            .options
            .iter()
            .any(|option| matches!(option, EdnsOption::Cookie(_)))
        {
            return false;
        }
        let mut all = self.cookies.borrow_mut();
        let cookies = all.entry(server).or_insert_with(|| Cookies {
            client: self.rng.borrow_mut().next_u64().to_be_bytes(),
            returned: None,
        });
        let cookie = cookies.returned.unwrap_or_else(|| {
            Cookie::new(cookies.client, None).expect("a client cookie alone is valid")
        });
        edns.options.push(EdnsOption::Cookie(cookie));
        true
    }

    /// Keeps the server cookie of `cookie`, if it has one, for the next query to `server` (RFC 7873 §5.3).
    fn keep_cookie(&self, server: SocketAddr, cookie: Option<Cookie>) {
        if let Some(cookie) = cookie
            && cookie.server().is_some()
            && let Some(cookies) = self.cookies.borrow_mut().get_mut(&server)
        {
            cookies.returned = Some(cookie);
        }
    }

    /// Sends `query` to `server` over `carrier`, with the timeout, tries and fallbacks of `options`, and returns
    /// the response or why there is none. The ID of `query` is replaced by a random one.
    ///
    /// # Errors
    ///
    /// [`ClientError`] as the real client ends: [`Failure`] when no try is answered or the query cannot be
    /// encoded, and the I/O error of the socket or the connection otherwise.
    pub async fn exchange(
        &self,
        mut query: Message<'static>,
        server: SocketAddr,
        carrier: Carrier,
        options: &Options,
    ) -> Result<Response, ClientError> {
        let (id, spare_ids) = {
            let mut rng = self.rng.borrow_mut();
            (rng.next_u16(), [(); SPARE_IDS].map(|()| rng.next_u16()))
        };
        query.header.id = id;
        let cookie = options.cookies && self.add_cookie(&mut query, server);
        let mut options = *options;
        options.transport = carrier.into();
        let exchange = Exchange::start(query, server, options, spare_ids, now())?;
        let mut progress = Progress::Send(exchange);
        // One socket for the tries over UDP, as the real client keeps one.
        let mut socket = None;
        loop {
            progress = match progress {
                Progress::Send(exchange) => {
                    // A BADCOOKIE response changes the cookie of the next query.
                    if cookie {
                        self.keep_cookie(server, exchange.cookie());
                    }
                    self.sent(&exchange);
                    step(exchange, &mut socket).await?
                }
                // Waiting is done inside a step: it reads on until the deadline.
                Progress::Wait(exchange) => step(exchange, &mut socket).await?,
                Progress::Done(done) => {
                    if cookie && let Ok(response) = &done {
                        self.keep_cookie(server, response.cookie);
                    }
                    return Ok(done?);
                }
            };
        }
    }

    /// Notes the query `exchange` sends.
    fn sent(&self, exchange: &Exchange) {
        let id = exchange
            .wire()
            .first_chunk()
            .map_or(0, |id| u16::from_be_bytes(*id));
        self.trace.record(
            self.host,
            What::Sent {
                server: exchange.server(),
                id,
                sends: exchange.sends(),
                transport: exchange.transport(),
            },
        );
    }
}

/// Sends the query of `exchange` and reads until the response, or the deadline.
async fn step(exchange: Exchange, socket: &mut Option<UdpSocket>) -> Result<Progress, ClientError> {
    match exchange.transport() {
        Transport::Tcp => tcp(exchange).await,
        // The exchange starts over UDP or TCP and falls back from UDP to TCP only.
        _ => udp(exchange, socket).await,
    }
}

/// Sends the query of `exchange` over UDP and reads until the response, or the deadline. A socket error is an
/// error when it ends the last try, a lost try otherwise.
async fn udp(exchange: Exchange, socket: &mut Option<UdpSocket>) -> Result<Progress, ClientError> {
    let mut exchange = exchange;
    let socket = match socket {
        Some(socket) => socket,
        None => socket.insert(
            UdpSocket::bind("0.0.0.0:0")
                .await
                .map_err(ClientError::Udp)?,
        ),
    };
    socket
        .send_to(exchange.wire(), exchange.server())
        .await
        .map_err(ClientError::Udp)?;
    let mut buffer = vec![0; usize::from(u16::MAX)];
    loop {
        let deadline = exchange.deadline();
        match timeout_at(deadline.into(), socket.recv_from(&mut buffer)).await {
            Err(_) => return Ok(exchange.time_out(now().max(deadline))),
            Ok(Err(error)) => {
                return match exchange.lose(now()) {
                    Progress::Done(Err(Failure::TimedOut { .. })) => Err(ClientError::Udp(error)),
                    progress => Ok(progress),
                };
            }
            Ok(Ok((len, from))) => {
                let bytes = buffer.get(..len).unwrap_or_default().to_vec();
                match exchange.receive(from, Transport::Udp, bytes, now()) {
                    Progress::Wait(next) => exchange = next,
                    progress => return Ok(progress),
                }
            }
        }
    }
}

/// Sends the query of `exchange` over TCP, and takes the response, or the deadline. A response that does not
/// match ends the wait at the deadline: nothing else comes with its ID.
async fn tcp(exchange: Exchange) -> Result<Progress, ClientError> {
    let server = exchange.server();
    let deadline = exchange.deadline();
    match timeout_at(deadline.into(), over_tcp(server, exchange.wire())).await {
        Err(_) => Ok(exchange.time_out(now().max(deadline))),
        Ok(Err(error)) => Err(error.into()),
        Ok(Ok(bytes)) => Ok(
            match exchange.receive(server, Transport::Tcp, bytes, now()) {
                Progress::Wait(next) => next.time_out(deadline.max(now())),
                progress => progress,
            },
        ),
    }
}

/// The response to `wire` over a connection to `server`: a connection that closes before it is replaced once and
/// the query sent again (D27).
///
/// # Errors
///
/// [`TcpError::Connect`] when no connection opens, [`TcpError::Closed`] when two closed.
async fn over_tcp(server: SocketAddr, wire: &[u8]) -> Result<Vec<u8>, TcpError> {
    for _ in 0..2 {
        let mut stream = TcpStream::connect(server)
            .await
            .map_err(TcpError::Connect)?;
        if framing::write(&mut stream, wire).await.is_ok()
            && let Ok(bytes) = framing::read(&mut stream).await
        {
            return Ok(bytes);
        }
    }
    Err(TcpError::Closed)
}
