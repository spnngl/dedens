//! The client: one [`Exchange`] over turmoil's UDP and TCP, as `dedens_net::client::Client::exchange` drives it
//! over compio's (D26, D27).
//!
//! Left out: connection reuse, and the transports other than UDP and TCP (D133).

use std::cell::RefCell;
use std::collections::BTreeMap;
use std::net::SocketAddr;
use std::rc::Rc;
use std::time::Instant;

use dedens_net::exchange::{Exchange, Failure, Options, Progress, Response, SPARE_IDS};
use dedens_proto::edns::{Cookie, EdnsOption};
use dedens_proto::{Message, Transport};
use tokio::time::timeout_at;
use turmoil::net::{TcpStream, UdpSocket};

use crate::framing;
use crate::seed::Rng;

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
/// host that restarted starts with none.
#[derive(Debug, Clone)]
pub struct Client {
    rng: Rc<RefCell<Rng>>,
    cookies: Rc<RefCell<BTreeMap<SocketAddr, Cookies>>>,
}

impl Client {
    /// A client drawing from `rng`.
    #[must_use]
    pub fn new(rng: Rc<RefCell<Rng>>) -> Self {
        Self {
            rng,
            cookies: Rc::default(),
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
    /// [`Failure`] as [`Exchange`] ends: no response to any try, or a query that cannot be encoded.
    pub async fn exchange(
        &self,
        mut query: Message<'static>,
        server: SocketAddr,
        carrier: Carrier,
        options: &Options,
    ) -> Result<Response, Failure> {
        let (id, spare_ids) = {
            let mut rng = self.rng.borrow_mut();
            (rng.next_u16(), [(); SPARE_IDS].map(|()| rng.next_u16()))
        };
        query.header.id = id;
        let cookie = options.cookies && self.add_cookie(&mut query, server);
        let mut options = *options;
        options.transport = carrier.into();
        let mut progress =
            Progress::Send(Exchange::start(query, server, options, spare_ids, now())?);
        // One socket for the tries over UDP, as the real client keeps one.
        let mut socket = None;
        loop {
            progress = match progress {
                Progress::Send(exchange) => {
                    // A BADCOOKIE response changes the cookie of the next query.
                    if cookie {
                        self.keep_cookie(server, exchange.cookie());
                    }
                    step(exchange, &mut socket).await
                }
                // Waiting is done inside a step: it reads on until the deadline.
                Progress::Wait(exchange) => step(exchange, &mut socket).await,
                Progress::Done(done) => {
                    if cookie && let Ok(response) = &done {
                        self.keep_cookie(server, response.cookie);
                    }
                    return done;
                }
            };
        }
    }
}

/// Sends the query of `exchange` and reads until the response, or the deadline.
async fn step(exchange: Exchange, socket: &mut Option<UdpSocket>) -> Progress {
    match exchange.transport() {
        Transport::Tcp => tcp(exchange).await,
        // The exchange starts over UDP or TCP and falls back from UDP to TCP only.
        _ => udp(exchange, socket).await,
    }
}

/// Sends the query of `exchange` over UDP and reads until the response, or the deadline.
async fn udp(exchange: Exchange, socket: &mut Option<UdpSocket>) -> Progress {
    let mut exchange = exchange;
    let socket = match socket {
        Some(socket) => socket,
        None => match UdpSocket::bind("0.0.0.0:0").await {
            Ok(bound) => socket.insert(bound),
            Err(_) => return exchange.lose(now()),
        },
    };
    let server = exchange.server();
    if socket.send_to(exchange.wire(), server).await.is_err() {
        return exchange.lose(now());
    }
    let mut buffer = vec![0; usize::from(u16::MAX)];
    loop {
        let deadline = exchange.deadline();
        match timeout_at(deadline.into(), socket.recv_from(&mut buffer)).await {
            Err(_) => return exchange.time_out(now().max(deadline)),
            Ok(Err(_)) => return exchange.lose(now()),
            Ok(Ok((len, from))) => {
                let bytes = buffer.get(..len).unwrap_or_default().to_vec();
                match exchange.receive(from, Transport::Udp, bytes, now()) {
                    Progress::Wait(next) => exchange = next,
                    progress => return progress,
                }
            }
        }
    }
}

/// Sends the query of `exchange` over a new connection and reads until the response, or the deadline.
async fn tcp(exchange: Exchange) -> Progress {
    let mut exchange = exchange;
    let server = exchange.server();
    let deadline = exchange.deadline();
    let mut stream = match timeout_at(deadline.into(), TcpStream::connect(server)).await {
        Err(_) => return exchange.time_out(now().max(deadline)),
        Ok(Err(_)) => return exchange.lose(now()),
        Ok(Ok(stream)) => stream,
    };
    match timeout_at(
        deadline.into(),
        framing::write(&mut stream, exchange.wire()),
    )
    .await
    {
        Err(_) => return exchange.time_out(now().max(deadline)),
        Ok(Err(_)) => return exchange.lose(now()),
        Ok(Ok(())) => {}
    }
    loop {
        let deadline = exchange.deadline();
        match timeout_at(deadline.into(), framing::read(&mut stream)).await {
            Err(_) => return exchange.time_out(now().max(deadline)),
            Ok(Err(_)) => return exchange.lose(now()),
            Ok(Ok(bytes)) => match exchange.receive(server, Transport::Tcp, bytes, now()) {
                Progress::Wait(next) => exchange = next,
                progress => return progress,
            },
        }
    }
}
