//! The authoritative mode of the client: one query to one of the thousands of servers a recursive resolver asks,
//! with the defences of RFC 5452 and bounded resources (D190).
//!
//! Each query over UDP opens a socket of its own, bound to a port drawn by [`Io::random`] (RFC 5452 §9.2, §10)
//! and connected to the server, and closes it on the response, the move to TCP or the deadline; at most
//! [`Limits::sockets`] are open at once, the queries past them waiting. The query goes with a random ID, the letters
//! of its question in a random case (`0x20`, D184), EDNS advertising 1232 bytes (DNS flag day 2020) and the DO bit,
//! and a cookie (RFC 7873 §5.1) from a table of [`Limits::cookies`] pairs. A truncated response asks again over TCP
//! (RFC 7766 §5), on a connection per server kept while idle (RFC 7766 §6.2.3), [`Limits::tcp`] at most, the
//! queries past them waiting.
//!
//! A response that answers the query but for the case of its question, its cookie checked, comes from a forger or
//! from a server that does not repeat the case (draft-vixie-dnsext-dns0x20 §6.2): the query goes again over TCP
//! (RFC 5452 §9.3), its letters in the same case, and is answered whatever the case ([`CaseMismatch::Tcp`]).
//! Only that TCP response, which an off-path forger cannot send, tells the server does not repeat the case:
//! [`Quirks::no_case`]. A forged mismatch costs a TCP query, never the `0x20` check.
//!
//! An ICMP error, which anyone knowing the port can send, never ends a query: the wait goes on to the deadline,
//! and the error comes back beside the timeout only, [`ServerError::Unreachable`].
//!
//! What a server shows of itself, [`Quirks`], goes back to the caller, whose infra cache keeps it and passes it in
//! with the next query (step 07 of the recursive resolver).

#![deny(clippy::disallowed_methods)]

use std::cell::RefCell;
use std::io;
use std::net::SocketAddr;
use std::num::{NonZeroU8, NonZeroUsize};
use std::time::{Duration, Instant};

use dedens_proto::edns::EdnsFlags;
use dedens_proto::{EncodeError, Flags, Message, Query, Question, Rcode, Transport};

use crate::client::{Random, local_io};
use crate::cookies::{COOKIES, Jar, Pair};
use crate::exchange::{
    CaseMismatch, Exchange, Failure, Moved, Options, Progress, Response, SPARE_IDS,
};
use crate::io::{Compio, Io, Udp};
use crate::tcp::{TcpError, TcpPool};
use crate::udp::{MAX_DATAGRAM, unspecified};

/// How long a TCP connection to a server stays open without a query waiting, as the forwarder's (D27): Unbound
/// keeps one 60 s (`tcp-reuse-timeout`, `util/config_file.c:config_create`), for queries a recursive resolver
/// sends over TCP only when UDP failed.
const TCP_IDLE: Duration = Duration::from_secs(10);

/// The lowest port a query goes from: below it, the ports of the system's services. Unbound starts there too,
/// leaving out the ports IANA assigned (`util/config_file.c:init_outgoing_availports`); BIND takes the system's
/// ephemeral range (`lib/dns/dispatch.c:setup_socket`).
const FIRST_PORT: u16 = 1024;

/// Ports drawn before giving up when each is taken. This client holds at most [`Limits::sockets`] of the 64512
/// ports: with the default 1024, eight draws all taken by it have a chance of (1024/64512)⁸, about 4·10⁻¹⁵, so
/// something else holds the ports then. BIND draws six (`lib/dns/dispatch.c:setup_socket`), Unbound up to 10000
/// (`MAX_PORT_RETRY`, `services/outside_network.c`).
const PORT_TRIES: usize = 8;

/// The default [`Limits::sockets`].
const SOCKETS: NonZeroUsize = NonZeroUsize::new(1024).expect("1024 is not zero");

/// The default [`Limits::tcp`].
const TCP: NonZeroUsize = NonZeroUsize::new(32).expect("32 is not zero");

/// The TCP connections to one server at most, [`TcpPool::per_server`]: a server that asks for no more queries on
/// each connection holds four of the 32 by default, no more.
const TCP_PER_SERVER: NonZeroUsize = NonZeroUsize::new(4).expect("4 is not zero");

/// The bounds of an [`Authoritative`], per thread. A thread holds [`Limits::sockets`] plus [`Limits::tcp`]
/// descriptors at most, 1056 by default: the process's limit on open files must hold them for each thread
/// (D190).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Limits {
    /// UDP sockets open at once, one per query in flight; a query past them waits for one. Default: 1024, the
    /// upstream queries `dedensd` has in flight per thread (D47), each with one socket: 1024 descriptors, under the
    /// 4096 sockets Unbound opens per thread (`outgoing-range`, `util/config_file.c:config_create`).
    pub sockets: NonZeroUsize,
    /// TCP connections open at once, four to a server at most; past them, the one idle longest closes, or the
    /// query waits for one. Default: 32, three times Unbound's (`outgoing-num-tcp: 10`,
    /// `util/config_file.c:config_create`): TCP comes after a truncated response or a case mismatch, rare beside
    /// UDP.
    pub tcp: NonZeroUsize,
    /// Pairs of source address and server whose cookies are kept, the one used longest ago going first. Default:
    /// 4096, about 400 KiB.
    pub cookies: NonZeroUsize,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            sockets: SOCKETS,
            tcp: TCP,
            cookies: COOKIES,
        }
    }
}

/// What a server showed of itself: the caller keeps it and passes it in with the next query to that server, which
/// [`Authoritative::query`] then adapts to. Nothing known by default.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Quirks {
    /// What it showed of EDNS.
    pub edns: Edns,
    /// Its response over TCP had the question in another case than the query's: ask without `0x20`.
    pub no_case: bool,
    /// It answered BADCOOKIE twice over UDP, then over TCP (RFC 7873 §5.3): ask over TCP. A truncated response
    /// tells only that the answer was large, and leaves it (D190).
    pub tcp: bool,
}

/// What a server showed of EDNS (RFC 6891 §7).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum Edns {
    /// Nothing yet: ask with EDNS.
    #[default]
    Unknown,
    /// It answered a query with EDNS with an OPT record.
    Supported,
    /// It answered a query with EDNS by `rejected`, FORMERR or NOTIMP, its question repeated and no OPT record, then
    /// the query without EDNS by `answered`, NOERROR, NXDOMAIN or YXDOMAIN: ask without EDNS, so without the DO bit
    /// nor a cookie. Unbound keeps no such mark for a query that wants DNSSEC (`services/outside_network.c:3483-3505`):
    /// whether a validating resolver keeps it is its infra cache's (step 07, D190).
    Unsupported {
        /// The rcode of the response to the query with EDNS.
        rejected: Rcode,
        /// The rcode of the response to the query without.
        answered: Rcode,
    },
}

impl Quirks {
    /// These quirks, with those `response` showed.
    fn with(self, response: &Response) -> Self {
        let read = Query::read(&response.wire).ok();
        let answered = read.as_ref().map(Query::rcode);
        let edns = match (read.as_ref().and_then(Query::edns), response.edns_dropped) {
            (Some(_), _) => Edns::Supported,
            (None, Some(rejected))
                if let Some(answered) = answered
                    && [Rcode::NOERROR, Rcode::NXDOMAIN, Rcode::YXDOMAIN].contains(&answered) =>
            {
                Edns::Unsupported { rejected, answered }
            }
            (None, _) => self.edns,
        };
        Self {
            edns,
            no_case: self.no_case || response.case_changed,
            tcp: self.tcp || response.moved == Some(Moved::BadCookie),
        }
    }
}

/// The response to [`Authoritative::query`], and what the server showed of itself.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct Answer {
    /// The response, its question in the case of the one asked; [`Response::moved`] tells why it came over TCP.
    pub response: Response,
    /// The quirks passed in, with those this exchange showed.
    pub quirks: Quirks,
}

/// Why [`Authoritative::query`] got no response: ours, or the server's and the network's.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum AuthoritativeError {
    /// Ours: the server is not to blame.
    #[error(transparent)]
    Local(#[from] LocalError),
    /// The server's, or the network's on the way.
    #[error(transparent)]
    Server(#[from] ServerError),
}

/// A failure of ours: randomness, descriptors or room within [`Limits`] ran out.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum LocalError {
    /// No randomness for the ID, the port, the `0x20` bits or the cookie.
    #[error("no randomness")]
    Random(#[source] io::Error),
    /// No UDP socket free before the deadline, [`Limits::sockets`] in flight.
    #[error("no UDP socket free before the deadline")]
    NoSocket,
    /// No UDP socket bound: eight ports drawn all in use, or another error, no descriptor left or a port not allowed.
    #[error("cannot bind a UDP socket")]
    Bind(#[source] io::Error),
    /// A socket error that is not the network's, such as no buffer left.
    #[error("socket")]
    Socket(#[source] io::Error),
    /// No TCP connection free before the deadline, [`Limits::tcp`] busy, or four to the server.
    #[error("no TCP connection free before the deadline")]
    TcpBusy,
    /// The query cannot be encoded.
    #[error("cannot encode the query")]
    Encode(#[from] EncodeError),
}

/// A failure of the server, or of the network on the way.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum ServerError {
    /// No response before the deadline.
    #[error("no response after {sends} queries")]
    TimedOut {
        /// Queries sent in all.
        sends: u16,
    },
    /// No response before the deadline, responses dropped for their cookie (RFC 7873 §5.3).
    #[error(
        "no response after {sends} queries, responses with a wrong cookie dropped (RFC 7873 §5.3)"
    )]
    Forged {
        /// Queries sent in all.
        sends: u16,
    },
    /// No response before the deadline, an ICMP error received meanwhile, or no route to the server: the server
    /// or the network unreachable, or a forger knowing the port.
    #[error("no response after {sends} queries, the server unreachable: {kind}")]
    Unreachable {
        /// Queries sent in all.
        sends: u16,
        /// The error, such as [`io::ErrorKind::ConnectionRefused`] for a port unreachable.
        kind: io::ErrorKind,
    },
    /// The TCP connection failed: refused, or closed before the response.
    #[error("TCP")]
    Tcp(#[source] TcpError),
}

/// Queries to authoritative servers, from one thread: sockets, TCP connections and cookies within [`Limits`].
#[derive(Debug)]
pub struct Authoritative<N: Io = Compio> {
    io: N,
    /// One token per UDP socket allowed: a query takes one, and gives it back when its socket closes.
    sockets: (flume::Sender<()>, flume::Receiver<()>),
    tcp: TcpPool<N>,
    cookies: RefCell<Jar>,
    random: RefCell<Random>,
    /// Each datagram is read here, then copied out at its length: one buffer of the largest for all sockets.
    scratch: RefCell<Box<[u8]>>,
}

/// A UDP socket of a query, and the token it holds.
struct Socket<U> {
    udp: U,
    _token: Token,
}

/// A token of [`Authoritative::sockets`], given back when dropped.
struct Token(flume::Sender<()>);

impl Drop for Token {
    fn drop(&mut self) {
        // The channel holds every token: there is room for this one.
        let _ = self.0.try_send(());
    }
}

impl Authoritative {
    /// Nothing open yet, on compio.
    #[must_use]
    pub fn new(limits: Limits) -> Self {
        Self::with_io(Compio, limits)
    }
}

impl<N: Io> Authoritative<N> {
    /// As [`Authoritative::new`], on `io`.
    #[must_use]
    pub fn with_io(io: N, limits: Limits) -> Self {
        let sockets = flume::bounded(limits.sockets.get());
        for _ in 0..limits.sockets.get() {
            // The channel has room for each token.
            let _ = sockets.0.try_send(());
        }
        Self {
            tcp: TcpPool::with_io(io.clone(), TCP_IDLE)
                .at_most(limits.tcp)
                .per_server(TCP_PER_SERVER),
            io,
            sockets,
            cookies: RefCell::new(Jar::new(limits.cookies)),
            random: RefCell::new(Random::new()),
            scratch: RefCell::new(vec![0; MAX_DATAGRAM].into_boxed_slice()),
        }
    }

    /// Asks `server` for `question`, once, until `deadline`: the wait for a socket, the query over UDP, and its
    /// fallbacks, to TCP on a truncated response or a case mismatch, without EDNS, or with a fresh server cookie
    /// (D27), all end by then. The query has RD clear, and its question's name in the case given comes back in
    /// [`Answer::response`]. With [`Quirks::tcp`], the query goes over TCP from the start, without `0x20`, which an
    /// off-path forger cannot answer anyway, nor a cookie, the source being known to the server's handshake. Trying
    /// again, maybe another server, is the caller's.
    ///
    /// # Errors
    ///
    /// [`AuthoritativeError::Local`] when the query could not go or wait, [`AuthoritativeError::Server`] when no
    /// response came by `deadline` or the TCP connection failed.
    pub async fn query(
        &self,
        question: Question<'_>,
        server: SocketAddr,
        quirks: Quirks,
        deadline: Instant,
    ) -> Result<Answer, AuthoritativeError> {
        let mut query = Message::query(u16::from_be_bytes(self.draw()?), question);
        query.header.flags = query.header.flags.without(Flags::RD);
        query.edns = query
            .edns
            .filter(|_| !matches!(quirks.edns, Edns::Unsupported { .. }))
            .map(|mut edns| {
                edns.flags = edns.flags.with(EdnsFlags::DO);
                edns
            });
        let mut options = Options {
            tries: NonZeroU8::MIN,
            timeout: deadline.saturating_duration_since(self.io.now()),
            case_mismatch: CaseMismatch::Tcp,
            ..Options::default()
        };
        let response = if quirks.tcp {
            options.transport = Transport::Tcp;
            self.exchange(query, server, options, None, None, deadline)
                .await?
        } else {
            let socket = self.open(server, deadline).await?;
            let local = socket.udp.local_addr().map_err(LocalError::Socket)?;
            let pair = self
                .cookies
                .borrow_mut()
                .add(&mut query, (local.ip(), server), || self.draw())?;
            if !quirks.no_case {
                options.random_case = Some(self.draw()?);
            }
            self.exchange(query, server, options, Some(socket), pair, deadline)
                .await?
        };
        Ok(Answer {
            quirks: quirks.with(&response),
            response,
        })
    }

    /// Runs the exchange of `query` with `server` until `deadline`, over `socket` while it stays on UDP: the socket
    /// closes when the query moves to TCP.
    async fn exchange(
        &self,
        query: Message<'_>,
        server: SocketAddr,
        options: Options,
        mut socket: Option<Socket<N::Udp>>,
        pair: Option<Pair>,
        deadline: Instant,
    ) -> Result<Response, AuthoritativeError> {
        let mut spare_ids = [0; SPARE_IDS];
        for id in &mut spare_ids {
            *id = u16::from_be_bytes(self.draw()?);
        }
        let exchange = Exchange::start(query, server, options, spare_ids, self.io.now())
            .map_err(LocalError::Encode)?;
        // The last ICMP error, told beside the timeout only.
        let mut unreachable = None;
        let mut progress = Progress::Send(exchange);
        loop {
            progress = match progress {
                Progress::Done(Ok(response)) => {
                    self.cookies.borrow_mut().keep(pair, response.cookie);
                    return Ok(response);
                }
                Progress::Done(Err(failure)) => {
                    return Err(match (failure, unreachable) {
                        (Failure::Encode(error), _) => LocalError::Encode(error).into(),
                        (Failure::Forged { sends }, _) => ServerError::Forged { sends }.into(),
                        (Failure::TimedOut { sends }, Some(kind)) => {
                            ServerError::Unreachable { sends, kind }.into()
                        }
                        (Failure::TimedOut { sends }, None) => {
                            ServerError::TimedOut { sends }.into()
                        }
                    });
                }
                Progress::Send(next) => {
                    self.io.sending(&next);
                    self.cookies.borrow_mut().keep(pair, next.cookie());
                    if next.transport() != Transport::Udp {
                        socket = None;
                    }
                    match &socket {
                        Some(socket) => {
                            match send(&socket.udp, next.wire()).await {
                                Ok(()) => {}
                                // An ICMP error of a send before: as on the receive.
                                Err(error) if !local_io(&error) => unreachable = Some(error.kind()),
                                Err(error) => return Err(LocalError::Socket(error).into()),
                            }
                            Progress::Wait(next)
                        }
                        None => self.tcp(next, deadline).await?,
                    }
                }
                // Over UDP only: over TCP, the connection's response ended the wait already.
                Progress::Wait(next) => {
                    let until = next.deadline().min(deadline);
                    let received = match &socket {
                        Some(socket) => self
                            .recv(&socket.udp, until, &mut unreachable)
                            .await
                            .map_err(LocalError::Socket)?,
                        None => None,
                    };
                    let now = self.io.now();
                    match received {
                        Some(bytes) => next.receive(server, Transport::Udp, bytes, now),
                        None => next.lose(now.max(until)),
                    }
                }
            };
        }
    }

    /// Sends the query of `exchange` over TCP and takes the response, until its deadline or `deadline`.
    async fn tcp(
        &self,
        exchange: Exchange,
        deadline: Instant,
    ) -> Result<Progress, AuthoritativeError> {
        let server = exchange.server();
        let until = exchange.deadline().min(deadline);
        match self.tcp.exchange(server, exchange.wire(), until).await {
            Ok(bytes) => {
                let now = self.io.now();
                Ok(match exchange.receive(server, Transport::Tcp, bytes, now) {
                    // Nothing else comes with its ID on the connection.
                    Progress::Wait(next) => next.lose(now),
                    progress => progress,
                })
            }
            Err(TcpError::TimedOut) => Ok(exchange.lose(self.io.now())),
            Err(TcpError::Busy) => Err(LocalError::TcpBusy.into()),
            Err(TcpError::Connect(error)) if local_io(&error) => {
                Err(LocalError::Socket(error).into())
            }
            Err(error) => Err(ServerError::Tcp(error).into()),
        }
    }

    /// A UDP socket to `server` from a random port, once one is free before `deadline`.
    async fn open(
        &self,
        server: SocketAddr,
        deadline: Instant,
    ) -> Result<Socket<N::Udp>, AuthoritativeError> {
        let token = self
            .io
            .timeout_at(deadline, self.sockets.1.recv_async())
            .await;
        let Ok(Ok(())) = token else {
            debug!(%server, "no UDP socket free before the deadline");
            return Err(LocalError::NoSocket.into());
        };
        let token = Token(self.sockets.0.clone());
        let mut in_use = None;
        for _ in 0..PORT_TRIES {
            let mut local = unspecified(server);
            local.set_port(self.port()?);
            match self.io.udp_bind(local).await {
                Ok(udp) => {
                    return match udp.connect(server).await {
                        Ok(()) => {
                            trace!(%server, %local, "socket open");
                            Ok(Socket { udp, _token: token })
                        }
                        Err(error) if local_io(&error) => Err(LocalError::Socket(error).into()),
                        // No route to the server.
                        Err(error) => Err(ServerError::Unreachable {
                            sends: 0,
                            kind: error.kind(),
                        }
                        .into()),
                    };
                }
                Err(error) if error.kind() == io::ErrorKind::AddrInUse => in_use = Some(error),
                // A port not allowed, as one Windows reserves or SELinux denies, is not drawn again: unlike a port in
                // use, nothing tells another would do. Unbound draws again on a port in use only.
                Err(error) => return Err(LocalError::Bind(error).into()),
            }
        }
        Err(LocalError::Bind(in_use.unwrap_or_else(|| io::ErrorKind::AddrInUse.into())).into())
    }

    /// A port drawn at random from [`FIRST_PORT`] up, each as likely: a draw below is drawn again.
    fn port(&self) -> Result<u16, LocalError> {
        loop {
            let port = u16::from_be_bytes(self.draw()?);
            if port >= FIRST_PORT {
                return Ok(port);
            }
        }
    }

    /// The next datagram on `udp`, or `None` past `deadline`. An ICMP error, such as a port unreachable, goes in
    /// `unreachable` and the wait goes on (Unbound's `util/netevent.c:comm_point_udp_callback`).
    async fn recv(
        &self,
        udp: &N::Udp,
        deadline: Instant,
        unreachable: &mut Option<io::ErrorKind>,
    ) -> io::Result<Option<Vec<u8>>> {
        loop {
            match self.io.timeout_at(deadline, udp.readable()).await {
                Err(_) => return Ok(None),
                Ok(ready) => ready?,
            }
            let mut scratch = self.scratch.borrow_mut();
            match udp.try_recv(&mut scratch) {
                Ok(len) => return Ok(Some(scratch[..len].to_vec())),
                Err(error)
                    if matches!(
                        error.kind(),
                        io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted
                    ) => {}
                Err(error) if !local_io(&error) => {
                    debug!(error = %error, "ICMP error: waiting on");
                    *unreachable = Some(error.kind());
                }
                Err(error) => return Err(error),
            }
        }
    }

    /// The next `LEN` random bytes.
    fn draw<const LEN: usize>(&self) -> Result<[u8; LEN], LocalError> {
        self.random
            .borrow_mut()
            .take(&self.io)
            .map_err(LocalError::Random)
    }
}

/// Sends `wire` whole on `udp`.
async fn send(udp: &impl Udp, wire: &[u8]) -> io::Result<()> {
    let compio::BufResult(sent, _) = udp.send(wire.to_vec()).await;
    if sent? == wire.len() {
        Ok(())
    } else {
        Err(io::ErrorKind::WriteZero.into())
    }
}
