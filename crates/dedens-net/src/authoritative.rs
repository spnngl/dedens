//! The authoritative mode of the client: one query to one of the thousands of servers a recursive resolver asks,
//! with the defences of RFC 5452 and bounded resources (D190).
//!
//! Each query over UDP opens a socket of its own, bound to a port drawn by [`Io::random`] (RFC 5452 §9.2, §10)
//! and connected to the server, and closes it on the response or the deadline; at most [`Limits::sockets`] are
//! open at once, the queries past them waiting. The query goes with a random ID, the letters of its question in a
//! random case (`0x20`, D184), EDNS advertising 1232 bytes (DNS flag day 2020) and the DO bit, and a cookie (RFC
//! 7873 §5.1) from a table of [`Limits::cookies`] pairs. A truncated response asks again over TCP (RFC 7766 §5),
//! on a connection per server kept while idle (RFC 7766 §6.2.3), [`Limits::tcp`] at most.
//!
//! A response that answers the query but for the case of its question comes from a forger or from a server that
//! does not repeat the case (draft-vixie-dnsext-dns0x20 §6.2): the query goes again over TCP (RFC 5452 §9.3), its
//! letters in the same case, and is answered whatever the case. Only that TCP response, which an off-path forger
//! cannot send, tells the server does not repeat the case: [`Quirks::no_case`]. A forged mismatch costs a TCP
//! query, never the `0x20` check.
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
use dedens_proto::{Flags, MAX_NAME_LEN, Message, Query, Question, Transport};

use crate::client::{ClientError, Random};
use crate::cookies::{COOKIES, Jar, Pair};
use crate::exchange::{
    Exchange, Failure, Options, Progress, Response, SPARE_IDS, after, give_case, random_case,
};
use crate::io::{Compio, Io, Udp};
use crate::tcp::{TcpError, TcpPool};
use crate::udp::{MAX_DATAGRAM, unspecified};

/// How long a TCP connection to a server stays open without a query waiting, as the forwarder's (D27): Unbound
/// keeps one 60 s (`tcp-reuse-timeout`, `util/config_file.c:config_create`), for queries a recursive resolver
/// sends over TCP only when UDP did not do.
const TCP_IDLE: Duration = Duration::from_secs(10);

/// The lowest port a query goes from: below it, the ports of the system''s services. Unbound
/// starts there too, leaving out the ports IANA assigned (`util/config_file.c:init_outgoing_availports`); BIND
/// takes the system's ephemeral range (`lib/dns/dispatch.c:setup_socket`).
const FIRST_PORT: u16 = 1024;

/// Ports drawn before giving up when each is taken: with [`Limits::sockets`] of 64512 ports open at most, eight
/// draws all taken by this client have a chance under 10⁻¹⁴; something else holds the ports then. BIND draws six
/// (`lib/dns/dispatch.c:setup_socket`), Unbound up to 10000 (`MAX_PORT_RETRY`, `services/outside_network.c`).
const PORT_TRIES: usize = 8;

/// The bounds of an [`Authoritative`], per thread.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Limits {
    /// UDP sockets open at once, one per query in flight; a query past them waits for one. Default: 1024, the
    /// upstream queries `dedensd` has in flight per thread (D47), each with one socket: 1024 descriptors, under the
    /// 4096 sockets Unbound opens per thread (`outgoing-range`, `util/config_file.c:config_create`).
    pub sockets: NonZeroUsize,
    /// TCP connections open at once; past them, the one idle longest closes, or the query fails with
    /// [`TcpError::Busy`] when each has a query waiting. Default: 32, three times Unbound's (`outgoing-num-tcp: 10`,
    /// `util/config_file.c:config_create`): TCP comes after a truncated response or a case mismatch, rare
    /// beside UDP.
    pub tcp: NonZeroUsize,
    /// Pairs of source address and server whose cookies are kept, the one used longest ago going first. Default:
    /// 4096, about 400 KiB.
    pub cookies: NonZeroUsize,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            sockets: NonZeroUsize::new(1024).expect("1024 is not zero"),
            tcp: NonZeroUsize::new(32).expect("32 is not zero"),
            cookies: COOKIES,
        }
    }
}

/// What a server showed of itself: the caller keeps it and passes it in with the next query to that server, which
/// [`Authoritative::query`] then adapts to. All off by default.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Quirks {
    /// It answered an EDNS query with FORMERR or NOTIMP, the question repeated and no OPT record (RFC 6891 §7): ask
    /// without EDNS.
    pub no_edns: bool,
    /// Its response over TCP had the question in another case than the query's: ask without `0x20`.
    pub no_case: bool,
    /// Its response over UDP did not do, truncated or BADCOOKIE twice, and came over TCP: ask over TCP.
    pub tcp: bool,
}

/// The response to [`Authoritative::query`], and what the server showed of itself.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct Answer {
    /// The response, its question in the case of the one asked.
    pub response: Response,
    /// The quirks passed in, with those this exchange showed.
    pub quirks: Quirks,
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

/// The end of the exchange over UDP.
enum Outcome {
    /// Its response.
    Response(Response),
    /// A response but for the case of its question, asked in the case of these bits.
    Folded([u8; 32]),
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
            tcp: TcpPool::with_io(io.clone(), TCP_IDLE).at_most(limits.tcp),
            io,
            sockets,
            cookies: RefCell::new(Jar::new(limits.cookies)),
            random: RefCell::new(Random::new()),
            scratch: RefCell::new(vec![0; MAX_DATAGRAM].into_boxed_slice()),
        }
    }

    /// Asks `server` for `question`, once, waiting `timeout` for each query sent: one, or more when the response
    /// moves it to TCP, drops EDNS or brings a fresh server cookie (D27). The query has RD clear, and its
    /// question's name in the case given comes back in [`Answer::response`]. Trying again, maybe another server,
    /// is the caller's.
    ///
    /// # Errors
    ///
    /// [`ClientError`]: no randomness, a socket that cannot be opened, a send that fails or a refusal, a TCP failure,
    /// [`TcpError::Busy`] included, and [`Failure::TimedOut`] when no socket was free before the deadline or no
    /// response came.
    pub async fn query(
        &self,
        question: Question<'_>,
        server: SocketAddr,
        quirks: Quirks,
        timeout: Duration,
    ) -> Result<Answer, ClientError> {
        let deadline = after(self.io.now(), timeout);
        let mut query = Message::query(u16::from_be_bytes(self.draw()?), question);
        query.header.flags = query.header.flags.without(Flags::RD);
        query.edns = query.edns.filter(|_| !quirks.no_edns).map(|mut edns| {
            edns.flags = edns.flags.with(EdnsFlags::DO);
            edns
        });
        let mut options = Options {
            tries: NonZeroU8::MIN,
            timeout,
            ..Options::default()
        };
        let bits = if quirks.no_case {
            None
        } else {
            Some(self.draw::<32>()?)
        };
        let (response, quirks) = if quirks.tcp {
            // Over TCP, `0x20` adds nothing: an off-path forger cannot answer.
            options.transport = Transport::Tcp;
            (self.over_tcp(query, server, options, None).await?, quirks)
        } else {
            let socket = self.open(server, deadline).await?;
            let local = socket.udp.local_addr().map_err(ClientError::Udp)?;
            let pair = self
                .cookies
                .borrow_mut()
                .add(&mut query, (local.ip(), server), || self.draw())?;
            options.random_case = bits;
            let first = self
                .exchange(query.clone(), server, options, Some(&socket.udp), pair)
                .await?;
            drop(socket);
            match first {
                Outcome::Response(response) => {
                    let tcp = response.transport == Transport::Tcp;
                    (response, Quirks { tcp, ..quirks })
                }
                Outcome::Folded(bits) => {
                    self.cased(query, server, options, &bits, pair, quirks)
                        .await?
                }
            }
        };
        // The query that got the response went without EDNS: asked so, or dropped on FORMERR or NOTIMP.
        let no_edns = Query::read(&response.query).is_ok_and(|sent| sent.edns().is_none());
        Ok(Answer {
            response,
            quirks: Quirks { no_edns, ..quirks },
        })
    }

    /// Asks `query` again over TCP after a response over UDP repeated its question in another case: its letters
    /// in the case of `bits`, and the response taken whatever its case, which tells whether the server repeats it.
    async fn cased(
        &self,
        mut query: Message<'_>,
        server: SocketAddr,
        mut options: Options,
        bits: &[u8; 32],
        pair: Option<Pair>,
        quirks: Quirks,
    ) -> Result<(Response, Quirks), ClientError> {
        let mut buf = [0; MAX_NAME_LEN];
        let given: Option<Box<[u8]>> = query
            .questions
            .first()
            .map(|question| Box::from(question.name.to_wire(&mut buf)));
        for question in &mut query.questions {
            question.name = random_case(&question.name, bits);
        }
        query.header.id = u16::from_be_bytes(self.draw()?);
        options.transport = Transport::Tcp;
        options.random_case = None;
        let mut response = self.over_tcp(query, server, options, pair).await?;
        let echoed = question_of(&response.wire) == question_of(&response.query);
        debug!(%server, echoed, "asked over TCP after a case mismatch");
        if let Some(given) = &given {
            give_case(&mut response.wire, given);
        }
        Ok((
            response,
            Quirks {
                no_case: quirks.no_case || !echoed,
                ..quirks
            },
        ))
    }

    /// Runs the exchange of `query` with `server` over TCP, without `0x20`.
    async fn over_tcp(
        &self,
        query: Message<'_>,
        server: SocketAddr,
        options: Options,
        pair: Option<Pair>,
    ) -> Result<Response, ClientError> {
        match self.exchange(query, server, options, None, pair).await? {
            Outcome::Response(response) => Ok(response),
            Outcome::Folded(_) => unreachable!("a case mismatch is looked for over UDP only"),
        }
    }

    /// Runs the exchange of `query` with `server`, over `udp` when it starts there.
    async fn exchange(
        &self,
        query: Message<'_>,
        server: SocketAddr,
        options: Options,
        udp: Option<&N::Udp>,
        pair: Option<Pair>,
    ) -> Result<Outcome, ClientError> {
        let mut spare_ids = [0; SPARE_IDS];
        for id in &mut spare_ids {
            *id = u16::from_be_bytes(self.draw()?);
        }
        let exchange = Exchange::start(query, server, options, spare_ids, self.io.now())
            .map_err(ClientError::Encode)?;
        let mut progress = Progress::Send(exchange);
        loop {
            progress = match progress {
                Progress::Done(done) => {
                    let response = done.map_err(ClientError::Exchange)?;
                    self.cookies.borrow_mut().keep(pair, response.cookie);
                    return Ok(Outcome::Response(response));
                }
                Progress::Send(next) => {
                    self.io.sending(&next);
                    self.cookies.borrow_mut().keep(pair, next.cookie());
                    match (next.transport(), udp) {
                        // A refusal (ICMP port unreachable) shows on the receive after the send; one that a
                        // later send of the same exchange sees fails the query as any error of the socket.
                        (Transport::Udp, Some(udp)) => {
                            send(udp, next.wire()).await.map_err(ClientError::Udp)?;
                            Progress::Wait(next)
                        }
                        _ => self.tcp(next).await?,
                    }
                }
                // Over TCP, the connection's response ended the wait already.
                Progress::Wait(next) => {
                    let deadline = next.deadline();
                    let received = match udp {
                        Some(udp) => self.recv(udp, deadline).await,
                        None => Ok(None),
                    };
                    let now = self.io.now();
                    if let (Some(bits), Ok(Some(bytes))) = (options.random_case, &received)
                        && folded(bytes, next.wire())
                    {
                        debug!(%server, "case mismatch: asking over TCP");
                        return Ok(Outcome::Folded(bits));
                    }
                    match received {
                        Ok(Some(bytes)) => next.receive(server, Transport::Udp, bytes, now),
                        Ok(None) => next.time_out(now.max(deadline)),
                        // A refusal too: the caller, which picks the next server, tells it from a timeout.
                        Err(error) => return Err(ClientError::Udp(error)),
                    }
                }
            };
        }
    }

    /// Sends the query of `exchange` over TCP and takes the response.
    async fn tcp(&self, exchange: Exchange) -> Result<Progress, ClientError> {
        let deadline = exchange.deadline();
        let server = exchange.server();
        match self.tcp.exchange(server, exchange.wire(), deadline).await {
            Ok(bytes) => {
                let now = self.io.now();
                Ok(match exchange.receive(server, Transport::Tcp, bytes, now) {
                    // Nothing else comes with its ID on the connection.
                    Progress::Wait(next) => next.time_out(deadline.max(now)),
                    progress => progress,
                })
            }
            Err(TcpError::TimedOut) => Ok(exchange.time_out(deadline.max(self.io.now()))),
            Err(error) => Err(ClientError::Tcp(error)),
        }
    }

    /// A UDP socket to `server` from a random port, once one is free before `deadline`.
    async fn open(
        &self,
        server: SocketAddr,
        deadline: Instant,
    ) -> Result<Socket<N::Udp>, ClientError> {
        let token = self
            .io
            .timeout_at(deadline, self.sockets.1.recv_async())
            .await;
        let Ok(Ok(())) = token else {
            debug!(%server, "no UDP socket free before the deadline");
            return Err(ClientError::Exchange(Failure::TimedOut { sends: 0 }));
        };
        let token = Token(self.sockets.0.clone());
        let mut in_use = None;
        for _ in 0..PORT_TRIES {
            let mut local = unspecified(server);
            local.set_port(self.port()?);
            match self.io.udp_bind(local).await {
                Ok(udp) => {
                    udp.connect(server).await.map_err(ClientError::Udp)?;
                    trace!(%server, %local, "socket open");
                    return Ok(Socket { udp, _token: token });
                }
                Err(error) if error.kind() == io::ErrorKind::AddrInUse => in_use = Some(error),
                Err(error) => return Err(ClientError::Udp(error)),
            }
        }
        Err(ClientError::Udp(
            in_use.unwrap_or_else(|| io::ErrorKind::AddrInUse.into()),
        ))
    }

    /// A port drawn at random from [`FIRST_PORT`] up, each as likely: a draw below is drawn again.
    fn port(&self) -> Result<u16, ClientError> {
        loop {
            let port = u16::from_be_bytes(self.draw()?);
            if port >= FIRST_PORT {
                return Ok(port);
            }
        }
    }

    /// The next datagram on `udp`, or `None` past `deadline`.
    async fn recv(&self, udp: &N::Udp, deadline: Instant) -> io::Result<Option<Vec<u8>>> {
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
                Err(error) => return Err(error),
            }
        }
    }

    /// The next `LEN` random bytes.
    fn draw<const LEN: usize>(&self) -> Result<[u8; LEN], ClientError> {
        self.random.borrow_mut().take(&self.io)
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

/// Whether `bytes` answers `query` but for the case of its question's name: QR, ID, opcode, type and class
/// those of the query, the name the same one in another case.
fn folded(bytes: &[u8], query: &[u8]) -> bool {
    let (Ok(got), Ok(sent)) = (Query::read(bytes), Query::read(query)) else {
        return false;
    };
    let (header, asked) = (got.header(), sent.header());
    header.flags.contains(Flags::QR)
        && header.id == asked.id
        && header.opcode == asked.opcode
        && got
            .question()
            .zip(sent.question())
            .is_some_and(|(got, sent)| {
                got.qtype == sent.qtype
                    && got.qclass == sent.qclass
                    && got.name == sent.name
                    && !got.name.labels().eq(sent.name.labels())
            })
}

/// The name of the question of `wire`, as its bytes.
fn question_of(wire: &[u8]) -> Option<Vec<u8>> {
    let read = Query::read(wire).ok()?;
    let question = read.question()?;
    let mut buf = [0; MAX_NAME_LEN];
    Some(question.name.to_wire(&mut buf).to_vec())
}
