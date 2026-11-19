//! The authoritative mode on the loopback address (D190): a port per query (RFC 5452 §9.2), forged responses
//! dropped (RFC 5452 §9.1) and `0x20` kept against them (draft-vixie-dnsext-dns0x20, RFC 5452 §9.3), ICMP errors
//! waited out, EDNS dropped (RFC 6891 §7), TC to TCP (RFC 7766 §5), BADCOOKIE to TCP (RFC 7873 §5.3), and the
//! bounds on sockets and connections.
//!
//! The server answers as `ns1.google.com` answered `google.com. A` (`testdata/recursion/unsigned.yaml`, D188). A
//! forger answers with the referral `a.gtld-servers.net` gave for it: a real response, but not this server's.

use std::cell::RefCell;
use std::collections::HashSet;
use std::hash::{BuildHasher as _, RandomState};
use std::io::{self, Read as _, Write as _};
use std::net::{IpAddr, Ipv4Addr, SocketAddr, TcpListener, UdpSocket};
use std::num::NonZeroUsize;
use std::rc::Rc;
use std::sync::{Arc, LazyLock, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use compio::BufResult;
use compio::buf::{IoBuf, IoBufMut};
use compio::net::TcpStream;
use dedens_net::authoritative::{
    Authoritative, AuthoritativeError, Edns, Limits, LocalError, Quirks, SERVER_FLOOR, ServerError,
};
use dedens_net::exchange::Moved;
use dedens_net::io::{Compio, Io, TimedOut, Udp};
use dedens_net::tcp::{TcpError, frame};
use dedens_proto::edns::{Cookie, EdnsFlags, EdnsOption};
use dedens_proto::{Flags, Message, Name, Question, Rcode, RecordType, Transport};
use dedens_testkit::recursion::{self, Authorities, Resolution};
use futures_util::future::join_all;
use rustix::io::Errno;

use crate::util::loopback::CLOSED;
use crate::util::{cookie_of, response, wire};

/// How long each query may take.
const TIMEOUT: Duration = Duration::from_secs(5);

/// The ports a query may go from.
const PORTS: std::ops::RangeInclusive<u16> = 1024..=65535;

/// `ns1.google.com`, authoritative for `google.com`.
const GOOGLE: IpAddr = IpAddr::V4(Ipv4Addr::new(216, 239, 32, 10));

/// `a.gtld-servers.net`, authoritative for `com`.
const COM: IpAddr = IpAddr::V4(Ipv4Addr::new(192, 5, 6, 30));

/// A server of `microsoft.com`, whose answer to `microsoft.com. TXT` is truncated over UDP.
const MICROSOFT: IpAddr = IpAddr::V4(Ipv4Addr::new(150, 171, 10, 39));

/// The captures of the servers above.
static AUTHORITIES: LazyLock<Authorities> = LazyLock::new(|| {
    let resolutions = [Resolution::read("unsigned"), Resolution::read("truncated")];
    Authorities::new(&resolutions)
});

fn deadline() -> Instant {
    Instant::now() + TIMEOUT
}

fn google() -> Question<'static> {
    Question::new("google.com.".parse().expect("a name"), RecordType::A)
}

/// The real response to `query`, its ID and question the query's.
fn real(query: &[u8]) -> Vec<u8> {
    AUTHORITIES.answer(GOOGLE, recursion::Transport::Udp, query)
}

/// The response of another server to `query`: a forger's.
fn forged(query: &[u8]) -> Vec<u8> {
    AUTHORITIES.answer(COM, recursion::Transport::Udp, query)
}

/// The end of the question of `wire`: its name, type and class.
fn question_end(wire: &[u8]) -> usize {
    let mut at = 12;
    while wire[at] != 0 {
        at += usize::from(wire[at]) + 1;
    }
    at + 1 + 4
}

/// `response` with the letters of its question's name in the other case: changed by the test.
fn swap_case(mut response: Vec<u8>) -> Vec<u8> {
    let end = question_end(&response) - 4;
    for byte in &mut response[12..end] {
        if byte.is_ascii_lowercase() {
            byte.make_ascii_uppercase();
        } else if byte.is_ascii_uppercase() {
            byte.make_ascii_lowercase();
        }
    }
    response
}

/// `response` with the letters of its question's name lowercased, as a server that does not repeat the case
/// answers: changed by the test.
fn lowercase(mut response: Vec<u8>) -> Vec<u8> {
    let end = question_end(&response) - 4;
    response[12..end].make_ascii_lowercase();
    response
}

/// `response` cut to its header and question, with `rcode` and no OPT record (RFC 6891 §7): changed by the test.
fn cut(response: &[u8], rcode: Rcode) -> Vec<u8> {
    let mut cut = response[..question_end(response)].to_vec();
    cut[3] = (cut[3] & 0xf0) | (u8::try_from(rcode.0).expect("a header rcode") & 0x0f);
    cut[6..12].fill(0);
    cut
}

/// `response` cut to its header and question, TC set: changed by the test.
fn truncated(response: &[u8]) -> Vec<u8> {
    let mut truncated = cut(response, Rcode::NOERROR);
    truncated[2] |= 0x02;
    truncated
}

/// `response` without its OPT record, as a server not knowing EDNS answers: changed by the test.
fn without_edns(response: &[u8]) -> Vec<u8> {
    let mut message = decode(response);
    message.edns = None;
    wire(&message)
}

/// Whether `query` has an OPT record: the only additional record a query of these tests carries.
fn has_edns(query: &[u8]) -> bool {
    query[10..12] != [0, 0]
}

/// Where a datagram comes from.
#[derive(Clone, Copy)]
enum From {
    /// The server's port.
    Server,
    /// Another port of the same address: a forger.
    Elsewhere,
}

/// A server over UDP and TCP on one port of the loopback address: each UDP query gets the datagrams of `udp`, in
/// order, and each TCP query the response of `tcp`, one connection after the other. Its threads run until the
/// test process exits.
fn server(
    udp: impl Fn(&[u8]) -> Vec<(From, Vec<u8>)> + Send + 'static,
    tcp: impl Fn(&[u8]) -> Vec<u8> + Send + Sync + 'static,
) -> SocketAddr {
    let (socket, listener) = loop {
        let socket = UdpSocket::bind("127.0.0.1:0").expect("a UDP socket");
        if let Ok(listener) = TcpListener::bind(socket.local_addr().expect("bound")) {
            break (socket, listener);
        }
    };
    let addr = socket.local_addr().expect("bound");
    let elsewhere = UdpSocket::bind("127.0.0.1:0").expect("a UDP socket");
    thread::spawn(move || {
        let mut buf = vec![0; 65535];
        while let Ok((len, client)) = socket.recv_from(&mut buf) {
            for (from, datagram) in udp(&buf[..len]) {
                let sender = match from {
                    From::Server => &socket,
                    From::Elsewhere => &elsewhere,
                };
                sender.send_to(&datagram, client).expect("sent");
            }
        }
    });
    thread::spawn(move || {
        for mut stream in listener.incoming().flatten() {
            let mut len = [0; 2];
            while stream.read_exact(&mut len).is_ok() {
                let mut query = vec![0; usize::from(u16::from_be_bytes(len))];
                stream.read_exact(&mut query).expect("a whole query");
                let response = frame(&tcp(&query)).expect("under 64 KiB");
                // The client may have given up meanwhile.
                let _ = stream.write_all(&response);
            }
        }
    });
    addr
}

/// A server answering as `ns1.google.com` over both transports, after `delay`.
fn google_server(delay: Duration) -> SocketAddr {
    server(
        move |query| {
            thread::sleep(delay);
            vec![(From::Server, real(query))]
        },
        move |query| {
            thread::sleep(delay);
            real(query)
        },
    )
}

/// A server that never answers.
fn silent() -> SocketAddr {
    server(|_| Vec::new(), |_| unreachable!("all over UDP"))
}

/// The queries a server got, in order.
type Queries = Arc<Mutex<Vec<Vec<u8>>>>;

/// The response a server gives to a query.
type Respond = fn(&[u8]) -> Vec<u8>;

/// Records each query in order.
fn recorder() -> (Queries, impl Fn(&[u8]) + Clone + Send + Sync + 'static) {
    let queries = Arc::new(Mutex::new(Vec::new()));
    let record = {
        let queries = Arc::clone(&queries);
        move |query: &[u8]| queries.lock().expect("not poisoned").push(query.to_vec())
    };
    (queries, record)
}

/// What [`Watched`] saw.
#[derive(Debug, Default)]
struct Seen {
    /// The port of each UDP socket bound, in order.
    ports: Vec<u16>,
    /// The UDP sockets open now.
    open: usize,
    /// The most open at once.
    most: usize,
    /// The errors the next binds fail with, in order, before any socket is bound: a port another program holds.
    failing: Vec<io::ErrorKind>,
    /// The binds tried, failed ones included.
    binds: usize,
    /// The errors the next receives on a socket fail with, in order, before any datagram is read.
    recv_errors: Vec<io::Error>,
    /// The errors the next waits for a socket to be readable fail with, in order.
    readable_errors: Vec<io::Error>,
    /// The errors the next sends on a socket fail with, in order, sending nothing.
    send_errors: Vec<io::Error>,
    /// The errors the next connects, of a UDP socket or a TCP stream, fail with, in order.
    connect_errors: Vec<io::ErrorKind>,
}

/// Compio, its UDP sockets counted and its randomness from a seed.
#[derive(Debug, Clone)]
struct Watched {
    seen: Rc<RefCell<Seen>>,
    /// The state of `SplitMix64`.
    state: Rc<RefCell<u64>>,
}

impl Watched {
    fn new() -> Self {
        // A seed of its own: one shared by the tests running at once, here or in another run of them, would draw
        // the same ports at once.
        let seed = RandomState::new().hash_one(());
        // Shown with the failure of the test, to replay it.
        eprintln!("Watched::seeded({seed:#x})");
        Self::seeded(seed)
    }

    /// Drawing from `seed`, the same ports at each run.
    fn seeded(seed: u64) -> Self {
        Self {
            seen: Rc::default(),
            state: Rc::new(RefCell::new(seed)),
        }
    }
}

impl Io for Watched {
    type Udp = WatchedUdp;
    type Stream = TcpStream;
    type Listener = compio::net::TcpListener;
    type Task = <Compio as Io>::Task;

    fn now(&self) -> Instant {
        Compio.now()
    }

    fn spawn(&self, task: impl Future<Output = ()> + 'static) -> Self::Task {
        Compio.spawn(task)
    }

    fn detach(&self, task: impl Future<Output = ()> + 'static) {
        Compio.detach(task);
    }

    async fn timeout_at<F: Future>(
        &self,
        deadline: Instant,
        future: F,
    ) -> Result<F::Output, TimedOut> {
        Compio.timeout_at(deadline, future).await
    }

    fn random(&self, bytes: &mut [u8]) -> io::Result<()> {
        let mut state = self.state.borrow_mut();
        for chunk in bytes.chunks_mut(8) {
            // `SplitMix64` (Steele, Lea, Flood 2014).
            *state = state.wrapping_add(0x9e37_79b9_7f4a_7c15);
            let mut z = *state;
            z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
            z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
            z ^= z >> 31;
            chunk.copy_from_slice(&z.to_le_bytes()[..chunk.len()]);
        }
        Ok(())
    }

    async fn udp_bind(&self, addr: SocketAddr) -> io::Result<WatchedUdp> {
        {
            let mut seen = self.seen.borrow_mut();
            seen.binds += 1;
            if !seen.failing.is_empty() {
                return Err(seen.failing.remove(0).into());
            }
        }
        let udp = Compio.udp_bind(addr).await?;
        let mut seen = self.seen.borrow_mut();
        seen.ports.push(udp.local_addr()?.port());
        seen.open += 1;
        seen.most = seen.most.max(seen.open);
        Ok(WatchedUdp {
            udp,
            seen: Rc::clone(&self.seen),
        })
    }

    async fn tcp_connect(&self, addr: SocketAddr) -> io::Result<TcpStream> {
        let failing = {
            let mut seen = self.seen.borrow_mut();
            (!seen.connect_errors.is_empty()).then(|| seen.connect_errors.remove(0))
        };
        match failing {
            Some(kind) => Err(kind.into()),
            None => Compio.tcp_connect(addr).await,
        }
    }
}

/// A compio UDP socket, counted while open.
#[derive(Debug)]
struct WatchedUdp {
    udp: <Compio as Io>::Udp,
    seen: Rc<RefCell<Seen>>,
}

impl Drop for WatchedUdp {
    fn drop(&mut self) {
        self.seen.borrow_mut().open -= 1;
    }
}

impl Udp for WatchedUdp {
    type Datagram = <<Compio as Io>::Udp as Udp>::Datagram;

    fn local_addr(&self) -> io::Result<SocketAddr> {
        self.udp.local_addr()
    }

    async fn connect(&self, addr: SocketAddr) -> io::Result<()> {
        let failing = {
            let mut seen = self.seen.borrow_mut();
            (!seen.connect_errors.is_empty()).then(|| seen.connect_errors.remove(0))
        };
        match failing {
            Some(kind) => Err(kind.into()),
            None => self.udp.connect(addr).await,
        }
    }

    async fn recv<B: IoBufMut>(&self, buffer: B) -> BufResult<usize, B> {
        self.udp.recv(buffer).await
    }

    async fn readable(&self) -> io::Result<()> {
        let failing = {
            let mut seen = self.seen.borrow_mut();
            (!seen.readable_errors.is_empty()).then(|| seen.readable_errors.remove(0))
        };
        match failing {
            Some(error) => Err(error),
            None => self.udp.readable().await,
        }
    }

    fn try_recv(&self, buffer: &mut [u8]) -> io::Result<usize> {
        let mut seen = self.seen.borrow_mut();
        if seen.recv_errors.is_empty() {
            self.udp.try_recv(buffer)
        } else {
            Err(seen.recv_errors.remove(0))
        }
    }

    async fn send<B: IoBuf>(&self, buffer: B) -> BufResult<usize, B> {
        let failing = {
            let mut seen = self.seen.borrow_mut();
            (!seen.send_errors.is_empty()).then(|| seen.send_errors.remove(0))
        };
        match failing {
            Some(error) => BufResult(Err(error), buffer),
            None => self.udp.send(buffer).await,
        }
    }

    fn recv_multi(&self) -> impl futures_util::Stream<Item = io::Result<Self::Datagram>> {
        Udp::recv_multi(&self.udp)
    }

    async fn send_to<B: IoBuf>(&self, buffer: B, peer: SocketAddr) -> BufResult<usize, B> {
        self.udp.send_to(buffer, peer).await
    }

    fn try_send_to(&self, buffer: &[u8], peer: SocketAddr) -> io::Result<usize> {
        self.udp.try_send_to(buffer, peer)
    }
}

fn client(limits: Limits) -> (Authoritative<Watched>, Rc<RefCell<Seen>>) {
    let io = Watched::new();
    let seen = Rc::clone(&io.seen);
    (Authoritative::with_io(io, limits), seen)
}

fn decode(wire: &[u8]) -> Message<'static> {
    Message::decode(wire)
        .expect("a message")
        .message
        .into_owned()
}

/// The quirks of a server known to answer with EDNS, and nothing else.
fn with_edns() -> Quirks {
    Quirks {
        edns: Edns::Supported,
        ..Quirks::default()
    }
}

/// The query: RD clear, EDNS of 1232 bytes with DO and a cookie, the question in a random case (RFC 5452 §9.3);
/// the response comes back in the case asked, its sections the server's.
#[compio::test]
async fn a_query_asks_as_a_resolver_asks_an_authoritative_server() {
    let (queries, record) = recorder();
    let addr = server(
        move |query| {
            record(query);
            vec![(From::Server, real(query))]
        },
        |_| unreachable!("all over UDP"),
    );
    // A fixed seed: one draw in 2^9 leaves the nine letters of `google.com.` as they were.
    let client = Authoritative::with_io(Watched::seeded(0x0020), Limits::default());
    let answer = client
        .query(google(), addr, Quirks::default(), deadline())
        .await
        .expect("answered");
    let queries = queries.lock().expect("not poisoned");
    let [query] = queries.as_slice() else {
        panic!("not one query: {queries:?}");
    };
    let query = decode(query);
    assert!(!query.header.flags.contains(Flags::RD));
    let edns = query.edns.as_ref().expect("EDNS");
    assert_eq!(edns.udp_payload, 1232);
    assert!(edns.flags.contains(EdnsFlags::DO));
    assert!(
        edns.options
            .iter()
            .any(|option| matches!(option, EdnsOption::Cookie(_)))
    );
    let asked = &query.questions[0].name;
    assert!(!asked.labels().eq(google().name.labels()), "0x20: {asked}");
    assert_eq!(
        (answer.response.transport, answer.response.moved),
        (Transport::Udp, None)
    );
    let response = decode(&answer.response.wire);
    assert!(
        response.questions[0]
            .name
            .labels()
            .eq(google().name.labels())
    );
    let captured = AUTHORITIES.answer(GOOGLE, recursion::Transport::Udp, &wire(&query));
    assert_eq!(response.answer, decode(&captured).answer);
    assert_eq!(answer.quirks, with_edns());
}

/// RFC 5452 §9.2: each query goes from a port of its own, drawn from the whole range. The randomness is
/// [`Watched`]'s, from a fixed seed: this checks how a port is drawn from random bytes, not the system's
/// randomness.
#[compio::test]
async fn ports_differ_from_query_to_query() {
    let addr = google_server(Duration::ZERO);
    let io = Watched::seeded(0x5eed);
    let seen = Rc::clone(&io.seen);
    let client = Authoritative::with_io(io, Limits::default());
    for _ in 0..1000 {
        client
            .query(google(), addr, with_edns(), deadline())
            .await
            .expect("answered");
    }
    let ports = std::mem::take(&mut seen.borrow_mut().ports);
    assert_eq!(ports.len(), 1000);
    assert!(ports.iter().all(|port| PORTS.contains(port)));
    assert!(ports.windows(2).all(|pair| pair[0] != pair[1]));
    // Each of the 63 blocks of 1024 ports holds one, the lowest and the highest included: 1000 draws miss a block
    // with a chance of 63·(62/63)¹⁰⁰⁰, about 7·10⁻⁶.
    let blocks: HashSet<u16> = ports.iter().map(|port| port / 1024).collect();
    assert_eq!(blocks.len(), PORTS.len() / 1024, "{blocks:?}");
    let (low, high) = (ports.iter().min(), ports.iter().max());
    assert!(
        low < Some(&4096) && high > Some(&61440),
        "{low:?}..{high:?}"
    );
}

/// RFC 5452 §9.1: a response from another port comes first, the server's after; the connected socket drops the
/// forged one.
#[compio::test]
async fn a_response_from_another_port_is_dropped() {
    let addr = server(
        |query| {
            vec![
                (From::Elsewhere, forged(query)),
                (From::Server, real(query)),
            ]
        },
        |_| unreachable!("all over UDP"),
    );
    let (client, _) = client(Limits::default());
    let answer = client
        .query(google(), addr, Quirks::default(), deadline())
        .await
        .expect("answered");
    assert_eq!(answer.response.transport, Transport::Udp);
    assert_eq!(
        decode(&answer.response.wire).answer,
        decode(&real(&answer.response.query)).answer
    );
}

/// RFC 5452 §9.3: a forged response with the question in another case, a referral, FORMERR or TC, asks over TCP,
/// where the server repeats the case: the server's response is taken, and neither `0x20` nor EDNS is given up.
#[compio::test]
async fn a_forged_case_mismatch_moves_to_tcp_and_gives_nothing_up() {
    let forgeries: [Respond; 3] = [
        forged,
        |query| cut(&real(query), Rcode::FORMERR),
        |query| truncated(&real(query)),
    ];
    for forgery in forgeries {
        let addr = server(
            move |query| vec![(From::Server, swap_case(forgery(query)))],
            real,
        );
        let (client, _) = client(Limits::default());
        let answer = client
            .query(google(), addr, Quirks::default(), deadline())
            .await
            .expect("answered");
        assert_eq!(
            (answer.response.transport, answer.response.moved),
            (Transport::Tcp, Some(Moved::Case))
        );
        assert_eq!(
            decode(&answer.response.wire).answer,
            decode(&real(&answer.response.query)).answer
        );
        assert_eq!(answer.quirks, with_edns());
    }
}

/// A server that lowercases the question (draft-vixie-dnsext-dns0x20 §6.2) is answered over TCP and marked; the
/// next query, told of it, goes over UDP without `0x20`.
#[compio::test]
async fn a_server_not_repeating_the_case_is_marked_over_tcp() {
    let addr = server(
        |query| vec![(From::Server, lowercase(real(query)))],
        |query| lowercase(real(query)),
    );
    // A fixed seed: one draw in 2^9 is all lowercase, which the server repeats.
    let client = Authoritative::with_io(Watched::seeded(0x0020), Limits::default());
    let question = Question::new(
        Name::from_labels([b"Google".as_slice(), b"COM"]).expect("a name"),
        RecordType::A,
    );
    let answer = client
        .query(question.clone(), addr, Quirks::default(), deadline())
        .await
        .expect("answered");
    assert_eq!(
        (answer.response.transport, answer.response.moved),
        (Transport::Tcp, Some(Moved::Case))
    );
    assert!(answer.quirks.no_case);
    assert!(
        decode(&answer.response.wire).questions[0]
            .name
            .labels()
            .eq(question.name.labels())
    );
    let again = client
        .query(question, addr, answer.quirks, deadline())
        .await
        .expect("answered");
    assert_eq!(again.response.transport, Transport::Udp);
}

/// D114: a response over TCP without its question, as a FORMERR may come, tells nothing of the case.
#[compio::test]
async fn a_tcp_response_without_the_question_marks_nothing() {
    let addr = server(
        |query| vec![(From::Server, swap_case(forged(query)))],
        |query| {
            let mut formerr = cut(&real(query), Rcode::FORMERR);
            formerr.truncate(12);
            formerr[4..6].fill(0);
            formerr
        },
    );
    let (client, _) = client(Limits::default());
    let answer = client
        .query(google(), addr, Quirks::default(), deadline())
        .await
        .expect("answered");
    assert_eq!(answer.response.moved, Some(Moved::Case));
    assert_eq!(answer.quirks, Quirks::default());
}

/// One send, waiting until the deadline, even past the 5 s an exchange waits by default: trying again is the
/// caller's.
#[compio::test]
async fn a_silent_server_costs_one_send_until_the_deadline() {
    let addr = silent();
    let (client, _) = client(Limits::default());
    let start = Instant::now();
    let wait = Duration::from_millis(5500);
    let silence = client
        .query(google(), addr, Quirks::default(), start + wait)
        .await;
    assert!(
        matches!(
            silence,
            Err(AuthoritativeError::Server(ServerError::TimedOut {
                sends: 1
            }))
        ),
        "{silence:?}"
    );
    assert!((wait..wait + Duration::from_secs(1)).contains(&start.elapsed()));
}

/// A port taken is drawn again, 8 times at most; another error of the bind, as a port not allowed, fails the
/// query at once.
#[compio::test]
async fn a_port_taken_is_drawn_again() {
    let addr = google_server(Duration::ZERO);
    let (client, seen) = client(Limits::default());
    seen.borrow_mut().failing = vec![io::ErrorKind::AddrInUse; 7];
    client
        .query(google(), addr, with_edns(), deadline())
        .await
        .expect("answered");
    assert_eq!((seen.borrow().binds, seen.borrow().ports.len()), (8, 1));
    for (kind, binds) in [
        (io::ErrorKind::AddrInUse, 8),
        (io::ErrorKind::PermissionDenied, 1),
    ] {
        {
            let mut watched = seen.borrow_mut();
            watched.failing = vec![kind; 8];
            watched.binds = 0;
        }
        let failed = client.query(google(), addr, with_edns(), deadline()).await;
        assert!(
            matches!(&failed, Err(AuthoritativeError::Local(LocalError::Bind(error))) if error.kind() == kind),
            "{failed:?}"
        );
        assert_eq!(seen.borrow().binds, binds);
    }
}

/// An ICMP error, which a forger knowing the port can send, does not end the query: a closed port is waited on
/// until the deadline, and its error told beside the timeout.
#[compio::test]
async fn an_icmp_error_waits_until_the_deadline() {
    let (client, _) = client(Limits::default());
    let start = Instant::now();
    let wait = Duration::from_millis(300);
    let refused = client
        .query(google(), CLOSED, Quirks::default(), start + wait)
        .await;
    assert!(
        matches!(
            refused,
            Err(AuthoritativeError::Server(ServerError::Unreachable {
                sends: 1,
                kind: io::ErrorKind::ConnectionRefused
            }))
        ),
        "{refused:?}"
    );
    assert!(start.elapsed() >= wait);
}

/// Errors a connected UDP socket may report for an ICMP error, which anyone knowing the port can forge: on Linux,
/// port unreachable (ECONNREFUSED), host unreachable or filtered (EHOSTUNREACH), administratively prohibited of
/// `ICMPv6` (EACCES), a parameter problem (EPROTO), fragmentation needed or packet too big (EMSGSIZE), and with
/// `IP_RECVERR` a source route failed (EOPNOTSUPP) (`icmp_err_convert`, `__udp4_lib_err`, `icmpv6_err_convert`).
const ICMP: [fn() -> io::Error; 6] = [
    || io::ErrorKind::ConnectionRefused.into(),
    || io::ErrorKind::HostUnreachable.into(),
    || io::Error::from_raw_os_error(Errno::ACCESS.raw_os_error()),
    || io::Error::from_raw_os_error(Errno::PROTO.raw_os_error()),
    || io::Error::from_raw_os_error(Errno::MSGSIZE.raw_os_error()),
    || io::Error::from_raw_os_error(Errno::OPNOTSUPP.raw_os_error()),
];

/// Errors of ours: no memory, no buffer, or a send a firewall of ours denied (EPERM, of the kind of EACCES).
const OURS: [fn() -> io::Error; 3] = [
    || io::ErrorKind::OutOfMemory.into(),
    || io::Error::from_raw_os_error(Errno::NOBUFS.raw_os_error()),
    || io::Error::from_raw_os_error(Errno::PERM.raw_os_error()),
];

/// The response after ICMP errors, or after a wake-up with no datagram to read, is taken.
#[compio::test]
async fn the_response_after_an_icmp_error_or_a_spurious_wakeup_is_taken() {
    let addr = google_server(Duration::ZERO);
    let (client, seen) = client(Limits::default());
    for errors in [
        ICMP.map(|error| error()).into(),
        vec![
            io::ErrorKind::WouldBlock.into(),
            io::ErrorKind::Interrupted.into(),
        ],
    ] {
        seen.borrow_mut().recv_errors = errors;
        let answer = client
            .query(google(), addr, with_edns(), deadline())
            .await
            .expect("answered");
        assert_eq!(answer.response.transport, Transport::Udp);
        assert!(seen.borrow().recv_errors.is_empty());
    }
}

/// A wake-up with no datagram to read is no error of the server: a server sending only a datagram of another ID
/// times out, not unreachable.
#[compio::test]
async fn a_spurious_wakeup_tells_nothing_of_the_server() {
    let addr = server(
        |query| {
            let mut other = real(query);
            other[0] ^= 0xff;
            vec![(From::Server, other)]
        },
        |_| unreachable!("all over UDP"),
    );
    let (client, seen) = client(Limits::default());
    seen.borrow_mut().recv_errors = vec![
        io::ErrorKind::WouldBlock.into(),
        io::ErrorKind::Interrupted.into(),
    ];
    let silence = client
        .query(
            google(),
            addr,
            with_edns(),
            Instant::now() + Duration::from_millis(200),
        )
        .await;
    assert!(
        matches!(
            silence,
            Err(AuthoritativeError::Server(ServerError::TimedOut {
                sends: 1
            }))
        ),
        "{silence:?}"
    );
    assert!(seen.borrow().recv_errors.is_empty());
}

/// A receive failing for want of ours fails the query at once, the server not to blame.
#[compio::test]
async fn a_receive_failing_for_want_of_ours_fails_at_once() {
    let addr = google_server(Duration::ZERO);
    let (client, seen) = client(Limits::default());
    for error in OURS {
        seen.borrow_mut().recv_errors = vec![error()];
        let failed = client.query(google(), addr, with_edns(), deadline()).await;
        assert!(
            matches!(&failed, Err(AuthoritativeError::Local(LocalError::Socket(failure))) if same(failure, &error())),
            "{failed:?}"
        );
    }
}

/// A send failing with the ICMP error of a datagram before waits until the deadline as on a receive; one failing
/// for want of ours fails the query at once, the server not to blame. Any failure of the wait for a datagram is
/// ours: an ICMP error makes the socket readable, and shows on the receive.
#[compio::test]
async fn a_send_failing_waits_unless_ours_and_a_wait_failing_is_ours() {
    let addr = silent();
    let (client, seen) = client(Limits::default());
    let wait = Duration::from_millis(200);
    let sends = ICMP
        .map(|error| (error, false, false))
        .into_iter()
        .chain(OURS.map(|error| (error, false, true)));
    let waits = ICMP
        .into_iter()
        .chain(OURS)
        .map(|error| (error, true, true));
    for (error, readable, local) in sends.chain(waits) {
        {
            let mut seen = seen.borrow_mut();
            let failing = if readable {
                &mut seen.readable_errors
            } else {
                &mut seen.send_errors
            };
            *failing = vec![error()];
        }
        let start = Instant::now();
        let failed = client
            .query(google(), addr, Quirks::default(), start + wait)
            .await;
        let elapsed = start.elapsed();
        match &failed {
            Err(AuthoritativeError::Server(ServerError::Unreachable { sends: 1, kind })) => {
                assert!(!local && *kind == error().kind(), "{failed:?} {readable}");
                assert!(elapsed >= wait, "{failed:?} {readable}");
            }
            Err(AuthoritativeError::Local(LocalError::Socket(failure))) => {
                assert!(local && same(failure, &error()), "{failed:?} {readable}");
                assert!(elapsed < wait, "{failed:?} {readable}");
            }
            _ => panic!("{failed:?} {readable}"),
        }
    }
}

/// Whether `one` and `other` are the same error.
fn same(one: &io::Error, other: &io::Error) -> bool {
    (one.kind(), one.raw_os_error()) == (other.kind(), other.raw_os_error())
}

/// A TCP connection refused is the server's failure; one not made for want of a buffer of ours is ours.
#[compio::test]
async fn a_tcp_connect_failing_is_ours_only_for_want_of_ours() {
    let addr = silent();
    let (client, seen) = client(Limits::default());
    let tcp = Quirks {
        tcp: true,
        ..Quirks::default()
    };
    for kind in [io::ErrorKind::ConnectionRefused, io::ErrorKind::OutOfMemory] {
        seen.borrow_mut().connect_errors = vec![kind; 2];
        let failed = client.query(google(), addr, tcp, deadline()).await;
        let (local, to_blame) = match &failed {
            Err(AuthoritativeError::Server(ServerError::Tcp(TcpError::Connect(error)))) => {
                (false, error.kind())
            }
            Err(AuthoritativeError::Local(LocalError::Socket(error))) => (true, error.kind()),
            _ => panic!("{failed:?}"),
        };
        assert_eq!(
            (local, to_blame),
            (kind == io::ErrorKind::OutOfMemory, kind)
        );
        seen.borrow_mut().connect_errors.clear();
    }
}

/// A UDP socket not connected for want of a route is the network's failure, no query sent; for want of a buffer
/// of ours, ours.
#[compio::test]
async fn a_udp_connect_failing_is_ours_only_for_want_of_ours() {
    let addr = silent();
    let (client, seen) = client(Limits::default());
    for kind in [
        io::ErrorKind::NetworkUnreachable,
        io::ErrorKind::OutOfMemory,
    ] {
        seen.borrow_mut().connect_errors = vec![kind];
        let failed = client
            .query(google(), addr, Quirks::default(), deadline())
            .await;
        let (local, to_blame) = match &failed {
            Err(AuthoritativeError::Server(ServerError::Unreachable { sends: 0, kind })) => {
                (false, *kind)
            }
            Err(AuthoritativeError::Local(LocalError::Socket(error))) => (true, error.kind()),
            _ => panic!("{failed:?}"),
        };
        assert_eq!(
            (local, to_blame),
            (kind == io::ErrorKind::OutOfMemory, kind)
        );
    }
}

/// RFC 6891 §7: a server answering FORMERR without OPT, then NOERROR to the query without EDNS, is marked; the
/// next query, told of it, goes without.
#[compio::test]
async fn a_server_not_knowing_edns_is_marked() {
    let (queries, record) = recorder();
    let addr = server(
        move |query| {
            record(query);
            let response = if has_edns(query) {
                cut(&real(query), Rcode::FORMERR)
            } else {
                without_edns(&real(query))
            };
            vec![(From::Server, response)]
        },
        |_| unreachable!("all over UDP"),
    );
    let (client, _) = client(Limits::default());
    let answer = client
        .query(google(), addr, Quirks::default(), deadline())
        .await
        .expect("answered");
    assert_eq!(
        answer.quirks.edns,
        Edns::Unsupported {
            rejected: Rcode::FORMERR,
            answered: Rcode::NOERROR
        }
    );
    client
        .query(google(), addr, answer.quirks, deadline())
        .await
        .expect("answered");
    let edns: Vec<_> = queries
        .lock()
        .expect("not poisoned")
        .iter()
        .map(|query| has_edns(query))
        .collect();
    assert_eq!(edns, [true, false, false]);
}

/// A failure to the query without EDNS, such as SERVFAIL, does not tell EDNS was the trouble: nothing is marked.
#[compio::test]
async fn a_failure_without_edns_marks_nothing() {
    let addr = server(
        |query| {
            let rcode = if has_edns(query) {
                Rcode::NOTIMP
            } else {
                Rcode::SERVFAIL
            };
            vec![(From::Server, cut(&real(query), rcode))]
        },
        |_| unreachable!("all over UDP"),
    );
    let (client, _) = client(Limits::default());
    let answer = client
        .query(google(), addr, Quirks::default(), deadline())
        .await
        .expect("answered");
    assert_eq!(answer.response.edns_dropped, Some(Rcode::NOTIMP));
    assert_eq!(answer.quirks, Quirks::default());
}

/// A FORMERR without OPT from a server known to answer with EDNS, as a forger may send, does not drop EDNS, as
/// Unbound's `edns_lame_known`: it is the response.
#[compio::test]
async fn a_server_known_to_do_edns_keeps_it() {
    let (queries, record) = recorder();
    let addr = server(
        move |query| {
            record(query);
            vec![(From::Server, cut(&real(query), Rcode::FORMERR))]
        },
        |_| unreachable!("all over UDP"),
    );
    let (client, _) = client(Limits::default());
    let answer = client
        .query(google(), addr, with_edns(), deadline())
        .await
        .expect("answered");
    assert_eq!(
        (answer.response.rcode, answer.response.edns_dropped),
        (Rcode::FORMERR, None)
    );
    assert_eq!(answer.quirks, with_edns());
    let queries = queries.lock().expect("not poisoned");
    assert_eq!(queries.len(), 1);
    assert!(has_edns(&queries[0]));
}

/// RFC 7766 §5: a truncated response asks again over TCP, and tells only that the answer was large: the server
/// is not marked.
#[compio::test]
async fn a_truncated_response_moves_to_tcp() {
    let (queries, record) = recorder();
    let addr = server(
        move |query| {
            record(query);
            vec![(
                From::Server,
                AUTHORITIES.answer(MICROSOFT, recursion::Transport::Udp, query),
            )]
        },
        |query| AUTHORITIES.answer(MICROSOFT, recursion::Transport::Tcp, query),
    );
    let (client, _) = client(Limits::default());
    let question = Question::new("microsoft.com.".parse().expect("a name"), RecordType::TXT);
    let answer = client
        .query(question, addr, Quirks::default(), deadline())
        .await
        .expect("answered");
    assert_eq!(
        (answer.response.transport, answer.response.moved),
        (Transport::Tcp, Some(Moved::Truncated))
    );
    assert!(!answer.quirks.tcp);
    assert!(decode(&answer.response.wire).answer.len() > 1);
    assert_eq!(queries.lock().expect("not poisoned").len(), 1);
}

/// RFC 7873 §5.3: a server answering BADCOOKIE twice over UDP is asked over TCP and marked; the next query, told
/// of it, goes over TCP from the start, without a cookie.
#[compio::test]
async fn a_server_answering_badcookie_twice_is_marked() {
    const FRESH: &[u8] = b"fresh-cookie-016";
    /// `response` with the client cookie of `query` and [`FRESH`].
    fn with_cookie(query: &[u8], mut response: Message<'static>) -> Vec<u8> {
        let client = cookie_of(query).expect("a cookie").client();
        let cookie = Cookie::new(client, Some(FRESH)).expect("a valid cookie");
        response.edns.as_mut().expect("EDNS").options = vec![EdnsOption::Cookie(cookie)];
        wire(&response)
    }
    let (queries, record) = recorder();
    let tcp = record.clone();
    let addr = server(
        move |query| {
            record(query);
            let badcookie = response(&decode(query), Rcode::BADCOOKIE);
            vec![(From::Server, with_cookie(query, badcookie))]
        },
        move |query| {
            tcp(query);
            match cookie_of(query) {
                Some(_) => with_cookie(query, decode(&real(query))),
                None => real(query),
            }
        },
    );
    let (client, _) = client(Limits::default());
    let answer = client
        .query(google(), addr, Quirks::default(), deadline())
        .await
        .expect("answered");
    assert_eq!(
        (answer.response.transport, answer.response.moved),
        (Transport::Tcp, Some(Moved::BadCookie))
    );
    assert!(answer.quirks.tcp);
    let again = client
        .query(google(), addr, answer.quirks, deadline())
        .await
        .expect("answered");
    assert_eq!(again.response.transport, Transport::Tcp);
    let queries = queries.lock().expect("not poisoned");
    assert_eq!(queries.len(), 4);
    assert_eq!(cookie_of(&queries[3]), None);
}

/// Queries past the sockets allowed wait for one: never more open at once, and each answered.
#[compio::test]
async fn sockets_in_flight_never_exceed_the_bound() {
    let addr = google_server(Duration::from_millis(20));
    let sockets = NonZeroUsize::new(4).expect("not zero");
    let (client, seen) = client(Limits {
        sockets,
        ..Limits::default()
    });
    let queries = (0..16).map(|_| client.query(google(), addr, with_edns(), deadline()));
    let answers = join_all(queries).await;
    assert!(answers.iter().all(Result::is_ok));
    let seen = seen.borrow();
    assert_eq!(seen.most, sockets.get());
    assert_eq!((seen.ports.len(), seen.open), (16, 0));
}

/// A query waiting for a socket gives up at its deadline, the one holding it going on.
#[compio::test]
async fn a_query_waiting_for_a_socket_fails_at_its_deadline() {
    let addr = silent();
    let (client, _) = client(Limits {
        sockets: NonZeroUsize::MIN,
        ..Limits::default()
    });
    let start = Instant::now();
    let (holding, waiting) = futures_util::join!(
        client.query(
            google(),
            addr,
            with_edns(),
            start + Duration::from_millis(300)
        ),
        client.query(
            google(),
            addr,
            with_edns(),
            start + Duration::from_millis(100)
        ),
    );
    assert!(
        matches!(
            waiting,
            Err(AuthoritativeError::Local(LocalError::NoSocket))
        ),
        "{waiting:?}"
    );
    assert!(
        matches!(
            holding,
            Err(AuthoritativeError::Server(ServerError::TimedOut {
                sends: 1
            }))
        ),
        "{holding:?}"
    );
}

/// D190: a query whose wait for a UDP socket or a TCP connection leaves the server less than [`SERVER_FLOOR`] fails
/// as ours, not as the server's timeout.
#[compio::test]
async fn a_wait_of_ours_leaving_too_little_is_not_the_servers_timeout() {
    let tcp = Quirks {
        tcp: true,
        ..with_edns()
    };
    let cases = [
        (
            Quirks::default(),
            Limits {
                sockets: NonZeroUsize::MIN,
                ..Limits::default()
            },
        ),
        (
            tcp,
            Limits {
                tcp: NonZeroUsize::MIN,
                ..Limits::default()
            },
        ),
    ];
    for (quirks, limits) in cases {
        let (client, _) = client(limits);
        let start = Instant::now();
        // The socket or the connection is free at 300 ms, which leaves the waiting query less than the floor.
        let free = start + Duration::from_millis(300);
        let (_, waiting) = futures_util::join!(
            client.query(
                google(),
                google_server(Duration::from_millis(300)),
                quirks,
                free
            ),
            client.query(
                google(),
                google_server(Duration::ZERO),
                quirks,
                free + SERVER_FLOOR / 2
            ),
        );
        assert!(
            matches!(
                waiting,
                Err(AuthoritativeError::Local(
                    LocalError::NoSocket | LocalError::TcpBusy
                ))
            ),
            "{waiting:?}"
        );
    }
}

/// A query dropped before its end, as by a caller giving up, gives its socket back.
#[compio::test]
async fn a_dropped_query_gives_its_socket_back() {
    let (client, seen) = client(Limits {
        sockets: NonZeroUsize::MIN,
        ..Limits::default()
    });
    let dropped = compio::time::timeout(
        Duration::from_millis(50),
        client.query(google(), silent(), with_edns(), deadline()),
    )
    .await;
    assert!(dropped.is_err(), "{dropped:?}");
    assert_eq!(seen.borrow().open, 0);
    client
        .query(
            google(),
            google_server(Duration::ZERO),
            with_edns(),
            Instant::now() + Duration::from_millis(500),
        )
        .await
        .expect("answered");
}

/// Past the TCP connections allowed, a new one closes the one idle longest, or waits for one to be until its
/// deadline.
#[compio::test]
async fn tcp_connections_never_exceed_the_bound() {
    let slow = google_server(Duration::from_millis(300));
    let fast = google_server(Duration::ZERO);
    let (client, _) = client(Limits {
        tcp: NonZeroUsize::MIN,
        ..Limits::default()
    });
    let tcp = Quirks {
        tcp: true,
        ..with_edns()
    };
    let start = Instant::now();
    let (holding, busy, waiting) = futures_util::join!(
        client.query(google(), slow, tcp, deadline()),
        client.query(google(), fast, tcp, start + Duration::from_millis(100)),
        client.query(google(), fast, tcp, deadline()),
    );
    assert!(holding.is_ok(), "{holding:?}");
    assert!(
        matches!(busy, Err(AuthoritativeError::Local(LocalError::TcpBusy))),
        "{busy:?}"
    );
    // The slow server's connection went idle: it closed for the fast one's.
    assert!(waiting.is_ok(), "{waiting:?}");
    assert!(start.elapsed() >= Duration::from_millis(300));
}
