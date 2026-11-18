//! The authoritative mode on the loopback address (D190): a port per query (RFC 5452 §9.2), forged responses
//! dropped (RFC 5452 §9.1) and `0x20` kept against them (draft-vixie-dnsext-dns0x20), TC to TCP (RFC 7766 §5), and
//! the bounds on sockets and connections.
//!
//! The server answers with the response `a.root-servers.net` gave to `example.com. A`, without RD
//! (`testdata/proto/referral_root.bin`). A forger answers with the one `a.gtld-servers.net` gave
//! (`referral_com.bin`): a real response, but not this server's.

use std::cell::RefCell;
use std::collections::HashSet;
use std::io::{self, Read as _, Write as _};
use std::net::{SocketAddr, TcpListener, UdpSocket};
use std::num::NonZeroUsize;
use std::rc::Rc;
use std::thread;
use std::time::{Duration, Instant};

use compio::BufResult;
use compio::buf::{IoBuf, IoBufMut};
use compio::net::TcpStream;
use dedens_net::authoritative::{Authoritative, Limits, Quirks};
use dedens_net::client::ClientError;
use dedens_net::io::{Compio, Io, TimedOut, Udp};
use dedens_net::tcp::{TcpError, frame};
use dedens_proto::edns::{EdnsFlags, EdnsOption};
use dedens_proto::{Flags, Message, Name, Question, RecordType, Transport};
use dedens_testkit::captured;
use dedens_testkit::responder::{self, Responder};
use futures_util::future::join_all;

/// How long each query waits.
const TIMEOUT: Duration = Duration::from_secs(5);

/// The ports a query may go from.
const PORTS: std::ops::RangeInclusive<u16> = 1024..=65535;

fn example() -> Question<'static> {
    Question::new("example.com.".parse().expect("a name"), RecordType::A)
}

/// The real response to `query`: the root server's capture, its ID and question the query's, as
/// [`Responder`] answers.
fn real(query: &[u8]) -> Vec<u8> {
    answer("referral_root", query)
}

/// The capture `case`, its ID and question bytes those of `query`.
fn answer(case: &str, query: &[u8]) -> Vec<u8> {
    let mut response = captured(case);
    let end = question_end(query);
    response[..2].copy_from_slice(&query[..2]);
    response[12..end].copy_from_slice(&query[12..end]);
    response
}

/// The end of the question of `query`: its name, type and class.
fn question_end(query: &[u8]) -> usize {
    let mut at = 12;
    while query[at] != 0 {
        at += usize::from(query[at]) + 1;
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

/// Where a datagram comes from.
#[derive(Clone, Copy)]
enum From {
    /// The server's port.
    Server,
    /// Another port of the same address: a forger.
    Elsewhere,
}

/// A server over UDP and TCP on one port of the loopback address: each UDP query gets the datagrams of `udp`, in
/// order, and each TCP query the response of `tcp`. Its threads run until the test process exits.
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
                stream.write_all(&response).expect("written");
            }
        }
    });
    addr
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
}

/// Compio, its UDP sockets counted and its randomness from a fixed seed, so that each run draws the same ports.
#[derive(Debug, Clone)]
struct Watched {
    seen: Rc<RefCell<Seen>>,
    /// The state of `SplitMix64`.
    state: Rc<RefCell<u64>>,
}

impl Watched {
    fn new() -> Self {
        Self {
            seen: Rc::default(),
            state: Rc::new(RefCell::new(0x5eed)),
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
        Compio.tcp_connect(addr).await
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
        self.udp.connect(addr).await
    }

    async fn recv<B: IoBufMut>(&self, buffer: B) -> BufResult<usize, B> {
        self.udp.recv(buffer).await
    }

    async fn readable(&self) -> io::Result<()> {
        self.udp.readable().await
    }

    fn try_recv(&self, buffer: &mut [u8]) -> io::Result<usize> {
        self.udp.try_recv(buffer)
    }

    async fn send<B: IoBuf>(&self, buffer: B) -> BufResult<usize, B> {
        self.udp.send(buffer).await
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

/// The query: RD clear, EDNS of 1232 bytes with DO and a cookie, the question in a random case (RFC 5452 §9.3);
/// the response comes back in the case asked, its sections the server's.
#[compio::test]
async fn a_query_asks_as_a_resolver_asks_an_authoritative_server() {
    let responder = Responder::start(&["referral_root"]);
    let (client, _) = client(Limits::default());
    let answer = client
        .query(example(), responder.addr, Quirks::default(), TIMEOUT)
        .await
        .expect("answered");
    let queries: [_; 1] = responder.queries().try_into().expect("one query");
    let [(responder::Transport::Udp, query)] = queries else {
        panic!("not over UDP");
    };
    let query = decode(&query);
    assert!(!query.header.flags.contains(Flags::RD));
    let edns = query.edns.expect("EDNS");
    assert_eq!(edns.udp_payload, 1232);
    assert!(edns.flags.contains(EdnsFlags::DO));
    assert!(
        edns.options
            .iter()
            .any(|option| matches!(option, EdnsOption::Cookie(_)))
    );
    let asked = &query.questions[0].name;
    assert!(!asked.labels().eq(example().name.labels()), "0x20: {asked}");
    let response = decode(&answer.response.wire);
    assert!(
        response.questions[0]
            .name
            .labels()
            .eq(example().name.labels())
    );
    assert_eq!(
        response.authority,
        decode(&captured("referral_root")).authority
    );
    assert_eq!(answer.quirks, Quirks::default());
}

/// RFC 5452 §9.2: each query goes from a port of its own, drawn from the whole range.
#[compio::test]
async fn ports_differ_from_query_to_query() {
    let responder = Responder::start(&["referral_root"]);
    let (client, seen) = client(Limits::default());
    for _ in 0..1000 {
        client
            .query(example(), responder.addr, Quirks::default(), TIMEOUT)
            .await
            .expect("answered");
    }
    let ports = std::mem::take(&mut seen.borrow_mut().ports);
    assert_eq!(ports.len(), 1000);
    assert!(ports.iter().all(|port| PORTS.contains(port)));
    assert!(ports.windows(2).all(|pair| pair[0] != pair[1]));
    // The range in blocks of 1024 ports: at least half of them hold a port.
    let blocks: HashSet<u16> = ports.iter().map(|port| port / 1024).collect();
    assert!(
        blocks.len() >= PORTS.len() / 1024 / 2,
        "{} blocks",
        blocks.len()
    );
}

/// RFC 5452 §9.1: a response from another port comes first, the server's after; the connected socket drops the
/// forged one.
#[compio::test]
async fn a_response_from_another_port_is_dropped() {
    let addr = server(
        |query| {
            vec![
                (From::Elsewhere, answer("referral_com", query)),
                (From::Server, real(query)),
            ]
        },
        |_| unreachable!("all over UDP"),
    );
    let (client, _) = client(Limits::default());
    let answer = client
        .query(example(), addr, Quirks::default(), TIMEOUT)
        .await
        .expect("answered");
    assert_eq!(answer.response.transport, Transport::Udp);
    assert_eq!(
        decode(&answer.response.wire).authority,
        decode(&captured("referral_root")).authority
    );
}

/// A forged response with the question in another case asks over TCP, where the server repeats the case: the
/// server's response is taken, and `0x20` stays on.
#[compio::test]
async fn a_forged_case_mismatch_moves_to_tcp_and_keeps_0x20() {
    let addr = server(
        |query| vec![(From::Server, swap_case(answer("referral_com", query)))],
        real,
    );
    let (client, _) = client(Limits::default());
    let answer = client
        .query(example(), addr, Quirks::default(), TIMEOUT)
        .await
        .expect("answered");
    assert_eq!(answer.response.transport, Transport::Tcp);
    assert_eq!(
        decode(&answer.response.wire).authority,
        decode(&captured("referral_root")).authority
    );
    assert_eq!(answer.quirks, Quirks::default());
}

/// A server that lowercases the question (draft-vixie-dnsext-dns0x20 §6.2) is answered over TCP and marked; the
/// next query, told of it, goes over UDP without `0x20`.
#[compio::test]
async fn a_server_not_repeating_the_case_is_marked_over_tcp() {
    let addr = server(
        |query| vec![(From::Server, lowercase(real(query)))],
        |query| lowercase(real(query)),
    );
    let (client, _) = client(Limits::default());
    let question = Question::new(
        Name::from_labels([b"Example".as_slice(), b"COM"]).expect("a name"),
        RecordType::A,
    );
    let answer = client
        .query(question.clone(), addr, Quirks::default(), TIMEOUT)
        .await
        .expect("answered");
    assert_eq!(answer.response.transport, Transport::Tcp);
    assert!(answer.quirks.no_case);
    assert!(
        decode(&answer.response.wire).questions[0]
            .name
            .labels()
            .eq(question.name.labels())
    );
    let again = client
        .query(question, addr, answer.quirks, TIMEOUT)
        .await
        .expect("answered");
    assert_eq!(again.response.transport, Transport::Udp);
}

/// RFC 7766 §5: a truncated response asks again over TCP.
#[compio::test]
async fn a_truncated_response_moves_to_tcp() {
    let responder = Responder::start(&["truncated", "txt_large"]);
    let (client, _) = client(Limits::default());
    let question = Question::new("google.com.".parse().expect("a name"), RecordType::TXT);
    let answer = client
        .query(question, responder.addr, Quirks::default(), TIMEOUT)
        .await
        .expect("answered");
    assert_eq!(answer.response.transport, Transport::Tcp);
    assert!(answer.quirks.tcp);
    let transports: Vec<_> = responder
        .queries()
        .into_iter()
        .map(|(transport, _)| transport)
        .collect();
    assert_eq!(
        transports,
        [responder::Transport::Udp, responder::Transport::Tcp]
    );
}

/// Queries past the sockets allowed wait for one: never more open at once, and each answered.
#[compio::test]
async fn sockets_in_flight_never_exceed_the_bound() {
    let responder = Responder::delayed(&["referral_root"], Duration::from_millis(20));
    let sockets = NonZeroUsize::new(4).expect("not zero");
    let (client, seen) = client(Limits {
        sockets,
        ..Limits::default()
    });
    let queries =
        (0..16).map(|_| client.query(example(), responder.addr, Quirks::default(), TIMEOUT));
    let answers = join_all(queries).await;
    assert!(answers.iter().all(Result::is_ok));
    let seen = seen.borrow();
    assert_eq!(seen.most, sockets.get());
    assert_eq!((seen.ports.len(), seen.open), (16, 0));
}

/// Past the TCP connections allowed, a new one closes the one idle longest, or fails when each has a query
/// waiting.
#[compio::test]
async fn tcp_connections_never_exceed_the_bound() {
    let slow = Responder::delayed(&["referral_root"], Duration::from_millis(500));
    let fast = Responder::start(&["referral_root"]);
    let (client, _) = client(Limits {
        tcp: NonZeroUsize::MIN,
        ..Limits::default()
    });
    let tcp = Quirks {
        tcp: true,
        ..Quirks::default()
    };
    let (waiting, refused) = futures_util::join!(
        client.query(example(), slow.addr, tcp, TIMEOUT),
        client.query(example(), fast.addr, tcp, TIMEOUT),
    );
    assert!(waiting.is_ok());
    assert!(
        matches!(refused, Err(ClientError::Tcp(TcpError::Busy))),
        "{refused:?}"
    );
    // The slow server's connection is idle now: it goes.
    client
        .query(example(), fast.addr, tcp, TIMEOUT)
        .await
        .expect("answered");
}
