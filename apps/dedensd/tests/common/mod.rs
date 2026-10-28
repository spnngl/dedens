//! Shared by the tests running `dedensd`: a loopback upstream answering captured bytes, a running server with its
//! configuration file, and DNS over UDP and TCP with the standard library.

#![allow(dead_code, reason = "each test file uses part of these")]

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream, UdpSocket};
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::thread;
use std::time::{Duration, Instant};

use dedens_proto::{Message, Name, RecordType, Ttl};

/// A captured response of `dedens-proto`'s test data.
pub(crate) fn captured(case: &str) -> Vec<u8> {
    let path = format!(
        "{}/../../crates/dedens-proto/tests/testdata/{case}.bin",
        env!("CARGO_MANIFEST_DIR")
    );
    std::fs::read(path).expect("a captured response")
}

/// A query, under `id`, for the question of `response`.
pub(crate) fn query_for(response: &[u8], id: u16) -> Vec<u8> {
    let question = Message::decode(response)
        .expect("a captured response decodes")
        .message
        .questions
        .swap_remove(0);
    Message::query(id, question).to_vec().expect("a query fits")
}

/// The question of `wire`, if it reads; names compare without case (RFC 4343).
fn question(wire: &[u8]) -> Option<(Name<'static>, RecordType)> {
    let question = Message::decode(wire)
        .ok()?
        .message
        .questions
        .into_iter()
        .next()?;
    Some((question.name.into_owned(), question.qtype))
}

/// A loopback upstream over UDP and TCP on one port, answering each query with the capture asking its question,
/// under the query's ID; silent to other questions.
pub(crate) struct Responder {
    pub(crate) addr: SocketAddr,
    queries: Arc<AtomicUsize>,
}

impl Responder {
    /// Answers with the captures named `cases`.
    pub(crate) fn start(cases: &[&str]) -> Self {
        let captures = cases.iter().map(|case| captured(case)).collect();
        Self::answering(captures, Duration::ZERO)
    }

    /// Answers with the capture named `case`, its records' TTL `ttl`, every query after the first `delay` late.
    pub(crate) fn slow(case: &str, ttl: u32, delay: Duration) -> Self {
        let mut message = decode(&captured(case));
        let ttl = Ttl::new(ttl).expect("a TTL");
        for record in &mut message.answer {
            record.ttl = ttl;
        }
        Self::answering(vec![message.to_vec().expect("it fits")], delay)
    }

    fn answering(responses: Vec<Vec<u8>>, delay: Duration) -> Self {
        let captures: Arc<[_]> = responses
            .into_iter()
            .map(|wire| (question(&wire).expect("a captured question"), wire))
            .collect();
        let queries = Arc::new(AtomicUsize::new(0));
        let reply = {
            let queries = Arc::clone(&queries);
            move |query: &[u8]| {
                if queries.fetch_add(1, Ordering::Relaxed) > 0 {
                    thread::sleep(delay);
                }
                let asked = question(query)?;
                let (_, wire) = captures.iter().find(|(question, _)| *question == asked)?;
                let mut answer = wire.clone();
                answer[..2].copy_from_slice(&query[..2]);
                Some(answer)
            }
        };
        let udp = UdpSocket::bind("127.0.0.1:0").expect("a UDP port");
        let addr = udp.local_addr().expect("its address");
        let tcp = TcpListener::bind(addr).expect("the same port over TCP");
        let for_udp = reply.clone();
        thread::spawn(move || {
            let mut buf = vec![0; 65535];
            while let Ok((len, peer)) = udp.recv_from(&mut buf) {
                if let Some(answer) = for_udp(&buf[..len]) {
                    let _ = udp.send_to(&answer, peer);
                }
            }
        });
        thread::spawn(move || {
            for mut stream in tcp.incoming().flatten() {
                while let Some(query) = read_framed(&mut stream) {
                    if let Some(answer) = reply(&query) {
                        let _ = stream.write_all(&framed(&answer));
                    }
                }
            }
        });
        Self { addr, queries }
    }

    /// The queries received so far, over both transports.
    pub(crate) fn queries(&self) -> usize {
        self.queries.load(Ordering::Relaxed)
    }
}

/// A loopback upstream that never answers.
pub(crate) fn silent() -> (UdpSocket, SocketAddr) {
    let udp = UdpSocket::bind("127.0.0.1:0").expect("a UDP port");
    let addr = udp.local_addr().expect("its address");
    (udp, addr)
}

/// A port free over UDP and TCP on loopback, as far as a moment ago.
fn free_port() -> SocketAddr {
    loop {
        let udp = UdpSocket::bind("127.0.0.1:0").expect("a UDP port");
        let addr = udp.local_addr().expect("its address");
        if TcpListener::bind(addr).is_ok() {
            return addr;
        }
    }
}

/// A configuration file of a caching forwarder answering on `listen`, forwarding to `upstream` with a 1 s timeout,
/// in the temporary directory; each call writes its own.
pub(crate) fn config(listen: &str, upstream: &str) -> PathBuf {
    config_with(listen, upstream, "")
}

/// [`config`] with `cache`, lines of settings for the cache stage.
fn config_with(listen: &str, upstream: &str, cache: &str) -> PathBuf {
    static NEXT: AtomicUsize = AtomicUsize::new(0);
    let path = std::env::temp_dir().join(format!(
        "dedensd-{}-{}.yaml",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::Relaxed)
    ));
    let text = format!(
        "listen: ['{listen}']\npipeline: [cache, up]\nstages:\n  cache:\n    type: cache\n{cache}  up:\n    type: forward\n    servers: ['{upstream}']\n    timeout_ms: 1000\n"
    );
    std::fs::write(&path, text).expect("a configuration file");
    path
}

/// A running `dedensd`, killed when dropped.
pub(crate) struct Server {
    child: Child,
    pub(crate) addr: SocketAddr,
}

impl Drop for Server {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

impl Server {
    /// Starts `dedensd` on a free port, forwarding to `upstream`, and waits until it accepts connections.
    pub(crate) fn start(upstream: SocketAddr) -> Self {
        Self::start_with(upstream, "")
    }

    /// [`Server::start`] with `cache`, lines of settings for the cache stage, as `"    key: value\n"`.
    pub(crate) fn start_with(upstream: SocketAddr, cache: &str) -> Self {
        let addr = free_port();
        let child = Command::new(env!("CARGO_BIN_EXE_dedensd"))
            .arg("--config")
            .arg(config_with(&addr.to_string(), &upstream.to_string(), cache))
            .stderr(Stdio::null())
            .spawn()
            .expect("dedensd starts");
        let server = Self { child, addr };
        let start = Instant::now();
        while TcpStream::connect(addr).is_err() {
            assert!(start.elapsed() < Duration::from_secs(10), "dedensd listens");
            thread::sleep(Duration::from_millis(20));
        }
        server
    }
}

/// The reply over UDP to `query`.
pub(crate) fn ask_udp(server: SocketAddr, query: &[u8]) -> Message<'static> {
    let socket = UdpSocket::bind("127.0.0.1:0").expect("a UDP port");
    socket
        .set_read_timeout(Some(Duration::from_secs(10)))
        .expect("a timeout");
    socket.send_to(query, server).expect("sent");
    let mut buf = vec![0; 65535];
    let len = socket.recv(&mut buf).expect("a reply");
    decode(&buf[..len])
}

/// The reply over a new TCP connection to `query`.
pub(crate) fn ask_tcp(server: SocketAddr, query: &[u8]) -> Message<'static> {
    let mut stream = TcpStream::connect(server).expect("connected");
    stream
        .set_read_timeout(Some(Duration::from_secs(10)))
        .expect("a timeout");
    stream.write_all(&framed(query)).expect("sent");
    decode(&read_framed(&mut stream).expect("a reply"))
}

/// `wire` decoded, without a broken rule.
pub(crate) fn decode(wire: &[u8]) -> Message<'static> {
    let decoded = Message::decode(wire).expect("a reply decodes");
    assert_eq!(decoded.violations, []);
    decoded.message.into_owned()
}

/// `wire` behind its two-byte length (RFC 1035 §4.2.2).
pub(crate) fn framed(wire: &[u8]) -> Vec<u8> {
    let len = u16::try_from(wire.len()).expect("a message fits");
    [&len.to_be_bytes()[..], wire].concat()
}

/// The next message of a TCP stream, `None` at its end.
pub(crate) fn read_framed(stream: &mut TcpStream) -> Option<Vec<u8>> {
    let mut len = [0; 2];
    stream.read_exact(&mut len).ok()?;
    let mut message = vec![0; usize::from(u16::from_be_bytes(len))];
    stream.read_exact(&mut message).ok()?;
    Some(message)
}
