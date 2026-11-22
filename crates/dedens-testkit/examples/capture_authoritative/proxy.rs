//! The recording proxy: a UDP and TCP relay in front of a server that logs each DNS message with its direction
//! and time, as [`Packet`]s. A TCP stream is read as the two-byte-framed messages of RFC 1035 §4.2.2, which the
//! relay forwards as they come, whole or not.

use std::io::{Read, Write};
use std::net::{Ipv4Addr, Shutdown, SocketAddr, TcpListener, TcpStream, UdpSocket};
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::sync::{Arc, Mutex, PoisonError};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use dedens_testkit::authoritative::{Packet, Peer, Transport};

use crate::Result;

/// How long the relay waits for a server's response to a datagram.
const UDP_WAIT: Duration = Duration::from_secs(3);
/// The pause of the loops that poll the stop flag.
const POLL: Duration = Duration::from_millis(20);
/// The settle time after a tool exits: its last messages are still in a relay's buffers.
const SETTLE: Duration = Duration::from_millis(400);

/// A message seen, before its time is made relative.
struct Seen {
    at: Instant,
    packet: Packet,
}

/// The log the relay threads share.
type Log = Arc<Mutex<Vec<Seen>>>;

fn record(log: &Log, transport: Transport, connection: u32, from: Peer, message: &[u8]) {
    log.lock()
        .unwrap_or_else(PoisonError::into_inner)
        .push(Seen {
            at: Instant::now(),
            packet: Packet {
                at_ms: 0,
                transport,
                connection,
                from,
                message: message.to_vec(),
            },
        });
}

/// A relay from its own port, on every interface, to the server at `target`.
pub(crate) struct Proxy {
    pub(crate) port: u16,
    log: Log,
    stop: Arc<AtomicBool>,
    threads: Vec<JoinHandle<()>>,
}

impl Proxy {
    /// Starts relaying to `target`, over UDP and over TCP.
    pub(crate) fn start(target: SocketAddr) -> Result<Self> {
        let (tcp, udp) = loop {
            let tcp = TcpListener::bind((Ipv4Addr::UNSPECIFIED, 0))?;
            if let Ok(udp) = UdpSocket::bind((Ipv4Addr::UNSPECIFIED, tcp.local_addr()?.port())) {
                break (tcp, udp);
            }
        };
        let port = tcp.local_addr()?.port();
        tcp.set_nonblocking(true)?;
        udp.set_read_timeout(Some(POLL))?;
        let log = Log::default();
        let stop = Arc::new(AtomicBool::new(false));
        let threads = vec![
            thread::spawn({
                let (log, stop) = (Arc::clone(&log), Arc::clone(&stop));
                move || relay_udp(&udp, target, &log, &stop)
            }),
            thread::spawn({
                let (log, stop) = (Arc::clone(&log), Arc::clone(&stop));
                move || relay_tcp(&tcp, target, &log, &stop)
            }),
        ];
        Ok(Self {
            port,
            log,
            stop,
            threads,
        })
    }

    /// The messages logged since the last call, in order, their times from the first one's. Waits first for the
    /// relays to finish the last of them.
    pub(crate) fn take(&self) -> Vec<Packet> {
        thread::sleep(SETTLE);
        let mut seen =
            std::mem::take(&mut *self.log.lock().unwrap_or_else(PoisonError::into_inner));
        seen.sort_by_key(|seen| seen.at);
        let Some(first) = seen.first().map(|seen| seen.at) else {
            return Vec::new();
        };
        seen.into_iter()
            .map(|Seen { at, mut packet }| {
                packet.at_ms =
                    u64::try_from(at.duration_since(first).as_millis()).unwrap_or(u64::MAX);
                packet
            })
            .collect()
    }
}

impl Drop for Proxy {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        for thread in self.threads.drain(..) {
            let _ = thread.join();
        }
    }
}

/// Relays datagrams one at a time: a query, the server's response, the client's reply.
fn relay_udp(socket: &UdpSocket, target: SocketAddr, log: &Log, stop: &AtomicBool) {
    let mut buf = vec![0u8; 65535];
    while !stop.load(Ordering::Relaxed) {
        let Ok((len, client)) = socket.recv_from(&mut buf) else {
            continue;
        };
        record(log, Transport::Udp, 0, Peer::Client, &buf[..len]);
        let Ok(upstream) = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)) else {
            continue;
        };
        let _ = upstream.set_read_timeout(Some(UDP_WAIT));
        if upstream.send_to(&buf[..len], target).is_err() {
            continue;
        }
        let mut response = vec![0u8; 65535];
        if let Ok(len) = upstream.recv(&mut response) {
            record(log, Transport::Udp, 0, Peer::Server, &response[..len]);
            let _ = socket.send_to(&response[..len], client);
        }
    }
}

/// Accepts connections, a relay for each.
fn relay_tcp(listener: &TcpListener, target: SocketAddr, log: &Log, stop: &AtomicBool) {
    let connections = AtomicU32::new(0);
    while !stop.load(Ordering::Relaxed) {
        let Ok((client, _)) = listener.accept() else {
            thread::sleep(POLL);
            continue;
        };
        let connection = connections.fetch_add(1, Ordering::Relaxed) + 1;
        let Ok(server) = TcpStream::connect(target) else {
            continue;
        };
        let (Ok(client_read), Ok(server_read)) = (client.try_clone(), server.try_clone()) else {
            continue;
        };
        let _ = client_read.set_nonblocking(false);
        let _ = client.set_nonblocking(false);
        for (from, mut source, mut sink) in [
            (Peer::Client, client_read, server),
            (Peer::Server, server_read, client),
        ] {
            let log = Arc::clone(log);
            thread::spawn(move || pump(&mut source, &mut sink, &log, connection, from));
        }
    }
}

/// Copies `source` to `sink`, logging the framed messages passing.
fn pump(source: &mut TcpStream, sink: &mut TcpStream, log: &Log, connection: u32, from: Peer) {
    let mut pending = Vec::new();
    let mut buf = vec![0u8; 65536];
    while let Ok(len) = source.read(&mut buf) {
        if len == 0 || sink.write_all(&buf[..len]).is_err() {
            break;
        }
        pending.extend_from_slice(&buf[..len]);
        while let [high, low, rest @ ..] = pending.as_slice() {
            let size = usize::from(u16::from_be_bytes([*high, *low]));
            if rest.len() < size {
                break;
            }
            record(log, Transport::Tcp, connection, from, &rest[..size]);
            pending.drain(..2 + size);
        }
    }
    let _ = sink.shutdown(Shutdown::Write);
}

/// The address of a container's published port, on the loopback.
pub(crate) fn local(port: u16) -> SocketAddr {
    SocketAddr::from((Ipv4Addr::LOCALHOST, port))
}
