//! A loopback Anonymized `DNSCrypt` relay (draft-denis-dprive-dnscrypt-11, "Anonymized `DNSCrypt`"; D100), for the
//! tests of `dedens` and `dedensd`: on one port over UDP and TCP, it passes the inner packet after the 28-byte prefix to
//! the resolver the prefix names, over UDP whatever carried it, and the response back if it is not longer than the
//! inner packet, as the reference relay does.

use std::io::{Read, Write};
use std::net::{Ipv6Addr, SocketAddr, TcpListener, UdpSocket};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::thread;
use std::time::Duration;

/// The length of the prefix: the magic, the address and the port.
const PREFIX_LEN: usize = 28;

/// The magic of the prefix: eight `0xff` and two NULs.
const MAGIC: [u8; 10] = [0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0, 0];

/// How long the relay waits for the resolver.
const WAIT: Duration = Duration::from_secs(2);

/// A relay on a loopback port, UDP and TCP, running until the process ends.
pub struct Relay {
    /// The packets it got, over UDP then over TCP.
    seen: Arc<(AtomicUsize, AtomicUsize)>,
    /// Where it listens, over UDP and over TCP.
    pub addr: SocketAddr,
}

/// The response of the resolver the prefix of `packet` names, if there is one not longer than the inner packet.
fn pass(packet: &[u8]) -> Option<Vec<u8>> {
    let (prefix, inner) = packet.split_at_checked(PREFIX_LEN)?;
    assert_eq!(
        &prefix[..10],
        &MAGIC,
        "the magic of an Anonymized DNSCrypt query"
    );
    let ip = Ipv6Addr::from(<[u8; 16]>::try_from(&prefix[10..26]).ok()?);
    let target = SocketAddr::new(
        ip.to_canonical(),
        u16::from_be_bytes([prefix[26], prefix[27]]),
    );
    let socket = UdpSocket::bind("127.0.0.1:0").ok()?;
    socket.set_read_timeout(Some(WAIT)).ok()?;
    socket.send_to(inner, target).ok()?;
    let mut buf = vec![0; usize::from(u16::MAX)];
    let (len, _) = socket.recv_from(&mut buf).ok()?;
    (len <= inner.len()).then(|| buf[..len].to_vec())
}

/// Passes the framed packets of one TCP connection.
fn pass_tcp(mut stream: impl Read + Write, seen: &AtomicUsize) {
    loop {
        let mut length = [0; 2];
        if stream.read_exact(&mut length).is_err() {
            return;
        }
        let mut packet = vec![0; usize::from(u16::from_be_bytes(length))];
        if stream.read_exact(&mut packet).is_err() {
            return;
        }
        seen.fetch_add(1, Ordering::SeqCst);
        let Some(reply) = pass(&packet) else { continue };
        let Ok(length) = u16::try_from(reply.len()) else {
            return;
        };
        if stream
            .write_all(&[&length.to_be_bytes()[..], &reply].concat())
            .is_err()
        {
            return;
        }
    }
}

impl Relay {
    /// Starts a relay on a port free over UDP and TCP.
    ///
    /// # Panics
    ///
    /// When no socket can be bound.
    #[must_use]
    pub fn start() -> Self {
        let (udp, tcp) = loop {
            let udp = UdpSocket::bind("127.0.0.1:0").expect("a UDP socket");
            let addr = udp.local_addr().expect("an address");
            if let Ok(tcp) = TcpListener::bind(addr) {
                break (udp, tcp);
            }
        };
        let addr = udp.local_addr().expect("an address");
        let seen = Arc::new((AtomicUsize::new(0), AtomicUsize::new(0)));
        let counted = Arc::clone(&seen);
        thread::spawn(move || {
            let mut buf = vec![0; usize::from(u16::MAX)];
            while let Ok((len, from)) = udp.recv_from(&mut buf) {
                counted.0.fetch_add(1, Ordering::SeqCst);
                if let Some(reply) = pass(&buf[..len]) {
                    let _ = udp.send_to(&reply, from);
                }
            }
        });
        let counted = Arc::clone(&seen);
        thread::spawn(move || {
            for stream in tcp.incoming().flatten() {
                let counted = Arc::clone(&counted);
                thread::spawn(move || pass_tcp(stream, &counted.1));
            }
        });
        Self { seen, addr }
    }

    /// The packets it got over UDP and over TCP.
    #[must_use]
    pub fn seen(&self) -> (usize, usize) {
        (
            self.seen.0.load(Ordering::SeqCst),
            self.seen.1.load(Ordering::SeqCst),
        )
    }
}
