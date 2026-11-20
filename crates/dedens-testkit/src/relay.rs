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

use crate::loopback::{accept, receive};

/// The length of the prefix: the magic, the address and the port.
const PREFIX_LEN: usize = 28;

/// The magic of the prefix: eight `0xff` and two NULs.
const MAGIC: [u8; 10] = [0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0, 0];

/// The UDP ports tried before one is found free over TCP too.
const BINDS: usize = 64;

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
    // A packet without the magic is no Anonymized DNSCrypt query: dropped, as the reference relay does.
    if prefix[..10] != MAGIC {
        return None;
    }
    let ip = Ipv6Addr::from(<[u8; 16]>::try_from(&prefix[10..26]).ok()?);
    let target = SocketAddr::new(
        ip.to_canonical(),
        u16::from_be_bytes([prefix[26], prefix[27]]),
    );
    let socket = UdpSocket::bind("127.0.0.1:0").ok()?;
    socket.set_read_timeout(Some(WAIT)).ok()?;
    // Connected: a datagram from another address is no response.
    socket.connect(target).ok()?;
    socket.send(inner).ok()?;
    let mut buf = vec![0; usize::from(u16::MAX)];
    let len = socket.recv(&mut buf).ok()?;
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
    /// When no socket can be bound, or no port of [`BINDS`] tried is free over TCP too.
    #[must_use]
    pub fn start() -> Self {
        let (udp, tcp) = (0..BINDS)
            .find_map(|_| {
                let udp = UdpSocket::bind("127.0.0.1:0").expect("a UDP socket");
                let addr = udp.local_addr().expect("an address");
                TcpListener::bind(addr).ok().map(|tcp| (udp, tcp))
            })
            .expect("a port free over UDP and TCP");
        let addr = udp.local_addr().expect("an address");
        let seen = Arc::new((AtomicUsize::new(0), AtomicUsize::new(0)));
        let counted = Arc::clone(&seen);
        thread::spawn(move || {
            let mut buf = vec![0; usize::from(u16::MAX)];
            loop {
                let (len, from) = receive(&udp, &mut buf);
                counted.0.fetch_add(1, Ordering::SeqCst);
                if let Some(reply) = pass(&buf[..len]) {
                    let _ = udp.send_to(&reply, from);
                }
            }
        });
        let counted = Arc::clone(&seen);
        thread::spawn(move || {
            loop {
                let stream = accept(&tcp);
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_packet_without_the_magic_is_dropped_and_the_relay_passes_the_next() {
        let resolver = UdpSocket::bind("127.0.0.1:0").expect("a socket");
        let SocketAddr::V4(at) = resolver.local_addr().expect("an address") else {
            unreachable!("bound on IPv4");
        };
        let prefix = [
            &MAGIC[..],
            &at.ip().to_ipv6_mapped().octets(),
            &at.port().to_be_bytes(),
        ]
        .concat();
        let inner = [0x5a; 32];
        let relay = Relay::start();
        let client = UdpSocket::bind("127.0.0.1:0").expect("a socket");
        let mut wrong = prefix.clone();
        wrong[0] = 0;
        client
            .send_to(&[&wrong[..], &inner].concat(), relay.addr)
            .expect("sent");
        client
            .send_to(&[&prefix[..], &inner].concat(), relay.addr)
            .expect("sent");
        resolver.set_read_timeout(Some(WAIT)).expect("a timeout");
        let mut buf = [0; 64];
        let (len, _) = resolver
            .recv_from(&mut buf)
            .expect("the second packet passed");
        assert_eq!(&buf[..len], &inner);
        assert_eq!(relay.seen(), (2, 0));
    }

    /// A datagram to the relay's socket from another address than the resolver's is no response: the relay waits
    /// for the resolver's.
    #[test]
    fn a_reply_from_another_address_is_not_passed() {
        let resolver = UdpSocket::bind("127.0.0.1:0").expect("a socket");
        let SocketAddr::V4(at) = resolver.local_addr().expect("an address") else {
            unreachable!("bound on IPv4");
        };
        let prefix = [
            &MAGIC[..],
            &at.ip().to_ipv6_mapped().octets(),
            &at.port().to_be_bytes(),
        ]
        .concat();
        let relay = Relay::start();
        let client = UdpSocket::bind("127.0.0.1:0").expect("a socket");
        client.set_read_timeout(Some(WAIT)).expect("a timeout");
        client
            .send_to(&[&prefix[..], &[0x5a; 32]].concat(), relay.addr)
            .expect("sent");
        resolver.set_read_timeout(Some(WAIT)).expect("a timeout");
        let mut buf = [0; 64];
        let (_, from) = resolver.recv_from(&mut buf).expect("the packet passed");
        let other = UdpSocket::bind("127.0.0.1:0").expect("a socket");
        other.send_to(&[1; 16], from).expect("sent");
        resolver.send_to(&[2; 16], from).expect("sent");
        let (len, _) = client.recv_from(&mut buf).expect("a reply");
        assert_eq!(&buf[..len], &[2; 16]);
    }
}
