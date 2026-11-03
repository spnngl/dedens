//! RFC 7766 on `dedensd`'s TCP listener, §6.2.3 and §8: a connection that sends a broken frame costs nothing but its
//! slot. A length prefix with no message behind it (the frame that made aardvark-dns spin at 100% CPU,
//! CVE-2026-35406), a length of 0, half a prefix, and a message that trickles in all end the connection, or leave it
//! to the idle close (D47); a full frame holding a message that does not read gets FORMERR and the connection
//! stays. Meanwhile a second client's UDP and TCP queries are answered, and the server's CPU time does not grow.

#![cfg(unix)]

mod common;

use std::io::{ErrorKind, Read, Write};
use std::net::TcpStream;
use std::process::Command;
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use common::{
    Responder, Server, ask_tcp, ask_udp, captured, decode, framed, query_for, read_framed,
};
use dedens_proto::Rcode;

/// The idle time of a TCP connection (D47).
const IDLE: Duration = Duration::from_secs(10);

/// How long a connection may last past [`IDLE`]: a loaded machine reads late, it does not hold a connection open.
const SLACK: Duration = Duration::from_secs(20);

/// How long the server's CPU time is watched.
const WINDOW: Duration = Duration::from_secs(4);

/// The CPU time the server may use in [`WINDOW`]: `ps` gives whole seconds on Linux, so a few milliseconds of work
/// can show as one, where a thread spinning for [`WINDOW`] shows at least three. CPU time, not queries answered late,
/// because it does not move with the load of the machine.
const CPU_LIMIT: f64 = 2.0;

/// A server forwarding to a responder, and the query both clients ask.
struct Fixture {
    server: Server,
    query: Vec<u8>,
    _upstream: Responder,
}

impl Fixture {
    fn start() -> Self {
        let upstream = Responder::start(&["a"]);
        let fixture = Self {
            server: Server::start(upstream.addr, ""),
            query: query_for(&captured("a"), 1),
            _upstream: upstream,
        };
        fixture.assert_served();
        fixture
    }

    /// A second client, over UDP and over a new TCP connection, gets its answer.
    fn assert_served(&self) {
        for reply in [
            ask_udp(self.server.addr, &self.query),
            ask_tcp(self.server.addr, &self.query),
        ] {
            assert_eq!((reply.header.id, reply.rcode()), (1, Rcode::NOERROR));
        }
    }

    /// The CPU seconds the server used so far.
    fn cpu(&self) -> f64 {
        let output = Command::new("ps")
            .args(["-o", "time=", "-p", &self.server.pid().to_string()])
            .output()
            .expect("ps runs");
        let text = String::from_utf8(output.stdout).expect("ps writes text");
        // `[DD-][[hh:]mm:]ss[.cc]`, the CPU time of every thread, on Linux and on macOS.
        let (days, clock) = text.trim().split_once('-').unwrap_or(("0", text.trim()));
        let number = |text: &str| text.parse::<f64>().expect("a number of ps's time");
        let clock = clock
            .split(':')
            .fold(0.0, |total, part| total * 60.0 + number(part));
        number(days) * 86400.0 + clock
    }

    /// The server answers a second client at both ends of [`WINDOW`], and used less than [`CPU_LIMIT`] seconds of
    /// CPU since `before`, a reading of [`Fixture::cpu`].
    fn assert_unharmed(&self, before: f64) {
        self.assert_served();
        thread::sleep(WINDOW);
        self.assert_served();
        let used = self.cpu() - before;
        assert!(used < CPU_LIMIT, "{used} s of CPU in {WINDOW:?}");
    }
}

/// Reads `stream` until the server closes it, each second writing a byte if `trickle`, on a thread: its time. The
/// server sends nothing more, and closes within [`IDLE`] and [`SLACK`].
fn until_closed(mut stream: TcpStream, trickle: bool) -> JoinHandle<Duration> {
    stream
        .set_read_timeout(Some(Duration::from_secs(1)))
        .expect("a timeout");
    thread::spawn(move || {
        let start = Instant::now();
        loop {
            assert!(
                start.elapsed() < IDLE + SLACK,
                "open after {:?}",
                start.elapsed()
            );
            if trickle && stream.write_all(&[0]).is_err() {
                return start.elapsed();
            }
            match stream.read(&mut [0; 1]) {
                Ok(read) => {
                    assert_eq!(read, 0, "the server wrote to a broken connection");
                    return start.elapsed();
                }
                Err(error)
                    if matches!(error.kind(), ErrorKind::WouldBlock | ErrorKind::TimedOut) => {}
                // Reset: closed with the bytes we sent unread.
                Err(_) => return start.elapsed(),
            }
        }
    })
}

/// A connection to the server, which `bytes` open: sent as they are. A reply that does not come fails the test
/// within 10 s, as in [`ask_tcp`], and does not hang it.
fn connect(fixture: &Fixture, bytes: &[u8]) -> TcpStream {
    let mut stream = TcpStream::connect(fixture.server.addr).expect("connected");
    stream
        .set_read_timeout(Some(Duration::from_secs(10)))
        .expect("a timeout");
    stream.write_all(bytes).expect("sent");
    stream
}

/// The length of a 60-byte message, as aardvark-dns's test sends it.
const SIXTY: [u8; 2] = 60_u16.to_be_bytes();

/// A length with nothing behind it, the client gone: the connection ends, and no thread spins.
#[test]
fn a_length_alone_then_a_close_costs_no_cpu() {
    let fixture = Fixture::start();
    let before = fixture.cpu();
    drop(connect(&fixture, &SIXTY));
    fixture.assert_unharmed(before);
}

/// The same, the client silent and not gone: the idle close ends it, while others are served.
#[test]
fn a_length_alone_then_silence_is_closed_by_the_idle_time() {
    let fixture = Fixture::start();
    let before = fixture.cpu();
    let closed = until_closed(connect(&fixture, &SIXTY), false);
    fixture.assert_unharmed(before);
    closed.join().expect("closed within the idle time");
}

/// Half of a length (RFC 7766 §8: a message may arrive in pieces), the client gone.
#[test]
fn one_byte_of_a_length_then_a_close_costs_no_cpu() {
    let fixture = Fixture::start();
    let before = fixture.cpu();
    drop(connect(&fixture, &SIXTY[..1]));
    fixture.assert_unharmed(before);
}

/// A length of 0 is an empty message: it reads nothing, as a UDP datagram of no bytes, is not answered, and leaves
/// the connection to the next message and then to the idle close.
#[test]
fn a_length_of_zero_is_skipped_and_the_connection_idles_out() {
    let fixture = Fixture::start();
    let before = fixture.cpu();
    let mut stream = connect(&fixture, &framed(&[]));
    stream.write_all(&framed(&fixture.query)).expect("sent");
    // The first reply is the query's, so the empty message got none.
    let reply = decode(&read_framed(&mut stream).expect("a reply"));
    assert_eq!((reply.header.id, reply.rcode()), (1, Rcode::NOERROR));
    let closed = until_closed(stream, false);
    fixture.assert_unharmed(before);
    closed.join().expect("closed within the idle time");
}

/// A length promising more than comes, a byte a second: the time of the whole message is limited, not the time
/// between bytes, so the connection is closed long before the 60 bytes are in.
#[test]
fn a_message_trickling_in_is_closed_by_the_idle_time() {
    let fixture = Fixture::start();
    let before = fixture.cpu();
    let closed = until_closed(connect(&fixture, &SIXTY), true);
    fixture.assert_unharmed(before);
    let open = closed.join().expect("closed within the idle time");
    assert!(open < Duration::from_secs(60), "{open:?}");
}

/// A frame whole, holding a header that counts a question and carries none: FORMERR to it (RFC 1035 §4.1.1), and the
/// connection stays for the next query, and for the idle close.
#[test]
fn a_whole_frame_of_a_malformed_message_gets_formerr_and_the_connection_stays() {
    let fixture = Fixture::start();
    let before = fixture.cpu();
    // The header of the query, which counts one question: QDCOUNT is its bytes 4 and 5.
    let header = &fixture.query[..12];
    assert_eq!(header[4..6], [0, 1]);
    let mut stream = connect(&fixture, &framed(header));
    let reply = decode(&read_framed(&mut stream).expect("a reply"));
    assert_eq!((reply.header.id, reply.rcode()), (1, Rcode::FORMERR));
    stream.write_all(&framed(&fixture.query)).expect("sent");
    let reply = decode(&read_framed(&mut stream).expect("a second reply"));
    assert_eq!((reply.header.id, reply.rcode()), (1, Rcode::NOERROR));
    let closed = until_closed(stream, false);
    fixture.assert_unharmed(before);
    closed.join().expect("closed within the idle time");
}
