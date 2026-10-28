//! `dedensd` over real sockets on loopback: forwarding over UDP and TCP to a responder that answers captured
//! bytes, several queries on one TCP connection (RFC 7766 §6.2.1), SERVFAIL when upstream stays silent, a start
//! that fails on a taken address, and `validate` reading a configuration file without binding.

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream, UdpSocket};
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::thread;
use std::time::{Duration, Instant};

use dedens_proto::{Message, Opcode, Rcode};

/// A captured response of `dedens-proto`'s test data.
fn captured(case: &str) -> Vec<u8> {
    let path = format!(
        "{}/../../crates/dedens-proto/tests/testdata/{case}.bin",
        env!("CARGO_MANIFEST_DIR")
    );
    std::fs::read(path).expect("a captured response")
}

/// A query, under `id`, for the question of `response`.
fn query_for(response: &[u8], id: u16) -> Vec<u8> {
    let question = Message::decode(response)
        .expect("a captured response decodes")
        .message
        .questions
        .swap_remove(0);
    Message::query(id, question).to_vec().expect("a query fits")
}

/// `response` under the ID of `query`.
fn answer(query: &[u8], response: &[u8]) -> Vec<u8> {
    let mut answer = response.to_vec();
    answer[..2].copy_from_slice(&query[..2]);
    answer
}

/// A loopback upstream answering `response` to every query, over UDP and TCP on one port.
fn responder(response: Vec<u8>) -> SocketAddr {
    let udp = UdpSocket::bind("127.0.0.1:0").expect("a UDP port");
    let addr = udp.local_addr().expect("its address");
    let tcp = TcpListener::bind(addr).expect("the same port over TCP");
    let for_udp = response.clone();
    thread::spawn(move || {
        let mut buf = vec![0; 65535];
        while let Ok((len, peer)) = udp.recv_from(&mut buf) {
            let _ = udp.send_to(&answer(&buf[..len], &for_udp), peer);
        }
    });
    thread::spawn(move || {
        for mut stream in tcp.incoming().flatten() {
            while let Some(query) = read_framed(&mut stream) {
                let _ = stream.write_all(&framed(&answer(&query, &response)));
            }
        }
    });
    addr
}

/// A loopback upstream that never answers.
fn silent() -> (UdpSocket, SocketAddr) {
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

/// A running `dedensd`, killed when dropped.
struct Server {
    child: Child,
    addr: SocketAddr,
}

impl Drop for Server {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// A configuration file of a caching forwarder answering on `listen`, forwarding to `upstream`; removed with the
/// test process's temporary files, each test writing its own.
fn config(listen: &str, upstream: &str) -> PathBuf {
    static NEXT: AtomicUsize = AtomicUsize::new(0);
    let path = std::env::temp_dir().join(format!(
        "dedensd-{}-{}.yaml",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::Relaxed)
    ));
    let text = format!(
        "listen: ['{listen}']\npipeline: [cache, up]\nstages:\n  cache:\n    type: cache\n  up:\n    type: forward\n    servers: ['{upstream}']\n"
    );
    std::fs::write(&path, text).expect("a configuration file");
    path
}

/// Starts `dedensd` on a free port, forwarding to `upstream`, and waits until it accepts connections.
fn start(upstream: SocketAddr) -> Server {
    let addr = free_port();
    let child = Command::new(env!("CARGO_BIN_EXE_dedensd"))
        .arg("--config")
        .arg(config(&addr.to_string(), &upstream.to_string()))
        .stderr(Stdio::null())
        .spawn()
        .expect("dedensd starts");
    let server = Server { child, addr };
    let start = Instant::now();
    while TcpStream::connect(addr).is_err() {
        assert!(start.elapsed() < Duration::from_secs(10), "dedensd listens");
        thread::sleep(Duration::from_millis(20));
    }
    server
}

/// The reply over UDP to `query`.
fn ask_udp(server: SocketAddr, query: &[u8]) -> Message<'static> {
    let socket = UdpSocket::bind("127.0.0.1:0").expect("a UDP port");
    socket
        .set_read_timeout(Some(Duration::from_secs(10)))
        .expect("a timeout");
    socket.send_to(query, server).expect("sent");
    let mut buf = vec![0; 65535];
    let len = socket.recv(&mut buf).expect("a reply");
    decode(&buf[..len])
}

fn decode(wire: &[u8]) -> Message<'static> {
    let decoded = Message::decode(wire).expect("a reply decodes");
    assert_eq!(decoded.violations, []);
    decoded.message.into_owned()
}

/// `wire` behind its two-byte length (RFC 1035 §4.2.2).
fn framed(wire: &[u8]) -> Vec<u8> {
    let len = u16::try_from(wire.len()).expect("a message fits");
    [&len.to_be_bytes()[..], wire].concat()
}

/// The next message of a TCP stream, `None` at its end.
fn read_framed(stream: &mut TcpStream) -> Option<Vec<u8>> {
    let mut len = [0; 2];
    stream.read_exact(&mut len).ok()?;
    let mut message = vec![0; usize::from(u16::from_be_bytes(len))];
    stream.read_exact(&mut message).ok()?;
    Some(message)
}

#[test]
fn queries_over_udp_and_tcp_are_forwarded() {
    let response = captured("a");
    let upstream = decode(&response);
    let server = start(responder(response.clone()));
    let reply = ask_udp(server.addr, &query_for(&response, 1));
    assert_eq!((reply.header.id, reply.rcode()), (1, Rcode::NOERROR));
    assert_eq!(reply.answer, upstream.answer);
    let mut stream = TcpStream::connect(server.addr).expect("connected");
    stream
        .write_all(&framed(&query_for(&response, 2)))
        .expect("sent");
    let reply = decode(&read_framed(&mut stream).expect("a reply"));
    assert_eq!((reply.header.id, reply.rcode()), (2, Rcode::NOERROR));
    assert_eq!(reply.answer, upstream.answer);
}

#[test]
fn a_tcp_connection_answers_several_queries() {
    let response = captured("a");
    let server = start(responder(response.clone()));
    // The opcode is bits 1 to 4 of the third byte (RFC 1035 §4.1.1).
    let mut notify = query_for(&response, 3);
    notify[2] = notify[2] & 0x87 | Opcode::NOTIFY.0 << 3;
    let mut stream = TcpStream::connect(server.addr).expect("connected");
    for query in [query_for(&response, 1), query_for(&response, 2), notify] {
        stream.write_all(&framed(&query)).expect("sent");
    }
    let mut replies: Vec<_> = (0..3)
        .map(|_| {
            let reply = decode(&read_framed(&mut stream).expect("a reply"));
            (reply.header.id, reply.rcode())
        })
        .collect();
    replies.sort_unstable();
    assert_eq!(
        replies,
        [(1, Rcode::NOERROR), (2, Rcode::NOERROR), (3, Rcode::NOTIMP)]
    );
}

#[test]
fn a_silent_upstream_gets_servfail() {
    let (_socket, upstream) = silent();
    let server = start(upstream);
    let reply = ask_udp(server.addr, &query_for(&captured("a"), 1));
    assert_eq!((reply.header.id, reply.rcode()), (1, Rcode::SERVFAIL));
}

#[test]
fn a_taken_address_fails_the_start() {
    let taken = UdpSocket::bind("127.0.0.1:0").expect("a UDP port");
    let addr = taken.local_addr().expect("its address").to_string();
    let output = Command::new(env!("CARGO_BIN_EXE_dedensd"))
        .arg("--config")
        .arg(config(&addr, "127.0.0.1"))
        .output()
        .expect("dedensd runs");
    assert_eq!(output.status.code(), Some(1));
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains(&format!("cannot bind UDP {addr}")),
        "{stderr}"
    );
}

#[test]
fn validate_reads_the_configuration_without_binding() {
    let taken = UdpSocket::bind("127.0.0.1:0").expect("a UDP port");
    let path = config(
        &taken.local_addr().expect("its address").to_string(),
        "${UPSTREAM}",
    );
    let validate = |upstream: Option<&str>| {
        let mut command = Command::new(env!("CARGO_BIN_EXE_dedensd"));
        command.arg("validate").arg("--config").arg(&path);
        match upstream {
            Some(upstream) => command.env("UPSTREAM", upstream),
            None => command.env_remove("UPSTREAM"),
        };
        command.output().expect("dedensd runs")
    };
    let output = validate(Some("127.0.0.1"));
    assert_eq!(output.status.code(), Some(0));
    assert!(String::from_utf8_lossy(&output.stdout).ends_with(": valid\n"));
    let output = validate(None);
    assert_eq!(output.status.code(), Some(1));
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("variable `UPSTREAM` is not set"),
        "{stderr}"
    );
}
