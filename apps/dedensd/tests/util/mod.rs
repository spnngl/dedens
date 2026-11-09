//! Shared by the tests running `dedensd`: a running server with its configuration file (`server`), and DNS over
//! UDP and TCP with the standard library.

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream, UdpSocket};
use std::process::Command;
use std::time::Duration;

use dedens_net::tcp::frame;
use dedens_proto::Message;

mod server;

/// A reply decoded as a capture is: without a broken rule.
pub(crate) use dedens_testkit::message as decode;
pub(crate) use server::{Server, config, write_config, write_key};

/// The query, under `id`, that the captured response `case` answers, as sent.
pub(crate) fn query_for(case: &str, id: u16) -> Vec<u8> {
    dedens_testkit::query(case, id)
        .to_vec()
        .expect("a query fits")
}

/// A loopback upstream that never answers.
pub(crate) fn silent() -> (UdpSocket, SocketAddr) {
    let udp = UdpSocket::bind("127.0.0.1:0").expect("a UDP port");
    let addr = udp.local_addr().expect("its address");
    (udp, addr)
}

/// What `dedensd validate` makes of the configuration `text`: its exit code and its stderr.
pub(crate) fn validate(text: &str) -> (Option<i32>, String) {
    let output = Command::new(env!("CARGO_BIN_EXE_dedensd"))
        .arg("validate")
        .arg("--config")
        .arg(write_config(text))
        .output()
        .expect("dedensd runs");
    (
        output.status.code(),
        String::from_utf8_lossy(&output.stderr).into_owned(),
    )
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

/// `wire` behind its two-byte length (RFC 1035 §4.2.2).
pub(crate) fn framed(wire: &[u8]) -> Vec<u8> {
    frame(wire).expect("a message fits")
}

/// The next message of a TCP stream, `None` at its end.
pub(crate) fn read_framed(stream: &mut TcpStream) -> Option<Vec<u8>> {
    let mut len = [0; 2];
    stream.read_exact(&mut len).ok()?;
    let mut message = vec![0; usize::from(u16::from_be_bytes(len))];
    stream.read_exact(&mut message).ok()?;
    Some(message)
}
