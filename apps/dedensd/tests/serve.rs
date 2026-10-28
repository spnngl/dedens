//! `dedensd` over real sockets on loopback: forwarding over UDP and TCP to a responder that answers captured
//! bytes, several queries on one TCP connection (RFC 7766 §6.2.1), SERVFAIL when upstream stays silent, a start
//! that fails on a taken address, and `validate` reading a configuration file without binding.

mod common;

use std::io::Write;
use std::net::{TcpStream, UdpSocket};
use std::process::Command;

use common::{
    Responder, Server, ask_tcp, ask_udp, captured, config, decode, framed, query_for, read_framed,
    silent,
};
use dedens_proto::{Opcode, Rcode};

#[test]
fn queries_over_udp_and_tcp_are_forwarded() {
    let response = captured("a");
    let upstream = decode(&response);
    let server = Server::start(Responder::start(&["a"]).addr);
    let reply = ask_udp(server.addr, &query_for(&response, 1));
    assert_eq!((reply.header.id, reply.rcode()), (1, Rcode::NOERROR));
    assert_eq!(reply.answer, upstream.answer);
    let reply = ask_tcp(server.addr, &query_for(&response, 2));
    assert_eq!((reply.header.id, reply.rcode()), (2, Rcode::NOERROR));
    assert_eq!(reply.answer, upstream.answer);
}

#[test]
fn a_tcp_connection_answers_several_queries() {
    let response = captured("a");
    let server = Server::start(Responder::start(&["a"]).addr);
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
    let server = Server::start(upstream);
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
