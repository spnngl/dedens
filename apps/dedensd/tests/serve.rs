//! `dedensd` over real sockets on loopback: forwarding over UDP and TCP to a responder that answers captured
//! bytes, several queries on one TCP connection (RFC 7766 §6.2.1), SERVFAIL when upstream stays silent, a start
//! that fails on a taken address, SIGTERM and SIGINT ending it, `validate` reading a configuration file without binding, and expired data
//! answering a client kept waiting while resolution goes on (RFC 8767 §5).

mod common;

use std::io::Write;
use std::net::{TcpStream, UdpSocket};
use std::process::Command;
use std::thread;
use std::time::{Duration, Instant};

use common::{
    Responder, Server, ask_tcp, ask_udp, captured, config, decode, framed, query_for, read_framed,
    silent,
};
use dedens_proto::edns::{EdnsOption, InfoCode};
use dedens_proto::{Message, Opcode, Rcode};

#[test]
fn queries_over_udp_and_tcp_are_forwarded() {
    let response = captured("a");
    let upstream = decode(&response);
    // No minimum TTL: the records come back as captured.
    let server = Server::start(Responder::start(&["a"]).addr, "    min_ttl: 0\n");
    let reply = ask_udp(server.addr, &query_for(&response, 1));
    assert_eq!((reply.header.id, reply.rcode()), (1, Rcode::NOERROR));
    assert_eq!(reply.answer, upstream.answer);
    let reply = ask_tcp(server.addr, &query_for(&response, 2));
    assert_eq!((reply.header.id, reply.rcode()), (2, Rcode::NOERROR));
    assert_eq!(reply.answer, upstream.answer);
}

/// D115: `threads` sets the serving threads, which the "serving" event counts; more than one needs Linux, where
/// `SO_REUSEPORT` spreads queries.
#[test]
fn threads_set_the_serving_threads() {
    let response = captured("a");
    let upstream = Responder::start(&["a"]);
    let threads: u64 = if cfg!(target_os = "linux") { 3 } else { 1 };
    let server = Server::configured(|listen| {
        format!(
            "threads: {threads}\nlisten: ['{listen}']\npipeline: [up]\nstages:\n  up:\n    type: forward\n    servers: ['{}']\n    timeout_ms: 1000\n    tries: 1\n",
            upstream.addr
        )
    });
    assert_eq!(server.serving["fields"]["threads"], threads);
    let reply = ask_udp(server.addr, &query_for(&response, 1));
    assert_eq!(reply.rcode(), Rcode::NOERROR);
}

#[test]
fn a_tcp_connection_answers_several_queries() {
    let response = captured("a");
    let server = Server::start(Responder::start(&["a"]).addr, "");
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
    let server = Server::start(upstream, "");
    let reply = ask_udp(server.addr, &query_for(&captured("a"), 1));
    assert_eq!((reply.header.id, reply.rcode()), (1, Rcode::SERVFAIL));
}

/// D107: the start says which driver the threads run on, as compio falls back from `io_uring` to `poll` without
/// anyone seeing (D51). Linux has `io_uring` from 5.19, the floor: `poll` there fails the test, unless
/// `DEDENS_TEST_ALLOW_POLL` is set, for a container whose seccomp filter refuses `io_uring`.
#[test]
fn the_start_logs_the_driver() {
    let (_socket, upstream) = silent();
    let server = Server::start(upstream, "");
    let driver = server.serving["fields"]["driver"].as_str();
    let known: &[_] = if !cfg!(target_os = "linux") {
        &["poll", "iocp"]
    } else if std::env::var_os("DEDENS_TEST_ALLOW_POLL").is_some() {
        &["io_uring", "poll"]
    } else {
        &["io_uring"]
    };
    assert!(
        driver.is_some_and(|driver| known.contains(&driver)),
        "{driver:?}"
    );
}

/// D157: SIGTERM and SIGINT end the server at once, with success and its reason logged; as PID 1 of the image the
/// kernel would drop either without a handler.
#[cfg(unix)]
#[test]
fn sigterm_and_sigint_end_the_server() {
    for (name, signal) in [("TERM", "SIGTERM"), ("INT", "SIGINT")] {
        let (_socket, upstream) = silent();
        let mut server = Server::start(upstream, "");
        server.signal(name);
        let stopped = server.event("dedensd ends: stopped").expect("logged");
        assert_eq!(stopped["fields"]["signal"], signal);
        let status = server.exited().expect("exited");
        assert!(status.success(), "{signal}: {status}");
    }
}

#[test]
fn a_taken_address_fails_the_start() {
    let taken = UdpSocket::bind("127.0.0.1:0").expect("a UDP port");
    let addr = taken.local_addr().expect("its address").to_string();
    let output = Command::new(env!("CARGO_BIN_EXE_dedensd"))
        .arg("--config")
        .arg(config(&addr, "127.0.0.1", ""))
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
        "",
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

/// The extended error codes of `reply`.
fn errors(reply: &Message<'_>) -> Vec<InfoCode> {
    let options = reply.edns.iter().flat_map(|edns| &edns.options);
    options
        .filter_map(|option| match option {
            EdnsOption::Ede(error) => Some(error.code),
            _ => None,
        })
        .collect()
}

#[test]
fn a_client_kept_waiting_gets_expired_data_and_the_next_one_fresh_data() {
    let response = captured("a");
    let upstream = Responder::slow("a", 3, Duration::from_millis(500));
    // No minimum TTL, which would keep the 3 seconds of the answer fresh for a minute.
    let server = Server::start(
        upstream.addr,
        "    min_ttl: 0\n    stale_answer_after_ms: 200\n",
    );
    let first = ask_udp(server.addr, &query_for(&response, 1));
    assert_eq!(errors(&first), []);
    // Past the TTL, upstream answers 500 ms late, within the 1 s timeout: expired data answers once the 200 ms
    // timer runs out.
    thread::sleep(Duration::from_millis(3200));
    let asked = Instant::now();
    let stale = ask_udp(server.addr, &query_for(&response, 2));
    assert!(
        (Duration::from_millis(200)..Duration::from_millis(450)).contains(&asked.elapsed()),
        "{:?}",
        asked.elapsed()
    );
    assert_eq!((stale.header.id, stale.rcode()), (2, Rcode::NOERROR));
    assert_eq!(errors(&stale), [InfoCode::STALE_ANSWER]);
    assert!(stale.answer.iter().all(|record| record.ttl.get() == 30));
    // Resolution went on and refreshed the entry.
    thread::sleep(Duration::from_millis(800));
    let fresh = ask_udp(server.addr, &query_for(&response, 3));
    assert_eq!((upstream.queries(), errors(&fresh)), (2, vec![]));
    assert!(fresh.answer.iter().all(|record| record.ttl.get() <= 3));
}
