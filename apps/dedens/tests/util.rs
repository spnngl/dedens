//! Helpers shared by the tests of the command: the binary, its output, the queries a responder received, an RDAP
//! server.

use std::io::{BufRead, BufReader, Write};
use std::net::{SocketAddr, TcpListener};
use std::sync::{Arc, Mutex};
use std::thread;

use assert_cmd::Command;
use compio::rustls::version::TLS13;
use compio::rustls::{ServerConfig, ServerConnection, StreamOwned};
use dedens_proto::Message;
use dedens_testkit::certificates::certificates;
use dedens_testkit::responder::{Responder, Transport};
use tempfile::NamedTempFile;

/// The command, without colors and with a resolv.conf that does not exist.
pub(crate) fn dedens() -> Command {
    let mut command = assert_cmd::cargo_bin_cmd!("dedens");
    command
        .env("DEDENS_RESOLV_CONF", "/nonexistent/resolv.conf")
        .env_remove("NO_COLOR")
        .env_remove("CLICOLOR_FORCE");
    command
}

/// The standard output of a run that exits with `code`.
pub(crate) fn run(args: &[&str], code: i32) -> String {
    let output = dedens()
        .args(args)
        .assert()
        .code(code)
        .get_output()
        .stdout
        .clone();
    String::from_utf8(output).expect("UTF-8")
}

/// `text` with the run's own numbers replaced by `N`: RTT, message ID, the server's port.
pub(crate) fn redact(text: &str, port: u16) -> String {
    let mut text: String = text
        .replace(&format!(":{port}"), ":PORT")
        .split_inclusive('\n')
        .map(|line| match line.split_once(" ms from ") {
            Some((head, tail)) => {
                let rtt = head.rfind(' ').map_or(0, |at| at + 1);
                format!("{}N ms from {tail}", &head[..rtt])
            }
            None => line.to_owned(),
        })
        .collect();
    for prefix in ["\"rtt_us\":", "\"id\":", "rtt_us: ", "id: "] {
        let mut out = String::new();
        let mut rest = text.as_str();
        while let Some(at) = rest.find(prefix) {
            let (before, after) = rest.split_at(at + prefix.len());
            out.push_str(before);
            let digits = after
                .find(|c: char| !c.is_ascii_digit() && c != '.')
                .unwrap_or(after.len());
            if digits > 0 {
                out.push('N');
            }
            rest = &after[digits..];
        }
        out.push_str(rest);
        text = out;
    }
    text
}

/// The queries `responder` received, decoded.
pub(crate) fn queries(responder: &Responder) -> Vec<(Transport, Message<'static>)> {
    responder
        .queries()
        .into_iter()
        .map(|(transport, wire)| {
            let message = Message::decode(&wire)
                .expect("a query")
                .message
                .into_owned();
            (transport, message)
        })
        .collect()
}

/// An HTTPS server on the loopback answering each path of its table with a status and a body, 500 for another, and
/// the heads of the requests it read. The body of a redirect (3xx) is the path it sends to, on this server.
pub(crate) struct Rdap {
    addr: SocketAddr,
    ca: NamedTempFile,
    heads: Arc<Mutex<Vec<String>>>,
}

impl Rdap {
    pub(crate) fn start(table: &'static [(&'static str, u16, &'static [u8])]) -> Self {
        let certificates = certificates();
        let config = Arc::new(certificates.config(&[&TLS13], b"http/1.1"));
        let mut ca = NamedTempFile::new().expect("a file");
        ca.write_all(certificates.ca_pem.as_bytes())
            .expect("the CA");
        let listener = TcpListener::bind("127.0.0.1:0").expect("a port");
        let addr = listener.local_addr().expect("an address");
        let heads = Arc::new(Mutex::new(Vec::new()));
        let seen = Arc::clone(&heads);
        thread::spawn(move || {
            for stream in listener.incoming().flatten() {
                let config = Arc::clone(&config);
                let seen = Arc::clone(&seen);
                thread::spawn(move || serve(&config, stream, addr, table, &seen));
            }
        });
        Self { addr, ca, heads }
    }

    /// Its scheme, address and port, the `DEDENS_RDAP` that sends `dedens` here.
    pub(crate) fn origin(&self) -> String {
        format!("https://{}", self.addr)
    }

    /// The command asking this server, trusting its authority.
    pub(crate) fn dedens(&self, args: &[&str]) -> Command {
        let mut command = dedens();
        command
            .env("DEDENS_RDAP", self.origin())
            .arg(format!("--tls-ca={}", self.ca.path().display()))
            .args(args);
        command
    }

    /// The standard output of `args`, exiting with `code`, the RTT and port redacted.
    pub(crate) fn run(&self, args: &[&str], code: i32) -> String {
        let out = self
            .dedens(args)
            .assert()
            .code(code)
            .get_output()
            .stdout
            .clone();
        redact(&String::from_utf8(out).expect("UTF-8"), self.addr.port())
    }

    /// The heads of the requests it read, in order.
    pub(crate) fn heads(&self) -> Vec<String> {
        self.heads.lock().expect("the heads").clone()
    }

    /// The path of each request it read, in order.
    pub(crate) fn paths(&self) -> Vec<String> {
        self.heads()
            .iter()
            .map(|head| head.split(' ').nth(1).unwrap_or_default().to_owned())
            .collect()
    }
}

/// Answers the one request of `stream`, to the server at `addr`.
fn serve(
    config: &Arc<ServerConfig>,
    stream: std::net::TcpStream,
    addr: SocketAddr,
    table: &[(&str, u16, &[u8])],
    heads: &Mutex<Vec<String>>,
) {
    let connection = ServerConnection::new(Arc::clone(config)).expect("a connection");
    let mut tls = BufReader::new(StreamOwned::new(connection, stream));
    let mut head = String::new();
    loop {
        let mut line = String::new();
        if tls.read_line(&mut line).unwrap_or(0) == 0 {
            return;
        }
        if line == "\r\n" {
            break;
        }
        head.push_str(&line);
    }
    let path = head.split(' ').nth(1).unwrap_or_default().to_owned();
    heads.lock().expect("the heads").push(head);
    let (status, mut body) = table
        .iter()
        .find(|(at, _, _)| *at == path)
        .map_or((500, &b""[..]), |&(_, status, body)| (status, body));
    let mut location = String::new();
    if (300..400).contains(&status) {
        location = format!(
            "location: https://{addr}{}\r\n",
            String::from_utf8_lossy(body)
        );
        body = b"";
    }
    let tls = tls.get_mut();
    let _ = write!(
        tls,
        "HTTP/1.1 {status} X\r\ncontent-type: application/rdap+json\r\n{location}content-length: {}\r\nconnection: close\r\n\r\n",
        body.len()
    );
    let _ = tls.write_all(body);
    let _ = tls.flush();
    tls.conn.send_close_notify();
    let _ = tls.flush();
}
