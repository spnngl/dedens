//! Shared by the tests running `dedensd`: a running server with its
//! configuration file, and DNS over UDP and TCP with the standard library.

use std::collections::VecDeque;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream, UdpSocket};
use std::path::PathBuf;
use std::process::{Child, Command, ExitStatus, Stdio};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, PoisonError, mpsc};
use std::thread;
use std::time::{Duration, Instant};

use dedens_net::tcp::frame;
use dedens_proto::Message;
use serde_json::Value;

/// A query, under `id`, for the question of `response`.
pub(crate) fn query_for(response: &[u8], id: u16) -> Vec<u8> {
    let question = Message::decode(response)
        .expect("a captured response decodes")
        .message
        .questions
        .swap_remove(0);
    Message::query(id, question).to_vec().expect("a query fits")
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

/// A configuration file of a caching forwarder answering on `listen`, forwarding to `upstream` with one try of
/// 1 s, `cache` lines of settings for the cache stage, as `"    key: value\n"`.
pub(crate) fn config(listen: &str, upstream: &str, cache: &str) -> PathBuf {
    write_config(&forwarder(listen, upstream, cache))
}

/// The text of [`config`].
fn forwarder(listen: &str, upstream: &str, cache: &str) -> String {
    format!(
        "listen: ['{listen}']\npipeline: [cache, up]\nstages:\n  cache:\n    type: cache\n{cache}  up:\n    type: forward\n    servers: ['{upstream}']\n    timeout_ms: 1000\n    tries: 1\n"
    )
}

/// `text` in a configuration file of the temporary directory, each call its own.
pub(crate) fn write_config(text: &str) -> PathBuf {
    static NEXT: AtomicUsize = AtomicUsize::new(0);
    let path = std::env::temp_dir().join(format!(
        "dedensd-{}-{}.yaml",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::Relaxed)
    ));
    std::fs::write(&path, text).expect("a configuration file");
    path
}

/// Writes the private key `pem` to `path`, readable by its owner alone: `dedensd` refuses a key others can read (D115).
pub(crate) fn write_key(path: &std::path::Path, pem: impl AsRef<[u8]>) {
    std::fs::write(path, pem).expect("the key written");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
            .expect("the key's mode set");
    }
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

/// How long [`Server::event`] waits for an event before it panics: an event that does not come hangs a test.
const EVENT_TIMEOUT: Duration = Duration::from_secs(30);

/// A running `dedensd`, killed when dropped.
pub(crate) struct Server {
    child: Child,
    pub(crate) addr: SocketAddr,
    /// Its configuration file.
    pub(crate) config: PathBuf,
    /// Its events, one JSON object a line on stderr (D30).
    events: mpsc::Receiver<Value>,
    /// The events it logged before "serving", which a thread other than the main one (a list's download, whose reload
    /// follows) may log first: [`Server::event`] reads them before the rest.
    early: VecDeque<Value>,
    /// The "serving" event that announced it.
    pub(crate) serving: Value,
    /// Every line it wrote to stderr so far, as written.
    log: Arc<Mutex<Vec<String>>>,
}

impl Drop for Server {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

impl Server {
    /// Starts `dedensd` configured by [`config`]; see [`Server::configured`].
    pub(crate) fn start(upstream: SocketAddr, cache: &str) -> Self {
        Self::configured(|listen| forwarder(listen, &upstream.to_string(), cache))
    }

    /// Starts `dedensd` on a free port, configured by `text` of the address to listen on, and waits until it logs
    /// that it serves: its sockets are bound then. A connection accepted earlier could be another server's, on a
    /// port both were handed (with `SO_REUSEPORT` on Linux, both even bind it). So servers start one at a time,
    /// and one that cannot bind, its port taken meanwhile by another socket, exits and is started again on another
    /// port.
    pub(crate) fn configured(text: impl Fn(&str) -> String) -> Self {
        static STARTING: Mutex<()> = Mutex::new(());
        let _one = STARTING.lock().unwrap_or_else(PoisonError::into_inner);
        let mut tries = 0;
        loop {
            let addr = free_port();
            let config = write_config(&text(&addr.to_string()));
            let mut child = Command::new(env!("CARGO_BIN_EXE_dedensd"))
                .arg("--config")
                .arg(&config)
                .stderr(Stdio::piped())
                .spawn()
                .expect("dedensd starts");
            let stderr = child.stderr.take().expect("its piped stderr");
            let (send, events) = mpsc::channel();
            let log = Arc::new(Mutex::new(Vec::new()));
            let written = Arc::clone(&log);
            // Reads to the end of stderr, when the server exits, so a full pipe never blocks it.
            thread::spawn(move || {
                for line in BufReader::new(stderr).lines().map_while(Result::ok) {
                    let event = serde_json::from_str(&line);
                    written
                        .lock()
                        .unwrap_or_else(PoisonError::into_inner)
                        .push(line);
                    if let Ok(event) = event {
                        let _ = send.send(event);
                    }
                }
            });
            let mut server = Self {
                child,
                addr,
                config,
                events,
                early: VecDeque::new(),
                serving: Value::Null,
                log,
            };
            if let Some(serving) = server.next_event("serving", true) {
                server.serving = serving;
                return server;
            }
            let _ = server.child.wait();
            tries += 1;
            assert!(tries < 10, "dedensd binds a free port");
        }
    }

    /// The next event whose message is `message`, skipping others, those it logged before "serving" first; `None`
    /// once the server exited.
    ///
    /// # Panics
    ///
    /// When none comes within [`EVENT_TIMEOUT`].
    pub(crate) fn event(&mut self, message: &str) -> Option<Value> {
        self.next_event(message, false)
    }

    /// [`Server::event`], which keeps the events it skips for the next call when `keep` is set.
    fn next_event(&mut self, message: &str, keep: bool) -> Option<Value> {
        let is_wanted = |event: &Value| event["fields"]["message"] == message;
        while let Some(event) = self.early.pop_front() {
            if is_wanted(&event) {
                return Some(event);
            }
        }
        let deadline = Instant::now() + EVENT_TIMEOUT;
        loop {
            let received = self
                .events
                .recv_timeout(deadline.saturating_duration_since(Instant::now()));
            assert!(
                !matches!(received, Err(mpsc::RecvTimeoutError::Timeout)),
                "no {message:?} event within {EVENT_TIMEOUT:?}"
            );
            match received {
                Ok(event) if is_wanted(&event) => return Some(event),
                Ok(event) if keep => self.early.push_back(event),
                Ok(_) => {}
                Err(_) => return None,
            }
        }
    }

    /// Every line the server wrote to stderr so far, events or not.
    pub(crate) fn stderr(&self) -> Vec<String> {
        self.log
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }

    /// Its process ID.
    pub(crate) fn pid(&self) -> u32 {
        self.child.id()
    }

    /// Sends SIGHUP, asking for a reload (D55).
    #[cfg(unix)]
    pub(crate) fn hang_up(&self) {
        self.signal("HUP");
    }

    /// Sends the signal named `name`, `HUP` or `TERM`, with `kill`.
    #[cfg(unix)]
    pub(crate) fn signal(&self, name: &str) {
        let status = Command::new("kill")
            .arg(format!("-{name}"))
            .arg(self.child.id().to_string())
            .status()
            .expect("kill runs");
        assert!(status.success(), "kill -{name}");
    }

    /// How it exited, waiting at most [`EVENT_TIMEOUT`]; `None` while it still runs then.
    pub(crate) fn exited(&mut self) -> Option<ExitStatus> {
        let deadline = Instant::now() + EVENT_TIMEOUT;
        while Instant::now() < deadline {
            if let Some(status) = self.child.try_wait().expect("its status") {
                return Some(status);
            }
            thread::sleep(Duration::from_millis(20));
        }
        None
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
