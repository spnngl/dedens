//! A loopback DNS server for the command's tests: it answers over UDP and TCP, or TLS, QUIC or HTTP/3, with the captured responses of
//! `crates/dedens-proto/tests/testdata`, their ID and question set to the query's, and keeps every query it gets.

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, UdpSocket};
use std::path::PathBuf;
use std::sync::{Arc, Mutex, mpsc};
use std::thread;

use compio::BufResult;
use compio::bytes::{Buf, Bytes};
use compio::io::AsyncWriteExt as _;
use compio::quic::{ServerBuilder, h3};
use compio::rustls::version::TLS13;
use compio::rustls::{
    DEFAULT_VERSIONS, ServerConfig, ServerConnection, StreamOwned, SupportedProtocolVersion,
};

#[path = "../../../../crates/dedens-net/tests/common/certificates.rs"]
#[allow(
    dead_code,
    reason = "shared with the tests of dedens-net, which use all of it"
)]
mod certificates;

/// The transport a query came over.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Transport {
    Udp,
    Tcp,
    Tls,
    Quic,
    /// HTTP/3, a GET.
    HttpsGet,
    /// HTTP/3, a POST.
    HttpsPost,
    /// HTTP/3, a POST of an Oblivious `DoH` message, opened: the query it held.
    #[cfg(feature = "odoh")]
    Oblivious,
    /// CoAP, a FETCH (RFC 9953).
    #[cfg(feature = "doc")]
    Coap,
}

/// The queries received, in order, with their transport.
type Log = Arc<Mutex<Vec<(Transport, Vec<u8>)>>>;

/// A running server; its threads live as long as the test.
pub(crate) struct Responder {
    /// Its address, the same port for UDP and TCP.
    pub(crate) addr: SocketAddr,
    queries: Log,
}

/// One captured response and the question it answers.
struct Canned {
    key: (String, [u8; 2]),
    truncated: bool,
    wire: Vec<u8>,
}

impl Responder {
    /// Serves the captured responses named, `"a"` for `a.bin`: a query whose name (in any case) and type are
    /// those of one gets it, the truncated one over UDP when there are two; any other query gets no answer.
    pub(crate) fn start(names: &[&str]) -> Self {
        Self::serve(names, &[], false)
    }

    /// As [`Responder::start`], with more responses, as their wire: a forged one answers a question instead of
    /// the capture of it, which is then not named.
    pub(crate) fn start_with(names: &[&str], wires: &[Vec<u8>]) -> Self {
        Self::serve(names, wires, false)
    }

    /// As [`Responder::start`], but every second UDP query gets no answer.
    pub(crate) fn flaky(names: &[&str]) -> Self {
        Self::serve(names, &[], true)
    }

    fn serve(names: &[&str], wires: &[Vec<u8>], flaky: bool) -> Self {
        let canned = canned_with(names, wires);
        let (udp, tcp) = loop {
            let udp = UdpSocket::bind("127.0.0.1:0").expect("a UDP port");
            if let Ok(tcp) = TcpListener::bind(udp.local_addr().expect("bound")) {
                break (udp, tcp);
            }
        };
        let responder = Self {
            addr: udp.local_addr().expect("bound"),
            queries: Arc::default(),
        };
        let (queries, answers) = (Arc::clone(&responder.queries), Arc::clone(&canned));
        thread::spawn(move || {
            let mut buf = vec![0; 65535];
            while let Ok((len, from)) = udp.recv_from(&mut buf) {
                let query = buf[..len].to_vec();
                if !is_query(&query) {
                    continue;
                }
                let mut log = queries.lock().expect("unpoisoned");
                log.push((Transport::Udp, query.clone()));
                let dropped = flaky && log.len() % 2 == 0;
                drop(log);
                if !dropped && let Some(response) = answer(&answers, &query, Transport::Udp) {
                    udp.send_to(&response, from).expect("sent");
                }
            }
        });
        let queries = Arc::clone(&responder.queries);
        thread::spawn(move || {
            for stream in tcp.incoming().flatten() {
                let (queries, canned) = (Arc::clone(&queries), Arc::clone(&canned));
                thread::spawn(move || serve_stream(stream, Transport::Tcp, &queries, &canned));
            }
        });
        responder
    }

    /// The queries received so far, in order.
    pub(crate) fn queries(&self) -> Vec<(Transport, Vec<u8>)> {
        self.queries.lock().expect("unpoisoned").clone()
    }

    /// `@` and the address, for the command line.
    pub(crate) fn at(&self) -> String {
        format!("@{}", self.addr)
    }
}

/// Answers each query of a connection over `transport`, TCP or TLS.
fn serve_stream(
    mut stream: impl Read + Write,
    transport: Transport,
    queries: &Mutex<Vec<(Transport, Vec<u8>)>>,
    canned: &[Canned],
) {
    let mut len = [0; 2];
    while stream.read_exact(&mut len).is_ok() {
        let mut query = vec![0; usize::from(u16::from_be_bytes(len))];
        if stream.read_exact(&mut query).is_err() {
            return;
        }
        queries
            .lock()
            .expect("unpoisoned")
            .push((transport, query.clone()));
        if let Some(response) = answer(canned, &query, transport) {
            let len = u16::try_from(response.len()).expect("a response under 64 KiB");
            let _ = stream.write_all(&[&len.to_be_bytes()[..], &response].concat());
            let _ = stream.flush();
        }
    }
}

/// The name the certificate of [`Responder::tls`] holds, with 127.0.0.1.
pub(crate) use certificates::NAME as TLS_NAME;

impl Responder {
    /// As [`Responder::start`], over TLS only (RFC 7858), with a certificate signed by a certificate authority
    /// made for the test, whose PEM file comes with it.
    pub(crate) fn tls(names: &[&str]) -> (Self, tempfile::NamedTempFile) {
        let (config, pem) = certified(DEFAULT_VERSIONS, b"dot");
        let config = Arc::new(config);
        let listener = TcpListener::bind("127.0.0.1:0").expect("a TCP port");
        let responder = Self {
            addr: listener.local_addr().expect("bound"),
            queries: Arc::default(),
        };
        let (queries, canned) = (Arc::clone(&responder.queries), canned(names));
        thread::spawn(move || {
            for stream in listener.incoming().flatten() {
                let (queries, canned) = (Arc::clone(&queries), Arc::clone(&canned));
                let connection = ServerConnection::new(Arc::clone(&config)).expect("a TLS session");
                thread::spawn(move || {
                    let tls = StreamOwned::new(connection, stream);
                    serve_stream(tls, Transport::Tls, &queries, &canned);
                });
            }
        });
        (responder, pem)
    }

    /// As [`Responder::tls`], over QUIC only (RFC 9250): each query on its stream, answered on it.
    pub(crate) fn quic(names: &[&str]) -> (Self, tempfile::NamedTempFile) {
        let (config, pem) = certified(&[&TLS13], b"doq");
        let (queries, canned): (Log, _) = (Arc::default(), canned(names));
        let log = Arc::clone(&queries);
        let (bound, addr) = mpsc::channel();
        thread::spawn(move || {
            let runtime = compio::runtime::Runtime::new().expect("a runtime");
            runtime.block_on(async move {
                let endpoint = ServerBuilder::new_with_rustls_server_config(config)
                    .bind("127.0.0.1:0")
                    .await
                    .expect("a QUIC endpoint");
                bound
                    .send(endpoint.local_addr().expect("bound"))
                    .expect("the test waits");
                while let Some(incoming) = endpoint.wait_incoming().await {
                    let (log, canned) = (Arc::clone(&log), Arc::clone(&canned));
                    compio::runtime::spawn(async move {
                        // A client that refuses the certificate ends here.
                        let Ok(connecting) = incoming.accept() else {
                            return;
                        };
                        let Ok(connection) = connecting.await else {
                            return;
                        };
                        while let Ok((mut send, mut recv)) = connection.accept_bi().await {
                            let BufResult(read, bytes) = recv.read_to_end(Vec::new()).await;
                            let (Ok(_), Some(query)) = (read, bytes.get(2..)) else {
                                return;
                            };
                            log.lock()
                                .expect("unpoisoned")
                                .push((Transport::Quic, query.to_vec()));
                            if let Some(response) = answer(&canned, query, Transport::Quic) {
                                let len =
                                    u16::try_from(response.len()).expect("a response under 64 KiB");
                                let _ = send
                                    .write_all([&len.to_be_bytes()[..], &response].concat())
                                    .await;
                                let _ = send.finish();
                            }
                        }
                    })
                    .detach();
                }
            });
        });
        let addr = addr.recv().expect("the server's address");
        (Self { addr, queries }, pem)
    }
}

impl Responder {
    /// As [`Responder::start`], over HTTP/3 only (RFC 8484 over RFC 9114), on any path: each query on its request
    /// stream, answered on it.
    pub(crate) fn https(names: &[&str]) -> (Self, tempfile::NamedTempFile) {
        Self::h3(names, None)
    }

    /// As [`Responder::https`], and an Oblivious `DoH` target with `key` (RFC 9230 §8) and its own proxy: its
    /// configurations at the well-known path, oblivious messages opened wherever they come.
    #[cfg(feature = "odoh")]
    #[allow(dead_code, reason = "only the tests of Oblivious `DoH` use it")]
    pub(crate) fn oblivious(
        names: &[&str],
        key: dedens_odoh::TargetKey,
    ) -> (Self, tempfile::NamedTempFile) {
        Self::h3(names, Some(Arc::new(key)))
    }

    fn h3(names: &[&str], key: Option<Arc<Key>>) -> (Self, tempfile::NamedTempFile) {
        let (config, pem) = certified(&[&TLS13], b"h3");
        let (queries, canned): (Log, _) = (Arc::default(), canned(names));
        let log = Arc::clone(&queries);
        let (bound, addr) = mpsc::channel();
        thread::spawn(move || {
            let runtime = compio::runtime::Runtime::new().expect("a runtime");
            runtime.block_on(async move {
                let endpoint = ServerBuilder::new_with_rustls_server_config(config)
                    .bind("127.0.0.1:0")
                    .await
                    .expect("a QUIC endpoint");
                bound
                    .send(endpoint.local_addr().expect("bound"))
                    .expect("the test waits");
                while let Some(incoming) = endpoint.wait_incoming().await {
                    let (log, canned, key) = (Arc::clone(&log), Arc::clone(&canned), key.clone());
                    compio::runtime::spawn(async move {
                        let Ok(connecting) = incoming.accept() else {
                            return;
                        };
                        let Ok(connection) = connecting.await else {
                            return;
                        };
                        let Ok(mut server) =
                            h3::server::builder().build::<_, Bytes>(connection).await
                        else {
                            return;
                        };
                        while let Ok(Some(resolver)) = server.accept().await {
                            let (log, canned, key) =
                                (Arc::clone(&log), Arc::clone(&canned), key.clone());
                            compio::runtime::spawn(async move {
                                let Ok((request, mut stream)) = resolver.resolve_request().await
                                else {
                                    return;
                                };
                                let mut body = Vec::new();
                                while let Ok(Some(mut chunk)) = stream.recv_data().await {
                                    body.extend_from_slice(&chunk.copy_to_bytes(chunk.remaining()));
                                }
                                #[cfg(feature = "odoh")]
                                if let Some(key) = &key {
                                    let (head, body) =
                                        oblivious_answer(key, &request, &body, &log, &canned);
                                    let _ = stream
                                        .send_response(http::Response::from_parts(head, ()))
                                        .await;
                                    let _ = stream.send_data(Bytes::from(body)).await;
                                    let _ = stream.finish().await;
                                    return;
                                }
                                #[cfg(not(feature = "odoh"))]
                                let _ = &key;
                                let Ok(query) = dedens_net::doh::server_request(&request, &body)
                                else {
                                    return;
                                };
                                let transport = match *request.method() {
                                    http::Method::POST => Transport::HttpsPost,
                                    _ => Transport::HttpsGet,
                                };
                                log.lock()
                                    .expect("unpoisoned")
                                    .push((transport, query.clone()));
                                let Some(wire) = answer(&canned, &query, Transport::Quic) else {
                                    return;
                                };
                                let Ok(response) =
                                    dedens_net::doh::server_response(wire, request.method())
                                else {
                                    return;
                                };
                                let (head, body) = response.into_parts();
                                let _ = stream
                                    .send_response(http::Response::from_parts(head, ()))
                                    .await;
                                let _ = stream.send_data(Bytes::from(body)).await;
                                let _ = stream.finish().await;
                            })
                            .detach();
                        }
                    })
                    .detach();
                }
            });
        });
        let addr = addr.recv().expect("the server's address");
        (Self { addr, queries }, pem)
    }
}

#[cfg(feature = "doc")]
impl Responder {
    /// As [`Responder::start`], over CoAP only (RFC 9953), at `path`: the answers of the library's own server side
    /// ([`dedens_net::coap::dns`]), the same `dedensd` serves with, `/.well-known/core` too (D95). Any other path gets 4.04.
    pub(crate) fn coap(names: &[&str], path: &str) -> Self {
        use dedens_net::coap::Message;
        use dedens_net::coap::dns::{Query, discovery, error, path_segments, query, response};

        let (canned, path) = (canned(names), path_segments(path));
        let socket = UdpSocket::bind("127.0.0.1:0").expect("a UDP port");
        let responder = Self {
            addr: socket.local_addr().expect("bound"),
            queries: Arc::default(),
        };
        let queries = Arc::clone(&responder.queries);
        thread::spawn(move || {
            let mut buf = vec![0; 65535];
            while let Ok((len, from)) = socket.recv_from(&mut buf) {
                let Ok(request) = Message::parse(&buf[..len]) else {
                    continue;
                };
                if let Some(reply) = discovery(&request, 1, &path) {
                    socket
                        .send_to(&reply.to_vec().expect("it writes"), from)
                        .expect("sent");
                    continue;
                }
                let reply = match query(&request, &path) {
                    Err(code) => error(&request, 1, code),
                    // Nothing is kept here for the blocks past the first.
                    Ok(Query::Block(_)) => error(&request, 1, dedens_net::coap::Code::BAD_REQUEST),
                    Ok(Query::Dns(dns)) => {
                        queries
                            .lock()
                            .expect("unpoisoned")
                            .push((Transport::Coap, dns.to_vec()));
                        match answer(&canned, dns, Transport::Tcp) {
                            Some(wire) => response(&request, 1, wire)
                                .unwrap_or_else(|code| error(&request, 1, code)),
                            None => continue,
                        }
                    }
                };
                socket
                    .send_to(&reply.to_vec().expect("it writes"), from)
                    .expect("sent");
            }
        });
        responder
    }
}

/// The key of a target: nothing without the `odoh` feature.
#[cfg(feature = "odoh")]
type Key = dedens_odoh::TargetKey;
#[cfg(not(feature = "odoh"))]
type Key = std::convert::Infallible;

/// The response of a target with `key` to `request`: the configurations, the answer to a query opened, or a status.
#[cfg(feature = "odoh")]
fn oblivious_answer(
    key: &Key,
    request: &http::Request<()>,
    body: &[u8],
    log: &Mutex<Vec<(Transport, Vec<u8>)>>,
    canned: &[Canned],
) -> (http::response::Parts, Vec<u8>) {
    use dedens_net::odoh::{self, Entropy, Kind};
    use dedens_odoh::{Configs, Message};
    let status = |status| {
        http::Response::builder()
            .status(status)
            .body(Vec::new())
            .expect("a response")
    };
    let (kind, query) = odoh::classify(request, body, dedens_net::doh::DEFAULT_PATH);
    let response = match (kind, query) {
        (_, Err(code)) => status(code),
        (Kind::Configs, Ok(_)) => {
            let configs = Configs::new(vec![key.config().clone()])
                .encode()
                .expect("configurations encode");
            odoh::configs_response(configs, 3600)
        }
        (Kind::Oblivious, Ok(message)) => {
            let opened = Message::parse(&message)
                .ok()
                .map(|message| dedens_odoh::decrypt_query(key, &message));
            match opened {
                Some(Err(dedens_odoh::ExchangeError::UnknownKey)) => {
                    status(http::StatusCode::UNAUTHORIZED)
                }
                None | Some(Err(_)) => status(http::StatusCode::BAD_REQUEST),
                Some(Ok((plaintext, context))) => {
                    let query = plaintext.into_dns_message();
                    log.lock()
                        .expect("unpoisoned")
                        .push((Transport::Oblivious, query.clone()));
                    match answer(canned, &query, Transport::Quic) {
                        None => status(http::StatusCode::SERVICE_UNAVAILABLE),
                        Some(wire) => {
                            let mut entropy = Entropy::new().expect("randomness");
                            let padding = dedens_odoh::response_padding(wire.len());
                            let sealed = dedens_odoh::encrypt_response(
                                context,
                                &wire,
                                padding,
                                &mut entropy,
                            )
                            .expect("a response");
                            odoh::target_response(&sealed)
                        }
                    }
                }
            }
        }
        (Kind::Dns, Ok(_)) => status(http::StatusCode::UNSUPPORTED_MEDIA_TYPE),
    };
    response.into_parts()
}

/// A server configuration for TLS versions `versions` and protocol `alpn`, with a certificate for [`TLS_NAME`] and
/// 127.0.0.1 signed by a certificate authority made for the test; and that authority's PEM file.
fn certified(
    versions: &[&'static SupportedProtocolVersion],
    alpn: &[u8],
) -> (ServerConfig, tempfile::NamedTempFile) {
    let certificates = certificates::certificates();
    let mut pem = tempfile::NamedTempFile::new().expect("a temporary file");
    pem.write_all(certificates.ca_pem.as_bytes())
        .expect("written");
    (certificates.config(versions, alpn), pem)
}

/// The captured responses named, `"a"` for `a.bin`, from the captures of the protocol or of DNSSEC (no name is in
/// both).
fn canned(names: &[&str]) -> Arc<Vec<Canned>> {
    canned_with(names, &[])
}

/// As [`canned`], and the responses in `wires`.
fn canned_with(names: &[&str], wires: &[Vec<u8>]) -> Arc<Vec<Canned>> {
    let crates = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../crates");
    let dirs =
        ["dedens-proto", "dedens-dnssec"].map(|krate| crates.join(krate).join("tests/testdata"));
    let canned = names.iter().map(|name| {
        let file = format!("{name}.bin");
        let dir = dirs
            .iter()
            .find(|dir| dir.join(&file).exists())
            .expect("a captured response");
        std::fs::read(dir.join(file)).expect("captured response")
    });
    let canned = canned.chain(wires.iter().cloned()).map(|wire| {
        let (key, _) = question(&wire).expect("a question");
        Canned {
            key,
            truncated: wire[2] & 0x02 != 0,
            wire,
        }
    });
    Arc::new(canned.collect())
}

/// The captured response to `query`, its ID and question bytes those of the query.
fn answer(canned: &[Canned], query: &[u8], transport: Transport) -> Option<Vec<u8>> {
    let (key, end) = question(query)?;
    let mut matching = canned.iter().filter(|c| c.key == key);
    let first = matching.next()?;
    let chosen = match matching.next() {
        Some(second) if first.truncated != (transport == Transport::Udp) => second,
        _ => first,
    };
    let mut response = chosen.wire.clone();
    response[..2].copy_from_slice(&query[..2]);
    response[12..end].copy_from_slice(&query[12..end]);
    Some(response)
}

/// Whether a datagram is a query: a header (RFC 1035 §4.1.1) of a message that is no response, with one question and
/// no answer or authority record. A UDP port is reused as soon as it closes, so what a server gets may be meant for
/// the socket before it: the packets a QUIC server keeps sending to the port of a client that has exited.
fn is_query(wire: &[u8]) -> bool {
    matches!(wire, [_, _, flags, _, 0, 1, 0, 0, 0, 0, _, _, ..] if flags & 0x80 == 0)
}

/// The question of a message, its name lowercased and its type, and where it ends; the name is not compressed.
fn question(wire: &[u8]) -> Option<((String, [u8; 2]), usize)> {
    let mut at = 12;
    let mut name = String::new();
    loop {
        let len = usize::from(*wire.get(at)?);
        at += 1;
        if len == 0 {
            break;
        }
        let label = wire.get(at..at + len)?;
        name.push_str(&String::from_utf8_lossy(label).to_ascii_lowercase());
        name.push('.');
        at += len;
    }
    let qtype = wire.get(at..at + 2)?.try_into().ok()?;
    Some(((name, qtype), at + 4))
}
