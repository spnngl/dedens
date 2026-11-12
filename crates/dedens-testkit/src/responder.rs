//! A loopback DNS server for the tests of `dedens` and `dedensd`: it answers over UDP and TCP, or TLS, QUIC, HTTP/3
//! or CoAP, with the captured responses of `testdata/proto` and `testdata/dnssec`, their ID and question set to the
//! query's, and keeps every query it gets.

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, UdpSocket};
use std::sync::{Arc, Mutex, PoisonError, mpsc};
use std::thread;
use std::time::Duration;

use compio::BufResult;
use compio::bytes::{Buf, Bytes};
use compio::io::AsyncWriteExt as _;
use compio::quic::{ServerBuilder, h3};
use compio::rustls::version::TLS13;
use compio::rustls::{
    DEFAULT_VERSIONS, ServerConfig, ServerConnection, StreamOwned, SupportedProtocolVersion,
};
use dedens_proto::{Message, Name, RecordType, Ttl};
use tempfile::NamedTempFile;

use crate::certificates;

/// The transport a query came over.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Transport {
    /// UDP.
    Udp,
    /// TCP.
    Tcp,
    /// TLS (RFC 7858).
    Tls,
    /// QUIC (RFC 9250).
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

/// A running server; its threads run until the test process exits.
pub struct Responder {
    /// Its address, the same port for UDP and TCP.
    pub addr: SocketAddr,
    upstream: Arc<Upstream>,
}

/// One captured response and the question it answers.
struct Canned {
    key: (String, [u8; 2]),
    truncated: bool,
    wire: Vec<u8>,
}

/// What a server answers, and how.
struct Upstream {
    canned: Vec<Canned>,
    /// The queries received, in order, with their transport.
    queries: Mutex<Vec<(Transport, Vec<u8>)>>,
    /// Whether every second query over UDP gets no answer.
    flaky: bool,
    /// How late each query past the first `undelayed` is answered.
    delay: Duration,
    undelayed: usize,
}

impl Upstream {
    fn new(canned: Vec<Canned>) -> Self {
        Self {
            canned,
            queries: Mutex::default(),
            flaky: false,
            delay: Duration::ZERO,
            undelayed: 0,
        }
    }

    /// Keeps `query`, come over `transport`, and gives its answer, if any.
    fn reply(&self, query: &[u8], transport: Transport) -> Option<Vec<u8>> {
        let mut queries = self.queries.lock().unwrap_or_else(PoisonError::into_inner);
        queries.push((transport, query.to_vec()));
        let count = queries.len();
        let udp = queries.iter().filter(|(t, _)| *t == Transport::Udp).count();
        drop(queries);
        if self.flaky && transport == Transport::Udp && udp.is_multiple_of(2) {
            return None;
        }
        if count > self.undelayed {
            thread::sleep(self.delay);
        }
        self.answer(query, transport)
    }

    /// The captured response to `query`, its ID and question bytes those of the query: the truncated one over UDP
    /// when there are two.
    fn answer(&self, query: &[u8], transport: Transport) -> Option<Vec<u8>> {
        let (key, end) = question(query)?;
        let mut matching = self.canned.iter().filter(|c| c.key == key);
        let first = matching.next()?;
        let chosen = match matching.next() {
            Some(second) if first.truncated != (transport == Transport::Udp) => second,
            _ => first,
        };
        let mut response = chosen.wire.clone();
        response[..2].copy_from_slice(&query[..2]);
        response.get_mut(12..end)?.copy_from_slice(&query[12..end]);
        Some(response)
    }
}

impl Responder {
    /// Serves the captured responses named, `"a"` for `a.bin`: a query whose name (in any case) and type are those
    /// of one gets it, the truncated one over UDP when there are two; any other query gets no answer.
    ///
    /// # Panics
    ///
    /// When a capture cannot be read or no port is free.
    #[must_use]
    pub fn start(names: &[&str]) -> Self {
        Self::serve(Upstream::new(canned_with(names, &[])))
    }

    /// As [`Responder::start`], with more responses, as their wire: a forged one answers a question instead of the
    /// capture of it, which is then not named.
    ///
    /// # Panics
    ///
    /// As [`Responder::start`].
    #[must_use]
    pub fn start_with(names: &[&str], wires: &[Vec<u8>]) -> Self {
        Self::serve(Upstream::new(canned_with(names, wires)))
    }

    /// As [`Responder::start`], but every second UDP query gets no answer.
    ///
    /// # Panics
    ///
    /// As [`Responder::start`].
    #[must_use]
    pub fn flaky(names: &[&str]) -> Self {
        Self::serve(Upstream {
            flaky: true,
            ..Upstream::new(canned_with(names, &[]))
        })
    }

    /// As [`Responder::start`], each query answered `delay` late. One thread answers UDP, in turn: of `n` UDP queries
    /// sent at once, the last is answered `n` × `delay` late.
    ///
    /// # Panics
    ///
    /// As [`Responder::start`].
    #[must_use]
    pub fn delayed(names: &[&str], delay: Duration) -> Self {
        Self::serve(Upstream {
            delay,
            ..Upstream::new(canned_with(names, &[]))
        })
    }

    /// Serves the capture named `name`, its answer records' TTL `ttl`, every query after the first `delay` late.
    ///
    /// # Panics
    ///
    /// As [`Responder::start`], or when `ttl` is no TTL.
    #[must_use]
    pub fn slow(name: &str, ttl: u32, delay: Duration) -> Self {
        let wire = read(name);
        let mut message = Message::decode(&wire)
            .expect("a captured response decodes")
            .message;
        let ttl = Ttl::new(ttl).expect("a TTL");
        for record in &mut message.answer {
            record.ttl = ttl;
        }
        let wire = message.to_vec().expect("it fits");
        Self::serve(Upstream {
            delay,
            undelayed: 1,
            ..Upstream::new(canned_with(&[], &[wire]))
        })
    }

    /// Answers over UDP and TCP on one port.
    fn serve(upstream: Upstream) -> Self {
        // The port UDP got may be taken over TCP by a test running beside this one: take another.
        let (udp, tcp) = loop {
            let udp = UdpSocket::bind("127.0.0.1:0").expect("a UDP port");
            if let Ok(tcp) = TcpListener::bind(udp.local_addr().expect("bound")) {
                break (udp, tcp);
            }
        };
        let responder = Self {
            addr: udp.local_addr().expect("bound"),
            upstream: Arc::new(upstream),
        };
        let upstream = Arc::clone(&responder.upstream);
        thread::spawn(move || {
            let mut buf = vec![0; 65535];
            while let Ok((len, from)) = udp.recv_from(&mut buf) {
                let query = &buf[..len];
                if !is_query(query) {
                    continue;
                }
                if let Some(response) = upstream.reply(query, Transport::Udp) {
                    let _ = udp.send_to(&response, from);
                }
            }
        });
        let upstream = Arc::clone(&responder.upstream);
        // A thread per connection: on Linux each `dedensd` thread opens its own, and one kept open must not hold up
        // the others.
        thread::spawn(move || {
            for stream in tcp.incoming().flatten() {
                let upstream = Arc::clone(&upstream);
                thread::spawn(move || serve_stream(stream, Transport::Tcp, &upstream));
            }
        });
        responder
    }

    /// The queries received so far, in order, with their transport.
    #[must_use]
    pub fn queries(&self) -> Vec<(Transport, Vec<u8>)> {
        self.upstream
            .queries
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }

    /// How many times `name`, in presentation format, was asked for `qtype`, over any transport.
    ///
    /// # Panics
    ///
    /// When `name` is no name.
    #[must_use]
    pub fn asked(&self, name: &str, qtype: RecordType) -> usize {
        let name: Name<'static> = name.parse().expect("a name");
        self.queries()
            .iter()
            .filter_map(|(_, query)| Message::decode(query).ok())
            .filter(|decoded| {
                decoded
                    .message
                    .questions
                    .first()
                    .is_some_and(|question| question.name == name && question.qtype == qtype)
            })
            .count()
    }

    /// `@` and the address, for the command line.
    #[must_use]
    pub fn at(&self) -> String {
        format!("@{}", self.addr)
    }

    /// As [`Responder::start`], over TLS only (RFC 7858), with a certificate signed by a certificate authority made
    /// for the test, whose PEM file comes with it.
    ///
    /// # Panics
    ///
    /// As [`Responder::start`].
    #[must_use]
    pub fn tls(names: &[&str]) -> (Self, NamedTempFile) {
        let (config, pem) = certified(DEFAULT_VERSIONS, b"dot");
        let config = Arc::new(config);
        let listener = TcpListener::bind("127.0.0.1:0").expect("a TCP port");
        let responder = Self {
            addr: listener.local_addr().expect("bound"),
            upstream: Arc::new(Upstream::new(canned_with(names, &[]))),
        };
        let upstream = Arc::clone(&responder.upstream);
        thread::spawn(move || {
            for stream in listener.incoming().flatten() {
                let upstream = Arc::clone(&upstream);
                let connection = ServerConnection::new(Arc::clone(&config)).expect("a TLS session");
                thread::spawn(move || {
                    let tls = StreamOwned::new(connection, stream);
                    serve_stream(tls, Transport::Tls, &upstream);
                });
            }
        });
        (responder, pem)
    }

    /// As [`Responder::tls`], over QUIC only (RFC 9250): each query on its stream, answered on it.
    ///
    /// # Panics
    ///
    /// As [`Responder::start`].
    #[must_use]
    pub fn quic(names: &[&str]) -> (Self, NamedTempFile) {
        let (config, pem) = certified(&[&TLS13], b"doq");
        let upstream = Arc::new(Upstream::new(canned_with(names, &[])));
        let serving = Arc::clone(&upstream);
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
                    let upstream = Arc::clone(&serving);
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
                            if let Some(response) = upstream.reply(query, Transport::Quic) {
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
        (Self { addr, upstream }, pem)
    }

    /// As [`Responder::start`], over HTTP/3 only (RFC 8484 over RFC 9114), on any path: each query on its request
    /// stream, answered on it.
    ///
    /// # Panics
    ///
    /// As [`Responder::start`].
    #[must_use]
    pub fn https(names: &[&str]) -> (Self, NamedTempFile) {
        Self::h3(names, None)
    }

    /// As [`Responder::https`], and an Oblivious `DoH` target with `key` (RFC 9230 §8) and its own proxy: its
    /// configurations at the well-known path, oblivious messages opened wherever they come.
    ///
    /// # Panics
    ///
    /// As [`Responder::start`].
    #[cfg(feature = "odoh")]
    #[must_use]
    pub fn oblivious(names: &[&str], key: dedens_odoh::TargetKey) -> (Self, NamedTempFile) {
        Self::h3(names, Some(Arc::new(key)))
    }

    fn h3(names: &[&str], key: Option<Arc<Key>>) -> (Self, NamedTempFile) {
        let (config, pem) = certified(&[&TLS13], b"h3");
        let upstream = Arc::new(Upstream::new(canned_with(names, &[])));
        let serving = Arc::clone(&upstream);
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
                    let (upstream, key) = (Arc::clone(&serving), key.clone());
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
                            let (upstream, key) = (Arc::clone(&upstream), key.clone());
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
                                        oblivious_answer(key, &request, &body, &upstream);
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
                                let Some(wire) = upstream.reply(&query, transport) else {
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
        (Self { addr, upstream }, pem)
    }

    /// As [`Responder::start`], over CoAP only (RFC 9953), at `path`: the answers of the library's own server side
    /// ([`dedens_net::coap::dns`]), the same `dedensd` serves with, `/.well-known/core` too (D95). Any other path
    /// gets 4.04.
    ///
    /// # Panics
    ///
    /// As [`Responder::start`].
    #[cfg(feature = "doc")]
    #[must_use]
    pub fn coap(names: &[&str], path: &str) -> Self {
        use dedens_net::coap::Message;
        use dedens_net::coap::dns::{Query, discovery, error, path_segments, query, response};

        let path = path_segments(path);
        let socket = UdpSocket::bind("127.0.0.1:0").expect("a UDP port");
        let responder = Self {
            addr: socket.local_addr().expect("bound"),
            upstream: Arc::new(Upstream::new(canned_with(names, &[]))),
        };
        let upstream = Arc::clone(&responder.upstream);
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
                    Ok(Query::Dns(dns)) => match upstream.reply(dns, Transport::Coap) {
                        Some(wire) => response(&request, 1, wire)
                            .unwrap_or_else(|code| error(&request, 1, code)),
                        None => continue,
                    },
                };
                socket
                    .send_to(&reply.to_vec().expect("it writes"), from)
                    .expect("sent");
            }
        });
        responder
    }
}

/// Answers each query of a connection over `transport`, TCP or TLS.
fn serve_stream(mut stream: impl Read + Write, transport: Transport, upstream: &Upstream) {
    let mut len = [0; 2];
    while stream.read_exact(&mut len).is_ok() {
        let mut query = vec![0; usize::from(u16::from_be_bytes(len))];
        if stream.read_exact(&mut query).is_err() {
            return;
        }
        if let Some(response) = upstream.reply(&query, transport) {
            let len = u16::try_from(response.len()).expect("a response under 64 KiB");
            let _ = stream.write_all(&[&len.to_be_bytes()[..], &response].concat());
            let _ = stream.flush();
        }
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
    upstream: &Upstream,
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
                    match upstream.reply(&query, Transport::Oblivious) {
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

/// A server configuration for TLS versions `versions` and protocol `alpn`, with a certificate for
/// [`certificates::NAME`] and 127.0.0.1 signed by a certificate authority made for the test; and that authority's PEM
/// file.
fn certified(
    versions: &[&'static SupportedProtocolVersion],
    alpn: &[u8],
) -> (ServerConfig, NamedTempFile) {
    let certificates = certificates::certificates();
    let mut pem = NamedTempFile::new().expect("a temporary file");
    pem.write_all(certificates.ca_pem.as_bytes())
        .expect("written");
    (certificates.config(versions, alpn), pem)
}

/// The captured response named `name`, `"a"` for `a.bin`, from the captures of the protocol or of DNSSEC (no name
/// is in both).
fn read(name: &str) -> Vec<u8> {
    let file = format!("{name}.bin");
    let mut found = ["proto", "dnssec"]
        .map(|dir| crate::path(dir).join(&file))
        .into_iter()
        .filter(|path| path.exists());
    let path = found.next().expect("a captured response");
    assert_eq!(found.next(), None, "{name}: a capture of both");
    std::fs::read(path).expect("captured response")
}

/// The captured responses named, and the responses in `wires`.
fn canned_with(names: &[&str], wires: &[Vec<u8>]) -> Vec<Canned> {
    names
        .iter()
        .map(|name| read(name))
        .chain(wires.iter().cloned())
        .map(|wire| {
            let (key, _) = question(&wire).expect("a question");
            Canned {
                key,
                truncated: wire[2] & 0x02 != 0,
                wire,
            }
        })
        .collect()
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
    // QTYPE and QCLASS (RFC 1035 §4.1.2): a question cut short of its class is none.
    let [high, low, _, _] = *wire.get(at..at + 4)? else {
        return None;
    };
    Some(((name, [high, low]), at + 4))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_question_cut_short_of_its_class_is_none() {
        let wire = read("a");
        let (_, end) = question(&wire).expect("a question");
        assert!(question(&wire[..end]).is_some());
        assert_eq!(question(&wire[..end - 1]), None);
        // A server thread answering it would have panicked on the copy of the question.
        let upstream = Upstream::new(canned_with(&["a"], &[]));
        assert_eq!(upstream.answer(&wire[..end - 2], Transport::Udp), None);
    }

    #[test]
    fn flaky_drops_every_second_udp_query_whatever_comes_over_tcp() {
        let upstream = Upstream {
            flaky: true,
            ..Upstream::new(canned_with(&["a"], &[]))
        };
        let query = read("a");
        assert!(upstream.reply(&query, Transport::Udp).is_some());
        assert!(upstream.reply(&query, Transport::Tcp).is_some());
        assert!(upstream.reply(&query, Transport::Udp).is_none());
        assert!(upstream.reply(&query, Transport::Udp).is_some());
    }
}
