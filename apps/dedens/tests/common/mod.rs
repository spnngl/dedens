//! A loopback DNS server for the command's tests: it answers over UDP and TCP, or TLS, or QUIC, with the captured responses of
//! `crates/dedens-proto/tests/testdata`, their ID and question set to the query's, and keeps every query it gets.

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, UdpSocket};
use std::path::PathBuf;
use std::sync::{Arc, Mutex, mpsc};
use std::thread;

use compio::BufResult;
use compio::io::AsyncWriteExt as _;
use compio::quic::ServerBuilder;
use compio::rustls::crypto::ring;
use compio::rustls::pki_types::PrivateKeyDer;
use compio::rustls::version::TLS13;
use compio::rustls::{
    DEFAULT_VERSIONS, ServerConfig, ServerConnection, StreamOwned, SupportedProtocolVersion,
};
use rcgen::{BasicConstraints, CertificateParams, CertifiedIssuer, IsCa, KeyPair};

/// The transport a query came over.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Transport {
    Udp,
    Tcp,
    Tls,
    Quic,
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
        Self::serve(names, false)
    }

    /// As [`Responder::start`], but every second UDP query gets no answer.
    pub(crate) fn flaky(names: &[&str]) -> Self {
        Self::serve(names, true)
    }

    fn serve(names: &[&str], flaky: bool) -> Self {
        let canned = canned(names);
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
pub(crate) const TLS_NAME: &str = "dns.example";

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

/// A server configuration for TLS versions `versions` and protocol `alpn`, with a certificate for [`TLS_NAME`] and
/// 127.0.0.1 signed by a certificate authority made for the test; and that authority's PEM file.
fn certified(
    versions: &[&'static SupportedProtocolVersion],
    alpn: &[u8],
) -> (ServerConfig, tempfile::NamedTempFile) {
    let mut params = CertificateParams::new(Vec::<String>::new()).expect("CA parameters");
    params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    let ca =
        CertifiedIssuer::self_signed(params, KeyPair::generate().expect("a key")).expect("a CA");
    let key = KeyPair::generate().expect("a key");
    let certificate = CertificateParams::new(vec![TLS_NAME.to_owned(), "127.0.0.1".to_owned()])
        .expect("server parameters")
        .signed_by(&key, &ca)
        .expect("a server certificate");
    let mut pem = tempfile::NamedTempFile::new().expect("a temporary file");
    pem.write_all(ca.pem().as_bytes()).expect("written");
    let mut config = ServerConfig::builder_with_provider(Arc::new(ring::default_provider()))
        .with_protocol_versions(versions)
        .expect("TLS versions")
        .with_no_client_auth()
        .with_single_cert(
            vec![certificate.der().clone()],
            PrivateKeyDer::Pkcs8(key.serialize_der().into()),
        )
        .expect("a server configuration");
    config.alpn_protocols = vec![alpn.to_vec()];
    (config, pem)
}

/// The captured responses named, `"a"` for `a.bin`.
fn canned(names: &[&str]) -> Arc<Vec<Canned>> {
    let dir =
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../crates/dedens-proto/tests/testdata");
    let canned = names.iter().map(|name| {
        let wire = std::fs::read(dir.join(format!("{name}.bin"))).expect("captured response");
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
