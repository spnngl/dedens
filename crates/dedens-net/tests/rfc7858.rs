//! DNS over TLS (RFC 7858), the strict privacy profile (RFC 8310 §6.6) and padding (RFC 8467 §4.1), against a
//! loopback TLS server with certificates made for the test.

mod common;

use std::cell::{Cell, RefCell};
use std::net::SocketAddr;
use std::rc::Rc;
use std::sync::Arc;
use std::time::{Duration, Instant};

use common::certificates::{Certificates, NAME, certificates, named};
use common::loopback::{answer, listen};
use common::{query, sent, start, t0};
use compio::BufResult;
use compio::io::{AsyncReadExt, AsyncWrite, AsyncWriteExt};
use compio::rustls::DEFAULT_VERSIONS;
use compio::rustls::pki_types::ServerName;
use compio::tls::TlsAcceptor;
use dedens_net::client::{Client, ClientError, Server};
use dedens_net::exchange::{Options, Response, Transport};
use dedens_net::tcp::{Link, TcpError, TcpPool, frame};
use dedens_net::tls::{self, Presented, Trust};
use dedens_proto::Message;
use dedens_proto::edns::EdnsOption;

/// What the server saw.
#[derive(Default)]
struct Seen {
    connections: Cell<u32>,
    queries: RefCell<Vec<Vec<u8>>>,
}

/// A TLS server on the loopback address: on each connection, reads `batch` queries, then answers them in reverse
/// order, and again.
async fn tls_server(certificates: &Certificates, batch: usize) -> (SocketAddr, Rc<Seen>) {
    let acceptor = TlsAcceptor::from(Arc::new(certificates.config(DEFAULT_VERSIONS, b"dot")));
    serve(acceptor, batch).await
}

/// [`tls_server`] with `acceptor`.
async fn serve(acceptor: TlsAcceptor, batch: usize) -> (SocketAddr, Rc<Seen>) {
    let (listener, addr) = listen().await;
    let seen = Rc::new(Seen::default());
    let log = Rc::clone(&seen);
    compio::runtime::spawn(async move {
        loop {
            let (stream, _) = listener.accept().await.expect("a connection");
            log.connections.set(log.connections.get() + 1);
            let (acceptor, log) = (acceptor.clone(), Rc::clone(&log));
            compio::runtime::spawn(async move {
                // A client that refuses the certificate ends here.
                let Ok(mut tls) = acceptor.accept(stream).await else {
                    return;
                };
                loop {
                    let mut queries = Vec::new();
                    for _ in 0..batch {
                        let Ok(len) = tls.read_u16().await else {
                            return;
                        };
                        let BufResult(read, query) =
                            tls.read_exact(Vec::with_capacity(len.into())).await;
                        if read.is_err() {
                            return;
                        }
                        log.queries.borrow_mut().push(query.clone());
                        queries.push(query);
                    }
                    let bytes: Vec<u8> = queries
                        .iter()
                        .rev()
                        .flat_map(|query| frame(&answer(query, Vec::new())).expect("framed"))
                        .collect();
                    let BufResult(written, _) = tls.write_all(bytes).await;
                    written.expect("the client reads");
                    tls.flush().await.expect("a flush");
                }
            })
            .detach();
        }
    })
    .detach();
    (addr, seen)
}

fn tls() -> Options {
    let mut options = Options::default();
    options.transport = Transport::Tls;
    options
}

async fn ask(client: &Client, server: Server) -> Result<Response, ClientError> {
    client.exchange(query(), server, &tls()).await
}

/// RFC 7858 §3.3, RFC 8310 §8.1: the query goes over TLS to a server whose certificate holds the name given.
#[compio::test]
async fn s3_3_a_query_goes_over_tls_to_the_name_given() {
    let certificates = certificates();
    let (addr, seen) = tls_server(&certificates, 1).await;
    let client = Client::new().trusting(Trust::Roots(vec![certificates.ca]));
    let response = ask(&client, named(addr, NAME)).await.expect("a response");
    assert_eq!(response.transport, Transport::Tls);
    let answered = Message::decode(&response.wire).expect("a response").message;
    assert_eq!(answered.questions, query().questions);
    let queries = seen.queries.borrow();
    let [sent] = queries.as_slice() else {
        panic!("one query, not {}", queries.len());
    };
    // RFC 7873 §5.1: the query carries a client cookie, as over TCP.
    let options = Message::decode(sent)
        .expect("a query")
        .message
        .edns
        .expect("EDNS")
        .options;
    assert!(
        options
            .iter()
            .any(|option| matches!(option, EdnsOption::Cookie(_))),
        "{options:?}"
    );
}

/// RFC 8310 §8.1: a server known by its address only is verified by it.
#[compio::test]
async fn a_server_known_by_its_address_is_verified_by_it() {
    let certificates = certificates();
    let (addr, _) = tls_server(&certificates, 1).await;
    let client = Client::new().trusting(Trust::Roots(vec![certificates.ca]));
    ask(&client, Server::from(addr)).await.expect("a response");
}

/// RFC 8310 §6.6: in the strict profile, a server whose certificate does not hold the name is not queried.
#[compio::test]
async fn a_certificate_for_another_name_is_refused() {
    let certificates = certificates();
    let (addr, seen) = tls_server(&certificates, 1).await;
    let client = Client::new().trusting(Trust::Roots(vec![certificates.ca]));
    let error = ask(&client, named(addr, "other.example")).await;
    assert!(
        matches!(error, Err(ClientError::Tcp(TcpError::Handshake(_)))),
        "{error:?}"
    );
    assert_eq!(seen.queries.borrow().len(), 0);
}

/// RFC 8310 §6.6: a certificate no trusted authority signed is refused.
#[compio::test]
async fn a_certificate_of_an_unknown_authority_is_refused() {
    let (addr, seen) = tls_server(&certificates(), 1).await;
    let client = Client::new().trusting(Trust::Roots(vec![certificates().ca]));
    let error = ask(&client, named(addr, NAME)).await;
    assert!(
        matches!(error, Err(ClientError::Tcp(TcpError::Handshake(_)))),
        "{error:?}"
    );
    assert_eq!(seen.queries.borrow().len(), 0);
}

/// RFC 8310 §5: the opportunistic profile, for tests, takes any certificate.
#[compio::test]
async fn anyone_takes_any_certificate() {
    let (addr, _) = tls_server(&certificates(), 1).await;
    let client = Client::new().trusting(Trust::Anyone);
    ask(&client, named(addr, "other.example"))
        .await
        .expect("a response");
}

/// RFC 7858 §3.3: queries share one connection, and their responses come in any order.
#[compio::test]
async fn s3_3_queries_share_one_connection_answered_in_any_order() {
    let certificates = certificates();
    let (addr, seen) = tls_server(&certificates, 2).await;
    let client = Client::new().trusting(Trust::Roots(vec![certificates.ca]));
    let (first, second) = futures_util::future::join(
        ask(&client, named(addr, NAME)),
        ask(&client, named(addr, NAME)),
    )
    .await;
    first.expect("a response");
    second.expect("a response");
    assert_eq!(seen.connections.get(), 1);
}

/// RFC 8467 §4.1: a query over TLS is padded to a multiple of 128 bytes; RFC 7858 §3.4 with RFC 7828: it carries an
/// empty edns-tcp-keepalive.
#[test]
fn s3_4_a_query_over_tls_is_padded_and_asks_how_long_to_stay() {
    let exchange = start(&query(), tls(), t0());
    assert_eq!(exchange.wire().len() % 128, 0);
    let options = sent(&exchange).edns.expect("EDNS").options;
    assert!(
        matches!(
            options.as_slice(),
            // The fewest bytes reaching a multiple of 128.
            [EdnsOption::Keepalive(None), EdnsOption::Padding(0..128)]
        ),
        "{options:?}"
    );
}

/// RFC 7830: padding the caller put in is replaced; over UDP and TCP it stays.
#[test]
fn padding_of_the_caller_is_replaced_over_tls_only() {
    let mut padded = query();
    padded.edns.as_mut().expect("EDNS").options = vec![EdnsOption::Padding(3)];
    let mut tcp = Options::default();
    tcp.transport = Transport::Tcp;
    let over_tcp = sent(&start(&padded, tcp, t0())).edns.expect("EDNS").options;
    assert_eq!(
        over_tcp,
        vec![EdnsOption::Padding(3), EdnsOption::Keepalive(None)]
    );
    let over_tls = start(&padded, tls(), t0());
    assert_eq!(over_tls.wire().len() % 128, 0);
    let options = sent(&over_tls).edns.expect("EDNS").options;
    assert!(
        matches!(
            options.as_slice(),
            [EdnsOption::Keepalive(None), EdnsOption::Padding(_)]
        ),
        "{options:?}"
    );
}

/// A server's certificate replaced while it serves is presented from the next handshake on.
#[compio::test]
async fn a_replaced_certificate_is_presented_from_the_next_handshake() {
    let (old, new) = (certificates(), certificates());
    let presenting = |certificates: &Certificates| {
        Presented::new(
            vec![certificates.server.clone()],
            certificates.key.clone_key(),
        )
        .expect("a certificate")
    };
    let presented = Arc::new(presenting(&old));
    let acceptor = tls::acceptor(Arc::clone(&presented)).expect("an acceptor");
    let (addr, _) = serve(acceptor, 1).await;
    let trusting = |certificates: &Certificates| {
        Client::new().trusting(Trust::Roots(vec![certificates.ca.clone()]))
    };
    ask(&trusting(&old), named(addr, NAME))
        .await
        .expect("the first certificate");
    presented.replace(presenting(&new));
    ask(&trusting(&new), named(addr, NAME))
        .await
        .expect("the new certificate");
    let refused = ask(&trusting(&old), named(addr, NAME)).await;
    assert!(
        matches!(refused, Err(ClientError::Tcp(TcpError::Handshake(_)))),
        "{refused:?}"
    );
}

/// RFC 8446 §6.1: the client ends the TLS session of an idle connection with `close_notify`.
#[compio::test]
async fn an_idle_connection_ends_with_close_notify() {
    let certificates = certificates();
    let acceptor = TlsAcceptor::from(Arc::new(certificates.config(DEFAULT_VERSIONS, b"dot")));
    let (listener, addr) = listen().await;
    let server = compio::runtime::spawn(async move {
        let (stream, _) = listener.accept().await.expect("a connection");
        let mut tls = acceptor.accept(stream).await.expect("a handshake");
        let len = tls.read_u16().await.expect("a length");
        let BufResult(read, query) = tls.read_exact(Vec::with_capacity(len.into())).await;
        read.expect("a query");
        let response = frame(&answer(&query, Vec::new())).expect("framed");
        let BufResult(written, _) = tls.write_all(response).await;
        written.expect("the client reads");
        tls.flush().await.expect("a flush");
        // A clean end reads as no bytes; one without close_notify, as an error, which compio's `read` hides.
        let mut buf = [0; 16];
        futures_util::AsyncReadExt::read(&mut tls, &mut buf)
            .await
            .map_err(|error| error.kind())
    });
    let pool =
        TcpPool::new(Duration::from_millis(100)).trusting(Trust::Roots(vec![certificates.ca]));
    let link = Link::Tls(addr, ServerName::try_from(NAME).expect("a name"));
    let deadline = Instant::now() + Duration::from_secs(5);
    pool.exchange(link, &common::wire(&query()), deadline)
        .await
        .expect("a response");
    let end = compio::time::timeout(Duration::from_secs(2), server)
        .await
        .expect("an end")
        .expect("joined");
    assert_eq!(end, Ok(0));
}
