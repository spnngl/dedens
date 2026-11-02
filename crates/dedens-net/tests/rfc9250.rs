//! DNS over QUIC (RFC 9250) and the strict privacy profile (RFC 8310 §6.6), against a loopback QUIC server with
//! certificates made for the test.

mod common;

use std::cell::{Cell, RefCell};
use std::net::SocketAddr;
use std::num::NonZero;
use std::rc::Rc;
use std::time::Duration;

use common::certificates::{Certificates, NAME, certificates, named};
use common::loopback::answer;
use common::{query, sent, start, t0};
use compio::BufResult;
use compio::io::AsyncWriteExt;
use compio::quic::{ConnectionError, ServerBuilder, VarInt};
use compio::rustls::version::TLS13;
use dedens_net::client::{Client, ClientError};
use dedens_net::exchange::{Options, Transport};
use dedens_net::quic::QuicError;
use dedens_net::tcp::frame;
use dedens_net::tls::Trust;
use dedens_proto::Message;
use dedens_proto::edns::EdnsOption;

/// How the server answers.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Serve {
    /// Each response behind its length.
    Framed,
    /// Each response without its length.
    Unframed,
    /// Framed, but the connection closed at its stream of this number, that query unanswered.
    ClosingAt(u32),
    /// Framed, but from the second stream of a connection on, without the length.
    UnframedAfterFirst,
    /// More bytes than a response holds, the stream left open.
    Endless,
    /// Framed, padded to the most a response holds: 65535 bytes.
    Largest,
    /// No response: the stream waits for the client to stop it, the code it gives kept.
    Silent,
}

/// What the server saw.
#[derive(Default)]
struct Seen {
    connections: Cell<u32>,
    /// Whether the server could open a stream of its own.
    opened: Cell<bool>,
    /// Each stream's bytes, its length first.
    streams: RefCell<Vec<Vec<u8>>>,
    /// The code of each `STOP_SENDING` the server got.
    stopped: RefCell<Vec<u64>>,
    /// The error code of each `CONNECTION_CLOSE` of the application the server got.
    closed: RefCell<Vec<u64>>,
}

/// A QUIC server on the loopback address answering each stream's query on it as `serve` says.
async fn quic_server(certificates: &Certificates, serve: Serve) -> (SocketAddr, Rc<Seen>) {
    let config = certificates.config(&[&TLS13], b"doq");
    let endpoint = ServerBuilder::new_with_rustls_server_config(config)
        .bind("127.0.0.1:0")
        .await
        .expect("a QUIC endpoint");
    let addr = endpoint.local_addr().expect("its address");
    let seen = Rc::new(Seen::default());
    let log = Rc::clone(&seen);
    compio::runtime::spawn(async move {
        while let Some(incoming) = endpoint.wait_incoming().await {
            let log = Rc::clone(&log);
            compio::runtime::spawn(async move {
                // A client that refuses the certificate ends here.
                let Ok(connecting) = incoming.accept() else {
                    return;
                };
                let Ok(connection) = connecting.await else {
                    return;
                };
                log.connections.set(log.connections.get() + 1);
                let opened = connection.open_uni().is_ok() || connection.open_bi().is_ok();
                log.opened.set(log.opened.get() || opened);
                let mut streams = 0;
                loop {
                    let (mut send, mut recv) = match connection.accept_bi().await {
                        Ok(stream) => stream,
                        Err(ConnectionError::ApplicationClosed(close)) => {
                            log.closed.borrow_mut().push(close.error_code.into_inner());
                            return;
                        }
                        Err(_) => return,
                    };
                    streams += 1;
                    if serve == Serve::ClosingAt(streams) {
                        connection.close(VarInt::from_u32(0), b"going away");
                        return;
                    }
                    let BufResult(read, bytes) = recv.read_to_end(Vec::new()).await;
                    read.expect("the query");
                    log.streams.borrow_mut().push(bytes.clone());
                    if serve == Serve::Silent {
                        if let Ok(Some(code)) = send.stopped().await {
                            log.stopped.borrow_mut().push(code.into_inner());
                        }
                        continue;
                    }
                    let response = answer(&bytes[2..], Vec::new());
                    let response = match serve {
                        Serve::Unframed => response,
                        Serve::UnframedAfterFirst if streams > 1 => response,
                        Serve::Endless => vec![0; 70_000],
                        Serve::Largest => {
                            let short =
                                u16::MAX - u16::try_from(response.len() + 4).expect("short");
                            let padded = answer(&bytes[2..], vec![EdnsOption::Padding(short)]);
                            assert_eq!(padded.len(), 65_535);
                            frame(&padded).expect("framed")
                        }
                        Serve::Framed
                        | Serve::ClosingAt(_)
                        | Serve::UnframedAfterFirst
                        | Serve::Silent => frame(&response).expect("framed"),
                    };
                    let BufResult(written, _) = send.write_all(response).await;
                    if serve == Serve::Endless {
                        // The client may stop reading early; the stream stays open.
                        compio::time::sleep(Duration::from_secs(10)).await;
                        return;
                    }
                    written.expect("the client reads");
                    send.finish().expect("an open stream");
                }
            })
            .detach();
        }
    })
    .detach();
    (addr, seen)
}

fn quic() -> Options {
    let mut options = Options::default();
    options.transport = Transport::Quic;
    options
}

/// RFC 9250 §4.2, §4.2.1: the query goes alone on a stream, behind its length, with ID 0, and its response comes
/// back on the stream.
#[compio::test]
async fn s4_2_a_query_goes_alone_on_a_stream_with_id_0() {
    let certificates = certificates();
    let (addr, seen) = quic_server(&certificates, Serve::Framed).await;
    let client = Client::new().trusting(Trust::Roots(vec![certificates.ca]));
    let response = client
        .exchange(query(), named(addr, NAME), &quic())
        .await
        .expect("a response");
    assert_eq!(response.transport, Transport::Quic);
    let answered = Message::decode(&response.wire).expect("a response").message;
    assert_eq!(answered.questions, query().questions);
    let streams = seen.streams.borrow();
    let [stream] = streams.as_slice() else {
        panic!("one stream, not {}", streams.len());
    };
    assert_eq!(
        usize::from(u16::from_be_bytes([stream[0], stream[1]])),
        stream.len() - 2
    );
    let sent = Message::decode(&stream[2..]).expect("a query").message;
    assert_eq!(sent.header.id, 0);
    // No cookie: QUIC checks the client's address itself (RFC 9000 §8).
    let options = sent.edns.expect("EDNS").options;
    assert!(
        !options
            .iter()
            .any(|option| matches!(option, EdnsOption::Cookie(_))),
        "{options:?}"
    );
}

/// RFC 9250 §4.2, §5.5: queries share one connection, each on its own stream.
#[compio::test]
async fn s4_2_queries_share_one_connection_each_on_its_stream() {
    let certificates = certificates();
    let (addr, seen) = quic_server(&certificates, Serve::Framed).await;
    let client = Client::new().trusting(Trust::Roots(vec![certificates.ca]));
    let (query, options) = (query(), quic());
    let ask = || client.exchange(query.clone(), named(addr, NAME), &options);
    let (first, second) = futures_util::future::join(ask(), ask()).await;
    first.expect("a response");
    second.expect("a response");
    ask().await.expect("a response");
    assert_eq!(seen.connections.get(), 1);
    assert_eq!(seen.streams.borrow().len(), 3);
}

/// RFC 8310 §6.6, RFC 9250 §7.1: in the strict profile, a server whose certificate does not hold the name is not
/// queried.
#[compio::test]
async fn a_certificate_for_another_name_is_refused() {
    let certificates = certificates();
    let (addr, seen) = quic_server(&certificates, Serve::Framed).await;
    let client = Client::new().trusting(Trust::Roots(vec![certificates.ca]));
    let error = client
        .exchange(query(), named(addr, "other.example"), &quic())
        .await;
    assert!(
        matches!(error, Err(ClientError::Quic(QuicError::Connection(_)))),
        "{error:?}"
    );
    assert_eq!(seen.streams.borrow().len(), 0);
}

/// RFC 9250 §4.3.3: a stream that is not one message behind its length is a protocol error: the client closes the
/// connection with `DOQ_PROTOCOL_ERROR`, 2, and the next query opens another instead of reusing it (D109).
#[compio::test]
async fn s4_3_3_a_framing_error_closes_the_connection_with_doq_protocol_error() {
    let certificates = certificates();
    let (addr, seen) = quic_server(&certificates, Serve::Unframed).await;
    let client = Client::new().trusting(Trust::Roots(vec![certificates.ca]));
    let error = client.exchange(query(), named(addr, NAME), &quic()).await;
    assert!(
        matches!(error, Err(ClientError::Quic(QuicError::Framing))),
        "{error:?}"
    );
    for _ in 0..50 {
        if !seen.closed.borrow().is_empty() {
            break;
        }
        compio::time::sleep(Duration::from_millis(20)).await;
    }
    assert_eq!(*seen.closed.borrow(), [2]);
    let error = client.exchange(query(), named(addr, NAME), &quic()).await;
    assert!(
        matches!(error, Err(ClientError::Quic(QuicError::Framing))),
        "{error:?}"
    );
    assert_eq!(seen.connections.get(), 2);
    // Neither query was asked again.
    assert_eq!(seen.streams.borrow().len(), 2);
}

/// RFC 9250 §4.2: a response without its length is a protocol error: the query is not asked again.
#[compio::test]
async fn s4_2_a_response_without_its_length_is_refused() {
    let certificates = certificates();
    let (addr, seen) = quic_server(&certificates, Serve::Unframed).await;
    let client = Client::new().trusting(Trust::Roots(vec![certificates.ca]));
    for _ in 0..2 {
        let error = client.exchange(query(), named(addr, NAME), &quic()).await;
        assert!(
            matches!(error, Err(ClientError::Quic(QuicError::Framing))),
            "{error:?}"
        );
    }
    assert_eq!(seen.streams.borrow().len(), 2);
}

/// RFC 9250 §4.2: a response of 65535 bytes, the most its length can say, is read whole.
#[compio::test]
async fn s4_2_the_largest_response_is_read() {
    let certificates = certificates();
    let (addr, _) = quic_server(&certificates, Serve::Largest).await;
    let client = Client::new().trusting(Trust::Roots(vec![certificates.ca]));
    let response = client
        .exchange(query(), named(addr, NAME), &quic())
        .await
        .expect("a response");
    assert_eq!(response.wire.len(), 65_535);
}

/// RFC 9250 §4.3.1: a query given up, here at its timeout, is cancelled: `STOP_SENDING` with `DOQ_REQUEST_CANCELLED`.
#[compio::test]
async fn s4_3_1_a_query_given_up_is_cancelled() {
    let certificates = certificates();
    let (addr, seen) = quic_server(&certificates, Serve::Silent).await;
    let client = Client::new().trusting(Trust::Roots(vec![certificates.ca]));
    let mut options = quic();
    options.timeout = Duration::from_millis(300);
    options.tries = NonZero::<u8>::MIN;
    let error = client.exchange(query(), named(addr, NAME), &options).await;
    assert!(error.is_err(), "{error:?}");
    for _ in 0..50 {
        if !seen.stopped.borrow().is_empty() {
            break;
        }
        compio::time::sleep(Duration::from_millis(20)).await;
    }
    assert_eq!(*seen.stopped.borrow(), [3]);
}

/// RFC 9250 §4.2: a response is at most 65535 bytes behind its length; past that the stream is a protocol error,
/// not read on to its end.
#[compio::test]
async fn s4_2_a_stream_longer_than_a_response_is_refused() {
    let certificates = certificates();
    let (addr, _) = quic_server(&certificates, Serve::Endless).await;
    let client = Client::new().trusting(Trust::Roots(vec![certificates.ca]));
    let error = client.exchange(query(), named(addr, NAME), &quic()).await;
    assert!(
        matches!(error, Err(ClientError::Quic(QuicError::Framing))),
        "{error:?}"
    );
}

/// RFC 9250 §5.5, D27: a query on a reused connection that turns out closed goes again, once, on a new one.
#[compio::test]
async fn s5_5_a_closed_reused_connection_is_replaced_once() {
    let certificates = certificates();
    let (addr, seen) = quic_server(&certificates, Serve::ClosingAt(2)).await;
    let client = Client::new().trusting(Trust::Roots(vec![certificates.ca]));
    let (query, options) = (query(), quic());
    let ask = || client.exchange(query.clone(), named(addr, NAME), &options);
    ask().await.expect("a response");
    ask().await.expect("a response on a new connection");
    assert_eq!(seen.connections.get(), 2);
}

/// D27: a connection found closed on its first query is not a reused one that went stale: the query is not asked
/// again.
#[compio::test]
async fn a_fresh_connection_closed_at_its_first_query_is_not_replaced() {
    let certificates = certificates();
    let (addr, seen) = quic_server(&certificates, Serve::ClosingAt(1)).await;
    let client = Client::new().trusting(Trust::Roots(vec![certificates.ca]));
    let error = client.exchange(query(), named(addr, NAME), &quic()).await;
    assert!(
        matches!(error, Err(ClientError::Quic(QuicError::Stream(_)))),
        "{error:?}"
    );
    assert_eq!(seen.connections.get(), 1);
}

/// RFC 9250 §4.3.3, D27, D109: a framing error on a reused connection closes it, and that is no staleness: the query
/// is not asked again.
#[compio::test]
async fn a_framing_error_on_a_reused_connection_is_not_asked_again() {
    let certificates = certificates();
    let (addr, seen) = quic_server(&certificates, Serve::UnframedAfterFirst).await;
    let client = Client::new().trusting(Trust::Roots(vec![certificates.ca]));
    let (query, options) = (query(), quic());
    let ask = || client.exchange(query.clone(), named(addr, NAME), &options);
    ask().await.expect("a response");
    let error = ask().await;
    assert!(
        matches!(error, Err(ClientError::Quic(QuicError::Framing))),
        "{error:?}"
    );
    assert_eq!(seen.connections.get(), 1);
    assert_eq!(seen.streams.borrow().len(), 2);
}

/// RFC 9250 §4.3.3: the server may open no stream; the client allows none.
#[compio::test]
async fn s4_3_3_the_server_cannot_open_a_stream() {
    let certificates = certificates();
    let (addr, seen) = quic_server(&certificates, Serve::Framed).await;
    let client = Client::new().trusting(Trust::Roots(vec![certificates.ca]));
    client
        .exchange(query(), named(addr, NAME), &quic())
        .await
        .expect("a response");
    assert!(!seen.opened.get());
}

/// RFC 9250 §5.4: a query over QUIC is padded to a multiple of 128 bytes (RFC 8467 §4.1); §5.5.2: it carries no
/// edns-tcp-keepalive, even one the caller put in.
#[test]
fn s5_4_a_query_over_quic_is_padded_without_keepalive() {
    let mut keepalive = query();
    keepalive.edns.as_mut().expect("EDNS").options = vec![EdnsOption::Keepalive(None)];
    let exchange = start(&keepalive, quic(), t0());
    assert_eq!(exchange.wire().len() % 128, 0);
    let sent = sent(&exchange);
    assert_eq!(sent.header.id, 0);
    let options = sent.edns.expect("EDNS").options;
    assert!(
        matches!(options.as_slice(), [EdnsOption::Padding(_)]),
        "{options:?}"
    );
}
