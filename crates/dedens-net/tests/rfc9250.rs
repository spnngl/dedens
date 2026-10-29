//! DNS over QUIC (RFC 9250) and the strict privacy profile (RFC 8310 §6.6), against a loopback QUIC server with
//! certificates made for the test.

mod common;

use std::cell::{Cell, RefCell};
use std::net::SocketAddr;
use std::rc::Rc;

use common::certificates::{Certificates, NAME, certificates, named};
use common::loopback::answer;
use common::{query, sent, start, t0};
use compio::BufResult;
use compio::io::AsyncWriteExt;
use compio::quic::ServerBuilder;
use compio::rustls::version::TLS13;
use dedens_net::client::{Client, ClientError};
use dedens_net::exchange::{Options, Transport};
use dedens_net::quic::QuicError;
use dedens_net::tcp::frame;
use dedens_net::tls::Trust;
use dedens_proto::Message;
use dedens_proto::edns::EdnsOption;

/// What the server saw.
#[derive(Default)]
struct Seen {
    connections: Cell<u32>,
    /// Each stream's bytes, its length first.
    streams: RefCell<Vec<Vec<u8>>>,
}

/// A QUIC server on the loopback address answering each stream's query on it, framed unless `framed` is off.
async fn quic_server(certificates: &Certificates, framed: bool) -> (SocketAddr, Rc<Seen>) {
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
                while let Ok((mut send, mut recv)) = connection.accept_bi().await {
                    let BufResult(read, bytes) = recv.read_to_end(Vec::new()).await;
                    read.expect("the query");
                    log.streams.borrow_mut().push(bytes.clone());
                    let response = answer(&bytes[2..], Vec::new());
                    let response = if framed {
                        frame(&response).expect("framed")
                    } else {
                        response
                    };
                    let BufResult(written, _) = send.write_all(response).await;
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
    let (addr, seen) = quic_server(&certificates, true).await;
    let client = Client::new().trusting(Trust::Roots(vec![certificates.ca]));
    let response = client
        .exchange(&query(), named(addr, NAME), &quic())
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
    assert_eq!(
        Message::decode(&stream[2..])
            .expect("a query")
            .message
            .header
            .id,
        0
    );
}

/// RFC 9250 §4.2, §5.5: queries share one connection, each on its own stream.
#[compio::test]
async fn s4_2_queries_share_one_connection_each_on_its_stream() {
    let certificates = certificates();
    let (addr, seen) = quic_server(&certificates, true).await;
    let client = Client::new().trusting(Trust::Roots(vec![certificates.ca]));
    let (query, options) = (query(), quic());
    let ask = || client.exchange(&query, named(addr, NAME), &options);
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
    let (addr, seen) = quic_server(&certificates, true).await;
    let client = Client::new().trusting(Trust::Roots(vec![certificates.ca]));
    let error = client
        .exchange(&query(), named(addr, "other.example"), &quic())
        .await;
    assert!(
        matches!(error, Err(ClientError::Quic(QuicError::Connection(_)))),
        "{error:?}"
    );
    assert_eq!(seen.streams.borrow().len(), 0);
}

/// RFC 9250 §4.2: a response without its length is a protocol error.
#[compio::test]
async fn s4_2_a_response_without_its_length_is_refused() {
    let certificates = certificates();
    let (addr, _) = quic_server(&certificates, false).await;
    let client = Client::new().trusting(Trust::Roots(vec![certificates.ca]));
    let error = client.exchange(&query(), named(addr, NAME), &quic()).await;
    assert!(
        matches!(error, Err(ClientError::Quic(QuicError::Framing))),
        "{error:?}"
    );
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
