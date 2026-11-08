//! The QUIC DATAGRAM extension (RFC 9221) is not used: DNS over QUIC (RFC 9250) runs on streams, so the client
//! advertises no datagram support (D107).

mod common;

use std::cell::Cell;
use std::rc::Rc;

use common::query;
use compio::quic::{ServerBuilder, VarInt};
use compio::rustls::version::TLS13;
use dedens_net::client::Client;
use dedens_net::exchange::Options;
use dedens_net::tls::Trust;
use dedens_proto::Transport;
use dedens_testkit::certificates::{NAME, certificates, named};

/// RFC 9221 §3: an endpoint that does not support DATAGRAM frames leaves `max_datagram_frame_size` out (default 0),
/// so a peer sees no size it may send. quinn derives the parameter from its receive buffer, 1.25 MB unless unset.
/// That a DATAGRAM frame to an endpoint without the parameter closes the connection with `PROTOCOL_VIOLATION` is
/// quinn's behaviour, not tested here.
#[compio::test]
async fn s3_the_client_advertises_no_datagram_support() {
    let certificates = certificates();
    let config = certificates.config(&[&TLS13], b"doq");
    let endpoint = ServerBuilder::new_with_rustls_server_config(config)
        .bind("127.0.0.1:0")
        .await
        .expect("a QUIC endpoint");
    let addr = endpoint.local_addr().expect("its address");
    // `Some(size)` once a client let the server send DATAGRAM frames, `Some(None)` once one did not.
    let seen = Rc::new(Cell::new(None));
    let log = Rc::clone(&seen);
    compio::runtime::spawn(async move {
        let incoming = endpoint.wait_incoming().await.expect("a client");
        let connection = incoming
            .accept()
            .expect("a handshake")
            .await
            .expect("a connection");
        log.set(Some(connection.max_datagram_size()));
        connection.close(VarInt::from_u32(0), b"seen");
    })
    .detach();
    let mut options = Options::default();
    options.transport = Transport::Quic;
    let client = Client::new().trusting(Trust::Roots(vec![certificates.ca]));
    // The server closes the connection once it has looked, so the exchange fails.
    client
        .exchange(query(), named(addr, NAME), &options)
        .await
        .expect_err("a closed connection");
    assert_eq!(seen.get(), Some(None));
}
