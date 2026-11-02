//! HTTP/3 (RFC 9114) as `dedensd` serves it: what a peer that declares a frame it never completes costs the server,
//! and that a busy honest connection is rotated, not closed (D119). h3 0.0.8 buffers a frame until it is whole, and
//! reads the stream meanwhile, so the QUIC windows reopen and nothing but the bytes the connection received bounds
//! the buffer.

#[path = "../../../crates/dedens-net/tests/common/certificates.rs"]
#[allow(
    dead_code,
    reason = "shared with the tests of dedens-net, which use all of it"
)]
mod certificates;
mod common;

use std::cell::Cell;
use std::num::NonZero;
use std::time::Duration;

use certificates::{Certificates, NAME, certificates, named};
use common::{Responder, Server, captured, decode, query_for, write_config};
use compio::io::AsyncWriteExt;
use compio::quic::{ClientBuilder, Connection, ConnectionError, SendStream};
use compio::runtime::Runtime;
use dedens_net::client::Client;
use dedens_net::exchange::{Options, Transport};
use dedens_net::https::H3_EXCESSIVE_LOAD;
use dedens_net::tls::Trust;
use dedens_proto::Rcode;
use futures_util::future::join_all;

/// What a client may send before the server must have closed the connection: the budget of D119 is 4 MiB, and the
/// server checks it every 20 ms, in which this paced client sends far less than the other 4 MiB. The server sends
/// `GOAWAY` at the budget and closes at the budget and a connection window (256 KiB) after it.
const CLOSED_BEFORE: usize = 8 << 20;

/// The bytes the client stops at if the server never closes, and the time it gives the server.
const CAP: usize = 64 << 20;
const PATIENCE: Duration = Duration::from_secs(30);

/// `dedensd` answering `DoH` over HTTP/3, with an upstream that is never asked.
fn serving(certificates: &Certificates, upstream: &Responder) -> Server {
    let config = write_config("");
    let (certificate, key) = (
        config.with_extension("crt.pem"),
        config.with_extension("key.pem"),
    );
    std::fs::write(&certificate, &certificates.server_pem).expect("the certificate written");
    common::write_key(&key, &certificates.key_pem);
    let upstream = upstream.addr;
    Server::configured(|listen| {
        format!(
            "listen: ['https://{listen}']\ntls:\n  certificate: '{}'\n  key: '{}'\npipeline: [up]\nstages:\n  up:\n    type: forward\n    servers: ['{upstream}']\n    timeout_ms: 2000\n    tries: 1\n",
            certificate.display(),
            key.display()
        )
    })
}

/// A variable-length integer on eight bytes (RFC 9000 §16), as a peer that wants the longest length writes it.
fn varint8(value: u64) -> [u8; 8] {
    assert!(value < 1 << 62, "{value} fits a variable-length integer");
    (value | 0b11 << 62).to_be_bytes()
}

/// An HTTP/3 connection to `addr` whose client control stream has sent its empty SETTINGS, the stream is returned
/// with it to keep it open.
async fn connected(addr: std::net::SocketAddr, ca: &Certificates) -> (Connection, SendStream) {
    let endpoint = ClientBuilder::new_with_empty_roots()
        .with_custom_certificate(ca.ca.clone())
        .expect("a root")
        .with_no_crls()
        .with_alpn_protocols(&["h3"])
        .bind("127.0.0.1:0")
        .await
        .expect("an endpoint");
    let connection = endpoint
        .connect(addr, NAME, None)
        .expect("connecting")
        .await
        .expect("connected");
    let mut control = connection.open_uni_wait().await.expect("a control stream");
    // The stream type (control), then a SETTINGS frame (type 4, no setting).
    control
        .write_all(vec![0x00, 0x04, 0x00])
        .await
        .0
        .expect("the SETTINGS sent");
    (connection, control)
}

/// Writes `chunk`s to `streams` in turns, slowly, until the server closes the connection or `CAP` bytes are
/// out. Returns what was sent, and why the connection ended.
async fn flood(
    connection: &Connection,
    streams: &mut [SendStream],
) -> (usize, Option<ConnectionError>) {
    let sent = Cell::new(0);
    let chunk = vec![0_u8; 16 << 10];
    let flooding = async {
        while sent.get() < CAP {
            for stream in streams.iter_mut() {
                if stream.write_all(chunk.clone()).await.0.is_err() {
                    return;
                }
                sent.set(sent.get() + chunk.len());
            }
            compio::time::sleep(Duration::from_millis(5)).await;
        }
    };
    // A server that stops reading leaves the writes waiting for credit: the timeout ends them.
    let _ = compio::time::timeout(PATIENCE, flooding).await;
    let reason = compio::time::timeout(Duration::from_secs(5), connection.closed())
        .await
        .ok();
    (sent.get(), reason)
}

/// The connection must end with `H3_EXCESSIVE_LOAD` after at most `CLOSED_BEFORE` bytes.
fn assert_refused(sent: usize, reason: Option<&ConnectionError>) {
    assert!(sent < CLOSED_BEFORE, "{sent} bytes sent before the end");
    let code = match reason {
        Some(ConnectionError::ApplicationClosed(close)) => Some(u64::from(close.error_code)),
        _ => None,
    };
    assert_eq!(code, Some(H3_EXCESSIVE_LOAD), "{reason:?}");
}

/// §7.2.1, §10.5: a reserved frame on the control stream that declares 2^61 bytes, then trickles, is not buffered
/// for good: the server closes the connection once the peer has sent its budget.
#[test]
fn s10_5_a_control_frame_that_never_ends_closes_the_connection() {
    let upstream = Responder::start(&["a"]);
    let ca = certificates();
    let server = serving(&ca, &upstream);
    Runtime::new().expect("a runtime").block_on(async {
        let (connection, mut control) = connected(server.addr, &ca).await;
        // A reserved frame type (0x1f * N + 0x21) and its length.
        let mut frame = vec![0x21];
        frame.extend_from_slice(&varint8(1 << 61));
        control.write_all(frame).await.0.expect("the header sent");
        let (sent, reason) = flood(&connection, &mut [control]).await;
        assert_refused(sent, reason.as_ref());
    });
}

/// §4.1, §10.5: sixteen request streams whose HEADERS frame declares 2^30 bytes and trickles are not buffered for
/// good either.
#[test]
fn s10_5_request_headers_that_never_end_close_the_connection() {
    let upstream = Responder::start(&["a"]);
    let ca = certificates();
    let server = serving(&ca, &upstream);
    Runtime::new().expect("a runtime").block_on(async {
        let (connection, _control) = connected(server.addr, &ca).await;
        let mut streams = Vec::new();
        for _ in 0..16 {
            let (mut send, _recv) = connection.open_bi_wait().await.expect("a request stream");
            // HEADERS (type 1) and its length.
            let mut frame = vec![0x01];
            frame.extend_from_slice(&varint8(1 << 30));
            send.write_all(frame).await.0.expect("the header sent");
            streams.push(send);
        }
        let (sent, reason) = flood(&connection, &mut streams).await;
        assert_refused(sent, reason.as_ref());
    });
}

/// §5.2: a connection that passed its budget is sent `GOAWAY`, not closed: 60 000 requests of a client, which pass the
/// budget (some 25 000 requests) twice, are all answered, each on a connection that opens as the one before ends. The
/// client is `dedens`' own, which opens another connection after `GOAWAY` and after a request the server refused
/// (D83), with one try: a request cut by a close would fail.
#[test]
fn s5_2_a_busy_connection_is_rotated_not_closed() {
    const QUERIES: usize = 60_000;
    const BATCH: usize = 100;
    let response = captured("a");
    let upstream = Responder::start(&["a"]);
    let ca = certificates();
    let server = serving(&ca, &upstream);
    let client = Client::new().trusting(Trust::Roots(vec![ca.ca.clone()]));
    let mut options = Options::default();
    options.transport = Transport::Https;
    options.tries = NonZero::<u8>::MIN;
    let query = decode(&query_for(&response, 0));
    Runtime::new().expect("a runtime").block_on(async {
        for _ in 0..QUERIES / BATCH {
            let answers = join_all(
                (0..BATCH)
                    .map(|_| client.exchange(query.clone(), named(server.addr, NAME), &options)),
            )
            .await;
            for answer in answers {
                let answer = answer.expect("an answer");
                assert_eq!(decode(&answer.wire).rcode(), Rcode::NOERROR);
            }
        }
    });
    assert_eq!(upstream.queries(), QUERIES);
    let rotations = server
        .stderr()
        .iter()
        .filter(|line| line.contains("GOAWAY"))
        .count();
    assert!(rotations >= 2, "{rotations} connections sent GOAWAY");
}
