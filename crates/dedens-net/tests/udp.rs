//! UDP pool on the loopback address (RFC 1035 §4.2.1, RFC 5452 §9.2).

mod common;

use std::io;
use std::time::{Duration, Instant};

use common::loopback::{answer, id, query_with_id, udp_responder};
use compio::BufResult;
use compio::net::UdpSocket;
use dedens_net::udp::UdpPool;
use dedens_proto::edns::EdnsOption;

/// Room for any response of these tests.
const SIZE: usize = 1232;

fn soon() -> Instant {
    Instant::now() + Duration::from_secs(5)
}

#[compio::test]
async fn a_query_gets_its_response() {
    let server = udp_responder(|query| Some(answer(query, Vec::new()))).await;
    let pool = UdpPool::new(4);
    let mut query = pool.query(server, 0, 7, SIZE).await.expect("a socket");
    query.send(&query_with_id(7)).await.expect("sent");
    let response = query.recv(soon()).await.expect("received");
    assert_eq!(response.as_deref().map(id), Some(7));
}

#[compio::test]
async fn the_os_picks_the_source_port() {
    let server = udp_responder(|_| None).await;
    let query = UdpPool::new(4)
        .query(server, 0, 1, SIZE)
        .await
        .expect("a socket");
    assert_ne!(query.local_addr().expect("an address").port(), 0);
}

/// Queries on one socket each get the response with their ID, the later one first here.
#[compio::test]
async fn queries_on_one_socket_get_their_own_responses() {
    let server = udp_responder(|query| Some(answer(query, Vec::new()))).await;
    let pool = UdpPool::new(4);
    let mut first = pool.query(server, 1, 1, SIZE).await.expect("a socket");
    let mut second = pool.query(server, 5, 2, SIZE).await.expect("a socket");
    assert_eq!(first.local_addr().ok(), second.local_addr().ok());
    first.send(&query_with_id(1)).await.expect("sent");
    second.send(&query_with_id(2)).await.expect("sent");
    let two = second.recv(soon()).await.expect("received");
    let one = first.recv(soon()).await.expect("received");
    assert_eq!(
        (one.as_deref().map(id), two.as_deref().map(id)),
        (Some(1), Some(2))
    );
}

#[compio::test]
async fn sockets_are_picked_modulo_the_pool_size() {
    let server = udp_responder(|_| None).await;
    let pool = UdpPool::new(2);
    let port = async |pick| {
        let query = pool.query(server, pick, 1, SIZE).await.expect("a socket");
        query.local_addr().expect("an address").port()
    };
    let (a, b, c) = (port(0).await, port(1).await, port(2).await);
    assert_ne!(a, b);
    assert_eq!(a, c);
}

/// A response with an ID nobody waits for is dropped; the query takes the next with its own, from a new ID on.
#[compio::test]
async fn a_query_waits_for_its_id() {
    let server = udp_responder(|query| Some(answer(query, Vec::new()))).await;
    let pool = UdpPool::new(1);
    let mut query = pool.query(server, 0, 3, SIZE).await.expect("a socket");
    query.send(&query_with_id(4)).await.expect("sent");
    let early = query
        .recv(Instant::now() + Duration::from_millis(50))
        .await
        .expect("no error");
    assert_eq!(early, None);
    query.expect(5);
    query.send(&query_with_id(5)).await.expect("sent");
    let response = query.recv(soon()).await.expect("received");
    assert_eq!(response.as_deref().map(id), Some(5));
}

#[compio::test]
async fn a_late_response_still_arrives_after_the_deadline() {
    let server = UdpSocket::bind("127.0.0.1:0").await.expect("a UDP socket");
    let addr = server.local_addr().expect("an address");
    let pool = UdpPool::new(1);
    let mut query = pool.query(addr, 0, 9, SIZE).await.expect("a socket");
    query.send(&query_with_id(9)).await.expect("sent");
    let early = query
        .recv(Instant::now() + Duration::from_millis(20))
        .await
        .expect("no error");
    assert_eq!(early, None);
    // The server answers only now.
    let BufResult(received, sent_query) = server.recv_from(Vec::with_capacity(SIZE)).await;
    let (_, from) = received.expect("a query");
    let BufResult(sent, _) = server.send_to(answer(&sent_query, Vec::new()), from).await;
    sent.expect("sent");
    let late = query.recv(soon()).await.expect("received");
    assert_eq!(late.as_deref().map(id), Some(9));
}

/// A datagram shorter than the one before comes out whole: the receive buffer keeps no stale bytes.
#[compio::test]
async fn a_short_response_after_a_long_one_comes_out_whole() {
    // The response to ID 1 is padded, to ID 2 not.
    let options = |id| match id {
        1 => vec![EdnsOption::Padding(400)],
        _ => Vec::new(),
    };
    let server = udp_responder(move |query| Some(answer(query, options(id(query))))).await;
    let pool = UdpPool::new(1);
    for n in [1, 2] {
        let mut waiting = pool.query(server, 0, n, SIZE).await.expect("a socket");
        let query = query_with_id(n);
        waiting.send(&query).await.expect("sent");
        let response = waiting.recv(soon()).await.expect("received");
        assert_eq!(response, Some(answer(&query, options(n))));
    }
}

/// RFC 6891 §6.2.3: a datagram over the size the queries advertised comes cut to it.
#[compio::test]
async fn a_datagram_over_the_size_comes_cut() {
    let server = udp_responder(|query| Some(answer(query, vec![EdnsOption::Padding(600)]))).await;
    let pool = UdpPool::new(1);
    let mut query = pool.query(server, 0, 3, 512).await.expect("a socket");
    query.send(&query_with_id(3)).await.expect("sent");
    let response = query.recv(soon()).await.expect("received");
    assert_eq!(response.as_ref().map(Vec::len), Some(512));
}

/// The socket is connected: an ICMP port unreachable reaches the query waiting on it.
#[compio::test]
async fn a_closed_port_is_refused() {
    let closed = UdpSocket::bind("127.0.0.1:0").await.expect("a UDP socket");
    let addr = closed.local_addr().expect("an address");
    drop(closed);
    let pool = UdpPool::new(1);
    let mut query = pool.query(addr, 0, 3, SIZE).await.expect("a socket");
    query.send(&query_with_id(3)).await.expect("sent");
    let refused = query.recv(soon()).await.map_err(|error| error.kind());
    assert_eq!(refused, Err(io::ErrorKind::ConnectionRefused));
}
