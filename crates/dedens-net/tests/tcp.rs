//! TCP pool on the loopback address (RFC 1035 §4.2.2, RFC 7766 §6.2, RFC 7828 §3.2).

mod common;

use std::rc::Rc;
use std::time::{Duration, Instant};

use common::loopback::{Peer, answer, id, listen, query_with_id};
use dedens_net::tcp::{Frames, TcpError, TcpPool, frame};
use dedens_proto::edns::EdnsOption;
use proptest::prelude::*;

fn deadline() -> Instant {
    Instant::now() + Duration::from_secs(5)
}

fn pool() -> Rc<TcpPool> {
    Rc::new(TcpPool::new(Duration::from_secs(5)))
}

proptest! {
    /// RFC 7766 §8: the reads may cut the stream anywhere.
    #[test]
    fn frames_come_out_whole_however_the_stream_is_cut(
        messages in prop::collection::vec(prop::collection::vec(any::<u8>(), 0..300), 1..5),
        cut in 1..50usize,
    ) {
        let stream: Vec<u8> = messages.iter().flat_map(|m| frame(m).expect("short")).collect();
        let mut frames = Frames::new();
        let mut out = Vec::new();
        for piece in stream.chunks(cut) {
            frames.push(piece);
            while let Some(message) = frames.next_message() {
                out.push(message.to_vec());
            }
        }
        prop_assert_eq!(out, messages);
        prop_assert_eq!(frames.pending(), 0);
    }
}

#[test]
fn a_message_over_64_kib_cannot_be_framed() {
    assert_eq!(frame(&vec![0; 65536]), None);
    assert_eq!(frame(&[1, 2]), Some(vec![0, 2, 1, 2]));
}

/// RFC 7766 §6.2.1.1: responses may come in any order, each goes to the query with its ID.
#[compio::test]
async fn pipelined_queries_get_their_responses_in_any_order() {
    let (listener, server) = listen().await;
    let pool = pool();
    let ask = |n| {
        let pool = Rc::clone(&pool);
        compio::runtime::spawn(
            async move { pool.exchange(server, &query_with_id(n), deadline()).await },
        )
    };
    let (first, second) = (ask(1), ask(2));
    let mut peer = Peer::accept(&listener).await;
    let (one, two) = (
        peer.read().await.expect("a query"),
        peer.read().await.expect("a query"),
    );
    // An unknown ID first: dropped.
    peer.write(&[
        answer(&query_with_id(3), Vec::new()),
        answer(&two, Vec::new()),
        answer(&one, Vec::new()),
    ])
    .await;
    assert_eq!(
        first
            .await
            .expect("joined")
            .map(|r| id(&r))
            .expect("a response"),
        1
    );
    assert_eq!(
        second
            .await
            .expect("joined")
            .map(|r| id(&r))
            .expect("a response"),
        2
    );
}

#[compio::test]
async fn an_id_already_waiting_is_refused() {
    let (listener, server) = listen().await;
    let pool = pool();
    let waiting = {
        let pool = Rc::clone(&pool);
        compio::runtime::spawn(
            async move { pool.exchange(server, &query_with_id(5), deadline()).await },
        )
    };
    let mut peer = Peer::accept(&listener).await;
    let query = peer.read().await.expect("a query");
    let second = pool.exchange(server, &query_with_id(5), deadline()).await;
    assert!(matches!(second, Err(TcpError::IdInUse(5))), "{second:?}");
    peer.write(&[answer(&query, Vec::new())]).await;
    assert!(waiting.await.expect("joined").is_ok());
}

/// D27: a connection the server closes is replaced once and the query sent again.
#[compio::test]
async fn a_closed_connection_is_replaced_once() {
    let (listener, server) = listen().await;
    let pool = pool();
    let asked = {
        let pool = Rc::clone(&pool);
        compio::runtime::spawn(
            async move { pool.exchange(server, &query_with_id(4), deadline()).await },
        )
    };
    let mut first = Peer::accept(&listener).await;
    first.read().await.expect("a query");
    drop(first);
    let mut second = Peer::accept(&listener).await;
    let query = second.read().await.expect("the query again");
    second.write(&[answer(&query, Vec::new())]).await;
    assert_eq!(
        asked
            .await
            .expect("joined")
            .map(|r| id(&r))
            .expect("a response"),
        4
    );
}

#[compio::test]
async fn no_response_before_the_deadline_times_out() {
    let (listener, server) = listen().await;
    let pool = pool();
    let accepted = compio::runtime::spawn(async move { Peer::accept(&listener).await });
    let soon = Instant::now() + Duration::from_millis(50);
    let result = pool.exchange(server, &query_with_id(6), soon).await;
    assert!(matches!(result, Err(TcpError::TimedOut)), "{result:?}");
    drop(accepted);
}

#[compio::test]
async fn a_query_shorter_than_a_header_is_refused() {
    let result = pool()
        .exchange(common::server(), &[0; 11], deadline())
        .await;
    assert!(matches!(result, Err(TcpError::BadLength(11))), "{result:?}");
}

/// RFC 7766 §6.2.3: the client closes a connection idle for its timeout.
#[compio::test]
async fn an_idle_connection_closes() {
    let (listener, server) = listen().await;
    let pool = Rc::new(TcpPool::new(Duration::from_millis(50)));
    let asked = {
        let pool = Rc::clone(&pool);
        compio::runtime::spawn(
            async move { pool.exchange(server, &query_with_id(8), deadline()).await },
        )
    };
    let mut peer = Peer::accept(&listener).await;
    let query = peer.read().await.expect("a query");
    peer.write(&[answer(&query, Vec::new())]).await;
    assert!(asked.await.expect("joined").is_ok());
    assert_eq!(peer.read().await, None);
}

/// RFC 7828 §3.2.2: the server's edns-tcp-keepalive timeout, when shorter, closes the connection sooner.
#[compio::test]
async fn the_server_keepalive_shortens_the_idle_timeout() {
    let (listener, server) = listen().await;
    let pool = pool();
    let asked = {
        let pool = Rc::clone(&pool);
        compio::runtime::spawn(async move {
            pool.exchange(server, &query_with_id(10), deadline()).await
        })
    };
    let mut peer = Peer::accept(&listener).await;
    let query = peer.read().await.expect("a query");
    // One unit is 100 ms.
    peer.write(&[answer(&query, vec![EdnsOption::Keepalive(Some(1))])])
        .await;
    assert!(asked.await.expect("joined").is_ok());
    let closed = compio::time::timeout(Duration::from_secs(2), peer.read()).await;
    assert_eq!(closed, Ok(None));
}

#[compio::test]
async fn a_refused_connection_is_a_connect_error() {
    let (listener, server) = listen().await;
    drop(listener);
    let result = pool()
        .exchange(server, &query_with_id(11), deadline())
        .await;
    assert!(matches!(result, Err(TcpError::Connect(_))), "{result:?}");
}
