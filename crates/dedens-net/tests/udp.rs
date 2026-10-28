//! UDP channel on the loopback address (RFC 1035 §4.2.1, RFC 5452 §9.2).

mod common;

use std::time::{Duration, Instant};

use common::loopback::{answer, id, query_with_id, udp_responder, udp_server};
use dedens_net::udp::UdpChannel;
use dedens_proto::edns::EdnsOption;

#[compio::test]
async fn a_query_gets_its_response() {
    let server = udp_server(Duration::ZERO).await;
    let mut channel = UdpChannel::connect(server).await.expect("a socket");
    channel.send(&query_with_id(7)).await.expect("sent");
    let response = channel
        .recv(Instant::now() + Duration::from_secs(5))
        .await
        .expect("received");
    assert_eq!(response.map(id), Some(7));
    assert_eq!(channel.server(), server);
}

#[compio::test]
async fn the_os_picks_the_source_port() {
    let server = udp_server(Duration::ZERO).await;
    let channel = UdpChannel::connect(server).await.expect("a socket");
    assert_ne!(channel.local_addr().expect("an address").port(), 0);
}

#[compio::test]
async fn a_late_response_still_arrives_after_the_deadline() {
    let server = udp_server(Duration::from_millis(200)).await;
    let mut channel = UdpChannel::connect(server).await.expect("a socket");
    channel.send(&query_with_id(9)).await.expect("sent");
    let early = channel
        .recv(Instant::now() + Duration::from_millis(20))
        .await
        .expect("no error");
    assert_eq!(early, None);
    let late = channel
        .recv(Instant::now() + Duration::from_secs(5))
        .await
        .expect("received");
    assert_eq!(late.map(id), Some(9));
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
    let mut channel = UdpChannel::connect(server).await.expect("a socket");
    for n in [1, 2] {
        let query = query_with_id(n);
        channel.send(&query).await.expect("sent");
        let response = channel
            .recv(Instant::now() + Duration::from_secs(5))
            .await
            .expect("received")
            .map(<[u8]>::to_vec);
        assert_eq!(response, Some(answer(&query, options(n))));
    }
}
