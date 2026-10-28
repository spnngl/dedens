//! UDP channel on the loopback address (RFC 1035 §4.2.1, RFC 5452 §9.2).

mod common;

use std::time::{Duration, Instant};

use common::loopback::{id, query_with_id, udp_server};
use dedens_net::udp::UdpChannel;

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
