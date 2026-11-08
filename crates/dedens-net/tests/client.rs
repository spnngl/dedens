//! The client end to end, against scripted servers on the loopback address (D27).

mod common;

use std::cell::{Cell, RefCell};
use std::io;
use std::rc::Rc;
use std::sync::Arc;
use std::time::Duration;

use common::cookie_of;
use common::loopback::{answer, id, listen, responders, udp_responder};
use compio::BufResult;
use compio::io::{AsyncReadExt, AsyncWrite, AsyncWriteExt};
use compio::rustls::DEFAULT_VERSIONS;
use compio::tls::TlsAcceptor;
use dedens_net::client::{Client, ClientError};
use dedens_net::exchange::{Failure, Options};
use dedens_net::tcp::{TcpError, frame};
use dedens_net::tls::Trust;
use dedens_proto::edns::{Cookie, EdnsOption};
use dedens_proto::{Message, Rcode, Transport};
use dedens_testkit::certificates::{NAME, certificates, named};

fn answer_plainly(query: &[u8]) -> Vec<u8> {
    answer(query, Vec::new())
}

#[compio::test]
async fn a_query_gets_its_response_over_udp() {
    let server = udp_responder(|query| Some(answer_plainly(query))).await;
    let response = Client::new()
        .exchange(common::query(), server, &Options::default())
        .await
        .expect("a response");
    assert_eq!(response.transport, Transport::Udp);
    assert_eq!(response.sends, 1);
    assert_eq!(id(&response.wire), id(&response.query));
}

/// RFC 7766 §5, RFC 1123 §6.1.3.2.
#[compio::test]
async fn a_truncated_response_is_asked_again_over_tcp() {
    let server = responders(
        |query| {
            let mut truncated = answer_plainly(query);
            truncated[2] |= 0x02;
            Some(truncated)
        },
        answer_plainly,
    )
    .await;
    let response = Client::new()
        .exchange(common::query(), server, &Options::default())
        .await
        .expect("a response");
    assert_eq!(response.transport, Transport::Tcp);
    assert_eq!(response.sends, 2);
}

/// RFC 5452 §9.2, D114: the query asked again goes with a spare ID, each of its two bytes random. Four IDs whose
/// bytes all match have a chance of 2^-32, four equal IDs 2^-48.
#[compio::test]
async fn the_spare_ids_are_random_in_both_bytes() {
    let server = responders(
        |query| {
            let mut truncated = answer_plainly(query);
            truncated[2] |= 0x02;
            Some(truncated)
        },
        answer_plainly,
    )
    .await;
    let client = Client::new();
    let mut ids = Vec::new();
    for _ in 0..4 {
        let response = client
            .exchange(common::query(), server, &Options::default())
            .await
            .expect("a response");
        assert_eq!(response.transport, Transport::Tcp);
        ids.push(id(&response.query));
    }
    assert!(
        ids.iter()
            .any(|id| id.to_be_bytes()[0] != id.to_be_bytes()[1]),
        "{ids:04x?}"
    );
    // An ID equal to the first query's is replaced by the next one: its bytes differ even when nothing is random.
    assert!(ids.windows(2).any(|pair| pair[0] != pair[1]), "{ids:04x?}");
}

/// RFC 7873 §5.1, §5.3: the client cookie stays for the server, its server cookie comes back to it.
#[compio::test]
async fn the_server_cookie_goes_back_to_its_server() {
    const SERVER_COOKIE: &[u8] = b"server-cookie-16";
    let queries = Rc::new(RefCell::new(Vec::new()));
    let seen = Rc::clone(&queries);
    let server = udp_responder(move |query| {
        seen.borrow_mut().push(query.to_vec());
        let client = cookie_of(query).expect("a cookie").client();
        let returned = Cookie::new(client, Some(SERVER_COOKIE)).expect("a valid cookie");
        Some(answer(query, vec![EdnsOption::Cookie(returned)]))
    })
    .await;
    let client = Client::new();
    for _ in 0..2 {
        let response = client
            .exchange(common::query(), server, &Options::default())
            .await
            .expect("a response");
        assert!(cookie_of(&response.wire).is_some());
    }
    let queries = queries.borrow();
    let (first, second) = (
        cookie_of(&queries[0]).expect("a cookie"),
        cookie_of(&queries[1]).expect("a cookie"),
    );
    assert_eq!(first.server(), None);
    assert_eq!(second.client(), first.client());
    assert_eq!(second.server(), Some(SERVER_COOKIE));
}

#[compio::test]
async fn no_response_times_out_after_every_try() {
    let server = udp_responder(|_| None).await;
    let mut options = Options::default();
    options.timeout = Duration::from_millis(20);
    options.tries = 2.try_into().expect("not zero");
    let result = Client::new()
        .exchange(common::query(), server, &options)
        .await;
    assert!(
        matches!(
            result,
            Err(ClientError::Exchange(Failure::TimedOut { sends: 2 }))
        ),
        "{result:?}"
    );
}

#[compio::test]
async fn a_query_without_edns_goes_without_a_cookie() {
    let server = udp_responder(|query| Some(answer_plainly(query))).await;
    let mut query = common::query();
    query.edns = None;
    let response = Client::new()
        .exchange(query, server, &Options::default())
        .await
        .expect("a response");
    assert_eq!(cookie_of(&response.query), None);
}

#[compio::test]
async fn without_cookies_a_query_goes_without_one() {
    let server = udp_responder(|query| Some(answer_plainly(query))).await;
    let mut options = Options::default();
    options.cookies = false;
    let response = Client::new()
        .exchange(common::query(), server, &options)
        .await
        .expect("a response");
    assert_eq!(cookie_of(&response.query), None);
}

/// RFC 7873 §5.3: a response with the client cookie alone leaves the server cookie known.
#[compio::test]
async fn a_response_without_a_server_cookie_keeps_the_known_one() {
    const SERVER_COOKIE: &[u8] = b"server-cookie-16";
    let queries = Rc::new(RefCell::new(Vec::new()));
    let seen = Rc::clone(&queries);
    let server = udp_responder(move |query| {
        let mut seen = seen.borrow_mut();
        // Only the first response carries a server cookie.
        let server_cookie = seen.is_empty().then_some(SERVER_COOKIE);
        seen.push(query.to_vec());
        let client = cookie_of(query).expect("a cookie").client();
        let returned = Cookie::new(client, server_cookie).expect("a valid cookie");
        Some(answer(query, vec![EdnsOption::Cookie(returned)]))
    })
    .await;
    let client = Client::new();
    for _ in 0..3 {
        client
            .exchange(common::query(), server, &Options::default())
            .await
            .expect("a response");
    }
    let third = cookie_of(&queries.borrow()[2]).expect("a cookie");
    assert_eq!(third.server(), Some(SERVER_COOKIE));
}

/// RFC 7873 §5.3: the fresh server cookie of a BADCOOKIE is kept, though the exchange then fails.
#[compio::test]
async fn the_fresh_cookie_of_a_badcookie_is_kept_when_the_exchange_fails() {
    const FRESH: &[u8] = b"fresh-cookie-016";
    let queries = Rc::new(RefCell::new(Vec::new()));
    let seen = Rc::clone(&queries);
    // BADCOOKIE with a fresh cookie to the first query, then no response.
    let server = udp_responder(move |query| {
        let mut seen = seen.borrow_mut();
        seen.push(query.to_vec());
        (seen.len() == 1).then(|| {
            let client = cookie_of(query).expect("a cookie").client();
            let fresh = Cookie::new(client, Some(FRESH)).expect("a valid cookie");
            let query = Message::decode(query).expect("a query").message;
            let mut response = common::response(&query, Rcode::BADCOOKIE);
            response.edns.as_mut().expect("EDNS").options = vec![EdnsOption::Cookie(fresh)];
            common::wire(&response)
        })
    })
    .await;
    let client = Client::new();
    let mut options = Options::default();
    options.timeout = Duration::from_millis(20);
    options.tries = 1.try_into().expect("not zero");
    let failed = client.exchange(common::query(), server, &options).await;
    assert!(failed.is_err(), "{failed:?}");
    let _ = client.exchange(common::query(), server, &options).await;
    // The first query of the second exchange, after the BADCOOKIE retry.
    let next = cookie_of(&queries.borrow()[2]).expect("a cookie");
    assert_eq!(next.server(), Some(FRESH));
}

/// D27: a TLS handshake slower than a try, the cookie waiting for its address, costs that try, not the exchange.
#[compio::test]
async fn a_handshake_slower_than_a_try_costs_one_try() {
    // Accepted by the kernel, never answered.
    let (_listener, server) = listen().await;
    let mut options = Options::default();
    options.transport = Transport::Tls;
    options.timeout = Duration::from_millis(50);
    options.tries = 2.try_into().expect("not zero");
    let result = Client::new()
        .trusting(Trust::Anyone)
        .exchange(common::query(), server, &options)
        .await;
    assert!(
        matches!(
            result,
            Err(ClientError::Exchange(Failure::TimedOut { sends: 2 }))
        ),
        "{result:?}"
    );
}

/// D27: without a cookie, nothing waits for the connection's address: each try queues its query, which goes once
/// the handshake ends, the first one's too.
#[compio::test]
async fn without_cookies_a_slow_handshake_takes_every_query() {
    let certificates = certificates();
    let acceptor = TlsAcceptor::from(Arc::new(certificates.config(DEFAULT_VERSIONS, b"dot")));
    let (listener, addr) = listen().await;
    let read = Rc::new(Cell::new(0_u32));
    let count = Rc::clone(&read);
    compio::runtime::spawn(async move {
        let (stream, _) = listener.accept().await.expect("a connection");
        // Slower than a try.
        compio::time::sleep(Duration::from_millis(450)).await;
        let mut tls = acceptor.accept(stream).await.expect("a handshake");
        while let Ok(len) = tls.read_u16().await {
            let BufResult(read, query) = tls.read_exact(Vec::with_capacity(len.into())).await;
            if read.is_err() {
                return;
            }
            count.set(count.get() + 1);
            let BufResult(written, _) = tls
                .write_all(frame(&answer_plainly(&query)).expect("framed"))
                .await;
            written.expect("the client reads");
            tls.flush().await.expect("a flush");
        }
    })
    .detach();
    let mut options = Options::default();
    options.transport = Transport::Tls;
    options.cookies = false;
    options.timeout = Duration::from_millis(300);
    options.tries = 4.try_into().expect("not zero");
    let response = Client::new()
        .trusting(Trust::Roots(vec![certificates.ca]))
        .exchange(common::query(), named(addr, NAME), &options)
        .await
        .expect("a response");
    assert!(response.sends >= 2, "{}", response.sends);
    assert_eq!(read.get(), u32::from(response.sends));
}

#[test]
fn failures_of_ours_are_local_and_the_networks_are_not() {
    let io = |kind| io::Error::from(kind);
    assert!(ClientError::Udp(io(io::ErrorKind::OutOfMemory)).is_local());
    assert!(ClientError::Tcp(TcpError::Connect(io(io::ErrorKind::AddrNotAvailable))).is_local());
    assert!(!ClientError::Udp(io(io::ErrorKind::ConnectionRefused)).is_local());
    assert!(!ClientError::Tcp(TcpError::Connect(io(io::ErrorKind::HostUnreachable))).is_local());
    assert!(!ClientError::Tcp(TcpError::TimedOut).is_local());
    assert!(!ClientError::Exchange(Failure::TimedOut { sends: 2 }).is_local());
}
