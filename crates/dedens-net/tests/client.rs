//! The client end to end, against scripted servers on the loopback address (D27).

mod common;

use std::cell::RefCell;
use std::rc::Rc;
use std::time::Duration;

use common::loopback::{answer, id, tcp_responder, udp_responder};
use dedens_net::client::{Client, ClientError};
use dedens_net::exchange::{Failure, Options, Transport};
use dedens_proto::Message;
use dedens_proto::edns::{Cookie, EdnsOption};

/// The cookie a message carries.
fn cookie(wire: &[u8]) -> Option<Cookie> {
    let edns = Message::decode(wire).expect("a message").message.edns?;
    edns.options.into_iter().find_map(|option| match option {
        EdnsOption::Cookie(cookie) => Some(cookie),
        _ => None,
    })
}

fn answer_plainly(query: &[u8]) -> Vec<u8> {
    answer(query, Vec::new())
}

#[compio::test]
async fn a_query_gets_its_response_over_udp() {
    let server = udp_responder(|query| Some(answer_plainly(query))).await;
    let response = Client::new()
        .exchange(&common::query(), server, &Options::default())
        .await
        .expect("a response");
    assert_eq!(response.transport, Transport::Udp);
    assert_eq!(response.sends, 1);
    assert_eq!(id(&response.wire), id(&response.query));
}

/// RFC 7766 §5, RFC 1123 §6.1.3.2.
#[compio::test]
async fn a_truncated_response_is_asked_again_over_tcp() {
    let server = udp_responder(|query| {
        let mut truncated = answer_plainly(query);
        truncated[2] |= 0x02;
        Some(truncated)
    })
    .await;
    tcp_responder(server, answer_plainly).await;
    let response = Client::new()
        .exchange(&common::query(), server, &Options::default())
        .await
        .expect("a response");
    assert_eq!(response.transport, Transport::Tcp);
    assert_eq!(response.sends, 2);
}

/// RFC 7873 §5.1, §5.3: the client cookie stays for the server, its server cookie comes back to it.
#[compio::test]
async fn the_server_cookie_goes_back_to_its_server() {
    const SERVER_COOKIE: &[u8] = b"server-cookie-16";
    let queries = Rc::new(RefCell::new(Vec::new()));
    let seen = Rc::clone(&queries);
    let server = udp_responder(move |query| {
        seen.borrow_mut().push(query.to_vec());
        let client = cookie(query).expect("a cookie").client();
        let returned = Cookie::new(client, Some(SERVER_COOKIE)).expect("a valid cookie");
        Some(answer(query, vec![EdnsOption::Cookie(returned)]))
    })
    .await;
    let client = Client::new();
    for _ in 0..2 {
        let response = client
            .exchange(&common::query(), server, &Options::default())
            .await
            .expect("a response");
        assert!(cookie(&response.wire).is_some());
    }
    let queries = queries.borrow();
    let (first, second) = (
        cookie(&queries[0]).expect("a cookie"),
        cookie(&queries[1]).expect("a cookie"),
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
        .exchange(&common::query(), server, &options)
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
        .exchange(&query, server, &Options::default())
        .await
        .expect("a response");
    assert_eq!(cookie(&response.query), None);
}
